package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// oidExtKeyUsage is the X.509 extended-key-usage extension OID (RFC 5280 §4.2.1.12).
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// cmdTSAKey provisions an RFC 3161 Time-Stamp Authority signing credential: it
// generates (or reuses) a dedicated RSA key in the key provider and issues a TSA
// certificate under an existing CA. The certificate carries id-kp-timeStamping
// as its sole, critical extended key usage (RFC 3161 §2.3) and digitalSignature
// key usage. The private key never leaves the provider.
//
// The emitted PEM (the TSA certificate, plus the issuer chain when -chain is
// set) is what the server references via tsa.certificate_file; the key label is
// referenced via tsa.key_label.
func cmdTSAKey(db *database.DB, mgr *ca.Manager, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("tsa-key", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	label := fs.String("label", "tsa", "provider key label for the TSA signing key")
	keyType := fs.String("key-type", "rsa-2048", "TSA key type (must be RSA: rsa-2048 or rsa-4096)")
	cn := fs.String("cn", "Time-Stamp Authority", "TSA certificate subject common name")
	org := fs.String("o", "", "TSA certificate subject organization")
	validityDays := fs.Int("validity-days", 1185, "certificate validity in days")
	out := fs.String("out", "", "write the TSA certificate PEM here (default: stdout)")
	chain := fs.Bool("chain", false, "append the issuing CA chain to the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}

	kt, err := keyprovider.NormalizeKeyType(*keyType)
	if err != nil {
		return err
	}
	if kt != keyprovider.KeyTypeRSA2048 && kt != keyprovider.KeyTypeRSA4096 {
		return fmt.Errorf("TSA key must be RSA (got %q); openssl ts -verify interop and the CMS signer require RSA", kt)
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	caModel, err := db.GetCA(caID)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}
	if caModel == nil || caModel.Certificate == "" {
		return fmt.Errorf("CA %q has no certificate", *caRef)
	}
	caCert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	ctx := context.Background()

	// Reuse an existing key of this label (idempotent reissue) or generate one.
	pub, err := tsaPublicKey(ctx, provider, *label, kt)
	if err != nil {
		return err
	}

	eku, err := timeStampingEKUExtension()
	if err != nil {
		return err
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := time.Now().Add(time.Duration(*validityDays) * 24 * time.Hour)
	if notAfter.After(caCert.NotAfter) {
		return fmt.Errorf("requested validity (%s) exceeds issuing CA expiry (%s); lower -validity-days",
			notAfter.Format(time.RFC3339), caCert.NotAfter.Format(time.RFC3339))
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	caSigner, err := provider.Signer(ctx, tsaCAKeyRef(caModel))
	if err != nil {
		return fmt.Errorf("opening issuing CA signer: %w", err)
	}
	defer caSigner.Close()

	der, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:         pkix.Name{CommonName: *cn, Organization: orgSlice(*org)},
		PublicKey:       pub,
		Serial:          serial,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:     nil, // EKU carried critically via ExtraExtensions below
		ExtraExtensions: []pkix.Extension{eku},
	})
	if err != nil {
		return fmt.Errorf("issuing TSA certificate: %w", err)
	}

	// Sanity-check the freshly issued certificate against the same rules the
	// server enforces at startup, so provisioning fails loudly on a bad build.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing issued TSA certificate: %w", err)
	}
	if err := verifyTSACert(leaf); err != nil {
		return fmt.Errorf("issued TSA certificate is not usable: %w", err)
	}

	outPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if *chain {
		issuers, err := tsaIssuerChain(db, caID)
		if err != nil {
			return err
		}
		for _, c := range issuers {
			outPEM = append(outPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}

	fmt.Fprintf(os.Stderr, "Provisioned TSA certificate: serial=%s key=%s ca=%s not_after=%s\n",
		serial, *label, caModel.Label, notAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "Set tsa.key_label=%q and tsa.certificate_file to the written PEM in config.\n", *label)
	return writeOutput(*out, outPEM)
}

// tsaPublicKey returns the RSA public key for the TSA signing key, reusing an
// existing key of the given label or generating a new one. Reuse makes cert
// reissuance idempotent without rotating the key.
func tsaPublicKey(ctx context.Context, provider keyprovider.Provider, label, keyType string) (*rsa.PublicKey, error) {
	info, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: label})
	if err == nil {
		pub, ok := info.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("existing key %q is %T, not RSA; choose a different -label", label, info.PublicKey)
		}
		fmt.Fprintf(os.Stderr, "Reusing existing TSA key %q.\n", label)
		return pub, nil
	}

	gen, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType, Usage: keyprovider.KeyUsageSign})
	if err != nil {
		return nil, fmt.Errorf("generating TSA key %q: %w", label, err)
	}
	pub, ok := gen.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("generated key is %T, not RSA", gen.PublicKey)
	}
	return pub, nil
}

// timeStampingEKUExtension builds a critical extended-key-usage extension whose
// sole usage is id-kp-timeStamping, as RFC 3161 §2.3 requires for a TSA cert.
func timeStampingEKUExtension() (pkix.Extension, error) {
	val, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling extended key usage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val}, nil
}

// verifyTSACert re-checks that a certificate is a usable dedicated TSA
// credential: RSA key, and id-kp-timeStamping as the sole extended key usage.
func verifyTSACert(cert *x509.Certificate) error {
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return fmt.Errorf("public key is %T, want RSA", cert.PublicKey)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(cert.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("id-kp-timeStamping must be the sole extended key usage")
	}
	return nil
}

// tsaCAKeyRef resolves the provider key reference for an issuing CA.
func tsaCAKeyRef(caModel *models.CA) keyprovider.KeyRef {
	label := pki.ExtractKeyLabel(caModel.PKCS11URI)
	if label == "" {
		label = caModel.Label
	}
	return keyprovider.KeyRef{Label: label}
}

// tsaIssuerChain returns the issuing CA certificate followed by its parents up
// to the root, following the CA models' ParentID links.
func tsaIssuerChain(db *database.DB, caID string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	id := caID
	for id != "" {
		m, err := db.GetCA(id)
		if err != nil {
			return nil, fmt.Errorf("loading CA %q: %w", id, err)
		}
		if m == nil || m.Certificate == "" {
			break
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			return nil, fmt.Errorf("parsing CA %q certificate: %w", id, err)
		}
		chain = append(chain, cert)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	return chain, nil
}

func orgSlice(o string) []string {
	if o == "" {
		return nil
	}
	return []string{o}
}

// randomSerial returns a random, positive 128-bit certificate serial.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}
