package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// cmdSVID mints a SPIFFE X.509-SVID, or dispatches to the JWT-SVID subverbs
// (`svid jwt` to mint a JWT-SVID, `svid jwt-verify` to validate one). The X.509
// workload key is supplied by a CSR (-csr) or, for convenience, generated
// locally (an ECDSA P-256 key written to -key-out). The SVID's sole identity is
// the spiffe:// URI built from -trust-domain and -path (or given directly as
// -id); the CSR's own subject and SANs are ignored.
func cmdSVID(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "jwt":
			return cmdSVIDJWT(db, mgr, args[1:])
		case "jwt-verify":
			return cmdSVIDJWTVerify(db, mgr, cfg, args[1:])
		}
	}
	fs := flag.NewFlagSet("svid", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	id := fs.String("id", "", "full spiffe:// identity (overrides -trust-domain/-path)")
	trustDomain := fs.String("trust-domain", "", "SPIFFE trust domain, e.g. example.org")
	path := fs.String("path", "", "workload path, e.g. /ns/prod/sa/web")
	csrPath := fs.String("csr", "", "path to a PEM CSR (public-key source); '-' for stdin")
	keyOut := fs.String("key-out", "", "when generating a key, write the PEM private key here")
	profile := fs.String("profile", ca.SVIDProfileName, "SVID issuance profile")
	ttl := fs.Duration("ttl", 0, "SVID validity (0 = profile default; e.g. 30m, 1h)")
	out := fs.String("out", "", "write the SVID PEM here (default: stdout)")
	chain := fs.Bool("chain", false, "include the issuing CA certificate in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}

	// Resolve and validate the SPIFFE identity up front so a bad id fails before
	// any key is generated or the HSM is touched.
	var sid spiffe.ID
	var err error
	if *id != "" {
		sid, err = spiffe.ParseID(*id)
	} else {
		sid, err = spiffe.MakeID(*trustDomain, *path)
	}
	if err != nil {
		return fmt.Errorf("invalid SPIFFE identity: %w", err)
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	// Obtain the workload public key: from a supplied CSR, or by generating a key.
	var csrPEM []byte
	if *csrPath != "" {
		csrPEM, err = readInput(*csrPath)
		if err != nil {
			return fmt.Errorf("reading CSR: %w", err)
		}
	} else {
		csrPEM, err = generateSVIDCSR(sid, *keyOut)
		if err != nil {
			return err
		}
	}

	result, err := mgr.IssueSVID(context.Background(), ca.SVIDSpec{
		CAID:        caID,
		CSRPEM:      csrPEM,
		SPIFFEID:    sid.String(),
		Profile:     *profile,
		Validity:    *ttl,
		RequestedBy: "secsy-ca-cli",
	})
	if err != nil {
		return err
	}

	pemOut := result.PEM
	if *chain {
		pemOut = result.ChainPEM
	}
	fmt.Fprintf(os.Stderr, "Issued SVID: %s serial=%s profile=%s not_after=%s\n",
		sid.String(), result.Serial, result.Profile, result.Certificate.NotAfter.Format(time.RFC3339))
	return writeOutput(*out, pemOut)
}

// generateSVIDCSR generates an ECDSA P-256 key and a minimal CSR for it, writing
// the private key PEM to keyOut (or stderr-noting stdout is unavailable). The CSR
// subject/SANs are irrelevant to issuance; only its public key is used.
func generateSVIDCSR(_ spiffe.ID, keyOut string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating SVID key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("building SVID CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling SVID key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if keyOut == "" {
		return nil, fmt.Errorf("a generated SVID key needs -key-out to store its private key (or supply -csr)")
	}
	if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing SVID key to %s: %w", keyOut, err)
	}
	fmt.Fprintf(os.Stderr, "Generated SVID private key: %s\n", keyOut)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// cmdSVIDBundle emits a CA's SPIFFE trust bundle: its X.509 trust anchors (the
// combined overlap chain) as a JWKS-style SPIFFE bundle consumable by SPIRE and
// go-spiffe clients.
func cmdSVIDBundle(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("svid-bundle", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label whose trust anchors to bundle (required)")
	out := fs.String("out", "", "write the JWKS bundle here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	authorities, err := mgr.TrustBundleAuthorities(caID)
	if err != nil {
		return err
	}
	bundle, err := spiffe.BuildBundle(authorities, cfg.SPIFFE.RefreshHint(), 0)
	if err != nil {
		return err
	}
	return writeOutput(*out, append(bundle, '\n'))
}

// cmdSVIDJWT mints a SPIFFE JWT-SVID: a short-lived, HSM-signed JWS bearer token
// whose subject is the spiffe:// identity. Unlike an X.509-SVID there is no CSR
// — the token carries no workload key. The audience is required; the CA's active
// issuer key signs the token and its kid matches the JWKS trust bundle.
func cmdSVIDJWT(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("svid jwt", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	id := fs.String("id", "", "full spiffe:// identity (overrides -trust-domain/-path)")
	trustDomain := fs.String("trust-domain", "", "SPIFFE trust domain, e.g. example.org")
	path := fs.String("path", "", "workload path, e.g. /ns/prod/sa/web")
	var audiences multiFlag
	fs.Var(&audiences, "audience", "intended audience (repeatable or comma-separated); at least one required")
	ttl := fs.Duration("ttl", 0, "token lifetime (0 = server default; e.g. 5m, 1h)")
	out := fs.String("out", "", "write the token here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}

	var sid spiffe.ID
	var err error
	if *id != "" {
		sid, err = spiffe.ParseID(*id)
	} else {
		sid, err = spiffe.MakeID(*trustDomain, *path)
	}
	if err != nil {
		return fmt.Errorf("invalid SPIFFE identity: %w", err)
	}
	if len(audiences) == 0 {
		return fmt.Errorf("at least one -audience is required")
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	result, err := mgr.IssueJWTSVID(context.Background(), ca.JWTSVIDSpec{
		CAID:        caID,
		SPIFFEID:    sid.String(),
		Audience:    []string(audiences),
		TTL:         *ttl,
		RequestedBy: "secsy-ca-cli",
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Issued JWT-SVID: %s aud=%s kid=%s alg=%s exp=%s\n",
		sid.String(), strings.Join(result.Audience, ","), result.KeyID, result.Algorithm,
		result.Expiry.UTC().Format(time.RFC3339))
	return writeOutput(*out, []byte(result.Token+"\n"))
}

// cmdSVIDJWTVerify validates a JWT-SVID against a SPIFFE JWKS trust bundle: it
// verifies the signature against the bundle's jwt-svid keys, checks the required
// audience and the exp/nbf window, and enforces the trust-domain allowlist. The
// bundle is read from -bundle, or built from -ca's trust anchors. This is the
// same server-side validation the API exposes, runnable offline by an auditor.
func cmdSVIDJWTVerify(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("svid jwt-verify", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label whose trust bundle to verify against (or use -bundle)")
	bundlePath := fs.String("bundle", "", "path to a JWKS trust bundle ('-' for stdin); overrides -ca")
	tokenPath := fs.String("token", "-", "path to the JWT-SVID ('-' for stdin)")
	audience := fs.String("audience", "", "expected audience the token must carry (required)")
	var trustDomains multiFlag
	fs.Var(&trustDomains, "trust-domain", "allowed trust domain(s) (repeatable); default: config spiffe.trust_domains")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *audience == "" {
		return fmt.Errorf("-audience is required")
	}

	tokenBytes, err := readInput(*tokenPath)
	if err != nil {
		return fmt.Errorf("reading token: %w", err)
	}

	var bundle []byte
	if *bundlePath != "" {
		if bundle, err = readInput(*bundlePath); err != nil {
			return fmt.Errorf("reading bundle: %w", err)
		}
	} else {
		if *caRef == "" {
			return fmt.Errorf("either -bundle or -ca is required")
		}
		caID, rerr := resolveCA(db, *caRef)
		if rerr != nil {
			return rerr
		}
		authorities, aerr := mgr.TrustBundleAuthorities(caID)
		if aerr != nil {
			return aerr
		}
		if bundle, err = spiffe.BuildBundle(authorities, cfg.SPIFFE.RefreshHint(), 0); err != nil {
			return err
		}
	}

	tds := []string(trustDomains)
	if len(tds) == 0 {
		tds = cfg.SPIFFE.TrustDomains
	}
	res, err := spiffe.ValidateJWTSVID(strings.TrimSpace(string(tokenBytes)), bundle, spiffe.JWTValidationOptions{
		Audience:     *audience,
		TrustDomains: tds,
	})
	if err != nil {
		return fmt.Errorf("JWT-SVID INVALID: %w", err)
	}
	fmt.Fprintln(os.Stderr, "JWT-SVID OK")
	fmt.Printf("spiffe_id:    %s\n", res.SPIFFEID)
	fmt.Printf("trust_domain: %s\n", res.TrustDomain)
	fmt.Printf("audience:     %s\n", strings.Join(res.Audience, ","))
	fmt.Printf("kid:          %s\n", res.KeyID)
	fmt.Printf("alg:          %s\n", res.Algorithm)
	if !res.IssuedAt.IsZero() {
		fmt.Printf("issued_at:    %s\n", res.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !res.Expiry.IsZero() {
		fmt.Printf("expires_at:   %s\n", res.Expiry.UTC().Format(time.RFC3339))
	}
	return nil
}
