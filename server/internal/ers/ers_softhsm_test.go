package ers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// TestSoftHSMEvidenceRecord is the end-to-end check against real PKCS#11: an
// Evidence Record is generated and both-kind-renewed with archive timestamps
// signed entirely on the SoftHSM token, and verified against the HSM-resident
// TSA trust anchor. Skipped unless the SoftHSM environment variables are exported
// (run: eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMEvidenceRecord(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	provider, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	ctx := context.Background()
	suffix := time.Now().Format("150405") + "-" + ersRandHex(t)
	caLabel := "test-ers-ca-" + suffix
	tsaLabel := "test-ers-tsa-" + suffix

	// Self-signed RSA CA and TSA certificate, both keys resident on the HSM.
	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: caLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: caLabel})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM ERS Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: tsaLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, _ := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM ERS TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(36 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	authority, err := tsa.New(nil, provider, tsa.Config{
		KeyLabel:       tsaLabel,
		Certificate:    tsaCert,
		Chain:          []*x509.Certificate{tsaCert, caCert},
		Accuracy:       tsa.Accuracy{Seconds: 1},
		AcceptedHashes: []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}
	ts := NewAuthorityTimestamper(authority)
	roots := []*x509.Certificate{caCert}

	// Generate an Evidence Record over several objects (HSM-signed SHA-256 token).
	objs := objects("audit-1", "audit-2", "audit-3")
	er, err := Generate(ctx, ts, GenerateOptions{Objects: objs, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Generate (SoftHSM): %v", err)
	}
	res, err := Verify(er, VerifyOptions{Objects: objs, Roots: roots})
	if err != nil || !res.Valid {
		t.Fatalf("verify HSM-signed record: err=%v result=%+v", err, res)
	}

	// Time-stamp renewal (HSM-signed), still one chain.
	er, err = er.RenewTimestamp(ctx, ts)
	if err != nil {
		t.Fatalf("RenewTimestamp (SoftHSM): %v", err)
	}
	if er.ChainCount() != 1 {
		t.Fatalf("time-stamp renewal must stay in one chain, got %d", er.ChainCount())
	}

	// Hash-tree renewal to SHA-512 (HSM-signed with a SHA-512 imprint), new chain.
	er, err = er.RenewHashTree(ctx, ts, objs, crypto.SHA512)
	if err != nil {
		t.Fatalf("RenewHashTree (SoftHSM): %v", err)
	}
	if er.ChainCount() != 2 {
		t.Fatalf("hash-tree renewal must add a chain, got %d", er.ChainCount())
	}
	if cur, _ := er.CurrentHash(); cur != crypto.SHA512 {
		t.Fatalf("current hash after renewal = %v, want SHA-512", cur)
	}

	// The two-chain, HSM-signed record must still verify against the HSM CA root,
	// after a DER round-trip.
	der, err := er.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res, err = Verify(reparsed, VerifyOptions{Objects: objs, Roots: roots})
	if err != nil {
		t.Fatalf("Verify renewed (SoftHSM): %v", err)
	}
	if !res.Valid {
		t.Fatalf("HSM-signed renewed record should verify: %s", res.Reason)
	}
	for _, o := range res.Objects {
		if !o.Covered {
			t.Fatalf("object %q must remain covered after HSM-signed hash-tree renewal", o.ID)
		}
	}
}

func ersRandHex(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	const hexdig = "0123456789abcdef"
	return string([]byte{hexdig[b[0]&0xf], hexdig[b[1]&0xf], hexdig[b[2]&0xf]})
}
