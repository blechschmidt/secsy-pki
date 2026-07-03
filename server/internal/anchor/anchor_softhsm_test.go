//go:build sqlite

package anchor

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// TestSoftHSMAnchorHappyPath is the Task 64 end-to-end check against real
// PKCS#11: the audit chain head is anchored with a token signed entirely on
// the SoftHSM token, verification passes, and a post-anchor truncation is
// caught. Skipped unless the SoftHSM environment variables are exported (run:
// eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMAnchorHappyPath(t *testing.T) {
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
	suffix := time.Now().Format("150405") + "-" + anchorRandHex(t)
	caLabel := "test-anchor-ca-" + suffix
	tsaLabel := "test-anchor-tsa-" + suffix

	// Self-signed RSA CA and TSA certificate, both keys on the HSM.
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
		Subject:   pkix.Name{CommonName: "SoftHSM Anchor Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
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
		Subject:   pkix.Name{CommonName: "SoftHSM Anchor TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
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
		KeyLabel:    tsaLabel,
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
		Accuracy:    tsa.Accuracy{Seconds: 1},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}

	// Seed a store, anchor its head with the HSM-signed token, verify.
	db, path := anchorTestDB(t)
	appendEvents(t, db, 4)
	svc := NewService(db, NewAuthorityTimestamper(authority))
	res, err := svc.AnchorOnce(ctx, false)
	if err != nil {
		t.Fatalf("AnchorOnce (SoftHSM): %v", err)
	}
	if res.Skipped || res.Anchor.Seq != 4 {
		t.Fatalf("expected an anchor over seq 4, got %+v", res)
	}

	chainRes, checks := verifyAll(t, db, []*x509.Certificate{caCert})
	if !chainRes.Valid {
		t.Fatalf("chain should verify: %+v", chainRes)
	}
	if len(checks) != 1 || !checks[0].Valid {
		t.Fatalf("HSM-signed anchor should verify: %+v", checks)
	}
	if seq, _, action, _ := db.EventLogHead(); seq != 5 || action != audit.ActionAuditAnchor {
		t.Fatalf("audit.anchor event missing: head=(%d, %s)", seq, action)
	}

	// Truncating behind the anchor must fail verification even though the
	// remaining prefix is a valid chain.
	raw := rawConn(t, path)
	if _, err := raw.Exec(`DELETE FROM event_log WHERE seq > 2`); err != nil {
		t.Fatal(err)
	}
	chainRes, checks = verifyAll(t, db, []*x509.Certificate{caCert})
	if !chainRes.Valid {
		t.Fatalf("truncated prefix should be a valid chain: %+v", chainRes)
	}
	if checks[0].Valid {
		t.Fatalf("anchor must catch the truncation: %+v", checks[0])
	}
}

func anchorRandHex(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	const hex = "0123456789abcdef"
	return string([]byte{hex[b[0]&0xf], hex[b[1]&0xf], hex[b[2]&0xf]})
}
