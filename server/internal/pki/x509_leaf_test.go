package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// testCA builds a self-signed CA certificate and its signer for unit tests.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := CACertRequest{
		Subject:   pkix.Name{CommonName: "Unit Test CA"},
		PublicKey: key.Public(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	der, err := CreateCACertificate(key, nil, req)
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCreateLeafCertificate(t *testing.T) {
	caCert, caKey := testCA(t)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := CreateLeafCertificate(caKey, caCert, LeafCertRequest{
		Subject:     pkix.Name{CommonName: "leaf.test"},
		PublicKey:   leafKey.Public(),
		Serial:      big.NewInt(2),
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"leaf.test"},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf did not verify: %v", err)
	}
	if leaf.IsCA {
		t.Error("leaf should not be a CA")
	}
	if len(leaf.SubjectKeyId) == 0 {
		t.Error("leaf missing subject key identifier")
	}
	if len(leaf.AuthorityKeyId) == 0 {
		t.Error("leaf missing authority key identifier")
	}
}

func TestCreateLeafRejectsExpiryBeyondIssuer(t *testing.T) {
	caCert, caKey := testCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := CreateLeafCertificate(caKey, caCert, LeafCertRequest{
		Subject:   pkix.Name{CommonName: "too-long.test"},
		PublicKey: leafKey.Public(),
		Serial:    big.NewInt(2),
		NotBefore: time.Now(),
		NotAfter:  caCert.NotAfter.Add(time.Hour), // past issuer expiry
	})
	if err == nil {
		t.Fatal("expected error when leaf outlives issuer")
	}
}

func TestCreateCRL(t *testing.T) {
	caCert, caKey := testCA(t)
	der, err := CreateCRL(caKey, caCert, CRLRequest{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		Revoked: []RevokedEntry{
			{Serial: big.NewInt(42), RevokedAt: time.Now(), Reason: RevocationReasonKeyCompromise},
		},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("unexpected CRL entries: %+v", crl.RevokedCertificateEntries)
	}
}

func TestCreateOCSPResponse(t *testing.T) {
	caCert, caKey := testCA(t)
	respDER, err := CreateOCSPResponse(caKey, caCert, OCSPResponseSpec{
		Serial:     big.NewInt(7),
		Status:     OCSPRevoked,
		RevokedAt:  time.Now(),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Errorf("status = %d, want Revoked", resp.Status)
	}
	if resp.SerialNumber.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("serial = %s, want 7", resp.SerialNumber)
	}
}

func TestParseRevocationReason(t *testing.T) {
	cases := map[string]int{
		"":                     RevocationReasonUnspecified,
		"keyCompromise":        RevocationReasonKeyCompromise,
		"SUPERSEDED":           RevocationReasonSuperseded,
		"cessationOfOperation": RevocationReasonCessationOfOperation,
	}
	for name, want := range cases {
		got, err := ParseRevocationReason(name)
		if err != nil {
			t.Errorf("ParseRevocationReason(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseRevocationReason(%q) = %d, want %d", name, got, want)
		}
	}
	if _, err := ParseRevocationReason("bogus"); err == nil {
		t.Error("expected error for unknown reason")
	}
}
