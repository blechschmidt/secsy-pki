package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

func intPtr(v int) *int { return &v }

func TestCreateCACertificateRootAndIntermediate(t *testing.T) {
	rootKey := newECDSAKey(t)
	interKey := newECDSAKey(t)
	leafKey := newECDSAKey(t)

	now := time.Now()

	// Self-signed root.
	rootDER, err := CreateCACertificate(rootKey, nil, CACertRequest{
		Subject:    pkix.Name{CommonName: "Test Root CA"},
		PublicKey:  rootKey.Public(),
		Serial:     big.NewInt(1),
		NotBefore:  now.Add(-time.Minute),
		NotAfter:   now.Add(24 * time.Hour),
		MaxPathLen: intPtr(1),
	})
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if !rootCert.IsCA {
		t.Error("root is not marked CA")
	}
	if rootCert.Subject.CommonName != rootCert.Issuer.CommonName {
		t.Errorf("root should be self-signed: subject=%q issuer=%q", rootCert.Subject.CommonName, rootCert.Issuer.CommonName)
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("root self-signature invalid: %v", err)
	}

	// Intermediate signed by root.
	interDER, err := CreateCACertificate(rootKey, rootCert, CACertRequest{
		Subject:    pkix.Name{CommonName: "Test Intermediate CA"},
		PublicKey:  interKey.Public(),
		Serial:     big.NewInt(2),
		NotBefore:  now.Add(-time.Minute),
		NotAfter:   now.Add(12 * time.Hour),
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	if err := interCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}
	if !interCert.MaxPathLenZero {
		t.Error("intermediate should have MaxPathLenZero set")
	}

	// A leaf issued by the intermediate should chain up to the root.
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, leafKey.Public(), interKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(interCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestCreateCACertificateRejectsBadSerial(t *testing.T) {
	key := newECDSAKey(t)
	now := time.Now()
	base := CACertRequest{
		Subject:   pkix.Name{CommonName: "x"},
		PublicKey: key.Public(),
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}
	for _, serial := range []*big.Int{nil, big.NewInt(0), big.NewInt(-5)} {
		req := base
		req.Serial = serial
		if _, err := CreateCACertificate(key, nil, req); err == nil {
			t.Errorf("expected error for serial %v", serial)
		}
	}
}

func TestExtractKeyLabel(t *testing.T) {
	cases := map[string]string{
		"pkcs11:token=secsy;object=root-ca;type=private": "root-ca",
		"pkcs11:object=intermediate":                     "intermediate",
		"software:my-key":                                "my-key",
		"pkcs11:token=secsy;type=private":                "",
		"":                                               "",
	}
	for uri, want := range cases {
		if got := ExtractKeyLabel(uri); got != want {
			t.Errorf("ExtractKeyLabel(%q) = %q, want %q", uri, got, want)
		}
	}
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
