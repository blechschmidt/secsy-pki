package pqc

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

func TestPQCCSRRoundTrip(t *testing.T) {
	priv := mustGen(t, KeyTypeMLDSA65)
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "pqc-csr.example.com"},
		DNSNames: []string{"pqc-csr.example.com", "alt.example.com"},
	}
	der, err := CreatePQCCSR(tmpl, priv)
	if err != nil {
		t.Fatalf("CreatePQCCSR: %v", err)
	}
	csr, err := ParsePQCCSR(der)
	if err != nil {
		t.Fatalf("ParsePQCCSR: %v", err)
	}
	if csr.Subject.CommonName != "pqc-csr.example.com" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.Parsed.DNSNames) != 2 {
		t.Errorf("DNSNames = %v", csr.Parsed.DNSNames)
	}
	if csr.KeyType != KeyTypeMLDSA65 {
		t.Errorf("key type = %q", csr.KeyType)
	}

	// A tampered CRI (flip a subject byte) must fail signature verification.
	bad := append([]byte(nil), der...)
	// Corrupt a byte well inside the structure.
	bad[30] ^= 0xff
	if _, err := ParsePQCCSR(bad); err == nil {
		t.Fatal("tampered CSR unexpectedly verified")
	}
}

// TestPQCLeafFromCSR issues a pure-PQC leaf whose subject key comes from a
// PQC CSR and verifies the chain.
func TestPQCLeafFromCSR(t *testing.T) {
	rootKey := mustGen(t, KeyTypeMLDSA87)
	now := time.Now()
	rootDER, err := CreateCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PQC Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey := mustGen(t, KeyTypeMLDSA44)
	csrDER, err := CreatePQCCSR(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device-42"},
		DNSNames: []string{"device-42.iot.example"},
	}, leafKey)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := ParsePQCCSR(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	leafDER, err := CreateCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.Parsed.DNSNames,
	}, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	if err := VerifyChain([][]byte{leafDER, rootDER}, VerifyOptions{}); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestHybridChain builds a hybrid root and hybrid leaf and verifies both the
// classical and the ML-DSA signature dimensions.
func TestHybridChain(t *testing.T) {
	rootClassical, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootAlt := mustGen(t, KeyTypeMLDSA65)
	now := time.Now()

	rootDER, err := CreateHybridCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Hybrid Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, rootClassical.Public(), rootAlt.Public(), rootClassical, rootAlt)
	if err != nil {
		t.Fatalf("hybrid root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse hybrid root: %v", err)
	}
	if !IsHybridCertificate(rootCert) {
		t.Fatal("root not detected as hybrid")
	}
	// The classical primary signature must verify with an ordinary verifier.
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("classical self-signature: %v", err)
	}

	leafClassical, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafAlt := mustGen(t, KeyTypeMLDSA65)
	leafDER, err := CreateHybridCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "hybrid-leaf.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"hybrid-leaf.example.com"},
	}, rootCert, leafClassical.Public(), leafAlt.Public(), rootClassical, rootAlt)
	if err != nil {
		t.Fatalf("hybrid leaf: %v", err)
	}

	// Full hybrid verification (both dimensions).
	if err := VerifyHybridChain([][]byte{leafDER, rootDER}, VerifyOptions{}); err != nil {
		t.Fatalf("VerifyHybridChain: %v", err)
	}

	// Classical-only verification must also succeed via the standard library.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	leafCert, _ := x509.ParseCertificate(leafDER)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("classical x509.Verify: %v", err)
	}

	// Wrong alt key must fail the alternative dimension.
	if err := VerifyHybridAltSignature(leafDER, mustGen(t, KeyTypeMLDSA65).Public()); err == nil {
		t.Fatal("alt verification unexpectedly succeeded with wrong key")
	}
}

func TestHybridCSRRoundTrip(t *testing.T) {
	classical, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alt := mustGen(t, KeyTypeMLDSA65)
	der, err := CreateHybridCSR(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "hybrid-csr.example.com"},
		DNSNames: []string{"hybrid-csr.example.com"},
	}, classical, alt)
	if err != nil {
		t.Fatalf("CreateHybridCSR: %v", err)
	}
	csr, err := ParseHybridCSR(der)
	if err != nil {
		t.Fatalf("ParseHybridCSR: %v", err)
	}
	if csr.AltKeyType != KeyTypeMLDSA65 {
		t.Errorf("alt key type = %q", csr.AltKeyType)
	}
	if csr.PrimaryKey == nil {
		t.Error("primary key not recovered")
	}
	eq, ok := csr.AltKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok || !eq.Equal(alt.Public()) {
		t.Error("recovered alt key does not match the original")
	}
}
