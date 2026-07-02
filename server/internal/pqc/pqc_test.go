package pqc

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func mustGen(t *testing.T, keyType string) crypto.Signer {
	t.Helper()
	priv, err := GenerateKey(keyType)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", keyType, err)
	}
	return priv
}

func TestKeyRoundTrip(t *testing.T) {
	for _, kt := range []string{KeyTypeMLDSA44, KeyTypeMLDSA65, KeyTypeMLDSA87} {
		priv := mustGen(t, kt)

		p8, err := MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		priv2, gotKT, err := ParsePKCS8PrivateKey(p8)
		if err != nil {
			t.Fatalf("ParsePKCS8: %v", err)
		}
		if gotKT != kt {
			t.Errorf("key type = %q, want %q", gotKT, kt)
		}
		if !priv2.Equal(priv) {
			t.Errorf("%s: private key did not round-trip", kt)
		}

		spki, err := MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			t.Fatalf("MarshalPKIX: %v", err)
		}
		pub2, kt2, err := ParsePKIXPublicKey(spki)
		if err != nil {
			t.Fatalf("ParsePKIX: %v", err)
		}
		if kt2 != kt {
			t.Errorf("pub key type = %q, want %q", kt2, kt)
		}
		if !pub2.(interface{ Equal(crypto.PublicKey) bool }).Equal(priv.Public()) {
			t.Errorf("%s: public key did not round-trip", kt)
		}
	}
}

// TestPurePQCChain builds an ML-DSA root and an ML-DSA leaf and verifies the
// fully post-quantum chain.
func TestPurePQCChain(t *testing.T) {
	rootKey := mustGen(t, KeyTypeMLDSA65)
	leafKey := mustGen(t, KeyTypeMLDSA44)

	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PQC Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := CreateCertificate(rootTmpl, nil, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root (x509 must accept PQC structure): %v", err)
	}
	if !rootCert.IsCA {
		t.Fatal("root not parsed as CA")
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, err := CreateCertificate(leafTmpl, rootCert, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	if err := VerifyChain([][]byte{leafDER, rootDER}, VerifyOptions{}); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	// Tamper: a different key must fail verification.
	otherKey := mustGen(t, KeyTypeMLDSA65)
	if err := VerifyMLDSASignature(leafDER, otherKey.Public()); err == nil {
		t.Fatal("verification unexpectedly succeeded with wrong issuer key")
	}
}
