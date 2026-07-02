package spiffe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// selfSignedCA builds a minimal self-signed CA certificate for bundle tests.
func selfSignedCA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBuildAndParseBundle(t *testing.T) {
	root := selfSignedCA(t, "Test Root CA")
	intermediate := selfSignedCA(t, "Test Intermediate CA")

	data, err := BuildBundle([]*x509.Certificate{intermediate, root}, 90*time.Second, 7)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	// Structural checks on the JWKS shape.
	var doc struct {
		Keys        []map[string]any `json:"keys"`
		RefreshHint *int64           `json:"spiffe_refresh_hint"`
		Sequence    *int64           `json:"spiffe_sequence"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("bundle has %d keys, want 2", len(doc.Keys))
	}
	if doc.RefreshHint == nil || *doc.RefreshHint != 90 {
		t.Errorf("spiffe_refresh_hint = %v, want 90", doc.RefreshHint)
	}
	if doc.Sequence == nil || *doc.Sequence != 7 {
		t.Errorf("spiffe_sequence = %v, want 7", doc.Sequence)
	}
	for i, k := range doc.Keys {
		if k["use"] != "x509-svid" {
			t.Errorf("key %d use = %v, want x509-svid", i, k["use"])
		}
		if _, ok := k["x5c"]; !ok {
			t.Errorf("key %d missing x5c", i)
		}
	}

	// Round-trip: the parsed authorities must match the inputs.
	got, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ParseBundle returned %d certs, want 2", len(got))
	}
	if !got[0].Equal(intermediate) {
		t.Error("first parsed authority is not the intermediate")
	}
	if !got[1].Equal(root) {
		t.Error("second parsed authority is not the root")
	}
}

func TestBuildBundleRejectsNonCA(t *testing.T) {
	// A leaf certificate (IsCA=false) must not be accepted as a trust anchor.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	if _, err := BuildBundle([]*x509.Certificate{leaf}, 0, 0); err == nil {
		t.Error("BuildBundle should reject a non-CA certificate")
	}
}

func TestBuildBundleEmpty(t *testing.T) {
	if _, err := BuildBundle(nil, 0, 0); err == nil {
		t.Error("BuildBundle(nil) should error")
	}
}
