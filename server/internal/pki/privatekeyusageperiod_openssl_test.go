package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPrivateKeyUsagePeriod_OpenSSLAsn1Parse decodes the hand-rolled extension
// value with `openssl asn1parse` and confirms an independent ASN.1 decoder sees
// exactly the RFC 5280 structure: a SEQUENCE of two IMPLICIT context-tagged
// primitives (the [0] notBefore and [1] notAfter GeneralizedTimes), each 15
// bytes, with no decode error. This is the known-answer test for the DER.
func TestPrivateKeyUsagePeriod_OpenSSLAsn1Parse(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	nb := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	na := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ext, err := PrivateKeyUsagePeriod{NotBefore: nb, NotAfter: na}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}

	path := filepath.Join(t.TempDir(), "pkup.der")
	if err := os.WriteFile(path, ext.Value, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := exec.Command(openssl, "asn1parse", "-inform", "DER", "-in", path).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse failed: %v\n%s", err, out)
	}
	text := string(out)
	// The outer SEQUENCE and two 15-byte IMPLICIT context primitives ([0]/[1]).
	// IMPLICIT tagging hides the universal GeneralizedTime type, so openssl renders
	// them as "cont [ 0 ]" / "cont [ 1 ]" rather than "GENERALIZEDTIME".
	for _, want := range []string{"SEQUENCE", "cont [ 0 ]", "cont [ 1 ]", "l=  15"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl asn1parse output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "error") || strings.Contains(text, "BAD") {
		t.Errorf("openssl reported a decode error:\n%s", text)
	}
}

// TestPrivateKeyUsagePeriod_OpenSSLx509 issues a self-signed certificate carrying
// the extension and confirms `openssl x509 -text` parses the whole certificate
// without error and surfaces the extension (by OID or name), proving the DER is
// well-formed in context against an independent implementation.
func TestPrivateKeyUsagePeriod_OpenSSLx509(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	nb := time.Now().Add(-time.Hour)
	ext, err := PrivateKeyUsagePeriod{
		NotBefore: nb,
		NotAfter:  nb.Add(180 * 24 * time.Hour), // key retires well before the cert
	}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "signer.example"},
		NotBefore:       nb,
		NotAfter:        nb.Add(365 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// crypto/x509 must round-trip it too (non-critical, so it lands in Extensions).
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pkup, present, err := PrivateKeyUsagePeriodFromCertificate(cert)
	if err != nil || !present || pkup.NotBefore.IsZero() || pkup.NotAfter.IsZero() {
		t.Fatalf("PrivateKeyUsagePeriodFromCertificate = (%+v, %v, %v)", pkup, present, err)
	}

	path := filepath.Join(t.TempDir(), "signer.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := exec.Command(openssl, "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	text := string(out)
	// OpenSSL labels the extension "Private Key Usage Period"; older builds may only
	// print the OID. Accept either so the test is robust across versions.
	if !strings.Contains(text, "Private Key Usage Period") &&
		!strings.Contains(text, "X509v3 Private Key Usage Period") &&
		!strings.Contains(text, "2.5.29.16") {
		t.Errorf("openssl output does not mention the privateKeyUsagePeriod extension:\n%s", text)
	}
	if strings.Contains(text, "BAD ENCODING") {
		t.Errorf("openssl reported a decode error:\n%s", text)
	}
}
