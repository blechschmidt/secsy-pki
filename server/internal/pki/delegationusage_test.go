package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wantDelegationUsageExtDER is the exact DER of the complete RFC 9345
// id-ce-delegationUsage extension as it appears in a certificate (critical
// omitted, since it is false and DER omits a default BOOLEAN):
//
//	SEQUENCE {
//	  OBJECT IDENTIFIER 1.3.6.1.4.1.44363.44
//	  OCTET STRING { NULL }            -- extnValue wrapping 05 00
//	}
var wantDelegationUsageExtDER = []byte{
	0x30, 0x0f, // SEQUENCE, length 15
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2c, // OID 1.3.6.1.4.1.44363.44
	0x04, 0x02, 0x05, 0x00, // OCTET STRING { 05 00 } = NULL
}

// TestDelegationUsageExtensionKAT is the known-answer test for the extension:
// the OID, its non-criticality, and the exact NULL-valued DER.
func TestDelegationUsageExtensionKAT(t *testing.T) {
	ext := DelegationUsageExtension()

	if !ext.Id.Equal(OIDDelegationUsage) {
		t.Errorf("extension OID = %v, want %v", ext.Id, OIDDelegationUsage)
	}
	if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}) {
		t.Errorf("extension OID = %v, want 1.3.6.1.4.1.44363.44", ext.Id)
	}
	if ext.Critical {
		t.Errorf("extension marked critical; RFC 9345 §4.2 requires non-critical")
	}
	// The value is the DER of an ASN.1 NULL: 05 00.
	if want := []byte{0x05, 0x00}; !bytes.Equal(ext.Value, want) {
		t.Errorf("extension value = % x, want % x (DER NULL)", ext.Value, want)
	}
	// ParseDelegationUsage must accept its own output.
	if err := ParseDelegationUsage(ext.Value); err != nil {
		t.Errorf("ParseDelegationUsage(own value) = %v, want nil", err)
	}

	// Marshal the complete extension (OID + extnValue OCTET STRING) and compare to
	// the byte-for-byte expected DER.
	fullDER, err := asn1.Marshal(struct {
		ID  asn1.ObjectIdentifier
		Val []byte
	}{ext.Id, ext.Value})
	if err != nil {
		t.Fatalf("marshaling extension: %v", err)
	}
	if !bytes.Equal(fullDER, wantDelegationUsageExtDER) {
		t.Errorf("full extension DER =\n  % x\nwant\n  % x", fullDER, wantDelegationUsageExtDER)
	}
}

// TestDelegationUsageExtensionOpenSSLKAT feeds the exact extension DER to
// `openssl asn1parse` and confirms OpenSSL decodes the OID and the ASN.1 NULL
// value — an independent, tool-based known-answer check.
func TestDelegationUsageExtensionOpenSSLKAT(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}
	dir := t.TempDir()

	// (1) The whole extension: SEQUENCE { OID, OCTET STRING { NULL } }.
	extFile := filepath.Join(dir, "ext.der")
	if err := os.WriteFile(extFile, wantDelegationUsageExtDER, 0o600); err != nil {
		t.Fatalf("writing extension DER: %v", err)
	}
	out, err := exec.Command(openssl, "asn1parse", "-inform", "DER", "-in", extFile).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse (extension): %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"SEQUENCE", "OBJECT", "1.3.6.1.4.1.44363.44", "OCTET STRING"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl asn1parse output missing %q:\n%s", want, text)
		}
	}

	// (2) The extnValue on its own must parse as a bare NULL.
	valFile := filepath.Join(dir, "val.der")
	if err := os.WriteFile(valFile, DelegationUsageExtension().Value, 0o600); err != nil {
		t.Fatalf("writing value DER: %v", err)
	}
	out, err = exec.Command(openssl, "asn1parse", "-inform", "DER", "-in", valFile).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse (value): %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "NULL") {
		t.Errorf("openssl asn1parse did not render the value as NULL:\n%s", out)
	}
}

// TestDelegationUsageRoundTripThroughCertificate proves the extension survives
// crypto/x509 marshaling and re-parsing unchanged (non-critical, value 05 00),
// and that HasDelegationUsage detects it.
func TestDelegationUsageRoundTripThroughCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "delegation.example.com"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		DNSNames:        []string{"delegation.example.com"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{DelegationUsageExtension()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	if !HasDelegationUsage(cert) {
		t.Fatalf("HasDelegationUsage = false, want true")
	}
	var found *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(OIDDelegationUsage) {
			found = &cert.Extensions[i]
			break
		}
	}
	if found == nil {
		t.Fatal("id-ce-delegationUsage extension not present in the issued certificate")
	}
	if found.Critical {
		t.Error("id-ce-delegationUsage extension marked critical in the issued certificate")
	}
	if want := []byte{0x05, 0x00}; !bytes.Equal(found.Value, want) {
		t.Errorf("extension value in cert = % x, want % x", found.Value, want)
	}

	// A certificate without the extension must not be detected as DC-eligible.
	plain := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "plain.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	plainDER, err := x509.CreateCertificate(rand.Reader, plain, plain, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating plain certificate: %v", err)
	}
	plainCert, err := x509.ParseCertificate(plainDER)
	if err != nil {
		t.Fatalf("parsing plain certificate: %v", err)
	}
	if HasDelegationUsage(plainCert) {
		t.Error("HasDelegationUsage = true for a certificate without the extension")
	}
}

// TestParseDelegationUsage covers acceptance of the NULL and empty encodings and
// rejection of malformed values.
func TestParseDelegationUsage(t *testing.T) {
	cases := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{"null", []byte{0x05, 0x00}, false},
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"trailing", []byte{0x05, 0x00, 0x00}, true},
		{"not-null-boolean", []byte{0x01, 0x01, 0xff}, true},
		{"truncated", []byte{0x05}, true},
		{"null-with-content", []byte{0x05, 0x01, 0x00}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ParseDelegationUsage(tc.value)
			if tc.wantErr && err == nil {
				t.Errorf("ParseDelegationUsage(% x) = nil, want error", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ParseDelegationUsage(% x) = %v, want nil", tc.value, err)
			}
		})
	}
}
