package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// testRSACert builds a self-signed RSA certificate + key for round-trip tests.
func testRSACert(t *testing.T, cn string, serial int64) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func TestEnvelopedDataRoundTrip(t *testing.T) {
	recipient, key := testRSACert(t, "recipient", 1)
	plaintext := []byte("this is a PKCS#10 stand-in payload for SCEP")

	der, err := BuildEnvelopedData(plaintext, recipient)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}

	parsed, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	got, err := parsed.Decrypt(recipient, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEnvelopedDataWrongRecipient(t *testing.T) {
	recipient, _ := testRSACert(t, "recipient", 1)
	other, otherKey := testRSACert(t, "other", 2)

	der, err := BuildEnvelopedData([]byte("secret"), recipient)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	parsed, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatalf("ParseEnvelopedData: %v", err)
	}
	if _, err := parsed.Decrypt(other, otherKey); err == nil {
		t.Fatal("expected decryption failure for a non-recipient certificate")
	}
}

func TestSignedDataRoundTrip(t *testing.T) {
	signer, key := testRSACert(t, "signer", 7)
	content := []byte("degenerate certs-only or arbitrary eContent")

	// A SCEP-style transaction attribute (PrintableString) plus an octet-string
	// nonce, to exercise both value encodings.
	transID := asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	nonce := asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	der, err := BuildSignedData(SignedDataOpts{
		Content:    content,
		SignerCert: signer,
		Signer:     key,
		Digest:     crypto.SHA256,
		ExtraAttrs: []Attribute{
			{Type: transID, Value: "ABCDEF0123"},
			{Type: nonce, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	parsed, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(parsed.Content, content) {
		t.Fatalf("content mismatch: got %q want %q", parsed.Content, content)
	}
	if parsed.SignerCertificate() == nil || parsed.SignerCertificate().SerialNumber.Int64() != 7 {
		t.Fatalf("signer cert not resolved correctly")
	}

	// Transaction ID attribute round-trips as a PrintableString.
	tv, ok := parsed.AuthenticatedAttribute(transID)
	if !ok {
		t.Fatal("transaction-id attribute missing")
	}
	var gotID string
	if _, err := asn1.Unmarshal(tv.FullBytes, &gotID); err != nil {
		t.Fatalf("decoding transaction id: %v", err)
	}
	if gotID != "ABCDEF0123" {
		t.Fatalf("transaction id = %q, want ABCDEF0123", gotID)
	}

	// Nonce attribute round-trips as an OCTET STRING.
	nv, ok := parsed.AuthenticatedAttribute(nonce)
	if !ok {
		t.Fatal("nonce attribute missing")
	}
	var gotNonce []byte
	if _, err := asn1.Unmarshal(nv.FullBytes, &gotNonce); err != nil {
		t.Fatalf("decoding nonce: %v", err)
	}
	if !bytes.Equal(gotNonce, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("nonce mismatch: %x", gotNonce)
	}
}

func TestSignedDataTamperedContentFails(t *testing.T) {
	signer, key := testRSACert(t, "signer", 9)
	der, err := BuildSignedData(SignedDataOpts{
		Content:    []byte("original"),
		SignerCert: signer,
		Signer:     key,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	parsed, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	// Corrupt the recovered content so the messageDigest attribute no longer
	// matches; Verify must reject it.
	parsed.Content = []byte("tampered")
	if err := parsed.Verify(); err == nil {
		t.Fatal("expected verification failure after content tampering")
	}
}

func TestDegenerateCertsOnly(t *testing.T) {
	c1, _ := testRSACert(t, "ca-root", 100)
	c2, _ := testRSACert(t, "ca-inter", 101)

	der, err := DegenerateCertsOnly([]*x509.Certificate{c1, c2})
	if err != nil {
		t.Fatalf("DegenerateCertsOnly: %v", err)
	}
	parsed, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(parsed.Certificates) != 2 {
		t.Fatalf("got %d certs, want 2", len(parsed.Certificates))
	}
	if parsed.Certificates[0].Subject.CommonName != "ca-root" {
		t.Fatalf("unexpected first cert: %s", parsed.Certificates[0].Subject.CommonName)
	}
}
