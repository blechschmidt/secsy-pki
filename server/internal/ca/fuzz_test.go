package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// FuzzParseAndVerifyCSR drives the CSR ingestion path used by the issuance
// layer. A CSR is fully attacker-controlled: it arrives PEM-encoded from the
// REST API and (base64url) from ACME clients, and its DER structure, extensions,
// and self-signature are all untrusted. This target asserts the parser and
// signature check never panic, over-allocate, or return a nil CSR with a nil
// error on adversarial input — tightening the Task 12 hardening invariants that
// no raw CSR content reaches signing without validation.
func FuzzParseAndVerifyCSR(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "fuzz.example.com"},
		DNSNames: []string{"fuzz.example.com"},
	}, key)
	if err != nil {
		f.Fatalf("creating CSR: %v", err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	f.Add(validPEM)
	// Correct PEM armor, but the DER is a certificate not a CSR block type.
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: csrDER}))
	// Raw DER without PEM armor.
	f.Add(csrDER)
	// Valid armor, undecodable body.
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	// Valid armor, empty body.
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("not pem, not der"))

	f.Fuzz(func(t *testing.T, csrPEM []byte) {
		csr, err := parseAndVerifyCSR(csrPEM)
		if err == nil && csr == nil {
			t.Fatalf("parseAndVerifyCSR returned a nil CSR with a nil error for %d bytes", len(csrPEM))
		}
		if err != nil && csr != nil {
			t.Fatalf("parseAndVerifyCSR returned both a CSR and an error for %d bytes", len(csrPEM))
		}
	})
}
