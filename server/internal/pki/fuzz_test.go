package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// fuzzSelfSigned builds a throwaway self-signed CA certificate used only to
// derive well-formed seed inputs for the parser fuzz targets below. It is not a
// security boundary — the fuzzers exercise the parsers, not this helper.
func fuzzSelfSigned(tb testing.TB) (*x509.Certificate, []byte) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fuzz-seed"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parsing certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

// FuzzParseOCSPRequest drives the DER OCSP-request parser with adversarial
// input. OCSP requests arrive unauthenticated on a public endpoint (both as raw
// POST bodies and base64-decoded GET path segments), so the parser must never
// panic, over-allocate, or return a nil request with a nil error.
func FuzzParseOCSPRequest(f *testing.F) {
	cert, _ := fuzzSelfSigned(f)
	if reqDER, err := ocsp.CreateRequest(cert, cert, nil); err == nil {
		f.Add(reqDER)
	}
	// Known malformed / edge inputs.
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})             // empty SEQUENCE
	f.Add([]byte{0x30, 0x82, 0xff, 0xff}) // long-form length claiming 64 KiB, no body
	f.Add([]byte{0x05, 0x00})             // ASN.1 NULL, not a request
	f.Add([]byte("not-der-at-all"))

	f.Fuzz(func(t *testing.T, der []byte) {
		req, err := ParseOCSPRequest(der)
		if err == nil && req == nil {
			t.Fatalf("ParseOCSPRequest returned a nil request with a nil error for %d bytes", len(der))
		}
	})
}

// FuzzParseCertificatePEM drives the PEM certificate parser. Certificates are
// parsed from operator- and peer-supplied PEM in several code paths (CA config,
// chain validation), so malformed PEM/DER must fail cleanly rather than crash.
func FuzzParseCertificatePEM(f *testing.F) {
	_, validPEM := fuzzSelfSigned(f)
	f.Add(validPEM)
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n" + "QQ==" + "\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("garbage without any pem armor"))

	f.Fuzz(func(t *testing.T, pemBytes []byte) {
		cert, err := ParseCertificatePEM(pemBytes)
		if err == nil && cert == nil {
			t.Fatalf("ParseCertificatePEM returned a nil certificate with a nil error for %d bytes", len(pemBytes))
		}
	})
}
