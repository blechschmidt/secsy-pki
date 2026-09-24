package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
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

// FuzzParseCSRPEM drives the PKCS#10 parser. CSRs arrive unauthenticated at the
// EST, SCEP, ACME and MS-WSTEP endpoints, so the parser must never panic, and —
// because ParseCSRPEM also verifies the self-signature — must never return a
// request with a nil error unless that signature actually checked out.
func FuzzParseCSRPEM(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	if der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "fuzz-seed"},
		DNSNames: []string{"fuzz.example"},
	}, key); err == nil {
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		f.Add(der) // raw DER: must be refused, not parsed
		// A seed whose signature no longer matches the body.
		if i := bytes.Index(der, []byte("fuzz-seed")); i >= 0 {
			tampered := append([]byte{}, der...)
			tampered[i] = 'F'
			f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))
		}
	}
	_, certPEM := fuzzSelfSigned(f)
	f.Add(certPEM) // right shape, wrong block type
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"))

	f.Fuzz(func(t *testing.T, pemBytes []byte) {
		csr, err := ParseCSRPEM(pemBytes)
		if err == nil && csr == nil {
			t.Fatalf("ParseCSRPEM returned a nil request with a nil error for %d bytes", len(pemBytes))
		}
		if err == nil {
			// The whole point of the function is the proof-of-possession check, so
			// anything it accepts must still verify on a second look.
			if verr := csr.CheckSignature(); verr != nil {
				t.Fatalf("ParseCSRPEM accepted a CSR whose signature does not verify: %v", verr)
			}
		}
		if err != nil && csr != nil {
			t.Fatalf("ParseCSRPEM returned a request alongside error %v", err)
		}
	})
}

// FuzzParseCertificateChainPEM drives the bundle parser. Chains come from
// operator files and from remote peers (external-CA import, SVID, serving-cert
// refresh), and the invariant that matters is fail-closed: on error the caller
// must get nothing, never a truncated chain it would treat as complete.
func FuzzParseCertificateChainPEM(f *testing.F) {
	_, certPEM := fuzzSelfSigned(f)
	f.Add(certPEM)
	f.Add(append(append([]byte{}, certPEM...), certPEM...))
	f.Add(append([]byte("leading comment\n"), certPEM...))
	f.Add(append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...))
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte(strings.Repeat("-----BEGIN CERTIFICATE-----\n", 64)))

	f.Fuzz(func(t *testing.T, pemBytes []byte) {
		certs, err := ParseCertificateChainPEM(pemBytes)
		if err != nil {
			if certs != nil {
				t.Fatalf("ParseCertificateChainPEM returned %d certificates alongside error %v", len(certs), err)
			}
			return
		}
		for i, c := range certs {
			if c == nil {
				t.Fatalf("ParseCertificateChainPEM returned a nil certificate at index %d", i)
			}
			if len(c.Raw) == 0 {
				t.Fatalf("certificate %d has no raw bytes", i)
			}
		}
	})
}

// FuzzOCSPResponseNonce drives the hand-rolled OCSP response decoder. Responses
// are fetched from remote responders (the TLS stapler) and their nonce is read
// without any signature check first, so the decoder is reachable with arbitrary
// bytes. It must not panic, and on error it must not hand back a nonce a caller
// could compare against.
func FuzzOCSPResponseNonce(f *testing.F) {
	cert, _ := fuzzSelfSigned(f)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	// A real, well-formed signed response carrying a nonce.
	if respDER, err := CreateOCSPResponse(key, cert, OCSPResponseSpec{
		Serial:     big.NewInt(1),
		Status:     ocsp.Good,
		ThisUpdate: time.Unix(0, 0),
		NextUpdate: time.Unix(1<<31-1, 0),
		Nonce:      []byte("0123456789abcdef"),
	}); err == nil {
		f.Add(respDER)
	}
	f.Add(OCSPMalformedResponse)
	f.Add(OCSPTryLaterResponse)
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	f.Add([]byte{0x05, 0x00})
	f.Add([]byte("not a response"))

	f.Fuzz(func(t *testing.T, der []byte) {
		nonce, err := OCSPResponseNonce(der)
		if err != nil && nonce != nil {
			t.Fatalf("OCSPResponseNonce returned %d nonce bytes alongside error %v", len(nonce), err)
		}
		// The same bytes go through the other unauthenticated accessors; none may
		// panic either.
		_, _ = OCSPResponseNextUpdate(der)
		_, _, _ = OCSPResponseValidity(der)
		_, _ = OCSPRequestSerial(der)
	})
}

// FuzzParseCertificatePEMOrDER drives the dual-encoding parser used by
// `secsy-ca lint`/`validate` and the blocked-key and public-key search commands,
// all of which read a file whose encoding is not known in advance.
func FuzzParseCertificatePEMOrDER(f *testing.F) {
	cert, certPEM := fuzzSelfSigned(f)
	f.Add(certPEM)
	f.Add(cert.Raw)
	f.Add(append(append([]byte{}, cert.Raw...), 0x00))
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseCertificatePEMOrDER(data)
		if err == nil && got == nil {
			t.Fatalf("ParseCertificatePEMOrDER returned a nil certificate with a nil error for %d bytes", len(data))
		}
		if err != nil && got != nil {
			t.Fatalf("ParseCertificatePEMOrDER returned a certificate alongside error %v", err)
		}
	})
}
