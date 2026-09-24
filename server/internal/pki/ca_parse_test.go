package pki

// Untrusted-input certificate parsing (ca.go).
//
// ParseCertificatePEMOrDER and ParseCertificateChainPEM sit directly on operator
// and peer input: `secsy-ca lint`/`validate` feed them a file off disk, the
// external-CA import and the SVID/serving-cert paths feed them a chain that came
// over the wire. The interesting question is never "does a good certificate
// parse" — it is what happens to the eleven shapes of not-quite-a-certificate,
// and in particular whether a partially-bad bundle fails closed or silently
// yields a shorter chain than the caller thinks it got.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSignedDER mints a throwaway self-signed certificate with the given serial
// and common name, returning its DER.
func selfSignedDER(t *testing.T, key *ecdsa.PrivateKey, serial int64, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	return der
}

func TestParseCertificatePEMOrDERAccepts(t *testing.T) {
	key := newECDSAKey(t)
	der := selfSignedDER(t, key, 11, "both-encodings.example")

	t.Run("PEM", func(t *testing.T) {
		cert, err := ParseCertificatePEMOrDER(EncodeCertificatePEM(der))
		if err != nil {
			t.Fatalf("ParseCertificatePEMOrDER(PEM): %v", err)
		}
		if !bytes.Equal(cert.Raw, der) {
			t.Error("parsed certificate does not match the input DER")
		}
	})

	t.Run("raw DER", func(t *testing.T) {
		cert, err := ParseCertificatePEMOrDER(der)
		if err != nil {
			t.Fatalf("ParseCertificatePEMOrDER(DER): %v", err)
		}
		if !bytes.Equal(cert.Raw, der) {
			t.Error("parsed certificate does not match the input DER")
		}
	})

	t.Run("PEM with surrounding text", func(t *testing.T) {
		input := []byte("# issued 2026-01-01\n")
		input = append(input, EncodeCertificatePEM(der)...)
		input = append(input, []byte("# end of file\n")...)
		if _, err := ParseCertificatePEMOrDER(input); err != nil {
			t.Fatalf("ParseCertificatePEMOrDER: %v", err)
		}
	})

	t.Run("PEM with CRLF line endings", func(t *testing.T) {
		// A file that made a round trip through Windows still has to parse.
		crlf := bytes.ReplaceAll(EncodeCertificatePEM(der), []byte("\n"), []byte("\r\n"))
		if _, err := ParseCertificatePEMOrDER(crlf); err != nil {
			t.Fatalf("ParseCertificatePEMOrDER(CRLF): %v", err)
		}
	})
}

func TestParseCertificatePEMOrDERRejects(t *testing.T) {
	key := newECDSAKey(t)
	der := selfSignedDER(t, key, 12, "reject.example")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "a-csr.example"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	cases := []struct {
		name string
		// wantMentions, when non-empty, must appear in the error so the operator
		// can tell *why* their file was refused.
		wantMentions string
		input        []byte
	}{
		{name: "nil"},
		{name: "empty", input: []byte{}},
		{name: "plain text", input: []byte("this is not a certificate")},
		{name: "DER with trailing garbage", input: append(append([]byte{}, der...), 0xFF, 0xFF)},
		{name: "truncated DER", input: der[:len(der)/2]},
		// A PEM block whose label is wrong must be named, not silently retried as
		// DER: a CSR in a CERTIFICATE REQUEST block is a plausible operator mistake.
		{name: "CSR in its own armor", wantMentions: "CERTIFICATE REQUEST", input: EncodeCSRPEM(csrDER)},
		{name: "private key block", wantMentions: "PRIVATE KEY", input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		// Right label, wrong payload.
		{name: "CSR mislabeled as a certificate", input: EncodeCertificatePEM(csrDER)},
		{name: "empty CERTIFICATE block", input: []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")},
		// Invalid base64 makes pem.Decode return nothing at all, so the fallback
		// DER parse sees the armor text and both attempts must be reported.
		{name: "invalid base64 body", wantMentions: "tried PEM and DER",
			input: []byte("-----BEGIN CERTIFICATE-----\n@@@@not base64@@@@\n-----END CERTIFICATE-----\n")},
		{name: "unterminated armor", wantMentions: "tried PEM and DER",
			input: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n")},
		// pem.Decode only ever returns the *first* block, so a bundle that leads
		// with a key is refused even though a certificate follows it.
		{name: "key block ahead of the certificate", wantMentions: "PRIVATE KEY",
			input: append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), EncodeCertificatePEM(der)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := ParseCertificatePEMOrDER(tc.input)
			if err == nil {
				t.Fatalf("ParseCertificatePEMOrDER accepted %s", tc.name)
			}
			if cert != nil {
				t.Errorf("returned a certificate alongside error %v", err)
			}
			if tc.wantMentions != "" && !strings.Contains(err.Error(), tc.wantMentions) {
				t.Errorf("error %q does not mention %q", err, tc.wantMentions)
			}
		})
	}
}

// TestParseCertificateChainPEMPreservesOrder is the property every caller relies
// on: the first block is the leaf (or the issued CA) and the rest are its
// issuers in path order. A parser that reordered or deduplicated would build the
// wrong chain while looking like it worked.
func TestParseCertificateChainPEMPreservesOrder(t *testing.T) {
	key := newECDSAKey(t)
	names := []string{"leaf.example", "intermediate.example", "root.example"}
	var bundle []byte
	for i, cn := range names {
		bundle = append(bundle, EncodeCertificatePEM(selfSignedDER(t, key, int64(100+i), cn))...)
	}

	certs, err := ParseCertificateChainPEM(bundle)
	if err != nil {
		t.Fatalf("ParseCertificateChainPEM: %v", err)
	}
	if len(certs) != len(names) {
		t.Fatalf("parsed %d certificates, want %d", len(certs), len(names))
	}
	for i, cn := range names {
		if certs[i] == nil {
			t.Fatalf("certificate %d is nil", i)
		}
		if certs[i].Subject.CommonName != cn {
			t.Errorf("certificate %d = %q, want %q (file order must be preserved)", i, certs[i].Subject.CommonName, cn)
		}
		if certs[i].SerialNumber.Cmp(big.NewInt(int64(100+i))) != 0 {
			t.Errorf("certificate %d serial = %v, want %d", i, certs[i].SerialNumber, 100+i)
		}
	}
}

// TestParseCertificateChainPEMSkipsForeignBlocks documents the deliberate
// leniency: a bundle may carry comments, keys, or CRLs between certificates
// (that is how `cat *.pem > bundle.pem` output tends to look), and only the
// CERTIFICATE blocks are collected.
func TestParseCertificateChainPEMSkipsForeignBlocks(t *testing.T) {
	key := newECDSAKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	leaf := selfSignedDER(t, key, 200, "leaf.example")
	root := selfSignedDER(t, key, 201, "root.example")

	var bundle []byte
	bundle = append(bundle, []byte("subject=CN=leaf.example\nissuer=CN=root.example\n")...)
	bundle = append(bundle, EncodeCertificatePEM(leaf)...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	bundle = append(bundle, []byte("# and now the root\n")...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x00}})...)
	bundle = append(bundle, EncodeCertificatePEM(root)...)
	bundle = append(bundle, []byte("trailing text that is not PEM at all\n")...)

	certs, err := ParseCertificateChainPEM(bundle)
	if err != nil {
		t.Fatalf("ParseCertificateChainPEM: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("parsed %d certificates, want 2 (%v)", len(certs), certs)
	}
	if certs[0].Subject.CommonName != "leaf.example" || certs[1].Subject.CommonName != "root.example" {
		t.Errorf("order = %q, %q", certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}
}

// TestParseCertificateChainPEMFailsClosed is the important negative case. A
// bundle whose second block is corrupt must be rejected outright: returning the
// one certificate that did parse would hand the caller a chain that is missing
// an issuer, and every consumer here treats a short chain as authoritative
// (external-CA import persists it, the SVID path serves it).
func TestParseCertificateChainPEMFailsClosed(t *testing.T) {
	key := newECDSAKey(t)
	good := EncodeCertificatePEM(selfSignedDER(t, key, 300, "good.example"))
	goodDER := selfSignedDER(t, key, 301, "also-good.example")

	cases := []struct {
		name  string
		input []byte
	}{
		{"bad block first", append(EncodeCertificatePEM([]byte{0x30, 0x03, 0x02, 0x01, 0x01}), good...)},
		{"bad block last", append(append([]byte{}, good...), EncodeCertificatePEM([]byte("not der"))...)},
		{"truncated DER in the middle", func() []byte {
			var b []byte
			b = append(b, good...)
			b = append(b, EncodeCertificatePEM(goodDER[:len(goodDER)/2])...)
			b = append(b, EncodeCertificatePEM(goodDER)...)
			return b
		}()},
		{"trailing garbage inside a block", append(append([]byte{}, good...),
			EncodeCertificatePEM(append(append([]byte{}, goodDER...), 0x00))...)},
		{"empty CERTIFICATE block", append(append([]byte{}, good...),
			[]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := ParseCertificateChainPEM(tc.input)
			if err == nil {
				t.Fatalf("accepted a bundle with a malformed certificate, returning %d certs", len(certs))
			}
			if certs != nil {
				t.Errorf("returned a partial chain of %d certificates alongside the error", len(certs))
			}
		})
	}
}

// TestParseCertificateChainPEMNoCertificates pins the documented empty result:
// input with no CERTIFICATE block is not an error, it is an empty chain. Callers
// distinguish the two, so a spurious error here would turn "nothing to import"
// into a failure.
func TestParseCertificateChainPEMNoCertificates(t *testing.T) {
	key := newECDSAKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	cases := map[string][]byte{
		"nil":                   nil,
		"empty":                 {},
		"plain text":            []byte("nothing to see here\n"),
		"only a private key":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"only a CSR":            EncodeCSRPEM([]byte{0x30, 0x00}),
		"unterminated armor":    []byte("-----BEGIN CERTIFICATE-----\nMIIB\n"),
		"invalid base64 body":   []byte("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n"),
		"raw DER without armor": selfSignedDER(t, key, 400, "der-only.example"),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			certs, err := ParseCertificateChainPEM(input)
			if err != nil {
				t.Fatalf("ParseCertificateChainPEM(%s) = error %v, want an empty chain", name, err)
			}
			if len(certs) != 0 {
				t.Errorf("ParseCertificateChainPEM(%s) returned %d certificates", name, len(certs))
			}
		})
	}
}
