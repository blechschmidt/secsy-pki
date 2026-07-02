package cms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// The CMS parsers consume attacker-controlled DER off the SCEP/EST wire, so they
// must never panic on malformed input — only return an error. These fuzz targets
// seed with well-formed structures and let the fuzzer mutate toward edge cases.

func FuzzParseSignedData(f *testing.F) {
	signer, key := fuzzCert(f)
	if good, err := BuildSignedData(SignedDataOpts{Content: []byte("seed"), SignerCert: signer, Signer: key}); err == nil {
		f.Add(good)
	}
	if certs, err := DegenerateCertsOnly([]*x509.Certificate{signer}); err == nil {
		f.Add(certs)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseSignedData(data)
		if err != nil {
			return
		}
		// Verify must also be panic-free on parsed-but-untrusted input.
		_ = p.Verify()
	})
}

func FuzzParseEnvelopedData(f *testing.F) {
	recipient, _ := fuzzCert(f)
	if good, err := BuildEnvelopedData([]byte("seed payload"), recipient); err == nil {
		f.Add(good)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseEnvelopedData(data)
	})
}

// fuzzCert builds a throwaway self-signed RSA certificate + key for seeding.
func fuzzCert(f *testing.F) (*x509.Certificate, *rsa.PrivateKey) {
	f.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatal(err)
	}
	return cert, key
}
