package acme

// Coverage for the exported ARI CertID constructor (draft-ietf-acme-ari §4.1).
// A CertID is how a client names a certificate in a renewalInfo request and in a
// newOrder "replaces" field, so two distinct certificates must never share one:
// a collision would let a client read (or claim to supersede) a certificate it
// does not hold. The expected encoding is recomputed here from the AKI bytes and
// the DER content octets of the serial rather than by calling the implementation.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// derIntegerContent is an independent implementation of the DER INTEGER content
// octets of a non-negative integer: big-endian magnitude, prefixed with 0x00 when
// the top bit of the first byte is set so the value stays positive. This is the
// classic place an encoding bug hides, so the oracle is written out by hand.
func derIntegerContent(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 {
		return []byte{0x00}
	}
	if b[0]&0x80 != 0 {
		return append([]byte{0x00}, b...)
	}
	return b
}

func wantCertID(aki []byte, serial *big.Int) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString(aki) + "." + enc.EncodeToString(derIntegerContent(serial))
}

// certForCertID mints a self-signed certificate carrying the given Authority Key
// Identifier and serial number. Go honors template.AuthorityKeyId for a
// self-signed certificate, so the AKI survives the encode/parse round trip.
func certForCertID(t *testing.T, aki []byte, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: "certid.example.test"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		AuthorityKeyId: aki,
		SubjectKeyId:   []byte{0xde, 0xad, 0xbe, 0xef},
		DNSNames:       []string{"certid.example.test"},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(aki) > 0 && len(cert.AuthorityKeyId) == 0 {
		t.Fatalf("the test certificate lost its AuthorityKeyId; fixture is broken")
	}
	return cert
}

// TestCertID checks the identifier is built from exactly the AKI and the serial's
// DER content octets, including the leading-zero case a positive integer with a
// high top bit carries.
func TestCertID(t *testing.T) {
	aki := []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3,
		0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4}

	cases := []struct {
		name   string
		serial *big.Int
	}{
		{"small-serial", big.NewInt(1)},
		{"high-bit-set-needs-leading-zero", big.NewInt(0x8765_4321)},
		{"high-bit-clear", big.NewInt(0x7765_4321)},
		{"single-byte-0x7f", big.NewInt(0x7f)},
		{"single-byte-0x80-needs-leading-zero", big.NewInt(0x80)},
		{"single-byte-0xff-needs-leading-zero", big.NewInt(0xff)},
		{"20-byte-serial-high-bit-set", new(big.Int).SetBytes([]byte{
			0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13})},
		{"20-byte-serial-high-bit-clear", new(big.Int).SetBytes([]byte{
			0x7f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := certForCertID(t, aki, tc.serial)
			got, err := CertID(cert)
			if err != nil {
				t.Fatalf("CertID: %v", err)
			}
			if want := wantCertID(aki, tc.serial); got != want {
				t.Fatalf("CertID = %q, want %q", got, want)
			}
			// The two halves are raw (unpadded) base64url and there is exactly one
			// separator, which is what parseCertID and the URL router rely on.
			if strings.Count(got, ".") != 1 {
				t.Errorf("CertID %q must contain exactly one %q separator", got, ".")
			}
			if strings.ContainsAny(got, "+/=") {
				t.Errorf("CertID %q must be raw base64url (no +, / or =)", got)
			}
			// And it round-trips back to the certificate's identity.
			parsed, err := parseCertID(got)
			if err != nil {
				t.Fatalf("parseCertID(%q): %v", got, err)
			}
			if string(parsed.AKI) != string(aki) {
				t.Errorf("round-tripped AKI = %x, want %x", parsed.AKI, aki)
			}
			if parsed.Serial.Cmp(tc.serial) != 0 {
				t.Errorf("round-tripped serial = %s, want %s", parsed.Serial, tc.serial)
			}
		})
	}
}

// TestCertIDRejectsUnusableCertificates asserts CertID fails rather than
// inventing an identifier: a nil certificate and a certificate with no Authority
// Key Identifier have no ARI identity at all.
func TestCertIDRejectsUnusableCertificates(t *testing.T) {
	if id, err := CertID(nil); err == nil {
		t.Errorf("CertID(nil) = %q, nil error; want an error", id)
	}
	noAKI := certForCertID(t, nil, big.NewInt(42))
	if len(noAKI.AuthorityKeyId) != 0 {
		t.Fatalf("fixture unexpectedly has an AKI: %x", noAKI.AuthorityKeyId)
	}
	if id, err := CertID(noAKI); err == nil {
		t.Errorf("CertID(cert without AKI) = %q, nil error; want an error", id)
	}
	// A negative serial is not a certificate serial number and must be refused
	// rather than silently encoded.
	if id, err := certIDForCertificate([]byte{0x01, 0x02}, big.NewInt(-1)); err == nil {
		t.Errorf("certIDForCertificate(negative serial) = %q, nil error; want an error", id)
	}
	if id, err := certIDForCertificate([]byte{0x01, 0x02}, nil); err == nil {
		t.Errorf("certIDForCertificate(nil serial) = %q, nil error; want an error", id)
	}
}

// TestCertIDNeverCollides is the property that matters: distinct (AKI, serial)
// pairs must map to distinct CertIDs. The set below includes the pairs that
// collide under the two classic mistakes — concatenating the fields without a
// separator, and encoding the serial as its bare magnitude so 0x80 and 0x0080
// become indistinguishable.
func TestCertIDNeverCollides(t *testing.T) {
	pairs := []struct {
		aki    []byte
		serial *big.Int
	}{
		{[]byte{0x01, 0x02}, big.NewInt(0x03)},
		{[]byte{0x01}, big.NewInt(0x0203)},        // separator-less concatenation collides
		{[]byte{0x01, 0x02, 0x03}, big.NewInt(0)}, // ditto
		{[]byte{0xaa, 0xbb}, big.NewInt(0x80)},
		{[]byte{0xaa, 0xbb}, big.NewInt(0x0180)},
		{[]byte{0xaa, 0xbb}, big.NewInt(0x7f)},
		{[]byte{0xaa, 0xbb}, big.NewInt(0xff)},
		{[]byte{0xaa, 0xbc}, big.NewInt(0xff)}, // AKI differs by one bit
		{[]byte{0xaa, 0xbb, 0x00}, big.NewInt(0xff)},
		{make([]byte, 20), big.NewInt(1)},
	}

	seen := map[string]int{}
	for i, p := range pairs {
		id, err := certIDForCertificate(p.aki, p.serial)
		if err != nil {
			t.Fatalf("certIDForCertificate(%x, %s): %v", p.aki, p.serial, err)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("CertID collision: pair %d (%x, %s) and pair %d produce %q",
				i, p.aki, p.serial, prev, id)
		}
		seen[id] = i
	}
}

// TestCertIDMatchesRealIssuedCertificate confirms CertID and the internal
// certIDForCertificate agree on a parsed certificate, so the exported entry point
// clients use cannot drift from the one the renewalInfo lookup uses.
func TestCertIDMatchesRealIssuedCertificate(t *testing.T) {
	aki := []byte{0x9a, 0x80, 0x00, 0x7f, 0xff}
	serial := new(big.Int).SetBytes([]byte{0x80, 0x00, 0x00, 0x01})
	cert := certForCertID(t, aki, serial)

	exported, err := CertID(cert)
	if err != nil {
		t.Fatalf("CertID: %v", err)
	}
	internal, err := certIDForCertificate(cert.AuthorityKeyId, cert.SerialNumber)
	if err != nil {
		t.Fatalf("certIDForCertificate: %v", err)
	}
	if exported != internal {
		t.Errorf("CertID = %q but certIDForCertificate = %q", exported, internal)
	}
	if want := wantCertID(aki, serial); exported != want {
		t.Errorf("CertID = %q, want %q", exported, want)
	}
}
