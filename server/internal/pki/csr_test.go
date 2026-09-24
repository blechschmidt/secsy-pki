package pki

// DER encoding of the keyUsage BIT STRING and the CA CSR (csr.go).
//
// X.509 numbers key-usage bits from the *most significant* bit of the BIT STRING
// (RFC 5280 §4.2.1.3), while x509.KeyUsage is an ordinary little-endian bitmask.
// The conversion therefore reverses the bits within each byte and then trims
// trailing zero bits from the BIT STRING length, which is exactly the shape of
// code an off-by-one lives in. Everything below is checked against an
// independent oracle — math/bits for the reversal, and crypto/x509's own
// extension encoder for the finished BIT STRING — so a wrong bit order, a wrong
// unused-bit count, or a missing trailing-byte trim fails the test rather than
// silently shipping a certificate that asserts the wrong usages.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
	"testing"
	"time"
)

// keyUsageExtValue returns the raw value of the keyUsage extension (2.5.29.15)
// that crypto/x509 itself emits for ku, by minting a certificate and reading the
// extension back out of the parsed result. crypto/x509 is an independent
// implementation of the same RFC 5280 rule, which is what makes it a usable
// oracle for KeyUsageBitString.
func keyUsageExtValue(t *testing.T, key *ecdsa.PrivateKey, ku x509.KeyUsage) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ku-oracle"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     ku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate(KeyUsage=%d): %v", ku, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(KeyUsage=%d): %v", ku, err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionKeyUsage) {
			return ext.Value
		}
	}
	t.Fatalf("crypto/x509 emitted no keyUsage extension for KeyUsage=%d", ku)
	return nil
}

// certWithExtraExtension mints a self-signed certificate carrying ext verbatim
// and returns the parsed result, so a hand-rolled extension can be handed back
// to crypto/x509's parser for validation.
func certWithExtraExtension(t *testing.T, key *ecdsa.PrivateKey, ext pkix.Extension) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "ext-roundtrip"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestReverseBitsMatchesMathBits pins the per-byte reversal against
// math/bits.Reverse8 for all 256 inputs. A hand-written loop over bit positions
// is the classic place to write 7-i when i-7 was meant; the stdlib is the oracle.
func TestReverseBitsMatchesMathBits(t *testing.T) {
	for i := 0; i < 256; i++ {
		b := byte(i)
		if got, want := reverseBits(b), bits.Reverse8(b); got != want {
			t.Errorf("reverseBits(%#02x) = %#02x, want %#02x", b, got, want)
		}
		// Reversal is an involution: applying it twice must restore the byte.
		if got := reverseBits(reverseBits(b)); got != b {
			t.Errorf("reverseBits(reverseBits(%#02x)) = %#02x", b, got)
		}
	}
}

// TestKeyUsageBitStringNamedConstants pins every x509.KeyUsage constant to the
// exact DER its RFC 5280 bit position demands, spelled out so a regression names
// the usage that moved rather than a bitmask.
func TestKeyUsageBitStringNamedConstants(t *testing.T) {
	cases := []struct {
		name string
		ku   x509.KeyUsage
		want []byte // DER BIT STRING: 03 len unusedBits bytes...
	}{
		// Bit 0 is the most significant bit of the first octet, so
		// digitalSignature is 0x80 with seven unused bits, and each subsequent
		// usage shifts one bit right and consumes one more bit of length.
		{"digitalSignature", x509.KeyUsageDigitalSignature, []byte{0x03, 0x02, 0x07, 0x80}},
		{"contentCommitment", x509.KeyUsageContentCommitment, []byte{0x03, 0x02, 0x06, 0x40}},
		{"keyEncipherment", x509.KeyUsageKeyEncipherment, []byte{0x03, 0x02, 0x05, 0x20}},
		{"dataEncipherment", x509.KeyUsageDataEncipherment, []byte{0x03, 0x02, 0x04, 0x10}},
		{"keyAgreement", x509.KeyUsageKeyAgreement, []byte{0x03, 0x02, 0x03, 0x08}},
		{"keyCertSign", x509.KeyUsageCertSign, []byte{0x03, 0x02, 0x02, 0x04}},
		{"cRLSign", x509.KeyUsageCRLSign, []byte{0x03, 0x02, 0x01, 0x02}},
		{"encipherOnly", x509.KeyUsageEncipherOnly, []byte{0x03, 0x02, 0x00, 0x01}},
		// decipherOnly is bit 8: it is the only usage that needs a second octet,
		// and the first octet must still be emitted (as zero) ahead of it.
		{"decipherOnly", x509.KeyUsageDecipherOnly, []byte{0x03, 0x03, 0x07, 0x00, 0x80}},
		// Combinations: the TLS RSA server pair, the CA set CreateCACSR requests,
		// and a set spanning both octets.
		{"digitalSignature|keyEncipherment", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]byte{0x03, 0x02, 0x05, 0xA0}},
		{"certSign|cRLSign|digitalSignature", x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			[]byte{0x03, 0x02, 0x01, 0x86}},
		{"keyEncipherment|dataEncipherment|decipherOnly",
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDecipherOnly,
			[]byte{0x03, 0x03, 0x07, 0x30, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KeyUsageBitString(tc.ku)
			if err != nil {
				t.Fatalf("KeyUsageBitString: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("KeyUsageBitString(%d) = %x, want %x", tc.ku, got, tc.want)
			}
		})
	}
}

// TestKeyUsageBitStringMatchesGoEncoder sweeps every representable key-usage
// combination (1..511: nine defined bits) and requires the hand-rolled BIT
// STRING to be byte-identical to the one crypto/x509 puts in the certificate it
// mints. It also requires crypto/x509's *parser* to recover the original mask
// from our bytes, so both directions of the bit numbering are pinned.
func TestKeyUsageBitStringMatchesGoEncoder(t *testing.T) {
	key := newECDSAKey(t)
	const allDefinedBits = 1 << 9 // digitalSignature(0)..decipherOnly(8)
	for i := 1; i < allDefinedBits; i++ {
		ku := x509.KeyUsage(i)
		got, err := KeyUsageBitString(ku)
		if err != nil {
			t.Fatalf("KeyUsageBitString(%d): %v", i, err)
		}
		if want := keyUsageExtValue(t, key, ku); !bytes.Equal(got, want) {
			t.Fatalf("KeyUsage=%d: KeyUsageBitString = %x, crypto/x509 emits %x", i, got, want)
		}
		ext, err := marshalKeyUsage(ku)
		if err != nil {
			t.Fatalf("marshalKeyUsage(%d): %v", i, err)
		}
		if cert := certWithExtraExtension(t, key, ext); cert.KeyUsage != ku {
			t.Fatalf("KeyUsage=%d round-tripped through crypto/x509 as %d", i, cert.KeyUsage)
		}
	}
}

// TestKeyUsageBitStringEmptySet documents the degenerate input. crypto/x509
// omits the extension entirely for KeyUsage 0, so there is no encoder oracle;
// what matters is that the result is a well-formed BIT STRING with *no* bit set
// — an accidental bit here would grant a usage nobody asked for.
func TestKeyUsageBitStringEmptySet(t *testing.T) {
	got, err := KeyUsageBitString(0)
	if err != nil {
		t.Fatalf("KeyUsageBitString(0): %v", err)
	}
	var bs asn1.BitString
	rest, err := asn1.Unmarshal(got, &bs)
	if err != nil {
		t.Fatalf("KeyUsageBitString(0) = %x is not a parseable BIT STRING: %v", got, err)
	}
	if len(rest) != 0 {
		t.Errorf("KeyUsageBitString(0) left %d trailing bytes", len(rest))
	}
	for bit := 0; bit < 9; bit++ {
		if bs.At(bit) != 0 {
			t.Errorf("KeyUsageBitString(0) set bit %d (encoding %x)", bit, got)
		}
	}
	// And crypto/x509 must read it back as "no usages".
	ext, err := marshalKeyUsage(0)
	if err != nil {
		t.Fatalf("marshalKeyUsage(0): %v", err)
	}
	if cert := certWithExtraExtension(t, newECDSAKey(t), ext); cert.KeyUsage != 0 {
		t.Errorf("empty key usage parsed back as %d", cert.KeyUsage)
	}
}

// TestMarshalKeyUsageExtensionShape checks the extension wrapper: RFC 5280
// §4.2.1.3 requires keyUsage to be marked critical, and the value must be
// exactly the BIT STRING KeyUsageBitString produces (the EST /csrattrs path
// consumes that value directly, so the two must not drift).
func TestMarshalKeyUsageExtensionShape(t *testing.T) {
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	ext, err := marshalKeyUsage(ku)
	if err != nil {
		t.Fatalf("marshalKeyUsage: %v", err)
	}
	if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
		t.Errorf("extension OID = %v, want 2.5.29.15", ext.Id)
	}
	if !ext.Critical {
		t.Error("keyUsage extension must be critical")
	}
	want, err := KeyUsageBitString(ku)
	if err != nil {
		t.Fatalf("KeyUsageBitString: %v", err)
	}
	if !bytes.Equal(ext.Value, want) {
		t.Errorf("extension value = %x, want %x", ext.Value, want)
	}
}

// TestMarshalBasicConstraintsMatchesGoEncoder compares the hand-rolled
// basicConstraints value against the one crypto/x509 emits for the equivalent
// template, for every path through the optional pathLenConstraint: absent, zero
// (which must be encoded, not defaulted away), and positive.
func TestMarshalBasicConstraintsMatchesGoEncoder(t *testing.T) {
	key := newECDSAKey(t)

	goBasicConstraints := func(maxPathLen *int) []byte {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "bc-oracle"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		if maxPathLen != nil {
			tmpl.MaxPathLen = *maxPathLen
			tmpl.MaxPathLenZero = *maxPathLen == 0
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionBasicConstraints) {
				return ext.Value
			}
		}
		t.Fatal("crypto/x509 emitted no basicConstraints extension")
		return nil
	}

	for _, maxPathLen := range []*int{nil, intPtr(0), intPtr(1), intPtr(3)} {
		label := "unconstrained"
		if maxPathLen != nil {
			label = fmt.Sprintf("pathlen-%d", *maxPathLen)
		}
		t.Run(label, func(t *testing.T) {
			ext, err := marshalBasicConstraints(maxPathLen)
			if err != nil {
				t.Fatalf("marshalBasicConstraints: %v", err)
			}
			if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
				t.Errorf("extension OID = %v, want 2.5.29.19", ext.Id)
			}
			if !ext.Critical {
				t.Error("basicConstraints on a CA must be critical")
			}
			if want := goBasicConstraints(maxPathLen); !bytes.Equal(ext.Value, want) {
				t.Fatalf("value = %x, crypto/x509 emits %x", ext.Value, want)
			}

			// crypto/x509's parser must recover cA=TRUE and the constraint.
			cert := certWithExtraExtension(t, key, ext)
			if !cert.IsCA {
				t.Error("parsed certificate is not a CA")
			}
			if maxPathLen == nil {
				if cert.MaxPathLen != -1 || cert.MaxPathLenZero {
					t.Errorf("unconstrained path length parsed as %d (zero=%v)", cert.MaxPathLen, cert.MaxPathLenZero)
				}
			} else {
				if cert.MaxPathLen != *maxPathLen {
					t.Errorf("MaxPathLen = %d, want %d", cert.MaxPathLen, *maxPathLen)
				}
				if cert.MaxPathLenZero != (*maxPathLen == 0) {
					t.Errorf("MaxPathLenZero = %v, want %v", cert.MaxPathLenZero, *maxPathLen == 0)
				}
			}
		})
	}
}

// TestMarshalBasicConstraintsRejectsNegativePathLen guards the one input that
// cannot be encoded: RFC 5280 pathLenConstraint is a non-negative INTEGER, and
// -1 is this codebase's in-band marker for "absent". Encoding -1 verbatim would
// silently produce an unconstrained CA out of an explicit request.
func TestMarshalBasicConstraintsRejectsNegativePathLen(t *testing.T) {
	for _, bad := range []int{-1, -2, -1 << 20} {
		if _, err := marshalBasicConstraints(&bad); err == nil {
			t.Errorf("marshalBasicConstraints(%d) succeeded, want an error", bad)
		}
	}
}

// TestEncodeCSRPEMRoundTrip pins the PEM wrapper: the label openssl expects, a
// trailing newline, base64 wrapped at 64 columns, and byte-exact recovery.
func TestEncodeCSRPEMRoundTrip(t *testing.T) {
	key := newECDSAKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pem.example"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	out := EncodeCSRPEM(der)
	if !bytes.HasPrefix(out, []byte("-----BEGIN CERTIFICATE REQUEST-----\n")) {
		t.Errorf("missing/incorrect PEM header: %q", firstLine(out))
	}
	if !bytes.HasSuffix(out, []byte("-----END CERTIFICATE REQUEST-----\n")) {
		t.Error("PEM output must end with the armor footer and a newline")
	}
	block, rest := pem.Decode(out)
	if block == nil {
		t.Fatal("EncodeCSRPEM produced output pem.Decode rejects")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("block type = %q", block.Type)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Error("PEM round-trip changed the DER")
	}
	if len(rest) != 0 {
		t.Errorf("%d bytes trail the single block", len(rest))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if len(line) > 64 {
			t.Errorf("base64 line is %d chars, PEM wraps at 64: %q", len(line), line)
		}
	}
	// And the package's own parser must accept its own output.
	if _, err := ParseCSRPEM(out); err != nil {
		t.Fatalf("ParseCSRPEM(EncodeCSRPEM(der)): %v", err)
	}
}

// TestParseCSRPEMRejectsMalformedInput drives the parser with the shapes a CSR
// actually arrives in from an enrollment client or an operator's file: wrong
// armor label, truncated base64, a certificate mislabeled as a request, DER with
// trailing junk, and a bundle whose first block is something else. Every case
// must produce an error and no request — never a panic and never a nil/nil.
func TestParseCSRPEMRejectsMalformedInput(t *testing.T) {
	key := newECDSAKey(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "reject.example"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-a-csr"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-a-csr"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	withTrailing := append(append([]byte{}, csrDER...), 0x00, 0x01, 0x02)

	cases := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"no armor", []byte("just some text, no PEM here")},
		{"raw DER (PEM is required)", csrDER},
		{"empty body", []byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n")},
		{"invalid base64", []byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!not base64!!!!\n-----END CERTIFICATE REQUEST-----\n")},
		{"truncated DER", EncodeCSRPEM(csrDER[:len(csrDER)/2])},
		{"trailing DER garbage", EncodeCSRPEM(withTrailing)},
		{"certificate labeled as a request", EncodeCSRPEM(certDER)},
		{"request labeled as a certificate", EncodeCertificatePEM(csrDER)},
		{"private key block", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		// pem.Decode only ever returns the first block, so a bundle that leads
		// with a key does not "find" the request behind it.
		{"key block ahead of the request",
			append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), EncodeCSRPEM(csrDER)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			csr, err := ParseCSRPEM(tc.input)
			if err == nil {
				t.Fatalf("ParseCSRPEM accepted %s", tc.name)
			}
			if csr != nil {
				t.Errorf("ParseCSRPEM returned a request alongside error %v", err)
			}
		})
	}
}

// TestParseCSRPEMAcceptsSurroundingText documents the accepted-but-untidy cases:
// pem.Decode skips leading non-armor lines and ignores anything after the block,
// so a CSR pasted into an email body still parses.
func TestParseCSRPEMAcceptsSurroundingText(t *testing.T) {
	key := newECDSAKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "surrounded.example"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	body := EncodeCSRPEM(der)
	input := append([]byte("Subject: please sign this\n\n"), body...)
	input = append(input, []byte("\nthanks!\n")...)

	csr, err := ParseCSRPEM(input)
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	if csr.Subject.CommonName != "surrounded.example" {
		t.Errorf("CommonName = %q", csr.Subject.CommonName)
	}
}

// TestParseCSRPEMRejectsTamperedRequest is the proof-of-possession check. A CSR
// whose subject was edited in flight still parses as ASN.1, so only the
// self-signature stands between an attacker and a certificate naming someone
// else. Flipping one byte of the CommonName (preserving every DER length) must
// be refused.
func TestParseCSRPEMRejectsTamperedRequest(t *testing.T) {
	key := newECDSAKey(t)
	const original = "tamper-me.example"
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: original},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	idx := bytes.Index(der, []byte(original))
	if idx < 0 {
		t.Fatal("could not locate the CommonName in the CSR DER")
	}
	tampered := append([]byte{}, der...)
	tampered[idx] = 'T' // same length, different subject

	// Sanity: the edit must leave a structurally valid CSR, otherwise the test
	// would be exercising the DER parser rather than the signature check.
	parsed, err := x509.ParseCertificateRequest(tampered)
	if err != nil {
		t.Fatalf("tampered CSR no longer parses, test is not exercising CheckSignature: %v", err)
	}
	if parsed.Subject.CommonName == original {
		t.Fatal("tampering did not change the subject")
	}

	if _, err := ParseCSRPEM(EncodeCSRPEM(tampered)); err == nil {
		t.Fatal("ParseCSRPEM accepted a CSR whose subject was modified after signing")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should name the signature check, got: %v", err)
	}
}

// TestCreateCACSRCarriesCAExtensions checks the contract CreateCACSR documents:
// an external parent signing the request verbatim must end up issuing a
// certificate our own stack accepts, which means the request has to carry
// critical basicConstraints cA=TRUE (with the requested path length) and the
// critical CA keyUsage set.
func TestCreateCACSRCarriesCAExtensions(t *testing.T) {
	key := newECDSAKey(t)
	der, err := CreateCACSR(key, CACSRRequest{
		Subject:    pkix.Name{CommonName: "External Intermediate CA", Organization: []string{"secsy"}},
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("CreateCACSR: %v", err)
	}
	csr, err := ParseCSRPEM(EncodeCSRPEM(der))
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	if csr.Subject.CommonName != "External Intermediate CA" {
		t.Errorf("CommonName = %q", csr.Subject.CommonName)
	}

	wantBC, err := marshalBasicConstraints(intPtr(0))
	if err != nil {
		t.Fatalf("marshalBasicConstraints: %v", err)
	}
	wantKU, err := marshalKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatalf("marshalKeyUsage: %v", err)
	}

	var sawBC, sawKU bool
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionBasicConstraints):
			sawBC = true
			if !ext.Critical {
				t.Error("basicConstraints in the CA CSR must be critical")
			}
			if !bytes.Equal(ext.Value, wantBC.Value) {
				t.Errorf("basicConstraints = %x, want %x", ext.Value, wantBC.Value)
			}
			var bc basicConstraints
			if _, err := asn1.Unmarshal(ext.Value, &bc); err != nil {
				t.Errorf("basicConstraints does not decode: %v", err)
			} else if !bc.IsCA || bc.MaxPathLen != 0 {
				t.Errorf("basicConstraints = %+v, want cA=TRUE pathlen=0", bc)
			}
		case ext.Id.Equal(oidExtensionKeyUsage):
			sawKU = true
			if !ext.Critical {
				t.Error("keyUsage in the CA CSR must be critical")
			}
			if !bytes.Equal(ext.Value, wantKU.Value) {
				t.Errorf("keyUsage = %x, want %x", ext.Value, wantKU.Value)
			}
		}
	}
	if !sawBC {
		t.Error("CA CSR carries no basicConstraints extension")
	}
	if !sawKU {
		t.Error("CA CSR carries no keyUsage extension")
	}
}

// TestCreateCACSRRawSubjectIsEmittedVerbatim covers the external-renewal path:
// the DN of a CA whose certificate already exists must be re-emitted byte for
// byte, because a re-encoded pkix.Name can differ from the original and the
// external parent is expected to issue a drop-in replacement.
func TestCreateCACSRRawSubjectIsEmittedVerbatim(t *testing.T) {
	key := newECDSAKey(t)
	rawSubject, err := asn1.Marshal(pkix.Name{
		CommonName:   "Legacy Root CA",
		Organization: []string{"Example Org"},
		Country:      []string{"DE"},
	}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshaling raw subject: %v", err)
	}

	der, err := CreateCACSR(key, CACSRRequest{
		Subject:    pkix.Name{CommonName: "ignored-because-RawSubject-wins"},
		RawSubject: rawSubject,
	})
	if err != nil {
		t.Fatalf("CreateCACSR: %v", err)
	}
	csr, err := ParseCSRPEM(EncodeCSRPEM(der))
	if err != nil {
		t.Fatalf("ParseCSRPEM: %v", err)
	}
	if !bytes.Equal(csr.RawSubject, rawSubject) {
		t.Errorf("RawSubject = %x, want %x", csr.RawSubject, rawSubject)
	}
	if csr.Subject.CommonName != "Legacy Root CA" {
		t.Errorf("CommonName = %q, want the RawSubject's CN", csr.Subject.CommonName)
	}
}

// TestCreateCACSRRejectsNegativePathLen makes sure the path-length validation is
// reached through the public entry point, not only in the helper.
func TestCreateCACSRRejectsNegativePathLen(t *testing.T) {
	key := newECDSAKey(t)
	bad := -1
	if _, err := CreateCACSR(key, CACSRRequest{
		Subject:    pkix.Name{CommonName: "bad"},
		MaxPathLen: &bad,
	}); err == nil {
		t.Fatal("CreateCACSR accepted a negative path-length constraint")
	}
}

// firstLine returns the first line of b, for error messages.
func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
