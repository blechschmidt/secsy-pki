package agent

// Tests for the client side of the EST CSR Attributes exchange (RFC 7030 §4.5):
// parsing the advertisement and honoring it when building the CSR.

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// oidDER encodes an OID for use as an attribute value.
func oidDER(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	v, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal oid %v: %v", oid, err)
	}
	return v
}

// bareOIDElem / attrElem build the two AttrOrOID wire forms; csrAttrsDER wraps
// elements in the outer SEQUENCE. This mirrors the server encoder so the client
// parser is tested against the exact format the server emits.
func bareOIDElem(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(oid)
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func attrElem(t *testing.T, oid asn1.ObjectIdentifier, values ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
			for _, v := range values {
				b.AddBytes(v)
			}
		})
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func csrAttrsDER(t *testing.T, elements ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, e := range elements {
			b.AddBytes(e)
		}
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseCSRAttrs_RFCExample(t *testing.T) {
	// The RFC 7030 §4.5.2 worked example: the client parser must accept it.
	const b64 = "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJBgcrBgEBAQEWBggqhkjOPQQDAw=="
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := parseCSRAttrs(der)
	if err != nil {
		t.Fatalf("parseCSRAttrs: %v", err)
	}
	if len(attrs) != 4 {
		t.Fatalf("parsed %d attrs, want 4", len(attrs))
	}
	if !attrs[0].bare || !attrs[0].oid.Equal(oidChallengePasswordC) {
		t.Errorf("attr[0] = %+v, want bare challengePassword", attrs[0])
	}
	if attrs[1].bare || !attrs[1].oid.Equal(oidECPublicKeyC) || len(attrs[1].values) != 1 {
		t.Errorf("attr[1] = %+v, want id-ecPublicKey attribute with one value", attrs[1])
	}
	if !attrs[1].values[0].Equal(oidCurveP384C) {
		t.Errorf("attr[1] curve = %v, want secp384r1", attrs[1].values[0])
	}
}

func TestKeyTypeFromCSRAttrs(t *testing.T) {
	cases := []struct {
		name  string
		attrs []csrAttr
		want  string
	}{
		{"rsa", []csrAttr{{oid: oidRSAEncryptionC, bare: true}}, "rsa-2048"},
		{"ec-p384", []csrAttr{{oid: oidECPublicKeyC, values: []asn1.ObjectIdentifier{oidCurveP384C}}}, "ecdsa-p384"},
		{"ec-p256", []csrAttr{{oid: oidECPublicKeyC, values: []asn1.ObjectIdentifier{oidCurveP256C}}}, "ecdsa-p256"},
		{"ec-nocurve", []csrAttr{{oid: oidECPublicKeyC}}, "ecdsa-p256"},
		{"mldsa-unsupported", []csrAttr{{oid: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, bare: true}}, ""},
		{"none", nil, ""},
	}
	for _, tc := range cases {
		if got := keyTypeFromCSRAttrs(tc.attrs); got != tc.want {
			t.Errorf("%s: keyTypeFromCSRAttrs = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestChooseKeyType(t *testing.T) {
	cases := []struct {
		spec, hint, want string
	}{
		{"auto", "ecdsa-p384", "ecdsa-p384"},   // auto adopts the hint
		{"", "rsa-2048", "rsa-2048"},           // unset adopts the hint
		{"auto", "", defaultKeyType},           // auto with no hint -> default
		{"rsa-4096", "ecdsa-p384", "rsa-4096"}, // explicit spec wins over the hint
	}
	for _, tc := range cases {
		if got := chooseKeyType(tc.spec, tc.hint); got != tc.want {
			t.Errorf("chooseKeyType(%q,%q) = %q, want %q", tc.spec, tc.hint, got, tc.want)
		}
	}
}

func TestCSRExtensionsFromCSRAttrs_EKU(t *testing.T) {
	serverAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	clientAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	attrs := []csrAttr{{oid: oidExtKeyUsageC, values: []asn1.ObjectIdentifier{serverAuth, clientAuth}}}

	exts, err := csrExtensionsFromCSRAttrs(attrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(exts) != 1 || !exts[0].Id.Equal(oidExtKeyUsageC) {
		t.Fatalf("expected one extKeyUsage extension, got %+v", exts)
	}
	// The extension value must be a SEQUENCE OF the advertised purpose OIDs.
	var purposes []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(exts[0].Value, &purposes); err != nil {
		t.Fatalf("unmarshal EKU value: %v", err)
	}
	if len(purposes) != 2 || !purposes[0].Equal(serverAuth) || !purposes[1].Equal(clientAuth) {
		t.Errorf("EKU purposes = %v, want [serverAuth clientAuth]", purposes)
	}

	// A CSR built with the extension must carry the advertised EKUs so the
	// request is self-describing.
	key, _ := generateKeyOfType("ecdsa-p256")
	spec := &CertSpec{CommonName: "csrattrs-test", DNSNames: []string{"host.example"}}
	csrDER, err := buildCSR(spec, key, exts...)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	// crypto/x509 does not surface CSR EKUs as a typed field; find the raw
	// extKeyUsage extension carried in the request's extensionRequest attribute.
	var csrEKU []asn1.ObjectIdentifier
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidExtKeyUsageC) {
			if _, err := asn1.Unmarshal(ext.Value, &csrEKU); err != nil {
				t.Fatalf("unmarshal CSR EKU: %v", err)
			}
		}
	}
	if len(csrEKU) != 2 || !csrEKU[0].Equal(serverAuth) || !csrEKU[1].Equal(clientAuth) {
		t.Errorf("CSR extKeyUsage = %v, want [serverAuth clientAuth]", csrEKU)
	}
}

// TestParseCSRAttrs_ServerFormat feeds the parser a blob shaped exactly like the
// server's derived "server"-profile output — a bare rsaEncryption OID, a
// keyUsage attribute whose value is a BIT STRING (a value type the client does
// not act on and must skip), and an extKeyUsage attribute — and confirms the
// client honors it: RSA key type and the serverAuth EKU.
func TestParseCSRAttrs_ServerFormat(t *testing.T) {
	oidKeyUsage := asn1.ObjectIdentifier{2, 5, 29, 15}
	serverAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	// keyUsage BIT STRING: digitalSignature + keyEncipherment (05 unused bits, 0xa0).
	kuBitString := []byte{0x03, 0x02, 0x05, 0xa0}

	der := csrAttrsDER(t,
		bareOIDElem(t, oidRSAEncryptionC),
		attrElem(t, oidKeyUsage, kuBitString),
		attrElem(t, oidExtKeyUsageC, oidDER(t, serverAuth)),
	)

	attrs, err := parseCSRAttrs(der)
	if err != nil {
		t.Fatalf("parseCSRAttrs: %v", err)
	}
	if got := keyTypeFromCSRAttrs(attrs); got != "rsa-2048" {
		t.Errorf("keyType = %q, want rsa-2048", got)
	}
	ekus := ekuOIDsFromCSRAttrs(attrs)
	if len(ekus) != 1 || !ekus[0].Equal(serverAuth) {
		t.Errorf("EKUs = %v, want [serverAuth]", ekus)
	}
	if requiresAttestation(attrs) {
		t.Error("server profile does not require attestation")
	}
}

func TestRequiresAttestation(t *testing.T) {
	with := []csrAttr{{oid: oidAttestationBundleC, bare: true}}
	if !requiresAttestation(with) {
		t.Error("expected requiresAttestation=true when the attestation OID is advertised")
	}
	if requiresAttestation([]csrAttr{{oid: oidECPublicKeyC}}) {
		t.Error("expected requiresAttestation=false without the attestation OID")
	}
}

func TestParseCSRAttrs_Malformed(t *testing.T) {
	if _, err := parseCSRAttrs([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("expected error for non-SEQUENCE input")
	}
	// Trailing garbage after the outer SEQUENCE must be rejected.
	der := append(csrAttrsDER(t, bareOIDElem(t, oidRSAEncryptionC)), 0xff)
	if _, err := parseCSRAttrs(der); err == nil {
		t.Error("expected error for trailing bytes after the outer SEQUENCE")
	}
}
