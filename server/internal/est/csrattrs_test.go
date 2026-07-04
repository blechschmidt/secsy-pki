package est

// Unit tests for the RFC 7030 §4.5 CSR Attributes encoder and profile-driven
// derivation. They need no HSM, DB, or HTTP, so they run in the default build
// alongside the sqlite-tagged endpoint tests in csrattrs_endpoint_test.go.

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"os/exec"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// mustOIDValue DER-encodes an OID for use as an Attribute value.
func mustOIDValue(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	v, err := oidValue(oid)
	if err != nil {
		t.Fatalf("oidValue(%v): %v", oid, err)
	}
	return v
}

// opensslASN1Parse runs `openssl asn1parse` over DER, skipping when openssl is
// unavailable. The task requires the known-answer DER be validated this way.
func opensslASN1Parse(t *testing.T, der []byte) string {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	cmd := exec.Command("openssl", "asn1parse", "-inform", "DER")
	cmd.Stdin = bytes.NewReader(der)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestEncodeCsrAttrs_RFC7030Example reproduces, byte for byte, the worked
// example from RFC 7030 §4.5.2 — a challengePassword OID, an id-ecPublicKey
// attribute selecting secp384r1, an extensionRequest attribute, and an
// ecdsa-with-SHA384 signature-algorithm OID — and validates it with
// `openssl asn1parse`.
func TestEncodeCsrAttrs_RFC7030Example(t *testing.T) {
	oidECDSAWithSHA384 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidExampleExt := asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}

	attrs := []attrOrOID{
		bareOID(oidChallengePassword),
		attribute(oidECPublicKey, mustOIDValue(t, oidCurveP384)),
		attribute(oidExtensionRequest, mustOIDValue(t, oidExampleExt)),
		bareOID(oidECDSAWithSHA384),
	}
	der, err := encodeCsrAttrs(attrs)
	if err != nil {
		t.Fatalf("encodeCsrAttrs: %v", err)
	}

	const want = "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJBgcrBgEBAQEWBggqhkjOPQQDAw=="
	if got := base64.StdEncoding.EncodeToString(der); got != want {
		t.Fatalf("csrattrs DER mismatch with RFC 7030 §4.5.2\n got: %s\nwant: %s", got, want)
	}

	parsed := opensslASN1Parse(t, der)
	for _, needle := range []string{"SEQUENCE", "challengePassword", "id-ecPublicKey", "secp384r1", "ecdsa-with-SHA384"} {
		if !bytes.Contains([]byte(parsed), []byte(needle)) {
			t.Errorf("openssl asn1parse output missing %q:\n%s", needle, parsed)
		}
	}
}

// TestEncodeCsrAttrs_CanonicalSetOrdering ensures SET OF values are emitted in
// canonical DER order regardless of input order, so the output is deterministic.
func TestEncodeCsrAttrs_CanonicalSetOrdering(t *testing.T) {
	client := mustOIDValue(t, ekuOIDByName["clientAuth"]) // ...03 02
	server := mustOIDValue(t, ekuOIDByName["serverAuth"]) // ...03 01 (sorts first)

	forward, err := encodeCsrAttrs([]attrOrOID{attribute(oidExtKeyUsage, server, client)})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := encodeCsrAttrs([]attrOrOID{attribute(oidExtKeyUsage, client, server)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, reverse) {
		t.Fatal("SET OF value ordering is not canonical: encoding depends on input order")
	}
	// serverAuth (…01) must appear before clientAuth (…02) in the bytes.
	si := bytes.Index(forward, server)
	ci := bytes.Index(forward, client)
	if si < 0 || ci < 0 || si > ci {
		t.Fatalf("serverAuth should sort before clientAuth (si=%d ci=%d)", si, ci)
	}
}

// findBareOID / findAttr are assertion helpers over a derived attribute set.
func findBareOID(attrs []attrOrOID, oid asn1.ObjectIdentifier) bool {
	for _, a := range attrs {
		if a.values == nil && a.oid.Equal(oid) {
			return true
		}
	}
	return false
}

func findAttr(attrs []attrOrOID, oid asn1.ObjectIdentifier) (attrOrOID, bool) {
	for _, a := range attrs {
		if a.values != nil && a.oid.Equal(oid) {
			return a, true
		}
	}
	return attrOrOID{}, false
}

func TestDeriveCsrAttrs_ServerProfile(t *testing.T) {
	prof, err := ca.LookupProfile("server")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := deriveCsrAttrs(prof, false, oidCurveP256)
	if err != nil {
		t.Fatal(err)
	}

	// server has keyEncipherment, so the key-type hint is RSA (bare OID).
	if !findBareOID(attrs, oidRSAEncryption) {
		t.Error("server profile: expected rsaEncryption key-type hint")
	}
	if findBareOID(attrs, oidAttestationBundle) {
		t.Error("server profile: attestation must not be advertised when not required")
	}

	// keyUsage carries the exact BIT STRING the leaf will bear.
	kuAttr, ok := findAttr(attrs, oidKeyUsage)
	if !ok {
		t.Fatal("server profile: missing keyUsage attribute")
	}
	ku, err := keyUsageMask(prof)
	if err != nil {
		t.Fatal(err)
	}
	wantKU, err := pki.KeyUsageBitString(ku)
	if err != nil {
		t.Fatal(err)
	}
	if len(kuAttr.values) != 1 || !bytes.Equal(kuAttr.values[0], wantKU) {
		t.Errorf("keyUsage value = %x, want %x", kuAttr.values, wantKU)
	}

	// extKeyUsage advertises serverAuth.
	ekuAttr, ok := findAttr(attrs, oidExtKeyUsage)
	if !ok {
		t.Fatal("server profile: missing extKeyUsage attribute")
	}
	if len(ekuAttr.values) != 1 || !bytes.Equal(ekuAttr.values[0], mustOIDValue(t, ekuOIDByName["serverAuth"])) {
		t.Errorf("extKeyUsage value = %x, want serverAuth", ekuAttr.values)
	}

	// The whole set must encode and parse cleanly under openssl.
	der, err := encodeCsrAttrs(attrs)
	if err != nil {
		t.Fatal(err)
	}
	opensslASN1Parse(t, der)
}

func TestDeriveCsrAttrs_ClientProfileEC(t *testing.T) {
	prof, err := ca.LookupProfile("client")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := deriveCsrAttrs(prof, false, oidCurveP384)
	if err != nil {
		t.Fatal(err)
	}
	// client has no keyEncipherment -> EC key-type hint carrying the curve.
	ecAttr, ok := findAttr(attrs, oidECPublicKey)
	if !ok {
		t.Fatal("client profile: expected id-ecPublicKey key-type hint")
	}
	if len(ecAttr.values) != 1 || !bytes.Equal(ecAttr.values[0], mustOIDValue(t, oidCurveP384)) {
		t.Errorf("ec curve value = %x, want P-384", ecAttr.values)
	}
	if findBareOID(attrs, oidRSAEncryption) {
		t.Error("client profile must not advertise rsaEncryption")
	}
	ekuAttr, ok := findAttr(attrs, oidExtKeyUsage)
	if !ok || len(ekuAttr.values) != 1 || !bytes.Equal(ekuAttr.values[0], mustOIDValue(t, ekuOIDByName["clientAuth"])) {
		t.Errorf("client profile: expected clientAuth extKeyUsage, got %+v", ekuAttr)
	}

	// openssl renders id-ecPublicKey by name; the interop suite greps for it, so
	// pin that expectation here.
	der, err := encodeCsrAttrs(attrs)
	if err != nil {
		t.Fatal(err)
	}
	if parsed := opensslASN1Parse(t, der); !bytes.Contains([]byte(parsed), []byte("id-ecPublicKey")) {
		t.Errorf("openssl asn1parse should render id-ecPublicKey:\n%s", parsed)
	}
}

func TestDeriveCsrAttrs_PQCProfile(t *testing.T) {
	prof, err := ca.LookupProfile("pqc-server")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := deriveCsrAttrs(prof, false, oidCurveP256)
	if err != nil {
		t.Fatal(err)
	}
	if !findBareOID(attrs, oidMLDSA65) {
		t.Error("pqc-server profile: expected ml-dsa-65 key-type hint")
	}
	if _, ok := findAttr(attrs, oidECPublicKey); ok {
		t.Error("pqc-server profile must not advertise an EC key-type hint")
	}
}

func TestDeriveCsrAttrs_AttestationRequired(t *testing.T) {
	prof, err := ca.LookupProfile("client")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := deriveCsrAttrs(prof, true, oidCurveP256)
	if err != nil {
		t.Fatal(err)
	}
	if !findBareOID(attrs, oidAttestationBundle) {
		t.Error("attestation-required profile must advertise the attestation-bundle OID")
	}
}

func TestBuildOverrideAttrs(t *testing.T) {
	// A bare challengePassword and an id-ecPublicKey attribute selecting P-384.
	specs := []CSRAttr{
		{OID: "1.2.840.113549.1.9.7"},
		{OID: "1.2.840.10045.2.1", Values: []string{"1.3.132.0.34"}},
	}
	attrs, err := buildOverrideAttrs(specs)
	if err != nil {
		t.Fatal(err)
	}
	if !findBareOID(attrs, oidChallengePassword) {
		t.Error("override: expected bare challengePassword")
	}
	ecAttr, ok := findAttr(attrs, oidECPublicKey)
	if !ok || len(ecAttr.values) != 1 || !bytes.Equal(ecAttr.values[0], mustOIDValue(t, oidCurveP384)) {
		t.Errorf("override: expected id-ecPublicKey with P-384, got %+v", ecAttr)
	}
	if _, err := encodeCsrAttrs(attrs); err != nil {
		t.Fatalf("override attrs failed to encode: %v", err)
	}
}

func TestBuildOverrideAttrs_BadOID(t *testing.T) {
	if _, err := buildOverrideAttrs([]CSRAttr{{OID: "not-an-oid"}}); err == nil {
		t.Error("expected error for malformed override OID")
	}
	if _, err := buildOverrideAttrs([]CSRAttr{{OID: "1"}}); err == nil {
		t.Error("expected error for single-arc OID")
	}
}

func TestValidateCSRAttrConfig(t *testing.T) {
	if err := ValidateCSRAttrConfig("", nil); err != nil {
		t.Errorf("empty config should validate: %v", err)
	}
	if err := ValidateCSRAttrConfig("p-384", map[string][]CSRAttr{
		"client": {{OID: "1.2.840.113549.1.9.7"}},
	}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := ValidateCSRAttrConfig("brainpool", nil); err == nil {
		t.Error("unknown curve should be rejected")
	}
	if err := ValidateCSRAttrConfig("", map[string][]CSRAttr{
		"client": {{OID: "bogus"}},
	}); err == nil {
		t.Error("malformed override OID should be rejected")
	}
	// Parses syntactically but is not a valid DER OID (first arc > 2); must be
	// caught by the encode step at startup, not deferred to the first request.
	if err := ValidateCSRAttrConfig("", map[string][]CSRAttr{
		"client": {{OID: "3.1.1"}},
	}); err == nil {
		t.Error("OID with an invalid first arc should be rejected")
	}
}

func TestResolveECCurve(t *testing.T) {
	cases := map[string]asn1.ObjectIdentifier{
		"":           oidCurveP256,
		"p-256":      oidCurveP256,
		"prime256v1": oidCurveP256,
		"P-384":      oidCurveP384,
		"secp384r1":  oidCurveP384,
		"p-521":      oidCurveP521,
	}
	for name, want := range cases {
		got, err := resolveECCurve(name)
		if err != nil {
			t.Errorf("resolveECCurve(%q): %v", name, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("resolveECCurve(%q) = %v, want %v", name, got, want)
		}
	}
	if _, err := resolveECCurve("nope"); err == nil {
		t.Error("expected error for unknown curve")
	}
}
