package pki

// Unit tests for the raw PKCS#11 inspector's decoding, naming, batching and —
// most importantly — its withholding policy. None of these needs a token: they
// are about what the inspector does with the bytes a token hands it, which is
// exactly the part that has no HSM in it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// The catalogue is hand-written and the name tables are generated; this is the
// seam between them. A catalogued attribute whose name does not resolve would
// render as "CKA_0x…" in the console, which looks like a vendor attribute
// rather than the typo it is.
func TestCatalogueNamesAllResolve(t *testing.T) {
	seen := map[uint]bool{}
	for _, a := range pkcs11Attributes {
		if seen[a.typ] {
			t.Errorf("attribute %s (%#08x) is catalogued twice", attributeName(a.typ), a.typ)
		}
		seen[a.typ] = true
		if _, ok := ckaNames[a.typ]; !ok {
			t.Errorf("catalogued attribute %#08x has no CKA_ name in the generated table", a.typ)
		}
		if a.spec.kind == "" {
			t.Errorf("catalogued attribute %s has no kind", attributeName(a.typ))
		}
	}
	if len(pkcs11Attributes) < 80 {
		t.Errorf("catalogue holds only %d attributes; it is meant to cover the standard set", len(pkcs11Attributes))
	}
}

// The policy that keeps this feature from becoming the one path that exports a
// private key: for a private or secret key, the attributes whose value IS the
// key material must be withheld — and for a certificate or data object, the
// same CKA_VALUE must NOT be, since there it is public.
func TestPrivateKeyMaterialIsWithheld(t *testing.T) {
	material := []uint{
		pkcs11.CKA_VALUE, pkcs11.CKA_PRIVATE_EXPONENT,
		pkcs11.CKA_PRIME_1, pkcs11.CKA_PRIME_2,
		pkcs11.CKA_EXPONENT_1, pkcs11.CKA_EXPONENT_2, pkcs11.CKA_COEFFICIENT,
	}
	specs := map[uint]attrSpec{}
	for _, a := range pkcs11Attributes {
		specs[a.typ] = a.spec
	}
	for _, typ := range material {
		spec, ok := specs[typ]
		if !ok {
			t.Fatalf("%s is not catalogued at all", attributeName(typ))
		}
		for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_SECRET_KEY} {
			if !spec.withheldFor(class) {
				t.Errorf("%s is NOT withheld for %s — the inspector would ask the token for key material",
					attributeName(typ), ckoNames[class])
			}
		}
	}

	// The public halves stay readable: a modulus and a public exponent are not
	// secrets, and an inspector that hid them would be useless for the thing it
	// exists for (telling two keys apart).
	for _, typ := range []uint{pkcs11.CKA_MODULUS, pkcs11.CKA_PUBLIC_EXPONENT, pkcs11.CKA_EC_POINT, pkcs11.CKA_EC_PARAMS} {
		if specs[typ].withheldFor(pkcs11.CKO_PUBLIC_KEY) {
			t.Errorf("%s is withheld for a public key", attributeName(typ))
		}
	}
	// A certificate's body and a data object's contents are public.
	for _, class := range []uint{pkcs11.CKO_CERTIFICATE, pkcs11.CKO_DATA} {
		if specs[pkcs11.CKA_VALUE].withheldFor(class) {
			t.Errorf("CKA_VALUE is withheld for %s, where it is the object itself", ckoNames[class])
		}
	}
}

// Class scoping decides which attributes are even asked for, so a certificate
// is not interrogated about CKA_PIXEL_X — and a storage attribute is asked of
// everything.
func TestClassScoping(t *testing.T) {
	specs := map[uint]attrSpec{}
	for _, a := range pkcs11Attributes {
		specs[a.typ] = a.spec
	}
	cases := []struct {
		typ    uint
		class  uint
		expect bool
	}{
		{pkcs11.CKA_LABEL, pkcs11.CKO_CERTIFICATE, true},    // storage: every object
		{pkcs11.CKA_LABEL, pkcs11.CKO_DATA, true},           //
		{pkcs11.CKA_PIXEL_X, pkcs11.CKO_CERTIFICATE, false}, // hardware feature only
		{pkcs11.CKA_PIXEL_X, pkcs11.CKO_HW_FEATURE, true},   //
		{pkcs11.CKA_SENSITIVE, pkcs11.CKO_PUBLIC_KEY, false},
		{pkcs11.CKA_SENSITIVE, pkcs11.CKO_PRIVATE_KEY, true},
		{pkcs11.CKA_MODULUS_BITS, pkcs11.CKO_PRIVATE_KEY, false}, // public-key attribute
		{pkcs11.CKA_ISSUER, pkcs11.CKO_CERTIFICATE, true},
		{pkcs11.CKA_ISSUER, pkcs11.CKO_PRIVATE_KEY, false},
	}
	for _, c := range cases {
		if got := specs[c.typ].applies(c.class); got != c.expect {
			t.Errorf("%s applies to %s = %v, want %v", attributeName(c.typ), ckoNames[c.class], got, c.expect)
		}
	}
	// An unknown (vendor) class still gets the storage attributes, and nothing
	// class-specific — the catalogue cannot know what a vendor object holds.
	const vendorClass = pkcs11.CKO_VENDOR_DEFINED + 1
	if !specs[pkcs11.CKA_LABEL].applies(vendorClass) {
		t.Error("CKA_LABEL is not asked of a vendor-defined object")
	}
	if specs[pkcs11.CKA_MODULUS].applies(vendorClass) {
		t.Error("CKA_MODULUS is asked of a vendor-defined object")
	}
}

func TestAttributeNaming(t *testing.T) {
	cases := map[uint]string{
		pkcs11.CKA_LABEL:              "CKA_LABEL",
		pkcs11.CKA_EC_PARAMS:          "CKA_EC_PARAMS", // not its deprecated CKA_ECDSA_PARAMS alias
		pkcs11.CKA_ALLOWED_MECHANISMS: "CKA_ALLOWED_MECHANISMS",
		pkcs11.CKA_VENDOR_DEFINED + 7: "CKA_VENDOR_DEFINED+0x7",
		0x0000FFFE:                    "CKA_0xfffe",
	}
	for typ, want := range cases {
		if got := attributeName(typ); got != want {
			t.Errorf("attributeName(%#x) = %q, want %q", typ, got, want)
		}
	}
	if got := mechanismName(pkcs11.CKM_ECDSA_SHA256); got != "CKM_ECDSA_SHA256" {
		t.Errorf("mechanismName(CKM_ECDSA_SHA256) = %q", got)
	}
	if got := mechanismName(pkcs11.CKM_VENDOR_DEFINED + 0x10); got != "CKM_VENDOR_DEFINED+0x10" {
		t.Errorf("vendor mechanism name = %q", got)
	}
}

// ulong decoding has to honour the length the module wrote: a 32-bit module in
// a 64-bit process writes four bytes, and reading eight would walk into the
// next field.
func TestULongDecoding(t *testing.T) {
	if got := bytesToULong([]byte{0x2a, 0, 0, 0, 0, 0, 0, 0}); got != 42 {
		t.Errorf("64-bit CK_ULONG = %d, want 42", got)
	}
	if got := bytesToULong([]byte{0x2a, 0, 0, 0}); got != 42 {
		t.Errorf("32-bit CK_ULONG = %d, want 42", got)
	}
	if got := ulongValue(pkcs11.CK_UNAVAILABLE_INFORMATION); got != "unavailable" {
		t.Errorf("CK_UNAVAILABLE_INFORMATION rendered as %q", got)
	}
	if got := sessionCount(0, true); got != "effectively infinite" {
		t.Errorf("a zero maximum rendered as %q, want the CK_EFFECTIVELY_INFINITE reading", got)
	}
	if got := sessionCount(0, false); got != "0" {
		t.Errorf("a zero current count rendered as %q, want 0", got)
	}
}

func TestRenderValueByKind(t *testing.T) {
	ulong := func(v uint64) []byte {
		b := make([]byte, 8)
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * i))
		}
		return b
	}
	cases := []struct {
		name  string
		typ   uint
		kind  attrKind
		class uint
		in    []byte
		want  string
	}{
		{"true", pkcs11.CKA_SENSITIVE, kindBool, pkcs11.CKO_PRIVATE_KEY, []byte{1}, "true"},
		{"false", pkcs11.CKA_EXTRACTABLE, kindBool, pkcs11.CKO_PRIVATE_KEY, []byte{0}, "false"},
		{"odd bool", pkcs11.CKA_TOKEN, kindBool, 0, []byte{1, 0}, "(2-byte CK_BBOOL)"},
		{"ulong", pkcs11.CKA_MODULUS_BITS, kindULong, pkcs11.CKO_PUBLIC_KEY, ulong(2048), "2048"},
		{"label", pkcs11.CKA_LABEL, kindString, 0, []byte("ca-root"), "ca-root"},
		{"class", pkcs11.CKA_CLASS, kindClass, 0, ulong(pkcs11.CKO_PRIVATE_KEY), "CKO_PRIVATE_KEY (0x3)"},
		{"key type", pkcs11.CKA_KEY_TYPE, kindKeyType, 0, ulong(pkcs11.CKK_EC), "CKK_EC (0x3)"},
		{"cert type", pkcs11.CKA_CERTIFICATE_TYPE, kindCertType, 0, ulong(pkcs11.CKC_X_509), "CKC_X_509 (0x0)"},
		{"gen mechanism", pkcs11.CKA_KEY_GEN_MECHANISM, kindMechanism, 0, ulong(pkcs11.CKM_EC_KEY_PAIR_GEN), "CKM_EC_KEY_PAIR_GEN"},
		{"date unset", pkcs11.CKA_END_DATE, kindDate, 0, []byte("00000000"), "(unset)"},
		{"date", pkcs11.CKA_END_DATE, kindDate, 0, []byte("20301231"), "2030-12-31"},
		{"empty", pkcs11.CKA_ID, kindBytes, 0, nil, ""},
	}
	for _, c := range cases {
		if got := renderValue(c.typ, c.kind, c.class, c.in); got != c.want {
			t.Errorf("%s: renderValue = %q, want %q", c.name, got, c.want)
		}
	}

	// A big integer reports its bit length, which is how an operator reads an
	// RSA modulus without counting hex digits.
	mod := make([]byte, 256)
	mod[0] = 0x80
	if got := renderValue(pkcs11.CKA_MODULUS, kindBigInt, pkcs11.CKO_PUBLIC_KEY, mod); !strings.HasPrefix(got, "2048 bits") {
		t.Errorf("modulus rendered as %q, want a 2048-bit reading", got)
	}

	// CKA_ALLOWED_MECHANISMS is an array of CK_MECHANISM_TYPE.
	list := append(ulong(pkcs11.CKM_ECDSA), ulong(pkcs11.CKM_ECDSA_SHA256)...)
	if got := renderValue(pkcs11.CKA_ALLOWED_MECHANISMS, kindMechList, pkcs11.CKO_PRIVATE_KEY, list); got != "CKM_ECDSA, CKM_ECDSA_SHA256" {
		t.Errorf("mechanism list rendered as %q", got)
	}

	// A non-printable string is elided rather than put in a terminal or a
	// browser; the hex stays available in Raw.
	if got := renderValue(pkcs11.CKA_LABEL, kindString, 0, []byte{0x01, 0x1b, 0x5b}); !strings.Contains(got, "not printable") {
		t.Errorf("control characters rendered as %q", got)
	}
}

// The DER decodings are what turn an opaque blob into something an operator can
// act on: which curve, whose certificate, which name.
func TestRenderDER(t *testing.T) {
	p256, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	if got := renderDER(pkcs11.CKA_EC_PARAMS, p256); !strings.Contains(got, "P-256") {
		t.Errorf("CKA_EC_PARAMS for prime256v1 rendered as %q", got)
	}
	unknownCurve, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if got := renderDER(pkcs11.CKA_EC_PARAMS, unknownCurve); got != "curve OID 1.2.3.4" {
		t.Errorf("unknown curve rendered as %q", got)
	}

	subject, err := asn1.Marshal(pkix.Name{CommonName: "secsy issuing CA"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	if got := renderDER(pkcs11.CKA_SUBJECT, subject); !strings.Contains(got, "secsy issuing CA") {
		t.Errorf("CKA_SUBJECT rendered as %q", got)
	}

	serial, err := asn1.Marshal(big.NewInt(0x1234))
	if err != nil {
		t.Fatal(err)
	}
	if got := renderDER(pkcs11.CKA_SERIAL_NUMBER, serial); !strings.Contains(got, "0x1234") {
		t.Errorf("CKA_SERIAL_NUMBER rendered as %q", got)
	}

	// An undecodable value costs nothing: Raw still carries the bytes.
	if got := renderDER(pkcs11.CKA_SUBJECT, []byte{0xff, 0xff}); got != "" {
		t.Errorf("undecodable CKA_SUBJECT rendered as %q, want the empty decoding", got)
	}
}

// A certificate object's CKA_VALUE is summarised, because "4 objects, one of
// them a certificate" is far less useful than "whose certificate".
func TestCertificateValueSummary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		Issuer:       pkix.Name{CommonName: "issuer.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	got := renderValue(pkcs11.CKA_VALUE, kindBytes, pkcs11.CKO_CERTIFICATE, der)
	for _, want := range []string{"leaf.example", "99", "2031-01-02"} {
		if !strings.Contains(got, want) {
			t.Errorf("certificate summary %q does not mention %q", got, want)
		}
	}
	// The same bytes on a data object are just bytes.
	if got := renderValue(pkcs11.CKA_VALUE, kindBytes, pkcs11.CKO_DATA, der); !strings.HasSuffix(got, "bytes") {
		t.Errorf("data object value rendered as %q, want a byte count", got)
	}
}

func TestFlagDecoding(t *testing.T) {
	f := flagNames(pkcs11.CKF_RNG|pkcs11.CKF_LOGIN_REQUIRED|pkcs11.CKF_TOKEN_INITIALIZED, tokenFlagNames)
	want := []string{"CKF_RNG", "CKF_LOGIN_REQUIRED", "CKF_TOKEN_INITIALIZED"}
	if len(f.Names) != len(want) {
		t.Fatalf("decoded %v, want %v", f.Names, want)
	}
	for i, w := range want {
		if f.Names[i] != w {
			t.Errorf("flag %d = %q, want %q (flags are reported in bit order)", i, f.Names[i], w)
		}
	}
	if f.Hex != "0x00000405" {
		t.Errorf("hex = %q", f.Hex)
	}

	// A bit the table does not know must survive as hex rather than vanish —
	// a vendor flag is exactly the thing worth noticing.
	unknown := flagNames(pkcs11.CKF_RNG|0x10000000, tokenFlagNames)
	if len(unknown.Names) != 2 || unknown.Names[1] != "0x10000000" {
		t.Errorf("unknown bit decoded as %v", unknown.Names)
	}

	// The same bit value means different things per namespace.
	if got := flagNames(0x2, slotFlagNames).Names[0]; got != "CKF_REMOVABLE_DEVICE" {
		t.Errorf("slot flag 0x2 = %q", got)
	}
	if got := flagNames(0x2, tokenFlagNames).Names[0]; got != "CKF_WRITE_PROTECTED" {
		t.Errorf("token flag 0x2 = %q", got)
	}
	if got := flagNames(0x200, mechanismFlagNames).Names[0]; got != "CKF_DECRYPT" {
		t.Errorf("mechanism flag 0x200 = %q", got)
	}
}

// The batching strategy: one call when the token answers everything, and
// subdivision down to the refusals otherwise — with every value still attached
// to the attribute it came from.
func TestReadAttributesBatching(t *testing.T) {
	types := []uint{1, 2, 3, 4, 5, 6, 7, 8}
	value := func(t uint) []byte { return []byte{byte(t)} }

	// Case 1: the token answers the whole batch in one call.
	var calls int
	out := readAttributes(func(ts []uint) ([]*pkcs11.Attribute, error) {
		calls++
		attrs := make([]*pkcs11.Attribute, 0, len(ts))
		for _, typ := range ts {
			attrs = append(attrs, pkcs11.NewAttribute(typ, value(typ)))
		}
		return attrs, nil
	}, types)
	if calls != 1 {
		t.Errorf("a fully answered batch took %d calls, want 1", calls)
	}
	for _, typ := range types {
		if got := out[typ]; got.err != nil || len(got.value) != 1 || got.value[0] != byte(typ) {
			t.Errorf("attribute %d = %v, want its own value", typ, got)
		}
	}

	// Case 2: one attribute is sensitive. Every other value must still arrive,
	// attached to the right attribute, and the refusal must be reported as the
	// CKR the token gave.
	const sensitive = uint(5)
	calls = 0
	out = readAttributes(func(ts []uint) ([]*pkcs11.Attribute, error) {
		calls++
		for _, typ := range ts {
			if typ == sensitive {
				return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE)
			}
		}
		attrs := make([]*pkcs11.Attribute, 0, len(ts))
		for _, typ := range ts {
			attrs = append(attrs, pkcs11.NewAttribute(typ, value(typ)))
		}
		return attrs, nil
	}, types)
	if got := out[sensitive]; got.err == nil {
		t.Error("the sensitive attribute came back without an error")
	} else if name := ckrName(got.err); name != "CKR_ATTRIBUTE_SENSITIVE" {
		t.Errorf("refusal reported as %q", name)
	}
	for _, typ := range types {
		if typ == sensitive {
			continue
		}
		if got := out[typ]; got.err != nil || got.value[0] != byte(typ) {
			t.Errorf("attribute %d = %v: one refusal lost (or misaligned) the others", typ, got)
		}
	}
	// 8 attributes with one refusal: subdivision, not 8 individual calls.
	if calls >= len(types) {
		t.Errorf("one refusal cost %d calls for %d attributes — subdivision is not happening", calls, len(types))
	}

	// Case 3: a module that returns a different number of values than asked for
	// is not trusted to have kept the order — the batch is re-read singly, so
	// no value is attributed to the wrong name.
	out = readAttributes(func(ts []uint) ([]*pkcs11.Attribute, error) {
		if len(ts) > 1 {
			return []*pkcs11.Attribute{pkcs11.NewAttribute(ts[0], value(ts[0]))}, nil
		}
		return []*pkcs11.Attribute{pkcs11.NewAttribute(ts[0], value(ts[0]))}, nil
	}, types)
	for _, typ := range types {
		if got := out[typ]; got.err != nil || got.value[0] != byte(typ) {
			t.Errorf("attribute %d = %v after a short module answer", typ, got)
		}
	}
}

func TestCKRNaming(t *testing.T) {
	if got := ckrName(pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)); got != "CKR_ATTRIBUTE_TYPE_INVALID" {
		t.Errorf("ckrName = %q", got)
	}
	if got := ckrName(fmt.Errorf("wrapped: %w", pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))); got != "CKR_OBJECT_HANDLE_INVALID" {
		t.Errorf("wrapped ckrName = %q", got)
	}
	if got := ckrName(fmt.Errorf("the connector is gone")); got != "the connector is gone" {
		t.Errorf("non-Cryptoki error reported as %q", got)
	}
}

// Rendering caps the hex of a long value but hashes the whole of it, so a
// truncated modulus or certificate can still be compared between two tokens.
func TestRawTruncationKeepsAWholeValueDigest(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = byte(i)
	}
	a := renderAttribute(pkcs11.CKA_MODULUS, attrSpec{kind: kindBigInt, classes: clsPub}, pkcs11.CKO_PUBLIC_KEY,
		attrResult{value: long}, InspectOptions{MaxValueBytes: 16})
	if !a.RawTruncated {
		t.Error("a 600-byte value was not marked truncated")
	}
	if len(a.Raw) != 32 { // 16 bytes of hex
		t.Errorf("Raw is %d hex chars, want 32", len(a.Raw))
	}
	if a.Length != 600 {
		t.Errorf("Length = %d, want the full 600", a.Length)
	}
	if a.SHA256 == "" {
		t.Fatal("no digest for a truncated value")
	}
	if !strings.HasPrefix(hex.EncodeToString(long[:16]), a.Raw[:32]) {
		t.Error("Raw is not the value's prefix")
	}
	if a.Status != AttrStatusPresent {
		t.Errorf("status = %q", a.Status)
	}

	// A refused attribute carries the reason and no value at all.
	refused := renderAttribute(pkcs11.CKA_VALUE, attrSpec{kind: kindBytes, classes: clsPriv},
		pkcs11.CKO_PRIVATE_KEY, attrResult{err: pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE)}, InspectOptions{})
	if refused.Status != AttrStatusUnavailable || refused.Reason != "CKR_ATTRIBUTE_SENSITIVE" {
		t.Errorf("refused attribute = %+v", refused)
	}
	if refused.Raw != "" || refused.Value != "" {
		t.Errorf("refused attribute carries a value: %+v", refused)
	}
}

func TestInspectOptionDefaults(t *testing.T) {
	var zero InspectOptions
	if zero.maxObjects() != DefaultInspectMaxObjects {
		t.Errorf("default object cap = %d", zero.maxObjects())
	}
	if zero.maxValueBytes() != DefaultInspectMaxValueBytes {
		t.Errorf("default value cap = %d", zero.maxValueBytes())
	}
	set := InspectOptions{MaxObjects: 7, MaxValueBytes: 9}
	if set.maxObjects() != 7 || set.maxValueBytes() != 9 {
		t.Errorf("explicit caps not honoured: %+v", set)
	}
}

// A character attribute carries hex only when the text could not be shown —
// a label printed twice, as text and as bytes, is noise; a label that is not
// text is only answerable as bytes.
func TestStringAttributeHexOnlyWhenTheTextCannotBeShown(t *testing.T) {
	spec := attrSpec{kind: kindString}
	plain := renderAttribute(pkcs11.CKA_LABEL, spec, pkcs11.CKO_PRIVATE_KEY,
		attrResult{value: []byte("ca-root")}, InspectOptions{})
	if plain.Value != "ca-root" || plain.Raw != "" {
		t.Errorf("a printable label = %+v, want the text and no hex", plain)
	}

	binary := renderAttribute(pkcs11.CKA_LABEL, spec, pkcs11.CKO_PRIVATE_KEY,
		attrResult{value: []byte{0x01, 0x1b, 0x5b}}, InspectOptions{})
	if binary.Raw != "011b5b" {
		t.Errorf("a non-printable label = %+v, want its bytes", binary)
	}

	// A trailing NUL is padding, not content: the text still matches.
	padded := renderAttribute(pkcs11.CKA_LABEL, spec, pkcs11.CKO_PRIVATE_KEY,
		attrResult{value: []byte("ca-root\x00")}, InspectOptions{})
	if padded.Value != "ca-root" || padded.Raw != "" {
		t.Errorf("a NUL-padded label = %+v", padded)
	}

	// A short byte value IS its hex, so Value carries it and the caller is not
	// handed the same string twice.
	id := renderAttribute(pkcs11.CKA_ID, attrSpec{kind: kindBytes}, pkcs11.CKO_PRIVATE_KEY,
		attrResult{value: []byte{0x0a, 0x0b}}, InspectOptions{})
	if id.Value != "0x0a0b" || id.Raw != "0a0b" {
		t.Errorf("CKA_ID = %+v", id)
	}
}
