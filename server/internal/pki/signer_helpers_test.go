package pki

// Pure helpers behind HSM signing (signer.go).
//
// None of these touch a token, and all of them decide something a token cannot
// check for us:
//
//   - pkcs1DigestInfoPrefix is the DigestInfo the HSM never sees the hash of. The
//     device is asked to raw-sign prefix||digest with CKM_RSA_PKCS, so a wrong
//     prefix produces a signature that verifies against nothing — an invalid
//     certificate that the CA happily publishes.
//   - pssHashParams pairs a digest mechanism with a mask-generation function; a
//     crossed pair (SHA-256 digest, MGF1-SHA-384) is the classic copy-paste bug
//     and also yields signatures nobody can verify.
//   - KeyLocator.cacheKey indexes the per-session object cache. A collision
//     between two locators means signing with the wrong key.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestPKCS1DigestInfoPrefixMatchesStdlibSignature is the oracle that matters:
// sign a digest twice with the same software RSA key — once letting
// crypto/rsa build the DigestInfo itself, once by handing it
// prefix||digest with crypto.Hash(0) (its "already encoded" mode) — and require
// the two signatures to be identical. PKCS#1 v1.5 is deterministic, so equality
// here means our prefix is byte-for-byte the one the standard demands, which is
// exactly what the HSM's CKM_RSA_PKCS raw sign needs.
func TestPKCS1DigestInfoPrefixMatchesStdlibSignature(t *testing.T) {
	key := sharedRSAKey(t)
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run(hash.String(), func(t *testing.T) {
			h := hash.New()
			h.Write([]byte("the message the CA is about to certify"))
			digest := h.Sum(nil)

			want, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
			if err != nil {
				t.Fatalf("rsa.SignPKCS1v15(%v): %v", hash, err)
			}

			prefix, ok := pkcs1DigestInfoPrefix(hash)
			if !ok {
				t.Fatalf("pkcs1DigestInfoPrefix(%v) reported unsupported", hash)
			}
			digestInfo := append(append([]byte{}, prefix...), digest...)
			got, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), digestInfo)
			if err != nil {
				t.Fatalf("raw rsa.SignPKCS1v15 over prefix||digest: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("signature over prefix||digest differs from the stdlib's own PKCS#1 v1.5 signature for %v", hash)
			}
			// And the resulting signature must verify as that hash, which is the
			// property a relying party actually checks.
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, got); err != nil {
				t.Errorf("signature over prefix||digest does not verify as %v: %v", hash, err)
			}
		})
	}
}

// TestPKCS1DigestInfoPrefixIsWellFormedDigestInfo decodes prefix||digest as the
// RFC 8017 DigestInfo it claims to be. This is what catches a wrong *length*
// byte in the hand-written prefix, which the signature comparison above would
// also catch but not localize: here the failure says "the SEQUENCE header is
// wrong" instead of "the signatures differ".
func TestPKCS1DigestInfoPrefixIsWellFormedDigestInfo(t *testing.T) {
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		prefix, ok := pkcs1DigestInfoPrefix(hash)
		if !ok {
			t.Fatalf("pkcs1DigestInfoPrefix(%v) reported unsupported", hash)
		}
		digest := bytes.Repeat([]byte{0x5A}, hash.Size())

		var di struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		rest, err := asn1.Unmarshal(append(append([]byte{}, prefix...), digest...), &di)
		if err != nil {
			t.Errorf("%v: prefix||digest is not a DigestInfo: %v", hash, err)
			continue
		}
		if len(rest) != 0 {
			t.Errorf("%v: %d bytes trail the DigestInfo (a length byte is wrong)", hash, len(rest))
		}
		if !bytes.Equal(di.Digest, digest) {
			t.Errorf("%v: DigestInfo carries %x, want %x", hash, di.Digest, digest)
		}
		// The AlgorithmIdentifier must carry the explicit NULL parameters RFC 8017
		// requires for these hashes; an absent NULL changes the prefix length and
		// breaks interoperability with strict verifiers.
		if !bytes.Equal(di.Algorithm.Parameters.FullBytes, []byte{0x05, 0x00}) {
			t.Errorf("%v: AlgorithmIdentifier parameters = %x, want an explicit NULL",
				hash, di.Algorithm.Parameters.FullBytes)
		}
		// The prefix must end with the OCTET STRING header for exactly this
		// digest size.
		if n := len(prefix); n < 2 || prefix[n-2] != 0x04 || int(prefix[n-1]) != hash.Size() {
			t.Errorf("%v: prefix ends with %x, want 04 %02x (OCTET STRING of the digest size)",
				hash, prefix[len(prefix)-2:], hash.Size())
		}
	}
}

// TestPKCS1DigestInfoPrefixRejectsUnsupportedHashes: an unsupported hash must be
// reported, never answered with some other hash's prefix. Returning SHA-256's
// DigestInfo for a SHA-224 digest would produce a signature that verifies as
// neither.
func TestPKCS1DigestInfoPrefixRejectsUnsupportedHashes(t *testing.T) {
	for _, hash := range []crypto.Hash{
		crypto.Hash(0),
		crypto.MD5,
		crypto.SHA224,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.SHA3_256,
		crypto.SHA3_512,
		crypto.RIPEMD160,
		crypto.Hash(200), // not a hash at all
	} {
		prefix, ok := pkcs1DigestInfoPrefix(hash)
		if ok {
			t.Errorf("pkcs1DigestInfoPrefix(%v) reported supported, returning %x", hash, prefix)
		}
		if prefix != nil {
			t.Errorf("pkcs1DigestInfoPrefix(%v) returned %x alongside ok=false", hash, prefix)
		}
	}
}

// TestPSSHashParamsMatchPKCS11SpecValues pins the digest mechanism and MGF against
// the numeric values in the PKCS#11 specification (v2.40 §2.1.13 / the CK_RSA_PKCS
// _MGF_TYPE table), not against the Go constants the implementation uses. That is
// what makes a crossed pair — a SHA-256 digest mechanism with an MGF1-SHA-384 mask
// — a test failure rather than a self-consistent lie.
func TestPSSHashParamsMatchPKCS11SpecValues(t *testing.T) {
	cases := []struct {
		hash     crypto.Hash
		wantMech uint // CKM_SHA*
		wantMGF  uint // CKG_MGF1_SHA*
	}{
		{crypto.SHA256, 0x00000250, 0x00000002},
		{crypto.SHA384, 0x00000260, 0x00000003},
		{crypto.SHA512, 0x00000270, 0x00000004},
	}
	seenMech := map[uint]crypto.Hash{}
	seenMGF := map[uint]crypto.Hash{}
	for _, tc := range cases {
		mech, mgf, ok := pssHashParams(tc.hash)
		if !ok {
			t.Fatalf("pssHashParams(%v) reported unsupported", tc.hash)
		}
		if mech != tc.wantMech {
			t.Errorf("%v: digest mechanism = %#08x, want %#08x", tc.hash, mech, tc.wantMech)
		}
		if mgf != tc.wantMGF {
			t.Errorf("%v: MGF = %#08x, want %#08x", tc.hash, mgf, tc.wantMGF)
		}
		// Independently: no two hashes may share a mechanism or an MGF, or one
		// hash's parameters are being used for another.
		if prev, dup := seenMech[mech]; dup {
			t.Errorf("%v and %v share digest mechanism %#08x", prev, tc.hash, mech)
		}
		seenMech[mech] = tc.hash
		if prev, dup := seenMGF[mgf]; dup {
			t.Errorf("%v and %v share MGF %#08x", prev, tc.hash, mgf)
		}
		seenMGF[mgf] = tc.hash
	}
}

// TestPSSHashParamsRejectsUnsupportedHashes: unsupported hashes (notably SHA-1,
// which must not be used with PSS here) must be refused with zeroed outputs, so a
// caller that ignores ok cannot accidentally initialize a mechanism with 0.
func TestPSSHashParamsRejectsUnsupportedHashes(t *testing.T) {
	for _, hash := range []crypto.Hash{
		crypto.Hash(0), crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA512_256, crypto.SHA3_256,
	} {
		mech, mgf, ok := pssHashParams(hash)
		if ok {
			t.Errorf("pssHashParams(%v) reported supported (%#08x/%#08x)", hash, mech, mgf)
		}
		if mech != 0 || mgf != 0 {
			t.Errorf("pssHashParams(%v) = %#08x, %#08x alongside ok=false", hash, mech, mgf)
		}
	}
}

// TestRSAKeyTypeBitsAgreesWithTheRestOfTheVocabulary ties the three places that
// have to use the same RSA key-type strings together: the supported-size list,
// the PrivateKeyType naming used for imported keys, the isRSAKeyType predicate,
// and rsaKeyTypeBits. If any of them drifts, the others catch it here.
func TestRSAKeyTypeBitsAgreesWithTheRestOfTheVocabulary(t *testing.T) {
	for _, bits := range SupportedRSABits {
		name, err := PrivateKeyType(rsaKeyOfSize(t, bits))
		if err != nil {
			t.Fatalf("PrivateKeyType(rsa-%d): %v", bits, err)
		}
		got, err := rsaKeyTypeBits(name)
		if err != nil {
			t.Fatalf("rsaKeyTypeBits(%q): %v", name, err)
		}
		if got != bits {
			t.Errorf("rsaKeyTypeBits(%q) = %d, want %d", name, got, bits)
		}
		if !isRSAKeyType(name) {
			t.Errorf("isRSAKeyType(%q) = false, but rsaKeyTypeBits accepts it", name)
		}
	}

	notRSA := []string{
		"", "rsa", "rsa-", "rsa-1024", "rsa-2047", "rsa-8192", "RSA-2048", "rsa-2048 ", " rsa-2048",
		"ed25519", "ecdsa-sha2-nistp256", "rsa-2048-pss",
	}
	for _, name := range notRSA {
		bits, err := rsaKeyTypeBits(name)
		if err == nil {
			t.Errorf("rsaKeyTypeBits(%q) = %d, want an error", name, bits)
		}
		if bits != 0 {
			t.Errorf("rsaKeyTypeBits(%q) returned %d alongside an error", name, bits)
		}
		// The two must never disagree about what an RSA key type is.
		if isRSAKeyType(name) {
			t.Errorf("isRSAKeyType(%q) = true, but rsaKeyTypeBits rejects it", name)
		}
	}
}

// TestKeyLocatorDescribe covers all four rendering branches. Describe is what an
// operator reads when a key cannot be found, so "(no label or id)" has to be
// distinguishable from an empty label.
func TestKeyLocatorDescribe(t *testing.T) {
	cases := []struct {
		loc  KeyLocator
		want string
	}{
		{LabelLocator("root-ca"), `label "root-ca"`},
		{KeyLocator{ID: []byte{0x01, 0xAB}}, "id 01ab"},
		{KeyLocator{Label: "root-ca", ID: []byte{0x01, 0xAB}}, `label "root-ca" id 01ab`},
		{KeyLocator{}, "(no label or id)"},
		{KeyLocator{ID: []byte{}}, "(no label or id)"},
	}
	for _, tc := range cases {
		if got := tc.loc.Describe(); got != tc.want {
			t.Errorf("KeyLocator{%q,%x}.Describe() = %q, want %q", tc.loc.Label, tc.loc.ID, got, tc.want)
		}
	}
}

// TestKeyLocatorIsZero: a locator that constrains on nothing would make
// FindObjects return every key on the token, so callers gate on IsZero.
func TestKeyLocatorIsZero(t *testing.T) {
	zero := []KeyLocator{{}, {Label: ""}, {ID: nil}, {ID: []byte{}}, {Label: "", ID: []byte{}}}
	for _, loc := range zero {
		if !loc.IsZero() {
			t.Errorf("KeyLocator{%q,%x}.IsZero() = false, want true", loc.Label, loc.ID)
		}
	}
	nonZero := []KeyLocator{
		LabelLocator("x"),
		{ID: []byte{0x00}}, // a single zero byte is still a constraint
		{Label: "x", ID: []byte{0x01}},
		{Label: " "},
	}
	for _, loc := range nonZero {
		if loc.IsZero() {
			t.Errorf("KeyLocator{%q,%x}.IsZero() = true, want false", loc.Label, loc.ID)
		}
	}
	if got := LabelLocator("root-ca"); got.Label != "root-ca" || len(got.ID) != 0 {
		t.Errorf("LabelLocator = %+v, want a label-only locator", got)
	}
}

// TestKeyLocatorCacheKeyIsInjective is the one that matters for correctness: the
// per-session object cache is keyed by this string, so two *different* locators
// sharing a key would resolve one CA's label to another CA's key handle. The
// tricky pairs are the ones where a naive "label+id" concatenation collides.
func TestKeyLocatorCacheKeyIsInjective(t *testing.T) {
	distinct := []KeyLocator{
		{},
		{Label: "a"},
		{Label: "ab"},
		{Label: "a|62"},    // the separator and hex of "b", spelled out in the label
		{Label: "1:a"},     // looks like the length-prefixed form
		{ID: []byte("b")},  // 62
		{ID: []byte("ab")}, // 6162
		{Label: "a", ID: []byte("b")},
		{Label: "root-ca", ID: []byte{0x01}},
		{Label: "root-ca", ID: []byte{0x01, 0x00}},
		{Label: "root-c", ID: []byte{0x61, 0x01}},
	}
	seen := map[string]KeyLocator{}
	for _, loc := range distinct {
		key := loc.cacheKey()
		if prev, dup := seen[key]; dup {
			t.Errorf("cacheKey collision %q: {%q,%x} and {%q,%x}", key, prev.Label, prev.ID, loc.Label, loc.ID)
			continue
		}
		seen[key] = loc
	}

	// Equal locators must share a key, including the nil/empty ID spelling —
	// otherwise the cache simply never hits.
	if a, b := (KeyLocator{Label: "x"}).cacheKey(), (KeyLocator{Label: "x", ID: []byte{}}).cacheKey(); a != b {
		t.Errorf("nil and empty ID produce different cache keys: %q vs %q", a, b)
	}
	if a, b := LabelLocator("x").cacheKey(), (KeyLocator{Label: "x"}).cacheKey(); a != b {
		t.Errorf("LabelLocator and the equivalent literal differ: %q vs %q", a, b)
	}
}

// TestKeyLocatorAppendMatch checks the FindObjects template the locator
// contributes: only the fields that are set may be constrained. Appending an
// empty CKA_LABEL would match nothing at all on most modules, and omitting a set
// CKA_ID would make an HA deployment (where replicas deliberately share a label)
// resolve the wrong replica's key.
func TestKeyLocatorAppendMatch(t *testing.T) {
	base := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}

	attrTypes := func(attrs []*pkcs11.Attribute) []uint {
		out := make([]uint, 0, len(attrs))
		for _, a := range attrs {
			out = append(out, a.Type)
		}
		return out
	}
	find := func(attrs []*pkcs11.Attribute, typ uint) *pkcs11.Attribute {
		for _, a := range attrs {
			if a.Type == typ {
				return a
			}
		}
		return nil
	}

	t.Run("label only", func(t *testing.T) {
		got := LabelLocator("root-ca").appendMatch(base)
		if len(got) != 2 {
			t.Fatalf("template has %d attributes (%v), want 2", len(got), attrTypes(got))
		}
		label := find(got, pkcs11.CKA_LABEL)
		if label == nil || string(label.Value) != "root-ca" {
			t.Errorf("CKA_LABEL = %v, want \"root-ca\"", label)
		}
		if find(got, pkcs11.CKA_ID) != nil {
			t.Error("an unset ID must not be constrained")
		}
	})

	t.Run("id only", func(t *testing.T) {
		id := []byte{0xDE, 0xAD}
		got := KeyLocator{ID: id}.appendMatch(base)
		if len(got) != 2 {
			t.Fatalf("template has %d attributes (%v), want 2", len(got), attrTypes(got))
		}
		if find(got, pkcs11.CKA_LABEL) != nil {
			t.Error("an empty label must not be constrained")
		}
		if a := find(got, pkcs11.CKA_ID); a == nil || !bytes.Equal(a.Value, id) {
			t.Errorf("CKA_ID = %v, want %x", a, id)
		}
	})

	t.Run("label and id", func(t *testing.T) {
		got := KeyLocator{Label: "replica", ID: []byte{0x07}}.appendMatch(base)
		if len(got) != 3 {
			t.Fatalf("template has %d attributes (%v), want 3", len(got), attrTypes(got))
		}
		if a := find(got, pkcs11.CKA_LABEL); a == nil || string(a.Value) != "replica" {
			t.Errorf("CKA_LABEL = %v", a)
		}
		if a := find(got, pkcs11.CKA_ID); a == nil || !bytes.Equal(a.Value, []byte{0x07}) {
			t.Errorf("CKA_ID = %v", a)
		}
	})

	t.Run("zero locator adds nothing", func(t *testing.T) {
		got := KeyLocator{}.appendMatch(base)
		if len(got) != len(base) {
			t.Fatalf("template has %d attributes (%v), want %d", len(got), attrTypes(got), len(base))
		}
	})

	// The caller's prefix must survive in place.
	got := LabelLocator("x").appendMatch(base)
	if got[0].Type != pkcs11.CKA_CLASS {
		t.Errorf("the caller's first attribute was overwritten: %v", got[0].Type)
	}
	if len(base) != 1 {
		t.Errorf("appendMatch mutated the caller's slice length to %d", len(base))
	}
}
