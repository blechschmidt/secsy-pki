package pki

// Key-type naming for the HSM inventory listing (inventory.go).
//
// keyTypeName turns a raw CKA_KEY_TYPE value into the string an operator reads in
// `secsy-ca hsm list` and that compliance exports repeat, so a mislabel is a
// wrong claim about what is protecting a CA. Only the branches that answer from
// the CKA_KEY_TYPE value alone are reachable without a token: the RSA and EC arms
// read further attributes off the device, and are covered by the HSM-backed
// suite. See the note at the bottom of this file.

import (
	"encoding/binary"
	"testing"

	"github.com/miekg/pkcs11"
)

// ckULong encodes a PKCS#11 CK_ULONG the way a module hands it back in an
// attribute value: native byte order, machine word width. keyTypeName only looks
// at the low byte, which on a little-endian host is element 0.
func ckULong(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// TestKeyTypeNameFromKeyTypeAloneClassifies covers every branch that can answer
// without reading a second attribute off the token.
func TestKeyTypeNameFromKeyTypeAloneClassifies(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		// A module that refuses CKA_KEY_TYPE must not produce an empty column, and
		// must not be mistaken for CKK_RSA (whose numeric value is 0).
		{"attribute unavailable", nil, "unknown"},
		{"attribute empty", []byte{}, "unknown"},

		// CKK_EC_EDWARDS (0x40) is the PKCS#11 v3.0 Ed25519 key type; the whole
		// point of the branch is that it must not fall through to the generic EC
		// arm and be reported as "ecdsa".
		{"CKK_EC_EDWARDS", ckULong(CKK_EC_EDWARDS), "ed25519"},
		{"CKK_EC_EDWARDS bare byte", []byte{CKK_EC_EDWARDS}, "ed25519"},

		// Anything else is reported as the raw Cryptoki type rather than guessed
		// at, so an operator can look the number up.
		{"CKK_DSA", ckULong(pkcs11.CKK_DSA), "ckk-0x1"},
		{"CKK_DH", ckULong(pkcs11.CKK_DH), "ckk-0x2"},
		{"CKK_GENERIC_SECRET", ckULong(pkcs11.CKK_GENERIC_SECRET), "ckk-0x10"},
		{"CKK_AES", ckULong(pkcs11.CKK_AES), "ckk-0x1f"},
		{"CKK_EC_MONTGOMERY", ckULong(0x41), "ckk-0x41"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A nil *pkcs11.Ctx is safe here precisely because none of these
			// branches consults the token; if one of them started to, this test
			// would fail loudly rather than silently stop covering it.
			if got := keyTypeName(0, nil, 0, tc.raw); got != tc.want {
				t.Errorf("keyTypeName(%x) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestKeyTypeNameEdwardsMatchesImportTemplate ties the listing back to what
// import writes: importTemplates stores Ed25519 keys under CKK_EC_EDWARDS, so the
// inventory must name that exact value "ed25519" or a key this PKI created would
// be unidentifiable in its own listing.
func TestKeyTypeNameEdwardsMatchesImportTemplate(t *testing.T) {
	attr := pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS)
	if len(attr.Value) == 0 {
		t.Fatal("CKA_KEY_TYPE attribute carries no value")
	}
	if got := keyTypeName(0, nil, 0, attr.Value); got != "ed25519" {
		t.Errorf("keyTypeName of the CKA_KEY_TYPE import writes = %q, want %q", got, "ed25519")
	}
}

// Deliberately not covered here: the CKK_RSA arm (which calls rsaModulusBits to
// read CKA_MODULUS) and the CKK_EC arm (which calls ecCurveName to read
// CKA_EC_PARAMS). Both dereference the *pkcs11.Ctx to reach the module, so they
// cannot be exercised without a real token and belong to the HSM-backed suite.
// The OID→curve mapping ecCurveName applies is the same one ecParamsForCurve
// produces and isEdwards25519 recognizes, and both of those are covered:
// see TestECParamsForCurveKnownAnswer and TestIsEdwards25519_*.
