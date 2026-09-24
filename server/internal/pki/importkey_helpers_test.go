package pki

// Pure helpers behind key import (importkey.go).
//
// These run host-side, before any PKCS#11 module is involved, and they decide
// what bytes are handed to C_CreateObject. padScalar in particular is the last
// thing that touches an EC private key before it is written to a token: a scalar
// that comes out the wrong length is a private key that no longer matches its
// public half, discovered — if at all — by a verifier months later.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"
)

// testRSA2048 returns a process-wide 2048-bit RSA key. RSA generation is by far
// the most expensive thing these tests could do, and none of them care which key
// they get, so exactly one is minted per test binary.
var testRSA2048 = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func sharedRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := testRSA2048()
	if err != nil {
		t.Fatalf("generating shared RSA key: %v", err)
	}
	return key
}

// TestPadScalarMatchesFillBytes checks the fixed-width big-endian padding against
// big.Int.FillBytes, which is the standard library's implementation of exactly
// this operation (and which panics rather than truncating if the value does not
// fit — so agreeing with it also means agreeing on the byte order).
func TestPadScalarMatchesFillBytes(t *testing.T) {
	values := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(255),
		big.NewInt(256),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 31)),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 32)),
		// A value whose natural encoding starts with a zero byte cannot exist as a
		// big.Int (it normalizes), which is precisely why the padding is needed:
		// 0x00...01 must still be written as a full-width scalar.
		new(big.Int).SetBytes([]byte{0x00, 0x00, 0x01}),
	}
	for _, size := range []int{1, 2, 32, 48, 66} {
		for _, v := range values {
			if len(v.Bytes()) > size {
				continue // FillBytes would panic; covered separately below
			}
			got := padScalar(v, size)
			want := v.FillBytes(make([]byte, size))
			if !bytes.Equal(got, want) {
				t.Errorf("padScalar(%s, %d) = %x, want %x", v, size, got, want)
			}
			if len(got) != size {
				t.Errorf("padScalar(%s, %d) returned %d bytes", v, size, len(got))
			}
		}
	}
}

// TestPadScalarZeroAndLeadingZeros spells out the two shapes a token is most
// likely to choke on: an all-zero value (big.Int.Bytes() is empty, so every byte
// must come from the padding) and a value that is shorter than the field size.
func TestPadScalarZeroAndLeadingZeros(t *testing.T) {
	zero := padScalar(big.NewInt(0), 32)
	if len(zero) != 32 {
		t.Fatalf("padScalar(0, 32) returned %d bytes, want 32", len(zero))
	}
	for i, b := range zero {
		if b != 0 {
			t.Fatalf("padScalar(0, 32)[%d] = %#02x, want 0", i, b)
		}
	}

	one := padScalar(big.NewInt(1), 32)
	want := make([]byte, 32)
	want[31] = 0x01
	if !bytes.Equal(one, want) {
		t.Fatalf("padScalar(1, 32) = %x, want %x (big-endian, left-padded)", one, want)
	}

	// Exactly the requested width must be returned unchanged.
	exact := bytes.Repeat([]byte{0xA5}, 32)
	exact[0] = 0x7F // keep the high bit clear so Bytes() is 32 long
	if got := padScalar(new(big.Int).SetBytes(exact), 32); !bytes.Equal(got, exact) {
		t.Errorf("padScalar of an exactly-width value = %x, want %x", got, exact)
	}

	// A zero width is degenerate but must not panic or allocate a phantom byte.
	if got := padScalar(big.NewInt(0), 0); len(got) != 0 {
		t.Errorf("padScalar(0, 0) = %x, want no bytes", got)
	}
}

// TestPadScalarNeverTruncates pins the over-wide case. It is unreachable for a
// real key (a curve's private scalar is below the group order and so never wider
// than the field), but the behavior matters: silently dropping the high-order
// bytes would write a *different* private key onto the token, one whose public
// half no longer matches — the kind of corruption the import read-back check can
// only catch if the bytes were not quietly cut here first.
func TestPadScalarNeverTruncates(t *testing.T) {
	wide := new(big.Int).SetBytes(bytes.Repeat([]byte{0xFE}, 40))
	got := padScalar(wide, 32)
	if len(got) < 40 {
		t.Fatalf("padScalar truncated a 40-byte value to %d bytes: %x", len(got), got)
	}
	if !bytes.Equal(got, wide.Bytes()) {
		t.Errorf("padScalar(wide, 32) = %x, want the value unchanged (%x)", got, wide.Bytes())
	}
	if new(big.Int).SetBytes(got).Cmp(wide) != 0 {
		t.Error("padScalar changed the value it was given")
	}
}

// TestPadScalarOnRealECDSAKeys checks the invocation importTemplates actually
// makes: for every supported curve the scalar must come out at exactly the field
// width, including for keys whose D happens to have leading zero bytes (the case
// that motivated the padding in the first place).
func TestPadScalarOnRealECDSAKeys(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		size := (curve.Params().BitSize + 7) / 8
		sawShortD := false
		for i := 0; i < 32; i++ {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("%s: %v", curve.Params().Name, err)
			}
			scalar := padScalar(key.D, size)
			if len(scalar) != size {
				t.Fatalf("%s: padScalar returned %d bytes, want %d", curve.Params().Name, len(scalar), size)
			}
			if new(big.Int).SetBytes(scalar).Cmp(key.D) != 0 {
				t.Fatalf("%s: padded scalar no longer equals D", curve.Params().Name)
			}
			if len(key.D.Bytes()) < size {
				sawShortD = true
			}
		}
		// P-521's scalar is 521 bits in a 66-byte field, so a leading zero byte is
		// near-certain; for the others 32 draws is only a sanity signal, not a
		// requirement, so nothing is asserted when it does not occur.
		if curve == elliptic.P521() && !sawShortD {
			t.Errorf("P-521: no key with a short D in 32 draws, expected the padding path to be exercised")
		}
	}
}

// TestECParamsForCurveMatchesSPKI compares the CKA_EC_PARAMS encoding against the
// namedCurve OID crypto/x509 itself puts in a SubjectPublicKeyInfo — the same DER
// object, produced by an independent encoder.
func TestECParamsForCurveMatchesSPKI(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("%s: %v", curve.Params().Name, err)
		}
		spkiDER, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatalf("%s: MarshalPKIXPublicKey: %v", curve.Params().Name, err)
		}
		var spki struct {
			Algorithm        pkix.AlgorithmIdentifier
			SubjectPublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
			t.Fatalf("%s: decoding SPKI: %v", curve.Params().Name, err)
		}
		want := spki.Algorithm.Parameters.FullBytes
		if len(want) == 0 {
			t.Fatalf("%s: crypto/x509 emitted no namedCurve parameters", curve.Params().Name)
		}

		got, err := ecParamsForCurve(curve)
		if err != nil {
			t.Fatalf("%s: ecParamsForCurve: %v", curve.Params().Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: ecParamsForCurve = %x, crypto/x509 uses %x", curve.Params().Name, got, want)
		}
		// It must be a bare OID, not wrapped: PKCS#11 CKA_EC_PARAMS is the
		// ECParameters CHOICE, and a token matching on the tag rejects anything else.
		var oid asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(got, &oid); err != nil || len(rest) != 0 {
			t.Errorf("%s: CKA_EC_PARAMS is not a bare OBJECT IDENTIFIER: err=%v rest=%d", curve.Params().Name, err, len(rest))
		}
	}
}

// TestECParamsForCurveKnownAnswer pins the three curve OIDs so a renamed constant
// cannot quietly swap P-384 for P-521.
func TestECParamsForCurveKnownAnswer(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		want  []byte
	}{
		// secp256r1 / prime256v1 = 1.2.840.10045.3.1.7
		{elliptic.P256(), []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}},
		// secp384r1 = 1.3.132.0.34
		{elliptic.P384(), []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}},
		// secp521r1 = 1.3.132.0.35
		{elliptic.P521(), []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}},
	}
	for _, tc := range cases {
		got, err := ecParamsForCurve(tc.curve)
		if err != nil {
			t.Fatalf("%s: %v", tc.curve.Params().Name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: ecParamsForCurve = %x, want %x", tc.curve.Params().Name, got, tc.want)
		}
	}
}

// TestECParamsForCurveRejectsUnsupported: an unnamed or unsupported curve must be
// refused by name rather than encoded as some default, which would hand the token
// a scalar on one curve labeled as another.
func TestECParamsForCurveRejectsUnsupported(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P224(), // a real NIST curve no HSM here holds
		// A bare CurveParams stands in for any curve outside the supported set
		// (brainpool, sm2, a custom domain), which is what a key parsed from an
		// arbitrary PKCS#8 file could carry.
		&elliptic.CurveParams{Name: "brainpoolP256r1", BitSize: 256},
	}
	for _, curve := range curves {
		name := curve.Params().Name
		t.Run(name, func(t *testing.T) {
			if _, err := ecParamsForCurve(curve); err == nil {
				t.Errorf("ecParamsForCurve(%s) succeeded, want an error", name)
			} else if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q does not name the curve %q", err, name)
			}
		})
	}
}

// TestPublicOf checks the public-half extraction used by the post-import
// read-back comparison. Returning a wrong (or nil-but-ignored) public key there
// would defeat the check that the token stored what we sent.
func TestPublicOf(t *testing.T) {
	ecKey := importTestECDSA(t, elliptic.P256())
	edKey := importTestEd25519(t)
	rsaKey := sharedRSAKey(t)

	for _, tc := range []struct {
		name string
		priv crypto.PrivateKey
		want crypto.PublicKey
	}{
		{"ecdsa", ecKey, ecKey.Public()},
		{"ed25519", edKey, edKey.Public()},
		{"rsa", rsaKey, rsaKey.Public()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := publicOf(tc.priv)
			if got == nil {
				t.Fatal("publicOf returned nil for a crypto.Signer")
			}
			if !publicKeysEqual(got, tc.want) {
				t.Errorf("publicOf returned a key that does not equal the private key's public half")
			}
			// And it must not match an unrelated key of the same type.
			other := importTestECDSA(t, elliptic.P256())
			if publicKeysEqual(got, other.Public()) && tc.name == "ecdsa" {
				t.Error("publicKeysEqual accepted two different keys")
			}
		})
	}

	// Anything that is not a crypto.Signer has no public half to report, and the
	// caller treats nil as "cannot compare" (publicKeysEqual then fails closed).
	for name, notASigner := range map[string]crypto.PrivateKey{
		"nil":        nil,
		"byte slice": []byte("raw key material"),
		"struct":     struct{}{},
	} {
		if got := publicOf(notASigner); got != nil {
			t.Errorf("publicOf(%s) = %v, want nil", name, got)
		}
	}
	if publicKeysEqual(nil, ecKey.Public()) || publicKeysEqual(ecKey.Public(), nil) {
		t.Error("publicKeysEqual must reject a nil operand")
	}
	if publicKeysEqual(ecKey.Public(), edKey.Public()) {
		t.Error("publicKeysEqual matched keys of different algorithms")
	}
}

// TestImportRejectionHint covers the operator-facing explanation attached to a
// CKR_ATTRIBUTE_VALUE_INVALID from C_CreateObject. The hint must appear for the
// case it was written for (an RSA key a token will not take) and must stay silent
// otherwise — a hint about RSA modulus sizes printed under an EC failure sends
// the operator after the wrong thing.
func TestImportRejectionHint(t *testing.T) {
	rsaKey := sharedRSAKey(t)
	attrInvalid := pkcs11.Error(pkcs11.CKR_ATTRIBUTE_VALUE_INVALID)

	t.Run("rsa attribute-value-invalid", func(t *testing.T) {
		hint := importRejectionHint(rsaKey, attrInvalid)
		if hint == "" {
			t.Fatal("no hint for the failure mode the hint exists for")
		}
		for _, want := range []string{"2048", "65537", "2048, 3072, or 4096"} {
			if !strings.Contains(hint, want) {
				t.Errorf("hint does not mention %q: %s", want, hint)
			}
		}
	})

	t.Run("wrapped error still matches", func(t *testing.T) {
		wrapped := fmt.Errorf("import: creating private key object on the token: %w", attrInvalid)
		if importRejectionHint(rsaKey, wrapped) == "" {
			t.Error("the hint is lost once the pkcs11 error is wrapped")
		}
	})

	t.Run("reports the key's actual parameters", func(t *testing.T) {
		// A key the PKI would never generate: an unusual size with exponent 3.
		odd := &rsa.PrivateKey{PublicKey: rsa.PublicKey{
			N: new(big.Int).Lsh(big.NewInt(1), 2559), E: 3,
		}}
		hint := importRejectionHint(odd, attrInvalid)
		if !strings.Contains(hint, "2560") {
			t.Errorf("hint does not report the key's 2560-bit modulus: %s", hint)
		}
		if !strings.Contains(hint, "exponent 3") {
			t.Errorf("hint does not report the key's public exponent: %s", hint)
		}
	})

	t.Run("silent when there is nothing to add", func(t *testing.T) {
		cases := map[string]struct {
			priv crypto.PrivateKey
			err  error
		}{
			"no error":            {rsaKey, nil},
			"different pkcs11 rv": {rsaKey, pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)},
			"plain error":         {rsaKey, fmt.Errorf("attribute value invalid")},
			"ecdsa key":           {importTestECDSA(t, elliptic.P256()), attrInvalid},
			"ed25519 key":         {importTestEd25519(t), attrInvalid},
			"not a key at all":    {struct{}{}, attrInvalid},
		}
		for name, tc := range cases {
			if hint := importRejectionHint(tc.priv, tc.err); hint != "" {
				t.Errorf("%s: unexpected hint %q", name, hint)
			}
		}
	})
}

// compile-time assertion that the key types the helpers above pass around really
// are signers, which is what publicOf keys off.
var (
	_ crypto.Signer = (*rsa.PrivateKey)(nil)
	_ crypto.Signer = (*ecdsa.PrivateKey)(nil)
	_ crypto.Signer = ed25519.PrivateKey(nil)
)
