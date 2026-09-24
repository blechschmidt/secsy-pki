package keyprovider

// Unit tests for the Azure Key Vault translation layer — the pure functions that
// turn a canonical key type into Key Vault create parameters, a returned JWK back
// into a Go public key, and a Key Vault ECDSA signature into the ASN.1 DER form
// x509/CMS verifiers require. No network, no credentials: every function here is
// a mapper, and a mapper that drifts corrupts silently rather than failing.
//
// The signature conversion is held to independent oracles throughout: real
// signatures produced by crypto/ecdsa and verified with ecdsa.VerifyASN1, and DER
// built with golang.org/x/crypto/cryptobyte (the encoder crypto/ecdsa itself
// uses) rather than with encoding/asn1, which is what the implementation uses.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// azureCurves is the set of curves Key Vault offers for signing, paired with the
// canonical key type and the JWK curve name, so every table below stays in sync
// with a single list.
var azureCurves = []struct {
	name    azkeys.CurveName
	curve   elliptic.Curve
	keyType string
}{
	{azkeys.CurveNameP256, elliptic.P256(), KeyTypeECDSAP256},
	{azkeys.CurveNameP384, elliptic.P384(), KeyTypeECDSAP384},
	{azkeys.CurveNameP521, elliptic.P521(), KeyTypeECDSAP521},
}

// coordWidth is the fixed width of one P1363 signature half (and of one JWK
// coordinate): ceil(bitsize/8). Derived from the curve parameters so P-521's 66
// bytes — not a power of two, and the width most implementations get wrong —
// comes out of the same rule as P-256's 32.
func coordWidth(c elliptic.Curve) int { return (c.Params().BitSize + 7) / 8 }

// p1363Encode builds the IEEE P1363 signature Key Vault returns: r and s each
// left-padded with zeros to the curve's fixed width. Written with big.Int.FillBytes
// rather than with anything from the implementation under test.
func p1363Encode(t *testing.T, c elliptic.Curve, r, s *big.Int) []byte {
	t.Helper()
	half := coordWidth(c)
	if len(r.Bytes()) > half || len(s.Bytes()) > half {
		t.Fatalf("r/s too wide for %s: %d/%d bytes > %d", c.Params().Name, len(r.Bytes()), len(s.Bytes()), half)
	}
	out := make([]byte, 2*half)
	r.FillBytes(out[:half])
	s.FillBytes(out[half:])
	return out
}

// derFromRS encodes SEQUENCE{INTEGER r, INTEGER s} with cryptobyte — the exact
// construction crypto/ecdsa.SignASN1 uses — as an oracle independent of the
// encoding/asn1 marshaller p1363ToASN1 relies on.
func derFromRS(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1BigInt(r)
		c.AddASN1BigInt(s)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("building reference DER: %v", err)
	}
	return out
}

// parseDERSig parses SEQUENCE{INTEGER r, INTEGER s} exactly as
// crypto/ecdsa.parseSignature does: DER-strict, no trailing bytes, minimal
// INTEGER encodings. It reports what a verifier would actually read back.
func parseDERSig(t *testing.T, der []byte) (r, s *big.Int) {
	t.Helper()
	r, s = new(big.Int), new(big.Int)
	input := cryptobyte.String(der)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		t.Fatalf("p1363ToASN1 produced bytes a strict DER verifier rejects: %x", der)
	}
	return r, s
}

// testRSAKey returns one 2048-bit RSA key shared by every subtest in this file —
// key generation, not the mappers, would otherwise dominate the runtime.
var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generating shared test RSA key: " + err.Error())
	}
	return k
})

// rsaJWK builds the bundle Key Vault returns for an RSA key: modulus and
// exponent as minimal big-endian byte strings (RFC 7518 §6.3.1).
func rsaJWK(kty azkeys.KeyType, pub *rsa.PublicKey) *azkeys.JSONWebKey {
	return &azkeys.JSONWebKey{
		Kty: &kty,
		N:   pub.N.Bytes(),
		E:   big.NewInt(int64(pub.E)).Bytes(),
	}
}

// ecJWK builds the bundle Key Vault returns for an EC key: the affine
// coordinates left-padded to the curve width (RFC 7518 §6.2.1.2).
func ecJWK(kty azkeys.KeyType, crv azkeys.CurveName, pub *ecdsa.PublicKey) *azkeys.JSONWebKey {
	w := coordWidth(pub.Curve)
	x, y := make([]byte, w), make([]byte, w)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return &azkeys.JSONWebKey{Kty: &kty, Crv: &crv, X: x, Y: y}
}

func azureKeyTypePtr(k azkeys.KeyType) *azkeys.KeyType { return &k }

// ---------------------------------------------------------------------------
// p1363ToASN1
// ---------------------------------------------------------------------------

// TestP1363ToASN1VerifiesAgainstStdlib is the end-to-end oracle: real (r,s)
// pairs from crypto/ecdsa, re-encoded into the fixed-width form Key Vault
// returns, must come back out as DER that ecdsa.VerifyASN1 accepts. A wrong
// half-width or a mishandled leading zero breaks every Azure signature, and
// nothing else in the signing path would notice.
func TestP1363ToASN1VerifiesAgainstStdlib(t *testing.T) {
	digest := sha256.Sum256([]byte("azure key vault p1363 signature"))
	for _, c := range azureCurves {
		t.Run(c.curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			// Several signatures per curve: ECDSA is randomized, so this naturally
			// covers high-bit-set and (over enough runs) short r/s values too. The
			// crafted cases below cover those deterministically.
			for i := 0; i < 16; i++ {
				r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatalf("ecdsa.Sign: %v", err)
				}
				raw := p1363Encode(t, c.curve, r, s)
				if want := 2 * coordWidth(c.curve); len(raw) != want {
					t.Fatalf("test vector is %d bytes, want %d", len(raw), want)
				}
				der, err := p1363ToASN1(raw)
				if err != nil {
					t.Fatalf("p1363ToASN1(%d bytes): %v", len(raw), err)
				}
				if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
					t.Fatalf("converted signature does not verify (r=%x s=%x der=%x)", r, s, der)
				}
				if ref := derFromRS(t, r, s); !bytes.Equal(der, ref) {
					t.Fatalf("DER = %x, want %x (cryptobyte reference)", der, ref)
				}
				gotR, gotS := parseDERSig(t, der)
				if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
					t.Fatalf("round-trip lost values: got r=%x s=%x, want r=%x s=%x", gotR, gotS, r, s)
				}
			}
		})
	}
}

// TestP1363ToASN1LeadingZeroAndHighBit drives the two encodings DER treats
// specially, with r and s chosen rather than drawn: a value whose top bit is set
// (DER must prepend 0x00 or the INTEGER reads as negative) and a value with
// leading zero bytes in the fixed-width form (DER must strip them). Both are
// checked against a hand-computed byte sequence, so a regression cannot hide
// behind a matching reference encoder.
func TestP1363ToASN1LeadingZeroAndHighBit(t *testing.T) {
	p256 := elliptic.P256()
	one := big.NewInt(1)
	highByte := big.NewInt(0x80)
	// A value with the top bit of its first significant byte set, spanning the
	// full curve width.
	fullHigh := new(big.Int).Sub(new(big.Int).Lsh(one, 256), one) // 2^256-1, all 0xff
	// A value one byte shorter than the curve width: the fixed-width form carries
	// a leading zero byte that DER must not keep.
	shortLow := new(big.Int).SetBytes(bytes.Repeat([]byte{0x01}, 31))

	cases := []struct {
		name    string
		r, s    *big.Int
		wantDER []byte
	}{
		{
			// Minimal INTEGERs: 30 06 (02 01 01)(02 01 01).
			name:    "r=1,s=1 strips 31 leading zero bytes each",
			r:       one,
			s:       one,
			wantDER: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		},
		{
			// 0x80 has its high bit set: 02 02 00 80, not 02 01 80.
			name:    "r=0x80 gets the mandatory 0x00 prefix",
			r:       highByte,
			s:       one,
			wantDER: []byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01},
		},
		{
			name:    "s=0x80 gets the mandatory 0x00 prefix",
			r:       one,
			s:       highByte,
			wantDER: []byte{0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := p1363ToASN1(p1363Encode(t, p256, tc.r, tc.s))
			if err != nil {
				t.Fatalf("p1363ToASN1: %v", err)
			}
			if !bytes.Equal(der, tc.wantDER) {
				t.Errorf("DER = %x, want %x", der, tc.wantDER)
			}
		})
	}

	// The wide cases are checked structurally: r=2^256-1 must be encoded in 33
	// octets (0x00 || 32 x 0xff) and s must survive the leading-zero strip.
	der, err := p1363ToASN1(p1363Encode(t, p256, fullHigh, shortLow))
	if err != nil {
		t.Fatalf("p1363ToASN1: %v", err)
	}
	gotR, gotS := parseDERSig(t, der)
	if gotR.Cmp(fullHigh) != 0 || gotS.Cmp(shortLow) != 0 {
		t.Fatalf("got r=%x s=%x, want r=%x s=%x", gotR, gotS, fullHigh, shortLow)
	}
	if want := derFromRS(t, fullHigh, shortLow); !bytes.Equal(der, want) {
		t.Fatalf("DER = %x, want %x", der, want)
	}
	if !bytes.Contains(der, append([]byte{0x02, 0x21, 0x00}, bytes.Repeat([]byte{0xff}, 32)...)) {
		t.Errorf("r=2^256-1 was not encoded as a 33-octet INTEGER with a 0x00 prefix: %x", der)
	}
}

// TestP1363ToASN1P521 pins the curve whose width is neither a power of two nor a
// multiple of four: P-521 signatures are 2x66 bytes, and code that assumes 64 or
// 65 splits r and s apart at the wrong offset.
func TestP1363ToASN1P521(t *testing.T) {
	p521 := elliptic.P521()
	if got := coordWidth(p521); got != 66 {
		t.Fatalf("P-521 half width = %d, want 66", got)
	}
	key, err := ecdsa.GenerateKey(p521, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("p-521"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	raw := p1363Encode(t, p521, r, s)
	if len(raw) != 132 {
		t.Fatalf("P-521 P1363 signature is %d bytes, want 132", len(raw))
	}
	der, err := p1363ToASN1(raw)
	if err != nil {
		t.Fatalf("p1363ToASN1: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatalf("P-521 signature does not verify: %x", der)
	}

	// The leading half of a P-521 r is very often zero (the top byte holds a
	// single bit), which is exactly the case a naive encoder mangles. Force it.
	smallR := big.NewInt(1)
	der, err = p1363ToASN1(p1363Encode(t, p521, smallR, s))
	if err != nil {
		t.Fatalf("p1363ToASN1 with a 1-byte r: %v", err)
	}
	gotR, gotS := parseDERSig(t, der)
	if gotR.Cmp(smallR) != 0 || gotS.Cmp(s) != 0 {
		t.Errorf("got r=%x s=%x, want r=1 s=%x", gotR, gotS, s)
	}
}

// TestP1363ToASN1RejectsMalformedLength covers the inputs that cannot be a
// fixed-width r||s pair at all. They must be rejected rather than split at a
// bogus offset — a silently mis-split signature is emitted as a certificate
// signature and fails only at the relying party.
func TestP1363ToASN1RejectsMalformedLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"odd 63", make([]byte, 63)},
		{"odd 65", make([]byte, 65)},
		{"odd 131 (P-521 minus one)", make([]byte, 131)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p1363ToASN1(tc.in)
			if err == nil {
				t.Fatalf("p1363ToASN1(%d bytes) = %x, want an error", len(tc.in), got)
			}
			if got != nil {
				t.Errorf("returned %x alongside the error; callers that ignore err would sign with it", got)
			}
		})
	}
}

// TestP1363ToASN1MisSplitDoesNotVerify documents the one check the converter
// cannot make: it takes no curve, so an even-length input of the wrong width for
// the key (a backend that stripped leading zeros, say) is split at len/2 and
// accepted. The guarantee that remains — and that this test holds — is that the
// result is an *invalid* signature, never a second valid one.
func TestP1363ToASN1MisSplitDoesNotVerify(t *testing.T) {
	p521 := elliptic.P521()
	key, err := ecdsa.GenerateKey(p521, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("wrong width"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	// The same signature at P-256 width (64 bytes) instead of P-521's 132: a
	// plausible shape for a backend that pads to the wrong curve.
	narrow := make([]byte, 64)
	copy(narrow[:32], r.Bytes()[:32])
	copy(narrow[32:], s.Bytes()[:32])
	der, err := p1363ToASN1(narrow)
	if err != nil {
		// Rejecting it outright is strictly better; accept that as correct too.
		return
	}
	if ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatal("a truncated P1363 signature converted into a verifying signature")
	}
}

// ---------------------------------------------------------------------------
// azurePublicKey / azureKeyType
// ---------------------------------------------------------------------------

// TestAzurePublicKeyRoundTrip decodes the bundle Key Vault returns for a key
// whose public half we already know, and requires the decoded key to be equal to
// the original — the property that keeps the certificate's SubjectPublicKeyInfo
// matching the key that will sign with it. Both the software ("EC"/"RSA") and
// Managed HSM ("EC-HSM"/"RSA-HSM") key types are covered: Managed HSM is the
// deployment shape the docs recommend, and an unhandled kty there would break
// every key lookup.
func TestAzurePublicKeyRoundTrip(t *testing.T) {
	for _, kty := range []azkeys.KeyType{azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM} {
		t.Run(string(kty), func(t *testing.T) {
			want := &testRSAKey().PublicKey
			got, err := azurePublicKey(rsaJWK(kty, want))
			if err != nil {
				t.Fatalf("azurePublicKey: %v", err)
			}
			pub, ok := got.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("decoded %T, want *rsa.PublicKey", got)
			}
			if !pub.Equal(want) {
				t.Errorf("decoded RSA key does not equal the original (E=%d)", pub.E)
			}
			if pub.E != want.E {
				t.Errorf("E = %d, want %d", pub.E, want.E)
			}
		})
	}
	for _, c := range azureCurves {
		for _, kty := range []azkeys.KeyType{azkeys.KeyTypeEC, azkeys.KeyTypeECHSM} {
			t.Run(string(kty)+"/"+string(c.name), func(t *testing.T) {
				key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				got, err := azurePublicKey(ecJWK(kty, c.name, &key.PublicKey))
				if err != nil {
					t.Fatalf("azurePublicKey: %v", err)
				}
				pub, ok := got.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("decoded %T, want *ecdsa.PublicKey", got)
				}
				if !pub.Equal(&key.PublicKey) {
					t.Error("decoded EC key does not equal the original")
				}
				if pub.Curve != c.curve {
					t.Errorf("curve = %v, want %v", pub.Curve.Params().Name, c.curve.Params().Name)
				}
				// A JWK coordinate is fixed-width by spec, but a peer that trims
				// leading zeros must still decode to the same point.
				trimmed := ecJWK(kty, c.name, &key.PublicKey)
				trimmed.X = key.X.Bytes()
				trimmed.Y = key.Y.Bytes()
				got2, err := azurePublicKey(trimmed)
				if err != nil {
					t.Fatalf("azurePublicKey with minimal-length coordinates: %v", err)
				}
				if !got2.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
					t.Error("minimal-length coordinates decoded to a different point")
				}
			})
		}
	}
}

// TestAzurePublicKeyRejectsMalformedBundles covers the inputs that carry no
// usable key material. Each must produce an error, not a zero-valued key that
// would be published in a certificate.
func TestAzurePublicKeyRejectsMalformedBundles(t *testing.T) {
	rsaPub := &testRSAKey().PublicKey
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	unknownCurve := azkeys.CurveName("P-256K")
	unknownKty := azkeys.KeyType("oct")

	noN := rsaJWK(azkeys.KeyTypeRSA, rsaPub)
	noN.N = nil
	noE := rsaJWK(azkeys.KeyTypeRSA, rsaPub)
	noE.E = nil
	emptyE := rsaJWK(azkeys.KeyTypeRSA, rsaPub)
	emptyE.E = []byte{}
	noCurve := ecJWK(azkeys.KeyTypeEC, azkeys.CurveNameP256, &ecKey.PublicKey)
	noCurve.Crv = nil

	for _, tc := range []struct {
		name string
		jwk  *azkeys.JSONWebKey
	}{
		{"nil bundle", nil},
		{"nil kty", &azkeys.JSONWebKey{}},
		{"RSA without modulus", noN},
		{"RSA without exponent", noE},
		{"RSA with empty exponent", emptyE},
		{"EC without curve", noCurve},
		{"EC with unknown curve", &azkeys.JSONWebKey{
			Kty: azureKeyTypePtr(azkeys.KeyTypeEC), Crv: &unknownCurve,
			X: ecKey.X.Bytes(), Y: ecKey.Y.Bytes(),
		}},
		{"unknown key type", &azkeys.JSONWebKey{Kty: &unknownKty, N: rsaPub.N.Bytes(), E: []byte{1, 0, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := azurePublicKey(tc.jwk)
			if err == nil {
				t.Fatalf("azurePublicKey = %#v, want an error", got)
			}
			if got != nil {
				t.Errorf("returned %#v alongside the error", got)
			}
		})
	}
}

// TestAzurePublicKeyCorruptCoordinatesNeverYieldAUsableKey covers the EC
// coordinate cases the decoder does not validate — a zero-length or truncated
// coordinate. The decoder accepts them (big.Int.SetBytes takes any width), so the
// property that has to hold is the next one down: the resulting point is not on
// the curve and the x509 encoder refuses it, so a corrupt coordinate cannot reach
// a certificate as a plausible-looking key.
func TestAzurePublicKeyCorruptCoordinatesNeverYieldAUsableKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	base := ecJWK(azkeys.KeyTypeEC, azkeys.CurveNameP256, &key.PublicKey)

	emptyX := *base
	emptyX.X = nil
	emptyY := *base
	emptyY.Y = []byte{}
	// Wrong width for the stated curve: a P-384-width X on a P-256 key.
	wideX := *base
	wideX.X = append(bytes.Repeat([]byte{0xab}, 16), base.X...)
	// Truncated by one byte, the classic "stripped a leading zero" corruption.
	shortX := *base
	shortX.X = base.X[1:]

	for _, tc := range []struct {
		name string
		jwk  *azkeys.JSONWebKey
	}{
		{"zero-length X", &emptyX},
		{"zero-length Y", &emptyY},
		{"X wider than the curve", &wideX},
		{"X truncated by one byte", &shortX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := azurePublicKey(tc.jwk)
			if err != nil {
				return // rejecting outright is the stronger behavior
			}
			pub, ok := got.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("decoded %T, want *ecdsa.PublicKey", got)
			}
			if pub.Equal(&key.PublicKey) {
				t.Fatal("a corrupted coordinate decoded to the original key")
			}
			// ecdh.NewPublicKey performs the on-curve check that the deprecated
			// elliptic.Curve.IsOnCurve used to expose, through a supported API.
			if _, err := pub.ECDH(); err == nil {
				t.Fatal("a corrupted coordinate produced a point on the curve")
			}
			if _, err := x509.MarshalPKIXPublicKey(pub); err == nil {
				t.Fatal("x509 accepted a public key that is not on the curve: corruption would reach a certificate")
			}
		})
	}
}

// TestAzureKeyTypeFromBundle pins the canonical key type derived from a returned
// bundle, for the software and Managed HSM key types alike. The RSA cases are
// keyed on the modulus width Key Vault reports for each supported size.
func TestAzureKeyTypeFromBundle(t *testing.T) {
	for _, c := range azureCurves {
		for _, kty := range []azkeys.KeyType{azkeys.KeyTypeEC, azkeys.KeyTypeECHSM} {
			t.Run(string(kty)+"/"+string(c.name), func(t *testing.T) {
				k := kty
				crv := c.name
				got, err := azureKeyType(&azkeys.JSONWebKey{Kty: &k, Crv: &crv})
				if err != nil {
					t.Fatalf("azureKeyType: %v", err)
				}
				if got != c.keyType {
					t.Errorf("key type = %q, want %q", got, c.keyType)
				}
			})
		}
	}
	for _, tc := range []struct {
		bits int
		want string
	}{
		{2048, KeyTypeRSA2048},
		{3072, KeyTypeRSA3072},
		{4096, KeyTypeRSA4096},
	} {
		for _, kty := range []azkeys.KeyType{azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM} {
			t.Run(fmt.Sprintf("%s/%d", kty, tc.bits), func(t *testing.T) {
				k := kty
				// A real modulus is exactly bits/8 bytes with the top bit set.
				n := make([]byte, tc.bits/8)
				n[0] = 0xc0
				got, err := azureKeyType(&azkeys.JSONWebKey{Kty: &k, N: n})
				if err != nil {
					t.Fatalf("azureKeyType: %v", err)
				}
				if got != tc.want {
					t.Errorf("%d-bit modulus (%d bytes) mapped to %q, want %q", tc.bits, len(n), got, tc.want)
				}
			})
		}
	}
}

func TestAzureKeyTypeRejectsUnusableBundles(t *testing.T) {
	unknownCurve := azkeys.CurveName("P-256K")
	unknownKty := azkeys.KeyType("oct-HSM")
	ec := azkeys.KeyTypeEC
	for _, tc := range []struct {
		name string
		jwk  *azkeys.JSONWebKey
	}{
		{"nil bundle", nil},
		{"nil kty", &azkeys.JSONWebKey{}},
		{"EC without curve", &azkeys.JSONWebKey{Kty: &ec}},
		{"EC with an unsupported curve", &azkeys.JSONWebKey{Kty: &ec, Crv: &unknownCurve}},
		{"unsupported key type", &azkeys.JSONWebKey{Kty: &unknownKty}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := azureKeyType(tc.jwk)
			if err == nil {
				t.Fatalf("azureKeyType = %q, want an error", got)
			}
			if got != "" {
				t.Errorf("returned %q alongside the error", got)
			}
		})
	}
}

// TestAzureCreateParamsRoundTripToKeyType is the drift guard across the pair of
// mappers: for every key type the backend will create, the bundle Key Vault
// returns for those parameters must map back to the same canonical key type. If
// one direction learns a new key size and the other does not, a key created as
// RSA-3072 starts reporting as something else — and this test fails instead.
func TestAzureCreateParamsRoundTripToKeyType(t *testing.T) {
	for _, keyType := range []string{
		KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521,
		KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096,
	} {
		t.Run(keyType, func(t *testing.T) {
			params, err := azureCreateParams(keyType)
			if err != nil {
				t.Fatalf("azureCreateParams: %v", err)
			}
			if params.Kty == nil {
				t.Fatal("create parameters carry no key type")
			}
			// Rebuild the bundle Key Vault would answer with for those parameters.
			jwk := &azkeys.JSONWebKey{Kty: params.Kty}
			switch *params.Kty {
			case azkeys.KeyTypeEC:
				if params.Curve == nil {
					t.Fatal("EC create parameters carry no curve")
				}
				if params.KeySize != nil {
					t.Errorf("EC create parameters also set KeySize = %d", *params.KeySize)
				}
				jwk.Crv = params.Curve
			case azkeys.KeyTypeRSA:
				if params.KeySize == nil {
					t.Fatal("RSA create parameters carry no key size")
				}
				if params.Curve != nil {
					t.Errorf("RSA create parameters also set Curve = %q", *params.Curve)
				}
				n := make([]byte, *params.KeySize/8)
				n[0] = 0xc0
				jwk.N = n
			default:
				t.Fatalf("unexpected kty %q", *params.Kty)
			}
			got, err := azureKeyType(jwk)
			if err != nil {
				t.Fatalf("azureKeyType on the bundle for %q: %v", keyType, err)
			}
			if got != keyType {
				t.Errorf("round trip: %q -> create params -> %q", keyType, got)
			}
		})
	}
}

// TestAzureCreateParamsRejectsUnsupportedKeyTypes: a key type Key Vault cannot
// hold must fail before the API call, and must not come back as empty parameters
// that would create something unintended.
func TestAzureCreateParamsRejectsUnsupportedKeyTypes(t *testing.T) {
	for _, keyType := range []string{
		"", " ", KeyTypeEd25519, KeyTypeMLDSA44, KeyTypeMLDSA65, KeyTypeMLDSA87,
		"rsa-1024", "rsa", "ecdsa", "RSA-2048", KeyTypeECDSAP256 + "x",
	} {
		t.Run("keyType="+keyType, func(t *testing.T) {
			params, err := azureCreateParams(keyType)
			if err == nil {
				t.Fatalf("azureCreateParams(%q) succeeded, want an error", keyType)
			}
			if params.Kty != nil || params.Curve != nil || params.KeySize != nil {
				t.Errorf("returned non-zero parameters alongside the error: %+v", params)
			}
		})
	}
}

func TestAzureECAndRSAParams(t *testing.T) {
	ec := ecParams(azkeys.CurveNameP384)
	if ec.Kty == nil || *ec.Kty != azkeys.KeyTypeEC {
		t.Errorf("ecParams Kty = %v, want EC", ec.Kty)
	}
	if ec.Curve == nil || *ec.Curve != azkeys.CurveNameP384 {
		t.Errorf("ecParams Curve = %v, want P-384", ec.Curve)
	}
	// Each call must own its pointers: a shared pointer would let one create call
	// mutate another's parameters.
	other := ecParams(azkeys.CurveNameP256)
	if ec.Curve == other.Curve || ec.Kty == other.Kty {
		t.Error("ecParams reuses pointers across calls")
	}
	if *ec.Curve != azkeys.CurveNameP384 {
		t.Error("a second ecParams call changed the first result's curve")
	}

	r := rsaParams(3072)
	if r.Kty == nil || *r.Kty != azkeys.KeyTypeRSA {
		t.Errorf("rsaParams Kty = %v, want RSA", r.Kty)
	}
	if r.KeySize == nil || *r.KeySize != 3072 {
		t.Errorf("rsaParams KeySize = %v, want 3072", r.KeySize)
	}
	if r2 := rsaParams(4096); r.KeySize == r2.KeySize || *r.KeySize != 3072 {
		t.Error("rsaParams reuses the KeySize pointer across calls")
	}
}

// ---------------------------------------------------------------------------
// azureSignatureAlgorithm
// ---------------------------------------------------------------------------

// TestAzureSignatureAlgorithm pins every (key family, digest, PSS) combination
// the CA/TSA/OCSP paths emit onto its JOSE algorithm name. The RSA padding half
// matters most: hand back RS256 for a PSS request and Key Vault produces a
// PKCS#1 v1.5 signature under a certificate that advertises PSS — a signature no
// verifier accepts.
func TestAzureSignatureAlgorithm(t *testing.T) {
	rsaTypes := []string{KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096}
	for _, keyType := range rsaTypes {
		for _, tc := range []struct {
			hash crypto.Hash
			pss  bool
			want azkeys.SignatureAlgorithm
		}{
			{crypto.SHA256, false, azkeys.SignatureAlgorithmRS256},
			{crypto.SHA384, false, azkeys.SignatureAlgorithmRS384},
			{crypto.SHA512, false, azkeys.SignatureAlgorithmRS512},
			{crypto.SHA256, true, azkeys.SignatureAlgorithmPS256},
			{crypto.SHA384, true, azkeys.SignatureAlgorithmPS384},
			{crypto.SHA512, true, azkeys.SignatureAlgorithmPS512},
		} {
			t.Run(fmt.Sprintf("%s/%v/pss=%v", keyType, tc.hash, tc.pss), func(t *testing.T) {
				got, err := azureSignatureAlgorithm(keyType, tc.hash, tc.pss)
				if err != nil {
					t.Fatalf("azureSignatureAlgorithm: %v", err)
				}
				if got != tc.want {
					t.Fatalf("algorithm = %q, want %q", got, tc.want)
				}
				if tc.pss != strings.HasPrefix(string(got), "PS") {
					t.Errorf("pss=%v produced %q: the padding scheme does not match the request", tc.pss, got)
				}
			})
		}
	}
	for _, c := range azureCurves {
		for _, tc := range []struct {
			hash crypto.Hash
			want azkeys.SignatureAlgorithm
		}{
			{crypto.SHA256, azkeys.SignatureAlgorithmES256},
			{crypto.SHA384, azkeys.SignatureAlgorithmES384},
			{crypto.SHA512, azkeys.SignatureAlgorithmES512},
		} {
			t.Run(fmt.Sprintf("%s/%v", c.keyType, tc.hash), func(t *testing.T) {
				got, err := azureSignatureAlgorithm(c.keyType, tc.hash, false)
				if err != nil {
					t.Fatalf("azureSignatureAlgorithm: %v", err)
				}
				if got != tc.want {
					t.Errorf("algorithm = %q, want %q", got, tc.want)
				}
				// PSS is an RSA-only notion; an ECDSA key must not be routed to a
				// PS* algorithm because a caller passed *rsa.PSSOptions.
				pssGot, err := azureSignatureAlgorithm(c.keyType, tc.hash, true)
				if err != nil {
					t.Fatalf("azureSignatureAlgorithm(pss=true): %v", err)
				}
				if pssGot != tc.want {
					t.Errorf("pss=true on an ECDSA key changed the algorithm to %q", pssGot)
				}
			})
		}
	}
}

// TestAzureSignatureAlgorithmRejectsUnsupportedHash: a digest Key Vault has no
// algorithm for must fail locally. An empty SignatureAlgorithm sent to the API
// would be rejected by the service, but only after the CA believed it had signed.
func TestAzureSignatureAlgorithmRejectsUnsupportedHash(t *testing.T) {
	for _, keyType := range []string{KeyTypeRSA2048, KeyTypeECDSAP256} {
		for _, hash := range []crypto.Hash{crypto.Hash(0), crypto.SHA1, crypto.SHA224, crypto.MD5, crypto.SHA512_256} {
			for _, pss := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%v/pss=%v", keyType, hash, pss), func(t *testing.T) {
					got, err := azureSignatureAlgorithm(keyType, hash, pss)
					if err == nil {
						t.Fatalf("azureSignatureAlgorithm(%q, %v) = %q, want an error", keyType, hash, got)
					}
					if got != "" {
						t.Errorf("returned %q alongside the error", got)
					}
				})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// keyName / remoteFromBundle
// ---------------------------------------------------------------------------

// TestAzureKeyNameSanitizes holds keyName to the Key Vault name charset
// (alphanumerics and hyphens). A character that slips through produces a 400 on
// every operation for that key, and a label that sanitizes differently on the
// create and resolve paths produces a key nobody can find.
func TestAzureKeyNameSanitizes(t *testing.T) {
	allowed := regexp.MustCompile(`^[0-9A-Za-z-]*$`)
	for _, tc := range []struct {
		prefix, label, want string
	}{
		{"", "ca-root", "ca-root"},
		{"secsy-", "ca-root", "secsy-ca-root"},
		{"secsy/", "ca root", "secsy-ca-root"},
		{"", "tenant_1.key", "tenant-1-key"},
		{"", "a:b;c=d", "a-b-c-d"},
		{"", "trailing\n", "trailing-"},
		{"pre-", "", "pre-"},
		// One hyphen per *rune*, not per byte: byte-wise sanitization would turn
		// each two-byte rune into two hyphens and change the name length.
		{"", "café", "caf-"},
		{"", "日本", "--"},
	} {
		t.Run(tc.prefix+"|"+tc.label, func(t *testing.T) {
			b := &azureKeyVaultBackend{prefix: tc.prefix}
			got := b.keyName(tc.label)
			if got != tc.want {
				t.Errorf("keyName(%q) with prefix %q = %q, want %q", tc.label, tc.prefix, got, tc.want)
			}
			if !allowed.MatchString(got) {
				t.Errorf("keyName(%q) = %q contains characters Key Vault rejects", tc.label, got)
			}
		})
	}
}

// TestAzureRemoteFromBundle checks the identity the rest of the backend depends
// on: Sign addresses the key by KeyID, and KeyID must therefore be the sanitized
// vault name (prefix included), with the URI derived from the same string. A
// KeyID holding the raw label would 404 on every signature.
func TestAzureRemoteFromBundle(t *testing.T) {
	b := &azureKeyVaultBackend{prefix: "secsy-"}
	want := &testRSAKey().PublicKey
	rk, err := b.remoteFromBundle("ca root", KeyTypeRSA2048, rsaJWK(azkeys.KeyTypeRSA, want))
	if err != nil {
		t.Fatalf("remoteFromBundle: %v", err)
	}
	if rk.Label != "ca root" {
		t.Errorf("Label = %q, want the unsanitized label %q", rk.Label, "ca root")
	}
	if rk.KeyID != "secsy-ca-root" {
		t.Errorf("KeyID = %q, want the sanitized vault name %q", rk.KeyID, "secsy-ca-root")
	}
	if rk.URI != "kms:azure:"+rk.KeyID {
		t.Errorf("URI = %q, want %q", rk.URI, "kms:azure:"+rk.KeyID)
	}
	if rk.KeyType != KeyTypeRSA2048 {
		t.Errorf("KeyType = %q, want %q", rk.KeyType, KeyTypeRSA2048)
	}
	pub, ok := rk.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(want) {
		t.Errorf("PublicKey = %#v, want the bundle's key", rk.PublicKey)
	}

	// A bundle with no usable key material must fail the whole conversion rather
	// than yield a RemoteKey with a nil public key.
	if rk, err := b.remoteFromBundle("ca", KeyTypeRSA2048, &azkeys.JSONWebKey{}); err == nil {
		t.Errorf("remoteFromBundle with an empty bundle = %+v, want an error", rk)
	}
}

// ---------------------------------------------------------------------------
// isAzureNotFound
// ---------------------------------------------------------------------------

// azureResponseError builds the *azcore.ResponseError the Key Vault SDK returns
// for a given status and body, so the not-found predicate is tested against real
// SDK errors rather than hand-written strings.
func azureResponseError(t *testing.T, status int, statusText, body string) error {
	t.Helper()
	resp := &http.Response{
		StatusCode: status,
		Status:     statusText,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    httptest.NewRequest(http.MethodGet, "https://example.vault.azure.net/keys/secsy-ca", nil),
	}
	err := runtime.NewResponseError(resp)
	if err == nil {
		t.Fatal("runtime.NewResponseError returned nil")
	}
	return err
}

// TestIsAzureNotFound holds the predicate to the distinction the callers rely
// on. Ping treats "not found" as *healthy* and ResolveKey turns it into
// ErrKeyNotFound, so a 403 or a 5xx misclassified as not-found would report a
// broken vault as ready and tell callers the CA key does not exist.
func TestIsAzureNotFound(t *testing.T) {
	notFound := azureResponseError(t, http.StatusNotFound, "404 Not Found",
		`{"error":{"code":"KeyNotFound","message":"A key with (name/id) secsy-ca was not found in this key vault"}}`)
	forbidden := azureResponseError(t, http.StatusForbidden, "403 Forbidden",
		`{"error":{"code":"Forbidden","message":"The user, group or application does not have keys get permission on key vault"}}`)
	serverErr := azureResponseError(t, http.StatusInternalServerError, "500 Internal Server Error",
		`{"error":{"code":"InternalServerError","message":"the service encountered an error"}}`)
	throttled := azureResponseError(t, http.StatusTooManyRequests, "429 Too Many Requests",
		`{"error":{"code":"Throttled","message":"slow down"}}`)

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"404 KeyNotFound", notFound, true},
		{"404 wrapped by the caller", fmt.Errorf("checking azure key %q: %w", "ca", notFound), true},
		{"403 Forbidden", forbidden, false},
		{"500 InternalServerError", serverErr, false},
		{"429 Throttled", throttled, false},
		{"transport failure", errors.New("dial tcp: connection reset by peer"), false},
		{"context cancelled", errors.New("context deadline exceeded"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAzureNotFound(tc.err); got != tc.want {
				t.Errorf("isAzureNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
