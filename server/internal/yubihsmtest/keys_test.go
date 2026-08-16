package yubihsmtest

// Tier 2: the on-device key lifecycle, over every algorithm the product can ask
// for through the native driver.
//
// The pre-existing hardware tests exercise generate-and-sign on P-256 only,
// which is the one curve where a mistake in the curve-size arithmetic cannot
// show up: P-256's field size, digest size and signature component size all
// happen to be 32 bytes. P-384 and P-521 are where truncated digests, mis-sized
// public-key blobs and short signature components become visible, and P-521 is
// where the 521-bit-in-66-bytes encoding does. So the matrix is the point.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// The device's algorithm identifiers. The driver's table names them; these are
// the ones the CA, SSH CA, TSA and signing service can be configured to use.
const (
	algECP256  byte = 12
	algECP384  byte = 13
	algECP521  byte = 14
	algEd25519 byte = 46
)

type ecAlgorithm struct {
	name  string
	id    byte
	curve elliptic.Curve
	// ecdh is the same curve through crypto/ecdh, whose NewPublicKey performs
	// the on-curve check that elliptic.Curve.IsOnCurve used to.
	ecdh ecdh.Curve
	hash func() hash.Hash
}

var ecAlgorithms = []ecAlgorithm{
	{"ecp256", algECP256, elliptic.P256(), ecdh.P256(), sha256.New},
	{"ecp384", algECP384, elliptic.P384(), ecdh.P384(), sha512.New384},
	// P-521 is signed against SHA-512: the device takes a pre-hashed digest and
	// a 64-byte digest is the largest it will accept for a 66-byte field.
	{"ecp521", algECP521, elliptic.P521(), ecdh.P521(), sha512.New},
}

// TestGenerateSignVerifyECDSA is the core lifecycle for each curve: generate on
// the device, read the public half back, sign a digest, and verify the
// signature against that public key with the standard library.
//
// Verifying with crypto/ecdsa rather than with the device is deliberate. A
// device that verified its own signatures would agree with itself even if its
// encoding were wrong; only an independent verifier proves the signature is the
// ASN.1 ECDSA the rest of the world expects.
func TestGenerateSignVerifyECDSA(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 4*len(ecAlgorithms))

	for i, alg := range ecAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			c, ctx := client(t)
			id := generateScratch(t, c, ctx, scratchID(i), alg.name, alg.id, "sign-ecdsa")

			pub := readECDSAPublicKey(t, ctx, c, id, alg)

			h := alg.hash()
			h.Write([]byte("tier 2 signs this"))
			digest := h.Sum(nil)

			sig, err := c.SignECDSA(ctx, id, digest)
			if err != nil {
				t.Fatalf("signing with the %s key: %v", alg.name, err)
			}
			if !ecdsa.VerifyASN1(pub, digest, sig) {
				t.Fatalf("the %s signature does not verify against the device's own public key", alg.name)
			}

			// A signature over a different digest must not verify, or the
			// verification above proves nothing about what was signed.
			other := alg.hash()
			other.Write([]byte("tier 2 did NOT sign this"))
			if ecdsa.VerifyASN1(pub, other.Sum(nil), sig) {
				t.Fatalf("the %s signature verifies against a digest it was not made over", alg.name)
			}

			// ECDSA is randomised: two signatures over the same digest must
			// differ. Identical signatures would mean a deterministic nonce, and
			// a repeated nonce across different digests leaks the private key.
			sig2, err := c.SignECDSA(ctx, id, digest)
			if err != nil {
				t.Fatalf("signing with the %s key a second time: %v", alg.name, err)
			}
			if bytes.Equal(sig, sig2) {
				t.Errorf("two %s signatures over the same digest are byte-identical", alg.name)
			}
			if !ecdsa.VerifyASN1(pub, digest, sig2) {
				t.Fatalf("the second %s signature does not verify", alg.name)
			}

			assertSignatureComponentsFit(t, sig, alg)
		})
	}
}

// readECDSAPublicKey fetches the public half and checks that it describes the
// curve that was asked for. GET PUBLIC KEY returns the raw X||Y coordinates,
// and the length of that blob is the only thing that distinguishes one curve
// from another — a driver that assumed 32-byte coordinates would silently
// mis-parse P-384 into a point that is not on the curve.
func readECDSAPublicKey(t *testing.T, ctx context.Context, c *yubihsm.Client, id uint16, alg ecAlgorithm) *ecdsa.PublicKey {
	t.Helper()
	gotAlg, raw, err := c.GetPublicKey(ctx, id)
	if err != nil {
		t.Fatalf("reading the %s public key: %v", alg.name, err)
	}
	if gotAlg != alg.id {
		t.Fatalf("asked for a %s key, the device says its public key is %s",
			alg.name, yubihsm.AlgorithmName(gotAlg))
	}
	byteLen := (alg.curve.Params().BitSize + 7) / 8
	if len(raw) != 2*byteLen {
		t.Fatalf("%s public key is %d bytes, want %d (X||Y at %d bytes each)",
			alg.name, len(raw), 2*byteLen, byteLen)
	}
	// NewPublicKey rejects a point that is not on the curve, which is the check
	// that matters here: the device returns bare coordinates, and a driver that
	// mis-sliced them would otherwise yield a plausible-looking key that no
	// signature could ever verify against.
	if _, err := alg.ecdh.NewPublicKey(append([]byte{4}, raw...)); err != nil {
		t.Fatalf("the %s public key the device returned is not a valid curve point: %v", alg.name, err)
	}
	return &ecdsa.PublicKey{
		Curve: alg.curve,
		X:     new(big.Int).SetBytes(raw[:byteLen]),
		Y:     new(big.Int).SetBytes(raw[byteLen:]),
	}
}

// assertSignatureComponentsFit checks r and s against the curve order size.
// A component wider than the field means the signature was assembled with the
// wrong curve parameters, which VerifyASN1 would not necessarily catch.
func assertSignatureComponentsFit(t *testing.T, sig []byte, alg ecAlgorithm) {
	t.Helper()
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		t.Fatalf("the %s signature is not a DER SEQUENCE of two INTEGERs: %v", alg.name, err)
	}
	byteLen := (alg.curve.Params().BitSize + 7) / 8
	if l := len(parsed.R.Bytes()); l > byteLen {
		t.Errorf("%s signature r is %d bytes, wider than the %d-byte field", alg.name, l, byteLen)
	}
	if l := len(parsed.S.Bytes()); l > byteLen {
		t.Errorf("%s signature s is %d bytes, wider than the %d-byte field", alg.name, l, byteLen)
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		t.Errorf("%s signature has a non-positive component", alg.name)
	}
}

// TestGenerateSignVerifyEd25519 is the same lifecycle for Ed25519, which takes a
// different path: the device signs the message itself rather than a digest, so
// a driver that pre-hashed here would produce signatures nothing can verify.
func TestGenerateSignVerifyEd25519(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 5)
	c, ctx := client(t)

	id := generateScratch(t, c, ctx, scratchID(3), "ed25519", algEd25519, "sign-eddsa")

	gotAlg, raw, err := c.GetPublicKey(ctx, id)
	if err != nil {
		t.Fatalf("reading the Ed25519 public key: %v", err)
	}
	if gotAlg != algEd25519 {
		t.Fatalf("asked for an Ed25519 key, the device says %s", yubihsm.AlgorithmName(gotAlg))
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("Ed25519 public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(raw)

	message := []byte("tier 2 signs this whole message, not a digest of it")
	sig, err := c.SignEdDSA(ctx, id, message)
	if err != nil {
		t.Fatalf("signing with the Ed25519 key: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Ed25519 signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, message, sig) {
		t.Fatal("the Ed25519 signature does not verify against the device's own public key")
	}
	if ed25519.Verify(pub, append(message, '!'), sig) {
		t.Fatal("the Ed25519 signature verifies against a message it was not made over")
	}

	// Ed25519 is deterministic: the same message must produce the same
	// signature. A difference would mean the device is not implementing
	// RFC 8032, and callers that cache signatures would be wrong.
	sig2, err := c.SignEdDSA(ctx, id, message)
	if err != nil {
		t.Fatalf("signing with the Ed25519 key a second time: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Error("two Ed25519 signatures over the same message differ; RFC 8032 signing is deterministic")
	}
}

// TestImportedKeySignsAndVerifies imports a host-generated key and signs with
// it. Import is how a CA migrated from a software key gets onto the device
// (Task 74), and the property that matters is that the device's copy is the key
// that was sent: signing with it must verify against the public half the host
// kept.
func TestImportedKeySignsAndVerifies(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 4)
	c, ctx := client(t)

	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key on the host: %v", err)
	}

	id := scratchID(4)
	deleteScratch(ctx, c, id)
	// The device wants the raw private scalar, padded to the field size.
	scalar := host.D.FillBytes(make([]byte, 32))
	got, err := c.PutAsymmetricKey(ctx, yubihsm.KeySpec{
		ID:           id,
		Label:        label("imported"),
		Domains:      1,
		Capabilities: capabilities(t, "sign-ecdsa"),
		Algorithm:    algECP256,
	}, scalar)
	if err != nil {
		t.Fatalf("importing the host key: %v", err)
	}
	t.Cleanup(func() { deleteScratch(ctx, c, got) })

	// The device's public half must be the host key's public half.
	_, raw, err := c.GetPublicKey(ctx, got)
	if err != nil {
		t.Fatalf("reading the imported key's public half: %v", err)
	}
	wantX := host.X.FillBytes(make([]byte, 32))
	wantY := host.Y.FillBytes(make([]byte, 32))
	if !bytes.Equal(raw[:32], wantX) || !bytes.Equal(raw[32:], wantY) {
		t.Fatal("the device's public key is not the imported key's public key")
	}

	digest := sha256.Sum256([]byte("signed by the imported key"))
	sig, err := c.SignECDSA(ctx, got, digest[:])
	if err != nil {
		t.Fatalf("signing with the imported key: %v", err)
	}
	if !ecdsa.VerifyASN1(&host.PublicKey, digest[:], sig) {
		t.Fatal("the imported key's signature does not verify against the host key it was imported from")
	}
}

// TestObjectMetadataSurvivesRoundTrip checks that what the device reports about
// a key is what was asked for.
//
// Every claim the attestation and audit tiers make is phrased in terms of these
// fields — the capability mask decides whether a key is exportable, the origin
// byte decides whether it was generated on the device — so a field that did not
// round-trip would make those verdicts meaningless.
func TestObjectMetadataSurvivesRoundTrip(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 3)
	c, ctx := client(t)

	wantLabel := label("metadata")
	wantCaps := capabilities(t, "sign-ecdsa", "sign-attestation-certificate")
	id := scratchID(5)
	deleteScratch(ctx, c, id)
	got, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
		ID:           id,
		Label:        wantLabel,
		Domains:      3, // two domains, so a single-domain default would show
		Capabilities: wantCaps,
		Algorithm:    algECP256,
	})
	if err != nil {
		t.Fatalf("generating the key: %v", err)
	}
	t.Cleanup(func() { deleteScratch(ctx, c, got) })

	info, err := c.GetObjectInfo(ctx, got, yubihsm.ObjectTypeAsymmetricKey)
	if err != nil {
		t.Fatalf("describing the key: %v", err)
	}
	if info.Label != wantLabel {
		t.Errorf("label = %q, want %q", info.Label, wantLabel)
	}
	if info.Capabilities != wantCaps {
		t.Errorf("capabilities = 0x%016x, want 0x%016x", info.Capabilities, wantCaps)
	}
	if info.Domains != 3 {
		t.Errorf("domains = 0x%04x, want 0x0003", info.Domains)
	}
	if info.Algorithm != algECP256 {
		t.Errorf("algorithm = %s, want ecp256", yubihsm.AlgorithmName(info.Algorithm))
	}
	if info.Type != yubihsm.ObjectTypeAsymmetricKey {
		t.Errorf("type = %s, want asymmetric-key", yubihsm.ObjectTypeName(info.Type))
	}
	// Origin distinguishes a generated key from an imported one, and the
	// exportability verdict in the attestation tier is built on it.
	if info.Origin == 0 {
		t.Error("the device reports no origin for a key it generated")
	}
}

// TestCapabilitiesAreEnforced signs with a key that has no signing capability.
//
// The capability mask is the device's authorization model, and every "this key
// can only do X" claim the product makes is really a claim about that mask. If
// the device did not enforce it, an audit that reported a key's capabilities
// would be describing a preference rather than a constraint.
func TestCapabilitiesAreEnforced(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 3)
	c, ctx := client(t)

	// sign-eddsa on an EC P-256 key: a capability the key cannot use, so the
	// key has no applicable signing capability at all.
	id := generateScratch(t, c, ctx, scratchID(6), "nosign", algECP256, "sign-eddsa")

	digest := sha256.Sum256([]byte("this must not be signed"))
	if _, err := c.SignECDSA(ctx, id, digest[:]); err == nil {
		t.Fatal("the device signed with a key that has no sign-ecdsa capability")
	} else {
		var devErr yubihsm.DeviceError
		if !errors.As(err, &devErr) {
			t.Fatalf("want a device refusal, got %T: %v", err, err)
		}
		t.Logf("refused as expected: %v", devErr)
	}
}

// TestDeleteRemovesTheKey checks that deletion actually deletes.
//
// Key destruction is the last step of every rotation and of the escrow and
// ceremony flows. A delete that reported success without removing the object
// would leave a supposedly-retired signing key live on the device.
func TestDeleteRemovesTheKey(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 3)
	c, ctx := client(t)

	id := scratchID(7)
	deleteScratch(ctx, c, id)
	got, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
		ID: id, Label: label("delete-me"), Domains: 1,
		Capabilities: capabilities(t, "sign-ecdsa"), Algorithm: algECP256,
	})
	if err != nil {
		t.Fatalf("generating the key: %v", err)
	}
	if _, err := c.GetObjectInfo(ctx, got, yubihsm.ObjectTypeAsymmetricKey); err != nil {
		t.Fatalf("the key is not there right after generating it: %v", err)
	}
	if err := c.DeleteObject(ctx, got, yubihsm.ObjectTypeAsymmetricKey); err != nil {
		t.Fatalf("deleting the key: %v", err)
	}
	if _, err := c.GetObjectInfo(ctx, got, yubihsm.ObjectTypeAsymmetricKey); err == nil {
		t.Fatal("the key is still on the device after a successful delete")
	}
	// Deleting it again must fail rather than silently succeed, so that a
	// double-delete in a rotation is visible instead of masking a wrong handle.
	if err := c.DeleteObject(ctx, got, yubihsm.ObjectTypeAsymmetricKey); err == nil {
		t.Error("deleting an already-deleted object reported success")
	}
}

// TestGeneratedKeysAreDistinct generates the same specification twice and
// checks the two keys differ.
//
// It is a cheap sanity check on the device's key generation: two keys born from
// identical templates sharing a public key would mean the generator is seeded
// from the template rather than from the device's entropy source, which would
// make every CA key in a fleet the same key.
func TestGeneratedKeysAreDistinct(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)
	c, ctx := client(t)

	pubs := make([][]byte, 0, 2)
	for i, id := range []uint16{scratchID(8), scratchID(9)} {
		key := generateScratch(t, c, ctx, id, "distinct", algECP256, "sign-ecdsa")
		_, raw, err := c.GetPublicKey(ctx, key)
		if err != nil {
			t.Fatalf("reading public key %d: %v", i, err)
		}
		pubs = append(pubs, raw)
	}
	if bytes.Equal(pubs[0], pubs[1]) {
		t.Fatal("two keys generated from the same template have the same public key")
	}
}

// TestPublicKeyMatchesAttestationCertificate cross-checks the two ways the
// device will hand out a key's public half: GET PUBLIC KEY and the subject
// public key of its attestation certificate.
//
// The audit subsystem identifies a key by the public key an auditor supplies
// and then finds the matching attestation. If these two views disagreed, that
// lookup would fail for keys that are perfectly fine, or — worse — succeed for
// the wrong key.
func TestPublicKeyMatchesAttestationCertificate(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 4)
	c, ctx := client(t)

	id := generateScratch(t, c, ctx, scratchID(10), "pubmatch", algECP256, "sign-ecdsa")

	_, raw, err := c.GetPublicKey(ctx, id)
	if err != nil {
		t.Fatalf("reading the public key: %v", err)
	}
	der, err := c.AttestAsymmetricKey(ctx, id, 0)
	if err != nil {
		t.Fatalf("attesting the key: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the attestation certificate: %v", err)
	}
	attested, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the attestation certificate carries a %T, want an ECDSA key", cert.PublicKey)
	}
	want := append(attested.X.FillBytes(make([]byte, 32)), attested.Y.FillBytes(make([]byte, 32))...)
	if !bytes.Equal(raw, want) {
		t.Fatalf("GET PUBLIC KEY and the attestation certificate disagree about the key:\n  direct %x\n  cert   %x", raw, want)
	}
}
