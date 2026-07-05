package secret

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fpe"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestDeriveFPEKeyDeterministicAndSeparated: derivation is a pure function of its
// inputs (stable ciphertext / equality search depends on it) and independent
// across templates and families (per-template key isolation).
func TestDeriveFPEKeyDeterministicAndSeparated(t *testing.T) {
	seed := make([]byte, FPESeedBytes)
	for i := range seed {
		seed[i] = byte(i)
	}
	k1, err := DeriveFPEKey(seed, "fam", "pan")
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != fpeKeyBytes {
		t.Fatalf("key length %d, want %d", len(k1), fpeKeyBytes)
	}
	again, _ := DeriveFPEKey(seed, "fam", "pan")
	if string(k1) != string(again) {
		t.Fatal("derivation is not deterministic")
	}
	if other, _ := DeriveFPEKey(seed, "fam", "ssn"); string(k1) == string(other) {
		t.Fatal("different templates derived the same key")
	}
	if otherFam, _ := DeriveFPEKey(seed, "other", "pan"); string(k1) == string(otherFam) {
		t.Fatal("different families derived the same key")
	}
}

// TestDeriveFPEKeyValidation rejects malformed inputs.
func TestDeriveFPEKeyValidation(t *testing.T) {
	if _, err := DeriveFPEKey(make([]byte, 8), "fam", "pan"); err == nil {
		t.Fatal("expected rejection of short seed")
	}
	if _, err := DeriveFPEKey(make([]byte, FPESeedBytes), "fam", ""); err == nil {
		t.Fatal("expected rejection of empty template")
	}
}

// TestResolveTransformTemplate covers the config-resolution rules: defaults, the
// FF1 domain-minimum floor, and tweak-source / determinism consistency.
func TestResolveTransformTemplate(t *testing.T) {
	// A deterministic digits template with defaults resolves to a radix-10, min-6
	// (domain minimum), tweak=none template.
	tmpl, err := ResolveTransformTemplate(TransformSpec{Name: "pan", Alphabet: "digits", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Radix() != 10 || tmpl.MinLength != 6 || tmpl.TweakSource != TweakSourceNone {
		t.Fatalf("unexpected resolution: radix=%d min=%d tweak=%s", tmpl.Radix(), tmpl.MinLength, tmpl.TweakSource)
	}

	// A min_length below the FF1 domain minimum is rejected.
	if _, err := ResolveTransformTemplate(TransformSpec{Name: "x", Alphabet: "digits", MinLength: 4, Deterministic: true}); err == nil {
		t.Fatal("expected rejection of min_length below the domain minimum")
	}
	// Deterministic + tweak_source=request is contradictory.
	if _, err := ResolveTransformTemplate(TransformSpec{Name: "x", Alphabet: "digits", Deterministic: true, TweakSource: TweakSourceRequest}); err == nil {
		t.Fatal("expected rejection of deterministic+request")
	}
	// Non-deterministic + tweak_source=none is contradictory.
	if _, err := ResolveTransformTemplate(TransformSpec{Name: "x", Alphabet: "digits", Deterministic: false, TweakSource: TweakSourceNone}); err == nil {
		t.Fatal("expected rejection of non-deterministic+none")
	}
	// Unknown alphabet is rejected.
	if _, err := ResolveTransformTemplate(TransformSpec{Name: "x", Alphabet: "nope", Deterministic: true}); err == nil {
		t.Fatal("expected rejection of unknown alphabet")
	}
	// An inline custom alphabet resolves to its own radix.
	custom, err := ResolveTransformTemplate(TransformSpec{Name: "dna", Alphabet: "chars:ACGT", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if custom.Radix() != 4 {
		t.Fatalf("custom radix = %d, want 4", custom.Radix())
	}
}

// transformerFor builds a Transformer directly from a key derived off a fixed
// seed, so the Encode/Decode policy (length, tweak, format) is exercised without
// needing a KEK. The full seal/unseal/derive path over a real Ring is covered by
// TestFPESeedLifecycleWithRing and the SoftHSM test.
func transformerFor(t *testing.T, spec TransformSpec) *Transformer {
	t.Helper()
	tmpl, err := ResolveTransformTemplate(spec)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("transform-test-seed"))
	key, err := DeriveFPEKey(seed[:], "fam", tmpl.Name)
	if err != nil {
		t.Fatal(err)
	}
	ff1, err := fpe.NewFF1(key, tmpl.Alphabet.Radix())
	if err != nil {
		t.Fatal(err)
	}
	return &Transformer{tmpl: tmpl, ff1: ff1}
}

// TestTransformerRoundTripAndFormat: a deterministic digits template preserves
// length and format, decodes back to the original, and yields identical
// ciphertext for identical input (equality search).
func TestTransformerRoundTripAndFormat(t *testing.T) {
	tr := transformerFor(t, TransformSpec{Name: "pan", Alphabet: "digits", Deterministic: true, PreserveOther: true, MinLength: 12, MaxLength: 19})
	pan := "4111-1111-1111-1111"
	tok, err := tr.Encode(pan, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(tok) != len(pan) {
		t.Fatalf("length not preserved: %q -> %q", pan, tok)
	}
	// Dashes preserved at the same positions.
	for i, r := range pan {
		if r == '-' && rune(tok[i]) != '-' {
			t.Fatalf("separator not preserved at %d: %q", i, tok)
		}
	}
	if tok == pan {
		t.Fatal("ciphertext equals plaintext (no encryption happened)")
	}
	// Convergent: same input -> same token.
	if tok2, _ := tr.Encode(pan, nil); tok2 != tok {
		t.Fatal("deterministic template produced differing ciphertext")
	}
	back, err := tr.Decode(tok, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back != pan {
		t.Fatalf("round-trip mismatch: %q != %q", back, pan)
	}
}

// TestTransformerTweakPolicy: a deterministic template rejects a tweak; a
// request-tweak template requires one and diverges across tweaks.
func TestTransformerTweakPolicy(t *testing.T) {
	det := transformerFor(t, TransformSpec{Name: "det", Alphabet: "digits", Deterministic: true})
	if _, err := det.Encode("123456", []byte("nope")); err == nil {
		t.Fatal("deterministic template accepted a tweak")
	}

	ctx := transformerFor(t, TransformSpec{Name: "ctx", Alphabet: "digits", Deterministic: false, TweakSource: TweakSourceRequest})
	if _, err := ctx.Encode("123456", nil); err == nil {
		t.Fatal("request-tweak template accepted an empty tweak")
	}
	a, err := ctx.Encode("123456", []byte("acct-1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ctx.Encode("123456", []byte("acct-2"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different tweaks produced identical ciphertext")
	}
	// Decode requires the matching tweak.
	if _, err := ctx.Decode(a, []byte("acct-2")); err == nil {
		// wrong tweak decodes to a WRONG value, not an error — assert it differs.
		wrong, _ := ctx.Decode(a, []byte("acct-2"))
		if wrong == "123456" {
			t.Fatal("decoding with the wrong tweak recovered the plaintext")
		}
	}
	right, err := ctx.Decode(a, []byte("acct-1"))
	if err != nil || right != "123456" {
		t.Fatalf("decode with correct tweak: %q err=%v", right, err)
	}
}

// TestTransformerRejectsForeignChars: without PreserveOther, a non-alphabet
// character is rejected; the error names the offending character.
func TestTransformerRejectsForeignChars(t *testing.T) {
	tr := transformerFor(t, TransformSpec{Name: "d", Alphabet: "digits", Deterministic: true})
	if _, err := tr.Encode("12-3456", nil); err == nil || !strings.Contains(err.Error(), "preserve_other") {
		t.Fatalf("expected rejection naming preserve_other, got %v", err)
	}
}

// TestTransformerLengthWindow enforces the min/max symbol window.
func TestTransformerLengthWindow(t *testing.T) {
	tr := transformerFor(t, TransformSpec{Name: "acct", Alphabet: "digits", Deterministic: true, MinLength: 8, MaxLength: 10})
	if _, err := tr.Encode("1234567", nil); err == nil {
		t.Fatal("expected too-short rejection")
	}
	if _, err := tr.Encode("12345678901", nil); err == nil {
		t.Fatal("expected too-long rejection")
	}
	if _, err := tr.Encode("123456789", nil); err != nil {
		t.Fatalf("in-window value rejected: %v", err)
	}
}

// TestFPESeedLifecycleWithRing exercises the full seal→unseal→derive path over a
// real (software-provider) Ring: EnsureFPESeed provisions once and is idempotent,
// NewTransformer round-trips, and — the load-bearing invariant — after a KEK
// rotation + ResealFPESeed the SAME plaintext still tokenizes to the SAME value,
// because the seed bytes (and thus the derived FF1 key) are unchanged while only
// the KEK wrapping advances. This is what keeps issued tokens decodable and
// equality search stable across rotation.
func TestFPESeedLifecycleWithRing(t *testing.T) {
	ctx := context.Background()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if _, err := ProvisionKEK(ctx, prov, "fam-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	store := newFakeKEKStore()
	// Record version 1 in the store so the ring loads it.
	if _, err := RotateKEK(ctx, prov, store, "fam-kek", keyprovider.KeyTypeRSA2048); err != nil {
		// RotateKEK bootstraps the lineage; the first call registers v1 (+ v2).
		t.Fatalf("RotateKEK bootstrap: %v", err)
	}
	ring, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatalf("loadRing: %v", err)
	}

	seedStore := newFakeSeedStore()
	seedRand := func(n int) ([]byte, error) {
		b := make([]byte, n)
		for i := range b {
			b[i] = 0xa5 ^ byte(i)
		}
		return b, nil
	}
	row, err := EnsureFPESeed(ctx, seedStore, ring, "fam-kek", seedRand)
	if err != nil {
		t.Fatalf("EnsureFPESeed: %v", err)
	}
	// Idempotent: a second call returns the same row, not a new seed.
	row2, err := EnsureFPESeed(ctx, seedStore, ring, "fam-kek", seedRand)
	if err != nil || row2.Envelope != row.Envelope {
		t.Fatalf("EnsureFPESeed not idempotent: %v", err)
	}

	tmpl, err := ResolveTransformTemplate(TransformSpec{Name: "pan", Alphabet: "digits", Deterministic: true, MinLength: 12, MaxLength: 19, PreserveOther: true})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransformer(ctx, ring, row, tmpl)
	if err != nil {
		t.Fatalf("NewTransformer: %v", err)
	}
	const pan = "4111-1111-1111-1111"
	tokBefore, err := tr.Encode(pan, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if back, _ := tr.Decode(tokBefore, nil); back != pan {
		t.Fatalf("round-trip mismatch before rotation: %q", back)
	}

	// Rotate the KEK, reload the ring, and re-seal the seed onto the new version.
	if _, err := RotateKEK(ctx, prov, store, "fam-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	ring2, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatalf("reload ring: %v", err)
	}
	resealed, ver, err := ResealFPESeed(ctx, ring2, seedStore, "fam-kek")
	if err != nil {
		t.Fatalf("ResealFPESeed: %v", err)
	}
	if !resealed || ver != ring2.ActiveVersion() {
		t.Fatalf("reseal did not advance to the active version: resealed=%v ver=%d active=%d", resealed, ver, ring2.ActiveVersion())
	}
	if got, _ := seedStore.GetFPESeed("fam-kek"); got.SealedUnderVersion != ring2.ActiveVersion() {
		t.Fatalf("sealed_under_version = %d, want %d", got.SealedUnderVersion, ring2.ActiveVersion())
	}

	// The invariant: after rotation + reseal, the token is UNCHANGED and still decodes.
	row3, _ := seedStore.GetFPESeed("fam-kek")
	tr2, err := NewTransformer(ctx, ring2, row3, tmpl)
	if err != nil {
		t.Fatalf("NewTransformer after reseal: %v", err)
	}
	tokAfter, err := tr2.Encode(pan, nil)
	if err != nil {
		t.Fatalf("Encode after reseal: %v", err)
	}
	if tokAfter != tokBefore {
		t.Fatalf("token changed across KEK rotation: %q -> %q (derived key must be stable)", tokBefore, tokAfter)
	}
	if back, _ := tr2.Decode(tokBefore, nil); back != pan {
		t.Fatalf("pre-rotation token no longer decodes after reseal: %q", back)
	}
}

// fakeSeedStore is an in-memory FPESeedStore for the ring-lifecycle test.
type fakeSeedStore struct {
	rows map[string]*models.FPESeed
}

func newFakeSeedStore() *fakeSeedStore { return &fakeSeedStore{rows: map[string]*models.FPESeed{}} }

func (f *fakeSeedStore) GetFPESeed(family string) (*models.FPESeed, error) {
	if r, ok := f.rows[family]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, nil
}
func (f *fakeSeedStore) InsertFPESeed(s *models.FPESeed) error {
	if _, ok := f.rows[s.Family]; ok {
		return &dupErr{}
	}
	cp := *s
	f.rows[s.Family] = &cp
	return nil
}
func (f *fakeSeedStore) UpdateFPESeedEnvelope(family, envelope string, sealedUnderVersion int) (bool, error) {
	r, ok := f.rows[family]
	if !ok {
		return false, nil
	}
	r.Envelope = envelope
	r.SealedUnderVersion = sealedUnderVersion
	return true, nil
}

type dupErr struct{}

func (*dupErr) Error() string { return "duplicate family" }
