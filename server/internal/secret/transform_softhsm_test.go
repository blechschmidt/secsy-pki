package secret

// SoftHSM acceptance test for Task 144: format-preserving-encryption key
// derivation with the KEK on a real PKCS#11 token. The FF1 key is HKDF-derived
// from a seed sealed under the HSM KEK, so this walks the full HSM path —
//
//	provision KEK → EnsureFPESeed (seal the seed on the token)
//	→ NewTransformer (unwrap the seed on the token, derive the FF1 key)
//	→ encode/decode round-trips, deterministic, per-template isolated
//	→ rotate the KEK → ResealFPESeed → the SAME token still results and decodes
//	  (the derived key is stable; only the KEK wrapping advanced)
//
// Mirrors the other *_softhsm_test.go files: skipped unless setup-softhsm.sh's
// environment is present.

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

func TestHSMTransformKeyDerivation(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)
	family := uniqueKEKLabel(t)

	if _, err := ProvisionKEK(ctx, p, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK on HSM: %v", err)
	}
	store := newFakeKEKStore()
	ring, err := loadRingFromStore(ctx, p, store, family)
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}

	seedStore := newFakeSeedStore()
	// A fixed seed keeps the run reproducible; the seed is sealed on the token
	// either way, which is the HSM path under test.
	seedRand := func(n int) ([]byte, error) {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i * 7)
		}
		return b, nil
	}
	row, err := EnsureFPESeed(ctx, seedStore, ring, family, seedRand)
	if err != nil {
		t.Fatalf("EnsureFPESeed: %v", err)
	}

	panTmpl, err := ResolveTransformTemplate(TransformSpec{Name: "pan", Alphabet: "digits", Deterministic: true, MinLength: 12, MaxLength: 19, PreserveOther: true})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransformer(ctx, ring, row, panTmpl)
	if err != nil {
		t.Fatalf("NewTransformer (HSM seed unwrap + derive): %v", err)
	}
	const pan = "4111 1111 1111 1111"
	tok, err := tr.Encode(pan, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if tok == pan {
		t.Fatal("ciphertext equals plaintext")
	}
	if len(tok) != len(pan) {
		t.Fatalf("length not preserved: %q -> %q", pan, tok)
	}
	if back, derr := tr.Decode(tok, nil); derr != nil || back != pan {
		t.Fatalf("round-trip failed: %q err=%v", back, derr)
	}

	// Per-template key isolation on the HSM path: a different template over the
	// same seed yields an independent token for the same input.
	acctTmpl, _ := ResolveTransformTemplate(TransformSpec{Name: "acct", Alphabet: "digits", Deterministic: true, MinLength: 12, MaxLength: 19, PreserveOther: true})
	trAcct, err := NewTransformer(ctx, ring, row, acctTmpl)
	if err != nil {
		t.Fatalf("NewTransformer(acct): %v", err)
	}
	tokAcct, _ := trAcct.Encode(pan, nil)
	if tokAcct == tok {
		t.Fatal("distinct templates produced identical tokens (key not per-template)")
	}

	// Rotate the KEK on the token, re-seal the seed, and confirm the derived key —
	// and therefore the token — is unchanged (issued tokens stay decodable).
	if _, err := RotateKEK(ctx, p, store, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("RotateKEK on HSM: %v", err)
	}
	ring2, err := loadRingFromStore(ctx, p, store, family)
	if err != nil {
		t.Fatalf("reload ring: %v", err)
	}
	if resealed, _, rerr := ResealFPESeed(ctx, ring2, seedStore, family); rerr != nil || !resealed {
		t.Fatalf("ResealFPESeed: resealed=%v err=%v", resealed, rerr)
	}
	row2, _ := seedStore.GetFPESeed(family)
	tr2, err := NewTransformer(ctx, ring2, row2, panTmpl)
	if err != nil {
		t.Fatalf("NewTransformer after reseal: %v", err)
	}
	tokAfter, err := tr2.Encode(pan, nil)
	if err != nil {
		t.Fatalf("Encode after reseal: %v", err)
	}
	if tokAfter != tok {
		t.Fatalf("token changed across HSM KEK rotation: %q -> %q", tok, tokAfter)
	}
	if back, derr := tr2.Decode(tok, nil); derr != nil || back != pan {
		t.Fatalf("pre-rotation token no longer decodes: %q err=%v", back, derr)
	}
}
