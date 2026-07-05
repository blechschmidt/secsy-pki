package secret

import (
	"bytes"
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestPQCHybridSoftHSM proves the post-quantum hybrid mode with the classical
// KEK on a real HSM (SoftHSM): the RSA KEK's private half never leaves the
// token, the ML-KEM decapsulation key is sealed under it (so unsealing — and
// therefore decapsulation — requires an on-token C_Decrypt), and ML-KEM itself
// runs in software (SoftHSM has no ML-KEM mechanism). A hybrid envelope
// round-trips, and the classical layer alone cannot open it.
//
// Skipped unless SoftHSM is configured (SECSY_PKCS11_MODULE/SECSY_TOKEN_LABEL),
// matching the other HSM tests.
func TestPQCHybridSoftHSM(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)
	family := uniqueKEKLabel(t)

	// Classical KEK lives on the token (private key non-extractable). SoftHSM
	// only does SHA-1 RSA-OAEP, so the ML-KEM seal negotiates SHA-1 — exercising
	// the fallback path end to end.
	svc, err := ProvisionKEK(ctx, p, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK on SoftHSM: %v", err)
	}
	// Unique per-run label (uniqueKEKLabel) avoids collisions on the persistent
	// token, matching the other HSM tests; no key deletion is needed.

	rec, err := GeneratePQCHybridKEK(svc, family)
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK (decap key sealed on token): %v", err)
	}
	if rec.SealAlg != AlgRSAOAEPSHA1 && rec.SealAlg != AlgRSAOAEPSHA256 {
		t.Fatalf("unexpected seal algorithm %q", rec.SealAlg)
	}
	// The sealed decapsulation key must be genuinely wrapped — never the raw
	// 64-byte seed in the clear.
	if len(rec.SealedDecapKey) < 128 {
		t.Fatalf("sealed decapsulation key looks unwrapped (%d bytes)", len(rec.SealedDecapKey))
	}

	ring, err := LoadRingWithPQC(ctx, p, family, nil, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC: %v", err)
	}

	// Round-trip: sealing encapsulates in software; opening unseals the ML-KEM
	// decapsulation key on the token (C_Decrypt) then decapsulates in software.
	pt := []byte("hsm-anchored-pqc-secret")
	blob, err := ring.EncryptToJSON(pt, nil)
	if err != nil {
		t.Fatalf("hybrid EncryptToJSON: %v", err)
	}
	env := decodeEnv(t, blob)
	if env.Version != FormatVersion3 || env.PQC == nil || env.PQC.Alg != AlgMLKEM1024 {
		t.Fatalf("expected a v3 ML-KEM hybrid envelope, got version %d", env.Version)
	}
	got, err := ring.DecryptJSON(ctx, blob, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("hybrid round-trip on SoftHSM: got %q err %v", got, err)
	}

	// The classical KEK alone (no ML-KEM material) cannot open it — the token is
	// necessary but not sufficient; the post-quantum layer is required too.
	classical, err := LoadRing(ctx, p, family, []models.KEKVersion(nil))
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}
	if _, err := classical.DecryptJSON(ctx, blob, nil); err == nil {
		t.Fatal("hybrid envelope opened with the classical KEK alone — post-quantum layer bypassed")
	}
}
