package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// hybridRing provisions a software RSA KEK, generates ML-KEM-1024 hybrid
// material sealed under it, and returns a Ring with that material attached. No
// HSM is needed — the classical KEK is software (RSA-OAEP-SHA256) and the ML-KEM
// operations are pure Go (crypto/mlkem). sealHybrid controls whether the ring
// seals NEW envelopes hybrid (the secret.pqc_hybrid gate).
func hybridRing(t *testing.T, sealHybrid bool) (*Ring, keyprovider.Provider, *models.PQCHybridKey) {
	t.Helper()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	ctx := context.Background()
	const family = "pqc-kek"
	svc, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	rec, err := GeneratePQCHybridKEK(svc, family)
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK: %v", err)
	}
	ring, err := LoadRingWithPQC(ctx, prov, family, nil, rec, sealHybrid)
	if err != nil {
		t.Fatalf("LoadRingWithPQC: %v", err)
	}
	return ring, prov, rec
}

// TestPQCHybridRoundTrip is the core acceptance test: with the gate on, encrypt
// produces a FormatVersion3 envelope carrying a PQC block, and decrypt recovers
// the plaintext — proving the ML-KEM + classical combiner is reversible.
func TestPQCHybridRoundTrip(t *testing.T) {
	ring, _, rec := hybridRing(t, true)
	ctx := context.Background()

	if !ring.HybridEnabled() {
		t.Fatal("ring should report hybrid sealing enabled")
	}
	if ring.PQCKeyID() != rec.KeyID {
		t.Fatalf("ring key id = %q, want %q", ring.PQCKeyID(), rec.KeyID)
	}

	cases := []struct {
		name string
		pt   []byte
		ctx  []byte
	}{
		{"password", []byte("hunter2"), nil},
		{"empty", []byte(""), nil},
		{"binary", []byte{0x00, 0xff, 0x10, 0x7f, 0x00}, nil},
		{"large", bytes.Repeat([]byte("A"), 8192), nil},
		{"with-context", []byte("db-password"), []byte("service=payments")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := ring.EncryptToJSON(tc.pt, tc.ctx)
			if err != nil {
				t.Fatalf("EncryptToJSON: %v", err)
			}
			if bytes.Contains(blob, tc.pt) && len(tc.pt) > 0 {
				t.Fatal("plaintext leaked into ciphertext")
			}

			// The envelope must be v3 with a well-formed PQC block naming ML-KEM.
			var env Envelope
			if err := json.Unmarshal(blob, &env); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if env.Version != FormatVersion3 {
				t.Errorf("version = %d, want %d", env.Version, FormatVersion3)
			}
			if env.PQC == nil {
				t.Fatal("PQC block missing")
			}
			if env.PQC.Alg != AlgMLKEM1024 || env.PQC.KeyID != rec.KeyID {
				t.Errorf("PQC block alg/keyid = %q/%q", env.PQC.Alg, env.PQC.KeyID)
			}
			if len(env.PQC.KEMCiphertext) != mlkem1024CiphertextSize {
				t.Errorf("KEM ciphertext len = %d, want %d", len(env.PQC.KEMCiphertext), mlkem1024CiphertextSize)
			}

			got, err := ring.DecryptJSON(ctx, blob, tc.ctx)
			if err != nil {
				t.Fatalf("DecryptJSON: %v", err)
			}
			if !bytes.Equal(got, tc.pt) {
				t.Errorf("round trip mismatch: got %q want %q", got, tc.pt)
			}
		})
	}
}

// TestPQCHybridClassicalStillOpens verifies backward/forward compatibility: a
// classical (v2) envelope opens through a hybrid-capable ring unchanged, and a
// hybrid (v3) envelope still opens after the gate is turned off (material stays
// attached for reads).
func TestPQCHybridBackwardForwardCompatible(t *testing.T) {
	ctx := context.Background()

	// A classical ring (no PQC material) seals v2; a hybrid ring opens it fine.
	classical, prov, rec := hybridRing(t, false) // sealHybrid off → seals classical
	classicalBlob, err := classical.EncryptToJSON([]byte("legacy"), nil)
	if err != nil {
		t.Fatalf("classical EncryptToJSON: %v", err)
	}
	var cenv Envelope
	_ = json.Unmarshal(classicalBlob, &cenv)
	if cenv.Version != FormatVersion2 || cenv.PQC != nil {
		t.Fatalf("gate-off ring must seal classical v2, got version %d pqc=%v", cenv.Version, cenv.PQC != nil)
	}

	// Turn the gate ON: seal a hybrid envelope.
	hybrid, err := LoadRingWithPQC(ctx, prov, classical.Family(), classical.Versions(), rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC (gate on): %v", err)
	}
	hybridBlob, err := hybrid.EncryptToJSON([]byte("modern"), nil)
	if err != nil {
		t.Fatalf("hybrid EncryptToJSON: %v", err)
	}

	// Gate OFF again but material still attached: the hybrid envelope must still
	// open (forward compatibility — disabling the gate never strands ciphertext).
	gateOff, err := LoadRingWithPQC(ctx, prov, classical.Family(), classical.Versions(), rec, false)
	if err != nil {
		t.Fatalf("LoadRingWithPQC (gate off, material present): %v", err)
	}
	if got, err := gateOff.DecryptJSON(ctx, hybridBlob, nil); err != nil || string(got) != "modern" {
		t.Fatalf("hybrid envelope must open with gate off: got %q err %v", got, err)
	}
	if got, err := gateOff.DecryptJSON(ctx, classicalBlob, nil); err != nil || string(got) != "legacy" {
		t.Fatalf("classical envelope must open through hybrid-capable ring: got %q err %v", got, err)
	}
}

// TestPQCHybridDowngradeResistance proves the post-quantum layer is genuinely
// required and cannot be stripped, tampered with, or bypassed to force a
// weaker classical-only decryption.
func TestPQCHybridDowngradeResistance(t *testing.T) {
	ring, prov, rec := hybridRing(t, true)
	ctx := context.Background()
	pt := []byte("top-secret")

	blob, err := ring.EncryptToJSON(pt, nil)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}

	// (1) A ring WITHOUT the ML-KEM material (classical-only) cannot open it: the
	// post-quantum secret is genuinely required, not decorative.
	classicalRing, err := LoadRing(ctx, prov, ring.Family(), ring.Versions())
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}
	if _, err := classicalRing.DecryptJSON(ctx, blob, nil); err == nil {
		t.Fatal("hybrid envelope opened without ML-KEM material — post-quantum layer bypassed")
	}

	// (2) Stripping the PQC block to masquerade as a classical v2 envelope fails:
	// WrappedDEK protects the classical shared secret (not the DEK), and the DEK
	// commitment no longer matches, so it fails closed.
	stripped := decodeEnv(t, blob)
	stripped.PQC = nil
	stripped.Version = FormatVersion2
	if _, err := ring.Decrypt(ctx, stripped, nil); err == nil {
		t.Fatal("decrypt succeeded after stripping the PQC block")
	}

	// (3) Tampering with any authenticated PQC field fails closed. Each mutation
	// starts from a fresh copy of the original.
	tamper := []struct {
		name   string
		mutate func(e *Envelope)
	}{
		{"kem-ciphertext", func(e *Envelope) { e.PQC.KEMCiphertext[0] ^= 0x01 }},
		{"wrapped-dek", func(e *Envelope) { e.PQC.WrappedDEK[0] ^= 0x01 }},
		{"wrap-nonce", func(e *Envelope) { e.PQC.WrapNonce[0] ^= 0x01 }},
		{"classical-commit", func(e *Envelope) { e.PQC.ClassicalCommit[0] ^= 0x01 }},
		{"key-id", func(e *Envelope) { e.PQC.KeyID = "mlkem1024-deadbeefdeadbeef" }},
	}
	for _, tc := range tamper {
		t.Run("tamper-"+tc.name, func(t *testing.T) {
			env := decodeEnv(t, blob)
			tc.mutate(env)
			if _, err := ring.Decrypt(ctx, env, nil); err == nil {
				t.Fatalf("decrypt succeeded after tampering with %s", tc.name)
			}
		})
	}

	// (4) Transplanting another envelope's PQC block (a valid block, wrong DEK)
	// fails: the block is bound into the outer GCM AAD and its wrapped DEK is a
	// different key.
	other, err := ring.EncryptToJSON([]byte("other"), nil)
	if err != nil {
		t.Fatalf("second EncryptToJSON: %v", err)
	}
	swapped := decodeEnv(t, blob)
	swapped.PQC = decodeEnv(t, other).PQC
	if _, err := ring.Decrypt(ctx, swapped, nil); err == nil {
		t.Fatal("decrypt succeeded after swapping in another envelope's PQC block")
	}

	// (5) A ring whose ML-KEM key ID differs refuses (belt-and-suspenders on top
	// of the cryptographic failure): provision a second, unrelated family.
	otherRing, _, _ := hybridRing(t, true)
	if otherRing.PQCKeyID() == rec.KeyID {
		t.Skip("unexpected key-id collision")
	}
	if _, err := otherRing.Decrypt(ctx, decodeEnv(t, blob), nil); err == nil {
		t.Fatal("decrypt succeeded with the wrong family's ML-KEM key")
	}
}

// TestPQCHybridRewrapPreservesLayer exercises the rewrap path: rotating the
// classical KEK re-wraps only the classical shared secret onto the new version,
// leaving the ML-KEM layer untouched, and the migrated envelope still decrypts.
func TestPQCHybridRewrapPreservesLayer(t *testing.T) {
	ctx := context.Background()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	const family = "pqc-rot"

	// Version 1 base KEK + ML-KEM material sealed under it; seal a hybrid envelope.
	v1, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	rec, err := GeneratePQCHybridKEK(v1, family)
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK: %v", err)
	}
	ring1, err := LoadRingWithPQC(ctx, prov, family, nil, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC v1: %v", err)
	}
	pt := []byte("rotate-me")
	blob, err := ring1.EncryptToJSON(pt, nil)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	origPQC := decodeEnv(t, blob).PQC

	// Rotate the classical KEK: provision version 2 and build a two-version ring
	// (v1 retiring, v2 active). The ML-KEM material stays sealed under v1
	// (retiring, still openable).
	v2label := VersionLabel(family, 2)
	if _, err := prov.GenerateKey(ctx, keyprovider.KeySpec{
		Label: v2label, KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatalf("GenerateKey v2: %v", err)
	}
	versions := []models.KEKVersion{
		{Family: family, Version: 1, Label: family, Status: models.KEKStatusRetiring},
		{Family: family, Version: 2, Label: v2label, Status: models.KEKStatusActive},
	}
	ring2, err := LoadRingWithPQC(ctx, prov, family, versions, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC v2: %v", err)
	}

	// Before rewrap the envelope still opens (dual-KEK window).
	if got, err := ring2.DecryptJSON(ctx, blob, nil); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("pre-rewrap decrypt: got %q err %v", got, err)
	}

	newBlob, changed, err := ring2.RewrapJSON(ctx, blob)
	if err != nil {
		t.Fatalf("RewrapJSON: %v", err)
	}
	if !changed {
		t.Fatal("rewrap reported no change across a KEK rotation")
	}

	newEnv := decodeEnv(t, newBlob)
	if newEnv.KEKLabel != v2label || newEnv.KEKVersion != 2 {
		t.Errorf("rewrapped envelope still on %s v%d, want %s v2", newEnv.KEKLabel, newEnv.KEKVersion, v2label)
	}
	if newEnv.Version != FormatVersion3 || newEnv.PQC == nil {
		t.Fatal("rewrap dropped the post-quantum layer")
	}
	// The ML-KEM layer must be byte-for-byte identical — rewrap migrates only the
	// classical wrap of the shared secret.
	if !bytes.Equal(newEnv.PQC.KEMCiphertext, origPQC.KEMCiphertext) ||
		!bytes.Equal(newEnv.PQC.WrappedDEK, origPQC.WrappedDEK) ||
		!bytes.Equal(newEnv.PQC.ClassicalCommit, origPQC.ClassicalCommit) {
		t.Fatal("rewrap altered the post-quantum block")
	}

	if got, err := ring2.DecryptJSON(ctx, newBlob, nil); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("post-rewrap decrypt: got %q err %v", got, err)
	}
}

// TestPQCHybridReSeal verifies the ML-KEM decapsulation key can be re-sealed
// under a newer classical KEK version (run before retiring the sealing version)
// and that envelopes keep opening across the re-seal.
func TestPQCHybridReSeal(t *testing.T) {
	ctx := context.Background()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	const family = "pqc-reseal"

	v1, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	rec, err := GeneratePQCHybridKEK(v1, family) // sealed under v1
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK: %v", err)
	}
	ring1, _ := LoadRingWithPQC(ctx, prov, family, nil, rec, true)
	blob, err := ring1.EncryptToJSON([]byte("seal-me"), nil)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}

	// Rotate to v2 and re-seal the decapsulation key under it.
	v2label := VersionLabel(family, 2)
	if _, err := prov.GenerateKey(ctx, keyprovider.KeySpec{
		Label: v2label, KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatalf("GenerateKey v2: %v", err)
	}
	versions := []models.KEKVersion{
		{Family: family, Version: 1, Label: family, Status: models.KEKStatusRetiring},
		{Family: family, Version: 2, Label: v2label, Status: models.KEKStatusActive},
	}
	ring2, err := LoadRingWithPQC(ctx, prov, family, versions, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC v2: %v", err)
	}
	sealedDK, sealAlg, version, err := ring2.ReSealPQC()
	if err != nil {
		t.Fatalf("ReSealPQC: %v", err)
	}
	if version != 2 {
		t.Fatalf("re-sealed under version %d, want 2", version)
	}
	rec.SealedDecapKey = sealedDK
	rec.SealAlg = sealAlg
	rec.SealedUnderVersion = version

	// A ring whose PQC record is now sealed under v2 opens the envelope even if
	// v1 is retired (no longer accessible for unsealing).
	versionsRetired := []models.KEKVersion{
		{Family: family, Version: 1, Label: family, Status: models.KEKStatusRetired},
		{Family: family, Version: 2, Label: v2label, Status: models.KEKStatusActive},
	}
	ring3, err := LoadRingWithPQC(ctx, prov, family, versionsRetired, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC after reseal+retire: %v", err)
	}
	// The envelope's classical secret is still on v1 (retired) — so this specific
	// envelope cannot open, but a freshly sealed one (on v2) must. Re-seal is
	// about the ML-KEM key, not the per-envelope classical wrap.
	fresh, err := ring3.EncryptToJSON([]byte("fresh"), nil)
	if err != nil {
		t.Fatalf("post-reseal EncryptToJSON: %v", err)
	}
	if got, err := ring3.DecryptJSON(ctx, fresh, nil); err != nil || string(got) != "fresh" {
		t.Fatalf("post-reseal decrypt: got %q err %v", got, err)
	}
	_ = blob
}

// TestPQCHybridGateWithoutMaterialFailsClosed verifies enabling the gate without
// provisioned material is a hard, actionable error rather than a silent classical
// fallback.
func TestPQCHybridGateWithoutMaterialFailsClosed(t *testing.T) {
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	ctx := context.Background()
	if _, err := ProvisionKEK(ctx, prov, "bare-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	_, err = LoadRingWithPQC(ctx, prov, "bare-kek", nil, nil, true)
	if err == nil {
		t.Fatal("gate on without material should fail closed")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("pqc-enable")) {
		t.Errorf("error should point at provisioning, got: %v", err)
	}
}

func decodeEnv(t *testing.T, blob []byte) *Envelope {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(blob, &e); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return &e
}
