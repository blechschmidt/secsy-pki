package keyprovider

import (
	"context"
	"errors"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// TestGenerateKeyFIPSGate verifies that key generation is the fail-closed
// chokepoint for the FIPS policy: non-approved key types (Ed25519, ML-DSA via
// the software CIRCL path) are refused so the key never exists, while approved
// types keep working. The software backend stands in for all backends — the
// gate runs before any backend-specific work.
func TestGenerateKeyFIPSGate(t *testing.T) {
	prev := fips.PolicyEnforced()
	fips.SetPolicy(true)
	t.Cleanup(func() { fips.SetPolicy(prev) })

	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	ctx := context.Background()

	for _, keyType := range []string{KeyTypeEd25519, KeyTypeMLDSA65, "ml-dsa-87"} {
		_, err := p.GenerateKey(ctx, KeySpec{Label: "fips-reject-" + keyType, KeyType: keyType})
		if !errors.Is(err, fips.ErrNotApproved) {
			t.Errorf("GenerateKey(%s): want ErrNotApproved, got %v", keyType, err)
		}
	}

	for _, keyType := range []string{KeyTypeECDSAP256, KeyTypeRSA2048} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: "fips-ok-" + keyType, KeyType: keyType}); err != nil {
			t.Errorf("GenerateKey(%s) under policy: %v", keyType, err)
		}
	}

	// With the policy off, the same non-approved generation succeeds (the gate,
	// not the backend, was rejecting).
	fips.SetPolicy(false)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "nofips-ed25519", KeyType: KeyTypeEd25519}); err != nil {
		t.Errorf("GenerateKey(ed25519) without policy: %v", err)
	}
}
