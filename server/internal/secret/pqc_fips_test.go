package secret

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestPQCHybridFIPSApproved documents the FIPS interaction: ML-KEM-1024 is a
// FIPS 203 algorithm inside the Go Cryptographic Module (unlike the CIRCL-based
// ML-DSA of Task 29, which the policy rejects), so the post-quantum hybrid mode
// is FIPS-approvable. With the policy enforced AND a SHA-256-capable classical
// KEK (software RSA), a full hybrid round-trip succeeds — the policy blocks the
// SHA-1 OAEP fallback, not the feature.
func TestPQCHybridFIPSApproved(t *testing.T) {
	if err := PQCHybridApproved(); err != nil {
		t.Fatalf("ML-KEM-1024 hybrid should be FIPS-approved, got: %v", err)
	}

	prev := fips.PolicyEnforced()
	fips.SetPolicy(true)
	t.Cleanup(func() { fips.SetPolicy(prev) })

	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	ctx := context.Background()
	const family = "fips-pqc-kek"

	// A software RSA-2048 KEK negotiates SHA-256 OAEP (allowed under the policy).
	svc, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK under FIPS policy: %v", err)
	}
	if got := svc.KEKInfo().WrapAlg; got != AlgRSAOAEPSHA256 {
		t.Fatalf("KEK negotiated %q under FIPS, want SHA-256 OAEP", got)
	}
	rec, err := GeneratePQCHybridKEK(svc, family)
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK under FIPS policy: %v", err)
	}
	if rec.SealAlg != AlgRSAOAEPSHA256 {
		t.Fatalf("ML-KEM decap key sealed with %q under FIPS, want SHA-256 OAEP", rec.SealAlg)
	}

	ring, err := LoadRingWithPQC(ctx, prov, family, nil, rec, true)
	if err != nil {
		t.Fatalf("LoadRingWithPQC under FIPS policy: %v", err)
	}
	pt := []byte("fips-hybrid-secret")
	blob, err := ring.EncryptToJSON(pt, nil)
	if err != nil {
		t.Fatalf("hybrid EncryptToJSON under FIPS policy: %v", err)
	}
	got, err := ring.DecryptJSON(ctx, blob, nil)
	if err != nil {
		t.Fatalf("hybrid DecryptJSON under FIPS policy: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch under FIPS: got %q want %q", got, pt)
	}
}

// TestPQCHybridFIPSRefusesSHA1Classical confirms the hybrid mode inherits the
// classical layer's FIPS behavior: on a token that can only RSA-OAEP with SHA-1
// (SoftHSM), provisioning the hybrid material fails closed under the policy —
// the ML-KEM seal cannot fall back to SHA-1.
func TestPQCHybridFIPSRefusesSHA1Classical(t *testing.T) {
	prev := fips.PolicyEnforced()
	fips.SetPolicy(false)
	t.Cleanup(func() { fips.SetPolicy(prev) })

	provider, ref := newSHA1OnlyKEK(t)
	ctx := context.Background()

	// Without the policy the classical KEK negotiates SHA-1 and hybrid works.
	svc, err := NewService(ctx, provider, ref)
	if err != nil {
		t.Fatalf("NewService without policy: %v", err)
	}
	if _, err := GeneratePQCHybridKEK(svc, ref.Label); err != nil {
		t.Fatalf("GeneratePQCHybridKEK without policy (SHA-1 OAEP): %v", err)
	}

	// With the policy, constructing the classical Service on that token already
	// fails closed (the SHA-1 fallback is refused), so hybrid can never be built.
	fips.SetPolicy(true)
	if _, err := NewService(ctx, provider, ref); err == nil {
		t.Fatal("NewService under security.fips should refuse the SHA-1-only classical KEK")
	} else if !strings.Contains(err.Error(), "SHA-1") {
		t.Errorf("error should explain the refused SHA-1 fallback, got: %v", err)
	}
}
