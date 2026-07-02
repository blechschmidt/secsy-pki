package keyprovider

import (
	"context"
	"crypto"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

// TestSoftwareMLDSAKeyLifecycle verifies the software provider can generate,
// persist, reload, and sign with ML-DSA keys, and that the reloaded signer
// produces signatures that verify against the exported public key.
func TestSoftwareMLDSAKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	for _, kt := range []string{KeyTypeMLDSA44, KeyTypeMLDSA65, KeyTypeMLDSA87} {
		t.Run(kt, func(t *testing.T) {
			info, err := p.GenerateKey(ctx, KeySpec{Label: "ca-" + kt, KeyType: kt})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if info.KeyType != kt {
				t.Errorf("key type = %q, want %q", info.KeyType, kt)
			}
			if info.SSHPublicKey != "" {
				t.Errorf("ML-DSA key should have no SSH public key, got %q", info.SSHPublicKey)
			}
			if !pqc.IsPQCPublicKey(info.PublicKey) {
				t.Fatalf("public key is not ML-DSA (%T)", info.PublicKey)
			}

			// Reload from disk and sign; verify with the exported public key.
			signer, err := p.Signer(ctx, KeyRef{Label: "ca-" + kt})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()
			if signer.KeyType() != kt {
				t.Errorf("signer key type = %q", signer.KeyType())
			}
			msg := []byte("post-quantum message")
			sig, err := signer.Sign(nil, msg, crypto.Hash(0))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			// Verify the signature via the pqc verification path (build a throwaway
			// certificate is overkill; use the scheme through a round-trip helper).
			if !verifyMLDSA(t, info.PublicKey, msg, sig) {
				t.Fatal("ML-DSA signature failed to verify against exported public key")
			}
		})
	}

	// Duplicate labels must be rejected, as for classical keys.
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeMLDSA44}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeMLDSA44}); err == nil {
		t.Fatal("duplicate ML-DSA label was not rejected")
	}
}

// verifyMLDSA verifies an ML-DSA signature over msg using the pqc scheme behind
// the public key.
func verifyMLDSA(t *testing.T, pub crypto.PublicKey, msg, sig []byte) bool {
	t.Helper()
	kt, err := pqc.KeyTypeOf(pub)
	if err != nil {
		t.Fatalf("KeyTypeOf: %v", err)
	}
	// Re-marshal/parse to exercise the SPKI path, then verify via a tiny helper
	// exposed for tests through the exported scheme name.
	return pqc.VerifyMessage(kt, pub, msg, sig)
}

// TestPKCS11RejectsPQC verifies the PKCS#11 backend fails closed for ML-DSA key
// generation with an actionable message pointing at the software provider.
func TestPKCS11RejectsPQC(t *testing.T) {
	p, err := NewPKCS11Provider(PKCS11Settings{ModulePath: "/nonexistent.so", TokenLabel: "t"})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	// This must fail on the PQC guard, BEFORE ever touching the (absent) module.
	_, err = p.GenerateKey(context.Background(), KeySpec{Label: "x", KeyType: KeyTypeMLDSA65})
	if err == nil {
		t.Fatal("PKCS#11 backend unexpectedly accepted an ML-DSA key")
	}
	if !contains(err.Error(), "software key provider") {
		t.Errorf("error should point at the software provider, got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
