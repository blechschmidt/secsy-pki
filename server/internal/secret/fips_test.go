package secret

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// sha1OnlyProvider wraps a real provider but fails RSA-OAEP decryption for any
// hash other than SHA-1, mimicking SoftHSM 2.6.x's CKR_ARGUMENTS_BAD on
// SHA-256 OAEP (the softhsm-oaep-sha1-only behavior the negotiation exists for).
type sha1OnlyProvider struct {
	keyprovider.Provider
}

func (p *sha1OnlyProvider) Decrypter(ctx context.Context, ref keyprovider.KeyRef) (keyprovider.Decrypter, error) {
	dp, ok := p.Provider.(keyprovider.DecrypterProvider)
	if !ok {
		return nil, fmt.Errorf("wrapped provider cannot decrypt")
	}
	inner, err := dp.Decrypter(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &sha1OnlyDecrypter{inner}, nil
}

type sha1OnlyDecrypter struct {
	keyprovider.Decrypter
}

func (d *sha1OnlyDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if o, ok := opts.(*rsa.OAEPOptions); ok && o.Hash != crypto.SHA1 {
		return nil, fmt.Errorf("simulated token: CKR_ARGUMENTS_BAD (only SHA-1 OAEP supported)")
	}
	return d.Decrypter.Decrypt(rand, ciphertext, opts)
}

// newSHA1OnlyKEK provisions an RSA KEK on a software keystore and returns the
// SHA-1-only wrapped provider plus the KEK ref.
func newSHA1OnlyKEK(t *testing.T) (keyprovider.Provider, keyprovider.KeyRef) {
	t.Helper()
	raw, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ref := keyprovider.KeyRef{Label: "fips-kek"}
	if _, err := raw.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label:   ref.Label,
		KeyType: keyprovider.KeyTypeRSA2048,
		Usage:   keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatal(err)
	}
	return &sha1OnlyProvider{raw}, ref
}

// TestFIPSRefusesSHA1OAEPFallback covers Task 65's secret-layer requirement:
// on a token that supports only SHA-1 OAEP (SoftHSM), the negotiation falls
// back to SHA-1 normally, but with security.fips enforced the Service
// constructor fails closed with an actionable error instead of downgrading —
// and a Service that already negotiated SHA-1 refuses to open SHA-1 envelopes
// once the policy is on.
func TestFIPSRefusesSHA1OAEPFallback(t *testing.T) {
	prev := fips.PolicyEnforced()
	fips.SetPolicy(false)
	t.Cleanup(func() { fips.SetPolicy(prev) })

	provider, ref := newSHA1OnlyKEK(t)
	ctx := context.Background()

	// Without the policy: negotiation degrades to SHA-1 (the SoftHSM memory).
	svc, err := NewService(ctx, provider, ref)
	if err != nil {
		t.Fatalf("NewService without policy: %v", err)
	}
	if got := svc.KEKInfo().WrapAlg; got != AlgRSAOAEPSHA1 {
		t.Fatalf("negotiated wrap alg = %q, want %q", got, AlgRSAOAEPSHA1)
	}
	env, err := svc.Encrypt([]byte("legacy secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// With the policy: constructing a Service on the same token fails closed.
	fips.SetPolicy(true)
	_, err = NewService(ctx, provider, ref)
	if err == nil {
		t.Fatal("NewService under security.fips should refuse the SHA-1 OAEP fallback")
	}
	if !strings.Contains(err.Error(), "security.fips") || !strings.Contains(err.Error(), "SHA-1") {
		t.Errorf("error should explain the refused SHA-1 fallback, got: %v", err)
	}

	// And the pre-policy Service refuses to open its SHA-1 envelope.
	_, err = svc.Decrypt(env, nil)
	if !errors.Is(err, fips.ErrNotApproved) {
		t.Errorf("Decrypt of SHA-1 envelope under policy: want ErrNotApproved, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "re-wrap") {
		t.Errorf("rejection should point the operator at re-wrapping, got: %v", err)
	}

	// A SHA-256-capable provider works under the policy end to end (positive
	// control: the policy blocks the fallback, not the feature).
	raw, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ref2 := keyprovider.KeyRef{Label: "fips-kek-256"}
	if _, err := raw.GenerateKey(ctx, keyprovider.KeySpec{
		Label: ref2.Label, KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatal(err)
	}
	svc256, err := NewService(ctx, raw, ref2)
	if err != nil {
		t.Fatalf("NewService (SHA-256 provider) under policy: %v", err)
	}
	if got := svc256.KEKInfo().WrapAlg; got != AlgRSAOAEPSHA256 {
		t.Fatalf("wrap alg = %q, want %q", got, AlgRSAOAEPSHA256)
	}
	env2, err := svc256.Encrypt([]byte("modern secret"), []byte("ctx"))
	if err != nil {
		t.Fatalf("Encrypt under policy: %v", err)
	}
	pt, err := svc256.Decrypt(env2, []byte("ctx"))
	if err != nil || string(pt) != "modern secret" {
		t.Fatalf("Decrypt under policy: %v (pt=%q)", err, pt)
	}
}
