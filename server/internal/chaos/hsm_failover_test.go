//go:build sqlite

package chaos

// Scenario 1 — mid-load HSM token failure and session-pool saturation
// (Tasks 44 & 20). Requires SoftHSM.
//
//   - TestChaosHSMFailoverUnderLoad imports one EC CA key into two SoftHSM
//     tokens as a genuine replica, drives a concurrent signing load through the
//     HA provider, pulls the primary token out mid-load, and asserts every
//     signature — before, during, and after the fault — verifies against the one
//     CA public key (no silent wrong signature), that health/failover metrics
//     record the event, and that the background prober returns the token to
//     rotation once the fault clears.
//
//   - TestChaosSessionPoolSaturationAndRecovery drives far more concurrent
//     signers than the bounded session pool has slots and asserts every
//     signature is still valid (correct serialization under saturation), that a
//     canceled-context borrow sheds cleanly instead of deadlocking, and that the
//     pool keeps working afterward.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func TestChaosHSMFailoverUnderLoad(t *testing.T) {
	module, pin, soPin := softHSMTokenTooling(t)

	suffix := randSuffix(t)
	labelA := "chaos-tokA-" + suffix
	labelB := "chaos-tokB-" + suffix
	keyLabel := "chaos-cakey-" + suffix
	nameA := "chaosA-" + suffix
	nameB := "chaosB-" + suffix

	initToken(t, labelA, pin, soPin)
	initToken(t, labelB, pin, soPin)
	t.Cleanup(func() { deleteToken(labelA) })
	t.Cleanup(func() { deleteToken(labelB) })

	// One EC key imported into both tokens under the same label: a genuine
	// replica, so a signature made on either token verifies against the single
	// public key — the essential precondition for CA failover.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling PKCS#8: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "cakey.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	importKey(t, keyPath, labelA, keyLabel, pin)
	importKey(t, keyPath, labelB, keyLabel, pin)

	p, err := keyprovider.NewPKCS11HAProvider(keyprovider.PKCS11Settings{
		ModulePath:       module,
		Pin:              pin,
		SelectionPolicy:  string(keyprovider.PolicyPrimaryBackup),
		FailureThreshold: 1, // fail over on the first error → deterministic
		ProbeInterval:    200 * time.Millisecond,
		Tokens: []keyprovider.TokenSettings{
			{Name: nameA, TokenLabel: labelA},
			{Name: nameB, TokenLabel: labelB},
		},
	})
	if err != nil {
		t.Fatalf("NewPKCS11HAProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: keyLabel})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Fatalf("signer public key does not match the imported CA key")
	}

	failoversBefore := metricValue(t, renderMetrics(t), fmt.Sprintf(`secsy_hsm_token_failovers_total{token=%q}`, nameA))

	// Concurrent signing load; a controller pulls the primary token out once a
	// handful of signatures have gone through. Every signature must verify.
	const goroutines, perG = 8, 120
	triggerAt := int64(40)
	var signed atomic.Int64
	var faultOnce sync.Once
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				digest := sha256.Sum256([]byte{seed, byte(i), byte(i >> 8)})
				sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- fmt.Errorf("sign: %w", err)
					return
				}
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					errs <- fmt.Errorf("signature failed verification (g%d op%d)", seed, i)
					return
				}
				if signed.Add(1) >= triggerAt {
					faultOnce.Do(func() { p.FailTokenForTest(0, true) })
				}
			}
		}(byte(g))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("load failed: %v", err)
	}

	// The primary is out of rotation; the backup carries the load.
	if p.TokenHealthy(0) {
		t.Error("primary token still healthy after being pulled mid-load")
	}
	if !p.TokenHealthy(1) {
		t.Error("backup token unexpectedly unhealthy")
	}

	// Metrics reflect the failover.
	out := renderMetrics(t)
	if got := metricValue(t, out, fmt.Sprintf(`secsy_hsm_token_up{token=%q}`, nameA)); got != 0 {
		t.Errorf("secsy_hsm_token_up{token=%q} = %v, want 0", nameA, got)
	}
	if got := metricValue(t, out, fmt.Sprintf(`secsy_hsm_token_up{token=%q}`, nameB)); got != 1 {
		t.Errorf("secsy_hsm_token_up{token=%q} = %v, want 1", nameB, got)
	}
	if got := metricValue(t, out, fmt.Sprintf(`secsy_hsm_token_failovers_total{token=%q}`, nameA)); got-failoversBefore < 1 {
		t.Errorf("failover counter delta for %q = %v, want >= 1", nameA, got-failoversBefore)
	}

	// Signing keeps working entirely on the backup while the primary is down.
	for i := 0; i < 10; i++ {
		digest := sha256.Sum256([]byte{0xAB, byte(i)})
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("post-failover sign %d: %v", i, err)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			t.Fatalf("post-failover signature %d failed verification", i)
		}
	}

	// Recovery: clear the fault and let the background prober restore the token.
	p.FailTokenForTest(0, false)
	if !waitFor(2*time.Second, func() bool { return p.TokenHealthy(0) }) {
		t.Fatal("primary token did not recover after fault cleared")
	}
}

func TestChaosSessionPoolSaturationAndRecovery(t *testing.T) {
	module, pin := softHSM(t)
	token := envOr("SECSY_TOKEN_LABEL", "")
	if token == "" {
		t.Skip("SECSY_TOKEN_LABEL not set")
	}

	cfg := pki.PKCS11Config{ModulePath: module, Pin: pin, TokenLabel: token}
	const poolSize = 3
	pool, err := pki.NewSessionPool(cfg, poolSize)
	if err != nil {
		t.Fatalf("NewSessionPool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	ctx := context.Background()
	label := "chaos-poolkey-" + randSuffix(t)
	if _, err := pool.GenerateSignKey(ctx, label, keyprovider.KeyTypeECDSAP256); err != nil {
		t.Fatalf("GenerateSignKey: %v", err)
	}
	rawPub, _, _, err := pool.PublicKey(ctx, label)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := rawPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type %T, want *ecdsa.PublicKey", rawPub)
	}

	// Saturate: far more concurrent signers than the pool has slots. The bounded
	// pool must serialize them correctly — every signature valid, none dropped.
	const goroutines, perG = 16, 25
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				digest := sha256.Sum256([]byte{seed, byte(i)})
				sig, err := pool.Sign(ctx, label, digest[:], crypto.SHA256)
				if err != nil {
					errs <- fmt.Errorf("sign under saturation: %w", err)
					return
				}
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					errs <- fmt.Errorf("saturated signature failed verification (g%d op%d)", seed, i)
					return
				}
			}
		}(byte(g))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("%v", err)
	}

	// Graceful degradation under context cancellation: a borrow on an
	// already-canceled context must never return a WRONG result. It either sheds
	// cleanly with an error or (because select over a ready free-session and a
	// ready ctx.Done() is nondeterministic when the pool is not saturated)
	// returns a fully valid signature — but never a corrupt one, and never a
	// deadlock.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	digest := sha256.Sum256([]byte("canceled"))
	shed := 0
	for i := 0; i < 8; i++ {
		sig, err := pool.Sign(cctx, label, digest[:], crypto.SHA256)
		if err != nil {
			shed++ // clean shed — acceptable
			continue
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			t.Fatal("canceled-context Sign returned an INVALID signature (corruption)")
		}
	}
	t.Logf("canceled-context Sign: %d/8 shed cleanly, remainder returned valid signatures", shed)

	// Recovery: the pool is immediately usable again with a live context.
	sig, err := pool.Sign(ctx, label, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("post-cancellation Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("post-cancellation signature failed verification")
	}
}
