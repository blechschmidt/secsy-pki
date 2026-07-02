package keyprovider

import (
	"bytes"
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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// TestPKCS11HAFailover is the Task 44 acceptance test: it stands up two SoftHSM
// tokens holding a replica of the same CA key (same CKA_LABEL), drives a
// concurrent signing load through the high-availability provider, pulls the
// primary token out mid-load, and confirms every signature still verifies —
// i.e. issuance continues on the backup — and that per-token health and
// failover metrics reflect the event. It then clears the fault and confirms the
// background prober returns the recovered token to rotation.
//
// The two tokens are created via softhsm2-util in the ambient SoftHSM
// configuration (the one setup-softhsm.sh --export-env exports), so they are
// visible to the same PKCS#11 module the rest of the suite uses. The test is
// skipped when SoftHSM is not configured, matching the other HSM tests.
func TestPKCS11HAFailover(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	if module == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE (run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; cannot create matching HA tokens (run setup-softhsm.sh --export-env)")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found on PATH")
	}

	pin := envOr("SECSY_USER_PIN", "1234")
	soPin := envOr("SECSY_SO_PIN", "5678")

	// Unique per-run identifiers so repeated runs against the persistent SoftHSM
	// store do not collide (see the pkcs11-duplicate-label invariant).
	suffix := randSuffix(t)
	labelA := "ha-tokA-" + suffix
	labelB := "ha-tokB-" + suffix
	keyLabel := "ha-cakey-" + suffix
	nameA := "tokA-" + suffix
	nameB := "tokB-" + suffix

	initToken(t, labelA, pin, soPin)
	initToken(t, labelB, pin, soPin)
	// Registered before the provider is built so these run *after* the pool is
	// closed (t.Cleanup is LIFO), leaving the shared SoftHSM store tidy.
	t.Cleanup(func() { deleteToken(labelA) })
	t.Cleanup(func() { deleteToken(labelB) })

	// Generate one EC P-256 CA key and import the SAME private key into both
	// tokens under the same label — a genuine replica, so a signature made on
	// either token verifies against the one public key (essential for CA
	// failover). A non-extractable key generated independently per token would
	// not share a public half.
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

	// Build the HA provider: primary/backup, fail a token over on the very first
	// error (threshold 1) so the test is deterministic, and probe quickly so
	// recovery is observable within the test's lifetime.
	p, err := NewPKCS11HAProvider(PKCS11Settings{
		ModulePath:       module,
		Pin:              pin,
		SelectionPolicy:  string(PolicyPrimaryBackup),
		FailureThreshold: 1,
		ProbeInterval:    200 * time.Millisecond,
		Tokens: []TokenSettings{
			{Name: nameA, TokenLabel: labelA},
			{Name: nameB, TokenLabel: labelB},
		},
	})
	if err != nil {
		t.Fatalf("NewPKCS11HAProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	signer, err := p.Signer(ctx, KeyRef{Label: keyLabel})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	// The signer's public key must be the replicated CA public key.
	gotPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || gotPub.X.Cmp(priv.X) != 0 || gotPub.Y.Cmp(priv.Y) != 0 {
		t.Fatalf("signer public key does not match the imported CA key")
	}

	// Drive a concurrent signing load. A controller flips the primary token
	// "unreachable" once a handful of signatures have gone through, simulating the
	// token disappearing mid-load. Every signature — before and after — must
	// verify against the single CA public key.
	const goroutines = 8
	const perGoroutine = 120
	var signed atomic.Int64
	var faultOnce sync.Once
	triggerAt := int64(40)

	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				digest := sha256.Sum256([]byte{seed, byte(i), byte(i >> 8)})
				sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- fmt.Errorf("sign: %w", err)
					return
				}
				if !ecdsa.VerifyASN1(gotPub, digest[:], sig) {
					errs <- fmt.Errorf("signature failed verification (goroutine %d op %d)", seed, i)
					return
				}
				if signed.Add(1) >= triggerAt {
					faultOnce.Do(func() {
						// Pull the primary token out from under the load.
						p.members[0].unreachable.Store(true)
					})
				}
			}
		}(byte(g))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("load failed: %v", err)
	}

	// The primary must have been taken out of rotation and the backup must be
	// carrying the load.
	if p.members[0].isHealthy() {
		t.Error("primary token still healthy after being pulled mid-load")
	}
	if !p.members[1].isHealthy() {
		t.Error("backup token unexpectedly unhealthy")
	}

	// Metrics must reflect the failover: primary down, at least one failover
	// charged to it.
	out := renderMetrics(t)
	if got := gaugeValue(t, out, "secsy_hsm_token_up", nameA); got != 0 {
		t.Errorf("secsy_hsm_token_up{token=%q} = %v, want 0", nameA, got)
	}
	if got := gaugeValue(t, out, "secsy_hsm_token_up", nameB); got != 1 {
		t.Errorf("secsy_hsm_token_up{token=%q} = %v, want 1", nameB, got)
	}
	if got := counterValue(t, out, "secsy_hsm_token_failovers_total", nameA); got < 1 {
		t.Errorf("secsy_hsm_token_failovers_total{token=%q} = %v, want >= 1", nameA, got)
	}

	// Sanity: signing keeps working entirely on the backup while the primary is
	// still down.
	for i := 0; i < 10; i++ {
		digest := sha256.Sum256([]byte{0xAB, byte(i)})
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("post-failover sign %d: %v", i, err)
		}
		if !ecdsa.VerifyASN1(gotPub, digest[:], sig) {
			t.Fatalf("post-failover signature %d failed verification", i)
		}
	}

	// Recovery: clear the fault and let the background prober return the primary
	// to rotation.
	p.members[0].unreachable.Store(false)
	if !waitFor(2*time.Second, func() bool { return p.members[0].isHealthy() }) {
		t.Fatal("primary token did not recover after fault cleared")
	}
}

// --- helpers ---------------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 8)
	for _, x := range b {
		out = append(out, hex[x>>4], hex[x&0xf])
	}
	return string(out)
}

func initToken(t *testing.T, label, pin, soPin string) {
	t.Helper()
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--pin", pin, "--so-pin", soPin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init token %q: %v\n%s", label, err, out)
	}
}

// deleteToken removes a token from the shared SoftHSM store. Best-effort: it runs
// during cleanup, so errors are ignored (the store is scratch in CI anyway).
func deleteToken(label string) {
	_ = exec.Command("softhsm2-util", "--delete-token", "--token", label).Run()
}

func importKey(t *testing.T, keyPath, tokenLabel, keyLabel, pin string) {
	t.Helper()
	cmd := exec.Command("softhsm2-util", "--import", keyPath,
		"--token", tokenLabel, "--label", keyLabel, "--id", "a1", "--pin", pin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import key into %q: %v\n%s", tokenLabel, err, out)
	}
}

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

func renderMetrics(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if _, err := metrics.Default.WriteTo(&b); err != nil {
		t.Fatalf("rendering metrics: %v", err)
	}
	return b.String()
}

// gaugeValue extracts a single-label gauge/series value from rendered exposition
// text, e.g. metric{token="tokA"} 0.
func gaugeValue(t *testing.T, text, metric, tokenValue string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metric) + `\{token="` + regexp.QuoteMeta(tokenValue) + `"\} ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("metric %s{token=%q} not found in:\n%s", metric, tokenValue, text)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parsing %s value %q: %v", metric, m[1], err)
	}
	return v
}

func counterValue(t *testing.T, text, metric, tokenValue string) float64 {
	t.Helper()
	return gaugeValue(t, text, metric, tokenValue)
}
