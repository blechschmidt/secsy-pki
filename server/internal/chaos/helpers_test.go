//go:build sqlite

// Shared fault-injection test helpers: dependency gating (SoftHSM / PostgreSQL),
// SoftHSM token provisioning, metrics inspection, and the cross-cutting
// invariant checkers (audit-chain continuity, serial uniqueness) that every
// scenario asserts after it has finished degrading a dependency.
package chaos

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// --- dependency gating -----------------------------------------------------

// softHSM reports the PKCS#11 module path and user PIN, skipping the test when
// SoftHSM is not configured. It mirrors the skip contract of the other HSM
// tests in the tree so `go test ./...` stays green without an HSM.
func softHSM(t *testing.T) (module, pin string) {
	t.Helper()
	module = os.Getenv("SECSY_PKCS11_MODULE")
	if module == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE (run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	return module, envOr("SECSY_USER_PIN", "1234")
}

// softHSMTokenTooling additionally requires SOFTHSM2_CONF and softhsm2-util so a
// scenario can create its own scratch tokens (needed for HA replica setup).
func softHSMTokenTooling(t *testing.T) (module, pin, soPin string) {
	t.Helper()
	module, pin = softHSM(t)
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; cannot create scratch tokens (run setup-softhsm.sh --export-env)")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found on PATH")
	}
	return module, pin, envOr("SECSY_SO_PIN", "5678")
}

// postgresDSN returns the PostgreSQL DSN for the connection-drop scenarios, or
// skips when SECSY_TEST_PG_DSN is unset (matching internal/database tests).
func postgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SECSY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL not configured: set SECSY_TEST_PG_DSN to a reachable test database")
	}
	return dsn
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// randSuffix draws a fresh 8-hex-char suffix so repeated runs against a
// persistent SoftHSM store never collide on a token or key label.
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

// --- SoftHSM token provisioning --------------------------------------------

func initToken(t *testing.T, label, pin, soPin string) {
	t.Helper()
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--pin", pin, "--so-pin", soPin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init token %q: %v\n%s", label, err, out)
	}
}

// deleteToken removes a scratch token. Best-effort: it runs during cleanup.
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

// --- polling ---------------------------------------------------------------

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

// --- metrics inspection ----------------------------------------------------

// renderMetrics serializes the process-global registry to Prometheus text.
func renderMetrics(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if _, err := metrics.Default.WriteTo(&b); err != nil {
		t.Fatalf("rendering metrics: %v", err)
	}
	return b.String()
}

// metricValue returns the value of the exposition line whose series exactly
// matches series (a full `name{labels}` string, or a bare name for an
// unlabeled metric), or 0 when the series is absent. Counters are read as
// before/after deltas by the callers so the process-global registry's
// accumulation across tests never makes an assertion flaky.
func metricValue(t *testing.T, text, series string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parsing %q value %q: %v", series, m[1], err)
	}
	return v
}

// --- invariant checkers ----------------------------------------------------

// assertAuditChainIntact fails the test unless the hash-chained event_log is
// contiguous (no gaps), correctly back-linked, and untampered.
func assertAuditChainIntact(t *testing.T, db *database.DB) {
	t.Helper()
	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatalf("verifying audit chain: %v", err)
	}
	if !res.Valid {
		t.Fatalf("audit chain broken at seq %d: %s (verified %d events)",
			res.BrokenAtSeq, res.Reason, res.Count)
	}
}

// assertNoDuplicates fails the test if the slice contains a repeated value,
// reporting the collision. Used for serials and CRL numbers.
func assertNoDuplicates(t *testing.T, kind string, values []string) {
	t.Helper()
	seen := make(map[string]int, len(values))
	for i, v := range values {
		if prev, ok := seen[v]; ok {
			t.Fatalf("duplicate %s %q produced by concurrent index %d and %d", kind, v, prev, i)
		}
		seen[v] = i
	}
}
