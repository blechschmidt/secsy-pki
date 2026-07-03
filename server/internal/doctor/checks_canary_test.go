//go:build sqlite

package doctor

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// canaryCheckResult runs checkCanary against the given state and returns its
// single result.
func canaryCheckResult(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) Result {
	t.Helper()
	r := &Report{OK: true}
	checkCanary(r, cfg, db, schemaOK)
	if len(r.Checks) != 1 || r.Checks[0].Name != "canary.last_probe" {
		t.Fatalf("checkCanary produced %+v, want one canary.last_probe result", r.Checks)
	}
	return r.Checks[0]
}

// appendProbeEvent seals a canary.probe audit event with a controlled
// timestamp, target, and result.
func appendProbeEvent(t *testing.T, db *database.DB, target, name, result, detail string, at time.Time) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{
		ID:         fmt.Sprintf("evt-%s-%d", target, at.UnixNano()),
		Timestamp:  at,
		Actor:      "canary",
		ActorRoles: "system",
		Action:     audit.ActionCanaryProbe,
		Target:     target,
		TargetName: name,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

// TestCheckCanary walks the canary doctor check through its states: skip when
// disabled with no history, warn when enabled but silent, pass on a fresh
// success, fail when any CA's newest probe errored, and warn when the last
// success has gone stale relative to the configured interval.
func TestCheckCanary(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "doctor-canary.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	disabled := &config.Config{}
	enabled := &config.Config{}
	enabled.Canary.Enabled = true
	enabled.Canary.CAs = []string{"ca1"}
	enabled.Canary.IntervalMinutes = 15

	// Schema unavailable → skip regardless of config.
	if res := canaryCheckResult(t, enabled, db, false); res.Status != StatusSkip {
		t.Fatalf("schema-unavailable status = %s, want skip (%s)", res.Status, res.Detail)
	}

	// No probes on record: disabled skips, enabled warns (canary should run).
	if res := canaryCheckResult(t, disabled, db, true); res.Status != StatusSkip {
		t.Fatalf("disabled/no-history status = %s, want skip (%s)", res.Status, res.Detail)
	}
	if res := canaryCheckResult(t, enabled, db, true); res.Status != StatusWarn {
		t.Fatalf("enabled/no-history status = %s, want warn (%s)", res.Status, res.Detail)
	}

	// A fresh success passes.
	now := time.Now().UTC()
	appendProbeEvent(t, db, "ca1", "Issuing CA", audit.ResultSuccess, "serial=1 stages=issue:10ms", now.Add(-5*time.Minute))
	if res := canaryCheckResult(t, enabled, db, true); res.Status != StatusPass {
		t.Fatalf("fresh-success status = %s, want pass (%s)", res.Status, res.Detail)
	}

	// A newer failure for a second CA fails the check even though ca1 is green.
	appendProbeEvent(t, db, "ca2", "Other CA", audit.ResultError, "failed_stage=ocsp_good error=hsm down", now.Add(-2*time.Minute))
	res := canaryCheckResult(t, enabled, db, true)
	if res.Status != StatusFail {
		t.Fatalf("newest-error status = %s, want fail (%s)", res.Status, res.Detail)
	}
	// Both CAs' latest states must be visible in the detail.
	for _, want := range []string{"Other CA: FAILED", "Issuing CA: ok"} {
		if !strings.Contains(res.Detail, want) {
			t.Fatalf("detail %q missing %q", res.Detail, want)
		}
	}

	// A success that recovers ca2 but is far older than 3x the interval on ca1…
	// simulate by moving to a fresh store with only an old success.
	db2, err := database.New("sqlite", filepath.Join(t.TempDir(), "doctor-canary-stale.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db2.Close()
	appendProbeEvent(t, db2, "ca1", "Issuing CA", audit.ResultSuccess, "serial=9", now.Add(-2*time.Hour))
	if res := canaryCheckResult(t, enabled, db2, true); res.Status != StatusWarn {
		t.Fatalf("stale-success status = %s, want warn (%s)", res.Status, res.Detail)
	}
	// The same old success without the canary enabled is informational only.
	if res := canaryCheckResult(t, disabled, db2, true); res.Status != StatusPass {
		t.Fatalf("disabled/old-history status = %s, want pass (%s)", res.Status, res.Detail)
	}
}
