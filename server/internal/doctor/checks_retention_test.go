//go:build sqlite

package doctor

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// retentionCheckResult runs checkRetention against the given state and returns
// its single result.
func retentionCheckResult(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) Result {
	t.Helper()
	r := &Report{OK: true}
	checkRetention(r, cfg, db, schemaOK)
	if len(r.Checks) != 1 || r.Checks[0].Name != "retention.freshness" {
		t.Fatalf("checkRetention produced %+v, want one retention.freshness result", r.Checks)
	}
	return r.Checks[0]
}

func appendRetentionEvent(t *testing.T, db *database.DB, result, detail string, at time.Time) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{
		ID:         fmt.Sprintf("retention-%d", at.UnixNano()),
		Timestamp:  at,
		Actor:      "retention",
		ActorRoles: "system",
		Action:     audit.ActionInventoryRetention,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

func freshRetentionDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "doctor-retention.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func retentionEnabledConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Retention.Enabled = true
	cfg.Retention.Schedule.IntervalHours = 24
	return cfg
}

// TestCheckRetention walks the retention.freshness doctor check through its
// states: skip when the schema is unavailable, skip when disabled with no
// history, warn when enabled but silent, pass on a fresh success, fail on a
// newest-errored run, warn when merely stalled, and pass (informational) when a
// success exists but the loop is disabled.
func TestCheckRetention(t *testing.T) {
	now := time.Now().UTC()
	enabled := retentionEnabledConfig()
	disabled := &config.Config{}

	// Schema unavailable → skip regardless of config.
	if res := retentionCheckResult(t, enabled, freshRetentionDB(t), false); res.Status != StatusSkip {
		t.Fatalf("schema-unavailable status = %s, want skip (%s)", res.Status, res.Detail)
	}

	// No runs on record: disabled skips, enabled warns (it should be running).
	if res := retentionCheckResult(t, disabled, freshRetentionDB(t), true); res.Status != StatusSkip {
		t.Fatalf("disabled/no-history status = %s, want skip (%s)", res.Status, res.Detail)
	}
	if res := retentionCheckResult(t, enabled, freshRetentionDB(t), true); res.Status != StatusWarn {
		t.Fatalf("enabled/no-history status = %s, want warn (%s)", res.Status, res.Detail)
	}

	// A fresh success passes.
	freshDB := freshRetentionDB(t)
	appendRetentionEvent(t, freshDB, audit.ResultSuccess, "mode=archive archived=10 pruned=0 driver=sqlite", now.Add(-1*time.Hour))
	if res := retentionCheckResult(t, enabled, freshDB, true); res.Status != StatusPass {
		t.Fatalf("fresh-success status = %s, want pass (%s)", res.Status, res.Detail)
	}
	// The same success with the loop disabled is informational (pass).
	if res := retentionCheckResult(t, disabled, freshDB, true); res.Status != StatusPass {
		t.Fatalf("disabled/with-history status = %s, want pass (%s)", res.Status, res.Detail)
	}

	// A newest-errored run fails.
	errDB := freshRetentionDB(t)
	appendRetentionEvent(t, errDB, audit.ResultSuccess, "ok", now.Add(-3*time.Hour))
	appendRetentionEvent(t, errDB, audit.ResultError, "mode=prune error=archiving batch: boom driver=sqlite", now.Add(-1*time.Hour))
	if res := retentionCheckResult(t, enabled, errDB, true); res.Status != StatusFail {
		t.Fatalf("newest-error status = %s, want fail (%s)", res.Status, res.Detail)
	}

	// A success older than 3x the interval is a warn (stalled).
	stalledDB := freshRetentionDB(t)
	appendRetentionEvent(t, stalledDB, audit.ResultSuccess, "ok", now.Add(-96*time.Hour)) // > 3x 24h
	if res := retentionCheckResult(t, enabled, stalledDB, true); res.Status != StatusWarn {
		t.Fatalf("stalled status = %s, want warn (%s)", res.Status, res.Detail)
	}
}
