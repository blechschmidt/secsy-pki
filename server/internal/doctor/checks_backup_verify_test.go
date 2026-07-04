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

// verifyCheckResult runs checkBackupRestoreVerified against the given state and
// returns its single result.
func verifyCheckResult(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) Result {
	t.Helper()
	r := &Report{OK: true}
	checkBackupRestoreVerified(r, cfg, db, schemaOK)
	if len(r.Checks) != 1 || r.Checks[0].Name != "backup.restore-verified" {
		t.Fatalf("checkBackupRestoreVerified produced %+v, want one backup.restore-verified result", r.Checks)
	}
	return r.Checks[0]
}

// appendVerifyEvent seals a backup.verify audit event with a controlled
// timestamp and result.
func appendVerifyEvent(t *testing.T, db *database.DB, result, detail string, at time.Time) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{
		ID:         fmt.Sprintf("verify-%d", at.UnixNano()),
		Timestamp:  at,
		Actor:      "backup-verify",
		ActorRoles: "system",
		Action:     audit.ActionBackupVerify,
		Target:     "dir",
		Result:     result,
		Detail:     detail,
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

// freshVerifyDB opens an empty SQLite store for one doctor sub-scenario.
func freshVerifyDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "doctor-verify.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// verifyEnabledConfig is a config with the backup job and its restore-verification
// drill both enabled (24h interval, 30-day retention) unless overridden.
func verifyEnabledConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Backup.Enabled = true
	cfg.Backup.Verify.Enabled = true
	cfg.Backup.Schedule.IntervalHours = 24
	cfg.Backup.Retention.MaxAgeDays = 30
	return cfg
}

// TestCheckBackupRestoreVerified walks the restore-verification doctor check
// through its states: skip when the schema is unavailable, skip when disabled
// with no history, warn when enabled but silent, pass on a fresh success, fail
// on a newest-errored drill, fail when the last success is older than the
// retention max age, warn when merely stalled, and pass (informational) when a
// success exists but verification is disabled.
func TestCheckBackupRestoreVerified(t *testing.T) {
	now := time.Now().UTC()
	enabled := verifyEnabledConfig()
	disabled := &config.Config{}

	// Schema unavailable → skip regardless of config.
	if res := verifyCheckResult(t, enabled, freshVerifyDB(t), false); res.Status != StatusSkip {
		t.Fatalf("schema-unavailable status = %s, want skip (%s)", res.Status, res.Detail)
	}

	// No drills on record: disabled skips, enabled warns (it should be running).
	if res := verifyCheckResult(t, disabled, freshVerifyDB(t), true); res.Status != StatusSkip {
		t.Fatalf("disabled/no-history status = %s, want skip (%s)", res.Status, res.Detail)
	}
	if res := verifyCheckResult(t, enabled, freshVerifyDB(t), true); res.Status != StatusWarn {
		t.Fatalf("enabled/no-history status = %s, want warn (%s)", res.Status, res.Detail)
	}

	// A fresh success passes.
	freshDB := freshVerifyDB(t)
	appendVerifyEvent(t, freshDB, audit.ResultSuccess, "backend=dir driver=sqlite fingerprint_match=true", now.Add(-1*time.Hour))
	if res := verifyCheckResult(t, enabled, freshDB, true); res.Status != StatusPass {
		t.Fatalf("fresh-success status = %s, want pass (%s)", res.Status, res.Detail)
	}
	// The same success without verification enabled is informational (pass).
	if res := verifyCheckResult(t, disabled, freshDB, true); res.Status != StatusPass {
		t.Fatalf("disabled/with-history status = %s, want pass (%s)", res.Status, res.Detail)
	}

	// A newest-errored drill fails — recovery is unproven.
	errDB := freshVerifyDB(t)
	appendVerifyEvent(t, errDB, audit.ResultSuccess, "ok", now.Add(-3*time.Hour))
	appendVerifyEvent(t, errDB, audit.ResultError, "stage=fingerprint error=head mismatch", now.Add(-1*time.Hour))
	if res := verifyCheckResult(t, enabled, errDB, true); res.Status != StatusFail {
		t.Fatalf("newest-error status = %s, want fail (%s)", res.Status, res.Detail)
	}

	// A success older than the retention max age fails: the verified backup may
	// already be pruned, so nothing current is proven restorable.
	staleCfg := verifyEnabledConfig()
	staleCfg.Backup.Retention.MaxAgeDays = 1 // 24h window
	staleDB := freshVerifyDB(t)
	appendVerifyEvent(t, staleDB, audit.ResultSuccess, "ok", now.Add(-48*time.Hour))
	if res := verifyCheckResult(t, staleCfg, staleDB, true); res.Status != StatusFail {
		t.Fatalf("over-max-age status = %s, want fail (%s)", res.Status, res.Detail)
	}

	// With no age limit, a success beyond 3x the verify interval is a warn.
	stalledCfg := verifyEnabledConfig()
	stalledCfg.Backup.Retention.MaxAgeDays = 0 // no age gate
	stalledDB := freshVerifyDB(t)
	appendVerifyEvent(t, stalledDB, audit.ResultSuccess, "ok", now.Add(-96*time.Hour)) // > 3x 24h
	if res := verifyCheckResult(t, stalledCfg, stalledDB, true); res.Status != StatusWarn {
		t.Fatalf("stalled status = %s, want warn (%s)", res.Status, res.Detail)
	}
}
