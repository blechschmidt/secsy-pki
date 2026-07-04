//go:build sqlite

package doctor

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/google/uuid"
)

// ctCheckResult runs checkCTInclusion and returns its single result.
func ctCheckResult(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) Result {
	t.Helper()
	r := &Report{OK: true}
	checkCTInclusion(r, cfg, db, schemaOK)
	if len(r.Checks) != 1 || r.Checks[0].Name != "ct.inclusion" {
		t.Fatalf("checkCTInclusion produced %+v, want one ct.inclusion result", r.Checks)
	}
	return r.Checks[0]
}

func seedCTCA(t *testing.T, db *database.DB) {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID: "ca1", TenantID: models.DefaultTenantID, Label: "issuing",
		PKCS11URI: "pkcs11:token=ca1", KeyType: "ecdsa", PublicKey: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
}

func appendCTScan(t *testing.T, db *database.DB, result string, at time.Time) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{
		ID: uuid.New().String(), Timestamp: at, Actor: "ct-monitor", ActorRoles: "system",
		Action: audit.ActionCTInclusion, Result: result, Detail: "certs=1 checked=1",
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

// TestCheckCTInclusion walks the doctor check through its states: skip when the
// schema is unavailable, warn when enabled but silent, skip when disabled with no
// records, fail when any SCT failed (log misbehavior), and pass / stalled-warn on
// a fully-included set.
func TestCheckCTInclusion(t *testing.T) {
	db, err := database.New("sqlite", t.TempDir()+"/ct.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()
	seedCTCA(t, db)

	disabled := &config.Config{}
	enabled := &config.Config{}
	enabled.CertificateTransparency.InclusionMonitor.Enabled = true
	enabled.CertificateTransparency.InclusionMonitor.IntervalMinutes = 60

	// Schema unavailable → skip.
	if res := ctCheckResult(t, enabled, db, false); res.Status != StatusSkip {
		t.Fatalf("schema-unavailable = %s, want skip", res.Status)
	}
	// No records: enabled warns, disabled skips.
	if res := ctCheckResult(t, enabled, db, true); res.Status != StatusWarn {
		t.Fatalf("enabled/no-records = %s, want warn (%s)", res.Status, res.Detail)
	}
	if res := ctCheckResult(t, disabled, db, true); res.Status != StatusSkip {
		t.Fatalf("disabled/no-records = %s, want skip", res.Status)
	}

	now := time.Now().UTC()
	up := func(serial, logID, status string) {
		lc := now
		if err := db.UpsertSCTInclusion(&models.SCTInclusion{
			CAID: "ca1", Serial: serial, LogID: logID, LogName: logID,
			SCTTimestamp: now.Add(-48 * time.Hour), Status: status, LastCheckedAt: &lc,
		}); err != nil {
			t.Fatalf("UpsertSCTInclusion: %v", err)
		}
	}

	// A failed SCT → fail regardless of scan freshness.
	up("1001", "aa", models.SCTInclusionIncluded)
	up("1002", "bb", models.SCTInclusionFailed)
	appendCTScan(t, db, audit.ResultError, now.Add(-2*time.Minute))
	if res := ctCheckResult(t, enabled, db, true); res.Status != StatusFail {
		t.Fatalf("failed-SCT = %s, want fail (%s)", res.Status, res.Detail)
	}

	// Clear the failure to an included state: a fresh scan now passes.
	up("1002", "bb", models.SCTInclusionIncluded)
	appendCTScan(t, db, audit.ResultSuccess, now.Add(-1*time.Minute))
	if res := ctCheckResult(t, enabled, db, true); res.Status != StatusPass {
		t.Fatalf("all-included/fresh = %s, want pass (%s)", res.Status, res.Detail)
	}

	// A stale newest scan (older than 3x the interval) warns even with all-included.
	db2, err := database.New("sqlite", t.TempDir()+"/ct-stale.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db2.Close()
	seedCTCA(t, db2)
	lc := now
	if err := db2.UpsertSCTInclusion(&models.SCTInclusion{
		CAID: "ca1", Serial: "1", LogID: "aa", LogName: "aa",
		SCTTimestamp: now.Add(-48 * time.Hour), Status: models.SCTInclusionIncluded, LastCheckedAt: &lc,
	}); err != nil {
		t.Fatalf("UpsertSCTInclusion: %v", err)
	}
	appendCTScan(t, db2, audit.ResultSuccess, now.Add(-5*time.Hour)) // > 3x60m
	if res := ctCheckResult(t, enabled, db2, true); res.Status != StatusWarn {
		t.Fatalf("stalled-scan = %s, want warn (%s)", res.Status, res.Detail)
	}
}
