//go:build sqlite

package handlers

// Tests for the inventory-retention REST surface (Task 198). The load-bearing
// invariant is that the dry-run mutates NOTHING: the console's preview button
// must never be able to delete a certificate record, so the row counts are
// asserted before and after.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const retentionCA = "retention-ca"

// retentionAPI builds an API with the operations dependencies installed over the
// given retention policy — the same policy the CLI and the background loop read.
func retentionAPI(t *testing.T, cfg config.RetentionConfig) (*API, *database.DB) {
	t.Helper()
	api, db := tenantAPI(t)
	api.SetOps(&OpsDeps{Config: &config.Config{Retention: cfg}, ConfigPath: "/etc/secsy/test.yaml"})
	return api, db
}

// seedRetentionInventory records one still-valid certificate and two
// long-expired terminal ones, so exactly two rows are eligible under a 90-day
// grace window measured against the real clock (the handler's runner uses it).
func seedRetentionInventory(t *testing.T, db *database.DB) (eligible, retained []string) {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID: retentionCA, Label: retentionCA, PKCS11URI: "pkcs11:" + retentionCA,
		KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	now := time.Now().UTC()
	rec := func(serial string, notAfter time.Time, status models.CertStatus) {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: retentionCA + "-" + serial, CAID: retentionCA, Serial: serial,
			CommonName: serial + ".example.com", Profile: "server",
			Certificate: "-----BEGIN CERTIFICATE-----\n" + serial + "\n-----END CERTIFICATE-----\n",
			NotBefore:   notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter, Status: status,
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%s): %v", serial, err)
		}
	}
	rec("3001", now.Add(90*24*time.Hour), models.CertStatusValid)     // still valid -> never eligible
	rec("3002", now.Add(-200*24*time.Hour), models.CertStatusExpired) // eligible
	rec("3003", now.Add(-200*24*time.Hour), models.CertStatusExpired) // eligible
	return []string{"3002", "3003"}, []string{"3001"}
}

func retentionStatus(api *API, user *models.UserInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.InventoryRetentionStatus(rec, reqAs(http.MethodGet, "/api/inventory/retention", user, "", ""))
	return rec
}

func retentionRun(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.RunInventoryRetention(rec, reqAs(http.MethodPost, "/api/inventory/retention/run", user, "", body))
	return rec
}

// hotAndArchived reports how many of the given serials are still in the hot
// inventory table, plus the archive's total size.
func hotAndArchived(t *testing.T, db *database.DB, serials []string) (hot, archiveSize int) {
	t.Helper()
	for _, s := range serials {
		ic, err := db.GetIssuedCertificate(retentionCA, s)
		if err != nil {
			t.Fatalf("GetIssuedCertificate(%s): %v", s, err)
		}
		if ic != nil {
			hot++
		}
	}
	n, err := db.CountArchivedCertificates()
	if err != nil {
		t.Fatalf("CountArchivedCertificates: %v", err)
	}
	return hot, n
}

// TestRetentionAuthz pins both gates: status is a cross-tenant read (platform
// audit:read), running a pass is deployment-wide policy execution (platform
// ca:configure). No tenant-scoped principal reaches either.
func TestRetentionAuthz(t *testing.T) {
	api, _ := retentionAPI(t, config.RetentionConfig{Enabled: true, Mode: config.RetentionModeArchive, MinAgeDays: 90})

	for _, tc := range []struct {
		name                string
		user                *models.UserInfo
		status, dryRun, run int
	}{
		{"unauthenticated", nil, 403, 403, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403, 403, 403},
		// An auditor may read the posture but not execute a pass.
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 200, 403, 403},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 200, 403, 403},
		// Retention spans every tenant's inventory, so tenant-scoped authority —
		// even tenant admin — reaches neither endpoint.
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 403, 403, 403},
		{"tenant auditor", tenantUser("taud", "a", "auditor"), 403, 403, 403},
		{"root", rootUser(), 200, 200, 200},
		{"platform admin", platformAdmin(), 200, 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := retentionStatus(api, tc.user); rec.Code != tc.status {
				t.Errorf("status: got %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			if rec := retentionRun(api, tc.user, `{"dry_run":true}`); rec.Code != tc.dryRun {
				t.Errorf("dry-run: got %d, want %d; body=%s", rec.Code, tc.dryRun, rec.Body.String())
			}
			if rec := retentionRun(api, tc.user, `{"dry_run":false}`); rec.Code != tc.run {
				t.Errorf("run: got %d, want %d; body=%s", rec.Code, tc.run, rec.Body.String())
			}
		})
	}
}

// TestRetentionWithoutOpsDeps proves the endpoints degrade to 503 rather than
// panicking when the server was started without the operations dependencies —
// and that authorization is still decided first, so a roleless caller cannot
// probe the server's wiring.
func TestRetentionWithoutOpsDeps(t *testing.T) {
	api, _ := tenantAPI(t) // no SetOps

	for _, tc := range []struct {
		name string
		call func(*models.UserInfo) *httptest.ResponseRecorder
	}{
		{"status", func(u *models.UserInfo) *httptest.ResponseRecorder { return retentionStatus(api, u) }},
		{"run", func(u *models.UserInfo) *httptest.ResponseRecorder { return retentionRun(api, u, `{}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := tc.call(rootUser()); rec.Code != http.StatusServiceUnavailable {
				t.Errorf("capable caller: got %d, want 503; body=%s", rec.Code, rec.Body.String())
			}
			if rec := tc.call(&models.UserInfo{Subject: "nobody"}); rec.Code != http.StatusForbidden {
				t.Errorf("roleless caller: got %d, want 403 (authz decided before wiring); body=%s",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRetentionStatus reports the configured policy, the live eligibility counts,
// and the newest recorded run — the same three things the CLI's status prints.
func TestRetentionStatus(t *testing.T) {
	api, db := retentionAPI(t, config.RetentionConfig{
		Enabled: true, Mode: config.RetentionModeArchive, MinAgeDays: 90,
		Schedule: config.RetentionScheduleConfig{IntervalHours: 12},
	})
	seedRetentionInventory(t, db)

	var resp RetentionStatusResponse
	rec := retentionStatus(api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if !resp.Enabled || resp.Interval != (12*time.Hour).String() {
		t.Errorf("enabled=%v interval=%q, want true/12h0m0s", resp.Enabled, resp.Interval)
	}
	if resp.Mode != config.RetentionModeArchive || resp.Window != "90d" {
		t.Errorf("mode=%q window=%q, want archive/90d", resp.Mode, resp.Window)
	}
	if resp.Eligible != 2 {
		t.Errorf("eligible = %d, want 2 (the two long-expired rows)", resp.Eligible)
	}
	if resp.ArchiveSize != 0 {
		t.Errorf("archive_size = %d, want 0 before any run", resp.ArchiveSize)
	}
	if resp.LastRun != nil {
		t.Errorf("last_run = %+v, want absent before any run", resp.LastRun)
	}
	if resp.Cutoff.IsZero() || !resp.Cutoff.Before(time.Now()) {
		t.Errorf("cutoff = %v, want a past instant", resp.Cutoff)
	}

	// After a real pass the status surfaces the run the audit log recorded.
	if rec := retentionRun(api, rootUser(), `{}`); rec.Code != http.StatusOK {
		t.Fatalf("run: got %d; body=%s", rec.Code, rec.Body.String())
	}
	rec = retentionStatus(api, rootUser())
	resp = RetentionStatusResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LastRun == nil {
		t.Fatalf("last_run is absent after a run")
	}
	if resp.LastRun.Action != audit.ActionInventoryRetention || !strings.Contains(resp.LastRun.Detail, "archived=2") {
		t.Errorf("last_run = %+v, want an inventory.retention event reporting archived=2", resp.LastRun)
	}
	if resp.Eligible != 0 || resp.ArchiveSize != 2 {
		t.Errorf("after the run: eligible=%d archive_size=%d, want 0/2", resp.Eligible, resp.ArchiveSize)
	}
}

// TestRetentionDryRunDoesNotDelete is the safety invariant: the dry-run reports
// exactly what a pass would do and leaves every row where it was; only the real
// pass moves anything.
func TestRetentionDryRunDoesNotDelete(t *testing.T) {
	api, db := retentionAPI(t, config.RetentionConfig{Enabled: false, Mode: config.RetentionModeArchive, MinAgeDays: 90})
	eligible, retained := seedRetentionInventory(t, db)
	all := append(append([]string{}, eligible...), retained...)

	hotBefore, archiveBefore := hotAndArchived(t, db, all)
	if hotBefore != 3 || archiveBefore != 0 {
		t.Fatalf("fixture = %d hot / %d archived, want 3/0", hotBefore, archiveBefore)
	}

	rec := retentionRun(api, rootUser(), `{"dry_run":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var plan RetentionRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if !plan.DryRun {
		t.Errorf("dry_run = false in the response to a dry-run request")
	}
	if plan.Archived != 2 || plan.Eligible != 2 || plan.Pruned != 0 {
		t.Errorf("plan = archived %d eligible %d pruned %d, want 2/2/0", plan.Archived, plan.Eligible, plan.Pruned)
	}
	if !strings.HasPrefix(plan.Digest, "sha256:") {
		t.Errorf("digest = %q, want a sha256 manifest digest", plan.Digest)
	}

	// NOTHING moved, and no audit event claims otherwise.
	hotAfter, archiveAfter := hotAndArchived(t, db, all)
	if hotAfter != hotBefore || archiveAfter != archiveBefore {
		t.Fatalf("dry-run mutated the store: %d hot / %d archived, want %d/%d",
			hotAfter, archiveAfter, hotBefore, archiveBefore)
	}
	if events, _, err := db.ListEvents(audit.ActionInventoryRetention, "", "", 10, 0); err != nil || len(events) != 0 {
		t.Fatalf("dry-run recorded %d inventory.retention events (err=%v), want 0", len(events), err)
	}

	// The real pass, over the same policy, moves exactly the planned rows.
	rec = retentionRun(api, rootUser(), `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("run: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var run RetentionRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if run.DryRun || run.Archived != plan.Archived || run.Error != "" {
		t.Fatalf("run = %+v, want a real pass archiving the %d planned rows", run.Result, plan.Archived)
	}
	if hot, archived := hotAndArchived(t, db, all); hot != 1 || archived != 2 {
		t.Fatalf("after the run: %d hot / %d archived, want 1/2", hot, archived)
	}
	for _, s := range retained {
		if ic, _ := db.GetIssuedCertificate(retentionCA, s); ic == nil {
			t.Errorf("still-valid serial %s was archived", s)
		}
	}
	for _, s := range eligible {
		if ar, _ := db.GetArchivedCertificate(retentionCA, s); ar == nil {
			t.Errorf("eligible serial %s is not in the archive", s)
		}
	}

	// Two events: the runner's tamper-evident record (actor "retention", carrying
	// the manifest digest) and the operator-attributed one this endpoint adds.
	events, _, err := db.ListEvents(audit.ActionInventoryRetention, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawOperator, sawRunner bool
	for _, e := range events {
		switch e.Actor {
		case "root":
			sawOperator = strings.Contains(e.Detail, "via=api") && strings.Contains(e.Detail, "archived=2")
		case "retention":
			sawRunner = strings.Contains(e.Detail, run.Digest)
		}
	}
	if !sawOperator || !sawRunner {
		t.Errorf("audit events = %+v, want both the operator-attributed (via=api) and the runner's digest event", events)
	}
}

// TestRetentionRunConcurrentIsRejected is the single-flight invariant: only one
// real pass may be in flight in a process at a time.
//
// Leader election makes the background loop a singleton ACROSS replicas and says
// nothing about what else in that process prunes. internal/retention holds no lock,
// so before this guard the endpoint could start a pass against the leader's — two
// passes interleaving archive/prune transactions over one archive, which in prune
// mode are hard deletes. The dry run deliberately does NOT contend: it mutates
// nothing, and an operator wants the preview most while a pass is running.
func TestRetentionRunConcurrentIsRejected(t *testing.T) {
	api, db := retentionAPI(t, config.RetentionConfig{Mode: config.RetentionModeArchive, MinAgeDays: 90})
	eligible, retained := seedRetentionInventory(t, db)
	all := append(append([]string{}, eligible...), retained...)

	// Hold the guard as the background loop (or another request) would.
	release, ok := TryRetentionLock()
	if !ok {
		t.Fatal("the retention guard was already held at the start of the test")
	}
	rec := retentionRun(api, rootUser(), `{}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("contended run: got %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	// The refused pass touched nothing, and recorded no event claiming it had.
	if hot, archived := hotAndArchived(t, db, all); hot != 3 || archived != 0 {
		t.Errorf("a refused pass moved rows: %d hot / %d archived, want 3/0", hot, archived)
	}
	if events, _, err := db.ListEvents(audit.ActionInventoryRetention, "", "", 10, 0); err != nil || len(events) != 0 {
		t.Errorf("a refused pass recorded %d inventory.retention events (err=%v), want 0", len(events), err)
	}
	// The preview still works while a pass holds the guard.
	if rec := retentionRun(api, rootUser(), `{"dry_run":true}`); rec.Code != http.StatusOK {
		t.Errorf("dry run under contention: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Released, the same request succeeds — the guard is not leaked on the 409 path.
	release()
	if rec := retentionRun(api, rootUser(), `{}`); rec.Code != http.StatusOK {
		t.Fatalf("run after release: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if hot, archived := hotAndArchived(t, db, all); hot != 1 || archived != 2 {
		t.Errorf("after the pass: %d hot / %d archived, want 1/2", hot, archived)
	}
	// And the guard is free again after a completed pass.
	if release, ok := TryRetentionLock(); !ok {
		t.Error("the guard is still held after a completed pass")
	} else {
		release()
	}
}

// TestRetentionRunSurvivesClientDisconnect pins the other half of the
// mutating-pass contract: a pass hard-deletes rows in a sequence of independent
// transactions, so a client hanging up must not be able to stop it between batches,
// and the endpoint therefore hands the runner a context.WithoutCancel of the
// request's under its own deadline — the shape POST /api/publish and
// POST /api/backup/verify-restore use.
//
// It is a CONTRACT guard, not a reproduction: retention.Runner.RunNow currently
// accepts a context and never consults it (Runner.pass takes none and the store
// calls are context-free), so today a cancelled request context could not have
// aborted a pass either way. That is precisely why the guard is worth pinning — the
// moment a batch honors its context, the difference between r.Context() and
// WithoutCancel becomes a half-applied prune, and this test fails instead of an
// operator discovering it.
func TestRetentionRunSurvivesClientDisconnect(t *testing.T) {
	api, db := retentionAPI(t, config.RetentionConfig{Mode: config.RetentionModeArchive, MinAgeDays: 90})
	eligible, retained := seedRetentionInventory(t, db)
	all := append(append([]string{}, eligible...), retained...)

	// A request whose context is ALREADY cancelled is the extreme form of "the client
	// hung up". It is derived from the real request context, so the actor and tenant
	// values are still there — which is what makes the audit assertion below mean
	// something: WithoutCancel must drop the cancellation and keep the values.
	base := reqAs(http.MethodPost, "/api/inventory/retention/run", rootUser(), "", `{}`)
	ctx, cancel := context.WithCancel(base.Context())
	cancel()
	rec := httptest.NewRecorder()
	api.RunInventoryRetention(rec, base.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 despite the cancelled request context; body=%s", rec.Code, rec.Body.String())
	}
	var resp RetentionRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Error != "" || resp.Archived != 2 {
		t.Fatalf("result = archived %d error %q, want the 2 eligible rows archived", resp.Archived, resp.Error)
	}
	if hot, archived := hotAndArchived(t, db, all); hot != 1 || archived != 2 {
		t.Errorf("after the pass: %d hot / %d archived, want 1/2", hot, archived)
	}
	// The operator attribution survives the detachment: WithoutCancel keeps values.
	if log := eventDetails(t, db); !strings.Contains(log, "via=api") {
		t.Errorf("the detached pass lost the operator attribution:\n%s", log)
	}
}

// TestRetentionRunBadInput rejects a malformed body instead of guessing which
// half of the CLI the caller meant.
func TestRetentionRunBadInput(t *testing.T) {
	api, db := retentionAPI(t, config.RetentionConfig{Mode: config.RetentionModeArchive, MinAgeDays: 90})
	eligible, retained := seedRetentionInventory(t, db)
	all := append(append([]string{}, eligible...), retained...)

	for _, tc := range []struct {
		name, body string
	}{
		{"not json", `{`},
		{"dry_run not a bool", `{"dry_run":"yes"}`},
		{"body is an array", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := retentionRun(api, rootUser(), tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	// A rejected request never reached the runner.
	if hot, archived := hotAndArchived(t, db, all); hot != 3 || archived != 0 {
		t.Fatalf("after rejected requests: %d hot / %d archived, want 3/0", hot, archived)
	}
}
