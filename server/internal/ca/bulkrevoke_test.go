//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 70 engine tests: dry-run planning with every filter, batched execution
// with per-certificate + summary audit events, the single end-of-run CRL+delta
// regeneration, OCSP cache invalidation and presign refresh, mandatory-count
// enforcement, resumability after interruption, and the
// suspended-tenant-can-still-revoke invariant.

// bulkTestEnv is one CA with a set of issued leaves to mass-revoke.
type bulkTestEnv struct {
	mgr  *Manager
	root *models.CA
	// serials by CN suffix, in issuance order.
	serials []string
}

// setupBulkEnv issues n server-profile leaves named <prefix>-<i>.example.com.
func setupBulkEnv(t *testing.T, n int) *bulkTestEnv {
	t.Helper()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk")
	env := &bulkTestEnv{mgr: mgr, root: root}
	for i := 0; i < n; i++ {
		env.serials = append(env.serials, env.issue(t, fmt.Sprintf("bulk-%03d.example.com", i), "server"))
	}
	return env
}

func (e *bulkTestEnv) issue(t *testing.T, cn, profile string) string {
	t.Helper()
	res, err := e.mgr.IssueCertificate(context.Background(), IssueSpec{
		CAID:    e.root.ID,
		CSRPEM:  makeCSR(t, cn, []string{cn}),
		Profile: profile,
	})
	if err != nil {
		t.Fatalf("issuing %s: %v", cn, err)
	}
	return res.Serial.String()
}

func countBulkEvents(t *testing.T, db *database.DB, action, detailSub string) int {
	t.Helper()
	events, _, err := db.ListEvents(action, "", "", 100000, 0)
	if err != nil {
		t.Fatalf("ListEvents(%s): %v", action, err)
	}
	n := 0
	for _, e := range events {
		if detailSub == "" || strings.Contains(e.Detail, detailSub) {
			n++
		}
	}
	return n
}

func TestBulkRevokePreviewFilters(t *testing.T) {
	env := setupBulkEnv(t, 4) // bulk-000 .. bulk-003, profile "server"
	env.issue(t, "client-a.internal", "client")
	env.issue(t, "client-b.internal", "client")
	ctx := context.Background()
	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{})

	// Zero filter selects everything not yet revoked.
	plan, err := b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if plan.Total != 6 || plan.Known != 6 || plan.Unknown != 0 {
		t.Errorf("zero-filter plan = total %d known %d unknown %d, want 6/6/0", plan.Total, plan.Known, plan.Unknown)
	}
	if plan.OperationID == "" || plan.Filter != "all" {
		t.Errorf("plan metadata: op=%q filter=%q", plan.OperationID, plan.Filter)
	}
	if len(plan.Sample) != 6 {
		t.Errorf("sample = %d entries, want 6", len(plan.Sample))
	}

	// Profile filter.
	plan, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Profile: "client"}})
	if err != nil || plan.Total != 2 {
		t.Errorf("profile plan total = %d (%v), want 2", plan.Total, err)
	}

	// Pattern filter (case-insensitive glob over CN/SANs).
	plan, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Pattern: "*.INTERNAL"}})
	if err != nil || plan.Total != 2 {
		t.Errorf("pattern plan total = %d (%v), want 2", plan.Total, err)
	}
	if _, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Pattern: "[bad"}}); err == nil {
		t.Error("malformed pattern accepted")
	}

	// Serial list: one matching, one already revoked, one filtered out by
	// profile, one unknown to the inventory.
	if _, err := env.mgr.RevokeCertificate(ctx, env.root.ID, env.serials[0], "superseded"); err != nil {
		t.Fatal(err)
	}
	clientPlan, err := b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Profile: "client"}})
	if err != nil {
		t.Fatal(err)
	}
	clientSerial := clientPlan.Sample[0].Serial
	plan, err = b.Preview(ctx, BulkRevokeSpec{
		CAID: env.root.ID,
		Filter: BulkRevokeFilter{
			Profile: "server",
			Serials: []string{env.serials[1], env.serials[0], clientSerial, "424242"},
		},
	})
	if err != nil {
		t.Fatalf("serial-list preview: %v", err)
	}
	if plan.Known != 1 || plan.Unknown != 1 || plan.AlreadyRevoked != 1 || plan.FilteredOut != 1 || plan.Total != 2 {
		t.Errorf("serial-list plan = known %d unknown %d already %d filtered %d total %d, want 1/1/1/1/2",
			plan.Known, plan.Unknown, plan.AlreadyRevoked, plan.FilteredOut, plan.Total)
	}

	// Expired certificates are excluded (and counted) unless requested. The
	// expired row is planted directly in the store: issuance cannot mint one.
	now := time.Now()
	if err := env.mgr.db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID: "expired-row", CAID: env.root.ID, Serial: "77770001", CommonName: "old.example.com",
		Profile: "server", Certificate: "PEM",
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
		Status: models.CertStatusValid,
	}); err != nil {
		t.Fatal(err)
	}
	plan, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Pattern: "old.example.com"}})
	if err != nil || plan.Total != 0 || plan.ExpiredExcluded != 1 {
		t.Errorf("expired plan = total %d expired_excluded %d (%v), want 0/1", plan.Total, plan.ExpiredExcluded, err)
	}
	plan, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Pattern: "old.example.com", IncludeExpired: true}})
	if err != nil || plan.Total != 1 || plan.ExpiredExcluded != 0 {
		t.Errorf("include-expired plan = total %d expired_excluded %d (%v), want 1/0", plan.Total, plan.ExpiredExcluded, err)
	}

	// Bad inputs are rejected up front.
	if _, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Reason: "not-a-reason"}); err == nil {
		t.Error("unknown reason accepted")
	}
	if _, err = b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID, Filter: BulkRevokeFilter{Serials: []string{"0xzz"}}}); err == nil {
		t.Error("garbage serial accepted")
	}
}

func TestBulkRevokeExecuteEndToEnd(t *testing.T) {
	const n = 25
	env := setupBulkEnv(t, n)
	ctx := context.Background()

	// Live serving-layer caches: two demand-filled OCSP entries that must be
	// invalidated, and a presigner whose refresh must repopulate the cache.
	cache := NewOCSPCache(time.Hour)
	cache.Put(env.root.ID, env.serials[0], []byte("stale-good-0"))
	cache.Put(env.root.ID, env.serials[1], []byte("stale-good-1"))
	presigner := NewOCSPPresigner(env.mgr, OCSPPresignerConfig{Cache: cache})
	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{Cache: cache, Presigner: presigner})

	var progress []int
	spec := BulkRevokeSpec{
		CAID:         env.root.ID,
		Reason:       "keyCompromise",
		RequestedBy:  "ir-operator",
		BatchSize:    10,
		ConfirmCount: n,
		Progress:     func(done, total int) { progress = append(progress, done) },
	}
	result, err := b.Execute(ctx, spec)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if result.Revoked != n || result.Planned != n || result.AlreadySkipped != 0 {
		t.Errorf("result = revoked %d planned %d skipped %d, want %d/%d/0", result.Revoked, result.Planned, result.AlreadySkipped, n, n)
	}
	if result.Batches != 3 || len(progress) != 3 || progress[2] != n {
		t.Errorf("batches = %d progress %v, want 3 batches ending at %d", result.Batches, progress, n)
	}
	if result.OCSPInvalidated != n {
		t.Errorf("OCSP invalidations = %d, want %d", result.OCSPInvalidated, n)
	}
	if len(result.CRLScopes) != 1 || result.CRLScopes[0] != "full" {
		t.Errorf("CRL scopes = %v, want [full]", result.CRLScopes)
	}
	if result.PresignRefreshed != n {
		t.Errorf("presign refreshed = %d, want %d", result.PresignRefreshed, n)
	}
	if result.Duration <= 0 || result.DurationSecs <= 0 {
		t.Errorf("duration not recorded: %v / %v", result.Duration, result.DurationSecs)
	}

	// Store state: everything revoked with the keyCompromise reason.
	revoked, err := env.mgr.db.ListRevokedCertificates(env.root.ID)
	if err != nil || len(revoked) != n {
		t.Fatalf("revocation rows = %d (%v), want %d", len(revoked), err, n)
	}
	for _, rc := range revoked {
		if rc.Reason != 1 {
			t.Errorf("serial %s reason = %d, want 1 (keyCompromise)", rc.Serial, rc.Reason)
		}
	}

	// The demand-filled "good" answers are gone; the refreshed pre-signed set
	// is servable again with the revoked statuses.
	if der, hit := cache.Get(env.root.ID, env.serials[0]); hit && string(der) == "stale-good-0" {
		t.Error("stale cached OCSP response survived the bulk revocation")
	}
	if got := cache.PresignedCount(); got != n {
		t.Errorf("pre-signed cache entries = %d, want %d", got, n)
	}

	// Exactly one published base CRL regeneration carrying all serials, plus a
	// delta referencing it.
	base, err := env.mgr.db.GetPublishedCRL(env.root.ID, "full", "base")
	if err != nil || base == nil {
		t.Fatalf("published base CRL missing: %v", err)
	}
	crl, err := x509.ParseRevocationList(base.DER)
	if err != nil {
		t.Fatalf("parsing base CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != n {
		t.Errorf("base CRL entries = %d, want %d", len(crl.RevokedCertificateEntries), n)
	}
	delta, err := env.mgr.db.GetPublishedCRL(env.root.ID, "full", "delta")
	if err != nil || delta == nil {
		t.Fatalf("published delta CRL missing: %v", err)
	}
	if delta.BaseNumber != base.Number {
		t.Errorf("delta references base %d, want %d", delta.BaseNumber, base.Number)
	}

	// Audit trail: one cert.revoke per certificate tagged with the operation,
	// plus exactly one summary event; the CRL publishes are audited too.
	opTag := "bulk_op=" + result.OperationID
	if got := countBulkEvents(t, env.mgr.db, audit.ActionCertRevoke, opTag); got != n {
		t.Errorf("per-certificate audit events = %d, want %d", got, n)
	}
	if got := countBulkEvents(t, env.mgr.db, audit.ActionCertRevokeBulk, "op="+result.OperationID); got != 1 {
		t.Errorf("summary audit events = %d, want 1", got)
	}
	events, _, _ := env.mgr.db.ListEvents(audit.ActionCertRevokeBulk, "", "", 10, 0)
	if len(events) != 1 || events[0].Actor != "ir-operator" || events[0].Result != audit.ResultSuccess {
		t.Errorf("summary event = %+v", events)
	}
	if !strings.Contains(events[0].Detail, fmt.Sprintf("revoked=%d", n)) {
		t.Errorf("summary detail missing counts: %s", events[0].Detail)
	}

	// Re-running the exact spec is a no-op success (idempotent completion).
	spec.ConfirmCount = 0
	rerun, err := b.Execute(ctx, spec)
	if err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	if rerun.Revoked != 0 || rerun.Planned != 0 {
		t.Errorf("re-run revoked %d planned %d, want 0/0", rerun.Revoked, rerun.Planned)
	}
	if got := countBulkEvents(t, env.mgr.db, audit.ActionCertRevoke, opTag); got != n {
		t.Errorf("per-certificate events after re-run = %d, want still %d", got, n)
	}
}

func TestBulkRevokeShardedCRLRegeneration(t *testing.T) {
	SetCRLConfig(CRLDistConfig{Shards: 4})
	t.Cleanup(func() { SetCRLConfig(CRLDistConfig{}) })

	env := setupBulkEnv(t, 12)
	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{})
	result, err := b.Execute(context.Background(), BulkRevokeSpec{
		CAID: env.root.ID, Reason: "keyCompromise", ConfirmCount: -1,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Revoked != 12 {
		t.Fatalf("revoked = %d, want 12", result.Revoked)
	}
	// The full scope is always regenerated; with 12 random serials over 4
	// shards, at least one partition must be affected as well.
	if result.CRLScopes[0] != "full" || len(result.CRLScopes) < 2 {
		t.Fatalf("CRL scopes = %v, want full plus affected partitions", result.CRLScopes)
	}
	for _, scope := range result.CRLScopes[1:] {
		base, err := env.mgr.db.GetPublishedCRL(env.root.ID, scope, "base")
		if err != nil || base == nil {
			t.Errorf("published base CRL for %s missing: %v", scope, err)
			continue
		}
		delta, err := env.mgr.db.GetPublishedCRL(env.root.ID, scope, "delta")
		if err != nil || delta == nil || delta.BaseNumber != base.Number {
			t.Errorf("published delta CRL for %s missing or inconsistent: %+v (%v)", scope, delta, err)
		}
	}
}

func TestBulkRevokeCountMismatch(t *testing.T) {
	env := setupBulkEnv(t, 3)
	ctx := context.Background()
	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{})

	plan, err := b.Preview(ctx, BulkRevokeSpec{CAID: env.root.ID})
	if err != nil || plan.Total != 3 {
		t.Fatalf("preview: %v total=%d", err, plan.Total)
	}

	// A certificate is issued between the dry run and the confirmation.
	env.issue(t, "late.example.com", "server")

	_, err = b.Execute(ctx, BulkRevokeSpec{CAID: env.root.ID, ConfirmCount: plan.Total})
	var mismatch *BulkCountMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want BulkCountMismatchError", err)
	}
	if mismatch.Confirmed != 3 || mismatch.Actual != 4 {
		t.Errorf("mismatch = %+v, want confirmed 3 actual 4", mismatch)
	}
	// Nothing was revoked by the refused attempt.
	if revoked, _ := env.mgr.db.ListRevokedCertificates(env.root.ID); len(revoked) != 0 {
		t.Errorf("refused execution still revoked %d certificates", len(revoked))
	}
	// The fresh count executes.
	if result, err := b.Execute(ctx, BulkRevokeSpec{CAID: env.root.ID, ConfirmCount: mismatch.Actual}); err != nil || result.Revoked != 4 {
		t.Errorf("confirmed re-run: %v, revoked=%d", err, result.Revoked)
	}
}

func TestBulkRevokeResumeAfterInterruption(t *testing.T) {
	const n = 20
	env := setupBulkEnv(t, n)
	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{})

	// Cancel after the first batch lands: the second loop iteration sees the
	// canceled context and stops with a resumable error.
	ctx, cancel := context.WithCancel(context.Background())
	spec := BulkRevokeSpec{
		CAID:         env.root.ID,
		Reason:       "keyCompromise",
		OperationID:  "op-interrupted",
		BatchSize:    5,
		ConfirmCount: -1,
		Progress:     func(done, total int) { cancel() },
	}
	result, err := b.Execute(ctx, spec)
	if err == nil {
		t.Fatal("interrupted run reported success")
	}
	if result == nil || result.Revoked != 5 {
		t.Fatalf("interrupted result = %+v, want 5 revoked", result)
	}
	if !strings.Contains(err.Error(), "re-run to resume") {
		t.Errorf("interruption error not resumable-worded: %v", err)
	}
	// The interrupted run recorded an error summary.
	if got := countBulkEvents(t, env.mgr.db, audit.ActionCertRevokeBulk, "op=op-interrupted"); got != 1 {
		t.Errorf("interrupted summary events = %d, want 1", got)
	}

	// Resume: same spec, fresh context. Only the remainder is revoked.
	spec.Progress = nil
	resumed, err := b.Execute(context.Background(), spec)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Revoked != n-5 || resumed.Planned != n-5 {
		t.Errorf("resume revoked %d planned %d, want %d/%d", resumed.Revoked, resumed.Planned, n-5, n-5)
	}
	if revoked, _ := env.mgr.db.ListRevokedCertificates(env.root.ID); len(revoked) != n {
		t.Errorf("total revoked after resume = %d, want %d", len(revoked), n)
	}
	// No certificate was audited twice across the interrupted + resumed runs.
	if got := countBulkEvents(t, env.mgr.db, audit.ActionCertRevoke, "bulk_op=op-interrupted"); got != n {
		t.Errorf("per-certificate events across both runs = %d, want exactly %d", got, n)
	}
}

// TestBulkRevokeSuspendedTenant: revocation is an incident-response path and
// must work for a suspended tenant (whose issuance is refused).
func TestBulkRevokeSuspendedTenant(t *testing.T) {
	env := setupBulkEnv(t, 2)
	ctx := context.Background()

	if err := env.mgr.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.mgr.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusActive) })

	// Sanity: issuance is refused while suspended.
	if _, err := env.mgr.IssueCertificate(ctx, IssueSpec{
		CAID: env.root.ID, CSRPEM: makeCSR(t, "nope.example.com", nil), Profile: "server",
	}); err == nil {
		t.Fatal("suspended tenant could still issue")
	}

	b := NewBulkRevoker(env.mgr, BulkRevokerConfig{})
	result, err := b.Execute(ctx, BulkRevokeSpec{CAID: env.root.ID, Reason: "keyCompromise", ConfirmCount: 2})
	if err != nil {
		t.Fatalf("bulk revocation under suspension failed: %v", err)
	}
	if result.Revoked != 2 {
		t.Errorf("revoked = %d, want 2", result.Revoked)
	}
	// Usage accounting still recorded the revocations.
	day, err := env.mgr.db.GetTenantUsageDay(models.DefaultTenantID, database.UsageDay(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if day.CertsRevoked < 2 {
		t.Errorf("tenant usage certs_revoked = %d, want >= 2", day.CertsRevoked)
	}
}
