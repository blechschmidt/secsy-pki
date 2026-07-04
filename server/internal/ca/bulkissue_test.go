//go:build sqlite

package ca

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 101 engine tests: batch issuance with per-item results and partial
// success, the confirm-count guard, dry-run preview, bounded-concurrency
// correctness (unique serials, all recorded), tenant-quota partial exhaustion,
// the manual-approval-gate parking hook, and per-item + summary audit events.

// bulkIssueItems builds n server-profile items with refs r0..r(n-1).
func bulkIssueItems(t *testing.T, n int) []BulkIssueItem {
	t.Helper()
	items := make([]BulkIssueItem, n)
	for i := 0; i < n; i++ {
		cn := fmt.Sprintf("dev-%03d.example.com", i)
		items[i] = BulkIssueItem{
			Ref:     fmt.Sprintf("r%d", i),
			CSRPEM:  makeCSR(t, cn, []string{cn}),
			Profile: "server",
		}
	}
	return items
}

func countEventsByDetail(t *testing.T, m *Manager, action, detailSub string) int {
	t.Helper()
	events, _, err := m.db.ListEvents(action, "", "", 100000, 0)
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

// TestBulkIssueAllSucceed: a clean batch issues every item, with unique serials,
// recorded certificates, one cert.issue event per item, and one summary event.
func TestBulkIssueAllSucceed(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-issue")
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})

	const n = 12
	confirm := n
	result, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID:         root.ID,
		Items:        bulkIssueItems(t, n),
		RequestedBy:  "tester",
		ConfirmCount: confirm,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Requested != n || result.Issued != n || result.Failed != 0 || result.Pending != 0 {
		t.Fatalf("result = requested %d issued %d failed %d pending %d, want %d/%d/0/0",
			result.Requested, result.Issued, result.Failed, result.Pending, n, n)
	}
	// Serials unique and results in request order.
	seen := map[string]bool{}
	for i, it := range result.Items {
		if it.Status != BulkIssueStatusIssued {
			t.Errorf("item %d status = %s, want issued", i, it.Status)
		}
		if it.Ref != fmt.Sprintf("r%d", i) {
			t.Errorf("item %d ref = %q, want r%d (order not preserved)", i, it.Ref, i)
		}
		if it.Serial == "" || seen[it.Serial] {
			t.Errorf("item %d serial %q empty or duplicate", i, it.Serial)
		}
		seen[it.Serial] = true
		if it.Certificate == "" || it.Chain == "" {
			t.Errorf("item %d missing certificate/chain PEM", i)
		}
	}
	// All recorded in inventory (root self-cert + n leaves).
	certs, _ := mgr.db.ListIssuedCertificates(root.ID)
	if len(certs) != n {
		t.Errorf("recorded certificates = %d, want %d", len(certs), n)
	}
	// One cert.issue per item, tied to the operation, plus one summary event.
	if got := countEventsByDetail(t, mgr, audit.ActionCertIssue, "bulk_op="+result.OperationID); got != n {
		t.Errorf("cert.issue events for op = %d, want %d", got, n)
	}
	if got := countEventsByDetail(t, mgr, audit.ActionCertIssueBulk, "op="+result.OperationID); got != 1 {
		t.Errorf("cert.issue_bulk summary events = %d, want 1", got)
	}
}

// TestBulkIssuePartialFailure: malformed items fail with a structured error while
// the well-formed items in the same batch still issue.
func TestBulkIssuePartialFailure(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-partial")
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})

	items := []BulkIssueItem{
		{Ref: "good-1", CSRPEM: makeCSR(t, "good-1.example.com", []string{"good-1.example.com"}), Profile: "server"},
		{Ref: "bad-csr", CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n-----END CERTIFICATE REQUEST-----"), Profile: "server"},
		{Ref: "good-2", CSRPEM: makeCSR(t, "good-2.example.com", []string{"good-2.example.com"}), Profile: "server"},
		{Ref: "bad-profile", CSRPEM: makeCSR(t, "x.example.com", []string{"x.example.com"}), Profile: "no-such-profile"},
	}
	confirm := len(items)
	result, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID: root.ID, Items: items, RequestedBy: "tester", ConfirmCount: confirm,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Issued != 2 || result.Failed != 2 {
		t.Fatalf("result = issued %d failed %d, want 2/2", result.Issued, result.Failed)
	}
	byRef := map[string]BulkIssueItemResult{}
	for _, it := range result.Items {
		byRef[it.Ref] = it
	}
	if byRef["good-1"].Status != BulkIssueStatusIssued || byRef["good-2"].Status != BulkIssueStatusIssued {
		t.Errorf("good items not issued: %+v %+v", byRef["good-1"], byRef["good-2"])
	}
	for _, ref := range []string{"bad-csr", "bad-profile"} {
		it := byRef[ref]
		if it.Status != BulkIssueStatusFailed || it.Error == "" {
			t.Errorf("%s status = %s error = %q, want failed with error", ref, it.Status, it.Error)
		}
		if it.ErrorCode != BulkIssueCodeIssuanceError {
			t.Errorf("%s error_code = %q, want %s", ref, it.ErrorCode, BulkIssueCodeIssuanceError)
		}
	}
	// Exactly the two good leaves are recorded.
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 2 {
		t.Errorf("recorded certificates = %d, want 2", len(certs))
	}
}

// TestBulkIssueConfirmCountMismatch: a wrong confirm count aborts before any
// issuance.
func TestBulkIssueConfirmCountMismatch(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-confirm")
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})

	_, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID: root.ID, Items: bulkIssueItems(t, 3), RequestedBy: "tester", ConfirmCount: 5,
	})
	var mismatch *BulkIssueCountMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *BulkIssueCountMismatchError", err)
	}
	if mismatch.Confirmed != 5 || mismatch.Actual != 3 {
		t.Errorf("mismatch = confirmed %d actual %d, want 5/3", mismatch.Confirmed, mismatch.Actual)
	}
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 0 {
		t.Errorf("count mismatch must not issue anything, got %d certificates", len(certs))
	}
}

// TestBulkIssuePreview: the dry run validates each item and reports valid/invalid
// (and which profiles require approval) without issuing anything.
func TestBulkIssuePreview(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-preview")
	if err := SetCustomProfiles([]Profile{{
		Name: "gated", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
		DefaultValidityDays: 90, MaxValidityDays: 90, RequireApproval: true,
	}}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { SetCustomProfiles(nil) })
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})

	items := []BulkIssueItem{
		{Ref: "ok", CSRPEM: makeCSR(t, "ok.example.com", []string{"ok.example.com"}), Profile: "server"},
		{Ref: "gated", CSRPEM: makeCSR(t, "g.example.com", []string{"g.example.com"}), Profile: "gated"},
		{Ref: "bad", CSRPEM: []byte("garbage"), Profile: "server"},
	}
	plan, err := b.Preview(context.Background(), BulkIssueSpec{CAID: root.ID, Items: items})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if plan.Requested != 3 || plan.Valid != 2 || plan.Invalid != 1 || plan.NeedApproval != 1 {
		t.Errorf("plan = requested %d valid %d invalid %d need_approval %d, want 3/2/1/1",
			plan.Requested, plan.Valid, plan.Invalid, plan.NeedApproval)
	}
	if !plan.Items[1].RequiresApproval {
		t.Errorf("gated item RequiresApproval = false, want true")
	}
	if plan.Items[2].Valid || plan.Items[2].Error == "" {
		t.Errorf("bad item = %+v, want invalid with error", plan.Items[2])
	}
	// Nothing issued.
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 0 {
		t.Errorf("preview must not issue, got %d certificates", len(certs))
	}
}

// TestBulkIssueQuotaPartialExhaustion: with a tenant daily quota below the batch
// size, the first items issue and the rest fail with quota_exceeded — partial
// success, not a whole-batch abort.
func TestBulkIssueQuotaPartialExhaustion(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	tn := &models.Tenant{
		ID: "qt", Slug: "qt", Name: "qt", Status: models.TenantStatusActive,
		Quotas: models.TenantQuotas{MaxCertsPerDay: 3},
	}
	if err := mgr.db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	root, err := mgr.InitRoot(context.Background(), RootSpec{
		TenantID: tn.ID, Label: uniqueLabel(t, "qt-root"), KeyType: "ecdsa-p256",
		Subject: PKIXName(models.CASubject{CommonName: "Quota Bulk Root"}), Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	// Serialize so exactly the first 3 win the quota (concurrency races would
	// still leave 3 issued, but 1 worker makes the assertion exact).
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})
	result, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID: root.ID, Items: bulkIssueItems(t, 5), RequestedBy: "tester",
		ConfirmCount: 5, Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Issued != 3 || result.Failed != 2 {
		t.Fatalf("result = issued %d failed %d, want 3/2 (quota=3)", result.Issued, result.Failed)
	}
	quotaFails := 0
	for _, it := range result.Items {
		if it.Status == BulkIssueStatusFailed {
			if it.ErrorCode != BulkIssueCodeQuotaExceeded {
				t.Errorf("failed item %s code = %q, want %s", it.Ref, it.ErrorCode, BulkIssueCodeQuotaExceeded)
			}
			quotaFails++
		}
	}
	if quotaFails != 2 {
		t.Errorf("quota_exceeded failures = %d, want 2", quotaFails)
	}
}

// TestBulkIssueApprovalGateParks: a gate hook that holds an item reports it
// "pending" (never issued) while the ungated items in the batch issue.
func TestBulkIssueApprovalGateParks(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-gate")

	// Simulated approval gate: profile "hold" parks; a malformed CSR under it is a
	// client error; everything else is ungated.
	gate := func(ctx context.Context, item BulkIssueItem) (BulkIssueGateResult, error, error) {
		if item.Profile != "hold" {
			return BulkIssueGateResult{Gated: false}, nil, nil
		}
		if _, err := InspectCSRForIssue(item.CSRPEM); err != nil {
			return BulkIssueGateResult{}, err, nil // client error
		}
		return BulkIssueGateResult{Gated: true, ApprovalID: "appr-" + item.Ref, RequiredApprovals: 2}, nil, nil
	}
	b := NewBulkIssuer(mgr, BulkIssuerConfig{ApprovalGate: gate})

	items := []BulkIssueItem{
		{Ref: "issue-me", CSRPEM: makeCSR(t, "a.example.com", []string{"a.example.com"}), Profile: "server"},
		{Ref: "hold-me", CSRPEM: makeCSR(t, "b.example.com", []string{"b.example.com"}), Profile: "hold"},
		{Ref: "hold-bad", CSRPEM: []byte("garbage"), Profile: "hold"},
	}
	result, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID: root.ID, Items: items, RequestedBy: "tester", ConfirmCount: 3,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Issued != 1 || result.Pending != 1 || result.Failed != 1 {
		t.Fatalf("result = issued %d pending %d failed %d, want 1/1/1",
			result.Issued, result.Pending, result.Failed)
	}
	byRef := map[string]BulkIssueItemResult{}
	for _, it := range result.Items {
		byRef[it.Ref] = it
	}
	if p := byRef["hold-me"]; p.Status != BulkIssueStatusPending || p.ApprovalID != "appr-hold-me" || p.RequiredApprovals != 2 {
		t.Errorf("hold-me = %+v, want pending appr-hold-me/2", p)
	}
	if f := byRef["hold-bad"]; f.Status != BulkIssueStatusFailed || f.ErrorCode != BulkIssueCodeInvalidRequest {
		t.Errorf("hold-bad = %+v, want failed/invalid_request", f)
	}
	// The parked item never issued: only the one ungated leaf is recorded.
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 1 {
		t.Errorf("recorded certificates = %d, want 1 (parked item must not issue)", len(certs))
	}
}

// TestBulkIssueConcurrencyUniqueSerials stress-issues a larger batch with real
// concurrency and asserts every item issued with a distinct serial — the
// bounded worker pool must not corrupt serial allocation or the store.
func TestBulkIssueConcurrencyUniqueSerials(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-conc")
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})

	const n = 40
	result, err := b.Execute(context.Background(), BulkIssueSpec{
		CAID: root.ID, Items: bulkIssueItems(t, n), RequestedBy: "tester",
		ConfirmCount: n, Concurrency: 16,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Issued != n {
		t.Fatalf("issued = %d, want %d", result.Issued, n)
	}
	serials := map[string]bool{}
	for _, it := range result.Items {
		if it.Status != BulkIssueStatusIssued {
			t.Fatalf("item %s status = %s, want issued", it.Ref, it.Status)
		}
		if serials[it.Serial] {
			t.Fatalf("duplicate serial %s under concurrency", it.Serial)
		}
		serials[it.Serial] = true
	}
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != n {
		t.Errorf("recorded = %d, want %d", len(certs), n)
	}
}

// TestBulkIssueEmptyBatchRejected: an empty batch is a whole-operation error.
func TestBulkIssueEmptyBatchRejected(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "bulk-empty")
	b := NewBulkIssuer(mgr, BulkIssuerConfig{})
	if _, err := b.Execute(context.Background(), BulkIssueSpec{CAID: root.ID, ConfirmCount: 0}); err == nil {
		t.Fatal("empty batch accepted, want error")
	}
}
