//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func approvalTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkApproval(id, class, fingerprint, requester string) *models.PendingApproval {
	now := time.Now().UTC()
	return &models.PendingApproval{
		ID:                id,
		TenantID:          models.DefaultTenantID,
		OperationClass:    class,
		ResourceKey:       "ca:1",
		Fingerprint:       fingerprint,
		Summary:           "rotate ca:1",
		RequestedBy:       requester,
		RequiredApprovals: 2,
		Status:            "pending",
		CreatedAt:         now,
		ExpiresAt:         now.Add(72 * time.Hour),
	}
}

// TestApprovalCRUD covers insert, fetch (with populated approvals_count),
// open-request lookup by fingerprint, and status filtering.
func TestApprovalCRUD(t *testing.T) {
	db := approvalTestDB(t)

	pa := mkApproval("apr_1", "ca.rotate", "fp-1", "alice")
	if err := db.CreatePendingApproval(pa); err != nil {
		t.Fatalf("CreatePendingApproval: %v", err)
	}

	got, err := db.GetPendingApproval("apr_1")
	if err != nil || got == nil {
		t.Fatalf("GetPendingApproval: %v, %v", got, err)
	}
	if got.OperationClass != "ca.rotate" || got.RequiredApprovals != 2 || got.ApprovalsCount != 0 {
		t.Fatalf("unexpected row: %+v", got)
	}
	if got.Status != "pending" || got.ExecutedAt != nil {
		t.Fatalf("unexpected state: %+v", got)
	}

	// A missing id is (nil, nil), not an error.
	if miss, err := db.GetPendingApproval("nope"); err != nil || miss != nil {
		t.Fatalf("missing GetPendingApproval = %v, %v", miss, err)
	}

	// FindOpenApproval matches by (tenant, class, fingerprint).
	open, err := db.FindOpenApproval(models.DefaultTenantID, "ca.rotate", "fp-1")
	if err != nil || open == nil || open.ID != "apr_1" {
		t.Fatalf("FindOpenApproval = %v, %v", open, err)
	}
	if none, err := db.FindOpenApproval(models.DefaultTenantID, "ca.rotate", "other-fp"); err != nil || none != nil {
		t.Fatalf("FindOpenApproval(unknown) = %v, %v", none, err)
	}

	// List filters.
	if list, err := db.ListPendingApprovals("", "pending", "", 0); err != nil || len(list) != 1 {
		t.Fatalf("ListPendingApprovals(pending) = %d, %v", len(list), err)
	}
	if list, err := db.ListPendingApprovals("", "approved", "", 0); err != nil || len(list) != 0 {
		t.Fatalf("ListPendingApprovals(approved) = %d, %v", len(list), err)
	}
}

// TestApprovalDecisionsDistinct covers the UNIQUE(approval_id, approver)
// constraint — the mechanism enforcing "N distinct approvers".
func TestApprovalDecisionsDistinct(t *testing.T) {
	db := approvalTestDB(t)
	if err := db.CreatePendingApproval(mkApproval("apr_1", "ca.rotate", "fp-1", "alice")); err != nil {
		t.Fatal(err)
	}

	ins, err := db.AddApprovalDecision(&models.ApprovalDecision{ApprovalID: "apr_1", Approver: "bob", Decision: "approve"})
	if err != nil || !ins {
		t.Fatalf("first decision insert = %v, %v", ins, err)
	}
	// The same approver again is a no-op insert (distinct constraint).
	ins, err = db.AddApprovalDecision(&models.ApprovalDecision{ApprovalID: "apr_1", Approver: "bob", Decision: "approve"})
	if err != nil || ins {
		t.Fatalf("duplicate decision must not insert, got inserted=%v err=%v", ins, err)
	}
	// A different approver does insert.
	ins, err = db.AddApprovalDecision(&models.ApprovalDecision{ApprovalID: "apr_1", Approver: "carol", Decision: "approve"})
	if err != nil || !ins {
		t.Fatalf("distinct decision insert = %v, %v", ins, err)
	}

	if n, err := db.CountApprovalDecisions("apr_1", "approve"); err != nil || n != 2 {
		t.Fatalf("CountApprovalDecisions = %d, %v (want 2)", n, err)
	}

	// The count is reflected in the fetched row and its decision log.
	got, _ := db.GetPendingApproval("apr_1")
	if got.ApprovalsCount != 2 || len(got.Decisions) != 2 {
		t.Fatalf("row count/decisions = %d/%d (want 2/2)", got.ApprovalsCount, len(got.Decisions))
	}
}

// TestApprovalStatusOptimistic covers the conditional status transition: it
// applies only from the expected prior status and stamps decided_at/executed_at.
func TestApprovalStatusOptimistic(t *testing.T) {
	db := approvalTestDB(t)
	if err := db.CreatePendingApproval(mkApproval("apr_1", "ca.rotate", "fp-1", "alice")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	// Wrong prior status: no-op.
	if ok, err := db.SetApprovalStatus("apr_1", "approved", "executed", now); err != nil || ok {
		t.Fatalf("transition from wrong status must be a no-op, got ok=%v err=%v", ok, err)
	}
	// Correct prior status: applies and stamps decided_at.
	if ok, err := db.SetApprovalStatus("apr_1", "pending", "approved", now); err != nil || !ok {
		t.Fatalf("pending->approved = %v, %v", ok, err)
	}
	got, _ := db.GetPendingApproval("apr_1")
	if got.Status != "approved" || got.DecidedAt == nil {
		t.Fatalf("approved row = %+v", got)
	}
	// Consume: approved->executed stamps executed_at, and is a one-shot.
	if ok, err := db.SetApprovalStatus("apr_1", "approved", "executed", now); err != nil || !ok {
		t.Fatalf("approved->executed = %v, %v", ok, err)
	}
	if ok, _ := db.SetApprovalStatus("apr_1", "approved", "executed", now); ok {
		t.Fatal("a second consume must not apply (already executed)")
	}
	got, _ = db.GetPendingApproval("apr_1")
	if got.Status != "executed" || got.ExecutedAt == nil {
		t.Fatalf("executed row = %+v", got)
	}
}

// TestApprovalExpirable covers the expiry work-list query used by the sweep.
func TestApprovalExpirable(t *testing.T) {
	db := approvalTestDB(t)
	now := time.Now().UTC()

	fresh := mkApproval("apr_fresh", "ca.rotate", "fp-fresh", "alice")
	fresh.ExpiresAt = now.Add(time.Hour)
	stale := mkApproval("apr_stale", "ca.rotate", "fp-stale", "alice")
	stale.ExpiresAt = now.Add(-time.Hour)
	done := mkApproval("apr_done", "ca.rotate", "fp-done", "alice")
	done.ExpiresAt = now.Add(-time.Hour)
	done.Status = "executed" // terminal: not expirable even though past its window
	for _, pa := range []*models.PendingApproval{fresh, stale, done} {
		if err := db.CreatePendingApproval(pa); err != nil {
			t.Fatal(err)
		}
	}

	list, err := db.ListExpirableApprovals(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "apr_stale" {
		t.Fatalf("ListExpirableApprovals = %+v (want only apr_stale)", list)
	}
}
