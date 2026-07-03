//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// installApprovals attaches a threshold-2 four-eyes gate to the API under test.
func installApprovals(api *API, db *database.DB) {
	api.SetApprovals(approval.NewEngine(db, db, approval.Policy{
		Enabled:          true,
		DefaultThreshold: 2,
		TTL:              72 * time.Hour,
	}))
}

func approverUser(sub string) *models.UserInfo {
	return &models.UserInfo{Subject: sub, Roles: []string{"approver"}}
}

func decideReq(t *testing.T, fn func(http.ResponseWriter, *http.Request), user *models.UserInfo, id, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	fn(rec, reqAs(http.MethodPost, "/api/approvals/"+id+"/"+path, user, id, `{"comment":"ok"}`))
	return rec
}

// TestBulkRevokeGuardedByFourEyes is the headline end-to-end proof (Task 81): a
// guarded bulk revocation is BLOCKED (202, nothing revoked) until two DISTINCT
// approvers — neither of them the requester — sign off, after which re-running
// the operation executes. It also proves self-approval and repeat votes are
// refused.
func TestBulkRevokeGuardedByFourEyes(t *testing.T) {
	api, db := tenantAPI(t)
	installApprovals(api, db)
	_, root := quotaTenantWithRoot(t, api, db, "fe", models.TenantQuotas{})

	for i := 0; i < 3; i++ {
		if rec := issueVia(t, api, root.ID, fmt.Sprintf("fe-%d.example.com", i)); rec.Code != http.StatusCreated {
			t.Fatalf("seed issuance %d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	// Discover the live selection size via a dry run.
	dry := bulkRevokeReq(t, api, rootUser(), root.ID, `{"dry_run":true,"reason":"keyCompromise"}`)
	if dry.Code != http.StatusOK {
		t.Fatalf("dry run = %d: %s", dry.Code, dry.Body.String())
	}
	var plan struct {
		Total int `json:"total"`
	}
	json.Unmarshal(dry.Body.Bytes(), &plan)
	if plan.Total == 0 {
		t.Fatal("expected a non-empty selection to revoke")
	}
	body := fmt.Sprintf(`{"reason":"keyCompromise","confirm_count":%d}`, plan.Total)

	// First real attempt: HELD at the gate (202), nothing revoked.
	rec := bulkRevokeReq(t, api, rootUser(), root.ID, body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("guarded bulk revoke = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	id := rec.Header().Get("X-Secsy-Approval-Id")
	if id == "" {
		t.Fatal("expected an X-Secsy-Approval-Id header on the pending response")
	}
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != 0 {
		t.Fatalf("a blocked operation must not revoke anything, got %d", len(revoked))
	}

	// Self-approval by the requester (root) is refused.
	if rec := decideReq(t, api.ApproveApproval, rootUser(), id, "approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// First distinct approver: still short of the threshold.
	rec = decideReq(t, api.ApproveApproval, approverUser("bob"), id, "approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("bob approve = %d: %s", rec.Code, rec.Body.String())
	}
	var afterBob models.PendingApproval
	json.Unmarshal(rec.Body.Bytes(), &afterBob)
	if afterBob.Status != approval.StatusPending || afterBob.ApprovalsCount != 1 {
		t.Fatalf("after one approval want pending 1/2, got %s %d", afterBob.Status, afterBob.ApprovalsCount)
	}

	// Still blocked at 1 of 2.
	if rec := bulkRevokeReq(t, api, rootUser(), root.ID, body); rec.Code != http.StatusAccepted {
		t.Fatalf("still-pending bulk revoke = %d, want 202", rec.Code)
	}

	// A repeat vote by bob is refused (distinct-approver rule).
	if rec := decideReq(t, api.ApproveApproval, approverUser("bob"), id, "approve"); rec.Code != http.StatusConflict {
		t.Fatalf("bob repeat approve = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}

	// Second distinct approver meets the threshold.
	rec = decideReq(t, api.ApproveApproval, approverUser("carol"), id, "approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("carol approve = %d: %s", rec.Code, rec.Body.String())
	}
	var afterCarol models.PendingApproval
	json.Unmarshal(rec.Body.Bytes(), &afterCarol)
	if afterCarol.Status != approval.StatusApproved {
		t.Fatalf("after two distinct approvals want approved, got %s", afterCarol.Status)
	}

	// Re-running the operation now executes: the certificates are revoked.
	rec = bulkRevokeReq(t, api, rootUser(), root.ID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("approved bulk revoke = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != plan.Total {
		t.Fatalf("after approval expected %d revoked, got %d", plan.Total, len(revoked))
	}

	// The consumed approval cannot authorize a second execution: a fresh attempt
	// is blocked again.
	if rec := bulkRevokeReq(t, api, rootUser(), root.ID, body); rec.Code != http.StatusAccepted {
		t.Fatalf("re-blocked bulk revoke = %d, want 202 (approval consumed)", rec.Code)
	}
}

// TestApprovalRBAC proves the approve/reject endpoints require the
// approval:approve capability and that reading requires approval:read.
func TestApprovalRBAC(t *testing.T) {
	api, db := tenantAPI(t)
	installApprovals(api, db)

	// Seed a request directly.
	pa := &models.PendingApproval{
		ID: "apr_rbac", TenantID: models.DefaultTenantID, OperationClass: approval.ClassCARotate,
		ResourceKey: "ca:1", Fingerprint: "fp", RequestedBy: "alice", RequiredApprovals: 2,
		Status: approval.StatusPending, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := db.CreatePendingApproval(pa); err != nil {
		t.Fatal(err)
	}

	// An issuer (no approval:approve) is refused.
	issuer := &models.UserInfo{Subject: "ivan", Roles: []string{"issuer"}}
	if rec := decideReq(t, api.ApproveApproval, issuer, "apr_rbac", "approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("issuer approve = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// An approver can approve.
	if rec := decideReq(t, api.ApproveApproval, approverUser("bob"), "apr_rbac", "approve"); rec.Code != http.StatusOK {
		t.Fatalf("approver approve = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// A plain authenticated principal with no role cannot even list.
	rec := httptest.NewRecorder()
	api.ListApprovals(rec, reqAs(http.MethodGet, "/api/approvals", &models.UserInfo{Subject: "nobody"}, "", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("roleless list = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// An auditor (approval:read) may list.
	rec = httptest.NewRecorder()
	api.ListApprovals(rec, reqAs(http.MethodGet, "/api/approvals", &models.UserInfo{Subject: "amy", Roles: []string{"auditor"}}, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("auditor list = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
