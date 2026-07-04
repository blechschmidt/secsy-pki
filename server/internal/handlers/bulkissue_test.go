//go:build sqlite

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 101 REST-surface tests for POST /api/ca/{id}/certificates:bulk: the
// happy path with per-item results, the confirm-count guard (required + 409 on
// mismatch), the dry-run plan, partial failure, tenant-quota partial
// exhaustion, the approval-gate parking a single item while the rest issue, and
// the authorization gate.

// bulkIssueReq builds a JSON body for a batch of (profile, cn) items.
func bulkIssueReq(t *testing.T, confirm *int, dryRun bool, items ...[2]string) string {
	t.Helper()
	req := models.BulkIssueRequest{DryRun: dryRun, ConfirmCount: confirm}
	for _, it := range items {
		req.Items = append(req.Items, models.BulkIssueItemRequest{
			Ref: it[1], CSR: issueCSR(t, it[1]), Profile: it[0],
		})
	}
	b, _ := json.Marshal(req)
	return string(b)
}

func intp(v int) *int { return &v }

func postBulkIssue(t *testing.T, api *API, user *models.UserInfo, caID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.BulkIssueCertificates(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/certificates:bulk", user, caID, body))
	return rec
}

// TestBulkIssueHappyPath: a confirmed batch issues every item and returns
// per-item results with serials, in request order.
func TestBulkIssueHappyPath(t *testing.T) {
	api, caID := approvalIssueAPI(t, false) // no approval engine
	body := bulkIssueReq(t, intp(3), false,
		[2]string{"server", "a.example.com"},
		[2]string{"server", "b.example.com"},
		[2]string{"server", "c.example.com"})

	rec := postBulkIssue(t, api, rootUser(), caID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var result ca.BulkIssueResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Requested != 3 || result.Issued != 3 || result.Failed != 0 {
		t.Fatalf("result = requested %d issued %d failed %d, want 3/3/0", result.Requested, result.Issued, result.Failed)
	}
	for i, it := range result.Items {
		if it.Status != ca.BulkIssueStatusIssued || it.Serial == "" || it.Certificate == "" {
			t.Errorf("item %d = %+v, want issued with serial+cert", i, it)
		}
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 3 {
		t.Errorf("recorded certificates = %d, want 3", len(certs))
	}
}

// TestBulkIssueConfirmCountContract: confirm_count is required on a real run and
// must equal the item count (409 on mismatch); a dry run needs neither.
func TestBulkIssueConfirmCountContract(t *testing.T) {
	api, caID := approvalIssueAPI(t, false)

	// Missing confirm_count on a real run -> 400.
	rec := postBulkIssue(t, api, rootUser(), caID, bulkIssueReq(t, nil, false, [2]string{"server", "x.example.com"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing confirm_count = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}

	// Wrong confirm_count -> 409 with the actual count.
	rec = postBulkIssue(t, api, rootUser(), caID, bulkIssueReq(t, intp(9), false,
		[2]string{"server", "y.example.com"}, [2]string{"server", "z.example.com"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("wrong confirm_count = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	var conflict map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &conflict)
	if conflict["actual_count"].(float64) != 2 {
		t.Errorf("409 actual_count = %v, want 2", conflict["actual_count"])
	}
	// Nothing issued by either rejected request.
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Errorf("no certificate must be issued on a rejected confirm, got %d", len(certs))
	}
}

// TestBulkIssueDryRun: a dry run validates each item and returns the plan
// without issuing anything.
func TestBulkIssueDryRun(t *testing.T) {
	api, caID := approvalIssueAPI(t, false)
	body := bulkIssueReq(t, nil, true,
		[2]string{"server", "ok.example.com"},
		[2]string{"no-such-profile", "bad.example.com"})

	rec := postBulkIssue(t, api, rootUser(), caID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var plan ca.BulkIssuePlan
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if plan.Requested != 2 || plan.Valid != 1 || plan.Invalid != 1 {
		t.Errorf("plan = requested %d valid %d invalid %d, want 2/1/1", plan.Requested, plan.Valid, plan.Invalid)
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Errorf("dry run must not issue, got %d certificates", len(certs))
	}
}

// TestBulkIssueApprovalGateParksItem: with the four-eyes engine enabled, an item
// under a require_approval profile is parked ("pending") while the ungated items
// issue; the parked item's certificate is delivered after approval.
func TestBulkIssueApprovalGateParksItem(t *testing.T) {
	api, caID := approvalIssueAPI(t, true) // engine on, "hi-assurance" require_approval

	body := bulkIssueReq(t, intp(3), false,
		[2]string{"server", "plain-1.example.com"},
		[2]string{"hi-assurance", "gated.example.com"},
		[2]string{"server", "plain-2.example.com"})

	rec := postBulkIssue(t, api, rootUser(), caID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var result ca.BulkIssueResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Issued != 2 || result.Pending != 1 || result.Failed != 0 {
		t.Fatalf("result = issued %d pending %d failed %d, want 2/1/0 (body=%s)",
			result.Issued, result.Pending, result.Failed, rec.Body.String())
	}
	var approvalID string
	for _, it := range result.Items {
		if it.Ref == "gated.example.com" {
			if it.Status != ca.BulkIssueStatusPending || it.ApprovalID == "" || it.RequiredApprovals != 2 {
				t.Fatalf("gated item = %+v, want pending with approval id and 2 approvers", it)
			}
			approvalID = it.ApprovalID
		}
	}
	// Only the two ungated leaves are issued so far; the parked one is not.
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 2 {
		t.Fatalf("recorded = %d, want 2 (parked item must not issue yet)", len(certs))
	}

	// Two distinct approvers unlock the parked item; the certificate then delivers.
	for _, who := range []string{"bob", "carol"} {
		arec := httptest.NewRecorder()
		api.ApproveApproval(arec, reqAs(http.MethodPost, "/api/approvals/"+approvalID+"/approve",
			tenantUser(who, models.DefaultTenantID, "approver"), approvalID, `{}`))
		if arec.Code != http.StatusOK {
			t.Fatalf("approve by %s = %d, want 200 (body=%s)", who, arec.Code, arec.Body.String())
		}
	}
	crec := httptest.NewRecorder()
	api.GetApprovalCertificate(crec, reqAs(http.MethodGet, "/api/approvals/"+approvalID+"/certificate", rootUser(), approvalID, ""))
	if crec.Code != http.StatusOK {
		t.Fatalf("fetch after approval = %d, want 200 (body=%s)", crec.Code, crec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 3 {
		t.Errorf("recorded after approval = %d, want 3", len(certs))
	}
}

// TestBulkIssueQuotaPartialExhaustion: a tenant daily quota below the batch size
// issues the first items and fails the rest with quota_exceeded — partial
// success, HTTP 200 (the per-item quota failures are not a whole-request 429).
func TestBulkIssueQuotaPartialExhaustion(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "bulkq", models.TenantQuotas{MaxCertsPerDay: 2})

	body := bulkIssueReq(t, intp(4), false,
		[2]string{"server", "q1.example.com"},
		[2]string{"server", "q2.example.com"},
		[2]string{"server", "q3.example.com"},
		[2]string{"server", "q4.example.com"})
	// Serialize so exactly the first two win the quota.
	var req models.BulkIssueRequest
	_ = json.Unmarshal([]byte(body), &req)
	req.Concurrency = 1
	b, _ := json.Marshal(req)

	rec := postBulkIssue(t, api, rootUser(), root.ID, string(b))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var result ca.BulkIssueResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Issued != 2 || result.Failed != 2 {
		t.Fatalf("result = issued %d failed %d, want 2/2 (quota=2)", result.Issued, result.Failed)
	}
	for _, it := range result.Items {
		if it.Status == ca.BulkIssueStatusFailed && it.ErrorCode != ca.BulkIssueCodeQuotaExceeded {
			t.Errorf("failed item %s code = %q, want quota_exceeded", it.Ref, it.ErrorCode)
		}
	}
}

// TestBulkIssueForbidden: a caller without the issue capability on the CA is
// refused before any issuance.
func TestBulkIssueForbidden(t *testing.T) {
	api, caID := approvalIssueAPI(t, false)
	readonly := tenantUser("readonly", models.DefaultTenantID, "auditor")

	rec := postBulkIssue(t, api, readonly, caID, bulkIssueReq(t, intp(1), false, [2]string{"server", "nope.example.com"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Errorf("forbidden request must not issue, got %d certificates", len(certs))
	}
}

// TestBulkIssueEmptyItems: an empty batch is a 400.
func TestBulkIssueEmptyItems(t *testing.T) {
	api, caID := approvalIssueAPI(t, false)
	rec := postBulkIssue(t, api, rootUser(), caID, `{"items":[],"confirm_count":0}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
