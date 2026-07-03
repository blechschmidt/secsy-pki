//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 70 REST-surface tests for POST /api/ca/{id}/revocations:bulk: the
// dry-run/confirm contract (400 without a count, 409 on drift, 200 on match)
// and the ca:manage RBAC gate with tenant isolation.

func bulkRevokeReq(t *testing.T, api *API, user *models.UserInfo, caID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.BulkRevokeCertificates(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/revocations:bulk", user, caID, body))
	return rec
}

func TestBulkRevokeHandlerDryRunConfirmExecute(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "bulkrev", models.TenantQuotas{})

	for i := 0; i < 3; i++ {
		if rec := issueVia(t, api, root.ID, fmt.Sprintf("bulk-%d.example.com", i)); rec.Code != http.StatusCreated {
			t.Fatalf("seed issuance %d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	// Dry run returns the plan without touching anything.
	rec := bulkRevokeReq(t, api, rootUser(), root.ID, `{"dry_run":true,"reason":"keyCompromise"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run = %d: %s", rec.Code, rec.Body.String())
	}
	var plan struct {
		OperationID string `json:"operation_id"`
		Total       int    `json:"total"`
		Known       int    `json:"known"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("plan JSON: %v", err)
	}
	if plan.Total != 3 || plan.Known != 3 || plan.OperationID == "" {
		t.Fatalf("plan = %+v, want total/known 3 with an operation id", plan)
	}
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != 0 {
		t.Fatalf("dry run revoked %d certificates", len(revoked))
	}

	// Execution without confirm_count is refused: the preview is mandatory.
	rec = bulkRevokeReq(t, api, rootUser(), root.ID, `{"reason":"keyCompromise"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "confirm_count") {
		t.Fatalf("no-confirm execution = %d: %s, want 400 naming confirm_count", rec.Code, rec.Body.String())
	}

	// A drifted count is refused with 409 and the fresh total.
	rec = bulkRevokeReq(t, api, rootUser(), root.ID, `{"reason":"keyCompromise","confirm_count":2}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("drifted confirm = %d: %s, want 409", rec.Code, rec.Body.String())
	}
	var conflict struct {
		ActualCount int `json:"actual_count"`
	}
	json.Unmarshal(rec.Body.Bytes(), &conflict)
	if conflict.ActualCount != 3 {
		t.Fatalf("conflict actual_count = %d, want 3", conflict.ActualCount)
	}
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != 0 {
		t.Fatalf("refused execution revoked %d certificates", len(revoked))
	}

	// The confirmed count executes and reports the result.
	rec = bulkRevokeReq(t, api, rootUser(), root.ID, `{"reason":"keyCompromise","confirm_count":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed execution = %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Revoked   int      `json:"revoked"`
		Batches   int      `json:"batches"`
		CRLScopes []string `json:"crl_scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	if result.Revoked != 3 || len(result.CRLScopes) == 0 {
		t.Fatalf("result = %+v, want 3 revoked with regenerated CRL scopes", result)
	}
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != 3 {
		t.Fatalf("store revocations = %d, want 3", len(revoked))
	}
}

func TestBulkRevokeHandlerFilterBody(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "bulkfil", models.TenantQuotas{})
	if rec := issueVia(t, api, root.ID, "keep.example.com"); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	if rec := issueVia(t, api, root.ID, "cut.compromised.net"); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}

	body := `{"dry_run":true,"filter":{"pattern":"*.compromised.net"}}`
	rec := bulkRevokeReq(t, api, rootUser(), root.ID, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered dry run = %d: %s", rec.Code, rec.Body.String())
	}
	var plan struct {
		Total  int `json:"total"`
		Sample []struct {
			CommonName string `json:"common_name"`
		} `json:"sample"`
	}
	json.Unmarshal(rec.Body.Bytes(), &plan)
	if plan.Total != 1 || len(plan.Sample) != 1 || plan.Sample[0].CommonName != "cut.compromised.net" {
		t.Fatalf("filtered plan = %+v, want exactly cut.compromised.net", plan)
	}

	// An invalid filter is a 400, not a 500.
	rec = bulkRevokeReq(t, api, rootUser(), root.ID, `{"dry_run":true,"filter":{"serials":["not-a-serial"]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad serial dry run = %d, want 400", rec.Code)
	}
}

// TestBulkRevokeHandlerRBAC: bulk revocation needs ca:manage in the CA's
// tenant — an issuer (who may single-revoke) is refused, a tenant admin of
// another tenant is refused, and the owning tenant's admin is admitted.
func TestBulkRevokeHandlerRBAC(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "bulkrbac", models.TenantQuotas{})
	tenantID := root.TenantID
	mkTenant(t, db, "other")

	if rec := issueVia(t, api, root.ID, "victim.example.com"); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}

	deny := func(user *models.UserInfo, label string) {
		t.Helper()
		rec := bulkRevokeReq(t, api, user, root.ID, `{"dry_run":true}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d: %s, want 403", label, rec.Code, rec.Body.String())
		}
	}
	deny(tenantUser("issuer-same-tenant", tenantID, "issuer"), "issuer of owning tenant")
	deny(tenantUser("admin-other-tenant", "other", "admin"), "admin of another tenant")
	deny(tenantUser("auditor-same-tenant", tenantID, "auditor"), "auditor of owning tenant")

	// Nothing was revoked by the denied attempts.
	if revoked, _ := db.ListRevokedCertificates(root.ID); len(revoked) != 0 {
		t.Fatalf("denied requests revoked %d certificates", len(revoked))
	}

	// The owning tenant's admin may run it end to end.
	admin := tenantUser("admin-owner", tenantID, "admin")
	rec := bulkRevokeReq(t, api, admin, root.ID, `{"dry_run":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owning admin dry run = %d: %s", rec.Code, rec.Body.String())
	}
	rec = bulkRevokeReq(t, api, admin, root.ID, `{"reason":"keyCompromise","confirm_count":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owning admin execution = %d: %s", rec.Code, rec.Body.String())
	}

	// An unknown CA is a 404.
	rec = bulkRevokeReq(t, api, rootUser(), "no-such-ca", `{"dry_run":true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown CA = %d, want 404", rec.Code)
	}
}
