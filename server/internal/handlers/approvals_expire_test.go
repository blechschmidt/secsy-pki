//go:build sqlite

package handlers

// Tests for the approval expiry sweep REST surface (Task 198).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// expireApprovals drives POST /api/approvals/expire.
func expireApprovals(api *API, user *models.UserInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.ExpireApprovals(rec, reqAs(http.MethodPost, "/api/approvals/expire", user, "", ""))
	return rec
}

// seedExpiringApproval records a pending request with an explicit deadline, so a
// sweep has something real to retire.
func seedExpiringApproval(t *testing.T, db *database.DB, id string, expiresAt time.Time) {
	t.Helper()
	if err := db.CreatePendingApproval(&models.PendingApproval{
		ID: id, TenantID: "a", OperationClass: approval.ClassCARotate, ResourceKey: "ca:ca-a",
		Fingerprint: "fp-" + id, RequestedBy: "maker", RequiredApprovals: 2,
		Status: approval.StatusPending, CreatedAt: time.Now().Add(-96 * time.Hour).UTC(),
		ExpiresAt: expiresAt.UTC(),
	}); err != nil {
		t.Fatalf("CreatePendingApproval(%s): %v", id, err)
	}
}

// approvalsAPI installs an approval engine with the given enforcement state.
func approvalsAPI(t *testing.T, enabled bool) (*API, *database.DB) {
	t.Helper()
	api, db := tenantAPI(t)
	mkTenant(t, db, "a") // the approval rows are tenant-scoped (foreign key)
	api.SetApprovals(approval.NewEngine(db, db, approval.Policy{
		Enabled: enabled, DefaultThreshold: 2, TTL: 72 * time.Hour,
	}))
	return api, db
}

// TestExpireApprovalsUnavailable proves the endpoint reports 503 when the
// approval workflow was never installed, consistent with the rest of the
// approvals surface, and that it does so before authorizing — the gate's absence
// is not a secret, but it must not look like a successful no-op sweep either.
func TestApprovalsExpireUnavailable(t *testing.T) {
	api, _ := tenantAPI(t) // no SetApprovals
	for _, user := range []*models.UserInfo{rootUser(), {Subject: "nobody"}} {
		if rec := expireApprovals(api, user); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("user %+v: status = %d, want 503; body=%s", user, rec.Code, rec.Body.String())
		}
	}
}

// TestExpireApprovalsAuthz pins the gate: the sweep walks every tenant's queue,
// so it needs the platform-wide approval:approve capability. Reading the queue
// (auditor) is not enough, and tenant-scoped approval authority does not reach it.
func TestApprovalsExpireAuthz(t *testing.T) {
	api, db := approvalsAPI(t, true)

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 403},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 403},
		{"tenant approver", tenantUser("tappr", "a", "approver"), 403},
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 403},
		{"platform approver", &models.UserInfo{Subject: "appr", Roles: []string{"approver"}}, 200},
		{"platform admin", platformAdmin(), 200},
		{"root", rootUser(), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedExpiringApproval(t, db, "apr-"+strings.ReplaceAll(tc.name, " ", "-"), time.Now().Add(-time.Hour))
			if rec := expireApprovals(api, tc.user); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestExpireApprovalsSweeps retires exactly the requests whose window elapsed,
// leaves live ones alone, and records the operator-attributed audit event.
func TestApprovalsExpireSweeps(t *testing.T) {
	api, db := approvalsAPI(t, true)
	seedExpiringApproval(t, db, "apr-stale-1", time.Now().Add(-2*time.Hour))
	seedExpiringApproval(t, db, "apr-stale-2", time.Now().Add(-time.Minute))
	seedExpiringApproval(t, db, "apr-live", time.Now().Add(time.Hour))

	rec := expireApprovals(api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp ExpireApprovalsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Expired != 2 || !resp.Enabled {
		t.Fatalf("response = %+v, want expired 2 and enabled true", resp)
	}

	for id, want := range map[string]string{
		"apr-stale-1": approval.StatusExpired,
		"apr-stale-2": approval.StatusExpired,
		"apr-live":    approval.StatusPending,
	} {
		pa, err := db.GetPendingApproval(id)
		if err != nil || pa == nil {
			t.Fatalf("GetPendingApproval(%s): %v", id, err)
		}
		if pa.Status != want {
			t.Errorf("%s status = %q, want %q", id, pa.Status, want)
		}
	}

	// A second sweep is a clean no-op, and records nothing further.
	rec = expireApprovals(api, rootUser())
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Code != http.StatusOK || resp.Expired != 0 {
		t.Fatalf("second sweep = %d %+v, want 200 with expired 0", rec.Code, resp)
	}

	// The per-request trail is the engine's (actor "system"); the summary carries
	// the operator who asked for the sweep.
	events, _, err := db.ListEvents(audit.ActionApprovalExpire, "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var perRequest, summary int
	for _, e := range events {
		switch {
		case e.Target == "apr-stale-1" || e.Target == "apr-stale-2":
			perRequest++
		case e.Actor == "root" && strings.Contains(e.Detail, "expired=2") && strings.Contains(e.Detail, "via=api"):
			summary++
		}
	}
	if perRequest != 2 {
		t.Errorf("per-request approval.expire events = %d, want 2 (events=%+v)", perRequest, events)
	}
	if summary != 1 {
		t.Errorf("operator-attributed summary events = %d, want exactly 1 (events=%+v)", summary, events)
	}
}

// TestExpireApprovalsWithGateDisabled mirrors the CLI: a manual sweep still
// cleans up requests left behind by a previously-enabled gate, and the response
// says the gate is off so a count of zero is never ambiguous.
func TestApprovalsExpireWithGateDisabled(t *testing.T) {
	api, db := approvalsAPI(t, false)
	seedExpiringApproval(t, db, "apr-leftover", time.Now().Add(-time.Hour))

	rec := expireApprovals(api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp ExpireApprovalsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Expired != 1 {
		t.Errorf("expired = %d, want 1 — a manual sweep must work with the gate disabled", resp.Expired)
	}
	if resp.Enabled {
		t.Errorf("enabled = true, want the disabled gate reported honestly")
	}
	pa, err := db.GetPendingApproval("apr-leftover")
	if err != nil || pa == nil || pa.Status != approval.StatusExpired {
		t.Fatalf("leftover request = %+v (err=%v), want status expired", pa, err)
	}
}
