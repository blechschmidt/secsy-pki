//go:build sqlite

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// holdAction drives the CertificateHoldAction dispatcher directly, wiring both
// the {id} and {action} path values the router would set for
// POST /api/ca/{id}/certificates/{serial}:{verb}.
func holdAction(t *testing.T, api *API, user *models.UserInfo, caID, serial, verb string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := reqAs(http.MethodPost, "/api/ca/"+caID+"/certificates/"+serial+":"+verb, user, caID, "")
	r.SetPathValue("action", serial+":"+verb)
	api.CertificateHoldAction(rec, r)
	return rec
}

// issuedSerial issues a certificate through the REST handler and returns its serial.
func issuedSerial(t *testing.T, api *API, caID, cn string) string {
	t.Helper()
	rec := issueVia(t, api, caID, cn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue %s = %d: %s", cn, rec.Code, rec.Body.String())
	}
	var resp struct {
		Serial string `json:"serial"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Serial == "" {
		t.Fatalf("issue response serial: err=%v body=%s", err, rec.Body.String())
	}
	return resp.Serial
}

// TestSuspendReleaseHandlers covers the REST surface of the reversible-hold
// endpoints: suspend -> held (revocation store reason certificateHold) ->
// release -> good (no revocation record), plus idempotency.
func TestSuspendReleaseHandlers(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "hold", models.TenantQuotas{})
	serial := issuedSerial(t, api, root.ID, "hold-http.example.com")

	// Suspend: 200 with status "held".
	rec := holdAction(t, api, rootUser(), root.ID, serial, "suspend")
	if rec.Code != http.StatusOK {
		t.Fatalf("suspend = %d: %s", rec.Code, rec.Body.String())
	}
	assertHoldStatus(t, rec, "held")

	// The revocation store now carries the serial with reason certificateHold(6).
	rc, err := db.GetRevokedCertificate(root.ID, serial)
	if err != nil || rc == nil {
		t.Fatalf("GetRevokedCertificate after suspend: rc=%v err=%v", rc, err)
	}
	if rc.Reason != 6 {
		t.Errorf("held reason = %d, want certificateHold(6)", rc.Reason)
	}

	// Suspending again is idempotent: "already-held".
	rec = holdAction(t, api, rootUser(), root.ID, serial, "suspend")
	if rec.Code != http.StatusOK {
		t.Fatalf("re-suspend = %d: %s", rec.Code, rec.Body.String())
	}
	assertHoldStatus(t, rec, "already-held")

	// Release: 200 with status "released"; the revocation record is gone.
	rec = holdAction(t, api, rootUser(), root.ID, serial, "release")
	if rec.Code != http.StatusOK {
		t.Fatalf("release = %d: %s", rec.Code, rec.Body.String())
	}
	assertHoldStatus(t, rec, "released")
	if rc, err := db.GetRevokedCertificate(root.ID, serial); err != nil || rc != nil {
		t.Fatalf("GetRevokedCertificate after release: rc=%v err=%v, want nil", rc, err)
	}
}

// TestReleasePermanentRevocation409 proves a permanently revoked certificate
// cannot be released through the REST endpoint (409 Conflict), and that an
// unknown verb is a 400.
func TestReleasePermanentRevocation409(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "hold409", models.TenantQuotas{})
	serial := issuedSerial(t, api, root.ID, "perm-http.example.com")

	// Permanently revoke via the manager, then attempt release.
	mgr := ca.NewManager(db, api.keyProvider)
	if _, err := mgr.RevokeCertificate(context.Background(), root.ID, serial, "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	rec := holdAction(t, api, rootUser(), root.ID, serial, "release")
	if rec.Code != http.StatusConflict {
		t.Fatalf("release of permanently revoked cert = %d: %s, want 409", rec.Code, rec.Body.String())
	}

	// An unknown verb is rejected as a bad request.
	rec = holdAction(t, api, rootUser(), root.ID, serial, "frobnicate")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action = %d: %s, want 400", rec.Code, rec.Body.String())
	}
}

// TestSuspendReleaseRBAC: a principal with no issue capability on the CA's
// tenant is refused (403), matching the single-revocation gate.
func TestSuspendReleaseRBAC(t *testing.T) {
	api, db := tenantAPI(t)
	tn, root := quotaTenantWithRoot(t, api, db, "holdrbac", models.TenantQuotas{})
	serial := issuedSerial(t, api, root.ID, "rbac-http.example.com")

	// An auditor (read-only) may not suspend.
	auditor := tenantUser("read-only", tn.ID, "auditor")
	if rec := holdAction(t, api, auditor, root.ID, serial, "suspend"); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor suspend = %d: %s, want 403", rec.Code, rec.Body.String())
	}
	// ...and the certificate is untouched.
	if rc, _ := db.GetRevokedCertificate(root.ID, serial); rc != nil {
		t.Errorf("auditor's denied suspend still placed a hold: %+v", rc)
	}
}

func assertHoldStatus(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var resp struct {
		Status string `json:"status"`
		Serial string `json:"serial"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding hold response: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Status != want {
		t.Errorf("status = %q, want %q", resp.Status, want)
	}
}
