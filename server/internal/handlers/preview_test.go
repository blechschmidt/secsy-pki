//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// previewReq POSTs a preview request as the root operator and returns the recorder.
func previewReq(t *testing.T, api *API, caID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.PreviewCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/certificates:preview", rootUser(), caID, body))
	return rec
}

// decodePreview asserts a 200 and decodes the preview body.
func decodePreview(t *testing.T, rec *httptest.ResponseRecorder) *ca.PreviewResult {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var res ca.PreviewResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decoding preview response: %v", err)
	}
	return &res
}

func totalEvents(t *testing.T, api *API) int {
	t.Helper()
	_, total, err := api.db.ListEvents("", "", "", 1, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return total
}

// TestPreviewCertificateREST exercises POST /api/ca/{id}/certificates:preview end
// to end: an accepted request returns the resolved leaf and passing gates, an
// over-max validity is rejected inside a 200 body, an attestation gate verdict is
// always present, and no preview issues a certificate or appends an audit event.
func TestPreviewCertificateREST(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "preview", models.TenantQuotas{})

	certsBefore, err := db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	eventsBefore := totalEvents(t, api)

	// --- Accept.
	body := fmt.Sprintf(`{"csr":%q,"profile":"server"}`, quotaCSR(t, "a.example.com"))
	res := decodePreview(t, previewReq(t, api, root.ID, body))
	if !res.WouldIssue || res.Decision != "accept" {
		t.Fatalf("want accept, got decision=%q would_issue=%v", res.Decision, res.WouldIssue)
	}
	if res.SubjectKeyID == "" || res.AuthorityKeyID == "" {
		t.Errorf("preview should resolve SKI/AKI, got ski=%q aki=%q", res.SubjectKeyID, res.AuthorityKeyID)
	}
	// The serving layer always attaches an attestation verdict (informational).
	if !hasGate(res, ca.GateAttestation) {
		t.Errorf("preview should carry an attestation gate verdict, gates=%v", res.Gates)
	}
	if !hasGate(res, ca.GateApproval) {
		t.Errorf("preview should carry an approval gate verdict, gates=%v", res.Gates)
	}

	// --- Reject: over-max validity (the built-in server profile caps at 397 days).
	body = fmt.Sprintf(`{"csr":%q,"profile":"server","validity_days":3650}`, quotaCSR(t, "b.example.com"))
	res = decodePreview(t, previewReq(t, api, root.ID, body))
	if res.WouldIssue || res.Decision != "reject" {
		t.Fatalf("want reject for over-max validity, got decision=%q", res.Decision)
	}

	// --- No side effects: nothing issued, no audit event appended.
	certsAfter, err := db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	if len(certsAfter) != len(certsBefore) {
		t.Fatalf("preview issued a certificate: before=%d after=%d", len(certsBefore), len(certsAfter))
	}
	if got := totalEvents(t, api); got != eventsBefore {
		t.Fatalf("preview appended audit event(s): before=%d after=%d", eventsBefore, got)
	}
}

func hasGate(res *ca.PreviewResult, name string) bool {
	for _, g := range res.Gates {
		if g.Name == name {
			return true
		}
	}
	return false
}
