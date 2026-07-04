//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// issueMustStaple POSTs an issuance request with an optional per-request
// must_staple override and returns the parsed leaf certificate.
func issueMustStaple(t *testing.T, api *API, caID, cn, profile string, override *bool) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"csr":%q,"profile":%q`, quotaCSR(t, cn), profile)
	if override != nil {
		body += fmt.Sprintf(`,"must_staple":%t`, *override)
	}
	body += "}"
	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, body))
	return rec
}

// leafHasMustStaple parses an issuance response's certificate and reports whether
// it carries the RFC 7633 Must-Staple TLS feature.
func leafHasMustStaple(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding issue response: %v", err)
	}
	cert, err := pki.ParseCertificatePEM([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(pki.OIDTLSFeature) {
			feats, err := pki.ParseTLSFeature(ext.Value)
			if err != nil {
				t.Fatalf("issued cert has malformed TLS feature extension: %v", err)
			}
			return pki.TLSFeatureListed(feats, pki.TLSFeatureStatusRequest)
		}
	}
	return false
}

// TestIssueMustStapleRESTOverride exercises the REST per-request override wiring
// (models.IssueCertRequest.must_staple → ca.IssueSpec.MustStaple) end to end.
func TestIssueMustStapleRESTOverride(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "muststaple", models.TenantQuotas{})

	// Profile default (server-muststaple) stamps the extension.
	if !leafHasMustStaple(t, issueMustStaple(t, api, root.ID, "a.example.com", "server-muststaple", nil)) {
		t.Error("server-muststaple leaf missing the Must-Staple extension")
	}
	// server-muststaple permits overrides: must_staple=false suppresses it.
	if leafHasMustStaple(t, issueMustStaple(t, api, root.ID, "b.example.com", "server-muststaple", boolPtr(false))) {
		t.Error("must_staple=false override did not suppress the extension")
	}
	// The plain server profile does not permit overrides: must_staple=true ignored.
	if leafHasMustStaple(t, issueMustStaple(t, api, root.ID, "c.example.com", "server", boolPtr(true))) {
		t.Error("must_staple=true was honored on a profile that forbids overrides")
	}
}

func boolPtr(b bool) *bool { return &b }
