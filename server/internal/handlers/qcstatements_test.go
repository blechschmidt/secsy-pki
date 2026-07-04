//go:build sqlite

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// issueJSON POSTs a raw issuance JSON body and returns the recorder.
func issueJSON(t *testing.T, api *API, caID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, body))
	return rec
}

// leafQCStatements parses a 201 issuance response and returns the decoded eIDAS
// QCStatements the leaf carries (present=false when absent).
func leafQCStatements(t *testing.T, rec *httptest.ResponseRecorder) (pki.QCStatements, bool) {
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
	qc, present, err := pki.QCStatementsFromCertificate(cert)
	if err != nil {
		t.Fatalf("QCStatementsFromCertificate: %v", err)
	}
	return qc, present
}

// TestIssueQCStatementsRESTPSD2 exercises the REST per-request PSD2 wiring
// (models.IssueCertRequest.psd2 → ca.IssueSpec.PSD2 → id-pe-qcStatements).
func TestIssueQCStatementsRESTPSD2(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "qc", models.TenantQuotas{})

	// qualified-web (QWAC) with a per-request PSD2 override.
	body := `{"csr":` + jsonString(quotaCSR(t, "qwac.example.com")) +
		`,"profile":"qualified-web","psd2":{"roles":["PSP_AI"],"nca_name":"Financial Conduct Authority","nca_id":"GB-FCA"}}`
	qc, present := leafQCStatements(t, issueJSON(t, api, root.ID, body))
	if !present {
		t.Fatal("qualified-web leaf missing qcStatements over REST")
	}
	if !qc.Compliance {
		t.Error("missing QcCompliance")
	}
	if qc.PSD2 == nil || qc.PSD2.NCAID != "GB-FCA" || len(qc.PSD2.Roles) != 1 || qc.PSD2.Roles[0].Name != "PSP_AI" {
		t.Errorf("PSD2 override not carried through REST: %+v", qc.PSD2)
	}

	// A PSD2 override on a non-QC profile is rejected (400).
	badBody := `{"csr":` + jsonString(quotaCSR(t, "plain.example.com")) +
		`,"profile":"server","psd2":{"roles":["PSP_AS"],"nca_name":"x","nca_id":"GB-x"}}`
	rec := issueJSON(t, api, root.ID, badBody)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PSD2 override on non-QC profile = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
