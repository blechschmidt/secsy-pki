//go:build sqlite

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// validateReq POSTs a chain-validation request as user and returns the recorder.
func validateReq(t *testing.T, api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ValidateChain(rec, reqAs(http.MethodPost, "/api/validate", user, "", body))
	return rec
}

// decodeValidation asserts a 200 and decodes the validation response.
func decodeValidation(t *testing.T, rec *httptest.ResponseRecorder) *ValidateChainResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("validate = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var res ValidateChainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decoding validation response: %v", err)
	}
	return &res
}

func validationCheck(res *ValidateChainResponse, name string) string {
	for _, c := range res.Checks {
		if c.Name == name {
			return string(c.Status)
		}
	}
	return ""
}

// TestValidateChainREST exercises POST /api/validate end to end against a real
// software-backed CA: a freshly issued leaf validates, revoking it flips the
// revocation gate and the overall verdict, and a leaf issued by a different root
// fails to build a path (unknown issuer).
func TestValidateChainREST(t *testing.T) {
	api, db := tenantAPI(t)
	tn, root := quotaTenantWithRoot(t, api, db, "validate", models.TenantQuotas{})
	ctx := context.Background()
	mgr := ca.NewManager(db, api.keyProvider)

	// Issue a leaf under the root.
	leaf, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:    root.ID,
		CSRPEM:  []byte(quotaCSR(t, "leaf.example.com")),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// --- Valid.
	body := fmt.Sprintf(`{"ca":%q,"certificate":%q}`, root.ID, string(leaf.PEM))
	res := decodeValidation(t, validateReq(t, api, rootUser(), body))
	if !res.ChainBuilt || !res.Valid {
		t.Fatalf("fresh leaf should be valid: built=%v valid=%v reasons=%v", res.ChainBuilt, res.Valid, res.Reasons)
	}
	if got := validationCheck(res, "revocation"); got != "pass" {
		t.Errorf("revocation check = %q, want pass", got)
	}
	if got := validationCheck(res, "chain"); got != "pass" {
		t.Errorf("chain check = %q, want pass", got)
	}

	// --- Revoked: the revocation gate flips the verdict.
	if _, err := mgr.RevokeCertificate(ctx, root.ID, leaf.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	res = decodeValidation(t, validateReq(t, api, rootUser(), body))
	if res.Valid {
		t.Fatalf("revoked leaf must be invalid")
	}
	if got := validationCheck(res, "revocation"); got != "fail" {
		t.Errorf("revocation check after revoke = %q, want fail", got)
	}

	// --- Unknown issuer: a leaf under a different root does not chain to `root`.
	other, err := mgr.InitRoot(ctx, ca.RootSpec{
		TenantID: tn.ID,
		Label:    "validate-other-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Other Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot(other): %v", err)
	}
	stranger, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:    other.ID,
		CSRPEM:  []byte(quotaCSR(t, "stranger.example.com")),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate(stranger): %v", err)
	}
	body = fmt.Sprintf(`{"ca":%q,"certificate":%q}`, root.ID, string(stranger.PEM))
	res = decodeValidation(t, validateReq(t, api, rootUser(), body))
	if res.ChainBuilt || res.Valid {
		t.Fatalf("stranger leaf must not chain to the wrong root: built=%v valid=%v", res.ChainBuilt, res.Valid)
	}
	if got := validationCheck(res, "chain"); got != "fail" {
		t.Errorf("chain check for unknown issuer = %q, want fail", got)
	}
}

// TestValidateChainRESTErrors covers the client-error paths: a missing CA, an
// unknown CA, and a missing certificate.
func TestValidateChainRESTErrors(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "validate-err", models.TenantQuotas{})

	// Missing ca.
	if rec := validateReq(t, api, rootUser(), `{"certificate":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("missing ca = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// Unknown ca.
	if rec := validateReq(t, api, rootUser(), `{"ca":"nope","certificate":"x"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown ca = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	// Missing certificate.
	if rec := validateReq(t, api, rootUser(), fmt.Sprintf(`{"ca":%q}`, root.ID)); rec.Code != http.StatusBadRequest {
		t.Errorf("missing certificate = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// Malformed certificate.
	body := fmt.Sprintf(`{"ca":%q,"certificate":"not a certificate"}`, root.ID)
	if rec := validateReq(t, api, rootUser(), body); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed certificate = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
