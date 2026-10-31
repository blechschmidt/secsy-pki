//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// signedLifetime is the lifetime the sign endpoint reports, from the backdated
// ValidAfter to ValidBefore.
func signedLifetime(t *testing.T, resp SignSSHCertResponse) time.Duration {
	t.Helper()
	va, err := time.Parse(time.RFC3339, resp.ValidAfter)
	if err != nil {
		t.Fatalf("parsing valid_after %q: %v", resp.ValidAfter, err)
	}
	vb, err := time.Parse(time.RFC3339, resp.ValidBefore)
	if err != nil {
		t.Fatalf("parsing valid_before %q: %v", resp.ValidBefore, err)
	}
	return vb.Sub(va)
}

// sshSign signs a one-principal user certificate asking for the given lifetime
// (zero asks for the profile default).
func sshSign(t *testing.T, api *API, user *models.UserInfo, caID string, requested time.Duration) (int, SignSSHCertResponse, string) {
	t.Helper()
	payload := map[string]interface{}{
		"public_key": sshTestSubjectKey(t),
		"cert_type":  "user",
		"principals": []string{"alice"},
		"key_id":     "alice@corp",
	}
	if requested > 0 {
		payload["validity_seconds"] = int64(requested.Seconds())
	}
	body, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+caID+"/sign", user, caID, string(body)))
	var resp SignSSHCertResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding sign response: %v", err)
		}
	}
	return rec.Code, resp, rec.Body.String()
}

// setSSHMax calls PUT /api/ssh/cas/{id}/max-validity as the given principal.
func setSSHMax(t *testing.T, api *API, user *models.UserInfo, caID string, secs int64) (int, SetSSHCAMaxValidityResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"max_validity_seconds":%d}`, secs)
	api.SetSSHCAMaxValidity(rec, reqAs(http.MethodPut, "/api/ssh/cas/"+caID+"/max-validity", user, caID, body))
	var resp SetSSHCAMaxValidityResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding max-validity response: %v", err)
		}
	}
	return rec.Code, resp, rec.Body.String()
}

// createSSHCA provisions an SSH CA through the REST handler.
func createSSHCA(t *testing.T, api *API, user *models.UserInfo, body string) models.CA {
	t.Helper()
	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", user, "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateSSHCA(%s): status = %d, body=%s", body, rec.Code, rec.Body.String())
	}
	var ca models.CA
	if err := json.Unmarshal(rec.Body.Bytes(), &ca); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}
	return ca
}

// TestSSHCAMaxValidityRESTLifecycle is the REST-surface proof for Task 217: a
// ceiling can be set at creation, read back from the CA record, changed and
// cleared afterwards, and it clamps signing in every case.
func TestSSHCAMaxValidityRESTLifecycle(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	// Created WITH a ceiling: 4h, below user-default's 12h default.
	ca := createSSHCA(t, api, root, `{"label":"maxval-ca","max_validity_seconds":14400}`)
	if ca.MaxSSHValiditySecs != 14400 {
		t.Fatalf("created CA ceiling = %d, want 14400", ca.MaxSSHValiditySecs)
	}

	// The CA list surfaces the ceiling, so the console can show it.
	rec := httptest.NewRecorder()
	api.ListSSHCAs(rec, reqAs(http.MethodGet, "/api/ssh/cas", root, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListSSHCAs: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var listed []models.CA
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding SSH CA list: %v", err)
	}
	var seen bool
	for _, c := range listed {
		if c.ID == ca.ID {
			seen = true
			if c.MaxSSHValiditySecs != 14400 {
				t.Errorf("listed ceiling = %d, want 14400", c.MaxSSHValiditySecs)
			}
		}
	}
	if !seen {
		t.Fatalf("created CA missing from the SSH CA list: %s", rec.Body.String())
	}

	// Signing is clamped to the ceiling, and the response explains why.
	status, resp, body := sshSign(t, api, root, ca.ID, 30*24*time.Hour)
	if status != http.StatusCreated {
		t.Fatalf("sign: status = %d, body=%s", status, body)
	}
	if got := signedLifetime(t, resp); got > 4*time.Hour+10*time.Minute {
		t.Errorf("lifetime = %s, want clamped to ~4h", got)
	}
	if !resp.ClampedByCAMaxValidity {
		t.Error("clamped_by_ca_max_validity = false, want true")
	}
	if resp.CAMaxValiditySeconds != 14400 {
		t.Errorf("ca_max_validity_seconds = %d, want 14400", resp.CAMaxValiditySeconds)
	}

	// Even the profile default (12h) is clamped: this is what a profile-level
	// cap alone cannot do.
	status, resp, body = sshSign(t, api, root, ca.ID, 0)
	if status != http.StatusCreated {
		t.Fatalf("sign (profile default): status = %d, body=%s", status, body)
	}
	if got := signedLifetime(t, resp); got > 4*time.Hour+10*time.Minute {
		t.Errorf("profile-default lifetime = %s, want clamped to ~4h", got)
	}

	// Tighten to 1h through the endpoint; the previous value is reported back.
	status, setResp, body := setSSHMax(t, api, root, ca.ID, 3600)
	if status != http.StatusOK {
		t.Fatalf("set max-validity: status = %d, body=%s", status, body)
	}
	if setResp.MaxValiditySeconds != 3600 || setResp.PreviousMaxValiditySeconds != 14400 {
		t.Errorf("set response = %+v, want 3600 (previous 14400)", setResp)
	}
	if setResp.CAID != ca.ID || setResp.Label != ca.Label {
		t.Errorf("set response identity = %q/%q, want %q/%q", setResp.CAID, setResp.Label, ca.ID, ca.Label)
	}
	status, resp, body = sshSign(t, api, root, ca.ID, 12*time.Hour)
	if status != http.StatusCreated {
		t.Fatalf("sign after tightening: status = %d, body=%s", status, body)
	}
	if got := signedLifetime(t, resp); got > time.Hour+10*time.Minute {
		t.Errorf("lifetime after tightening = %s, want clamped to ~1h", got)
	}

	// Clear it: the profile bounds take over again (12h default honored).
	status, setResp, body = setSSHMax(t, api, root, ca.ID, 0)
	if status != http.StatusOK {
		t.Fatalf("clear max-validity: status = %d, body=%s", status, body)
	}
	if setResp.MaxValiditySeconds != 0 || setResp.PreviousMaxValiditySeconds != 3600 {
		t.Errorf("clear response = %+v, want 0 (previous 3600)", setResp)
	}
	status, resp, body = sshSign(t, api, root, ca.ID, 0)
	if status != http.StatusCreated {
		t.Fatalf("sign after clearing: status = %d, body=%s", status, body)
	}
	if got := signedLifetime(t, resp); got < 11*time.Hour {
		t.Errorf("lifetime after clearing = %s, want the 12h profile default", got)
	}
	if resp.ClampedByCAMaxValidity {
		t.Error("clamped_by_ca_max_validity = true after clearing the ceiling")
	}

	// Every change is audited under ssh.ca_config, naming the old and new value
	// — raising a ceiling is the privilege-granting direction.
	events, _, err := db.ListEvents(audit.ActionSSHCAConfig, "", "", 20, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ssh.ca_config events = %d, want 2", len(events))
	}
	var sawTighten, sawClear bool
	for _, e := range events {
		if e.Result != audit.ResultSuccess || e.Target != ca.ID {
			t.Errorf("unexpected audit event: %+v", e)
		}
		if strings.Contains(e.Detail, "max_ssh_validity_secs=3600 previous=14400") {
			sawTighten = true
			if !strings.Contains(e.Detail, "change=tightened") {
				t.Errorf("tightening audited as %q, want change=tightened", e.Detail)
			}
		}
		if strings.Contains(e.Detail, "max_ssh_validity_secs=0 previous=3600") {
			sawClear = true
			if !strings.Contains(e.Detail, "change=cleared") {
				t.Errorf("clearing audited as %q, want change=cleared", e.Detail)
			}
		}
	}
	if !sawTighten || !sawClear {
		t.Errorf("audit trail incomplete (tighten=%t clear=%t): %+v", sawTighten, sawClear, events)
	}
}

// TestSSHCAMaxValidityBadRequests pins the rejections: a negative ceiling (on
// create and on update), malformed JSON, and an unknown CA.
func TestSSHCAMaxValidityBadRequests(t *testing.T) {
	api, _ := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", root, "",
		`{"label":"neg-ca","max_validity_seconds":-1}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("create with negative ceiling: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	ca := createSSHCA(t, api, root, `{"label":"maxval-bad-ca"}`)

	if status, _, body := setSSHMax(t, api, root, ca.ID, -5); status != http.StatusBadRequest {
		t.Errorf("negative ceiling: status = %d, want 400; body=%s", status, body)
	}

	rec = httptest.NewRecorder()
	api.SetSSHCAMaxValidity(rec, reqAs(http.MethodPut, "/api/ssh/cas/"+ca.ID+"/max-validity", root, ca.ID, `{`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	// An unknown CA must not be confirmed or denied as existing: 404.
	if status, _, body := setSSHMax(t, api, root, "no-such-ca", 3600); status != http.StatusNotFound {
		t.Errorf("unknown CA: status = %d, want 404; body=%s", status, body)
	}
}

// TestSSHCAMaxValidityAuthorization proves the ceiling is a ca:manage control,
// not an issuance one, and that it is tenant-isolated: an issuer who may sign
// with the CA still cannot widen what it signs.
func TestSSHCAMaxValidityAuthorization(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")

	caB := createSSHCA(t, api, root, `{"label":"authz-maxval-ca","tenant_id":"b"}`)

	// An issuer of the OWNING tenant may sign but not change the ceiling.
	bobB := tenantUser("bob", "b", "issuer")
	if status, _, body := sshSign(t, api, bobB, caB.ID, time.Hour); status != http.StatusCreated {
		t.Fatalf("tenant issuer sign: status = %d, want 201; body=%s", status, body)
	}
	if status, _, body := setSSHMax(t, api, bobB, caB.ID, 3600); status != http.StatusForbidden {
		t.Errorf("tenant issuer set ceiling: status = %d, want 403; body=%s", status, body)
	}

	// A foreign-tenant admin is denied too.
	aliceA := tenantUser("alice", "a", "admin")
	if status, _, body := setSSHMax(t, api, aliceA, caB.ID, 3600); status != http.StatusForbidden {
		t.Errorf("cross-tenant admin set ceiling: status = %d, want 403; body=%s", status, body)
	}

	// The owning tenant's admin may.
	carolB := tenantUser("carol", "b", "admin")
	if status, resp, body := setSSHMax(t, api, carolB, caB.ID, 7200); status != http.StatusOK {
		t.Errorf("tenant admin set ceiling: status = %d, want 200; body=%s", status, body)
	} else if resp.MaxValiditySeconds != 7200 {
		t.Errorf("tenant admin set ceiling = %d, want 7200", resp.MaxValiditySeconds)
	}

	// The denials are audited under ssh.ca_config.
	events, _, err := db.ListEvents(audit.ActionSSHCAConfig, "", "", 20, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	denied := map[string]bool{}
	for _, e := range events {
		if e.Result == audit.ResultDenied {
			denied[e.Actor] = true
		}
	}
	if !denied["bob"] || !denied["alice"] {
		t.Errorf("denials not audited (bob=%t alice=%t)", denied["bob"], denied["alice"])
	}
}

// TestLegacySSHSignHonorsCAMaxValidity closes the bypass: the legacy
// restriction-set signing endpoint signs with the same CA key, so the CA-level
// ceiling has to bind there too — otherwise a permissive restriction set would
// be a way around it.
func TestLegacySSHSignHonorsCAMaxValidity(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	ca := createSSHCA(t, api, root, `{"label":"legacy-maxval-ca","max_validity_seconds":3600}`)
	// The legacy endpoint consults the per-CA SSH restriction set; a new SSH CA
	// defaults to deny-all, so open it to permit-all for this test.
	permitAll := database.BuiltinPermitAllSSH
	if err := db.SetCADefaultRestrictionSet(ca.ID, "ssh", &permitAll); err != nil {
		t.Fatalf("SetCADefaultRestrictionSet: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"public_key": sshTestSubjectKey(t),
		"cert_type":  "user",
		"key_id":     "alice@corp",
		"principals": []string{"alice"},
		// Ask for 30 days (valid_after defaults to now); the CA ceiling is 1h.
		"valid_before": "+4w",
	})
	rec := httptest.NewRecorder()
	api.SignCertificate(rec, reqAs(http.MethodPost, "/api/keys/"+ca.ID+"/sign", root, ca.ID, string(body)))
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("legacy sign: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding legacy sign response: %v", err)
	}
	if resp.Certificate == "" {
		t.Fatalf("legacy sign returned no certificate: %s", rec.Body.String())
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parsing legacy certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("legacy sign did not return a certificate")
	}
	if lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; lifetime > time.Hour+time.Minute {
		t.Errorf("legacy certificate lifetime = %s, want clamped to the CA's 1h ceiling", lifetime)
	}
}
