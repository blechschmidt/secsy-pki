//go:build sqlite

package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
)

func sshTestSubjectKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// TestSSHCAEndpointsFlow drives the /api/ssh lifecycle through the handlers as
// a platform admin: create a CA, sign a user certificate, list the inventory,
// revoke by serial, fetch the KRL (public), and fetch the CA public key
// (public) — asserting the audit trail (ssh.ca_init, ssh.sign, ssh.revoke)
// along the way.
func TestSSHCAEndpointsFlow(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	// Create the CA.
	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", root, "", `{"label":"ops-ssh-ca"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateSSHCA: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var ca models.CA
	if err := json.Unmarshal(rec.Body.Bytes(), &ca); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}
	if !strings.HasPrefix(ca.PublicKey, "ssh-ed25519 ") {
		t.Errorf("CA public key = %q, want ed25519 authorized_keys line", ca.PublicKey)
	}

	// Sign a user certificate.
	signBody, _ := json.Marshal(map[string]interface{}{
		"public_key": sshTestSubjectKey(t),
		"cert_type":  "user",
		"principals": []string{"alice"},
		"key_id":     "alice@corp",
	})
	rec = httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/sign", root, ca.ID, string(signBody)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("SignSSHCert: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var signResp SignSSHCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signResp); err != nil {
		t.Fatalf("decoding sign response: %v", err)
	}
	if !strings.Contains(signResp.Certificate, "-cert-v01@openssh.com ") {
		t.Errorf("certificate = %q, want an OpenSSH certificate line", signResp.Certificate)
	}
	if signResp.CAPublicKey != ca.PublicKey {
		t.Error("sign response does not carry the CA public key")
	}

	// The signed certificate parses and is bound to the CA key.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signResp.Certificate))
	if err != nil {
		t.Fatalf("parsing signed certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("response is not a certificate")
	}
	if cert.KeyId != "alice@corp" || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Errorf("cert key_id=%q principals=%v", cert.KeyId, cert.ValidPrincipals)
	}

	// Inventory lists it.
	rec = httptest.NewRecorder()
	api.ListSSHCertificates(rec, reqAs(http.MethodGet, "/api/ssh/cas/"+ca.ID+"/certificates", root, ca.ID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListSSHCertificates: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var certs []models.SSHCertificate
	if err := json.Unmarshal(rec.Body.Bytes(), &certs); err != nil {
		t.Fatalf("decoding inventory: %v", err)
	}
	if len(certs) != 1 || certs[0].Serial != signResp.Serial {
		t.Errorf("inventory = %+v, want the one signed certificate", certs)
	}

	// Revoke it by serial.
	rec = httptest.NewRecorder()
	api.RevokeSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/revoke", root, ca.ID,
		`{"serial":"`+signResp.Serial+`","reason":"compromised"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("RevokeSSHCert: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// The public KRL endpoint serves a KRL revoking that serial.
	rec = httptest.NewRecorder()
	krlReq := httptest.NewRequest(http.MethodGet, "/api/ssh/cas/"+ca.ID+"/krl", nil)
	krlReq.SetPathValue("id", ca.ID)
	api.GetSSHKRL(rec, krlReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetSSHKRL: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	parsed, err := sshca.ParseKRL(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("served KRL does not parse: %v", err)
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		t.Fatalf("parsing CA key: %v", err)
	}
	if !parsed.IsSerialRevoked(caKey, cert.Serial) {
		t.Error("served KRL does not revoke the revoked serial")
	}

	// The public CA-key endpoint serves the trust anchor.
	rec = httptest.NewRecorder()
	pubReq := httptest.NewRequest(http.MethodGet, "/api/ssh/cas/"+ca.ID+"/public", nil)
	pubReq.SetPathValue("id", ca.ID)
	api.GetSSHCAPublicKey(rec, pubReq)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != ca.PublicKey {
		t.Errorf("GetSSHCAPublicKey: status=%d body=%q", rec.Code, rec.Body.String())
	}

	// The audit trail records the lifecycle.
	for _, action := range []string{audit.ActionSSHCAInit, audit.ActionSSHSign, audit.ActionSSHRevoke} {
		events, _, err := db.ListEvents(action, "", "", 10, 0)
		if err != nil {
			t.Fatalf("ListEvents(%s): %v", action, err)
		}
		if len(events) == 0 {
			t.Errorf("no audit event recorded for %s", action)
			continue
		}
		if events[0].Result != audit.ResultSuccess {
			t.Errorf("audit %s result = %q, want success", action, events[0].Result)
		}
	}
}

// TestSSHCAEndpointsTenantIsolation proves the SSH endpoints enforce the same
// cross-tenant denial as X.509 issuance: an issuer of tenant A cannot sign or
// revoke on tenant B's SSH CA, and a roleless principal cannot create a CA.
func TestSSHCAEndpointsTenantIsolation(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")

	// Root provisions an SSH CA in tenant B.
	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", root, "", `{"label":"b-ssh-ca","tenant_id":"b"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateSSHCA: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var caB models.CA
	if err := json.Unmarshal(rec.Body.Bytes(), &caB); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}
	if caB.TenantID != "b" {
		t.Fatalf("CA tenant = %q, want b", caB.TenantID)
	}

	aliceA := tenantUser("alice", "a", "issuer")
	body, _ := json.Marshal(map[string]interface{}{
		"public_key": sshTestSubjectKey(t),
		"principals": []string{"alice"},
	})

	// Cross-tenant signing: denied.
	rec = httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+caB.ID+"/sign", aliceA, caB.ID, string(body)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-tenant sign: status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	// Cross-tenant revocation: denied.
	rec = httptest.NewRecorder()
	api.RevokeSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+caB.ID+"/revoke", aliceA, caB.ID, `{"serial":"2"}`))
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-tenant revoke: status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	// Cross-tenant inventory read: hidden (404, not 403, to avoid disclosure).
	rec = httptest.NewRecorder()
	api.ListSSHCertificates(rec, reqAs(http.MethodGet, "/api/ssh/cas/"+caB.ID+"/certificates", aliceA, caB.ID, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant list: status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}

	// An issuer of tenant B may sign on its own tenant's CA.
	bobB := tenantUser("bob", "b", "issuer")
	rec = httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+caB.ID+"/sign", bobB, caB.ID, string(body)))
	if rec.Code != http.StatusCreated {
		t.Errorf("same-tenant sign: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// A tenant issuer cannot create CAs (ca:manage required).
	rec = httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", aliceA, "", `{"label":"rogue","tenant_id":"a"}`))
	if rec.Code != http.StatusForbidden {
		t.Errorf("issuer CA creation: status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// The denial is audited.
	events, _, err := db.ListEvents(audit.ActionSSHSign, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var deniedSeen bool
	for _, e := range events {
		if e.Result == audit.ResultDenied && e.Actor == "alice" {
			deniedSeen = true
		}
	}
	if !deniedSeen {
		t.Error("cross-tenant sign denial not audited")
	}
}

// TestSSHCASignValidityClamp proves the REST surface honors profile validity
// clamping end to end.
func TestSSHCASignValidityClamp(t *testing.T) {
	api, _ := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", root, "", `{"label":"clamp-ca"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateSSHCA: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var ca models.CA
	json.Unmarshal(rec.Body.Bytes(), &ca)

	// user-default caps validity at 30 days; ask for a year.
	body, _ := json.Marshal(map[string]interface{}{
		"public_key":       sshTestSubjectKey(t),
		"principals":       []string{"alice"},
		"validity_seconds": int64((365 * 24 * time.Hour).Seconds()),
	})
	rec = httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/sign", root, ca.ID, string(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("SignSSHCert: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp SignSSHCertResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	va, _ := time.Parse(time.RFC3339, resp.ValidAfter)
	vb, _ := time.Parse(time.RFC3339, resp.ValidBefore)
	if lifetime := vb.Sub(va); lifetime > 31*24*time.Hour {
		t.Errorf("lifetime = %v, want clamped to the profile maximum (~30d)", lifetime)
	}
}
