//go:build sqlite

package handlers

// Tests for the two legacy signing endpoints the service layer does not cover
// (Task 224): POST /api/keys/{id}/sign (an OpenSSH certificate) and
// POST /api/keys/{id}/sign-x509 (a CSR signed straight with the CA key).
//
// Both predate the service layer and both hand a CA key to the pki package
// directly, which before this task meant they consulted no operator-written
// rule at all — a documented way around every one of them. The tests below pin
// that they are now gated, and that a refusal reaches the caller as 422 with
// the reasons as data.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// legacySignAPI builds an API with a CA whose key really exists in the software
// provider, so a permitted request signs rather than failing for an unrelated
// reason.
func legacySignAPI(t *testing.T) (*API, *database.DB, *models.CA) {
	t.Helper()
	api, db := tenantAPI(t)
	mkTenant(t, db, "acme")
	info, err := api.keyProvider.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label: "legacy-ca", KeyType: keyprovider.KeyTypeECDSAP256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ca := &models.CA{
		ID: "legacy-ca", TenantID: "acme", Label: "legacy-ca",
		PKCS11URI: info.URI, KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return api, db, ca
}

// signReq builds a request the way the server's middleware chain would: with a
// policy fact holder carrying the request URL and the *verified* principal, so a
// rule that reasons about the caller sees what it sees in production.
func signReq(method, target string, user *models.UserInfo, id, body string) *http.Request {
	r := reqAs(method, target, user, id, body)
	f := celpolicy.NewFacts()
	f.SetURL(celpolicy.URLFrom(r))
	if user != nil {
		f.SetPrincipal(celpolicy.PrincipalFrom(user.Subject, user.Email, user.Name,
			user.EmailVerified, user.IsRoot, user.Roles, user.Groups, user.TenantRoles, user.AuthProvider))
	}
	return r.WithContext(celpolicy.WithFacts(r.Context(), f))
}

func storeRule(t *testing.T, db *database.DB, rule *celpolicy.Rule) {
	t.Helper()
	if rule.ID == "" {
		rule.ID = rule.Name
	}
	rule.Enabled = true
	if err := db.CreateCELPolicyRule(rule); err != nil {
		t.Fatalf("CreateCELPolicyRule(%s): %v", rule.Name, err)
	}
}

// sshSubjectKey returns a fresh authorized_keys line to be certified.
func sshSubjectKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestLegacySSHSignEndpointIsGated(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	storeRule(t, db, &celpolicy.Rule{
		Kind: celpolicy.KindSigning, Name: "no-root", Effect: celpolicy.EffectDeny,
		Expression: `signing.ssh.principals.exists(p, p == "root")`,
		Message:    "an SSH certificate may not name root",
	})
	user := &models.UserInfo{Subject: "ops@example.com", Roles: []string{"admin"}}

	body := `{"public_key": ` + quoteJSON(sshSubjectKey(t)) + `, "principals": ["root"], "cert_type": "user"}`
	rec := httptest.NewRecorder()
	api.SignCertificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign", user, ca.ID, body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sign = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	var denied models.PolicyDeniedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &denied); err != nil {
		t.Fatalf("decoding the refusal: %v (%s)", err, rec.Body.String())
	}
	if denied.Code != "policy_denied" {
		t.Errorf("code = %q", denied.Code)
	}
	if len(denied.Violations) != 1 || denied.Violations[0].Rule != "no-root" {
		t.Fatalf("violations = %+v", denied.Violations)
	}
	if denied.Violations[0].Message != "an SSH certificate may not name root" {
		t.Errorf("message = %q", denied.Violations[0].Message)
	}

	// A permitted request still signs, through the same endpoint.
	body = `{"public_key": ` + quoteJSON(sshSubjectKey(t)) + `, "principals": ["deploy"], "cert_type": "user"}`
	rec = httptest.NewRecorder()
	api.SignCertificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign", user, ca.ID, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("permitted sign = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out models.SignResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !strings.Contains(out.Certificate, "-cert-v01@openssh.com") {
		t.Errorf("the response should carry an OpenSSH certificate: %q", out.Certificate)
	}
}

// TestLegacySSHSignSeesTheResolvedCertificate proves the facts come from the
// certificate the endpoint would sign, including the extension defaults it
// applies when the caller names none — not from the request body.
func TestLegacySSHSignSeesTheResolvedCertificate(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	storeRule(t, db, &celpolicy.Rule{
		Kind: celpolicy.KindSigning, Name: "no-port-forwarding", Effect: celpolicy.EffectDeny,
		Expression: `"permit-port-forwarding" in signing.ssh.extensions`,
		Message:    "port forwarding is not permitted on this CA",
	})
	user := &models.UserInfo{Subject: "ops@example.com", Roles: []string{"admin"}}
	// The body names no extensions at all; the endpoint's user-certificate
	// defaults add permit-port-forwarding, and the rule must see it.
	body := `{"public_key": ` + quoteJSON(sshSubjectKey(t)) + `, "principals": ["deploy"], "cert_type": "user"}`
	rec := httptest.NewRecorder()
	api.SignCertificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign", user, ca.ID, body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sign = %d, want 422 (the rule must see the resolved defaults): %s", rec.Code, rec.Body.String())
	}
}

func TestLegacyX509SignEndpointIsGatedByCertificateRules(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	// A *certificate* rule — the kind an operator already wrote for the issuance
	// path. The point of the gate here is that it binds on this endpoint too.
	storeRule(t, db, &celpolicy.Rule{
		Name: "no-wildcards", Effect: celpolicy.EffectDeny,
		Expression: `request.wildcard`,
		Message:    "a wildcard certificate requires the pki.wildcard entitlement",
	})
	user := &models.UserInfo{Subject: "ops@example.com", Roles: []string{"admin"}}

	body := `{"csr": ` + quoteJSON(string(testCSR(t, "*.example.com"))) + `}`
	rec := httptest.NewRecorder()
	api.SignX509Certificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign-x509", user, ca.ID, body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sign-x509 = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pki.wildcard") {
		t.Errorf("the operator's wording must reach the caller: %s", rec.Body.String())
	}

	// A non-wildcard request goes through.
	body = `{"csr": ` + quoteJSON(string(testCSR(t, "www.example.com"))) + `}`
	rec = httptest.NewRecorder()
	api.SignX509Certificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign-x509", user, ca.ID, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("permitted sign-x509 = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestLegacyX509SignIsLabelledAsRawSigning lets a rule treat the endpoint
// differently from an issuance surface, which matters because it has no profile.
func TestLegacyX509SignIsLabelledAsRawSigning(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	storeRule(t, db, &celpolicy.Rule{
		Name: "rawsign-needs-admin", Effect: celpolicy.EffectDeny,
		Expression: `request.source == "rawsign" && !("admin" in principal.roles)`,
		Message:    "the raw signing endpoint is restricted to administrators",
	})
	body := `{"csr": ` + quoteJSON(string(testCSR(t, "www.example.com"))) + `}`

	// An issuer (not an admin) is refused…
	issuer := &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}
	rec := httptest.NewRecorder()
	api.SignX509Certificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign-x509", issuer, ca.ID, body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("issuer sign-x509 = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	// …and an admin is not.
	admin := &models.UserInfo{Subject: "admin", Roles: []string{"admin"}}
	rec = httptest.NewRecorder()
	api.SignX509Certificate(rec, signReq(http.MethodPost, "/api/keys/legacy-ca/sign-x509", admin, ca.ID, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin sign-x509 = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestRawX509PolicyGateFailsClosed(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	csr := testCSR(t, "www.example.com")
	user := &models.UserInfo{Subject: "ops", Roles: []string{"admin"}}
	r := signReq(http.MethodPost, "/api/keys/legacy-ca/sign-x509", user, ca.ID, "")

	// With no rules there is nothing to check and nothing to refuse.
	if err := api.checkRawX509SignPolicy(r, ca, csr, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("an empty rule set must permit: %v", err)
	}
	storeRule(t, db, &celpolicy.Rule{Name: "any", Expression: `true`})

	// An unreadable rule set must refuse — and not as a policy denial, because
	// the caller did nothing wrong.
	db.Close()
	err := api.checkRawX509SignPolicy(r, ca, csr, time.Now().Add(24*time.Hour))
	if err == nil {
		t.Fatal("an unreadable rule set must refuse the signature")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
	if !strings.Contains(err.Error(), "pre-signing policy check failed") {
		t.Errorf("the failure should say what could not be checked: %v", err)
	}
	// A transport must be able to tell a gate failure from a refusal: the first
	// is a 503 the caller should retry, the second a 422 they must fix.
	if !errors.Is(err, celpolicy.ErrUnavailable) {
		t.Errorf("a gate failure must carry celpolicy.ErrUnavailable: %v", err)
	}
	rec := httptest.NewRecorder()
	if !writeSignPolicyDenied(rec, err) || rec.Code != http.StatusServiceUnavailable {
		t.Errorf("a gate failure should be answered 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sql:") {
		t.Errorf("the store's own error must not reach the client: %s", rec.Body.String())
	}
}

// TestLegacySSHPolicyGateFailsClosed is the same proof for the SSH endpoint's
// gate, which reaches the rule table through signpolicy.
func TestLegacySSHPolicyGateFailsClosed(t *testing.T) {
	api, db, ca := legacySignAPI(t)
	storeRule(t, db, &celpolicy.Rule{Kind: celpolicy.KindSigning, Name: "any", Expression: `true`})
	cert, err := pki.BuildSSHCertificate([]byte(sshSubjectKey(t)), ssh.UserCert, "ops",
		[]string{"deploy"}, time.Now(), time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("BuildSSHCertificate: %v", err)
	}
	user := &models.UserInfo{Subject: "ops", Roles: []string{"admin"}}
	r := signReq(http.MethodPost, "/api/keys/legacy-ca/sign", user, ca.ID, "")
	if err := api.checkLegacySSHSignPolicy(r, ca, cert, ""); err != nil {
		t.Fatalf("a satisfied rule must permit: %v", err)
	}
	db.Close()
	if err := api.checkLegacySSHSignPolicy(r, ca, cert, ""); err == nil {
		t.Error("an unreadable rule set must refuse the signature")
	} else if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
}
