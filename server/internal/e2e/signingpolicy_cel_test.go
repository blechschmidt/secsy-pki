//go:build sqlite

// End-to-end verification of the CEL signing-restriction engine (Task 224)
// through the real HTTP stack.
//
// The unit tests prove each gate decides correctly given a fact set, and the
// service tests prove each service assembles that fact set. What only an
// end-to-end test can prove is the property the feature is for: that a rule an
// operator writes through the API is evaluated inside the signing path of a
// *different* surface, with the verified claims of the caller's token, the URL
// the request arrived on and its body parameters all present — and that the
// refusal comes back as a 422 naming the rule and its own reason.
//
// It uses the same wired server as the issuance-policy end-to-end suite (see
// setupPolicyEnv), so the two halves of the engine are exercised through one
// route table, one middleware chain and one rule table.
package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// sshCA initializes an SSH certificate authority through the API, as the
// console's SSH view does.
func (e *policyEnv) sshCA(t *testing.T, label string) string {
	t.Helper()
	code, raw := e.do(t, http.MethodPost, "/api/ssh/cas", rootAuth,
		`{"label":"`+label+`","key_type":"ed25519"}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("creating the SSH CA = %d: %s", code, raw)
	}
	var ca models.CA
	if err := json.Unmarshal(raw, &ca); err != nil {
		t.Fatalf("decoding the SSH CA: %v (%s)", err, raw)
	}
	if ca.ID == "" {
		t.Fatalf("the SSH CA has no id: %s", raw)
	}
	return ca.ID
}

// sshPublicKey returns a fresh authorized_keys line to be certified.
func sshPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// signSSH asks for an OpenSSH certificate as the Bearer caller.
func (e *policyEnv) signSSH(t *testing.T, caID, token, body string) (int, models.PolicyDeniedResponse, []byte) {
	t.Helper()
	code, raw := e.do(t, http.MethodPost, "/api/ssh/cas/"+caID+"/sign", "Bearer "+token, body)
	var denied models.PolicyDeniedResponse
	if code == http.StatusUnprocessableEntity {
		if err := json.Unmarshal(raw, &denied); err != nil {
			t.Fatalf("decoding the refusal: %v (%s)", err, raw)
		}
	}
	return code, denied, raw
}

// TestSigningPolicyRefusesAnSSHCertificateWithAReason is the headline case: a
// rule written through the API refuses an OpenSSH certificate deep inside the
// SSH authority's signing path, and the requester is told which principal was
// the problem and which rule said so.
func TestSigningPolicyRefusesAnSSHCertificateWithAReason(t *testing.T) {
	e := setupPolicyEnv(t)
	caID := e.sshCA(t, "signing-policy-ssh-ca")
	e.addPolicy(t, `{
		"kind": "signing",
		"name": "no-privileged-principals",
		"description": "an SSH certificate may not name a shared privileged account",
		"expression": "signing.ssh.principals.filter(p, p.lowerAscii() in [\"root\", \"admin\"]).map(p, \"principal \" + p + \" is a shared privileged account; use a named account and sudo\")",
		"operations": ["ssh-certificate"]
	}`)
	token := e.mintToken(t, nil)
	pub := sshPublicKey(t)

	code, denied, raw := e.signSSH(t, caID, token,
		`{"public_key":"`+pub+`","principals":["root"],"cert_type":"user"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("signing = %d, want 422: %s", code, raw)
	}
	if denied.Code != "policy_denied" {
		t.Errorf("code = %q", denied.Code)
	}
	if len(denied.Violations) != 1 {
		t.Fatalf("violations = %+v", denied.Violations)
	}
	if denied.Violations[0].Rule != "no-privileged-principals" {
		t.Errorf("rule = %q", denied.Violations[0].Rule)
	}
	if !strings.Contains(denied.Violations[0].Message, "principal root is a shared privileged account") {
		t.Errorf("message = %q", denied.Violations[0].Message)
	}

	// Nothing was signed and nothing was recorded.
	code, raw = e.do(t, http.MethodGet, "/api/ssh/cas/"+caID+"/certificates", rootAuth, "")
	if code != http.StatusOK {
		t.Fatalf("listing certificates = %d: %s", code, raw)
	}
	if strings.Contains(string(raw), `"key_id"`) && strings.Contains(string(raw), "root") {
		t.Errorf("a refused certificate must not reach the inventory: %s", raw)
	}

	// An ordinary principal is signed through the same endpoint.
	code, _, raw = e.signSSH(t, caID, token,
		`{"public_key":"`+pub+`","principals":["deploy"],"cert_type":"user"}`)
	if code != http.StatusCreated {
		t.Fatalf("permitted signing = %d, want 201: %s", code, raw)
	}
	if !strings.Contains(string(raw), "-cert-v01@openssh.com") {
		t.Errorf("the response should carry an OpenSSH certificate: %s", raw)
	}
}

// TestSigningPolicyReadsTheVerifiedTokenAndBody proves the request-side facts
// reach a rule evaluated inside the SSH authority — the claims of a token the
// OIDC verifier accepted, the URL the request arrived on, and a body parameter
// the certificate itself does not carry.
func TestSigningPolicyReadsTheVerifiedTokenAndBody(t *testing.T) {
	e := setupPolicyEnv(t)
	caID := e.sshCA(t, "signing-policy-claims-ca")
	e.addPolicy(t, `{
		"kind": "signing",
		"name": "host-certs-need-an-entitlement-and-a-ticket",
		"expression": "signing.ssh.cert_type != \"host\" ? \"\" : ((has(jwt.entitlements) && \"ssh.host\" in jwt.entitlements) ? (has(body.reason) && string(body.reason).matches(\"^CHG-[0-9]{4,}$\") ? \"\" : \"a host certificate needs a \\\"reason\\\" naming a change ticket\") : \"a host certificate requires the ssh.host entitlement in your token\")",
		"keys": ["signing-policy-claims-ca"]
	}`)
	pub := sshPublicKey(t)
	body := `{"public_key":"` + pub + `","principals":["host1.example.com"],"cert_type":"host","reason":"CHG-10482"}`

	// No entitlement: refused, naming the entitlement.
	code, denied, raw := e.signSSH(t, caID, e.mintToken(t, nil), body)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("signing without the entitlement = %d, want 422: %s", code, raw)
	}
	if len(denied.Violations) != 1 || !strings.Contains(denied.Violations[0].Message, "ssh.host entitlement") {
		t.Fatalf("violations = %+v", denied.Violations)
	}

	// With the entitlement but no ticket in the body: refused for the other reason.
	entitled := e.mintToken(t, map[string]interface{}{"entitlements": []string{"ssh.host"}})
	code, denied, raw = e.signSSH(t, caID, entitled,
		`{"public_key":"`+pub+`","principals":["host1.example.com"],"cert_type":"host"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("signing without a ticket = %d, want 422: %s", code, raw)
	}
	if len(denied.Violations) != 1 || !strings.Contains(denied.Violations[0].Message, "change ticket") {
		t.Fatalf("violations = %+v", denied.Violations)
	}

	// With both: signed.
	code, _, raw = e.signSSH(t, caID, entitled, body)
	if code != http.StatusCreated {
		t.Fatalf("signing with both = %d, want 201: %s", code, raw)
	}

	// And a user certificate is untouched by the rule, because it selects on the
	// certificate type rather than on the caller.
	code, _, raw = e.signSSH(t, caID, e.mintToken(t, nil),
		`{"public_key":"`+pub+`","principals":["deploy"],"cert_type":"user"}`)
	if code != http.StatusCreated {
		t.Fatalf("user certificate = %d, want 201: %s", code, raw)
	}
}

// TestSigningPolicySeesTheClampedCertificate proves the facts come from the
// certificate that would be signed rather than from the request: the CA's own
// validity ceiling has already been applied when the rule runs, so a rule
// written against the certificate's lifetime cannot be fooled by asking for
// more than the CA will grant.
func TestSigningPolicySeesTheClampedCertificate(t *testing.T) {
	e := setupPolicyEnv(t)
	caID := e.sshCA(t, "signing-policy-clamp-ca")
	// The CA will sign at most 1h.
	code, raw := e.do(t, http.MethodPut, "/api/ssh/cas/"+caID+"/max-validity", rootAuth,
		`{"max_validity_seconds":3600}`)
	if code != http.StatusOK {
		t.Fatalf("setting the ceiling = %d: %s", code, raw)
	}
	e.addPolicy(t, `{
		"kind": "signing",
		"name": "ssh-validity-ceiling",
		"expression": "signing.ssh.validity <= duration(\"2h\")",
		"message": "this CA signs certificates valid for at most 2h"
	}`)
	pub := sshPublicKey(t)

	// A 24h request is clamped to 1h by the CA, so the 2h rule is satisfied —
	// a rule evaluated against the *request* would have refused it.
	code, _, raw = e.signSSH(t, caID, e.mintToken(t, nil),
		`{"public_key":"`+pub+`","principals":["deploy"],"validity_seconds":86400}`)
	if code != http.StatusCreated {
		t.Fatalf("a clamped request must be signed = %d: %s", code, raw)
	}
	if !strings.Contains(string(raw), `"clamped_by_ca_max_validity":true`) {
		t.Errorf("the response should report the clamp: %s", raw)
	}
}

// TestSigningPolicyMonitorModeSignsAndRecords proves a monitor-mode rule is
// adoptable: it records what it would have refused and signs anyway.
func TestSigningPolicyMonitorModeSignsAndRecords(t *testing.T) {
	e := setupPolicyEnv(t)
	caID := e.sshCA(t, "signing-policy-monitor-ca")
	e.addPolicy(t, `{
		"kind": "signing",
		"name": "watching-privileged-principals",
		"mode": "monitor",
		"effect": "deny",
		"expression": "signing.ssh.principals.exists(p, p == \"root\")",
		"message": "would refuse: root"
	}`)
	pub := sshPublicKey(t)
	code, _, raw := e.signSSH(t, caID, e.mintToken(t, nil),
		`{"public_key":"`+pub+`","principals":["root"],"cert_type":"user"}`)
	if code != http.StatusCreated {
		t.Fatalf("a monitor-mode rule must not block = %d: %s", code, raw)
	}
	// The finding is written down, which is the only thing that makes monitor
	// mode useful.
	events, _, err := e.db.ListEvents("sign.policy", "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	found := false
	for _, ev := range events {
		if strings.Contains(ev.Detail, "watching-privileged-principals[monitor]") {
			found = true
			if ev.Result != "success" {
				t.Errorf("a monitor finding on a signed certificate is a success, got %q", ev.Result)
			}
		}
	}
	if !found {
		t.Errorf("the monitor finding must be recorded; events = %+v", events)
	}
}

// TestSigningPolicyDryRunMatchesTheGate proves the dry-run an operator uses
// before switching a rule on agrees with what the gate then does.
func TestSigningPolicyDryRunMatchesTheGate(t *testing.T) {
	e := setupPolicyEnv(t)
	caID := e.sshCA(t, "signing-policy-dryrun-ca")
	rule := e.addPolicy(t, `{
		"kind": "signing",
		"name": "no-forwarding",
		"enabled": false,
		"effect": "deny",
		"expression": "\"permit-port-forwarding\" in signing.ssh.extensions",
		"message": "port forwarding is not permitted by this CA"
	}`)
	if rule.Enabled {
		t.Fatal("the rule was created enabled; the dry-run is supposed to come first")
	}

	// The dry-run refuses the default user certificate (the profile grants
	// permit-port-forwarding), while the rule is still switched off.
	code, raw := e.do(t, http.MethodPost, "/api/issuance-policies/test", rootAuth, `{
		"kind": "signing",
		"rule": "no-forwarding",
		"signing_input": {"signing": {"operation": "ssh-certificate", "ssh": {
			"present": true, "cert_type": "user", "principals": ["deploy"],
			"extensions": ["permit-pty", "permit-port-forwarding"]}}}
	}`)
	if code != http.StatusOK {
		t.Fatalf("dry-run = %d: %s", code, raw)
	}
	var out struct {
		Kind     celpolicy.Kind     `json:"kind"`
		Decision celpolicy.Decision `json:"decision"`
		Rules    []string           `json:"rules"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding the dry-run: %v (%s)", err, raw)
	}
	if out.Kind != celpolicy.KindSigning {
		t.Errorf("kind = %q", out.Kind)
	}
	if out.Decision.Allowed {
		t.Fatalf("the dry-run should refuse: %+v", out.Decision)
	}

	// Switched off, the gate signs.
	pub := sshPublicKey(t)
	code, _, raw = e.signSSH(t, caID, e.mintToken(t, nil),
		`{"public_key":"`+pub+`","principals":["deploy"],"cert_type":"user"}`)
	if code != http.StatusCreated {
		t.Fatalf("a disabled rule must not block = %d: %s", code, raw)
	}

	// Switched on, it refuses exactly what the dry-run said it would.
	code, raw = e.do(t, http.MethodPut, "/api/issuance-policies/"+rule.ID+"/enabled", rootAuth, `{"enabled":true}`)
	if code != http.StatusOK {
		t.Fatalf("enabling = %d: %s", code, raw)
	}
	code, denied, raw := e.signSSH(t, caID, e.mintToken(t, nil),
		`{"public_key":"`+pub+`","principals":["deploy"],"cert_type":"user"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("signing = %d, want 422: %s", code, raw)
	}
	if len(denied.Violations) != 1 || denied.Violations[0].Message != "port forwarding is not permitted by this CA" {
		t.Errorf("violations = %+v", denied.Violations)
	}
}

// TestSigningPolicyScopeByKeyAndOperation proves the selectors: a rule narrowed
// to one key and one operation does not touch another CA's certificates.
func TestSigningPolicyScopeByKeyAndOperation(t *testing.T) {
	e := setupPolicyEnv(t)
	guarded := e.sshCA(t, "guarded-ssh-ca")
	open := e.sshCA(t, "open-ssh-ca")
	e.addPolicy(t, `{
		"kind": "signing",
		"name": "guarded-ca-is-admin-only",
		"keys": ["guarded-ssh-ca"],
		"operations": ["ssh-certificate"],
		"expression": "has(jwt.entitlements) && \"ssh.privileged\" in jwt.entitlements",
		"message": "this CA signs only for holders of the ssh.privileged entitlement"
	}`)
	pub := sshPublicKey(t)
	body := `{"public_key":"` + pub + `","principals":["deploy"],"cert_type":"user"}`

	code, denied, raw := e.signSSH(t, guarded, e.mintToken(t, nil), body)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("the guarded CA should refuse = %d: %s", code, raw)
	}
	if len(denied.Violations) != 1 || !strings.Contains(denied.Violations[0].Message, "ssh.privileged") {
		t.Errorf("violations = %+v", denied.Violations)
	}
	// The other CA is unaffected by a rule scoped to the first.
	code, _, raw = e.signSSH(t, open, e.mintToken(t, nil), body)
	if code != http.StatusCreated {
		t.Fatalf("the unscoped CA should sign = %d: %s", code, raw)
	}
	// And the entitled caller gets a certificate from the guarded one.
	code, _, raw = e.signSSH(t, guarded,
		e.mintToken(t, map[string]interface{}{"entitlements": []string{"ssh.privileged"}}), body)
	if code != http.StatusCreated {
		t.Fatalf("the entitled caller should be signed = %d: %s", code, raw)
	}
}

// TestSigningPolicyRuleEditingIsRestricted proves the administration surface is
// gated the same way for both kinds: a signing rule is as sensitive as an
// issuance rule, and a caller who cannot configure CAs cannot write either.
func TestSigningPolicyRuleEditingIsRestricted(t *testing.T) {
	e := setupPolicyEnv(t)
	token := e.mintToken(t, nil) // an issuer, not a configurator
	code, raw := e.do(t, http.MethodPost, "/api/issuance-policies", "Bearer "+token, `{
		"kind": "signing", "name": "sneaky", "expression": "true"
	}`)
	if code != http.StatusForbidden {
		t.Fatalf("an issuer storing a signing rule = %d, want 403: %s", code, raw)
	}
	// Reading and dry-running are open to any role: an issuer who gets refused
	// needs to be able to look up the rule that refused them.
	code, raw = e.do(t, http.MethodGet, "/api/issuance-policies?kind=signing", "Bearer "+token, "")
	if code != http.StatusOK {
		t.Fatalf("an issuer listing signing rules = %d, want 200: %s", code, raw)
	}
	code, raw = e.do(t, http.MethodGet, "/api/issuance-policies/reference?kind=signing", "Bearer "+token, "")
	if code != http.StatusOK {
		t.Fatalf("an issuer reading the signing reference = %d, want 200: %s", code, raw)
	}
	if !strings.Contains(string(raw), `"signing"`) {
		t.Errorf("the signing reference should document the signing variable: %s", raw)
	}
}
