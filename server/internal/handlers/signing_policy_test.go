//go:build sqlite

package handlers

// Tests for the signing half of the policy REST surface (Task 224): the kind
// discriminator on the rule endpoints, the signing vocabulary reference, the
// signing dry-run, and — the part that matters operationally — that a refused
// signature comes back as 422 with the operator's own reasons rather than as a
// 500 or a bare "forbidden".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestSigningPolicyCRUDThroughTheKindParameter(t *testing.T) {
	api, _ := tenantAPI(t)

	rec := createPolicy(api, policyAdmin(), `{
		"kind": "signing",
		"name": "no-root-principals",
		"expression": "signing.ssh.principals.exists(p, p == \"root\")",
		"effect": "deny",
		"message": "an SSH certificate may not name root",
		"keys": ["ssh-user-ca", " "],
		"operations": ["ssh-certificate"],
		"priority": 5
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	created := decodePolicy(t, rec)
	if created.Kind != celpolicy.KindSigning {
		t.Errorf("kind = %q", created.Kind)
	}
	if len(created.Keys) != 1 || created.Keys[0] != "ssh-user-ca" {
		t.Errorf("keys = %v; blank selectors must be dropped", created.Keys)
	}
	if len(created.Operations) != 1 || created.Operations[0] != "ssh-certificate" {
		t.Errorf("operations = %v", created.Operations)
	}

	// A certificate rule alongside it, so the filters have something to separate.
	rec = createPolicy(api, policyAdmin(), `{
		"name": "one-san",
		"expression": "request.san_count <= 1"
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create(certificate) = %d: %s", rec.Code, rec.Body.String())
	}

	// The unfiltered listing is one table of rules.
	if all := listPolicies(t, api, policyIssuer()); len(all) != 2 {
		t.Errorf("the listing has %d rules, want both kinds", len(all))
	}
	// ?kind= narrows it.
	for kind, want := range map[string]string{"signing": "no-root-principals", "certificate": "one-san"} {
		rules := listPoliciesOfKind(t, api, policyIssuer(), kind)
		if len(rules) != 1 || rules[0].Name != want {
			t.Errorf("?kind=%s returned %v, want [%s]", kind, ruleNames(rules), want)
		}
	}
	// An unknown kind is an error, not a silent default.
	rec = httptest.NewRecorder()
	api.ListIssuancePolicies(rec, reqAs(http.MethodGet, "/api/issuance-policies?kind=sign", policyIssuer(), "", ""))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("?kind=sign = %d, want 400", rec.Code)
	}

	// Updating keeps the kind without having to repeat it.
	rec = updatePolicy(api, policyAdmin(), created.ID, `{
		"name": "no-root-principals",
		"expression": "signing.ssh.principals.exists(p, p.lowerAscii() == \"root\")",
		"effect": "deny",
		"priority": 7
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodePolicy(t, rec); got.Kind != celpolicy.KindSigning || got.Priority != 7 {
		t.Errorf("update changed the kind or lost a field: %+v", got)
	}

	// Changing the kind is refused: the expression was written for one
	// vocabulary, and reinterpreting it would usually stop it compiling.
	rec = updatePolicy(api, policyAdmin(), created.ID, `{"kind": "certificate", "expression": "request.san_count <= 1"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("changing the kind = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func listPoliciesOfKind(t *testing.T, api *API, user *models.UserInfo, kind string) []celpolicy.Rule {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ListIssuancePolicies(rec, reqAs(http.MethodGet, "/api/issuance-policies?kind="+kind, user, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list(kind=%s) = %d: %s", kind, rec.Code, rec.Body.String())
	}
	var out []celpolicy.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	return out
}

func TestSigningPolicyRejectsTheWrongVocabulary(t *testing.T) {
	api, _ := tenantAPI(t)
	// A signing rule reaching for a certificate fact must be rejected where it is
	// written, with a column: it would otherwise be a rule that never fires.
	rec := createPolicy(api, policyAdmin(), `{
		"kind": "signing", "name": "wrong", "expression": "request.dns_names.size() == 0"
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "request") {
		t.Errorf("the error should name the offending reference: %s", rec.Body.String())
	}
	// And the keys/operations selectors belong to a signing rule only.
	rec = createPolicy(api, policyAdmin(), `{
		"name": "cert-rule", "expression": "request.san_count <= 1", "keys": ["k"]
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a certificate rule with a key selector = %d, want 400", rec.Code)
	}
	// An operation that does not exist is rejected too.
	rec = createPolicy(api, policyAdmin(), `{
		"kind": "signing", "name": "bad-op", "expression": "true", "operations": ["timestamp"]
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown operation = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestSigningPolicyValidateUsesTheSigningEnvironment(t *testing.T) {
	api, _ := tenantAPI(t)
	validate := func(kind, expr string) map[string]interface{} {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"kind": kind, "expression": expr})
		rec := httptest.NewRecorder()
		api.ValidateIssuancePolicy(rec,
			reqAs(http.MethodPost, "/api/issuance-policies/validate", policyIssuer(), "", string(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("validate = %d: %s", rec.Code, rec.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		return out
	}
	if out := validate("signing", `signing.ssh.cert_type == "host"`); out["valid"] != true {
		t.Errorf("a valid signing expression reported %v", out)
	}
	if out := validate("signing", `request.wildcard`); out["valid"] != false {
		t.Errorf("a certificate expression must not validate as a signing rule: %v", out)
	}
	if out := validate("", `request.wildcard`); out["valid"] != true {
		t.Errorf("the default kind is still the certificate one: %v", out)
	}
	// The result type is reported per kind, which is what the editor shows.
	if out := validate("signing", `"refused"`); out["result_type"] != "string" {
		t.Errorf("result_type = %v", out["result_type"])
	}
}

func TestSigningPolicyReference(t *testing.T) {
	api, _ := tenantAPI(t)
	fetch := func(query string) celpolicy.Reference {
		t.Helper()
		rec := httptest.NewRecorder()
		api.IssuancePolicyReference(rec,
			reqAs(http.MethodGet, "/api/issuance-policies/reference"+query, policyIssuer(), "", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("reference%s = %d: %s", query, rec.Code, rec.Body.String())
		}
		var ref celpolicy.Reference
		if err := json.Unmarshal(rec.Body.Bytes(), &ref); err != nil {
			t.Fatalf("decoding the reference: %v", err)
		}
		return ref
	}
	signing := fetch("?kind=signing")
	if signing.Kind != celpolicy.KindSigning {
		t.Errorf("kind = %q", signing.Kind)
	}
	var names []string
	for _, v := range signing.Variables {
		names = append(names, v.Name)
	}
	if !contains(names, "signing") || contains(names, "request") {
		t.Errorf("the signing reference advertises %v", names)
	}
	if len(signing.Operations) == 0 || len(signing.Examples) == 0 {
		t.Error("the signing reference must carry the operations and worked examples")
	}
	if cert := fetch(""); cert.Kind != celpolicy.KindCertificate {
		t.Errorf("the default reference is %q", cert.Kind)
	}
}

func TestSigningPolicyDryRun(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := createPolicy(api, policyAdmin(), `{
		"kind": "signing",
		"name": "artifacts-need-a-timestamp",
		"expression": "signing.operation != \"artifact\" || signing.artifact.timestamped",
		"message": "an artifact signature must be timestamped"
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	// A signature the rule refuses…
	resp := signingPolicyTest(t, api, `{
		"kind": "signing",
		"signing_input": {"signing": {"operation": "artifact", "artifact": {"present": true, "signer": "release", "level": "b"}}}
	}`)
	if resp.Decision.Allowed {
		t.Error("an untimestamped artifact signature must be refused")
	}
	if len(resp.Decision.Violations) != 1 || resp.Decision.Violations[0].Message != "an artifact signature must be timestamped" {
		t.Errorf("violations = %+v", resp.Decision.Violations)
	}
	if resp.Kind != celpolicy.KindSigning {
		t.Errorf("the response should name the kind: %q", resp.Kind)
	}
	if resp.SigningInput == nil || resp.SigningInput.Signing.Operation != "artifact" {
		t.Errorf("the facts must be echoed: %+v", resp.SigningInput)
	}
	// …and one it permits.
	resp = signingPolicyTest(t, api, `{
		"kind": "signing",
		"signing_input": {"signing": {"operation": "artifact", "artifact": {"present": true, "level": "t", "timestamped": true}}}
	}`)
	if !resp.Decision.Allowed {
		t.Errorf("a timestamped signature must be permitted: %+v", resp.Decision.Violations)
	}

	// The operation is inferred from the facts an operator filled in.
	resp = signingPolicyTest(t, api, `{
		"kind": "signing",
		"signing_input": {"signing": {"ssh": {"present": true, "cert_type": "user", "principals": ["ops"]}}}
	}`)
	if resp.SigningInput.Signing.Operation != celpolicy.OpSignSSHCert {
		t.Errorf("inferred operation = %q, want ssh-certificate", resp.SigningInput.Signing.Operation)
	}
	if !resp.Decision.Allowed {
		t.Errorf("the artifact rule must not apply to an SSH certificate: %+v", resp.Decision.Violations)
	}

	// An ad-hoc expression, compiled in the signing environment.
	resp = signingPolicyTest(t, api, `{
		"kind": "signing",
		"expression": "signing.ssh.principals.all(p, p != \"root\")",
		"message": "no root",
		"signing_input": {"signing": {"ssh": {"present": true, "principals": ["root"]}}}
	}`)
	if resp.Decision.Allowed || resp.Decision.Violations[0].Message != "no root" {
		t.Errorf("the ad-hoc signing expression did not refuse: %+v", resp.Decision)
	}

	// A certificate rule cannot be dry-run as a signing one.
	rec = httptest.NewRecorder()
	api.CreateIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies", policyAdmin(), "",
		`{"name": "cert-rule", "expression": "request.san_count <= 1"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create(certificate) = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	api.TestIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/test", policyIssuer(), "",
		`{"kind": "signing", "rule": "cert-rule"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("dry-running a certificate rule as a signing one = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func signingPolicyTest(t *testing.T, api *API, body string) policyTestResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	api.TestIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/test", policyIssuer(), "", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	var out policyTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the dry-run: %v (%s)", err, rec.Body.String())
	}
	return out
}

func TestSigningPolicyDryRunOnlyConsidersSigningRules(t *testing.T) {
	api, _ := tenantAPI(t)
	for _, body := range []string{
		`{"name": "cert-rule", "expression": "request.san_count <= 1"}`,
		`{"kind": "signing", "name": "sign-rule", "expression": "signing.key.name != \"blocked\""}`,
	} {
		if rec := createPolicy(api, policyAdmin(), body); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
	}
	resp := signingPolicyTest(t, api, `{"kind": "signing", "signing_input": {"signing": {"key": {"name": "ok"}}}}`)
	if len(resp.Rules) != 1 || resp.Rules[0] != "sign-rule" {
		t.Errorf("the signing dry-run considered %v, want [sign-rule]", resp.Rules)
	}
	// And the certificate dry-run is unaffected by the signing rule.
	rec := httptest.NewRecorder()
	api.TestIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/test", policyIssuer(), "",
		`{"input": {"request": {"san_count": 1}}}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("certificate test = %d: %s", rec.Code, rec.Body.String())
	}
	var out policyTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0] != "cert-rule" {
		t.Errorf("the certificate dry-run considered %v, want [cert-rule]", out.Rules)
	}
}

// TestPolicyKindMustBeKnown pins that an unrecognized kind is an error rather
// than a silent default. A rule stored as "certificate" because its author
// typed "sign" would be a rule whose expression was written for the other
// vocabulary — i.e. one that does not compile, and therefore refuses every
// certificate in its scope.
func TestPolicyKindMustBeKnown(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := createPolicy(api, policyAdmin(), `{
		"kind": "sign", "name": "typo", "expression": "signing.key.name != \"x\""
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with kind=sign = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `kind \"sign\"`) {
		t.Errorf("the error should name the offending kind: %s", rec.Body.String())
	}

	// And on an update of a stored rule.
	rec = createPolicy(api, policyAdmin(), `{"kind": "signing", "name": "ok", "expression": "signing.key.name != \"x\""}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	id := decodePolicy(t, rec).ID
	rec = updatePolicy(api, policyAdmin(), id, `{"kind": "sign", "expression": "signing.key.name != \"y\""}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("update with kind=sign = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}
