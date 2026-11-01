//go:build sqlite

package handlers

// Tests for the issuance-policy REST surface (Task 223) — the endpoints behind
// the console's rule editor. Two things are load-bearing here and the rest is
// CRUD: an expression that does not compile must never reach the database (a row
// like that would refuse every certificate under its scope), and a policy
// refusal must come back to the requester as something they can act on rather
// than as "forbidden".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func policyAdmin() *models.UserInfo {
	return &models.UserInfo{Subject: "admin", Roles: []string{"admin"}}
}
func policyIssuer() *models.UserInfo {
	return &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}
}
func policyNobody() *models.UserInfo { return &models.UserInfo{Subject: "nobody"} }

// createPolicy drives POST /api/issuance-policies.
func createPolicy(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.CreateIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies", user, "", body))
	return rec
}

func updatePolicy(api *API, user *models.UserInfo, id, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.UpdateIssuancePolicy(rec, reqAs(http.MethodPut, "/api/issuance-policies/"+id, user, id, body))
	return rec
}

func getPolicy(api *API, user *models.UserInfo, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.GetIssuancePolicy(rec, reqAs(http.MethodGet, "/api/issuance-policies/"+id, user, id, ""))
	return rec
}

func deletePolicy(api *API, user *models.UserInfo, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.DeleteIssuancePolicy(rec, reqAs(http.MethodDelete, "/api/issuance-policies/"+id, user, id, ""))
	return rec
}

func togglePolicy(api *API, user *models.UserInfo, id string, enabled bool) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	body := `{"enabled":false}`
	if enabled {
		body = `{"enabled":true}`
	}
	api.SetIssuancePolicyEnabled(rec, reqAs(http.MethodPut, "/api/issuance-policies/"+id+"/enabled", user, id, body))
	return rec
}

func listPolicies(t *testing.T, api *API, user *models.UserInfo) []celpolicy.Rule {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ListIssuancePolicies(rec, reqAs(http.MethodGet, "/api/issuance-policies", user, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	var out []celpolicy.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	return out
}

func decodePolicy(t *testing.T, rec *httptest.ResponseRecorder) celpolicy.Rule {
	t.Helper()
	var r celpolicy.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decoding the rule: %v (%s)", err, rec.Body.String())
	}
	return r
}

func TestPolicyCRUD(t *testing.T) {
	api, db := tenantAPI(t)

	rec := createPolicy(api, policyAdmin(), `{
		"name": "dns-suffix",
		"description": "names must sit under example.com",
		"expression": "request.dns_names.all(d, d.endsWith(\".example.com\"))",
		"message": "that name is outside example.com",
		"profiles": ["server", " "],
		"cas": ["issuing"],
		"priority": 20
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	created := decodePolicy(t, rec)
	if created.ID == "" {
		t.Fatal("the created rule has no id")
	}
	if !created.Enabled {
		t.Error("a rule created without an explicit enabled flag must be on: an operator who writes a restriction meant it to apply")
	}
	if created.Effect != "" && created.Effect != celpolicy.EffectRequire {
		t.Errorf("effect = %q", created.Effect)
	}
	if len(created.Profiles) != 1 || created.Profiles[0] != "server" {
		t.Errorf("profiles = %v; blank selectors must be dropped", created.Profiles)
	}
	if created.CreatedBy != "admin" {
		t.Errorf("created_by = %q", created.CreatedBy)
	}

	// Readable by id and by name.
	for _, ref := range []string{created.ID, "dns-suffix", "DNS-SUFFIX"} {
		rec := getPolicy(api, policyIssuer(), ref)
		if rec.Code != http.StatusOK {
			t.Fatalf("get(%q) = %d: %s", ref, rec.Code, rec.Body.String())
		}
		if got := decodePolicy(t, rec); got.ID != created.ID {
			t.Errorf("get(%q) returned %q", ref, got.ID)
		}
	}
	if rec := getPolicy(api, policyAdmin(), "nope"); rec.Code != http.StatusNotFound {
		t.Errorf("get(missing) = %d, want 404", rec.Code)
	}

	// Update.
	rec = updatePolicy(api, policyAdmin(), created.ID, `{
		"name": "dns-suffix",
		"expression": "request.dns_names.all(d, d.endsWith(\".corp.example.com\"))",
		"message": "names must sit under corp.example.com",
		"effect": "require",
		"mode": "monitor",
		"priority": 5,
		"enabled": true,
		"fail_open": true
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	updated := decodePolicy(t, rec)
	if !strings.Contains(updated.Expression, "corp.example.com") || updated.Mode != celpolicy.ModeMonitor ||
		updated.Priority != 5 || !updated.FailOpen {
		t.Errorf("the update did not take: %+v", updated)
	}
	if updated.CreatedBy != "admin" || updated.UpdatedBy != "admin" {
		t.Errorf("provenance = %q/%q", updated.CreatedBy, updated.UpdatedBy)
	}
	// The selectors were not re-sent, so they are cleared — a PUT replaces.
	if len(updated.Profiles) != 0 {
		t.Errorf("profiles = %v; a PUT that omits them must clear them", updated.Profiles)
	}

	// Toggle.
	if rec := togglePolicy(api, policyAdmin(), created.ID, false); rec.Code != http.StatusOK {
		t.Fatalf("toggle = %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := db.GetCELPolicyRule(created.ID)
	if stored.Enabled {
		t.Error("the rule is still enabled")
	}
	if !strings.Contains(stored.Expression, "corp.example.com") {
		t.Error("the toggle rewrote the expression")
	}

	// List, then delete.
	if rules := listPolicies(t, api, policyIssuer()); len(rules) != 1 {
		t.Fatalf("list returned %d rules", len(rules))
	}
	if rec := deletePolicy(api, policyAdmin(), created.ID); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if rules := listPolicies(t, api, policyIssuer()); len(rules) != 0 {
		t.Fatalf("list returned %d rules after the delete", len(rules))
	}
	if rec := deletePolicy(api, policyAdmin(), created.ID); rec.Code != http.StatusNotFound {
		t.Errorf("delete(missing) = %d, want 404", rec.Code)
	}
}

// TestPolicyCreateRejectsUncompilableExpressions is the guard that matters: the
// console must not be able to write a rule that then denies everything.
func TestPolicyCreateRejectsUncompilableExpressions(t *testing.T) {
	api, db := tenantAPI(t)
	cases := []struct{ name, body string }{
		{"field typo", `{"name":"a","expression":"request.dsn_names.size() == 0"}`},
		{"syntax error", `{"name":"b","expression":"request.dns_names.all(d, d"}`},
		{"unusable result type", `{"name":"c","expression":"request.validity_days"}`},
		{"no expression", `{"name":"d"}`},
		{"no name", `{"expression":"true"}`},
		{"name with whitespace", `{"name":"my rule","expression":"true"}`},
		{"bad effect", `{"name":"e","expression":"true","effect":"permit"}`},
		{"bad mode", `{"name":"f","expression":"true","mode":"audit"}`},
		{"bad selector", `{"name":"g","expression":"true","profiles":["[a-"]}`},
	}
	for _, c := range cases {
		rec := createPolicy(api, policyAdmin(), c.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400 (%s)", c.name, rec.Code, rec.Body.String())
		}
	}
	if n, _, err := db.CountCELPolicyRules(); err != nil || n != 0 {
		t.Errorf("%d rules were stored despite being rejected", n)
	}
	// Malformed JSON too.
	if rec := createPolicy(api, policyAdmin(), `{not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("create(bad JSON) = %d", rec.Code)
	}
}

// TestPolicyNameCollisions: the name is the handle a refusal gives the
// requester, so two rules must not share one.
func TestPolicyNameCollisions(t *testing.T) {
	api, _ := tenantAPI(t)
	if rec := createPolicy(api, policyAdmin(), `{"name":"dup","expression":"true"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	if rec := createPolicy(api, policyAdmin(), `{"name":"dup","expression":"true"}`); rec.Code != http.StatusConflict {
		t.Errorf("a duplicate name = %d, want 409", rec.Code)
	}
	// A rename onto an existing name is refused too.
	rec := createPolicy(api, policyAdmin(), `{"name":"other","expression":"true"}`)
	other := decodePolicy(t, rec)
	if rec := updatePolicy(api, policyAdmin(), other.ID, `{"name":"dup","expression":"true"}`); rec.Code != http.StatusConflict {
		t.Errorf("a rename onto an existing name = %d, want 409", rec.Code)
	}
	// Renaming to itself is fine.
	if rec := updatePolicy(api, policyAdmin(), other.ID, `{"name":"other","expression":"false"}`); rec.Code != http.StatusOK {
		t.Errorf("renaming a rule to its own name = %d", rec.Code)
	}
}

// TestPolicyAuthorization: editing is ca:configure; reading needs any role.
func TestPolicyAuthorization(t *testing.T) {
	api, db := tenantAPI(t)
	rule := &celpolicy.Rule{ID: "r-1", Name: "existing", Expression: `true`, Enabled: true}
	if err := db.CreateCELPolicyRule(rule); err != nil {
		t.Fatal(err)
	}

	// An issuer may read but not write: a rule is a policy, not an issuance.
	if rec := getPolicy(api, policyIssuer(), "r-1"); rec.Code != http.StatusOK {
		t.Errorf("issuer get = %d, want 200", rec.Code)
	}
	for _, c := range []struct {
		name string
		rec  *httptest.ResponseRecorder
	}{
		{"create", createPolicy(api, policyIssuer(), `{"name":"x","expression":"true"}`)},
		{"update", updatePolicy(api, policyIssuer(), "r-1", `{"name":"existing","expression":"false"}`)},
		{"toggle", togglePolicy(api, policyIssuer(), "r-1", false)},
		{"delete", deletePolicy(api, policyIssuer(), "r-1")},
	} {
		if c.rec.Code != http.StatusForbidden {
			t.Errorf("issuer %s = %d, want 403", c.name, c.rec.Code)
		}
	}
	// A roleless principal may not even read.
	if rec := getPolicy(api, policyNobody(), "r-1"); rec.Code != http.StatusForbidden {
		t.Errorf("roleless get = %d, want 403", rec.Code)
	}
	rec := httptest.NewRecorder()
	api.ListIssuancePolicies(rec, reqAs(http.MethodGet, "/api/issuance-policies", policyNobody(), "", ""))
	if rec.Code != http.StatusForbidden {
		t.Errorf("roleless list = %d, want 403", rec.Code)
	}
	// Nothing changed.
	if stored, _ := db.GetCELPolicyRule("r-1"); stored == nil || stored.Expression != `true` || !stored.Enabled {
		t.Error("a denied write took effect anyway")
	}
}

// TestPolicyMutationsAreAudited: a restriction engine is only as trustworthy as
// the record of who changed it.
func TestPolicyMutationsAreAudited(t *testing.T) {
	api, db := tenantAPI(t)
	rec := createPolicy(api, policyAdmin(), `{"name":"audited","expression":"request.validity_days <= 30","message":"too long"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	id := decodePolicy(t, rec).ID
	if rec := updatePolicy(api, policyAdmin(), id, `{"name":"audited","expression":"request.validity_days <= 7"}`); rec.Code != http.StatusOK {
		t.Fatalf("update = %d", rec.Code)
	}
	if rec := deletePolicy(api, policyAdmin(), id); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	// A denied attempt is recorded too.
	_ = createPolicy(api, policyIssuer(), `{"name":"nope","expression":"true"}`)

	for _, c := range []struct {
		action string
		result string
		want   string
	}{
		{audit.ActionPolicyRuleCreate, audit.ResultSuccess, "request.validity_days <= 30"},
		{audit.ActionPolicyRuleUpdate, audit.ResultSuccess, "request.validity_days <= 7"},
		{audit.ActionPolicyRuleDelete, audit.ResultSuccess, "request.validity_days <= 7"},
		{audit.ActionPolicyRuleCreate, audit.ResultDenied, "ca:configure"},
	} {
		events, _, err := db.ListEvents(c.action, "", "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range events {
			if e.Result == c.result && strings.Contains(e.Detail, c.want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no %s event with result %q carrying %q", c.action, c.result, c.want)
		}
	}
}

// TestPolicyValidateEndpoint is what the console calls while the operator types.
func TestPolicyValidateEndpoint(t *testing.T) {
	api, _ := tenantAPI(t)
	check := func(expr string) map[string]interface{} {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]string{"expression": expr})
		api.ValidateIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/validate", policyIssuer(), "", string(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("validate(%q) = %d: %s", expr, rec.Code, rec.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// The three result shapes are reported, so the editor can tell the operator
	// whether their rule will explain itself or fall back to the message.
	for expr, want := range map[string]string{
		`request.validity_days <= 90`:                   "bool",
		`request.validity_days <= 90 ? "" : "too long"`: "string",
		`request.dns_names.filter(d, false)`:            "list(string)",
	} {
		out := check(expr)
		if out["valid"] != true {
			t.Errorf("validate(%q) = %v", expr, out)
			continue
		}
		if out["result_type"] != want {
			t.Errorf("validate(%q) result_type = %v, want %q", expr, out["result_type"], want)
		}
	}
	// A bad expression is a 200 with valid=false and the compiler's message —
	// the editor renders it, it is not an API error.
	out := check(`request.dsn_names.size() == 0`)
	if out["valid"] != false {
		t.Fatalf("validate(typo) = %v", out)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "dsn_names") || !strings.Contains(msg, "1:") {
		t.Errorf("the error does not name the field and its position: %q", msg)
	}
	// An empty expression is a client error.
	rec := httptest.NewRecorder()
	api.ValidateIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/validate", policyIssuer(), "", `{"expression":"  "}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("validate(empty) = %d, want 400", rec.Code)
	}
}

// policyTest drives POST /api/issuance-policies/test.
func policyTest(t *testing.T, api *API, user *models.UserInfo, body string) (*httptest.ResponseRecorder, policyTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	api.TestIssuancePolicy(rec, reqAs(http.MethodPost, "/api/issuance-policies/test", user, "", body))
	var out policyTestResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding the dry-run: %v (%s)", err, rec.Body.String())
		}
	}
	return rec, out
}

// TestPolicyDryRunAdHocExpression: trying a rule before saving it is the feature
// that makes the editor usable.
func TestPolicyDryRunAdHocExpression(t *testing.T) {
	api, _ := tenantAPI(t)
	rec, out := policyTest(t, api, policyIssuer(), `{
		"expression": "request.dns_names.filter(d, !d.endsWith(\".example.com\")).map(d, \"DNS name \" + d + \" is outside example.com\")",
		"input": {"request": {"dns_names": ["ok.example.com", "bad.evil.test"], "profile": "server"}}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if out.Decision.Allowed {
		t.Fatal("the dry-run allowed a request with a forbidden name")
	}
	if len(out.Decision.Violations) != 1 || !strings.Contains(out.Decision.Violations[0].Message, "bad.evil.test") {
		t.Fatalf("violations = %+v", out.Decision.Violations)
	}
	if len(out.Rules) != 1 || out.Rules[0] != "ad-hoc" {
		t.Errorf("rules = %v", out.Rules)
	}
	// The facts the rules saw are echoed back, so a surprising verdict is
	// diagnosable — the usual cause is a fact the operator assumed was present.
	if out.Input.Request.Source != celpolicy.SourcePreview || out.Input.Request.Operation != celpolicy.OpPreview {
		t.Errorf("the echoed input is not labelled as a dry-run: %+v", out.Input.Request)
	}
	if len(out.Input.Request.DNSNames) != 2 {
		t.Errorf("the echoed input lost the SANs: %+v", out.Input.Request)
	}

	// An ad-hoc expression that does not compile is a client error, not a denial.
	rec, _ = policyTest(t, api, policyIssuer(), `{"expression":"request.dsn_names"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("test(bad expression) = %d, want 400", rec.Code)
	}
}

// TestPolicyDryRunExercisesEveryFactSet: the JWT, URL, body and principal facts
// must all be settable from the dry-run body, or an operator cannot try the rules
// that read them.
func TestPolicyDryRunExercisesEveryFactSet(t *testing.T) {
	api, _ := tenantAPI(t)
	body := `{
		"expression": "has(jwt.groups) && \"pki\" in jwt.groups && path == \"/api/x\" && url.method == \"POST\" && has(body.reason) && principal.authenticated && \"issuer\" in principal.roles",
		"input": {
			"request": {"profile": "server"},
			"jwt": {"groups": ["pki"]},
			"url": {"method": "POST", "path": "/api/x", "present": true},
			"body": {"reason": "CHG-1"},
			"principal": {"subject": "ops", "roles": ["issuer"], "authenticated": true}
		}
	}`
	rec, out := policyTest(t, api, policyIssuer(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if !out.Decision.Allowed {
		t.Fatalf("a rule over every fact set failed in the dry-run: %+v", out.Decision.Violations)
	}
}

// TestPolicyDryRunStoredRules covers the two other modes: one named rule
// (evaluated even while disabled, because trying it before switching it on is
// the point) and the whole active set.
func TestPolicyDryRunStoredRules(t *testing.T) {
	api, db := tenantAPI(t)
	mustStore(t, db, &celpolicy.Rule{ID: "a", Name: "live", Expression: `request.validity_days <= 30`, Message: "too long", Enabled: true})
	mustStore(t, db, &celpolicy.Rule{ID: "b", Name: "parked", Expression: `false`, Message: "parked rule fired", Enabled: false})

	in := `"input": {"request": {"validity_days": 90, "profile": "server"}}`

	// The active set: only the enabled rule.
	rec, out := policyTest(t, api, policyIssuer(), `{`+in+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if len(out.Rules) != 1 || out.Rules[0] != "live" {
		t.Errorf("rules = %v, want only the enabled one", out.Rules)
	}
	if out.Decision.Allowed {
		t.Error("the active rule did not fire")
	}

	// all_rules includes the parked one.
	_, out = policyTest(t, api, policyIssuer(), `{"all_rules": true, `+in+`}`)
	if len(out.Rules) != 2 {
		t.Errorf("rules = %v, want both", out.Rules)
	}
	if len(out.Decision.Violations) != 2 {
		t.Errorf("violations = %+v, want one per rule", out.Decision.Violations)
	}

	// A named, disabled rule is still evaluated.
	_, out = policyTest(t, api, policyIssuer(), `{"rule": "parked", `+in+`}`)
	if len(out.Rules) != 1 || out.Rules[0] != "parked" {
		t.Errorf("rules = %v", out.Rules)
	}
	if out.Decision.Allowed {
		t.Error("a named disabled rule was skipped in a dry-run")
	}

	// An unknown rule name is a client error.
	rec, _ = policyTest(t, api, policyIssuer(), `{"rule": "nope", `+in+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("test(unknown rule) = %d, want 400", rec.Code)
	}
}

// TestPolicyDryRunRequiresCAForACSR keeps the CSR-seeded mode honest about what
// it needs.
func TestPolicyDryRunRequiresCAForACSR(t *testing.T) {
	api, _ := tenantAPI(t)
	rec, _ := policyTest(t, api, policyIssuer(), `{"expression":"true","csr":"-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("test(csr without ca_id) = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ca_id") {
		t.Errorf("the error does not say what is missing: %s", rec.Body.String())
	}
}

func TestPolicyDryRunAuthorization(t *testing.T) {
	api, _ := tenantAPI(t)
	rec, _ := policyTest(t, api, policyNobody(), `{"expression":"true"}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("roleless dry-run = %d, want 403", rec.Code)
	}
}

// TestPolicyReferenceEndpoint: the console renders this, so it must carry the
// whole vocabulary.
func TestPolicyReferenceEndpoint(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := httptest.NewRecorder()
	api.IssuancePolicyReference(rec, reqAs(http.MethodGet, "/api/issuance-policies/reference", policyIssuer(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("reference = %d: %s", rec.Code, rec.Body.String())
	}
	var ref celpolicy.Reference
	if err := json.Unmarshal(rec.Body.Bytes(), &ref); err != nil {
		t.Fatalf("decoding the reference: %v", err)
	}
	if len(ref.Variables) == 0 || len(ref.Functions) == 0 || len(ref.Examples) == 0 {
		t.Fatalf("the reference is incomplete: %d variables, %d function groups, %d examples",
			len(ref.Variables), len(ref.Functions), len(ref.Examples))
	}
	// Every example the console offers must be storable through the API, or the
	// editor's "insert example" button hands the operator a 400.
	for _, ex := range ref.Examples {
		body, err := json.Marshal(map[string]interface{}{
			"name":       "ex-" + strings.ToLower(strings.ReplaceAll(strings.Split(ex.Title, " ")[0], ",", "")),
			"expression": ex.Expression,
			"effect":     ex.Effect,
			"message":    ex.Message,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := createPolicy(api, policyAdmin(), string(body))
		if rec.Code != http.StatusCreated && rec.Code != http.StatusConflict {
			t.Errorf("example %q could not be stored: %d %s", ex.Title, rec.Code, rec.Body.String())
		}
	}
	if rec := httptest.NewRecorder(); true {
		api.IssuancePolicyReference(rec, reqAs(http.MethodGet, "/api/issuance-policies/reference", policyNobody(), "", ""))
		if rec.Code != http.StatusForbidden {
			t.Errorf("roleless reference = %d, want 403", rec.Code)
		}
	}
}

// TestPolicyDeniedResponseShape is the requester-facing contract: a refusal is a
// 422 whose body names each rule and reason.
func TestPolicyDeniedResponseShape(t *testing.T) {
	deny := &celpolicy.DenyError{Decision: celpolicy.Decision{
		Allowed: false,
		Violations: []celpolicy.Violation{
			{Rule: "max-lifetime", Message: "requested 400 days; this profile allows at most 90", Mode: celpolicy.ModeEnforce},
			{Rule: "dns-suffix", Message: "DNS name a.evil.test is outside example.com", Mode: celpolicy.ModeEnforce},
			{Rule: "watch", Message: "monitor only", Mode: celpolicy.ModeMonitor},
		},
	}}
	rec := httptest.NewRecorder()
	if !writePolicyDenyError(rec, deny) {
		t.Fatal("writePolicyDenyError did not handle a *DenyError")
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422: the credentials were fine, the request content was not", rec.Code)
	}
	var out models.PolicyDeniedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the refusal: %v", err)
	}
	if out.Code != "policy_denied" {
		t.Errorf("code = %q", out.Code)
	}
	if len(out.Violations) != 2 {
		t.Fatalf("violations = %+v; a monitor-mode finding must not appear in a refusal", out.Violations)
	}
	if out.Violations[0].Rule != "max-lifetime" || !strings.Contains(out.Violations[0].Message, "at most 90") {
		t.Errorf("violations = %+v", out.Violations)
	}
	for _, want := range []string{"at most 90", "a.evil.test", "max-lifetime", "dns-suffix"} {
		if !strings.Contains(out.Error, want) {
			t.Errorf("the one-sentence error is missing %q: %q", want, out.Error)
		}
	}

	// Any other error is left for the caller's own mapping.
	rec = httptest.NewRecorder()
	if writePolicyDenyError(rec, errContext("something else")) {
		t.Error("writePolicyDenyError claimed an unrelated error")
	}
}

type errContext string

func (e errContext) Error() string { return string(e) }

func mustStore(t *testing.T, db *database.DB, r *celpolicy.Rule) {
	t.Helper()
	if err := db.CreateCELPolicyRule(r); err != nil {
		t.Fatalf("storing rule %q: %v", r.Name, err)
	}
}
