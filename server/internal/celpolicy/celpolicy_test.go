package celpolicy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The engine's own test suite. It is organized around the four things a
// restriction engine can get wrong, in descending order of how badly:
//
//  1. it permits something it should have refused (every fail-closed test),
//  2. it refuses something it should have permitted (the satisfied cases),
//  3. it refuses for the wrong reason, or without saying one (the message tests),
//  4. it accepts a rule that does not mean what the operator wrote (compile).

// sampleInput is a realistic request: a TLS server certificate for an
// example.com name, asked for over REST by an authenticated operator whose token
// carries groups.
func sampleInput() Input {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return Input{
		Request: CertRequest{
			Source:         SourceREST,
			Operation:      OpIssue,
			Profile:        "server",
			CA:             CAInfo{ID: "ca-1", Label: "issuing", Tenant: "acme", Subject: "CN=Issuing CA,O=Acme"},
			Subject:        Subject{CommonName: "www.example.com", Organization: []string{"Acme"}, DN: "CN=www.example.com,O=Acme"},
			DNSNames:       []string{"www.example.com", "example.com"},
			IPAddresses:    []string{"10.1.2.3"},
			EmailAddresses: []string{"ops@example.com"},
			SANCount:       4,
			KeyUsages:      []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:   []string{"serverAuth"},
			MaxPathLen:     -1,
			NotBefore:      now,
			NotAfter:       now.Add(90 * 24 * time.Hour),
			Validity:       90 * 24 * time.Hour,
			ValidityDays:   90,
			Key:            KeyInfo{Algorithm: "ECDSA", Size: 256, Curve: "P-256"},
			Algorithm:      "classical",
			RequestedBy:    "ops@example.com",
		},
		JWT: map[string]interface{}{
			"sub":          "ops@example.com",
			"iss":          "https://idp.example.com",
			"groups":       []interface{}{"pki-issuers", "pki-ns-payments"},
			"entitlements": []interface{}{"pki.issue"},
		},
		URL: RequestURL{
			Method: "POST", Scheme: "https", Host: "pki.example.com", Port: "443",
			Path: "/api/keys/ca-1/issue", Segments: []string{"api", "keys", "ca-1", "issue"},
			RawQuery: "dry_run=0", Query: map[string][]string{"dry_run": {"0"}},
			ClientIP: "10.9.9.9", Full: "https://pki.example.com/api/keys/ca-1/issue?dry_run=0",
			Present: true,
		},
		Body: map[string]interface{}{
			"profile":       "server",
			"validity_days": float64(90),
			"reason":        "CHG-10482",
		},
		Principal: Principal{
			Subject: "ops@example.com", Email: "ops@example.com", EmailVerified: true,
			Roles: []string{"issuer"}, Groups: []string{"pki-issuers"},
			TenantRoles: map[string][]string{"acme": {"issuer"}}, Tenants: []string{"acme"},
			Authenticated: true,
		},
		Now: now,
	}
}

// rule is a terse constructor for an enabled require-effect rule.
func rule(name, expr string) Rule {
	return Rule{ID: name, Name: name, Expression: expr, Enabled: true}
}

func TestEnvironmentBuilds(t *testing.T) {
	env, err := Env()
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	want := map[string]bool{
		VarRequest: false, VarJWT: false, VarURL: false,
		VarPath: false, VarBody: false, VarPrincipal: false, VarNow: false,
	}
	for _, v := range env.Vars() {
		if _, ok := want[v.Name()]; !ok {
			t.Errorf("environment declares an undocumented variable %q", v.Name())
			continue
		}
		want[v.Name()] = true
		if v.Doc() == "" {
			t.Errorf("variable %q has no documentation; the console renders it", v.Name())
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("variable %q is documented but not declared", name)
		}
	}
}

// TestRequestIsTypedObject is the usability invariant that justifies declaring
// the request as a struct instead of a map: a misspelled field is a compile
// error with a position, not a denied certificate discovered in production.
func TestRequestIsTypedObject(t *testing.T) {
	for _, expr := range []string{
		`request.dsn_names.size() == 0`,      // transposed
		`request.subject.commonName == "x"`,  // camelCase
		`request.validityDays <= 90`,         // camelCase
		`request.ca.tennant == "acme"`,       // typo
		`request.key.bits >= 2048`,           // wrong name (it is .size)
		`url.pathname == "/api"`,             // wrong name
		`principal.role.exists(r, r == "x")`, // singular
	} {
		err := Validate(expr)
		if err == nil {
			t.Errorf("%q compiled; a field typo must be a load error", expr)
			continue
		}
		if !strings.Contains(err.Error(), "undefined field") && !strings.Contains(err.Error(), "no such") {
			t.Errorf("%q: error does not name the bad field: %v", expr, err)
		}
	}
}

// TestCompileRejectsUnusableResultTypes asserts a rule whose expression yields
// something the engine cannot read is rejected when it is written. Such a rule
// would otherwise be a gate that either never fires or always fails closed.
func TestCompileRejectsUnusableResultTypes(t *testing.T) {
	for _, expr := range []string{
		`request.validity_days`, // int
		`request.not_after`,     // timestamp
		`request.subject`,       // object
		`request.validity`,      // duration
		`[1, 2, 3]`,             // list(int)
		`{"a": "b"}`,            // map
	} {
		if err := Validate(expr); err == nil {
			t.Errorf("%q compiled; only bool, string and list(string) are usable verdicts", expr)
		}
	}
	// And the three usable shapes are accepted.
	for _, expr := range []string{
		`request.validity_days <= 90`,
		`"a reason"`,
		`["one", "two"]`,
		`request.dns_names.filter(d, false)`,
		`regex.extract(request.subject.common_name, "^(.*)$")`,
	} {
		if err := Validate(expr); err != nil {
			t.Errorf("%q must compile: %v", expr, err)
		}
	}
}

func TestCompileRejectsSyntaxErrorsWithPosition(t *testing.T) {
	err := Validate(`request.dns_names.all(d, d.endsWith(".example.com")`)
	if err == nil {
		t.Fatal("unbalanced parentheses compiled")
	}
	if !strings.Contains(err.Error(), "1:") {
		t.Errorf("compile error carries no position, so an operator cannot find it: %v", err)
	}
}

func TestEmptyExpressionRejected(t *testing.T) {
	if err := Validate("   "); err == nil {
		t.Error("an empty expression compiled")
	}
}

// TestRequireEffect covers the default reading: the condition must hold.
func TestRequireEffect(t *testing.T) {
	in := sampleInput()
	d := Shared().Evaluate([]Rule{rule("suffix", `request.dns_names.all(d, d.endsWith("example.com"))`)}, in)
	if !d.Allowed || len(d.Violations) != 0 {
		t.Fatalf("a satisfied require rule denied: %+v", d)
	}
	if d.Evaluated != 1 {
		t.Errorf("Evaluated = %d, want 1", d.Evaluated)
	}

	in.Request.DNSNames = []string{"www.evil.test"}
	d = Shared().Evaluate([]Rule{rule("suffix", `request.dns_names.all(d, d.endsWith("example.com"))`)}, in)
	if d.Allowed {
		t.Fatal("an unsatisfied require rule permitted the request")
	}
	if len(d.Violations) != 1 || d.Violations[0].Rule != "suffix" {
		t.Fatalf("violations = %+v", d.Violations)
	}
	if !strings.Contains(d.Violations[0].Message, "suffix") {
		t.Errorf("a rule with no message must still name itself: %q", d.Violations[0].Message)
	}
}

// TestDenyEffect covers the blocklist reading: the condition must NOT hold.
func TestDenyEffect(t *testing.T) {
	r := Rule{
		ID: "no-internal", Name: "no-internal", Enabled: true, Effect: EffectDeny,
		Expression: `request.dns_names.exists(d, d.endsWith(".internal"))`,
		Message:    "internal-only names cannot be certified here",
	}
	in := sampleInput()
	if d := Shared().Evaluate([]Rule{r}, in); !d.Allowed {
		t.Fatalf("a deny rule whose condition is false denied: %+v", d)
	}
	in.Request.DNSNames = append(in.Request.DNSNames, "db.internal")
	d := Shared().Evaluate([]Rule{r}, in)
	if d.Allowed {
		t.Fatal("a deny rule whose condition is true permitted the request")
	}
	if d.Violations[0].Message != "internal-only names cannot be certified here" {
		t.Errorf("message = %q, want the operator's own wording", d.Violations[0].Message)
	}
}

// TestStringVerdictCarriesTheReason is the feature the task exists for: the rule
// explains itself, and the explanation is what the requester gets.
func TestStringVerdictCarriesTheReason(t *testing.T) {
	r := rule("lifetime", `request.validity_days <= 30 ? "" : `+
		`"requested %d days of validity; this profile allows at most 30".format([request.validity_days])`)
	d := Shared().Evaluate([]Rule{r}, sampleInput())
	if d.Allowed {
		t.Fatal("a 90-day request passed a 30-day ceiling")
	}
	want := "requested 90 days of validity; this profile allows at most 30"
	if d.Violations[0].Message != want {
		t.Fatalf("message = %q, want %q", d.Violations[0].Message, want)
	}
	// And the satisfied case says nothing at all.
	in := sampleInput()
	in.Request.ValidityDays = 7
	if d := Shared().Evaluate([]Rule{r}, in); !d.Allowed || len(d.Violations) != 0 {
		t.Fatalf("a satisfied string rule produced violations: %+v", d)
	}
}

// TestListVerdictReportsEveryOffendingName: a requester who named three bad
// hosts is told about three, not told about one and left to retry twice.
func TestListVerdictReportsEveryOffendingName(t *testing.T) {
	in := sampleInput()
	in.Request.DNSNames = []string{"ok.example.com", "a.evil.test", "b.evil.test"}
	r := rule("suffix", `request.dns_names.filter(d, !d.endsWith(".example.com"))`+
		`.map(d, "DNS name " + d + " is outside example.com")`)
	d := Shared().Evaluate([]Rule{r}, in)
	if d.Allowed {
		t.Fatal("two forbidden names passed")
	}
	if len(d.Violations) != 2 {
		t.Fatalf("got %d violations, want one per offending name: %+v", len(d.Violations), d.Violations)
	}
	for _, v := range d.Violations {
		if !strings.Contains(v.Message, ".evil.test") {
			t.Errorf("violation does not name the offending host: %q", v.Message)
		}
	}
}

// TestEmptyStringsAreNotViolations guards the boundary of the string/list
// verdict: whitespace is "nothing to say", not a reason with no text.
func TestEmptyStringsAreNotViolations(t *testing.T) {
	for _, expr := range []string{
		`""`,
		`"   "`,
		`["", "  "]`,
		`request.dns_names.filter(d, false)`, // an empty result list
		`request.wildcard ? ["no wildcards"] : []`, // the realistic conditional shape
	} {
		d := Shared().Evaluate([]Rule{rule("quiet", expr)}, sampleInput())
		if !d.Allowed || len(d.Violations) != 0 {
			t.Errorf("%q produced a violation: %+v", expr, d.Violations)
		}
	}
	// A bare, untyped empty list is rejected at compile time instead: it is
	// indistinguishable from `[1, 2, 3]`, and catching that where the rule is
	// written beats failing closed on every certificate afterwards.
	if err := Validate(`[]`); err == nil {
		t.Error("an untyped empty list compiled")
	}
}

// TestJWTClaimsAreInspectable covers the second requirement: the token's claims
// reach the rule, and a missing claim is explicit rather than silently false.
func TestJWTClaimsAreInspectable(t *testing.T) {
	in := sampleInput()
	cases := []struct {
		expr string
		want bool
	}{
		{`has(jwt.entitlements) && "pki.issue" in jwt.entitlements`, true},
		{`has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements`, false},
		{`jwt.iss == "https://idp.example.com"`, true},
		{`has(jwt.department)`, false},
		{`jwt.groups.exists(g, g.startsWith("pki-ns-"))`, true},
		{`string(jwt.sub).endsWith("@example.com")`, true},
	}
	for _, c := range cases {
		d := Shared().Evaluate([]Rule{rule("jwt", c.expr)}, in)
		if d.Allowed != c.want {
			t.Errorf("%q: allowed = %v, want %v (violations %+v)", c.expr, d.Allowed, c.want, d.Violations)
		}
	}
	// An unguarded lookup of an absent claim is a runtime error, which must fail
	// CLOSED — the dangerous alternative is a rule that reads as satisfied because
	// the claim it tests was not asserted.
	d := Shared().Evaluate([]Rule{rule("unguarded", `jwt.department == "pki"`)}, in)
	if d.Allowed {
		t.Fatal("an unguarded missing-claim lookup permitted the request")
	}
	if d.Violations[0].Error == "" {
		t.Error("the violation does not record why the rule could not be evaluated")
	}
}

// TestURLIsExposedAsObjectAndPath covers the third requirement explicitly: both
// forms are available and agree.
func TestURLIsExposedAsObjectAndPath(t *testing.T) {
	in := sampleInput()
	for _, expr := range []string{
		`url.path == "/api/keys/ca-1/issue"`,
		`path == url.path`,
		`url.method == "POST"`,
		`url.host == "pki.example.com" && url.port == "443"`,
		`url.scheme == "https"`,
		`url.segments.size() == 4 && url.segments[2] == "ca-1"`,
		`url.full.startsWith("https://pki.example.com/api/")`,
		`has(url.query.dry_run) && url.query.dry_run[0] == "0"`,
		`url.raw_query == "dry_run=0"`,
		`cidr("10.0.0.0/8").containsIP(url.client_ip)`,
		`url.present`,
		`path.matches("^/api/keys/[^/]+/issue$")`,
	} {
		d := Shared().Evaluate([]Rule{rule("url", expr)}, in)
		if !d.Allowed {
			t.Errorf("%q did not hold: %+v", expr, d.Violations)
		}
	}
}

// TestBodyParametersAreExposed covers the fourth requirement: a parameter the
// API accepted but the certificate does not carry is still visible to a rule.
func TestBodyParametersAreExposed(t *testing.T) {
	in := sampleInput()
	r := rule("ticket", `has(body.reason) && string(body.reason).matches("^(CHG|INC)-[0-9]{4,}$")`)
	if d := Shared().Evaluate([]Rule{r}, in); !d.Allowed {
		t.Fatalf("a valid ticket was rejected: %+v", d.Violations)
	}
	in.Body = map[string]interface{}{"reason": "because"}
	if d := Shared().Evaluate([]Rule{r}, in); d.Allowed {
		t.Fatal("a malformed ticket passed")
	}
	in.Body = nil
	if d := Shared().Evaluate([]Rule{r}, in); d.Allowed {
		t.Fatal("an absent ticket passed")
	}
}

// TestAutomatedEnrollmentHasNoOperatorFacts is the fail-closed reading that
// matters most in practice: a rule written against an operator's token must not
// be satisfiable by a protocol enrollment that presents none.
func TestAutomatedEnrollmentHasNoOperatorFacts(t *testing.T) {
	// What an EST enrollment looks like: certificate facts, nothing else.
	in := Input{Request: CertRequest{
		Source: SourceEST, Operation: OpIssue, Profile: "client",
		DNSNames: []string{"device-1.example.com"}, MaxPathLen: -1,
	}}
	for _, expr := range []string{
		`has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements`,
		`principal.authenticated && "admin" in principal.roles`,
		`path.startsWith("/api/")`,
	} {
		d := Shared().Evaluate([]Rule{rule("operator-only", expr)}, in)
		if d.Allowed {
			t.Errorf("%q was satisfied by an unauthenticated EST enrollment", expr)
		}
	}
	// And the facts that DO exist are readable, so a rule can treat the surface
	// differently on purpose.
	d := Shared().Evaluate([]Rule{rule("by-source", `request.source == "est" && !url.present`)}, in)
	if !d.Allowed {
		t.Errorf("a rule reading request.source on an EST enrollment failed: %+v", d.Violations)
	}
}

// TestMonitorModeDoesNotBlock: the mechanism that makes a policy adoptable.
func TestMonitorModeDoesNotBlock(t *testing.T) {
	r := Rule{
		ID: "soon", Name: "soon", Enabled: true, Mode: ModeMonitor,
		Expression: `request.validity_days <= 1`,
		Message:    "would be refused once this rule is enforced",
	}
	d := Shared().Evaluate([]Rule{r}, sampleInput())
	if !d.Allowed {
		t.Fatal("a monitor-mode rule blocked the request")
	}
	if len(d.Violations) != 1 {
		t.Fatalf("a monitor-mode finding was not recorded: %+v", d)
	}
	if d.Violations[0].Mode != ModeMonitor {
		t.Errorf("mode = %q, want %q", d.Violations[0].Mode, ModeMonitor)
	}
	if len(d.Enforced()) != 0 {
		t.Errorf("Enforced() returned a monitor-mode violation: %+v", d.Enforced())
	}
	if d.Summary() != "no violations" {
		t.Errorf("Summary() = %q; a monitor finding blocked nothing", d.Summary())
	}
}

// TestDisabledRuleIsSkipped: parking a policy must not enforce it.
func TestDisabledRuleIsSkipped(t *testing.T) {
	r := rule("off", `false`)
	r.Enabled = false
	d := Shared().Evaluate([]Rule{r}, sampleInput())
	if !d.Allowed || d.Evaluated != 0 || d.Skipped != 1 {
		t.Fatalf("a disabled rule was evaluated: %+v", d)
	}
}

// TestFailClosedOnEvaluationError is the central safety property: a rule that
// breaks refuses, it does not wave the request through.
func TestFailClosedOnEvaluationError(t *testing.T) {
	cases := []struct{ name, expr string }{
		{"missing-claim", `jwt.nope == "x"`},
		{"index-out-of-range", `request.dns_names[99] == "x"`},
		{"bad-regex", `request.subject.common_name.matches("([")`},
		{"division-by-zero", `request.validity_days / (request.san_count - 4) > 0`},
		{"bad-cidr", `cidr("not-a-cidr").containsIP("10.0.0.1")`},
	}
	for _, c := range cases {
		d := Shared().Evaluate([]Rule{rule(c.name, c.expr)}, sampleInput())
		if d.Allowed {
			t.Errorf("%s: a rule that could not be evaluated permitted the request", c.name)
			continue
		}
		v := d.Violations[0]
		if v.Error == "" {
			t.Errorf("%s: no error recorded on the violation", c.name)
		}
		if !strings.Contains(v.Message, "could not be checked") {
			t.Errorf("%s: message does not say the rule failed rather than the request: %q", c.name, v.Message)
		}
	}
}

// TestFailOpenIsOptIn: an operator may mark a rule best-effort, and only then
// does a broken rule stop blocking.
func TestFailOpenIsOptIn(t *testing.T) {
	r := rule("best-effort", `jwt.nope == "x"`)
	r.FailOpen = true
	d := Shared().Evaluate([]Rule{r}, sampleInput())
	if !d.Allowed || len(d.Violations) != 0 {
		t.Fatalf("a fail-open rule blocked on its own error: %+v", d)
	}
}

// TestCostCeilingFailsClosed: a pathological comprehension cannot spend
// unbounded CPU on the signing path, and the abort denies.
func TestCostCeilingFailsClosed(t *testing.T) {
	in := sampleInput()
	big := make([]string, 400)
	for i := range big {
		big[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	in.Request.DNSNames = big
	// Quadratic over an attacker-influenced list: 160,000 inner comparisons.
	d := Shared().Evaluate([]Rule{rule("quadratic",
		`request.dns_names.all(a, request.dns_names.all(b, a != b || a == b))`)}, in)
	if d.Allowed {
		t.Fatal("a cost-limit abort permitted the request")
	}
	if !strings.Contains(strings.ToLower(d.Violations[0].Error), "cost") {
		t.Errorf("the recorded error does not mention the cost limit: %q", d.Violations[0].Error)
	}

	// A realistic rule over the same 400 names stays well inside the budget.
	d = Shared().Evaluate([]Rule{rule("realistic",
		`request.dns_names.all(x, x.endsWith(".example.com"))`)}, in)
	if !d.Allowed {
		t.Fatalf("a realistic rule over 400 names exceeded the budget: %+v", d.Violations)
	}
}

// TestEveryApplicableRuleRuns: the requester learns every reason at once.
func TestEveryApplicableRuleRuns(t *testing.T) {
	in := sampleInput()
	in.Request.DNSNames = []string{"bad.evil.test"}
	in.Request.ValidityDays = 800
	in.Request.Key = KeyInfo{Algorithm: "RSA", Size: 1024}
	rules := []Rule{
		{ID: "c", Name: "key-strength", Enabled: true, Priority: 30, Expression: `request.key.size >= 2048`, Message: "key too small"},
		{ID: "a", Name: "name-suffix", Enabled: true, Priority: 10, Expression: `request.dns_names.all(d, d.endsWith(".example.com"))`, Message: "name not permitted"},
		{ID: "b", Name: "lifetime", Enabled: true, Priority: 20, Expression: `request.validity_days <= 90`, Message: "lifetime too long"},
	}
	d := Shared().Evaluate(rules, in)
	if d.Allowed {
		t.Fatal("three broken constraints passed")
	}
	if len(d.Violations) != 3 {
		t.Fatalf("got %d violations, want 3: %+v", len(d.Violations), d.Violations)
	}
	// Priority fixes the reading order, so the most important reason is first.
	gotOrder := []string{d.Violations[0].Rule, d.Violations[1].Rule, d.Violations[2].Rule}
	wantOrder := []string{"name-suffix", "lifetime", "key-strength"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("violation order = %v, want %v", gotOrder, wantOrder)
		}
	}
	if d.Evaluated != 3 {
		t.Errorf("Evaluated = %d, want 3", d.Evaluated)
	}
}

// TestEqualPriorityOrdersByName keeps the reported order stable for a rule set
// an operator never assigned priorities to.
func TestEqualPriorityOrdersByName(t *testing.T) {
	rules := []Rule{rule("zebra", `false`), rule("alpha", `false`), rule("mike", `false`)}
	d := Shared().Evaluate(rules, sampleInput())
	got := []string{d.Violations[0].Rule, d.Violations[1].Rule, d.Violations[2].Rule}
	want := []string{"alpha", "mike", "zebra"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// TestScopeSelectors covers profile/CA/tenant narrowing, including globs.
func TestScopeSelectors(t *testing.T) {
	in := sampleInput() // profile "server", CA id "ca-1" label "issuing", tenant "acme"
	cases := []struct {
		name  string
		rule  Rule
		fires bool
	}{
		{"no selectors", Rule{Name: "r", Enabled: true, Expression: `false`}, true},
		{"matching profile", Rule{Name: "r", Enabled: true, Expression: `false`, Profiles: []string{"server"}}, true},
		{"other profile", Rule{Name: "r", Enabled: true, Expression: `false`, Profiles: []string{"client"}}, false},
		{"profile glob", Rule{Name: "r", Enabled: true, Expression: `false`, Profiles: []string{"serv*"}}, true},
		{"profile case", Rule{Name: "r", Enabled: true, Expression: `false`, Profiles: []string{"SERVER"}}, true},
		{"CA by id", Rule{Name: "r", Enabled: true, Expression: `false`, CAs: []string{"ca-1"}}, true},
		{"CA by label", Rule{Name: "r", Enabled: true, Expression: `false`, CAs: []string{"issuing"}}, true},
		{"CA glob", Rule{Name: "r", Enabled: true, Expression: `false`, CAs: []string{"iss*"}}, true},
		{"other CA", Rule{Name: "r", Enabled: true, Expression: `false`, CAs: []string{"staging-*"}}, false},
		{"matching tenant", Rule{Name: "r", Enabled: true, Expression: `false`, TenantID: "acme"}, true},
		{"other tenant", Rule{Name: "r", Enabled: true, Expression: `false`, TenantID: "other"}, false},
		{"profile and CA both match", Rule{Name: "r", Enabled: true, Expression: `false`,
			Profiles: []string{"server"}, CAs: []string{"issuing"}}, true},
		{"profile matches, CA does not", Rule{Name: "r", Enabled: true, Expression: `false`,
			Profiles: []string{"server"}, CAs: []string{"nope"}}, false},
	}
	for _, c := range cases {
		d := Shared().Evaluate([]Rule{c.rule}, in)
		if fired := !d.Allowed; fired != c.fires {
			t.Errorf("%s: rule fired = %v, want %v", c.name, fired, c.fires)
		}
	}
}

// TestValidateRejectsMalformedRules: the rule's own metadata is checked where it
// is written, not where it is enforced.
func TestValidateRejectsMalformedRules(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"no name", Rule{Expression: `true`}},
		{"whitespace in name", Rule{Name: "my rule", Expression: `true`}},
		{"no expression", Rule{Name: "r"}},
		{"bad effect", Rule{Name: "r", Expression: `true`, Effect: "permit"}},
		{"bad mode", Rule{Name: "r", Expression: `true`, Mode: "audit"}},
		{"bad selector pattern", Rule{Name: "r", Expression: `true`, Profiles: []string{"[a-"}}},
		{"bad expression", Rule{Name: "r", Expression: `request.nope`}},
	}
	for _, c := range cases {
		if err := c.rule.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", c.name)
		}
	}
	good := Rule{Name: "ok-rule", Expression: `request.validity_days <= 90`, Effect: EffectDeny, Mode: ModeMonitor}
	if err := good.Validate(); err != nil {
		t.Errorf("a well-formed rule was rejected: %v", err)
	}
}

// TestCheckReturnsDenyError wires the engine to the error channel every issuance
// surface uses.
func TestCheckReturnsDenyError(t *testing.T) {
	r := rule("lifetime", `request.validity_days <= 30`)
	r.Message = "this profile allows at most 30 days"
	_, err := Shared().Check([]Rule{r}, sampleInput())
	if err == nil {
		t.Fatal("Check returned no error for a denied request")
	}
	if !errors.Is(err, ErrDenied) {
		t.Error("errors.Is(err, ErrDenied) is false; surfaces cannot recognize a policy refusal")
	}
	var deny *DenyError
	if !errors.As(err, &deny) {
		t.Fatal("errors.As did not yield a *DenyError")
	}
	if len(deny.Violations()) != 1 {
		t.Fatalf("violations = %+v", deny.Violations())
	}
	if !strings.Contains(err.Error(), "at most 30 days") || !strings.Contains(err.Error(), "lifetime") {
		t.Errorf("the error does not carry the reason and the rule name: %v", err)
	}

	// The allowed path returns the decision and no error.
	in := sampleInput()
	in.Request.ValidityDays = 7
	d, err := Shared().Check([]Rule{r}, in)
	if err != nil || !d.Allowed {
		t.Fatalf("Check denied a satisfied request: %v %+v", err, d)
	}
}

// TestDenyErrorMessageListsEveryReason: a single sentence that is still complete.
func TestDenyErrorMessageListsEveryReason(t *testing.T) {
	in := sampleInput()
	in.Request.ValidityDays = 800
	rules := []Rule{
		{Name: "lifetime", Enabled: true, Expression: `request.validity_days <= 90`, Message: "too long"},
		{Name: "no-ip-sans", Enabled: true, Effect: EffectDeny, Expression: `request.ip_addresses.size() > 0`, Message: "IP SANs are not permitted"},
	}
	_, err := Shared().Check(rules, in)
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"too long", "IP SANs are not permitted", "lifetime", "no-ip-sans"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q: %v", want, err)
		}
	}
}

// TestDecisionSummary is what lands in the audit log.
func TestDecisionSummary(t *testing.T) {
	in := sampleInput()
	in.Request.ValidityDays = 800
	d := Shared().Evaluate([]Rule{
		{Name: "lifetime", Enabled: true, Expression: `request.validity_days <= 90`, Message: "too long"},
		{Name: "watch", Enabled: true, Mode: ModeMonitor, Expression: `false`, Message: "noted"},
	}, in)
	if got := d.Summary(); got != "lifetime: too long" {
		t.Errorf("Summary() = %q; it must carry the blocking reasons only", got)
	}
}

// TestEmptyRuleSetAllows: an unconfigured engine changes nothing.
func TestEmptyRuleSetAllows(t *testing.T) {
	d := Shared().Evaluate(nil, sampleInput())
	if !d.Allowed || d.Evaluated != 0 || len(d.Violations) != 0 {
		t.Fatalf("an empty rule set was not a no-op: %+v", d)
	}
}

// TestMessageFallbackChain documents what a bool rule reports when the operator
// supplied no message.
func TestMessageFallbackChain(t *testing.T) {
	cases := []struct {
		rule Rule
		want string
	}{
		{Rule{Name: "r", Message: "explicit", Description: "ignored"}, "explicit"},
		{Rule{Name: "r", Description: "the description"}, "the description"},
		{Rule{Name: "r"}, `does not satisfy policy rule "r"`},
		{Rule{Name: "r", Effect: EffectDeny}, `matches policy rule "r"`},
	}
	for _, c := range cases {
		if got := c.rule.messageOrDefault(); !strings.Contains(got, c.want) {
			t.Errorf("messageOrDefault() = %q, want it to contain %q", got, c.want)
		}
	}
}

// TestExamplesAreUsable compiles and evaluates every example the console offers.
// An example an operator copies must work, and must behave the way its title
// claims.
func TestExamplesAreUsable(t *testing.T) {
	for _, ex := range Examples() {
		if ex.Title == "" || ex.Description == "" {
			t.Errorf("example %q is missing its title or description", ex.Title)
		}
		r := Rule{Name: "example", Enabled: true, Expression: ex.Expression, Effect: ex.Effect, Message: ex.Message}
		if err := r.Validate(); err != nil {
			t.Errorf("example %q does not compile: %v", ex.Title, err)
			continue
		}
		// It must evaluate without erroring against the realistic sample input —
		// an example that fails closed on an ordinary request is a trap.
		d := Shared().Evaluate([]Rule{r}, sampleInput())
		for _, v := range d.Violations {
			if v.Error != "" {
				t.Errorf("example %q errored on an ordinary request: %s", ex.Title, v.Error)
			}
		}
	}
}

// TestExampleBehaviour spot-checks the examples that encode the task's named
// restrictions, in both directions.
func TestExampleBehaviour(t *testing.T) {
	byTitle := map[string]Example{}
	for _, ex := range Examples() {
		byTitle[ex.Title] = ex
	}
	run := func(title string, mutate func(*Input)) Decision {
		ex, ok := byTitle[title]
		if !ok {
			t.Fatalf("no example titled %q", title)
		}
		in := sampleInput()
		if mutate != nil {
			mutate(&in)
		}
		return Shared().Evaluate([]Rule{{
			Name: "ex", Enabled: true, Expression: ex.Expression, Effect: ex.Effect, Message: ex.Message,
		}}, in)
	}

	if d := run("Restrict DNS names to a suffix", nil); !d.Allowed {
		t.Errorf("example-suffix refused an in-scope name: %+v", d.Violations)
	}
	d := run("Restrict DNS names to a suffix", func(in *Input) {
		in.Request.DNSNames = []string{"www.example.com", "sneaky.evil.test"}
	})
	if d.Allowed || !strings.Contains(d.Violations[0].Message, "sneaky.evil.test") {
		t.Errorf("example-suffix did not name the out-of-scope host: %+v", d.Violations)
	}

	if d := run("Wildcards need an entitlement in the token", nil); !d.Allowed {
		t.Errorf("example-wildcard refused a non-wildcard request: %+v", d.Violations)
	}
	d = run("Wildcards need an entitlement in the token", func(in *Input) {
		in.Request.Wildcard = true
	})
	if d.Allowed {
		t.Error("example-wildcard permitted a wildcard without the entitlement")
	}
	d = run("Wildcards need an entitlement in the token", func(in *Input) {
		in.Request.Wildcard = true
		in.JWT["entitlements"] = []interface{}{"pki.wildcard"}
	})
	if !d.Allowed {
		t.Errorf("example-wildcard refused an entitled wildcard: %+v", d.Violations)
	}

	d = run("IP SANs must be inside the corporate range", func(in *Input) {
		in.Request.IPAddresses = []string{"10.1.2.3", "8.8.8.8"}
	})
	if d.Allowed || !strings.Contains(d.Violations[0].Message, "8.8.8.8") {
		t.Errorf("example-ip did not reject the public address: %+v", d.Violations)
	}

	d = run("Minimum key strength", func(in *Input) {
		in.Request.Key = KeyInfo{Algorithm: "RSA", Size: 2048}
	})
	if d.Allowed {
		t.Error("example-key-strength permitted RSA-2048 where 3072 is required")
	}

	d = run("Service accounts may only name their own host", func(in *Input) {
		in.Request.DNSNames = []string{"api.payments.svc.cluster.local"}
	})
	if !d.Allowed {
		t.Errorf("example-namespace refused a name inside the caller's namespace: %+v", d.Violations)
	}
	d = run("Service accounts may only name their own host", func(in *Input) {
		in.Request.DNSNames = []string{"api.treasury.svc.cluster.local"}
	})
	if d.Allowed || !strings.Contains(d.Violations[0].Message, "payments") {
		t.Errorf("example-namespace did not refuse a foreign namespace: %+v", d.Violations)
	}
	d = run("Service accounts may only name their own host", func(in *Input) {
		delete(in.JWT, "groups")
	})
	if d.Allowed {
		t.Error("example-namespace permitted a caller with no namespace group")
	}

	d = run("Only the console may ask for a CA certificate", func(in *Input) {
		in.Request.IsCA = true
	})
	if d.Allowed {
		t.Error("example-is-ca let an issuer mint a subordinate CA")
	}
	d = run("Only the console may ask for a CA certificate", func(in *Input) {
		in.Request.IsCA = true
		in.Principal.Roles = []string{"admin"}
	})
	if !d.Allowed {
		t.Errorf("example-is-ca refused an admin: %+v", d.Violations)
	}

	d = run("Automated enrollment may not request long-lived client certificates", func(in *Input) {
		in.Request.Source = SourceACME
	})
	if d.Allowed {
		t.Error("example-source permitted a 90-day ACME certificate against a 30-day cap")
	}
}

// TestFunctionLibraryIsAvailable evaluates one expression per documented
// function group, so a renamed or dropped upstream function cannot leave a lie
// in the console's reference.
func TestFunctionLibraryIsAvailable(t *testing.T) {
	in := sampleInput()
	exprs := []string{
		// operators, macros, comprehensions, bindings
		`request.dns_names.size() == 2 && !request.is_ca && (request.wildcard ? false : true)`,
		`has(jwt.groups) && jwt.groups.exists_one(g, g == "pki-issuers")`,
		`request.dns_names.all(i, d, i >= 0 && d != "")`,
		`request.dns_names.exists(i, d, i == 0 && d == "www.example.com")`,
		`request.dns_names.existsOne(i, d, i == 1)`,
		`request.dns_names.transformList(i, d, d + "/" + string(i)).size() == 2`,
		`cel.bind(n, request.dns_names.size(), n == 2)`,
		// strings
		`request.subject.common_name.startsWith("www.") && request.subject.common_name.endsWith(".com")`,
		`request.subject.common_name.contains("example") && request.subject.common_name.matches("^www\\.")`,
		`request.subject.common_name.charAt(0) == "w" && request.subject.common_name.indexOf("example") == 4`,
		`request.subject.common_name.lastIndexOf("e") > 0`,
		`"WWW".lowerAscii() == "www" && "www".upperAscii() == "WWW"`,
		`request.subject.common_name.replace("www", "api") == "api.example.com"`,
		`request.subject.common_name.split(".").size() == 3`,
		`request.subject.common_name.substring(0, 3) == "www"`,
		`"  x  ".trim() == "x" && "ab".reverse() == "ba"`,
		`request.dns_names.join(", ").contains("example.com")`,
		`strings.quote("a") == "\"a\""`,
		`"%s/%d".format([request.profile, request.validity_days]) == "server/90"`,
		// regex + optional
		`regex.replace(request.subject.common_name, "^www", "api") == "api.example.com"`,
		`regex.extract(request.subject.common_name, "^([a-z]+)\\.").orValue("") == "www"`,
		`regex.extract(request.subject.common_name, "^ZZZ").hasValue() == false`,
		`regex.extractAll(request.subject.common_name, "[a-z]+").size() == 3`,
		// lists + sets
		`[1, 1, 2].distinct().size() == 2`,
		`[[1], [2]].flatten().size() == 2`,
		`request.dns_names.reverse()[0] == "example.com"`,
		`request.dns_names.slice(0, 1).size() == 1`,
		`["b", "a"].sort()[0] == "a"`,
		`request.dns_names.sortBy(d, d.size())[0] == "example.com"`,
		`lists.range(3).size() == 3`,
		`sets.contains(request.key_usages, ["digitalSignature"])`,
		`sets.intersects(request.ext_key_usages, ["serverAuth", "clientAuth"])`,
		`sets.equivalent(["a", "b"], ["b", "a"])`,
		// math
		`math.greatest(request.key.size, 128) == 256 && math.least(1, 2) == 1`,
		`math.abs(-1) == 1 && math.sign(-2) == -1`,
		`math.ceil(1.2) == 2.0 && math.floor(1.8) == 1.0 && math.round(1.5) == 2.0 && math.trunc(1.9) == 1.0`,
		`!math.isNaN(1.0) && math.isFinite(1.0) && !math.isInf(1.0)`,
		`math.bitAnd(6, 3) == 2 && math.bitOr(4, 1) == 5 && math.bitXor(5, 1) == 4`,
		`math.bitShiftLeft(1, 3) == 8 && math.bitShiftRight(8, 3) == 1 && math.bitNot(0) == -1`,
		// network
		`isIP("10.0.0.1") && !isIP("nope")`,
		`ip("10.1.2.3").family() == 4 && ip("::1").family() == 6`,
		`ip("127.0.0.1").isLoopback() && ip("8.8.8.8").isGlobalUnicast()`,
		`!ip("8.8.8.8").isLinkLocalUnicast() && !ip("8.8.8.8").isLinkLocalMulticast() && !ip("8.8.8.8").isUnspecified()`,
		`ip.isCanonical("2001:db8::1") && !ip.isCanonical("2001:DB8::1")`,
		`isCIDR("10.0.0.0/8") && !isCIDR("nope")`,
		`cidr("10.0.0.0/8").containsIP(request.ip_addresses[0])`,
		`cidr("10.0.0.0/8").containsCIDR("10.1.0.0/16")`,
		`cidr("10.1.2.3/24").ip() == ip("10.1.2.3") && cidr("10.1.2.0/24").isMask()`,
		`cidr("10.1.2.3/24").masked() == cidr("10.1.2.0/24") && cidr("10.0.0.0/8").prefixLength() == 8`,
		// encoding
		`base64.encode(b"ab") == "YWI=" && base64.decode("YWI=") == b"ab"`,
		// time
		`request.not_after > request.not_before && request.validity == duration("2160h")`,
		`now >= request.not_before && request.not_after > now`,
		`request.not_after < now + duration("8760h")`,
		`request.not_before.getFullYear() == 2026 && request.not_before.getMonth() == 2`,
		`request.not_before.getHours() == 12 && request.not_before.getDayOfWeek() == 0`,
		`request.not_after - request.not_before == duration("2160h")`,
		`timestamp("2026-01-01T00:00:00Z") < now`,
	}
	for _, expr := range exprs {
		d := Shared().Evaluate([]Rule{rule("fn", expr)}, in)
		if !d.Allowed {
			detail := ""
			if len(d.Violations) > 0 {
				detail = d.Violations[0].Error
			}
			t.Errorf("%q did not hold: %s", expr, detail)
		}
	}
}

// TestNoAmbientCapabilities asserts a rule is a function of its inputs. A rule
// that could read the clock, the filesystem, the network or the environment
// would not be reviewable, and would not be safe to evaluate on the signing path.
func TestNoAmbientCapabilities(t *testing.T) {
	for _, expr := range []string{
		`now() > timestamp("2020-01-01T00:00:00Z")`,
		`os.getenv("HOME") == ""`,
		`file("/etc/passwd") == ""`,
		`http("https://example.com") == ""`,
		`exec("id") == ""`,
		`dns("example.com") == ""`,
	} {
		if err := Validate(expr); err == nil {
			t.Errorf("%q compiled; the environment exposes ambient state", expr)
		}
	}
}

// TestReferenceDescribesTheLiveEnvironment: the vocabulary the console renders
// is derived from the engine, so it cannot drift.
func TestReferenceDescribesTheLiveEnvironment(t *testing.T) {
	ref, err := BuildReference()
	if err != nil {
		t.Fatalf("BuildReference: %v", err)
	}
	if len(ref.Variables) != len(Vars()) {
		t.Fatalf("reference lists %d variables, environment declares %d", len(ref.Variables), len(Vars()))
	}
	byName := map[string]VarDoc{}
	for _, v := range ref.Variables {
		byName[v.Name] = v
	}
	// The object variables must expose their fields, or the console has nothing
	// to offer an operator writing a rule.
	for _, name := range []string{VarRequest, VarURL, VarPrincipal} {
		if len(byName[name].Fields) == 0 {
			t.Errorf("object variable %q lists no fields", name)
		}
	}
	// Every advertised field must actually resolve.
	for _, name := range []string{VarRequest, VarURL, VarPrincipal} {
		for _, f := range byName[name].Fields {
			if err := Validate(fmt.Sprintf(`string(%s.%s) != "\x00"`, name, f.Name)); err != nil {
				// Not every field is string-convertible; just assert the field resolves.
				if err2 := Validate(fmt.Sprintf(`size([%s.%s]) == 1`, name, f.Name)); err2 != nil {
					t.Errorf("reference advertises %s.%s but it does not resolve: %v", name, f.Name, err2)
				}
			}
		}
	}
	if byName[VarNow].Type != "timestamp" {
		t.Errorf("now is documented as %q, which is not CEL's spelling", byName[VarNow].Type)
	}
	if len(ref.Functions) == 0 || len(ref.Examples) == 0 || ref.CostLimit == 0 {
		t.Error("the reference is missing the function library, the examples or the cost ceiling")
	}
	if len(ref.Results) != 3 {
		t.Errorf("the reference documents %d result shapes, want 3", len(ref.Results))
	}
}

// TestProgramCacheReusesCompilations: the same rule text costs one compile, and
// an edited rule is simply a different key — which is why no invalidation is
// needed when the console rewrites a rule.
func TestProgramCacheReusesCompilations(t *testing.T) {
	e := NewEngine()
	p1, err := e.cache.get(`request.validity_days <= 90`)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := e.cache.get(` request.validity_days <= 90 `)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Error("the same expression (modulo surrounding whitespace) compiled twice")
	}
	p3, _ := e.cache.get(`request.validity_days <= 30`)
	if p3 == p1 {
		t.Error("two different expressions shared a program")
	}
	// A broken expression caches its failure rather than re-parsing per issuance,
	// and still denies.
	if _, err := e.cache.get(`request.nope`); err == nil {
		t.Error("a broken expression compiled")
	}
	if _, err := e.cache.get(`request.nope`); err == nil {
		t.Error("the cached failure turned into a success")
	}
}

// TestCacheBoundIsEnforced: the dry-run surface evaluates ad-hoc expressions, so
// the cache must not grow without limit.
func TestCacheBoundIsEnforced(t *testing.T) {
	e := NewEngine()
	for i := 0; i < maxCachedPrograms+10; i++ {
		if _, err := e.cache.get(fmt.Sprintf(`request.validity_days <= %d`, i)); err != nil {
			t.Fatalf("compile %d: %v", i, err)
		}
	}
	e.cache.mu.RLock()
	n := len(e.cache.entries)
	e.cache.mu.RUnlock()
	if n > maxCachedPrograms {
		t.Errorf("cache holds %d entries, bound is %d", n, maxCachedPrograms)
	}
}

// TestConcurrentEvaluation: compiled programs are shared across issuances, so
// the engine must be safe under the concurrency a bulk run creates. Run with
// -race, this is the test that would catch a shared mutable program.
func TestConcurrentEvaluation(t *testing.T) {
	rules := []Rule{
		rule("a", `request.dns_names.all(d, d.endsWith("example.com"))`),
		rule("b", `request.validity_days <= 90`),
		{Name: "c", Enabled: true, Effect: EffectDeny, Expression: `request.wildcard`, Message: "no wildcards"},
	}
	done := make(chan bool, 32)
	for i := 0; i < 32; i++ {
		go func(n int) {
			in := sampleInput()
			if n%2 == 0 {
				in.Request.Wildcard = true
			}
			d := Shared().Evaluate(rules, in)
			done <- d.Allowed
		}(i)
	}
	allowed, denied := 0, 0
	for i := 0; i < 32; i++ {
		if <-done {
			allowed++
		} else {
			denied++
		}
	}
	if allowed != 16 || denied != 16 {
		t.Errorf("concurrent evaluation gave %d allowed / %d denied, want 16/16", allowed, denied)
	}
}

func TestEffectAndModeDefaults(t *testing.T) {
	var r Rule
	if r.EffectOrDefault() != EffectRequire {
		t.Error("the zero effect must read as require: it is the one that denies on failure")
	}
	if r.ModeOrDefault() != ModeEnforce {
		t.Error("the zero mode must read as enforce")
	}
	if (Rule{Effect: "nonsense"}).EffectOrDefault() != EffectRequire {
		t.Error("an unrecognized effect must fall back to require, not to deny")
	}
	if (Rule{Mode: "nonsense"}).ModeOrDefault() != ModeEnforce {
		t.Error("an unrecognized mode must fall back to enforce, not to monitor")
	}
}
