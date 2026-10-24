package main

// Tests for `secsy-ca role-mapping` (Task 214).
//
// The command exists so an operator does not have to discover what an
// expression does by logging in repeatedly, which makes one property
// load-bearing: the dry-run must report what a login would actually resolve.
// It is built from the same config structs and the same compiled mappers the
// server uses, and these tests pin that down — including the cases where the
// answer is "this grants nothing", which is the answer an operator most needs
// to see explained.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// celTestConfig is a config with two declared tenants and a mapping set that
// exercises both forms: an exact value, a tenant derived by string replace, a
// tenant derived by regex extraction over a group DN, and an identity-field
// expression.
func celTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Tenants = []config.TenantConfig{{ID: "acme-corp"}, {ID: "globex"}}
	cfg.Auth.OIDC.Enabled = true
	cfg.Auth.OIDC.IssuerURL = "https://idp.corp.example.com"
	cfg.Auth.OIDC.ClientID = "console"
	cfg.Auth.OIDC.GroupsClaim = "groups"
	cfg.Auth.OIDC.RoleMappings = []config.ClaimMappingConfig{
		{Value: "pki-admins", Roles: []string{"admin"}},
		{
			Expression:       `groups.exists(g, g.startsWith("pki-issuers-"))`,
			TenantExpression: `groups.filter(g, g.startsWith("pki-issuers-")).map(g, g.replace("pki-issuers-", ""))`,
			Roles:            []string{"issuer"},
		},
		{
			Expression: `groups.exists(g, g.matches("^CN=PKI-Admins-[a-z0-9-]+,OU=Groups,DC=corp,DC=example,DC=com$"))`,
			TenantExpression: `regex.extract(groups.filter(g, g.startsWith("CN=PKI-Admins-"))[0],
			                                 "^CN=PKI-Admins-([a-z0-9-]+),").orValue("")`,
			Roles: []string{"admin"},
		},
		{Expression: `email_verified && email.endsWith("@corp.example.com")`, Roles: []string{"auditor"}},
	}
	return cfg
}

// captureRoleMappingOutput collects what fn prints so a test can assert on the
// operator-facing report. Named distinctly from the other capture helpers in
// this package so each test file stays self-contained.
func captureRoleMappingOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	runErr := fn()
	os.Stdout = orig
	_ = w.Close()
	return <-done, runErr
}

// TestRoleMappingListShowsEveryForm asserts the listing names each mapping's
// match and tenant, with the expressions rendered on one line.
func TestRoleMappingListShowsEveryForm(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{"list"})
	})
	if err != nil {
		t.Fatalf("role-mapping list: %v", err)
	}
	for _, want := range []string{
		`groups="pki-admins"`,
		"CEL: groups.exists(g, g.startsWith(\"pki-issuers-\"))",
		"<platform-wide>",
		"auth.oidc (console provider",
		"admin", "issuer", "auditor",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing does not mention %q:\n%s", want, out)
		}
	}
	// Every table row is one line: a wrapped expression would corrupt the table.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "CEL:") && strings.Count(line, "\n") > 0 {
			t.Errorf("a mapping row wrapped: %q", line)
		}
	}
}

// TestRoleMappingListIncludesDisabledSources asserts mappings written before
// the login mechanism is switched on are still inspectable — that is the order
// an operator does the work in.
func TestRoleMappingListIncludesDisabledSources(t *testing.T) {
	cfg := celTestConfig()
	cfg.Auth.OIDC.Enabled = false
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(cfg, []string{"list"})
	})
	if err != nil {
		t.Fatalf("role-mapping list: %v", err)
	}
	if !strings.Contains(out, "login disabled") {
		t.Errorf("listing does not mark the disabled source:\n%s", out)
	}
	if !strings.Contains(out, "pki-issuers-") {
		t.Errorf("listing dropped a disabled source's mappings:\n%s", out)
	}
}

// TestRoleMappingTestResolvesRoles asserts the dry-run reports the roles a
// login would resolve, including the derived tenants.
func TestRoleMappingTestResolvesRoles(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{
			"test", "-source", "default",
			"-subject", "alice", "-email", "alice@corp.example.com", "-email-verified",
			"-group", "pki-issuers-globex",
			"-group", "CN=PKI-Admins-acme-corp,OU=Groups,DC=corp,DC=example,DC=com",
		})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	for _, want := range []string{
		"MATCHED",
		"platform roles: auditor",
		`tenant "globex" roles: issuer`,
		`tenant "acme-corp" roles: admin`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run does not report %q:\n%s", want, out)
		}
	}
}

// TestRoleMappingTestExplainsARefusedTenant asserts the case an operator will
// actually hit: the pattern fires, the tenant id it derives is not one this
// deployment declares, and the mapping therefore grants nothing — said out
// loud, with the refused id, rather than reported as a plain non-match.
func TestRoleMappingTestExplainsARefusedTenant(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{
			"test", "-source", "default", "-group", "pki-issuers-typo",
		})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	if !strings.Contains(out, `refused tenant "typo"`) {
		t.Errorf("dry-run does not explain the refused tenant:\n%s", out)
	}
	if !strings.Contains(out, "platform roles: (none)") {
		t.Errorf("dry-run does not report that nothing was granted:\n%s", out)
	}
}

// TestRoleMappingTestDistinguishesFiredFromGranted asserts the report tells an
// operator which half went wrong: a pattern that matched but resolved to no
// tenant is FIRED, not a plain non-match, and the line says an empty tenant is
// never read as platform-wide.
func TestRoleMappingTestDistinguishesFiredFromGranted(t *testing.T) {
	cfg := celTestConfig()
	cfg.Auth.OIDC.RoleMappings = []config.ClaimMappingConfig{{
		Expression:       `groups.exists(g, g.startsWith("pki-"))`,
		TenantExpression: `regex.extract(groups[0], "^pki-admins-([a-z]+)$").orValue("")`,
		Roles:            []string{"admin"},
	}}
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(cfg, []string{"test", "-source", "default", "-group", "pki-something-else"})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	if !strings.Contains(out, "FIRED") {
		t.Errorf("report does not mark the mapping as fired:\n%s", out)
	}
	if !strings.Contains(out, "resolved to no tenant") {
		t.Errorf("report does not explain why nothing was granted:\n%s", out)
	}
	if !strings.Contains(out, "platform roles: (none)") {
		t.Errorf("report does not show that nothing was granted:\n%s", out)
	}
	// A plain non-match is not reported as FIRED.
	out, err = captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(cfg, []string{"test", "-source", "default", "-group", "unrelated"})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	if strings.Contains(out, "FIRED") {
		t.Errorf("an unmatched mapping was reported as fired:\n%s", out)
	}
}

// TestRoleMappingTestReportsRuntimeErrors asserts an expression that fails at
// evaluation is reported with its reason. Resolve swallows these (one broken
// mapping must not deny a login the others authorize), so the dry-run is where
// an operator sees them.
func TestRoleMappingTestReportsRuntimeErrors(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{
			"test", "-expression", `claims.department == "pki"`,
		})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	if !strings.Contains(out, "error (granted nothing)") || !strings.Contains(out, "no such key") {
		t.Errorf("dry-run does not report the evaluation error:\n%s", out)
	}
}

// TestRoleMappingTestAdHocExpression asserts the write-an-expression workflow:
// an expression supplied on the command line, evaluated against a synthetic
// identity, with claims read from a file.
func TestRoleMappingTestAdHocExpression(t *testing.T) {
	claimsFile := filepath.Join(t.TempDir(), "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"department":"pki","wids":["x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{
			"test",
			"-expression", `has(claims.department) && claims.department == "pki"`,
			"-roles", "issuer,auditor",
			"-claims", "@" + claimsFile,
		})
	})
	if err != nil {
		t.Fatalf("role-mapping test: %v", err)
	}
	if !strings.Contains(out, "MATCHED") || !strings.Contains(out, "platform roles: auditor, issuer") {
		t.Errorf("ad-hoc evaluation = %q", out)
	}

	// An ad-hoc tenant expression needs a match expression to attach to.
	if _, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{"test", "-tenant-expression", `"acme-corp"`})
	}); err == nil {
		t.Error("-tenant-expression was accepted without -expression")
	}
	// A malformed ad-hoc expression is reported as an error, not as a non-match.
	if _, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{"test", "-expression", `groups.exists(`})
	}); err == nil {
		t.Error("a malformed ad-hoc expression was accepted")
	}
}

// TestRoleMappingTestJSON asserts the machine-readable output carries the
// decisions, the resolved roles, and the identity as the expression saw it.
func TestRoleMappingTestJSON(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{
			"test", "-source", "default", "-json",
			"-group", "pki-issuers-globex", "-group", "pki-issuers-typo",
		})
	})
	if err != nil {
		t.Fatalf("role-mapping test -json: %v", err)
	}
	var got struct {
		Sources []struct {
			Name      string                 `json:"name"`
			Identity  map[string]interface{} `json:"identity"`
			Decisions []struct {
				Index    int      `json:"index"`
				Mapping  string   `json:"mapping"`
				Fired    bool     `json:"fired"`
				Matched  bool     `json:"matched"`
				Tenants  []string `json:"tenants"`
				Rejected []string `json:"rejected_tenants"`
			} `json:"decisions"`
			TenantRoles map[string][]string `json:"tenant_roles"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode -json output: %v\n%s", err, out)
	}
	if len(got.Sources) != 1 {
		t.Fatalf("sources = %d, want 1 (-source default)", len(got.Sources))
	}
	src := got.Sources[0]
	if len(src.Decisions) != 4 {
		t.Fatalf("decisions = %d, want one per mapping", len(src.Decisions))
	}
	d := src.Decisions[1]
	if !d.Fired {
		t.Errorf("decision = %+v, want fired", d)
	}
	if !d.Matched || len(d.Tenants) != 1 || d.Tenants[0] != "globex" {
		t.Errorf("decision = %+v, want a match on globex", d)
	}
	if len(d.Rejected) != 1 || d.Rejected[0] != "typo" {
		t.Errorf("decision = %+v, want the refused tenant reported", d)
	}
	if got := src.TenantRoles["globex"]; len(got) != 1 || got[0] != "issuer" {
		t.Errorf("tenant roles = %v, want issuer in globex", src.TenantRoles)
	}
	// Every variable the expression can read is echoed, by the mapper itself, so
	// a dry-run cannot be read as having evaluated different inputs than it did.
	for _, v := range []string{"subject", "email", "email_verified", "name", "username", "issuer", "provider", "groups", "claims"} {
		if _, ok := src.Identity[v]; !ok {
			t.Errorf("identity echo is missing %q: %v", v, src.Identity)
		}
	}
	if groups, ok := src.Identity["groups"].([]interface{}); !ok || len(groups) != 2 {
		t.Errorf("identity groups = %v, want the two supplied groups", src.Identity["groups"])
	}
}

// TestRoleMappingReference asserts the vocabulary help lists the variables and
// the function families an expression may use.
func TestRoleMappingReference(t *testing.T) {
	out, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{"reference"})
	})
	if err != nil {
		t.Fatalf("role-mapping reference: %v", err)
	}
	for _, want := range []string{
		"subject", "email_verified", "groups", "claims",
		"startsWith", "endsWith", "matches", "regex.replace", "regex.extract",
		"sets.intersects", "cost units",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reference does not mention %q:\n%s", want, out)
		}
	}

	jsonOut, err := captureRoleMappingOutput(t, func() error {
		return cmdRoleMapping(celTestConfig(), []string{"reference", "-json"})
	})
	if err != nil {
		t.Fatalf("role-mapping reference -json: %v", err)
	}
	var ref struct {
		Variables []struct {
			Name, Type, Doc string
		} `json:"variables"`
		Functions []string `json:"functions"`
		CostLimit uint64   `json:"cost_limit"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &ref); err != nil {
		t.Fatalf("decode reference -json: %v", err)
	}
	if len(ref.Variables) < 8 || len(ref.Functions) == 0 || ref.CostLimit == 0 {
		t.Errorf("reference -json = %+v, want the full vocabulary", ref)
	}
}

// TestRoleMappingBadInput asserts the usage errors.
func TestRoleMappingBadInput(t *testing.T) {
	cfg := celTestConfig()
	cases := [][]string{
		nil,                                     // no subcommand
		{"nonsense"},                            // unknown subcommand
		{"test", "-source", "no-such-provider"}, // unknown source
		{"test", "-claims", "not json"},         // unparseable claims
		{"test", "-claims", "@/nonexistent"},    // unreadable claims file
		{"test", "-expression", "true", "-roles", ""},
		{"test", "-expression", "true", "-roles", "administrator"}, // misspelled role
	}
	for _, args := range cases {
		if _, err := captureRoleMappingOutput(t, func() error { return cmdRoleMapping(cfg, args) }); err == nil {
			t.Errorf("cmdRoleMapping(%v) succeeded, want an error", args)
		}
	}
	// `help` is not an error.
	if _, err := captureRoleMappingOutput(t, func() error { return cmdRoleMapping(cfg, []string{"help"}) }); err != nil {
		t.Errorf("role-mapping help: %v", err)
	}
}

// TestRoleMappingSourcesRefusesBadConfig asserts the command reports a mapping
// that does not compile, naming where it is — the same refusal the server
// makes at startup.
func TestRoleMappingSourcesRefusesBadConfig(t *testing.T) {
	cfg := celTestConfig()
	cfg.Auth.LDAP.Enabled = true
	cfg.Auth.LDAP.RoleMappings = []config.ClaimMappingConfig{
		{Expression: `size(groups)`, Roles: []string{"admin"}},
	}
	_, err := captureRoleMappingOutput(t, func() error { return cmdRoleMapping(cfg, []string{"list"}) })
	if err == nil {
		t.Fatal("role-mapping list accepted a mapping that does not compile")
	}
	if !strings.Contains(err.Error(), "auth.ldap") || !strings.Contains(err.Error(), "must evaluate to bool") {
		t.Errorf("error = %q, want it to locate the bad mapping", err)
	}
}

// TestRoleMappingHelpers covers the small rendering helpers.
func TestRoleMappingHelpers(t *testing.T) {
	if got := oneLine("a\n  b\tc"); got != "a b c" {
		t.Errorf("oneLine = %q", got)
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("abc", 4); got != "abc" {
		t.Errorf("truncate shortened a short string: %q", got)
	}
	if got := joinOrNone(nil); got != "(none)" {
		t.Errorf("joinOrNone = %q", got)
	}
	if got := orDefault("  ", "fallback"); got != "fallback" {
		t.Errorf("orDefault = %q", got)
	}
	// A repeatable group flag must not split on commas: a DN contains them.
	var groups rawMultiFlag
	if err := groups.Set("CN=PKI-Admins,OU=Groups,DC=corp,DC=example,DC=com"); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Errorf("a group DN was split into %d values: %v", len(groups), groups)
	}
	if got, err := parseClaimsArg(""); err != nil || len(got) != 0 {
		t.Errorf("parseClaimsArg(\"\") = %v, %v", got, err)
	}
}
