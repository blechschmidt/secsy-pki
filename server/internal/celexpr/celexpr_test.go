package celexpr

import (
	"fmt"
	"strings"
	"testing"
)

// testEnv is the environment the unit tests compile against: the role-mapping
// variable set, which is also the only one this package declares.
func testEnv(t *testing.T) *Env {
	t.Helper()
	env, err := RoleMappingEnv()
	if err != nil {
		t.Fatalf("RoleMappingEnv: %v", err)
	}
	return env
}

// testVars is a representative identity: a corporate principal in two
// structured directory groups, with a couple of extra claims.
func testVars() map[string]interface{} {
	return RoleMappingInput{
		Subject:       "alice-oidc-subject",
		Email:         "alice@corp.example.com",
		EmailVerified: true,
		Name:          "Alice Example",
		Username:      "alice",
		Issuer:        "https://idp.corp.example.com",
		Provider:      "entra",
		Groups: []string{
			"CN=PKI-Admins-acme-corp,OU=Groups,DC=corp,DC=example,DC=com",
			"pki-issuers-globex",
			"staff",
		},
		Claims: map[string]interface{}{
			"sub":        "alice-oidc-subject",
			"email":      "alice@corp.example.com",
			"department": "pki",
			"roles":      []interface{}{"auditor"},
		},
	}.Activation()
}

// TestCompileBoolStandardFunctions covers the function vocabulary the
// documentation promises. Each case is an expression that must be true of the
// identity above; a failure here means a documented function is not actually
// available (or does not mean what the docs say).
func TestCompileBoolStandardFunctions(t *testing.T) {
	env := testEnv(t)
	cases := map[string]string{
		"startsWith":           `groups.exists(g, g.startsWith("CN=PKI-Admins-"))`,
		"endsWith":             `email.endsWith("@corp.example.com")`,
		"contains":             `subject.contains("oidc")`,
		"matches (RE2)":        `groups.exists(g, g.matches("^pki-issuers-[a-z]+$"))`,
		"bool variable":        `email_verified`,
		"in operator":          `"staff" in groups`,
		"size":                 `size(groups) == 3`,
		"has guard":            `has(claims.department) && claims.department == "pki"`,
		"absent claim guard":   `!has(claims.nothing)`,
		"claim list":           `"auditor" in claims.roles`,
		"filter + index":       `groups.filter(g, g.startsWith("pki-"))[0] == "pki-issuers-globex"`,
		"map":                  `groups.map(g, g.lowerAscii()).exists(g, g == "staff")`,
		"all":                  `groups.all(g, size(g) > 0)`,
		"exists_one":           `groups.exists_one(g, g.startsWith("pki-issuers-"))`,
		"ternary":              `(email_verified ? "yes" : "no") == "yes"`,
		"replace":              `"pki-issuers-globex".replace("pki-issuers-", "") == "globex"`,
		"split":                `"a,b,c".split(",").size() == 3`,
		"trim":                 `"  x  ".trim() == "x"`,
		"lowerAscii":           `"ACME".lowerAscii() == "acme"`,
		"upperAscii":           `"acme".upperAscii() == "ACME"`,
		"indexOf":              `"abc".indexOf("b") == 1`,
		"substring":            `"globex".substring(0, 3) == "glo"`,
		"join":                 `["a", "b"].join("-") == "a-b"`,
		"quote":                `strings.quote("a") == "\"a\""`,
		"regex.replace":        `regex.replace("pki-issuers-globex", "^pki-issuers-(.*)$", "\\1") == "globex"`,
		"regex.extract":        `regex.extract("CN=PKI-Admins-acme,OU=x", "^CN=PKI-Admins-([a-z]+),").orValue("") == "acme"`,
		"regex.extract none":   `!regex.extract("nothing", "^(zzz)").hasValue()`,
		"regex.extractAll":     `regex.extractAll("id:1 id:2", "id:[0-9]").size() == 2`,
		"sets.intersects":      `sets.intersects(groups, ["staff", "other"])`,
		"sets.contains":        `sets.contains(groups, ["staff"])`,
		"sets.equivalent":      `sets.equivalent(["a", "b"], ["b", "a"])`,
		"lists distinct":       `["a", "a", "b"].distinct().size() == 2`,
		"lists sort":           `["b", "a"].sort() == ["a", "b"]`,
		"lists slice":          `groups.slice(0, 1).size() == 1`,
		"identity: username":   `username == "alice"`,
		"identity: issuer":     `issuer.startsWith("https://idp.")`,
		"identity: provider":   `provider == "entra"`,
		"identity: name":       `name == "Alice Example"`,
		"identity: claims map": `claims.sub == subject`,
	}
	vars := testVars()
	for name, expr := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := env.CompileBool(expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := p.Eval(vars)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if !got {
				t.Errorf("%s evaluated false, want true", expr)
			}
			if p.Source() != expr {
				t.Errorf("Source() = %q, want the compiled text", p.Source())
			}
		})
	}
}

// TestCompileBoolRejectsWrongShape asserts the static gate: a role mapping must
// not be able to ship an expression that only fails once someone logs in.
func TestCompileBoolRejectsWrongShape(t *testing.T) {
	env := testEnv(t)
	cases := map[string]string{
		"syntax error":         `groups.exists(g, g.startsWith("x")`,
		"undeclared variable":  `nosuchvariable == "x"`,
		"undeclared function":  `readFile("/etc/passwd") == "x"`,
		"wrong result type":    `size(groups)`,
		"string result":        `"not a bool"`,
		"empty":                ``,
		"whitespace only":      "   \n  ",
		"unknown claim method": `claims.nope()`,
	}
	for name, expr := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := env.CompileBool(expr); err == nil {
				t.Errorf("CompileBool(%q) succeeded, want an error", expr)
			}
		})
	}
}

// TestCompileStrings covers the tenant-expression shape: a string, a list of
// strings, and an optional, all normalized to a slice — with empty results
// dropped, because "extracted nothing" must not read as a tenant.
func TestCompileStrings(t *testing.T) {
	env := testEnv(t)
	cases := []struct {
		name string
		expr string
		want []string
	}{
		{"literal string", `"acme-corp"`, []string{"acme-corp"}},
		{"identity field", `provider`, []string{"entra"}},
		{"replace", `"pki-issuers-globex".replace("pki-issuers-", "")`, []string{"globex"}},
		{
			"list via filter+map",
			`groups.filter(g, g.startsWith("pki-issuers-")).map(g, g.replace("pki-issuers-", ""))`,
			[]string{"globex"},
		},
		{
			"regex extraction over several groups",
			`groups.map(g, regex.extract(g, "^CN=PKI-Admins-([a-z-]+),").orValue(""))`,
			[]string{"acme-corp"}, // the two non-matching groups yield "" and are dropped
		},
		{"optional with a value", `regex.extract("x-acme", "^x-(.*)$")`, []string{"acme"}},
		{"optional with none", `regex.extract("x-acme", "^zzz-(.*)$")`, nil},
		{"empty string is dropped", `""`, nil},
		{"whitespace is dropped", `"   "`, nil},
		{"empty list", `groups.filter(g, g == "nothing")`, nil},
		{"claim list", `claims.roles`, []string{"auditor"}},
	}
	vars := testVars()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := env.CompileStrings(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := p.Eval(vars)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("eval = %q, want %q", got, tc.want)
			}
			if p.Source() != tc.expr {
				t.Errorf("Source() = %q, want the compiled text", p.Source())
			}
		})
	}
}

// TestCompileStringsRejectsWrongShape asserts a tenant expression cannot ship a
// bool, a number, or a list of non-strings.
func TestCompileStringsRejectsWrongShape(t *testing.T) {
	env := testEnv(t)
	for name, expr := range map[string]string{
		"bool":        `email_verified`,
		"int":         `size(groups)`,
		"syntax":      `groups.filter(`,
		"undeclared":  `tenantOf(groups)`,
		"empty":       ``,
		"list of int": `[1, 2]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := env.CompileStrings(expr); err == nil {
				t.Errorf("CompileStrings(%q) succeeded, want an error", expr)
			}
		})
	}
}

// TestEvalRuntimeErrorsAreReported asserts an expression that type-checks but
// fails at evaluation returns an error rather than a value. Every caller treats
// an error as "no match", so the error must not be silently a false.
func TestEvalRuntimeErrorsAreReported(t *testing.T) {
	env := testEnv(t)
	t.Run("absent map key", func(t *testing.T) {
		p, err := env.CompileBool(`claims.missing == "x"`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := p.Eval(testVars())
		if err == nil {
			t.Fatalf("eval = %v, want an error for an unguarded absent claim", got)
		}
		if !strings.Contains(err.Error(), "missing") {
			t.Errorf("error %q does not name the absent key", err)
		}
	})
	t.Run("index out of range", func(t *testing.T) {
		p, err := env.CompileStrings(`groups.filter(g, g == "nothing")[0]`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got, err := p.Eval(testVars()); err == nil {
			t.Fatalf("eval = %q, want an error for an empty-filter index", got)
		}
	})
	t.Run("invalid regex", func(t *testing.T) {
		p, err := env.CompileBool(`subject.matches("(")`)
		if err != nil {
			// Compile-time rejection is even better than a runtime error.
			return
		}
		if _, err := p.Eval(testVars()); err == nil {
			t.Error("an invalid regex neither failed to compile nor to evaluate")
		}
	})
	t.Run("nil program", func(t *testing.T) {
		var bp *BoolProgram
		if _, err := bp.Eval(nil); err == nil {
			t.Error("a nil BoolProgram evaluated without error")
		}
		var sp *StringsProgram
		if _, err := sp.Eval(nil); err == nil {
			t.Error("a nil StringsProgram evaluated without error")
		}
		if bp.Source() != "" || sp.Source() != "" {
			t.Error("a nil program reported a source")
		}
	})
}

// TestCostLimitBoundsEvaluation asserts the guard that makes it safe to
// evaluate operator-written expressions on the authentication path: a quadratic
// comprehension over an attacker-sized claim is cut off, while the heaviest
// realistic mapping over the same input stays well inside the budget.
func TestCostLimitBoundsEvaluation(t *testing.T) {
	env := testEnv(t)
	big := make([]string, 1000)
	for i := range big {
		big[i] = fmt.Sprintf("CN=PKI-Admins-team%04d,OU=Groups,DC=corp,DC=example,DC=com", i)
	}
	vars := RoleMappingInput{Groups: big}.Activation()

	quadratic, err := env.CompileBool(`groups.all(a, groups.all(b, a == b || a != b))`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := quadratic.Eval(vars); err == nil {
		t.Error("a quadratic comprehension over 1000 groups was not cost-limited")
	} else if !strings.Contains(err.Error(), "cost limit") {
		t.Errorf("error = %v, want a cost-limit error", err)
	}

	realistic, err := env.CompileStrings(
		`groups.filter(g, g.startsWith("CN=PKI-Admins-")).map(g, regex.extract(g, "^CN=PKI-Admins-([a-z0-9]+),").orValue(""))`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := realistic.Eval(vars)
	if err != nil {
		t.Fatalf("a realistic mapping over 1000 groups must fit the budget: %v", err)
	}
	if len(got) != len(big) {
		t.Errorf("extracted %d tenants, want %d", len(got), len(big))
	}
}

// TestNoAmbientCapabilities asserts an expression is a function of its inputs:
// the library exposes nothing that reads the clock, the filesystem, the
// network, or the process environment. A new extension library added to
// Functions() that brought one of these in would fail here.
func TestNoAmbientCapabilities(t *testing.T) {
	env := testEnv(t)
	for _, expr := range []string{
		`now() > timestamp("2020-01-01T00:00:00Z")`,
		`timestamp(0) < timestamp(1)`, // the standard timestamp type exists, but...
		`os.getenv("HOME") == ""`,
		`file("/etc/passwd") == ""`,
		`http("https://example.com") == ""`,
	} {
		if _, err := env.CompileBool(expr); err == nil && !strings.HasPrefix(expr, "timestamp(") {
			t.Errorf("%q compiled; the environment exposes ambient state", expr)
		}
	}
}

// TestNewEnvRejectsBadDeclarations asserts a programming error in a variable
// set surfaces at construction.
func TestNewEnvRejectsBadDeclarations(t *testing.T) {
	if _, err := NewEnv(StringVar("", "no name")); err == nil {
		t.Error("NewEnv accepted a variable with no name")
	}
	var nilEnv *Env
	if _, err := nilEnv.CompileBool(`true`); err == nil {
		t.Error("a nil Env compiled an expression")
	}
	if got := nilEnv.Vars(); got != nil {
		t.Errorf("a nil Env reported variables: %v", got)
	}
}

// TestProgramsAreSafeForConcurrentUse asserts the property the whole design
// rests on: a program is compiled once at startup and evaluated on every login,
// from whichever request goroutine arrives. Run under -race this is the proof
// that the compile-once/evaluate-many split is sound.
func TestProgramsAreSafeForConcurrentUse(t *testing.T) {
	env := testEnv(t)
	match, err := env.CompileBool(`groups.exists(g, g.startsWith("CN=PKI-Admins-")) && email_verified`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	tenant, err := env.CompileStrings(
		`groups.map(g, regex.extract(g, "^CN=PKI-Admins-([a-z-]+),").orValue(""))`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	const workers = 16
	errCh := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			// Each goroutine brings its own activation, as each request does.
			vars := testVars()
			for n := 0; n < 50; n++ {
				ok, err := match.Eval(vars)
				if err != nil {
					errCh <- err
					return
				}
				if !ok {
					errCh <- errUnexpectedResult
					return
				}
				got, err := tenant.Eval(vars)
				if err != nil {
					errCh <- err
					return
				}
				if len(got) != 1 || got[0] != "acme-corp" {
					errCh <- errUnexpectedResult
					return
				}
			}
			errCh <- nil
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent evaluation: %v", err)
		}
	}
}

// errUnexpectedResult marks a concurrent evaluation that returned the wrong
// answer rather than an error.
var errUnexpectedResult = errorString("concurrent evaluation produced the wrong result")

type errorString string

func (e errorString) Error() string { return string(e) }

// TestDynResultIsCheckedAtEvaluation covers the one branch where the static
// type gate cannot decide: an expression whose result comes straight out of the
// dynamically-typed claim map. The gate lets it compile — rejecting it would
// rule out `claims.x` entirely — so the check that a bool is really a bool
// happens at evaluation, and a claim holding something else is an error rather
// than a truthy value.
func TestDynResultIsCheckedAtEvaluation(t *testing.T) {
	env := testEnv(t)
	p, err := env.CompileBool(`claims.enabled`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	withClaim := func(v interface{}) map[string]interface{} {
		return RoleMappingInput{Claims: map[string]interface{}{"enabled": v}}.Activation()
	}
	got, err := p.Eval(withClaim(true))
	if err != nil || !got {
		t.Errorf("a true claim = %v, %v; want true", got, err)
	}
	got, err = p.Eval(withClaim(false))
	if err != nil || got {
		t.Errorf("a false claim = %v, %v; want false", got, err)
	}
	for _, v := range []interface{}{"yes", 1, []interface{}{"yes"}, map[string]interface{}{}} {
		if got, err := p.Eval(withClaim(v)); err == nil {
			t.Errorf("a %T claim evaluated to %v, want an error (not a truthy value)", v, got)
		}
	}

	// The same for a tenant expression reading a claim: a list of strings is
	// usable, a list of numbers is not.
	tp, err := env.CompileStrings(`claims.tenants`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got2, err := tp.Eval(RoleMappingInput{
		Claims: map[string]interface{}{"tenants": []interface{}{"acme", "globex"}},
	}.Activation())
	if err != nil || len(got2) != 2 {
		t.Errorf("a string-list claim = %q, %v; want two tenants", got2, err)
	}
	if got2, err := tp.Eval(RoleMappingInput{
		Claims: map[string]interface{}{"tenants": []interface{}{1, 2}},
	}.Activation()); err == nil {
		t.Errorf("a number-list claim evaluated to %q, want an error", got2)
	}
}
