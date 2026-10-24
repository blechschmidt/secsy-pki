package celexpr

import (
	"strings"
	"testing"
)

// TestRoleMappingEnvIsShared asserts the environment is built once and reused:
// the whole point of a single environment is that config validation and the
// login path cannot disagree about what compiles.
func TestRoleMappingEnvIsShared(t *testing.T) {
	a, err := RoleMappingEnv()
	if err != nil {
		t.Fatalf("RoleMappingEnv: %v", err)
	}
	b, err := RoleMappingEnv()
	if err != nil {
		t.Fatalf("RoleMappingEnv: %v", err)
	}
	if a != b {
		t.Error("RoleMappingEnv returned two different environments")
	}
}

// TestActivationCoversEveryDeclaredVariable asserts the invariant that keeps a
// mapping from failing at login for a reason no test would catch: a DECLARED
// variable missing from the activation is an evaluation error, so every
// variable RoleMappingVars declares must be populated by Activation — and an
// expression over an empty identity must still evaluate.
func TestActivationCoversEveryDeclaredVariable(t *testing.T) {
	env := testEnv(t)
	activation := RoleMappingInput{}.Activation()
	for _, v := range RoleMappingVars() {
		if _, ok := activation[v.Name()]; !ok {
			t.Errorf("variable %q is declared but absent from Activation()", v.Name())
		}
		// Reading the variable must work against the empty identity, which is
		// what an IdP asserting nothing optional produces.
		p, err := env.CompileBool(expressionReading(v.Name()))
		if err != nil {
			t.Errorf("compiling an expression over %q: %v", v.Name(), err)
			continue
		}
		if _, err := p.Eval(activation); err != nil {
			t.Errorf("evaluating %q against an empty identity: %v", v.Name(), err)
		}
	}
	if len(activation) != len(RoleMappingVars()) {
		t.Errorf("Activation() has %d entries for %d declared variables",
			len(activation), len(RoleMappingVars()))
	}
}

// expressionReading returns a boolean expression that reads the named variable
// whatever its type.
func expressionReading(name string) string {
	switch name {
	case VarGroups:
		return `size(groups) >= 0`
	case VarClaims:
		return `size(claims) >= 0`
	case VarEmailVerified:
		return `email_verified || !email_verified`
	default:
		return `size(` + name + `) >= 0`
	}
}

// TestActivationPopulatesNonNilContainers asserts the empty identity presents
// an empty list and map rather than a null, so size()/in/filter work instead of
// erroring.
func TestActivationPopulatesNonNilContainers(t *testing.T) {
	activation := RoleMappingInput{}.Activation()
	groups, ok := activation[VarGroups].([]string)
	if !ok || groups == nil {
		t.Errorf("groups = %#v, want a non-nil empty slice", activation[VarGroups])
	}
	claims, ok := activation[VarClaims].(map[string]interface{})
	if !ok || claims == nil {
		t.Errorf("claims = %#v, want a non-nil empty map", activation[VarClaims])
	}
}

// TestValidateRoleMapping covers the loader's gate.
func TestValidateRoleMapping(t *testing.T) {
	cases := []struct {
		name          string
		match, tenant string
		wantErr       string
	}{
		{name: "both empty is allowed here", match: "", tenant: ""},
		{
			name:   "valid pair",
			match:  `groups.exists(g, g.startsWith("pki-"))`,
			tenant: `groups.filter(g, g.startsWith("pki-")).map(g, g.replace("pki-", ""))`,
		},
		{name: "bad match", match: `groups.exists(`, wantErr: "expression:"},
		{name: "match wrong type", match: `size(groups)`, wantErr: "expression:"},
		{name: "bad tenant", match: `true`, tenant: `size(groups)`, wantErr: "tenant_expression:"},
		{name: "tenant only", tenant: `"acme"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRoleMapping(tc.match, tc.tenant)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("ValidateRoleMapping: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("ValidateRoleMapping succeeded, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestCompileRoleMappingHelpers asserts the two compile entry points agree with
// the environment they claim to use.
func TestCompileRoleMappingHelpers(t *testing.T) {
	if _, err := CompileRoleMappingMatch(`groups.exists(g, g == "x")`); err != nil {
		t.Errorf("CompileRoleMappingMatch: %v", err)
	}
	if _, err := CompileRoleMappingMatch(`"x"`); err == nil {
		t.Error("CompileRoleMappingMatch accepted a non-bool expression")
	}
	if _, err := CompileRoleMappingTenant(`regex.extract(subject, "^repo:([^/]+)/")`); err != nil {
		t.Errorf("CompileRoleMappingTenant: %v", err)
	}
	if _, err := CompileRoleMappingTenant(`email_verified`); err == nil {
		t.Error("CompileRoleMappingTenant accepted a bool expression")
	}
}

// TestRoleMappingVarsAreDocumented asserts every declared variable carries the
// help text the `secsy-ca role-mapping reference` command prints.
func TestRoleMappingVarsAreDocumented(t *testing.T) {
	for _, v := range RoleMappingVars() {
		if strings.TrimSpace(v.Doc()) == "" {
			t.Errorf("variable %q has no documentation", v.Name())
		}
		if strings.TrimSpace(v.Type()) == "" {
			t.Errorf("variable %q has no type", v.Name())
		}
	}
}
