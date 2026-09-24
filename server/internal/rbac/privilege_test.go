package rbac

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// IsPrivilegedRole decides when minting a token needs four-eyes approval
// (internal/handlers/tokens.go, cmd/secsy-ca/token.go). Under-reporting a role
// as unprivileged silently removes dual control from a privilege escalation, so
// the answer is asserted twice: once against an explicit expectation per role,
// and once against the capability model recomputed independently.

func TestIsPrivilegedRole(t *testing.T) {
	tests := []struct {
		role Role
		want bool
		why  string
	}{
		{RoleAdmin, true, "allow-all superuser"},
		{RoleIssuer, true, "cert:issue mints certificates"},
		{RoleSigner, true, "artifact:sign signs releases"},
		{RoleApprover, true, "approval:approve is the checker half of dual control"},
		{RoleAuditor, false, "read-only oversight: audit:read plus approval:read and nothing else"},
		// An unrecognized name must not be reported as privileged; the callers
		// validate role names with ValidRole first (internal/handlers/tokens.go),
		// so the pair of guards is what keeps a typo from bypassing the gate.
		{"", false, "empty role holds no capability"},
		{"Admin", false, "role names are case-sensitive, so a typo is not admin"},
		{"admin ", false, "a trailing space is not admin"},
		{"root", false, "not a role name at all"},
		{Role(ResourceRoleCAAdmin), false, "resource roles live in a separate vocabulary"},
	}
	covered := make(map[Role]bool, len(tests))
	for _, tc := range tests {
		covered[tc.role] = true
		if got := IsPrivilegedRole(tc.role); got != tc.want {
			t.Errorf("IsPrivilegedRole(%q) = %v, want %v (%s)", tc.role, got, tc.want, tc.why)
		}
		if !tc.want && ValidRole(tc.role) && AnyPrivilegedRole([]Role{tc.role}) {
			t.Errorf("AnyPrivilegedRole([%q]) disagrees with IsPrivilegedRole", tc.role)
		}
	}
	// A newly added role must not slip through untested.
	for _, r := range AllRoles {
		if !covered[r] {
			t.Errorf("role %q is not covered by this table: decide deliberately whether it is privileged", r)
		}
	}
}

// TestIsPrivilegedRoleMatchesCapabilityModel is the drift guard. IsPrivilegedRole
// is documented as derived from the capability model rather than a hardcoded list
// (rbac.go:262-268), so it must agree with the same question computed from the
// public surface: does this role grant anything beyond the two read-only
// oversight capabilities? If a future role grants, say, secret:decrypt and only
// the internal table is updated, this catches the mismatch.
func TestIsPrivilegedRoleMatchesCapabilityModel(t *testing.T) {
	readOnly := map[Action]bool{ActionReadAudit: true, ActionReadApproval: true}
	for _, role := range AllRoles {
		want := false
		var proof Action
		for _, act := range AllActions {
			if readOnly[act] {
				continue
			}
			if RoleGrants(role, act) {
				want, proof = true, act
				break
			}
		}
		if got := IsPrivilegedRole(role); got != want {
			t.Errorf("IsPrivilegedRole(%q) = %v, but the capability model says %v (e.g. %s)",
				role, got, want, proof)
		}
	}
	// Sanity-check the independent computation itself: the read-only exclusion
	// must be exactly those two actions, or the guard above becomes vacuous.
	if len(readOnly) != 2 || !readOnly[ActionReadAudit] || !readOnly[ActionReadApproval] {
		t.Fatal("the read-only action set under test drifted")
	}
	if !IsPrivilegedRole(RoleApprover) || IsPrivilegedRole(RoleAuditor) {
		t.Fatal("the two boundary roles no longer straddle the privileged line")
	}
}

func TestAnyPrivilegedRole(t *testing.T) {
	tests := []struct {
		name  string
		roles []Role
		want  bool
	}{
		{name: "nil", roles: nil, want: false},
		{name: "empty", roles: []Role{}, want: false},
		{name: "read-only only", roles: []Role{RoleAuditor}, want: false},
		// The privileged role sits last, so a loop that only inspects the first
		// element (or returns early) is caught.
		{name: "privileged last", roles: []Role{RoleAuditor, RoleIssuer}, want: true},
		{name: "privileged first", roles: []Role{RoleIssuer, RoleAuditor}, want: true},
		{name: "unknown role alone", roles: []Role{"wheel"}, want: false},
		{name: "unknown role plus admin", roles: []Role{"wheel", RoleAdmin}, want: true},
		{name: "duplicates", roles: []Role{RoleAuditor, RoleAuditor}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnyPrivilegedRole(tc.roles); got != tc.want {
				t.Errorf("AnyPrivilegedRole(%v) = %v, want %v", tc.roles, got, tc.want)
			}
		})
	}
}

// TestEnumeratedConstantsAreComplete is a drift guard over the All… slices. A
// constant added to a const block but forgotten in its slice breaks quietly:
// effective-permission introspection replays the real decision for every action
// in AllActions (rbac.go:186-189, "the reported capability set cannot drift from
// what the gates enforce"), validation walks AllRoles / AllResourceTypes, and the
// CLI offers AllResourceRoles as the valid choices. Constants are invisible to
// reflection, so the package's own source is parsed to enumerate them.
func TestEnumeratedConstantsAreComplete(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		typ    string
		listed []string
	}{
		{name: "AllActions", file: "rbac.go", typ: "Action", listed: toStrings(AllActions)},
		{name: "AllRoles", file: "rbac.go", typ: "Role", listed: toStrings(AllRoles)},
		{name: "AllResourceRoles", file: "grant.go", typ: "ResourceRole", listed: toStrings(AllResourceRoles)},
		{name: "AllResourceTypes", file: "grant.go", typ: "ResourceType", listed: toStrings(AllResourceTypes)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			declared := declaredStringConsts(t, tc.file, tc.typ)
			listed := make(map[string]bool, len(tc.listed))
			for _, v := range tc.listed {
				if listed[v] {
					t.Errorf("%s lists %q twice", tc.name, v)
				}
				listed[v] = true
			}
			for value, constName := range declared {
				if !listed[value] {
					t.Errorf("%s.%s (%q) is declared in %s but missing from %s",
						tc.typ, constName, value, tc.file, tc.name)
				}
			}
			for _, v := range tc.listed {
				if _, ok := declared[v]; !ok {
					t.Errorf("%s contains %q, which is not a declared %s constant in %s",
						tc.name, v, tc.typ, tc.file)
				}
			}
		})
	}
}

// toStrings renders a slice of any string-based enum as plain strings.
func toStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// declaredStringConsts parses one of the package's own source files and returns
// every `Name Type = "value"` constant of the given type, keyed by value.
func declaredStringConsts(t *testing.T, file, typeName string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	out := make(map[string]string)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != typeName {
				continue
			}
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				t.Fatalf("%s: unexpected %s const shape %v", file, typeName, vs.Names)
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("%s: %s const %s is not a string literal", file, typeName, vs.Names[0].Name)
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: unquoting %s: %v", file, vs.Names[0].Name, err)
			}
			if prev, dup := out[value]; dup {
				t.Errorf("%s: %s constants %s and %s share the value %q",
					file, typeName, prev, vs.Names[0].Name, value)
			}
			out[value] = vs.Names[0].Name
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s constants found in %s — did the declarations move?", typeName, file)
	}
	return out
}
