package authn

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// adGroup renders an Active-Directory-style group DN for a PKI admin team,
// which is the shape the expression mappings are written for.
func adGroup(team string) string {
	return "CN=PKI-Admins-" + team + ",OU=Groups,DC=corp,DC=example,DC=com"
}

// celMappings is the mapping set most of these tests resolve against: a
// platform-wide grant keyed on a verified corporate address, a tenant grant
// whose tenant is extracted from a structured group name, and a tenant grant
// that yields a LIST of tenants.
func celMappings() []ClaimMapping {
	return []ClaimMapping{
		{
			Expression: `email_verified && email.endsWith("@corp.example.com") && subject != ""`,
			Roles:      []rbac.Role{rbac.RoleAuditor},
		},
		{
			Expression: `groups.exists(g, g.matches("^CN=PKI-Admins-[a-z0-9-]+,OU=Groups,DC=corp,DC=example,DC=com$"))`,
			TenantExpression: `regex.extract(groups.filter(g, g.startsWith("CN=PKI-Admins-"))[0],
			                                 "^CN=PKI-Admins-([a-z0-9-]+),").orValue("")`,
			Roles: []rbac.Role{rbac.RoleAdmin},
		},
		{
			Expression: `groups.exists(g, g.startsWith("pki-issuers-"))`,
			TenantExpression: `groups.filter(g, g.startsWith("pki-issuers-"))
			                         .map(g, g.replace("pki-issuers-", ""))`,
			Roles: []rbac.Role{rbac.RoleIssuer},
		},
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// TestCELMappingGrantsPlatformRoles asserts an expression over the identity
// fields (not the claim map) grants the role, and that the same expression
// grants nothing when one conjunct does not hold — in particular that an
// unverified address does not satisfy email_verified.
func TestCELMappingGrantsPlatformRoles(t *testing.T) {
	m := mustMapper(t, "groups", celMappings()[:1])
	cases := []struct {
		name string
		id   Identity
		want []string
	}{
		{
			name: "verified corporate address",
			id:   Identity{Subject: "alice", Email: "alice@corp.example.com", EmailVerified: true},
			want: []string{"auditor"},
		},
		{
			name: "unverified address grants nothing",
			id:   Identity{Subject: "alice", Email: "alice@corp.example.com"},
			want: nil,
		},
		{
			name: "another domain grants nothing",
			id:   Identity{Subject: "alice", Email: "alice@partner.example.net", EmailVerified: true},
			want: nil,
		},
		{
			name: "no subject grants nothing",
			id:   Identity{Email: "alice@corp.example.com", EmailVerified: true},
			want: nil,
		},
		{
			name: "empty identity grants nothing",
			id:   Identity{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			platform, tenant := m.ResolveIdentity(tc.id)
			if len(tenant) != 0 {
				t.Errorf("unexpected tenant roles: %v", tenant)
			}
			if got := sortedRoles(platform); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("platform roles = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCELTenantExpressionDerivesTenants asserts the regex-replace / regex-
// extract half: the tenant a mapping grants in is computed from the group name,
// one tenant or several.
func TestCELTenantExpressionDerivesTenants(t *testing.T) {
	m := mustMapper(t, "groups", celMappings(),
		WithKnownTenants([]string{"acme-corp", "globex", "initech"}))

	t.Run("regex.extract yields one tenant", func(t *testing.T) {
		_, tenant := m.ResolveIdentity(Identity{Subject: "alice", Groups: []string{adGroup("acme-corp")}})
		if got := sortedRoles(tenant["acme-corp"]); !reflect.DeepEqual(got, []string{"admin"}) {
			t.Errorf("acme-corp roles = %v, want [admin]", got)
		}
		if len(tenant) != 1 {
			t.Errorf("tenant roles = %v, want only acme-corp", tenant)
		}
	})

	t.Run("filter+map yields several tenants", func(t *testing.T) {
		_, tenant := m.ResolveIdentity(Identity{Subject: "bob", Groups: []string{
			"pki-issuers-globex", "pki-issuers-initech", "staff",
		}})
		if got := sortedRoles(tenant["globex"]); !reflect.DeepEqual(got, []string{"issuer"}) {
			t.Errorf("globex roles = %v, want [issuer]", got)
		}
		if got := sortedRoles(tenant["initech"]); !reflect.DeepEqual(got, []string{"issuer"}) {
			t.Errorf("initech roles = %v, want [issuer]", got)
		}
		if len(tenant) != 2 {
			t.Errorf("tenant roles = %v, want globex and initech", tenant)
		}
	})

	t.Run("platform and tenant mappings compose", func(t *testing.T) {
		platform, tenant := m.ResolveIdentity(Identity{
			Subject: "carol", Email: "carol@corp.example.com", EmailVerified: true,
			Groups: []string{adGroup("globex"), "pki-issuers-acme-corp"},
		})
		if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"auditor"}) {
			t.Errorf("platform roles = %v, want [auditor]", got)
		}
		if got := sortedRoles(tenant["globex"]); !reflect.DeepEqual(got, []string{"admin"}) {
			t.Errorf("globex roles = %v, want [admin]", got)
		}
		if got := sortedRoles(tenant["acme-corp"]); !reflect.DeepEqual(got, []string{"issuer"}) {
			t.Errorf("acme-corp roles = %v, want [issuer]", got)
		}
	})
}

// TestCELTenantExpressionNeverEscalatesToPlatform is the central fail-closed
// property: a mapping whose pattern matched but whose tenant expression
// resolved to nothing must grant NOTHING. Were the empty result read the way an
// omitted `tenant:` is read, a pattern that failed to extract an id would hand
// out platform-wide — cross-tenant — authority.
func TestCELTenantExpressionNeverEscalatesToPlatform(t *testing.T) {
	m := mustMapper(t, "groups", []ClaimMapping{{
		Expression:       `groups.exists(g, g.startsWith("pki-"))`,
		TenantExpression: `regex.extract(groups[0], "^pki-admins-([a-z]+)$").orValue("")`,
		Roles:            []rbac.Role{rbac.RoleAdmin},
	}})
	// The pattern matches the group, but the tenant pattern does not.
	platform, tenant := m.ResolveIdentity(Identity{Groups: []string{"pki-something-else"}})
	if len(platform) != 0 {
		t.Errorf("platform roles = %v, want none — an unextracted tenant must not grant platform-wide", platform)
	}
	if len(tenant) != 0 {
		t.Errorf("tenant roles = %v, want none", tenant)
	}

	// Explain separates the two halves: the pattern FIRED, and the mapping still
	// granted nothing. An operator needs that distinction — it is the difference
	// between fixing the match pattern and fixing the tenant expression.
	decisions := m.Explain(Identity{Groups: []string{"pki-something-else"}})
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}
	if decisions[0].Matched {
		t.Error("a mapping that granted nothing was reported as matched")
	}
	if !decisions[0].Fired {
		t.Error("the match expression returned true but the decision does not report it fired")
	}
	// A mapping whose match half did NOT apply reports neither.
	none := m.Explain(Identity{Groups: []string{"unrelated"}})
	if none[0].Fired || none[0].Matched {
		t.Errorf("an unmatched mapping reported fired=%v matched=%v", none[0].Fired, none[0].Matched)
	}
}

// TestCELUnknownTenantIsRefused asserts a derived tenant id outside the
// declared set grants nothing, and that the refusal is visible.
func TestCELUnknownTenantIsRefused(t *testing.T) {
	mappings := []ClaimMapping{{
		Expression:       `groups.exists(g, g.startsWith("pki-issuers-"))`,
		TenantExpression: `groups.filter(g, g.startsWith("pki-issuers-")).map(g, g.replace("pki-issuers-", ""))`,
		Roles:            []rbac.Role{rbac.RoleIssuer},
	}}
	id := Identity{Groups: []string{"pki-issuers-acme-corp", "pki-issuers-ACME-CORP", "pki-issuers-nope"}}

	restricted := mustMapper(t, "groups", mappings, WithKnownTenants([]string{"acme-corp"}))
	_, tenant := restricted.ResolveIdentity(id)
	if len(tenant) != 1 || len(tenant["acme-corp"]) != 1 {
		t.Errorf("tenant roles = %v, want only acme-corp", tenant)
	}
	decisions := restricted.Explain(id)
	if got := sortedStrings(decisions[0].Rejected); !reflect.DeepEqual(got, []string{"ACME-CORP", "nope"}) {
		t.Errorf("rejected = %v, want the two ids outside the declared set", got)
	}

	// With no declared tenants there is nothing to check against, so the
	// syntactic gate alone applies and all three ids are granted in.
	unrestricted := mustMapper(t, "groups", mappings)
	_, tenant = unrestricted.ResolveIdentity(id)
	if len(tenant) != 3 {
		t.Errorf("tenant roles = %v, want all three derived ids", tenant)
	}
}

// TestCELDerivedTenantMustLookLikeAnID asserts the syntactic gate on a derived
// tenant id. The id comes from claim values the IdP controls, and it goes on to
// key role maps, log lines, and audit records.
func TestCELDerivedTenantMustLookLikeAnID(t *testing.T) {
	m := mustMapper(t, "groups", []ClaimMapping{{
		Expression:       `size(groups) > 0`,
		TenantExpression: `groups[0]`,
		Roles:            []rbac.Role{rbac.RoleAdmin},
	}})
	for _, bad := range []string{
		"../../etc/passwd", "acme corp", "acme\ncorp", "-leading-dash", ".leading-dot",
		strings.Repeat("a", 65), "acme/corp", "acme*", "<acme>",
	} {
		platform, tenant := m.ResolveIdentity(Identity{Groups: []string{bad}})
		if len(platform) != 0 || len(tenant) != 0 {
			t.Errorf("tenant id %q granted %v / %v, want nothing", bad, platform, tenant)
		}
	}
	for _, good := range []string{"acme", "acme-corp", "acme.corp", "acme_corp", "ACME1", "t:1", "a@b"} {
		_, tenant := m.ResolveIdentity(Identity{Groups: []string{good}})
		if len(tenant[good]) != 1 {
			t.Errorf("tenant id %q granted %v, want [admin]", good, tenant)
		}
	}
}

// TestCELRuntimeErrorIsFailClosedAndReported asserts an expression that fails
// at evaluation grants nothing, does not break the OTHER mappings, and reaches
// the error handler — the only signal that a mapping is broken rather than
// simply not matching.
func TestCELRuntimeErrorIsFailClosedAndReported(t *testing.T) {
	var errs []string
	m := mustMapper(t, "groups", []ClaimMapping{
		// Unguarded claim lookup: a runtime error for an identity without it.
		{Expression: `claims.department == "pki"`, Roles: []rbac.Role{rbac.RoleAdmin}},
		// Indexing an empty filter result: a runtime error in a TENANT expression.
		{
			Expression:       `size(groups) > 0`,
			TenantExpression: `groups.filter(g, g == "nothing")[0]`,
			Roles:            []rbac.Role{rbac.RoleIssuer},
		},
		// A sound mapping that must still be honored.
		{Expression: `"staff" in groups`, Roles: []rbac.Role{rbac.RoleAuditor}},
	}, WithExpressionErrorHandler(func(err error) { errs = append(errs, err.Error()) }))

	platform, tenant := m.ResolveIdentity(Identity{Groups: []string{"staff"}})
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"auditor"}) {
		t.Errorf("platform roles = %v, want [auditor] — the sound mapping must survive", got)
	}
	if len(tenant) != 0 {
		t.Errorf("tenant roles = %v, want none", tenant)
	}
	if len(errs) != 2 {
		t.Fatalf("error handler calls = %d (%v), want 2", len(errs), errs)
	}
	for _, e := range errs {
		if !strings.Contains(e, "role mapping") {
			t.Errorf("error %q does not identify the mapping", e)
		}
	}
	// A mapper with no handler must behave identically, just silently.
	silent := mustMapper(t, "groups", []ClaimMapping{
		{Expression: `claims.department == "pki"`, Roles: []rbac.Role{rbac.RoleAdmin}},
	})
	if platform, _ := silent.ResolveIdentity(Identity{}); len(platform) != 0 {
		t.Errorf("platform roles = %v, want none", platform)
	}
}

// TestCELMappingConstructionErrors asserts a contradictory or uncompilable
// mapping is refused at construction — the server declines to start rather than
// come up and deny the operators it was configured to admit.
func TestCELMappingConstructionErrors(t *testing.T) {
	cases := []struct {
		name    string
		mapping ClaimMapping
		want    string
	}{
		{
			name:    "value and expression",
			mapping: ClaimMapping{Value: "x", Expression: `true`, Roles: []rbac.Role{rbac.RoleAdmin}},
			want:    "mutually exclusive",
		},
		{
			name:    "claim and expression",
			mapping: ClaimMapping{Claim: "groups", Expression: `true`, Roles: []rbac.Role{rbac.RoleAdmin}},
			want:    "exact-value mapping",
		},
		{
			name: "tenant and tenant_expression",
			mapping: ClaimMapping{
				Value: "x", Tenant: "acme", TenantExpression: `"acme"`, Roles: []rbac.Role{rbac.RoleAdmin},
			},
			want: "mutually exclusive",
		},
		{
			name:    "match expression does not compile",
			mapping: ClaimMapping{Expression: `groups.exists(`, Roles: []rbac.Role{rbac.RoleAdmin}},
			want:    "celexpr",
		},
		{
			name:    "match expression is not a bool",
			mapping: ClaimMapping{Expression: `size(groups)`, Roles: []rbac.Role{rbac.RoleAdmin}},
			want:    "must evaluate to bool",
		},
		{
			name: "tenant expression is not a string",
			mapping: ClaimMapping{
				Expression: `true`, TenantExpression: `size(groups)`, Roles: []rbac.Role{rbac.RoleAdmin},
			},
			want: "must evaluate to string",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClaimMapper("groups", []ClaimMapping{tc.mapping})
			if err == nil {
				t.Fatalf("NewClaimMapper accepted %+v", tc.mapping)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "role_mappings[0]") {
				t.Errorf("error = %q, want it to locate the mapping", err)
			}
		})
	}
}

// TestCELInertMappingsAreDropped asserts a mapping that cannot grant anything
// is dropped rather than kept as something that looks like authorization.
func TestCELInertMappingsAreDropped(t *testing.T) {
	m := mustMapper(t, "groups", []ClaimMapping{
		{Expression: `true`, Roles: []rbac.Role{"nonsense"}}, // no valid role
		{Expression: `true`},                 // no role at all
		{Roles: []rbac.Role{rbac.RoleAdmin}}, // nothing to match
		{Expression: `"staff" in groups`, Roles: []rbac.Role{rbac.RoleAuditor}},
	})
	kept := m.Mappings()
	if len(kept) != 1 || kept[0].Expression != `"staff" in groups` {
		t.Fatalf("kept mappings = %+v, want only the sound one", kept)
	}
	if got := len(m.Explain(Identity{})); got != 1 {
		t.Errorf("Explain reported %d decisions, want 1", got)
	}
}

// TestResolveFromClaimsAloneDerivesTheIdentity asserts the claims-only entry
// point (used by the machine-Bearer path and by any caller holding nothing but
// a token) populates the identity variables from the standard claim names, so
// the same expression works on both paths.
func TestResolveFromClaimsAloneDerivesTheIdentity(t *testing.T) {
	m := mustMapper(t, "memberOf", []ClaimMapping{
		{
			Expression: `subject == "svc-1" && issuer == "https://idp.example.com" &&
			             username == "svc" && email == "svc@corp.example.com" && email_verified &&
			             name == "Service One" && groups.exists(g, g == "pki-signers")`,
			Roles: []rbac.Role{rbac.RoleSigner},
		},
	})
	claims := map[string]interface{}{
		"sub":                "svc-1",
		"iss":                "https://idp.example.com",
		"preferred_username": "svc",
		"email":              "svc@corp.example.com",
		"email_verified":     true,
		"name":               "Service One",
		"memberOf":           []interface{}{"pki-signers"},
	}
	platform, _ := m.Resolve(claims)
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"signer"}) {
		t.Fatalf("platform roles = %v, want [signer]", got)
	}

	id := m.IdentityFromClaims(claims)
	if id.Subject != "svc-1" || id.Issuer != "https://idp.example.com" ||
		id.Username != "svc" || id.Email != "svc@corp.example.com" ||
		!id.EmailVerified || id.Name != "Service One" {
		t.Errorf("IdentityFromClaims = %+v, want the standard claims read", id)
	}
	if !reflect.DeepEqual(id.Groups, []string{"pki-signers"}) {
		t.Errorf("groups = %v, want [pki-signers] from the configured claim", id.Groups)
	}
	// A nil claim set resolves to nothing rather than panicking.
	if platform, tenant := m.Resolve(nil); platform != nil || tenant != nil {
		t.Errorf("Resolve(nil) = %v / %v, want nothing", platform, tenant)
	}
}

// TestExpressionSeesResolvedGroupsNotJustTheClaim asserts the group list an
// expression reads is the one the caller resolved — the IdP claim plus the
// internal group memberships the store records — and that it falls back to the
// claim when the caller resolved none.
func TestExpressionSeesResolvedGroupsNotJustTheClaim(t *testing.T) {
	m := mustMapper(t, "groups", []ClaimMapping{
		{Expression: `"internal-only" in groups`, Roles: []rbac.Role{rbac.RoleAdmin}},
	})
	// The claim does not carry the group; the caller's resolved list does.
	platform, _ := m.ResolveIdentity(Identity{
		Groups: []string{"idp-group", "internal-only"},
		Claims: map[string]interface{}{"groups": []interface{}{"idp-group"}},
	})
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"admin"}) {
		t.Errorf("platform roles = %v, want [admin]", got)
	}
	// With no resolved list, the configured claim is read instead.
	platform, _ = m.ResolveIdentity(Identity{
		Claims: map[string]interface{}{"groups": []interface{}{"internal-only"}},
	})
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"admin"}) {
		t.Errorf("platform roles = %v, want [admin] from the claim fallback", got)
	}
}

// TestExactAndExpressionMappingsCoexist asserts the two forms compose in one
// list, which is how a deployment migrates from enumerated groups to patterns.
func TestExactAndExpressionMappingsCoexist(t *testing.T) {
	m := mustMapper(t, "groups", []ClaimMapping{
		{Value: "pki-admins", Roles: []rbac.Role{rbac.RoleAdmin}},
		{Claim: "roles", Value: "auditor", Roles: []rbac.Role{rbac.RoleAuditor}},
		{Expression: `groups.exists(g, g.startsWith("pki-signers-"))`, Roles: []rbac.Role{rbac.RoleSigner}},
	})
	platform, _ := m.ResolveIdentity(Identity{
		Groups: []string{"pki-admins", "pki-signers-ci"},
		Claims: map[string]interface{}{
			"groups": []interface{}{"pki-admins", "pki-signers-ci"},
			"roles":  []interface{}{"auditor"},
		},
	})
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"admin", "auditor", "signer"}) {
		t.Errorf("platform roles = %v, want [admin auditor signer]", got)
	}
}

// TestDescribeIsOneLine asserts the diagnostic rendering stays a single line
// even for a block-scalar expression: it goes into tables and log lines.
func TestDescribeIsOneLine(t *testing.T) {
	m := ClaimMapping{
		Expression:       "groups.exists(g,\n  g.startsWith(\"pki-\"))",
		TenantExpression: "groups\n  .map(g, g)",
		Roles:            []rbac.Role{rbac.RoleIssuer},
	}
	got := m.Describe()
	if strings.Contains(got, "\n") {
		t.Errorf("Describe() = %q, want a single line", got)
	}
	for _, want := range []string{"expression=", "tenant_expression=", "roles=[issuer]"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, want it to contain %q", got, want)
		}
	}
	// The exact-value form names the claim it reads, and the default claim when
	// the mapping does not name one.
	if got := (ClaimMapping{Value: "x", Roles: []rbac.Role{rbac.RoleAdmin}}).Describe(); !strings.Contains(got, "<groups claim>") {
		t.Errorf("Describe() = %q, want it to mark the default claim", got)
	}
	if got := (ClaimMapping{Claim: "wids", Value: "x", Roles: []rbac.Role{rbac.RoleAdmin}}).Describe(); !strings.Contains(got, `wids="x"`) {
		t.Errorf("Describe() = %q, want it to name the claim", got)
	}
	if got := (ClaimMapping{Value: "x", Tenant: "acme", Roles: []rbac.Role{rbac.RoleAdmin}}).Describe(); !strings.Contains(got, "tenant=acme") {
		t.Errorf("Describe() = %q, want it to name the tenant", got)
	}
}

// TestNilMapperIsInert asserts the zero value cannot grant anything.
func TestNilMapperIsInert(t *testing.T) {
	var m *ClaimMapper
	if platform, tenant := m.ResolveIdentity(Identity{}); platform != nil || tenant != nil {
		t.Errorf("a nil mapper granted %v / %v", platform, tenant)
	}
	if got := m.Explain(Identity{}); got != nil {
		t.Errorf("a nil mapper explained %v", got)
	}
	if got := m.Mappings(); got != nil {
		t.Errorf("a nil mapper reported mappings %v", got)
	}
	if got := m.GroupsClaim(); got != "groups" {
		t.Errorf("a nil mapper's groups claim = %q, want the default", got)
	}
}
