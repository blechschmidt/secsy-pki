// Tests for CEL role-mapping configuration (Task 214): the `expression` and
// `tenant_expression` fields on a claim -> role mapping.
//
// What is load-bearing here is that a bad expression is a LOAD error. A role
// mapping decides who administers the PKI; an expression with a typo that was
// only noticed at evaluation time would present as operators who mysteriously
// resolve to no role, discovered the moment someone needs to sign in. Every
// mapping list in the file — console providers, machine-token providers, the
// directory — goes through the same validator, so none of them can drift.
package config

import (
	"strings"
	"testing"
)

// celOIDCYAML renders a console-login config whose single role mapping is the
// one under test.
func celOIDCYAML(mapping string) string {
	return baseYAML + `
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "secsy-pki"
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    role_mappings:
      - ` + mapping + `
`
}

// TestCELRoleMappingLoads asserts the accepted forms load and keep their text
// verbatim — an expression the loader rewrote would not be the one an operator
// reviewed.
func TestCELRoleMappingLoads(t *testing.T) {
	cfg := mustLoadYAML(t, baseYAML+`
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "secsy-pki"
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    role_mappings:
      - { value: "pki-admins", roles: ["admin"] }
      - expression: 'groups.exists(g, g.startsWith("pki-issuers-"))'
        tenant_expression: |
          groups.filter(g, g.startsWith("pki-issuers-"))
                .map(g, g.replace("pki-issuers-", ""))
        roles: ["issuer"]
      - expression: 'email_verified && email.endsWith("@corp.example.com")'
        roles: ["auditor"]
`)
	mappings := cfg.Auth.OIDC.RoleMappings
	if len(mappings) != 3 {
		t.Fatalf("role_mappings = %d, want 3", len(mappings))
	}
	if mappings[0].Expression != "" || mappings[0].Value != "pki-admins" {
		t.Errorf("the exact-value mapping changed shape: %+v", mappings[0])
	}
	if !strings.Contains(mappings[1].Expression, `g.startsWith("pki-issuers-")`) {
		t.Errorf("expression = %q, want it kept verbatim", mappings[1].Expression)
	}
	if !strings.Contains(mappings[1].TenantExpression, `g.replace("pki-issuers-", "")`) {
		t.Errorf("tenant_expression = %q, want the block scalar kept", mappings[1].TenantExpression)
	}
	if mappings[2].TenantExpression != "" || mappings[2].Tenant != "" {
		t.Errorf("the platform-wide mapping gained a tenant: %+v", mappings[2])
	}
}

// TestCELRoleMappingRejectedAtLoad covers every way a mapping can be wrong.
func TestCELRoleMappingRejectedAtLoad(t *testing.T) {
	cases := []struct {
		name    string
		mapping string
		want    string
	}{
		{
			name:    "syntax error",
			mapping: `{ expression: 'groups.exists(g, g.startsWith("pki-")', roles: ["admin"] }`,
			want:    "Syntax error",
		},
		{
			name:    "undeclared variable",
			mapping: `{ expression: 'department == "pki"', roles: ["admin"] }`,
			want:    "undeclared reference to 'department'",
		},
		{
			name:    "undeclared function",
			mapping: `{ expression: 'lookup(groups)', roles: ["admin"] }`,
			want:    "undeclared reference to 'lookup'",
		},
		{
			name:    "match expression is not a bool",
			mapping: `{ expression: 'size(groups)', roles: ["admin"] }`,
			want:    "must evaluate to bool",
		},
		{
			name:    "tenant expression is not a string",
			mapping: `{ expression: 'true', tenant_expression: 'size(groups)', roles: ["admin"] }`,
			want:    "must evaluate to string or list(string)",
		},
		{
			name:    "value and expression together",
			mapping: `{ value: "pki-admins", expression: 'true', roles: ["admin"] }`,
			want:    "mutually exclusive",
		},
		{
			name:    "claim and expression together",
			mapping: `{ claim: "groups", expression: 'true', roles: ["admin"] }`,
			want:    "claim applies to the exact-value form",
		},
		{
			name:    "tenant and tenant_expression together",
			mapping: `{ expression: 'true', tenant: "acme", tenant_expression: '"acme"', roles: ["admin"] }`,
			want:    "mutually exclusive",
		},
		{
			name:    "neither value nor expression",
			mapping: `{ roles: ["admin"] }`,
			want:    "value or expression is required",
		},
		{
			name:    "no roles",
			mapping: `{ expression: 'true' }`,
			want:    "at least one role is required",
		},
		{
			name:    "misspelled role",
			mapping: `{ expression: 'true', roles: ["administrator"] }`,
			want:    "unknown role",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, celOIDCYAML(tc.mapping))
			if err == nil {
				t.Fatalf("Load accepted %s", tc.mapping)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "auth.oidc.role_mappings[0]") {
				t.Errorf("error = %q, want it to locate the mapping", err)
			}
		})
	}
}

// TestCELRoleMappingValidatedOnEveryMappingList asserts the validator covers
// the machine-token providers, the per-provider console mappings, and the
// directory — not just the top-level console block.
func TestCELRoleMappingValidatedOnEveryMappingList(t *testing.T) {
	bad := `{ expression: 'size(groups)', roles: ["admin"] }`
	cases := map[string]string{
		"oidc.providers": baseYAML + `
oidc:
  providers:
    - name: github
      issuer_url: "https://token.actions.githubusercontent.com"
      client_id: "secsy-pki"
      role_mappings:
        - ` + bad + `
`,
		"auth.oidc.providers": baseYAML + `
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "secsy-pki"
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - name: entra
        issuer_url: "https://login.microsoftonline.com/t/v2.0"
        client_id: "console"
        client_secret: "s"
        role_mappings:
          - ` + bad + `
`,
		"auth.ldap": baseYAML + `
auth:
  ldap:
    enabled: true
    url: "ldaps://dc.corp.example.com:636"
    user_dn_template: "uid=%s,ou=people,dc=corp,dc=example,dc=com"
    role_mappings:
      - ` + bad + `
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, yaml)
			if err == nil {
				t.Fatal("Load accepted a mapping whose expression is not a bool")
			}
			if !strings.Contains(err.Error(), "must evaluate to bool") {
				t.Errorf("error = %q, want the expression type error", err)
			}
			if !strings.Contains(err.Error(), "role_mappings[0]") {
				t.Errorf("error = %q, want it to locate the mapping", err)
			}
		})
	}
}

// TestRoleMappingAcceptsApprover asserts a mapping may grant the approver role.
// It is the one role whose natural home is an IdP group — the four-eyes
// checkers — and the mapper has always honored it; only the mapping validator's
// own shorter role list used to refuse it.
func TestRoleMappingAcceptsApprover(t *testing.T) {
	cfg := mustLoadYAML(t, celOIDCYAML(`{ expression: 'groups.exists(g, g == "pki-approvers")', roles: ["approver"] }`))
	if got := cfg.Auth.OIDC.RoleMappings[0].Roles; len(got) != 1 || got[0] != "approver" {
		t.Errorf("roles = %v, want [approver]", got)
	}
	// A misspelling is still refused, and the message lists what is accepted.
	_, err := loadYAML(t, celOIDCYAML(`{ expression: 'true', roles: ["approvers"] }`))
	if err == nil {
		t.Fatal("Load accepted the role \"approvers\"")
	}
	for _, want := range []string{"unknown role", "approver", "auditor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// TestTenantIDs asserts the accessor that bounds a derived tenant id.
func TestTenantIDs(t *testing.T) {
	cfg := mustLoadYAML(t, baseYAML+`
tenants:
  - id: "acme-corp"
    slug: "acme"
  - id: "globex"
`)
	got := cfg.TenantIDs()
	if len(got) != 2 || got[0] != "acme-corp" || got[1] != "globex" {
		t.Errorf("TenantIDs() = %v, want [acme-corp globex]", got)
	}
	// A deployment with no tenants declares none — the restriction then has
	// nothing to check against, which the mapper treats as "no restriction".
	if got := mustLoadYAML(t, baseYAML).TenantIDs(); len(got) != 0 {
		t.Errorf("TenantIDs() = %v, want none", got)
	}
}
