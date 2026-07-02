package authn

import (
	"reflect"
	"sort"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

func sortedRoles(in []rbac.Role) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, r := range in {
		out[i] = string(r)
	}
	sort.Strings(out)
	return out
}

func TestClaimMapperResolvePlatform(t *testing.T) {
	m := NewClaimMapper("groups", []ClaimMapping{
		{Value: "pki-admins", Roles: []rbac.Role{rbac.RoleAdmin}},
		{Value: "pki-issuers", Roles: []rbac.Role{rbac.RoleIssuer}},
		{Claim: "roles", Value: "auditor", Roles: []rbac.Role{rbac.RoleAuditor}},
	})

	cases := []struct {
		name   string
		claims map[string]interface{}
		want   []string
	}{
		{
			name:   "single group grants role",
			claims: map[string]interface{}{"groups": []interface{}{"pki-admins"}},
			want:   []string{"admin"},
		},
		{
			name:   "multiple groups union roles",
			claims: map[string]interface{}{"groups": []interface{}{"pki-admins", "pki-issuers"}},
			want:   []string{"admin", "issuer"},
		},
		{
			name:   "string group (not a list) also matches",
			claims: map[string]interface{}{"groups": "pki-issuers"},
			want:   []string{"issuer"},
		},
		{
			name:   "custom claim name mapping",
			claims: map[string]interface{}{"roles": []interface{}{"auditor"}},
			want:   []string{"auditor"},
		},
		{
			name:   "unrelated group grants nothing",
			claims: map[string]interface{}{"groups": []interface{}{"finance"}},
			want:   nil,
		},
		{
			name:   "no claims",
			claims: map[string]interface{}{},
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			platform, tenant := m.Resolve(tc.claims)
			if len(tenant) != 0 {
				t.Errorf("unexpected tenant roles: %v", tenant)
			}
			if got := sortedRoles(platform); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("platform roles = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClaimMapperResolveTenant(t *testing.T) {
	m := NewClaimMapper("groups", []ClaimMapping{
		{Value: "acme-issuers", Tenant: "acme-corp", Roles: []rbac.Role{rbac.RoleIssuer}},
		{Value: "acme-admins", Tenant: "acme-corp", Roles: []rbac.Role{rbac.RoleAdmin}},
		{Value: "globex-auditors", Tenant: "globex", Roles: []rbac.Role{rbac.RoleAuditor}},
		{Value: "platform-admins", Roles: []rbac.Role{rbac.RoleAdmin}},
	})

	claims := map[string]interface{}{
		"groups": []interface{}{"acme-issuers", "acme-admins", "globex-auditors", "platform-admins"},
	}
	platform, tenant := m.Resolve(claims)
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"admin"}) {
		t.Errorf("platform roles = %v, want [admin]", got)
	}
	if got := sortedRoles(tenant["acme-corp"]); !reflect.DeepEqual(got, []string{"admin", "issuer"}) {
		t.Errorf("acme-corp roles = %v, want [admin issuer]", got)
	}
	if got := sortedRoles(tenant["globex"]); !reflect.DeepEqual(got, []string{"auditor"}) {
		t.Errorf("globex roles = %v, want [auditor]", got)
	}
}

func TestClaimMapperDropsInvalidAndEmpty(t *testing.T) {
	m := NewClaimMapper("", []ClaimMapping{
		{Value: "good", Roles: []rbac.Role{rbac.RoleIssuer, "superuser" /* invalid */}},
		{Value: "no-roles", Roles: []rbac.Role{"nonsense"}}, // dropped entirely
		{Value: "", Roles: []rbac.Role{rbac.RoleAdmin}},     // no value, dropped
	})
	if m.GroupsClaim() != "groups" {
		t.Errorf("default groups claim = %q, want groups", m.GroupsClaim())
	}
	// "good" keeps only the valid role.
	platform, _ := m.Resolve(map[string]interface{}{"groups": []interface{}{"good"}})
	if got := sortedRoles(platform); !reflect.DeepEqual(got, []string{"issuer"}) {
		t.Errorf("roles = %v, want [issuer]", got)
	}
	// The all-invalid and empty-value mappings never grant anything.
	platform, _ = m.Resolve(map[string]interface{}{"groups": []interface{}{"no-roles", ""}})
	if len(platform) != 0 {
		t.Errorf("expected no roles from dropped mappings, got %v", platform)
	}
}

func TestClaimMapperGroups(t *testing.T) {
	m := NewClaimMapper("memberOf", nil)
	got := m.Groups(map[string]interface{}{"memberOf": []interface{}{"g1", "g2"}})
	if !reflect.DeepEqual(got, []string{"g1", "g2"}) {
		t.Errorf("groups = %v, want [g1 g2]", got)
	}
	// A bare string group is normalized to a single-element slice.
	if got := m.Groups(map[string]interface{}{"memberOf": "solo"}); !reflect.DeepEqual(got, []string{"solo"}) {
		t.Errorf("groups = %v, want [solo]", got)
	}
	// Missing claim yields nil.
	if got := m.Groups(map[string]interface{}{}); got != nil {
		t.Errorf("groups = %v, want nil", got)
	}
}
