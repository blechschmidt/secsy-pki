// Unit tests for the small trust-boundary decision helpers on the auth-related
// model types. These methods gate real security outcomes — whether an API token
// may authenticate (Active), how a verified token is turned into a request
// principal with the correct platform-vs-tenant scoping (Principal), and which
// tenants a principal may act on (TenantsWithRoles) — yet the package carried no
// test coverage. They are pure and need no HSM, DB, or network.
package models

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

func ptrTime(t time.Time) *time.Time { return &t }

func TestAPITokenActiveAndStatus(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name       string
		tok        *APIToken
		wantActive bool
		wantStatus string
	}{
		{"no expiry, not revoked", &APIToken{}, true, "active"},
		{"future expiry", &APIToken{ExpiresAt: ptrTime(future)}, true, "active"},
		{"past expiry", &APIToken{ExpiresAt: ptrTime(past)}, false, "expired"},
		// Expiry exactly at now is not in the future -> inactive/expired (fail-closed).
		{"expiry exactly now", &APIToken{ExpiresAt: ptrTime(now)}, false, "expired"},
		{"revoked", &APIToken{RevokedAt: ptrTime(past)}, false, "revoked"},
		// Revocation takes precedence over a still-valid expiry.
		{"revoked but not expired", &APIToken{RevokedAt: ptrTime(past), ExpiresAt: ptrTime(future)}, false, "revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tok.Active(now); got != tc.wantActive {
				t.Errorf("Active = %v, want %v", got, tc.wantActive)
			}
			if got := tc.tok.Status(now); got != tc.wantStatus {
				t.Errorf("Status = %q, want %q", got, tc.wantStatus)
			}
		})
	}

	// A nil token is never active (defensive: unknown-hash lookups return nil).
	if (*APIToken)(nil).Active(now) {
		t.Errorf("nil token reported Active")
	}
}

func TestAPITokenRevokedAndIsPlatform(t *testing.T) {
	if (*APIToken)(nil).Revoked() {
		t.Errorf("nil token reported Revoked")
	}
	if (&APIToken{}).Revoked() {
		t.Errorf("un-revoked token reported Revoked")
	}
	if !(&APIToken{RevokedAt: ptrTime(time.Now())}).Revoked() {
		t.Errorf("revoked token reported not Revoked")
	}
	if !(&APIToken{Scope: TokenScopePlatform}).IsPlatform() {
		t.Errorf("platform-scoped token reported not IsPlatform")
	}
	if (&APIToken{Scope: TokenScopeTenant}).IsPlatform() {
		t.Errorf("tenant-scoped token reported IsPlatform")
	}
}

func TestAPITokenPrincipal(t *testing.T) {
	t.Run("platform-scoped carries platform roles", func(t *testing.T) {
		tok := &APIToken{ID: "tok1", Name: "ci", Scope: TokenScopePlatform, Roles: []string{"admin", "issuer"}}
		p := tok.Principal()
		if p.Subject != "token:tok1" {
			t.Errorf("Subject = %q, want token:tok1", p.Subject)
		}
		if p.IsRoot {
			t.Errorf("an API-token principal must never be root")
		}
		if !reflect.DeepEqual(p.Roles, []string{"admin", "issuer"}) {
			t.Errorf("Roles = %v, want [admin issuer]", p.Roles)
		}
		if len(p.TenantRoles) != 0 {
			t.Errorf("platform token must not carry tenant roles, got %v", p.TenantRoles)
		}
	})

	t.Run("tenant-scoped confines roles to its tenant", func(t *testing.T) {
		tok := &APIToken{ID: "tok2", Scope: TokenScopeTenant, TenantID: "acme", Roles: []string{"issuer"}}
		p := tok.Principal()
		if len(p.Roles) != 0 {
			t.Errorf("tenant token must not carry platform roles, got %v", p.Roles)
		}
		if got := p.TenantRoles["acme"]; !reflect.DeepEqual(got, []string{"issuer"}) {
			t.Errorf("TenantRoles[acme] = %v, want [issuer]", got)
		}
	})

	t.Run("tenant-scoped without a tenant id falls back to default", func(t *testing.T) {
		tok := &APIToken{ID: "tok3", Scope: TokenScopeTenant, Roles: []string{"auditor"}}
		p := tok.Principal()
		if got := p.TenantRoles[DefaultTenantID]; !reflect.DeepEqual(got, []string{"auditor"}) {
			t.Errorf("TenantRoles[%s] = %v, want [auditor]", DefaultTenantID, got)
		}
	})

	// The principal's role slice must be a copy: later mutation of the stored
	// token must not retroactively alter an already-issued principal.
	t.Run("roles are copied, not aliased", func(t *testing.T) {
		tok := &APIToken{ID: "tok4", Scope: TokenScopePlatform, Roles: []string{"admin"}}
		p := tok.Principal()
		tok.Roles[0] = "tampered"
		if p.Roles[0] != "admin" {
			t.Errorf("principal roles aliased the token's backing array: got %v", p.Roles)
		}
	})
}

func TestUserInfoTenantsWithRoles(t *testing.T) {
	if got := (*UserInfo)(nil).TenantsWithRoles(); got != nil {
		t.Errorf("nil UserInfo = %v, want nil", got)
	}
	if got := (&UserInfo{}).TenantsWithRoles(); got != nil {
		t.Errorf("no tenant roles = %v, want nil", got)
	}
	u := &UserInfo{TenantRoles: map[string][]string{"acme": {"issuer"}, "globex": {"auditor"}}}
	got := u.TenantsWithRoles()
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"acme", "globex"}) {
		t.Errorf("tenants = %v, want [acme globex]", got)
	}
}

func TestResourceGrantProjection(t *testing.T) {
	// A stored row projects onto the evaluator's rule type verbatim, with the
	// scope default applied — the persisted and the config-declared form of the
	// same delegation must compare equal, or a grant made through the API would
	// not match the rule an operator reviewed in version control.
	stored := &ResourceGrant{
		ID:           "g-1",
		ResourceType: rbac.ResourceCA,
		ResourceID:   "ca-sub",
		EntityType:   rbac.EntityGroup,
		EntityID:     "platform-team",
		Role:         rbac.ResourceRoleCAAdmin,
		CreatedAt:    time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC),
		CreatedBy:    "root",
	}
	want := rbac.Grant{
		Resource:   rbac.Resource{Type: rbac.ResourceCA, ID: "ca-sub"},
		EntityType: rbac.EntityGroup,
		EntityID:   "platform-team",
		Role:       rbac.ResourceRoleCAAdmin,
		Scope:      rbac.ScopeSelf, // empty scope normalizes to "self"
	}
	if got := stored.Grant(); !reflect.DeepEqual(got, want) {
		t.Errorf("Grant() = %+v, want %+v", got, want)
	}
	if err := stored.Grant().Validate(); err != nil {
		t.Errorf("projected grant does not validate: %v", err)
	}

	// An explicit scope is carried through untouched.
	stored.Scope = rbac.ScopeSubtree
	if got := stored.Grant().Scope; got != rbac.ScopeSubtree {
		t.Errorf("Grant().Scope = %q, want %q", got, rbac.ScopeSubtree)
	}
}

func TestPendingApprovalExpired(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	// A zero expiry means no deadline — never expired.
	if (&PendingApproval{}).Expired(now) {
		t.Errorf("zero-expiry approval reported expired")
	}
	if (&PendingApproval{ExpiresAt: now.Add(time.Hour)}).Expired(now) {
		t.Errorf("future-expiry approval reported expired")
	}
	if !(&PendingApproval{ExpiresAt: now.Add(-time.Second)}).Expired(now) {
		t.Errorf("past-expiry approval reported not expired")
	}
}
