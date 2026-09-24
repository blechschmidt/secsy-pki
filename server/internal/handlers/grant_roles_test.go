//go:build sqlite

package handlers

// Tests for the resource-role catalog REST surface (Task 198). The catalog's only
// job is to agree with the evaluator, so the assertions compare it against
// internal/rbac rather than against a second hand-written copy of the policy.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

func listResourceRoles(api *API, user *models.UserInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.ListResourceRoles(rec, reqAs(http.MethodGet, "/api/grants/roles", user, "", ""))
	return rec
}

// TestGrantRolesAuthz gates the catalog at read level: static policy
// documentation naming no resource and no principal, readable by anyone holding a
// role, closed to an unauthenticated or roleless caller.
func TestGrantRolesAuthz(t *testing.T) {
	api, _ := tenantAPI(t)
	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 200},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 200},
		// A delegate scoped to one tenant must be able to read what a role means.
		{"tenant auditor", tenantUser("taud", "a", "auditor"), 200},
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 200},
		{"root", rootUser(), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := listResourceRoles(api, tc.user); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestGrantRolesCatalog checks the catalog against rbac itself: every grantable
// role, the resource types it is meaningful on, and the exact capability bundle
// the evaluator would apply.
func TestGrantRolesCatalog(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := listResourceRoles(api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp ResourceRoleCatalogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}

	if len(resp.Roles) != len(rbac.AllResourceRoles) {
		t.Fatalf("catalog has %d roles, want %d (rbac.AllResourceRoles)", len(resp.Roles), len(rbac.AllResourceRoles))
	}
	byName := map[string]ResourceRoleInfo{}
	for i, got := range resp.Roles {
		role := rbac.AllResourceRoles[i]
		if got.Role != string(role) {
			t.Fatalf("role %d = %q, want %q (catalog order must follow rbac.AllResourceRoles)", i, got.Role, role)
		}
		byName[got.Role] = got

		// A catalog entry the grant endpoints would refuse is worse than no entry.
		if !rbac.ValidResourceRole(rbac.ResourceRole(got.Role)) {
			t.Errorf("catalog advertises %q, which rbac.ValidResourceRole rejects", got.Role)
		}
		var wantActions []string
		for _, a := range rbac.ResourceRoleActions(role) {
			wantActions = append(wantActions, string(a))
		}
		if strings.Join(got.Actions, ",") != strings.Join(wantActions, ",") {
			t.Errorf("%s actions = %v, want %v (rbac.ResourceRoleActions)", got.Role, got.Actions, wantActions)
		}
		var wantTypes []string
		for _, ty := range rbac.AllResourceTypes {
			if rbac.ResourceRoleAppliesTo(role, ty) {
				wantTypes = append(wantTypes, string(ty))
			}
		}
		if strings.Join(got.AppliesTo, ",") != strings.Join(wantTypes, ",") {
			t.Errorf("%s applies_to = %v, want %v", got.Role, got.AppliesTo, wantTypes)
		}
		if len(got.AppliesTo) == 0 || len(got.Actions) == 0 {
			t.Errorf("%s = %+v, want a non-empty resource-type and capability list", got.Role, got)
		}
	}

	// Spot-check the two policy statements an operator choosing a delegation is
	// most likely to get wrong.
	if !contains(byName[string(rbac.ResourceRoleCAAdmin)].Actions, string(rbac.ActionDelegate)) {
		t.Errorf("ca-admin actions = %v, want resource:delegate among them",
			byName[string(rbac.ResourceRoleCAAdmin)].Actions)
	}
	if contains(byName[string(rbac.ResourceRoleCAManager)].Actions, string(rbac.ActionDelegate)) {
		t.Errorf("ca-manager actions = %v, want NO resource:delegate (operating a CA is not controlling who else may)",
			byName[string(rbac.ResourceRoleCAManager)].Actions)
	}
	if got := byName[string(rbac.ResourceRoleKeySigner)].AppliesTo; len(got) != 1 || got[0] != string(rbac.ResourceSigningKey) {
		t.Errorf("key-signer applies_to = %v, want just %q", got, rbac.ResourceSigningKey)
	}

	// The scope vocabulary and the additive-authority caveat the CLI prints.
	if len(resp.Scopes) != 2 || resp.Scopes[0].Scope != string(rbac.ScopeSelf) || resp.Scopes[1].Scope != string(rbac.ScopeSubtree) {
		t.Errorf("scopes = %+v, want self then subtree", resp.Scopes)
	}
	for _, s := range resp.Scopes {
		if strings.TrimSpace(s.Description) == "" {
			t.Errorf("scope %q has no description", s.Scope)
		}
	}
	if !strings.Contains(resp.Note, "ADDITIVE") {
		t.Errorf("note = %q, want the additive-authority caveat", resp.Note)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
