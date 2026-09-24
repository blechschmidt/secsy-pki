package handlers

// REST surface for the resource-role catalog (Task 191) — the counterpart of
// `secsy-ca grant roles` (Task 198).
//
// POST /api/grants accepts a role name and rejects anything else, but nothing
// told a caller which names exist, which resource types each is meaningful on, or
// what authority it confers: the console could only hard-code the vocabulary and
// silently drift from the evaluator. This endpoint reports the catalog straight
// out of internal/rbac, so it cannot drift — a role or capability added to the
// bundle table appears here with no change to this file.
//
// It is pure policy documentation: no store access, no per-request state, and
// nothing about any actual grant (those are GET /api/grants).

import (
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ResourceRoleInfo describes one grantable resource role.
type ResourceRoleInfo struct {
	// Role is the name to pass as `role` when creating a grant.
	Role string `json:"role"`
	// AppliesTo lists the resource types the role is meaningful on ("ca",
	// "signing-key"). A role granted on any other type would confer nothing, so
	// the grant endpoints refuse it.
	AppliesTo []string `json:"applies_to"`
	// Actions is the capability bundle the role confers AT THE RESOURCE IT IS
	// GRANTED ON, sorted. There is no allow-all resource role: every capability a
	// grant confers is listed explicitly.
	Actions []string `json:"actions"`
}

// ResourceGrantScopeInfo describes one grant scope.
type ResourceGrantScopeInfo struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// ResourceRoleCatalogResponse is the body of GET /api/grants/roles: the same
// three things `secsy-ca grant roles` prints — the roles with their capabilities,
// the scopes, and the additive-authority note.
type ResourceRoleCatalogResponse struct {
	Roles  []ResourceRoleInfo       `json:"roles"`
	Scopes []ResourceGrantScopeInfo `json:"scopes"`
	// Note is the standing caveat an operator choosing a delegation must read.
	Note string `json:"note"`
}

// resourceGrantScopeCatalog is the scope half of the catalog, worded as the CLI
// words it.
var resourceGrantScopeCatalog = []ResourceGrantScopeInfo{
	{Scope: string(rbac.ScopeSelf), Description: "the named resource only (default)"},
	{Scope: string(rbac.ScopeSubtree), Description: "the named CA and every CA beneath it, including ones created later"},
}

// resourceGrantNote is the additive-authority note the CLI prints under the
// table.
const resourceGrantNote = "Grants are ADDITIVE: they widen what a user or group may do at one resource and " +
	"never remove authority a platform or tenant role already confers."

// ListResourceRoles handles GET /api/grants/roles — the REST form of
// `secsy-ca grant roles`. Read-gated (any assigned role): it is static policy
// documentation naming no resource, no principal, and no tenant, and a delegate
// about to be granted a role has to be able to read what it means.
func (a *API) ListResourceRoles(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	roles := make([]ResourceRoleInfo, 0, len(rbac.AllResourceRoles))
	for _, role := range rbac.AllResourceRoles {
		info := ResourceRoleInfo{Role: string(role), AppliesTo: []string{}, Actions: []string{}}
		for _, t := range rbac.AllResourceTypes {
			if rbac.ResourceRoleAppliesTo(role, t) {
				info.AppliesTo = append(info.AppliesTo, string(t))
			}
		}
		for _, act := range rbac.ResourceRoleActions(role) {
			info.Actions = append(info.Actions, string(act))
		}
		roles = append(roles, info)
	}
	writeJSON(w, http.StatusOK, ResourceRoleCatalogResponse{
		Roles:  roles,
		Scopes: resourceGrantScopeCatalog,
		Note:   resourceGrantNote,
	})
}
