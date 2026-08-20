package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Resource-scoped authorization at the request layer (Task 191).
//
// rbac_audit.go decides coarse-grained standing: what a principal may do
// anywhere, or anywhere within a tenant. This file adds the third and narrowest
// source of authority — a grant naming ONE CA or key — and the endpoints that
// administer those grants.
//
// The evaluation order is deliberately "roles first, grants second". A grant
// lookup costs a database round trip, and a principal that is already authorized
// by a platform or tenant role does not need one, so the common path is
// unchanged and pays nothing. Grants are purely additive, so consulting them
// only after a role check has failed can never flip an allow into a deny.

// SetResourceGrants installs the declarative grants from the `rbac.grants`
// configuration blocks. They are unioned with the runtime grants stored in the
// database on every decision. Safe to call again on a configuration reload.
func (a *API) SetResourceGrants(grants []rbac.Grant) {
	cp := append([]rbac.Grant(nil), grants...)
	a.configGrants.Store(&cp)
}

// configuredGrants returns the currently installed declarative grants.
func (a *API) configuredGrants() []rbac.Grant {
	if p := a.configGrants.Load(); p != nil {
		return *p
	}
	return nil
}

// identityFor builds the set of names a principal answers to when grants are
// matched: its subject, its verified email, and the union of its internal
// (database) groups with the groups asserted by the identity provider.
//
// Both group sources matter. Internal groups let a deployment model teams
// without touching the IdP; directory groups let an existing enterprise group be
// handed a CA without mirroring its membership here. A grant naming either kind
// resolves the same way.
func (a *API) identityFor(user *models.UserInfo) rbac.Identity {
	if user == nil {
		return rbac.Identity{}
	}
	id := rbac.Identity{
		Subject:       user.Subject,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Groups:        append([]string(nil), user.Groups...),
	}
	if internal, err := a.db.GetUserGroups(user.Subject); err == nil {
		id.Groups = append(id.Groups, internal...)
	} else {
		log.Printf("resource grants: group lookup for %q failed: %v", user.Subject, err)
	}
	return id
}

// grantSetAt loads every grant that could bear on res — those recorded on the
// resource itself plus those on the supplied ancestors — from both the
// declarative configuration and the database.
func (a *API) grantSetAt(res rbac.Resource, ancestors []rbac.Resource) (*rbac.GrantSet, error) {
	scope := append([]rbac.Resource{res}, ancestors...)
	inScope := make(map[string]bool, len(scope))
	for _, r := range scope {
		inScope[r.String()] = true
	}

	var grants []rbac.Grant
	for _, g := range a.configuredGrants() {
		if inScope[g.Resource.String()] {
			grants = append(grants, g)
		}
	}
	stored, err := a.db.ListResourceGrantsAt(scope)
	if err != nil {
		return nil, err
	}
	for i := range stored {
		grants = append(grants, stored[i].Grant())
	}
	return rbac.NewGrantSet(grants), nil
}

// caAncestry returns the ancestors of a CA-shaped resource as resources of the
// same type, nearest first. Only X.509 CAs form a hierarchy; SSH CAs and signing
// keys are flat, so they have no ancestry and subtree grants do not apply.
func (a *API) caAncestry(res rbac.Resource) ([]rbac.Resource, error) {
	if res.Type != rbac.ResourceCA {
		return nil, nil
	}
	ids, err := a.db.GetCAAncestors(res.ID)
	if err != nil {
		return nil, err
	}
	out := make([]rbac.Resource, 0, len(ids))
	for _, id := range ids {
		out = append(out, rbac.Resource{Type: rbac.ResourceCA, ID: id})
	}
	return out, nil
}

// grantAllows reports whether a resource-scoped grant authorizes the user for
// action at res. It is the additive third source of authority; callers reach it
// only after the platform/tenant role check has already said no.
func (a *API) grantAllows(user *models.UserInfo, res rbac.Resource, action rbac.Action) bool {
	if user == nil || !res.Valid() {
		return false
	}
	ancestors, err := a.caAncestry(res)
	if err != nil {
		log.Printf("resource grants: ancestry lookup for %s failed: %v", res, err)
		return false
	}
	gs, err := a.grantSetAt(res, ancestors)
	if err != nil {
		log.Printf("resource grants: lookup for %s failed: %v", res, err)
		return false
	}
	return gs.Allows(res, ancestors, a.identityFor(user), action)
}

// canOnResource is the full per-resource decision: root, then platform role,
// then tenant role within the resource's tenant, then a grant on the resource or
// an ancestor. tenantID may be empty for resources with no tenant binding, in
// which case only platform standing and grants apply. A single authz metric is
// recorded for the combined decision.
func (a *API) canOnResource(user *models.UserInfo, res rbac.Resource, tenantID string, action rbac.Action) bool {
	allowed := a.decideInTenant(user, tenantID, action) || a.grantAllows(user, res, action)
	metrics.RecordAuthz(string(action), allowed)
	return allowed
}

// canOnCA is the chokepoint every per-CA authorization goes through. It resolves
// the CA's owning tenant (recording it on the request context so a resulting
// audit event is attributed correctly) and then applies canOnResource.
//
// It returns notFound=true when the CA does not exist, so callers can answer 404
// rather than leaking the difference between "absent" and "forbidden" to a
// principal with no standing.
func (a *API) canOnCA(ctx context.Context, user *models.UserInfo, caID string, action rbac.Action) (allowed, notFound bool, err error) {
	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		return false, false, err
	}
	if tenantID == "" {
		return false, true, nil
	}
	middleware.SetTenant(ctx, tenantID)
	return a.canOnResource(user, rbac.Resource{Type: rbac.ResourceCA, ID: caID}, tenantID, action), false, nil
}

// authorizeCAManage is the HTTP wrapper around canOnCA used by the per-CA
// management endpoints (rotate, retire, cross-sign, delete, import, grow the
// hierarchy, bulk-revoke). It resolves the CA's tenant, records it on the
// request context so a resulting audit event is attributed correctly, and
// authorizes ca:manage there — satisfied by a tenant role OR a resource grant on
// this specific CA.
//
// On denial it records the audit event under action (pass "" to skip, for read
// endpoints that do not warrant one), writes the response, and returns
// ok=false. On success it returns the CA's tenant.
func (a *API) authorizeCAManage(w http.ResponseWriter, r *http.Request, caID, action string) (string, bool) {
	user := middleware.GetUserInfo(r.Context())
	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CA lookup failed: %v", err)
		return "", false
	}
	if tenantID == "" {
		writeError(w, http.StatusNotFound, "CA %q not found", caID)
		return "", false
	}
	middleware.SetTenant(r.Context(), tenantID)
	if !a.canOnResource(user, rbac.Resource{Type: rbac.ResourceCA, ID: caID}, tenantID, rbac.ActionManageCA) {
		if action != "" {
			a.recordEvent(r, action, caID, "", audit.ResultDenied, string(rbac.ActionManageCA)+" capability required")
		}
		writeError(w, http.StatusForbidden,
			"administering this CA requires the %s capability for tenant %q, or an administrative grant on ca/%s",
			rbac.ActionManageCA, tenantID, caID)
		return "", false
	}
	return tenantID, true
}

// canOnSigningKey reports whether the caller may perform action against ONE
// named signing key on the secret layer: the tenant-wide capability, or a
// resource grant on `signing-key/<name>` (Task 191). It is what lets a release
// pipeline be handed exactly the key it signs with, and no other key in the
// tenant.
func (a *API) canOnSigningKey(ctx context.Context, tenantID, keyName string, action rbac.Action) bool {
	user := middleware.GetUserInfo(ctx)
	res := rbac.Resource{Type: rbac.ResourceSigningKey, ID: keyName}
	if keyName == "" {
		// No key named: only tenant-wide standing can authorize.
		return a.canInTenant(user, tenantID, action)
	}
	return a.canOnResource(user, res, tenantID, action)
}

// signingKeysVisibleByGrant returns the names of signing keys the caller holds a
// grant on. A listing endpoint unions it with the tenant-wide view so a
// delegated principal sees exactly its own keys instead of an empty list.
func (a *API) signingKeysVisibleByGrant(user *models.UserInfo) map[string]bool {
	if user == nil {
		return nil
	}
	stored, err := a.db.ListAllResourceGrants()
	if err != nil {
		log.Printf("resource grants: signing-key listing failed: %v", err)
		return nil
	}
	grants := append([]rbac.Grant(nil), a.configuredGrants()...)
	for i := range stored {
		grants = append(grants, stored[i].Grant())
	}
	gs := rbac.NewGrantSet(grants)
	if gs.Empty() {
		return nil
	}
	out := make(map[string]bool)
	for _, name := range gs.ResourcesFor(rbac.ResourceSigningKey, a.identityFor(user)) {
		out[name] = true
	}
	return out
}

// visibleCAIDsFromGrants returns the CA IDs the user can see purely by virtue of
// a grant. A delegated operator holds no tenant role, so without this it would
// be invisible to it — the CA would 404 on read even though the same principal
// may administer it. Listing endpoints union this with tenant-scoped visibility.
func (a *API) visibleCAIDsFromGrants(user *models.UserInfo, t rbac.ResourceType) map[string]bool {
	if user == nil {
		return nil
	}
	stored, err := a.db.ListAllResourceGrants()
	if err != nil {
		log.Printf("resource grants: listing for visibility failed: %v", err)
		return nil
	}
	grants := append([]rbac.Grant(nil), a.configuredGrants()...)
	for i := range stored {
		grants = append(grants, stored[i].Grant())
	}
	gs := rbac.NewGrantSet(grants)
	if gs.Empty() {
		return nil
	}
	id := a.identityFor(user)
	out := make(map[string]bool)
	for _, caID := range gs.ResourcesFor(t, id) {
		out[caID] = true
	}
	// A subtree grant on an ancestor also confers visibility on its descendants.
	// Expanding it needs the hierarchy, so it is resolved from the child's side:
	// any CA whose ancestry crosses a granted resource becomes visible.
	if t == rbac.ResourceCA && len(out) > 0 {
		if cas, err := a.db.ListCAs(); err == nil {
			for _, c := range cas {
				if out[c.ID] {
					continue
				}
				ancestors, err := a.caAncestry(rbac.Resource{Type: rbac.ResourceCA, ID: c.ID})
				if err != nil {
					continue
				}
				res := rbac.Resource{Type: rbac.ResourceCA, ID: c.ID}
				if gs.Allows(res, ancestors, id, rbac.ActionReadAudit) {
					out[c.ID] = true
				}
			}
		}
	}
	return out
}

// effectiveAccess computes, and explains, what a principal may do at a resource.
// It is the introspection behind `secsy-ca grant effective` and the console's
// access view: the answer plus the rules that produced it, so an operator can
// audit a delegation without re-deriving the decision by hand.
func (a *API) effectiveAccess(user *models.UserInfo, res rbac.Resource, tenantID string) (*models.EffectiveResourceAccess, error) {
	out := &models.EffectiveResourceAccess{
		Resource: res.String(),
		TenantID: tenantID,
	}
	if user == nil {
		out.Actions = []rbac.Action{}
		return out, nil
	}
	out.Subject = user.Subject
	out.IsRoot = user.IsRoot
	out.PlatformRoles = append([]string(nil), user.Roles...)
	if tenantID != "" {
		out.TenantRoles = append([]string(nil), user.TenantRoles[tenantID]...)
	}

	ancestors, err := a.caAncestry(res)
	if err != nil {
		return nil, err
	}
	gs, err := a.grantSetAt(res, ancestors)
	if err != nil {
		return nil, err
	}
	id := a.identityFor(user)
	out.ResourceRoles = gs.RolesFor(res, ancestors, id)
	for _, g := range gs.All() {
		if id.Matches(g) {
			out.Grants = append(out.Grants, g)
		}
	}

	// The capability set is derived by replaying the real decision for every
	// action, so this view can never drift from what the gates actually enforce.
	actions := make([]rbac.Action, 0, len(rbac.AllActions))
	for _, act := range rbac.AllActions {
		if a.decideInTenant(user, tenantID, act) || gs.Allows(res, ancestors, id, act) {
			actions = append(actions, act)
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i] < actions[j] })
	out.Actions = actions
	return out, nil
}

// --- Grant administration endpoints ----------------------------------------

// resolveGrantResource parses the `resource` query/body value and resolves the
// tenant that owns it, so authorization and audit attribution are correct. A
// resource that does not exist yields notFound.
func (a *API) resolveGrantResource(ctx context.Context, spec string) (res rbac.Resource, tenantID string, notFound bool, err error) {
	res, err = rbac.ParseResource(spec)
	if err != nil {
		return rbac.Resource{}, "", false, err
	}
	switch res.Type {
	case rbac.ResourceCA:
		// Covers X.509 and SSH authorities alike: both live in the cas table.
		tenantID, err = a.db.GetCATenant(res.ID)
		if err != nil {
			return res, "", false, err
		}
		if tenantID == "" {
			return res, "", true, nil
		}
	case rbac.ResourceSigningKey:
		// Signing keys are addressed by name within a tenant. The tenant is taken
		// from the request scope rather than the key, so a grant may be prepared
		// before the key is created.
		tenantID = middleware.GetTenant(ctx)
	}
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	return res, tenantID, false, nil
}

// authorizeGrantAdmin gates the grant-administration endpoints. Authority comes
// from the tenant-wide rbac:manage capability OR from holding resource:delegate
// at the resource itself — the latter being how the owner of a subordinate CA
// hands it to its team without any authority over the rest of the tenant.
func (a *API) authorizeGrantAdmin(w http.ResponseWriter, r *http.Request, spec string) (rbac.Resource, bool) {
	user := middleware.GetUserInfo(r.Context())
	res, tenantID, notFound, err := a.resolveGrantResource(r.Context(), spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return rbac.Resource{}, false
	}
	if notFound {
		writeError(w, http.StatusNotFound, "resource %q not found", spec)
		return rbac.Resource{}, false
	}
	// Recorded on the context so both the authorization below and any resulting
	// audit event are attributed to the resource's tenant; callers read it back
	// with middleware.GetTenant rather than threading it through.
	middleware.SetTenant(r.Context(), tenantID)
	if a.canInTenant(user, tenantID, rbac.ActionManageRBAC) {
		return res, true
	}
	if a.grantAllows(user, res, rbac.ActionDelegate) {
		metrics.RecordAuthz(string(rbac.ActionDelegate), true)
		return res, true
	}
	metrics.RecordAuthz(string(rbac.ActionDelegate), false)
	writeError(w, http.StatusForbidden,
		"managing grants on %s requires the %s capability for tenant %q, or an admin grant on that resource",
		res, rbac.ActionManageRBAC, tenantID)
	return rbac.Resource{}, false
}

// ListResourceGrants returns the grants recorded on one resource, both the
// stored ones and the read-only entries that came from configuration. Showing
// both is the point: an operator debugging "why can this group do that?" must
// not have to know which source a rule lives in.
func (a *API) ListResourceGrants(w http.ResponseWriter, r *http.Request) {
	spec := r.URL.Query().Get("resource")
	if spec == "" {
		writeError(w, http.StatusBadRequest, "resource query parameter is required, e.g. ?resource=ca/<id>")
		return
	}
	res, ok := a.authorizeGrantAdmin(w, r, spec)
	if !ok {
		return
	}

	stored, err := a.db.ListResourceGrants(res)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list grants: %v", err)
		return
	}
	type entry struct {
		models.ResourceGrant
		// Source distinguishes a runtime delegation from a declarative rule; only
		// the former can be revoked through this API.
		Source string `json:"source"`
	}
	out := make([]entry, 0, len(stored))
	for _, g := range stored {
		out = append(out, entry{ResourceGrant: g, Source: "database"})
	}
	for _, g := range a.configuredGrants() {
		if g.Resource != res {
			continue
		}
		out = append(out, entry{ResourceGrant: models.ResourceGrant{
			ResourceType: g.Resource.Type,
			ResourceID:   g.Resource.ID,
			EntityType:   g.EntityType,
			EntityID:     g.EntityID,
			Role:         g.Role,
			Scope:        g.Scope,
		}, Source: "config"})
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateResourceGrant delegates authority over one resource to a user or group.
func (a *API) CreateResourceGrant(w http.ResponseWriter, r *http.Request) {
	var req models.ResourceGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	res, ok := a.authorizeGrantAdmin(w, r, req.Resource)
	if !ok {
		return
	}

	entry := &models.ResourceGrant{
		ID:           uuid.New().String(),
		ResourceType: res.Type,
		ResourceID:   res.ID,
		EntityType:   req.EntityType,
		EntityID:     req.EntityID,
		Role:         req.Role,
		Scope:        req.Scope,
	}
	if err := entry.Grant().Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	// A delegator that is not a tenant RBAC administrator may not hand out more
	// than it holds: without this, a ca-admin on a subordinate could mint itself
	// a subtree grant reaching CAs it was never given.
	user := middleware.GetUserInfo(r.Context())
	if !a.canInTenant(user, middleware.GetTenant(r.Context()), rbac.ActionManageRBAC) && req.Scope == rbac.ScopeSubtree {
		if !a.grantAllows(user, res, rbac.ActionDelegate) || !a.holdsSubtreeDelegation(user, res) {
			a.recordEvent(r, audit.ActionResourceGrant, res.ID, req.EntityID, audit.ResultDenied,
				"subtree delegation exceeds the delegator's own scope")
			writeError(w, http.StatusForbidden,
				"granting %q scope requires tenant-wide %s, or an admin grant that is itself subtree-scoped",
				rbac.ScopeSubtree, rbac.ActionManageRBAC)
			return
		}
	}

	if err := a.db.PutResourceGrant(entry); err != nil {
		a.recordEvent(r, audit.ActionResourceGrant, res.ID, req.EntityID, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to store grant: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionResourceGrant, res.ID, req.EntityID, audit.ResultSuccess,
		string(entry.Role)+" on "+res.String()+" to "+entry.EntityType+":"+entry.EntityID+" (scope "+string(entry.Scope)+")")
	writeJSON(w, http.StatusOK, entry)
}

// holdsSubtreeDelegation reports whether the user's own delegating authority at
// res is subtree-scoped, i.e. whether it may pass subtree reach onward.
func (a *API) holdsSubtreeDelegation(user *models.UserInfo, res rbac.Resource) bool {
	ancestors, err := a.caAncestry(res)
	if err != nil {
		return false
	}
	gs, err := a.grantSetAt(res, ancestors)
	if err != nil {
		return false
	}
	id := a.identityFor(user)
	for _, g := range gs.All() {
		if g.Scope == rbac.ScopeSubtree && id.Matches(g) && rbac.ResourceRoleGrants(g.Role, rbac.ActionDelegate) {
			return true
		}
	}
	return false
}

// DeleteResourceGrant revokes a stored grant. Grants that came from
// configuration are immutable here by design — they are the reviewed baseline,
// and letting an API call silently override a rule that version control still
// shows as active would make the config unreadable as a source of truth.
func (a *API) DeleteResourceGrant(w http.ResponseWriter, r *http.Request) {
	var req models.ResourceGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	res, ok := a.authorizeGrantAdmin(w, r, req.Resource)
	if !ok {
		return
	}
	if !rbac.ValidEntityType(req.EntityType) {
		writeError(w, http.StatusBadRequest, "entity_type must be %q or %q", rbac.EntityUser, rbac.EntityGroup)
		return
	}

	removed, err := a.db.DeleteResourceGrant(res, req.EntityType, req.EntityID, req.Role)
	if err != nil {
		a.recordEvent(r, audit.ActionResourceRevoke, res.ID, req.EntityID, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to revoke grant: %v", err)
		return
	}
	if !removed {
		for _, g := range a.configuredGrants() {
			if g.Resource == res && g.EntityType == req.EntityType && g.EntityID == req.EntityID && g.Role == req.Role {
				writeError(w, http.StatusConflict,
					"that grant is declared in configuration (rbac.grants) and must be removed there, not through the API")
				return
			}
		}
		writeError(w, http.StatusNotFound, "no such grant on %s", res)
		return
	}
	a.recordEvent(r, audit.ActionResourceRevoke, res.ID, req.EntityID, audit.ResultSuccess,
		string(req.Role)+" on "+res.String()+" from "+req.EntityType+":"+req.EntityID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// EffectiveResourceAccess answers "what may this principal do here, and why?".
// A caller may always introspect itself; inspecting ANOTHER subject is an
// access-control review and needs the same authority as administering grants.
func (a *API) EffectiveResourceAccess(w http.ResponseWriter, r *http.Request) {
	spec := r.URL.Query().Get("resource")
	if spec == "" {
		writeError(w, http.StatusBadRequest, "resource query parameter is required, e.g. ?resource=ca/<id>")
		return
	}
	user := middleware.GetUserInfo(r.Context())
	res, tenantID, notFound, err := a.resolveGrantResource(r.Context(), spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if notFound {
		writeError(w, http.StatusNotFound, "resource %q not found", spec)
		return
	}
	middleware.SetTenant(r.Context(), tenantID)

	subject := r.URL.Query().Get("subject")
	target := user
	if subject != "" && (user == nil || subject != user.Subject) {
		if _, ok := a.authorizeGrantAdmin(w, r, spec); !ok {
			return
		}
		target = a.principalForSubject(subject)
	} else if !a.canOnResource(user, res, tenantID, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "no read access to %s", res)
		return
	}

	eff, err := a.effectiveAccess(target, res, tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to compute effective access: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, eff)
}

// PrincipalResolver reconstructs the standing another subject would hold, so an
// administrator can review someone else's effective access without that subject
// having to log in. Implementations resolve the same configuration the
// authentication middleware uses, so the answer matches what the subject would
// actually get. groups are the subject's known group identities.
type PrincipalResolver func(subject string, groups []string) (platform []string, tenant map[string][]string)

// SetPrincipalResolver installs the resolver used by effective-access review.
func (a *API) SetPrincipalResolver(fn PrincipalResolver) { a.principalResolver = fn }

// principalForSubject builds the principal an access review is asked about.
//
// Only group identities recorded in the database can be reconstructed here: a
// subject's IdP groups are asserted at ITS login and are unknowable from
// another operator's request. The review therefore reports what the deployment
// can prove about a subject; a grant that depends on a directory group shows up
// only once that subject has authenticated. The response carries the subject so
// the caller can tell whose access it is reading.
func (a *API) principalForSubject(subject string) *models.UserInfo {
	u := &models.UserInfo{Subject: subject}
	if groups, err := a.db.GetUserGroups(subject); err == nil {
		u.Groups = groups
	}
	if a.principalResolver != nil {
		u.Roles, u.TenantRoles = a.principalResolver(subject, u.Groups)
	}
	return u
}
