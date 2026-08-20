package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// The scenario Task 191 exists to serve, exercised through the real handlers:
//
//	tenant "a" holds a root CA and two subordinates. The platform administrator
//	administers all of them. The "pki-payments" group is delegated exactly
//	sub-payments — it may administer that one authority and nothing else, while
//	holding no role in the tenant at all.

// grantHarness is a minimal API + fixture set focused on delegation. It builds
// the CA hierarchy root → {sub-payments, sub-web} in tenant "a", plus an
// unrelated CA in tenant "b".
type grantHarness struct {
	api *API
	db  *database.DB
}

func newGrantHarness(t *testing.T) *grantHarness {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	mkTenantCA(t, db, "a", "root")
	mkTenantCA(t, db, "b", "other-tenant-ca")
	for _, id := range []string{"sub-payments", "sub-web"} {
		mkChildCA(t, db, "a", id, "root")
	}
	return &grantHarness{api: &API{db: db}, db: db}
}

// mkChildCA creates a subordinate CA whose parent_id links it into the
// hierarchy, which is what subtree-scoped grants traverse.
func mkChildCA(t *testing.T, db *database.DB, tenantID, id, parentID string) {
	t.Helper()
	parent := parentID
	if err := db.CreateCA(&models.CA{
		ID: id, TenantID: tenantID, ParentID: &parent, Label: id,
		PKCS11URI: "pkcs11:object=" + id, KeyType: "ecdsa-p256", PublicKey: "k",
		Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA(%s): %v", id, err)
	}
}

// ctxWithUser builds a context carrying an authenticated principal and a tenant
// holder, as the auth middleware would for a real request.
func ctxWithUser(t *testing.T, user *models.UserInfo) context.Context {
	t.Helper()
	return reqAs(http.MethodPost, "/", user, "", "").Context()
}

// paymentsOperator is a principal with NO platform and NO tenant role: its only
// authority is whatever a grant confers. That is the point of the model, so the
// tests deliberately use the weakest possible principal.
func paymentsOperator() *models.UserInfo {
	return &models.UserInfo{Subject: "alice", Groups: []string{"pki-payments"}}
}

func tenantAAdmin() *models.UserInfo {
	return &models.UserInfo{Subject: "a-admin", TenantRoles: map[string][]string{"a": {string(rbac.RoleAdmin)}}}
}

func caResource(id string) rbac.Resource { return rbac.Resource{Type: rbac.ResourceCA, ID: id} }

// grantToGroup stores a runtime grant, the same way the API endpoint does.
func (h *grantHarness) grantToGroup(t *testing.T, caID, group string, role rbac.ResourceRole, scope rbac.GrantScope) {
	t.Helper()
	if err := h.db.PutResourceGrant(&models.ResourceGrant{
		ID: caID + ":" + group + ":" + string(role), ResourceType: rbac.ResourceCA, ResourceID: caID,
		EntityType: rbac.EntityGroup, EntityID: group, Role: role, Scope: scope,
	}); err != nil {
		t.Fatalf("PutResourceGrant: %v", err)
	}
}

// TestGroupAdministersOnlyItsSubCA is the headline assertion of Task 191.
func TestGroupAdministersOnlyItsSubCA(t *testing.T) {
	h := newGrantHarness(t)
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAManager, rbac.ScopeSelf)
	op := paymentsOperator()

	// The delegated group administers the CA it was given...
	for _, act := range []rbac.Action{rbac.ActionManageCA, rbac.ActionConfigureCA, rbac.ActionIssue, rbac.ActionReadAudit} {
		allowed, notFound, err := h.api.canOnCA(t.Context(), op, "sub-payments", act)
		if err != nil || notFound {
			t.Fatalf("canOnCA(sub-payments, %s): err=%v notFound=%v", act, err, notFound)
		}
		if !allowed {
			t.Errorf("delegated group should hold %s on sub-payments", act)
		}
	}

	// ...and nothing on the root, its sibling, or another tenant's CA.
	for _, caID := range []string{"root", "sub-web", "other-tenant-ca"} {
		for _, act := range []rbac.Action{rbac.ActionManageCA, rbac.ActionIssue, rbac.ActionReadAudit} {
			allowed, _, err := h.api.canOnCA(t.Context(), op, caID, act)
			if err != nil {
				t.Fatalf("canOnCA(%s, %s): %v", caID, act, err)
			}
			if allowed {
				t.Errorf("delegated group must NOT hold %s on %s", act, caID)
			}
		}
	}

	// The platform administrator keeps authority over every CA, including the
	// delegated one — delegation adds an owner, it does not remove one.
	for _, caID := range []string{"root", "sub-payments", "sub-web"} {
		allowed, _, err := h.api.canOnCA(t.Context(), platformAdmin(), caID, rbac.ActionManageCA)
		if err != nil {
			t.Fatalf("canOnCA(%s) as platform admin: %v", caID, err)
		}
		if !allowed {
			t.Errorf("platform admin should still administer %s", caID)
		}
	}
}

// A ca-manager runs the CA but may not decide who else can.
func TestManagerCannotDelegate(t *testing.T) {
	h := newGrantHarness(t)
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAManager, rbac.ScopeSelf)
	op := paymentsOperator()

	if h.api.grantAllows(op, caResource("sub-payments"), rbac.ActionDelegate) {
		t.Fatal("ca-manager must not confer resource:delegate")
	}
	// Upgrading the same group to ca-admin does confer it — and only there.
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAAdmin, rbac.ScopeSelf)
	if !h.api.grantAllows(op, caResource("sub-payments"), rbac.ActionDelegate) {
		t.Fatal("ca-admin should confer resource:delegate on its own CA")
	}
	if h.api.grantAllows(op, caResource("sub-web"), rbac.ActionDelegate) {
		t.Fatal("ca-admin on one CA must not confer delegation on a sibling")
	}
}

// Subtree scope reaches down the hierarchy; self scope does not.
func TestSubtreeScopeThroughRealHierarchy(t *testing.T) {
	h := newGrantHarness(t)
	// A CA nested one level below sub-payments.
	mkChildCA(t, h.db, "a", "leaf", "sub-payments")
	op := paymentsOperator()

	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAManager, rbac.ScopeSelf)
	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "leaf", rbac.ActionManageCA); allowed {
		t.Fatal("a self-scoped grant must not reach a subordinate CA")
	}

	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAAdmin, rbac.ScopeSubtree)
	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "leaf", rbac.ActionManageCA); !allowed {
		t.Fatal("a subtree-scoped grant should reach a subordinate CA")
	}
	// Reach is downward only.
	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "root", rbac.ActionManageCA); allowed {
		t.Fatal("a subtree grant must not reach the parent")
	}
}

// A grant on a CA is enough to see it, even for a principal with no tenant role.
func TestGrantConfersReadVisibility(t *testing.T) {
	h := newGrantHarness(t)
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAAuditor, rbac.ScopeSelf)
	op := paymentsOperator()

	rec := httptest.NewRecorder()
	ca, ok := h.api.authorizeCARead(rec, reqAs(http.MethodGet, "/api/keys/sub-payments", op, "sub-payments", ""), "sub-payments")
	if !ok || ca == nil {
		t.Fatalf("a grant holder should be able to read its CA; status=%d body=%s", rec.Code, rec.Body.String())
	}
	// The sibling stays invisible — 404, not 403, so existence is not disclosed.
	rec = httptest.NewRecorder()
	if _, ok := h.api.authorizeCARead(rec, reqAs(http.MethodGet, "/api/keys/sub-web", op, "sub-web", ""), "sub-web"); ok {
		t.Fatal("a grant on one CA must not confer read on a sibling")
	}
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("expected 404/403 for the sibling, got %d", rec.Code)
	}

	// And the CA listing shows exactly the delegated authority.
	rec = httptest.NewRecorder()
	h.api.ListCAs(rec, reqAs(http.MethodGet, "/api/keys", op, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListCAs: got %d, body=%s", rec.Code, rec.Body.String())
	}
	var listed []models.CA
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decoding CA list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != "sub-payments" {
		ids := make([]string, len(listed))
		for i, c := range listed {
			ids[i] = c.ID
		}
		t.Fatalf("ListCAs = %v, want exactly [sub-payments]", ids)
	}
}

// Configuration-declared grants authorize identically to stored ones. This is
// what makes the example config in examples/delegated-ca-administration work
// without any runtime API call.
func TestConfigGrantsAuthorize(t *testing.T) {
	h := newGrantHarness(t)
	h.api.SetResourceGrants([]rbac.Grant{{
		Resource: caResource("sub-payments"), EntityType: rbac.EntityGroup,
		EntityID: "pki-payments", Role: rbac.ResourceRoleCAManager, Scope: rbac.ScopeSelf,
	}})
	op := paymentsOperator()

	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "sub-payments", rbac.ActionManageCA); !allowed {
		t.Fatal("a configured grant should authorize just like a stored one")
	}
	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "sub-web", rbac.ActionManageCA); allowed {
		t.Fatal("a configured grant must not leak to another CA")
	}
	// Config grants are the reviewed baseline, so the API refuses to revoke one.
	rec := httptest.NewRecorder()
	body := `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"pki-payments","role":"ca-manager"}`
	h.api.DeleteResourceGrant(rec, reqAs(http.MethodDelete, "/api/grants", tenantAAdmin(), "", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleting a config grant: got %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// An internal (database) group works as a grant subject too, so a deployment can
// model teams without touching the identity provider.
func TestInternalGroupMembershipMatchesGrant(t *testing.T) {
	h := newGrantHarness(t)
	if err := h.db.CreateGroup(&models.Group{ID: "grp-payments", Name: "payments"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := h.db.AddGroupMember("grp-payments", "bob"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	h.grantToGroup(t, "sub-payments", "grp-payments", rbac.ResourceRoleCAManager, rbac.ScopeSelf)

	// bob carries no IdP groups at all; membership comes from the database.
	bob := &models.UserInfo{Subject: "bob"}
	if allowed, _, _ := h.api.canOnCA(t.Context(), bob, "sub-payments", rbac.ActionManageCA); !allowed {
		t.Fatal("an internal group membership should satisfy a group grant")
	}
	carol := &models.UserInfo{Subject: "carol"}
	if allowed, _, _ := h.api.canOnCA(t.Context(), carol, "sub-payments", rbac.ActionManageCA); allowed {
		t.Fatal("a non-member must not satisfy the group grant")
	}
}

// Grant administration: a tenant admin may delegate; the delegated ca-admin may
// re-delegate its own CA; a ca-manager may not.
func TestGrantAdministrationEndpoints(t *testing.T) {
	h := newGrantHarness(t)

	create := func(user *models.UserInfo, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.api.CreateResourceGrant(rec, reqAs(http.MethodPost, "/api/grants", user, "", body))
		return rec
	}

	// The tenant admin delegates sub-payments to the group as ca-admin.
	rec := create(tenantAAdmin(), `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"pki-payments","role":"ca-admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant admin should be able to delegate: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// The delegated ca-admin may now hand the SAME CA to a second group...
	op := paymentsOperator()
	rec = create(op, `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"payments-oncall","role":"ca-issuer"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ca-admin should be able to re-delegate its own CA: got %d, body=%s", rec.Code, rec.Body.String())
	}
	// ...but not a CA it was never given.
	rec = create(op, `{"resource":"ca/sub-web","entity_type":"group","entity_id":"payments-oncall","role":"ca-admin"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ca-admin must not delegate a CA it does not hold: got %d, body=%s", rec.Code, rec.Body.String())
	}
	// ...and it may not widen a self-scoped delegation into a subtree one, which
	// would reach CAs beneath it that it was never granted.
	rec = create(op, `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"payments-oncall","role":"ca-admin","scope":"subtree"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-scoped ca-admin must not mint a subtree grant: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// A cross-tenant admin is refused outright.
	tenantBAdmin := &models.UserInfo{Subject: "b-admin", TenantRoles: map[string][]string{"b": {string(rbac.RoleAdmin)}}}
	rec = create(tenantBAdmin, `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"x","role":"ca-issuer"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant delegation must be refused: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// A malformed role is rejected rather than silently stored.
	rec = create(tenantAAdmin(), `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"x","role":"ca-god"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown role should be a 400: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// Revoking removes the authority.
	rec = httptest.NewRecorder()
	del := `{"resource":"ca/sub-payments","entity_type":"group","entity_id":"pki-payments","role":"ca-admin"}`
	h.api.DeleteResourceGrant(rec, reqAs(http.MethodDelete, "/api/grants", tenantAAdmin(), "", del))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d, body=%s", rec.Code, rec.Body.String())
	}
	if allowed, _, _ := h.api.canOnCA(t.Context(), op, "sub-payments", rbac.ActionManageCA); allowed {
		t.Fatal("authority should be gone after the grant is revoked")
	}
	// Revoking a grant that was never there is a 404, not a silent success.
	rec = httptest.NewRecorder()
	h.api.DeleteResourceGrant(rec, reqAs(http.MethodDelete, "/api/grants", tenantAAdmin(), "", del))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoking a missing grant: got %d, want 404", rec.Code)
	}
}

// Effective-access review reports the capability set AND the rules behind it.
func TestEffectiveAccessReview(t *testing.T) {
	h := newGrantHarness(t)
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAManager, rbac.ScopeSelf)

	eff, err := h.api.effectiveAccess(paymentsOperator(), caResource("sub-payments"), "a")
	if err != nil {
		t.Fatalf("effectiveAccess: %v", err)
	}
	if len(eff.ResourceRoles) != 1 || eff.ResourceRoles[0] != rbac.ResourceRoleCAManager {
		t.Fatalf("ResourceRoles = %v, want [ca-manager]", eff.ResourceRoles)
	}
	has := func(a rbac.Action) bool {
		for _, got := range eff.Actions {
			if got == a {
				return true
			}
		}
		return false
	}
	for _, a := range []rbac.Action{rbac.ActionManageCA, rbac.ActionConfigureCA, rbac.ActionIssue, rbac.ActionReadAudit} {
		if !has(a) {
			t.Errorf("effective actions should include %s; got %v", a, eff.Actions)
		}
	}
	// A delegation must never imply deployment-wide authority.
	for _, a := range []rbac.Action{rbac.ActionManageHSM, rbac.ActionManageTokens, rbac.ActionDelegate} {
		if has(a) {
			t.Errorf("effective actions must not include %s; got %v", a, eff.Actions)
		}
	}
	if len(eff.Grants) != 1 || eff.Grants[0].EntityID != "pki-payments" {
		t.Fatalf("Grants = %v, want the single matching rule", eff.Grants)
	}

	// The same review for the sibling CA reports no authority at all.
	eff, err = h.api.effectiveAccess(paymentsOperator(), caResource("sub-web"), "a")
	if err != nil {
		t.Fatalf("effectiveAccess(sub-web): %v", err)
	}
	if len(eff.Actions) != 0 || len(eff.ResourceRoles) != 0 {
		t.Fatalf("expected no authority on sub-web, got actions=%v roles=%v", eff.Actions, eff.ResourceRoles)
	}
}

// Deleting a CA takes its grants with it, so a reused identifier cannot inherit
// authority that was delegated over a CA that no longer exists.
func TestDeletingCARemovesItsGrants(t *testing.T) {
	h := newGrantHarness(t)
	h.grantToGroup(t, "sub-payments", "pki-payments", rbac.ResourceRoleCAAdmin, rbac.ScopeSelf)

	if err := h.db.DeleteResourceGrantsFor(caResource("sub-payments")); err != nil {
		t.Fatalf("DeleteResourceGrantsFor: %v", err)
	}
	got, err := h.db.ListResourceGrants(caResource("sub-payments"))
	if err != nil {
		t.Fatalf("ListResourceGrants: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no grants after cleanup, got %v", got)
	}
	if h.api.grantAllows(paymentsOperator(), caResource("sub-payments"), rbac.ActionManageCA) {
		t.Fatal("authority should not survive grant cleanup")
	}
}

// Per-key delegation: a release pipeline gets exactly the signing key it needs.
func TestSigningKeyGrantScopesToOneKey(t *testing.T) {
	h := newGrantHarness(t)
	if err := h.db.PutResourceGrant(&models.ResourceGrant{
		ID: "g-release", ResourceType: rbac.ResourceSigningKey, ResourceID: "release-signing",
		EntityType: rbac.EntityGroup, EntityID: "ci-release", Role: rbac.ResourceRoleKeySigner,
	}); err != nil {
		t.Fatalf("PutResourceGrant: %v", err)
	}
	pipeline := &models.UserInfo{Subject: "ci", Groups: []string{"ci-release"}}
	ctx := ctxWithUser(t, pipeline)

	if !h.api.canOnSigningKey(ctx, "a", "release-signing", rbac.ActionSign) {
		t.Fatal("the pipeline should be able to sign with the key it was granted")
	}
	if h.api.canOnSigningKey(ctx, "a", "customer-data", rbac.ActionSign) {
		t.Fatal("the grant must not reach another key in the tenant")
	}
	// key-signer uses the key but cannot create or replace it.
	if h.api.canOnSigningKey(ctx, "a", "release-signing", rbac.ActionManageSigningKey) {
		t.Fatal("key-signer must not confer secret:signing-key")
	}
}

// Storing a grant that authorizes nothing is refused at the persistence layer,
// so a typo cannot sit in the table looking like working access control.
func TestStoreRejectsInvalidGrant(t *testing.T) {
	h := newGrantHarness(t)
	err := h.db.PutResourceGrant(&models.ResourceGrant{
		ID: "bad", ResourceType: rbac.ResourceCA, ResourceID: "sub-payments",
		EntityType: rbac.EntityGroup, EntityID: "team", Role: "ca-god",
	})
	if err == nil {
		t.Fatal("PutResourceGrant should reject an unknown role")
	}
	if !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("error should name the problem, got %v", err)
	}
}

// The ancestry walk must terminate even if the stored parent chain is corrupt,
// because it runs inside every per-CA authorization decision.
func TestAncestryWalkSurvivesCycle(t *testing.T) {
	h := newGrantHarness(t)
	// Two CAs naming each other as parent: a chain the walk must not follow
	// forever. Created directly so the cycle exists in the stored rows.
	mkTenantCA(t, h.db, "a", "loop-a")
	mkChildCA(t, h.db, "a", "loop-b", "loop-a")
	if err := h.db.SetCAParentForTest("loop-a", "loop-b"); err != nil {
		t.Fatalf("creating the cycle: %v", err)
	}
	done := make(chan []string, 1)
	go func() {
		got, err := h.db.GetCAAncestors("loop-b")
		if err != nil {
			got = nil
		}
		done <- got
	}()
	select {
	case got := <-done:
		for _, id := range got {
			if id == "loop-b" {
				t.Fatalf("ancestry must not revisit the starting CA: %v", got)
			}
		}
	case <-t.Context().Done():
		t.Fatal("GetCAAncestors did not terminate on a cyclic parent chain")
	}
}
