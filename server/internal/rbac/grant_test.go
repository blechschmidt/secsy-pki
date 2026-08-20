package rbac

import "testing"

// The scenario Task 191 exists to support: a platform administrator owns the
// root CA, and one group owns exactly one subordinate CA.

func caRes(id string) Resource { return Resource{Type: ResourceCA, ID: id} }

func TestParseResource(t *testing.T) {
	tests := []struct {
		in      string
		want    Resource
		wantErr bool
	}{
		{in: "ca/root-1", want: caRes("root-1")},
		{in: " ca/root-1 ", want: caRes("root-1")},
		{in: "signing-key/release", want: Resource{Type: ResourceSigningKey, ID: "release"}},
		// A key name may itself contain a slash: only the first separator counts.
		{in: "signing-key/team/release", want: Resource{Type: ResourceSigningKey, ID: "team/release"}},
		{in: "ca/", wantErr: true},
		// A mangled argument (e.g. a shell pipeline that captured two lines) must
		// not become a grant row or forge an audit-record boundary.
		{in: "ca/root-1\nca/root-2", wantErr: true},
		{in: "ca/root 1", wantErr: true},
		{in: "/root-1", wantErr: true},
		{in: "root-1", wantErr: true},
		{in: "tenant/acme", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseResource(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseResource(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseResource(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseResource(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestGrantValidate(t *testing.T) {
	tests := []struct {
		name    string
		grant   Grant
		wantErr bool
	}{
		{
			name:  "well formed group grant",
			grant: Grant{Resource: caRes("sub"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager},
		},
		{
			name:    "unknown role",
			grant:   Grant{Resource: caRes("sub"), EntityType: EntityUser, EntityID: "a", Role: "ca-god"},
			wantErr: true,
		},
		{
			// A key role on a CA would silently authorize nothing, so it is refused.
			name:    "key role on a CA",
			grant:   Grant{Resource: caRes("sub"), EntityType: EntityUser, EntityID: "a", Role: ResourceRoleKeySigner},
			wantErr: true,
		},
		{
			name:    "ca role on a signing key",
			grant:   Grant{Resource: Resource{Type: ResourceSigningKey, ID: "k"}, EntityType: EntityUser, EntityID: "a", Role: ResourceRoleCAManager},
			wantErr: true,
		},
		{
			// Signing keys have no hierarchy, so subtree reach is meaningless there.
			name: "subtree on a signing key",
			grant: Grant{Resource: Resource{Type: ResourceSigningKey, ID: "k"}, EntityType: EntityUser,
				EntityID: "a", Role: ResourceRoleKeySigner, Scope: ScopeSubtree},
			wantErr: true,
		},
		{
			name:    "unknown entity type",
			grant:   Grant{Resource: caRes("sub"), EntityType: "robot", EntityID: "a", Role: ResourceRoleCAAdmin},
			wantErr: true,
		},
		{
			name:    "missing entity id",
			grant:   Grant{Resource: caRes("sub"), EntityType: EntityUser, Role: ResourceRoleCAAdmin},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.grant.Normalized().Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestDelegatedSubCAAdministration is the headline scenario: the platform team
// keeps the root, and the "pki-payments" group administers only sub-CA B.
func TestDelegatedSubCAAdministration(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "pki-payments", Role: ResourceRoleCAManager},
	})
	payments := Identity{Subject: "alice", Groups: []string{"pki-payments"}}

	// May administer the CA it was given.
	for _, act := range []Action{ActionManageCA, ActionConfigureCA, ActionIssue, ActionReadAudit} {
		if !gs.Allows(caRes("sub-b"), nil, payments, act) {
			t.Errorf("expected %s on sub-b", act)
		}
	}
	// A manager may NOT delegate: that is the ca-admin role.
	if gs.Allows(caRes("sub-b"), nil, payments, ActionDelegate) {
		t.Error("ca-manager must not grant resource:delegate")
	}
	// The grant does not reach the root, a sibling, or the tenant at large.
	for _, other := range []string{"root", "sub-a"} {
		for _, act := range []Action{ActionManageCA, ActionIssue, ActionReadAudit} {
			if gs.Allows(caRes(other), []Resource{caRes("root")}, payments, act) {
				t.Errorf("grant on sub-b must not reach %s for %s", other, act)
			}
		}
	}
	// Nor does it reach a principal outside the group.
	outsider := Identity{Subject: "mallory", Groups: []string{"other-team"}}
	if gs.Allows(caRes("sub-b"), nil, outsider, ActionReadAudit) {
		t.Error("a non-member must not inherit the group's grant")
	}
}

func TestScopeSelfDoesNotReachSubordinates(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAAdmin, Scope: ScopeSelf},
	})
	id := Identity{Subject: "alice", Groups: []string{"team"}}
	// The child names sub-b as an ancestor, but a self-scoped grant does not
	// descend — a CA created later under a delegated one must not be swept in.
	if gs.Allows(caRes("leaf-ca"), []Resource{caRes("sub-b"), caRes("root")}, id, ActionManageCA) {
		t.Fatal("self-scoped grant must not reach a subordinate CA")
	}
	if !gs.Allows(caRes("sub-b"), nil, id, ActionManageCA) {
		t.Fatal("self-scoped grant must still apply at the resource itself")
	}
}

func TestScopeSubtreeReachesDescendants(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAAdmin, Scope: ScopeSubtree},
	})
	id := Identity{Subject: "alice", Groups: []string{"team"}}
	if !gs.Allows(caRes("leaf-ca"), []Resource{caRes("sub-b"), caRes("root")}, id, ActionManageCA) {
		t.Fatal("subtree grant should reach a descendant CA")
	}
	// Reach is strictly downward: the ancestor above the granted node stays out.
	if gs.Allows(caRes("root"), nil, id, ActionManageCA) {
		t.Fatal("subtree grant must not reach upward to the root")
	}
	// A sibling branch that does not pass through sub-b is untouched.
	if gs.Allows(caRes("sub-a"), []Resource{caRes("root")}, id, ActionManageCA) {
		t.Fatal("subtree grant must not reach a sibling branch")
	}
}

func TestIdentityMatching(t *testing.T) {
	userGrant := Grant{Resource: caRes("c"), EntityType: EntityUser, EntityID: "alice@example.com", Role: ResourceRoleCAAuditor}
	gs := NewGrantSet([]Grant{userGrant})

	// An email-keyed grant applies only to a VERIFIED email, matching the rule
	// the platform role assignments use.
	verified := Identity{Subject: "sub-1", Email: "alice@example.com", EmailVerified: true}
	if !gs.Allows(caRes("c"), nil, verified, ActionReadAudit) {
		t.Error("verified email should match a user grant")
	}
	unverified := Identity{Subject: "sub-1", Email: "alice@example.com"}
	if gs.Allows(caRes("c"), nil, unverified, ActionReadAudit) {
		t.Error("unverified email must not match a user grant")
	}
	// Email comparison is case-insensitive; the subject is not.
	upper := Identity{Subject: "sub-1", Email: "Alice@Example.COM", EmailVerified: true}
	if !gs.Allows(caRes("c"), nil, upper, ActionReadAudit) {
		t.Error("email matching should be case-insensitive")
	}

	bySubject := NewGrantSet([]Grant{{Resource: caRes("c"), EntityType: EntityUser, EntityID: "sub-1", Role: ResourceRoleCAAuditor}})
	if !bySubject.Allows(caRes("c"), nil, Identity{Subject: "sub-1"}, ActionReadAudit) {
		t.Error("subject should match a user grant")
	}
	if bySubject.Allows(caRes("c"), nil, Identity{Subject: "SUB-1"}, ActionReadAudit) {
		t.Error("subject matching must be exact")
	}
	// An empty identity must never match, so an unauthenticated or role-less
	// principal cannot pick up a grant with a blank entity id.
	if NewGrantSet([]Grant{{Resource: caRes("c"), EntityType: EntityUser, EntityID: "", Role: ResourceRoleCAAuditor}}).
		Allows(caRes("c"), nil, Identity{}, ActionReadAudit) {
		t.Error("blank entity id must not match an empty identity")
	}
}

func TestResourceRoleBundles(t *testing.T) {
	// ca-issuer must not confer administration; ca-auditor must confer nothing
	// beyond read. These are the boundaries the delegation model rests on.
	if ResourceRoleGrants(ResourceRoleCAIssuer, ActionManageCA) {
		t.Error("ca-issuer must not grant ca:manage")
	}
	if ResourceRoleGrants(ResourceRoleCAIssuer, ActionConfigureCA) {
		t.Error("ca-issuer must not grant ca:configure")
	}
	for _, act := range AllActions {
		if act == ActionReadAudit {
			continue
		}
		if ResourceRoleGrants(ResourceRoleCAAuditor, act) {
			t.Errorf("ca-auditor must not grant %s", act)
		}
		if ResourceRoleGrants(ResourceRoleKeyAuditor, act) {
			t.Errorf("key-auditor must not grant %s", act)
		}
	}
	// key-signer uses a key but cannot create or delegate one.
	if !ResourceRoleGrants(ResourceRoleKeySigner, ActionSign) {
		t.Error("key-signer must grant secret:sign")
	}
	for _, act := range []Action{ActionManageSigningKey, ActionDelegate} {
		if ResourceRoleGrants(ResourceRoleKeySigner, act) {
			t.Errorf("key-signer must not grant %s", act)
		}
	}
	// No resource role may be an allow-all: every capability is opt-in, so a
	// newly added Action is denied until deliberately bundled.
	for _, role := range AllResourceRoles {
		if ResourceRoleGrants(role, ActionManageHSM) {
			t.Errorf("%s must not grant hsm:manage", role)
		}
		if ResourceRoleGrants(role, ActionManageRBAC) {
			t.Errorf("%s must not grant tenant-wide rbac:manage", role)
		}
		if ResourceRoleGrants(role, ActionManageTokens) {
			t.Errorf("%s must not grant token:manage", role)
		}
	}
}

func TestNewGrantSetDropsInvalidRules(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("c"), EntityType: EntityUser, EntityID: "a", Role: "typo-role"},
		{Resource: Resource{Type: "tenant", ID: "x"}, EntityType: EntityUser, EntityID: "a", Role: ResourceRoleCAAdmin},
	})
	if !gs.Empty() {
		t.Fatalf("malformed grants should be dropped, got %v", gs.All())
	}
	if gs.Allows(caRes("c"), nil, Identity{Subject: "a"}, ActionReadAudit) {
		t.Fatal("a dropped grant must authorize nothing")
	}
}

func TestResourcesForListsDelegatedObjects(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager},
		{Resource: caRes("sub-c"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAuditor},
		{Resource: Resource{Type: ResourceSigningKey, ID: "release"}, EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleKeySigner},
	})
	id := Identity{Subject: "alice", Groups: []string{"team"}}
	cas := gs.ResourcesFor(ResourceCA, id)
	if len(cas) != 2 || cas[0] != "sub-b" || cas[1] != "sub-c" {
		t.Fatalf("ResourcesFor(ca) = %v, want [sub-b sub-c]", cas)
	}
	keys := gs.ResourcesFor(ResourceSigningKey, id)
	if len(keys) != 1 || keys[0] != "release" {
		t.Fatalf("ResourcesFor(signing-key) = %v, want [release]", keys)
	}
	// Someone else's grants are not listed.
	if got := gs.ResourcesFor(ResourceCA, Identity{Subject: "bob"}); len(got) != 0 {
		t.Fatalf("ResourcesFor for an unrelated subject = %v, want none", got)
	}
}

func TestRolesForUnionsResourceAndAncestors(t *testing.T) {
	gs := NewGrantSet([]Grant{
		{Resource: caRes("sub"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAIssuer},
		{Resource: caRes("root"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAuditor, Scope: ScopeSubtree},
		// A self-scoped ancestor grant contributes nothing to the descendant.
		{Resource: caRes("root"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAdmin, Scope: ScopeSelf},
	})
	roles := gs.RolesFor(caRes("sub"), []Resource{caRes("root")}, Identity{Subject: "alice"})
	seen := map[ResourceRole]bool{}
	for _, r := range roles {
		seen[r] = true
	}
	if !seen[ResourceRoleCAIssuer] || !seen[ResourceRoleCAAuditor] {
		t.Fatalf("RolesFor = %v, want ca-issuer and ca-auditor", roles)
	}
	if seen[ResourceRoleCAAdmin] {
		t.Fatalf("RolesFor = %v, must not include the self-scoped ancestor role", roles)
	}
}
