package rbac

import (
	"sort"
	"strings"
	"testing"
)

// These tests cover the resolution side of the resource-scoped grant model: what
// a bundle actually confers (ResourceRoleActions), what identifies a rule (Key),
// what a lookup returns at one resource (At / All), and the ordering the CLI and
// API responses depend on (SortGrants).

func keyRes(name string) Resource { return Resource{Type: ResourceSigningKey, ID: name} }

// renderGrants renders grants compactly for failure messages.
func renderGrants(gs []Grant) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Key() + "|" + string(g.Scope)
	}
	return out
}

func containsAction(acts []Action, want Action) bool {
	for _, a := range acts {
		if a == want {
			return true
		}
	}
	return false
}

func TestResourceRoleActionsBundles(t *testing.T) {
	// The expected lists are written out in full and in the sorted order the
	// function promises, because this is the exact set the CLI prints and the
	// effective-permission endpoint reports: an unnoticed extra entry here is an
	// unnoticed capability at every resource the role is granted on.
	tests := []struct {
		role ResourceRole
		want []Action
	}{
		{ResourceRoleCAAdmin, []Action{ActionReadAudit, ActionConfigureCA, ActionManageCA, ActionIssue, ActionDelegate}},
		// Identical to ca-admin except for resource:delegate — the whole point of
		// the split (rbac.go:73-81).
		{ResourceRoleCAManager, []Action{ActionReadAudit, ActionConfigureCA, ActionManageCA, ActionIssue}},
		{ResourceRoleCAIssuer, []Action{ActionReadAudit, ActionIssue}},
		{ResourceRoleCAAuditor, []Action{ActionReadAudit}},
		{ResourceRoleKeyAdmin, []Action{ActionReadAudit, ActionDelegate, ActionSign, ActionManageSigningKey}},
		{ResourceRoleKeySigner, []Action{ActionReadAudit, ActionSign}},
		{ResourceRoleKeyAuditor, []Action{ActionReadAudit}},
	}
	covered := make(map[ResourceRole]bool, len(tests))
	for _, tc := range tests {
		t.Run(string(tc.role), func(t *testing.T) {
			covered[tc.role] = true
			got := ResourceRoleActions(tc.role)
			if strings.Join(toStrings(got), ",") != strings.Join(toStrings(tc.want), ",") {
				t.Fatalf("ResourceRoleActions(%s) = %v, want %v", tc.role, got, tc.want)
			}
			// Sorted ascending, as documented, so output is stable across runs.
			if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
				t.Errorf("ResourceRoleActions(%s) is not sorted: %v", tc.role, got)
			}
			// The reported set must equal what the evaluator actually enforces,
			// recomputed independently through ResourceRoleGrants.
			for _, act := range AllActions {
				if want, have := ResourceRoleGrants(tc.role, act), containsAction(got, act); want != have {
					t.Errorf("%s: ResourceRoleGrants(%s) = %v but the reported set says %v",
						tc.role, act, want, have)
				}
			}
		})
	}
	for _, role := range AllResourceRoles {
		if !covered[role] {
			t.Errorf("resource role %q is not covered by this table", role)
		}
	}

	// An unknown role bundles nothing: a grant that somehow carried a bad role
	// name must authorize zero actions rather than fall back to a default.
	for _, bogus := range []ResourceRole{"", "ca-god", "admin", "CA-ADMIN", ResourceRole(RoleAdmin)} {
		if got := ResourceRoleActions(bogus); len(got) != 0 {
			t.Errorf("ResourceRoleActions(%q) = %v, want none", bogus, got)
		}
		if ValidResourceRole(bogus) {
			t.Errorf("ValidResourceRole(%q) = true, want false", bogus)
		}
	}

	// The returned slice is the caller's to keep: writing to it must not rewrite
	// the shared capability table for every later authorization decision.
	acts := ResourceRoleActions(ResourceRoleCAAuditor)
	acts[0] = ActionManageCA
	if got := ResourceRoleActions(ResourceRoleCAAuditor); len(got) != 1 || got[0] != ActionReadAudit {
		t.Errorf("mutating the returned slice corrupted the bundle: %v", got)
	}
	if ResourceRoleGrants(ResourceRoleCAAuditor, ActionManageCA) {
		t.Fatal("ca-auditor gained ca:manage through a mutated result slice")
	}
}

func TestResourceRoleSeparationOfDuties(t *testing.T) {
	// Only the *-admin bundles carry the delegation capability. Per the
	// ActionDelegate doc (rbac.go:73-81) a ca-manager deliberately lacks it, so
	// day-to-day operation of a CA cannot be escalated into control over who else
	// may operate it.
	wantDelegate := map[ResourceRole]bool{ResourceRoleCAAdmin: true, ResourceRoleKeyAdmin: true}
	for _, role := range AllResourceRoles {
		if got := ResourceRoleGrants(role, ActionDelegate); got != wantDelegate[role] {
			t.Errorf("ResourceRoleGrants(%s, resource:delegate) = %v, want %v", role, got, wantDelegate[role])
		}
		// Introspection must tell the same story the gate enforces.
		if got := containsAction(ResourceRoleActions(role), ActionDelegate); got != wantDelegate[role] {
			t.Errorf("ResourceRoleActions(%s) delegate = %v, want %v", role, got, wantDelegate[role])
		}
	}
	// "It is never granted by a platform or tenant role": tenant-wide delegation
	// is rbac:manage, and admin is the allow-all superuser.
	for _, role := range AllRoles {
		if role == RoleAdmin {
			continue
		}
		if RoleGrants(role, ActionDelegate) {
			t.Errorf("organization role %q must not grant resource:delegate", role)
		}
	}

	// Each family is a chain: every capability of the weaker bundle is held by the
	// stronger one, and the ca/key families never cross over. A CA grant that
	// conferred secret:sign would hand out key material through the wrong door.
	chains := [][]ResourceRole{
		{ResourceRoleCAAdmin, ResourceRoleCAManager, ResourceRoleCAIssuer, ResourceRoleCAAuditor},
		{ResourceRoleKeyAdmin, ResourceRoleKeySigner, ResourceRoleKeyAuditor},
	}
	for _, chain := range chains {
		for i := 0; i+1 < len(chain); i++ {
			stronger, weaker := chain[i], chain[i+1]
			for _, act := range AllActions {
				if ResourceRoleGrants(weaker, act) && !ResourceRoleGrants(stronger, act) {
					t.Errorf("%s grants %s but the stronger %s does not: the family is no longer ordered",
						weaker, act, stronger)
				}
			}
		}
	}
	caOnly := []Action{ActionManageCA, ActionConfigureCA, ActionIssue}
	keyOnly := []Action{ActionSign, ActionManageSigningKey}
	for _, role := range []ResourceRole{ResourceRoleCAAdmin, ResourceRoleCAManager, ResourceRoleCAIssuer, ResourceRoleCAAuditor} {
		for _, act := range keyOnly {
			if ResourceRoleGrants(role, act) {
				t.Errorf("CA role %s must not grant the signing-key capability %s", role, act)
			}
		}
	}
	for _, role := range []ResourceRole{ResourceRoleKeyAdmin, ResourceRoleKeySigner, ResourceRoleKeyAuditor} {
		for _, act := range caOnly {
			if ResourceRoleGrants(role, act) {
				t.Errorf("signing-key role %s must not grant the CA capability %s", role, act)
			}
		}
	}
}

// TestEveryResourceRoleIsFullyWired catches a role that was declared and listed
// but never bundled or type-constrained: it would pass validation nowhere, or
// grant nothing while looking like a delegation.
func TestEveryResourceRoleIsFullyWired(t *testing.T) {
	for _, role := range AllResourceRoles {
		if !ValidResourceRole(role) {
			t.Errorf("%s is listed in AllResourceRoles but has no capability bundle", role)
			continue
		}
		if len(ResourceRoleActions(role)) == 0 {
			t.Errorf("%s bundles no actions, so granting it would silently authorize nothing", role)
		}
		var types []ResourceType
		for _, rt := range AllResourceTypes {
			if ResourceRoleAppliesTo(role, rt) {
				types = append(types, rt)
			}
		}
		if len(types) == 0 {
			t.Errorf("%s applies to no resource type, so it can never be granted", role)
		}
		for _, rt := range types {
			var found bool
			for _, offered := range ResourceRolesFor(rt) {
				if offered == role {
					found = true
				}
			}
			if !found {
				t.Errorf("%s applies to %s but is not offered by ResourceRolesFor(%s)", role, rt, rt)
			}
		}
	}
}

func TestGrantKeyIsTheRuleIdentity(t *testing.T) {
	base := Grant{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager, Scope: ScopeSelf}

	// The same rule arriving from configuration and from the database must
	// collapse to one key. The database enforces
	// UNIQUE(resource_type, resource_id, entity_type, entity_id, role)
	// (internal/database/database.go), so scope is deliberately NOT part of the
	// identity: widening a rule's reach updates it instead of adding a second one.
	widened := base
	widened.Scope = ScopeSubtree
	if base.Key() != widened.Key() {
		t.Errorf("widening the scope changed the rule identity: %q vs %q", base.Key(), widened.Key())
	}
	// Normalizing a grant must not change its identity either, or a stored rule
	// would stop matching the one that was written.
	unnormalized := base
	unnormalized.Scope = ""
	if unnormalized.Key() != base.Key() || unnormalized.Normalized().Key() != base.Key() {
		t.Errorf("Key() is not stable across normalization: %q / %q / %q",
			unnormalized.Key(), unnormalized.Normalized().Key(), base.Key())
	}

	// Every field that IS part of the identity has to change the key. (Key does
	// not validate, so the resource-type variant intentionally keeps the CA role.)
	variants := map[string]Grant{
		"resource type": {Resource: keyRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager},
		"resource id":   {Resource: caRes("sub-c"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager},
		"entity type":   {Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "team", Role: ResourceRoleCAManager},
		"entity id":     {Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "other-team", Role: ResourceRoleCAManager},
		"role":          {Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAAdmin},
	}
	keys := map[string]string{"base": base.Key()}
	for name, g := range variants {
		k := g.Key()
		for other, seen := range keys {
			if k == seen {
				t.Errorf("changing the %s must change the key, but %q collides with %s", name, k, other)
			}
		}
		keys[name] = k
	}
	// A key is a single line with no separator of its own, so it is usable as a
	// map key and inside an audit record.
	if strings.ContainsAny(base.Key(), "\n\r") {
		t.Errorf("grant key %q contains a line break", base.Key())
	}
}

func TestGrantSetAtReturnsOnlyDirectGrants(t *testing.T) {
	teamOnSubB := Grant{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager}
	aliceOnSubB := Grant{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAuditor}
	teamOnRoot := Grant{Resource: caRes("root"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAAdmin, Scope: ScopeSubtree}
	teamOnKey := Grant{Resource: keyRes("release"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleKeySigner}
	gs := NewGrantSet([]Grant{teamOnSubB, aliceOnSubB, teamOnRoot, teamOnKey})

	tests := []struct {
		name string
		res  Resource
		want []Grant
	}{
		{name: "the delegated CA", res: caRes("sub-b"), want: []Grant{teamOnSubB, aliceOnSubB}},
		{name: "a sibling CA", res: caRes("sub-a")},
		// At reports what is recorded ON the resource, never what reaches it: the
		// subtree grant above sub-b is not a rule of the child, so a caller
		// listing a CA's grants cannot mistake inherited authority for a local one.
		{name: "a descendant of the delegated CA", res: caRes("leaf")},
		{name: "the parent of the delegated CA", res: caRes("root"), want: []Grant{teamOnRoot}},
		// Resources are addressed by id; another tenant's CA is simply another id.
		{name: "a CA belonging to another tenant", res: caRes("other-tenant-ca")},
		// The resource TYPE is part of the index: a signing key whose name happens
		// to match a CA id must not inherit the CA's grants.
		{name: "a signing key named like the CA", res: keyRes("sub-b")},
		{name: "the delegated signing key", res: keyRes("release"), want: []Grant{teamOnKey}},
		{name: "an unnamed resource", res: Resource{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := gs.At(tc.res)
			want := make([]Grant, len(tc.want))
			for i, g := range tc.want {
				want[i] = g.Normalized()
			}
			gotSorted := append([]Grant(nil), got...)
			SortGrants(gotSorted)
			SortGrants(want)
			if strings.Join(renderGrants(gotSorted), " ") != strings.Join(renderGrants(want), " ") {
				t.Fatalf("At(%s) = %v, want %v", tc.res, renderGrants(gotSorted), renderGrants(want))
			}
			// Whatever comes back is normalized, so a caller comparing scopes sees
			// "self" rather than an empty string.
			for _, g := range got {
				if g.Scope == "" {
					t.Errorf("At(%s) returned an un-normalized grant %v", tc.res, g)
				}
				if g.Resource != tc.res {
					t.Errorf("At(%s) returned a grant on %s", tc.res, g.Resource)
				}
			}
		})
	}

	var nilSet *GrantSet
	if got := nilSet.At(caRes("sub-b")); got != nil {
		t.Errorf("nil GrantSet At() = %v, want nil", got)
	}
	if got := NewGrantSet(nil).At(caRes("sub-b")); len(got) != 0 {
		t.Errorf("empty GrantSet At() = %v, want none", got)
	}
	// A dropped (invalid) grant is not retrievable either.
	dropped := NewGrantSet([]Grant{{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "a", Role: "ca-god"}})
	if got := dropped.At(caRes("sub-b")); len(got) != 0 {
		t.Errorf("invalid grant surfaced through At(): %v", got)
	}
}

func TestGrantSetAllIsCompleteAndStable(t *testing.T) {
	in := []Grant{
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager},
		{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAuditor, Scope: ScopeSelf},
		{Resource: caRes("root"), EntityType: EntityGroup, EntityID: "platform", Role: ResourceRoleCAAdmin, Scope: ScopeSubtree},
		{Resource: caRes("sub-a"), EntityType: EntityUser, EntityID: "bob@corp.example", Role: ResourceRoleCAIssuer},
		{Resource: keyRes("release"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleKeySigner},
		{Resource: keyRes("release"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleKeyAuditor},
	}
	gs := NewGrantSet(in)
	first := gs.All()
	if len(first) != len(in) {
		t.Fatalf("All() returned %d grants, want %d: %v", len(first), len(in), renderGrants(first))
	}
	for _, g := range first {
		if g.Scope == "" {
			t.Errorf("All() returned an un-normalized grant %v", g)
		}
	}
	// All() walks a map whose iteration order Go randomizes deliberately, so the
	// sort is the only thing that makes CLI output and API responses reproducible.
	// Rebuilding the set re-randomizes the layout.
	want := strings.Join(renderGrants(first), " ")
	for i := 0; i < 64; i++ {
		if got := strings.Join(renderGrants(NewGrantSet(in).All()), " "); got != want {
			t.Fatalf("All() is not stable across runs:\n got %s\nwant %s", got, want)
		}
		if got := strings.Join(renderGrants(gs.All()), " "); got != want {
			t.Fatalf("All() is not stable across calls:\n got %s\nwant %s", got, want)
		}
	}
	// The result is sorted, so a caller can compare two listings directly.
	sorted := append([]Grant(nil), first...)
	SortGrants(sorted)
	if strings.Join(renderGrants(sorted), " ") != want {
		t.Errorf("All() is not returned in SortGrants order: %v", renderGrants(first))
	}

	// The caller owns the returned slice: writing to it must not rewrite the set.
	orig := first[0]
	first[0] = Grant{Resource: caRes("hijacked"), EntityType: EntityUser, EntityID: "mallory", Role: ResourceRoleCAAdmin, Scope: ScopeSubtree}
	if again := gs.All(); again[0] != orig {
		t.Errorf("mutating the result of All() corrupted the set: %v", again[0])
	}

	var nilSet *GrantSet
	if got := nilSet.All(); got != nil {
		t.Errorf("nil GrantSet All() = %v, want nil", got)
	}
	if got := NewGrantSet(nil).All(); len(got) != 0 {
		t.Errorf("empty GrantSet All() = %v, want none", got)
	}
}

// TestSortGrantsIsADeterministicTotalOrder asserts the property the doc comment
// promises — "orders grants deterministically for display and comparison" —
// rather than restating the comparator: every input order of the same grants must
// produce the same output. That matters because the sorted list is built from a
// map walk (GrantSet.All) over the union of the configured and the stored grants,
// and those two sources can hold the same rule at different scopes.
func TestSortGrantsIsADeterministicTotalOrder(t *testing.T) {
	// Consecutive entries differ in exactly one field, walking the comparator
	// from the resource type down to the scope, so every tiebreak is exercised.
	canonical := []Grant{
		{Resource: caRes("root"), EntityType: EntityGroup, EntityID: "platform", Role: ResourceRoleCAAdmin, Scope: ScopeSubtree},
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "alpha", Role: ResourceRoleCAManager, Scope: ScopeSelf},
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAIssuer, Scope: ScopeSelf},
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager, Scope: ScopeSelf},
		// Same rule as the previous one but reaching further: the config block and
		// the resource_grants table can each hold one of these, and they are
		// distinguishable only by scope.
		{Resource: caRes("sub-b"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleCAManager, Scope: ScopeSubtree},
		{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAuditor, Scope: ScopeSelf},
		{Resource: keyRes("release"), EntityType: EntityGroup, EntityID: "team", Role: ResourceRoleKeySigner, Scope: ScopeSelf},
	}
	want := strings.Join(renderGrants(canonical), " ")

	// Sorting the sorted list is a no-op.
	idempotent := append([]Grant(nil), canonical...)
	SortGrants(idempotent)
	if got := strings.Join(renderGrants(idempotent), " "); got != want {
		t.Fatalf("SortGrants is not idempotent:\n got %s\nwant %s", got, want)
	}

	// Every permutation converges on the same order — no randomness, no flakes.
	permuteGrants(append([]Grant(nil), canonical...), func(p []Grant) {
		got := append([]Grant(nil), p...)
		SortGrants(got)
		if rendered := strings.Join(renderGrants(got), " "); rendered != want {
			t.Fatalf("SortGrants(%v) =\n %s\nwant %s", renderGrants(p), rendered, want)
		}
	})

	// Degenerate inputs must not panic.
	SortGrants(nil)
	SortGrants([]Grant{})
	single := []Grant{canonical[0]}
	SortGrants(single)
	if single[0] != canonical[0] {
		t.Error("SortGrants altered a single-element slice")
	}
}

func TestGrantValidateRejectsUnknownScope(t *testing.T) {
	// An unrecognized scope must fail loudly rather than be treated as either
	// bound: read as "self" it locks a team out, read as "subtree" it hands over a
	// whole branch of the PKI. Only the empty string is allowed to mean "default".
	for _, scope := range []GrantScope{"all", "tree", "Subtree", "SELF", "self ", "*"} {
		g := Grant{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAdmin, Scope: scope}
		if err := g.Validate(); err == nil {
			t.Errorf("Validate() accepted scope %q", scope)
		}
		if ValidGrantScope(scope) {
			t.Errorf("ValidGrantScope(%q) = true, want false", scope)
		}
		// Normalizing must not launder it into a valid grant, and the evaluator
		// must refuse to index it.
		if err := g.Normalized().Validate(); err == nil {
			t.Errorf("Normalized() laundered the invalid scope %q", scope)
		}
		if gs := NewGrantSet([]Grant{g}); !gs.Empty() {
			t.Errorf("a grant with scope %q was indexed: %v", scope, renderGrants(gs.All()))
		}
	}
	// The empty scope is the documented default and stays valid.
	ok := Grant{Resource: caRes("sub-b"), EntityType: EntityUser, EntityID: "alice", Role: ResourceRoleCAAdmin}
	if err := ok.Validate(); err != nil {
		t.Errorf("an empty scope must remain valid: %v", err)
	}
	if got := ok.Normalized().Scope; got != ScopeSelf {
		t.Errorf("Normalized() scope = %q, want %q", got, ScopeSelf)
	}
}

func TestIdentityMatchesEdgeCases(t *testing.T) {
	// A grant whose entity id is empty must match nobody — least of all an
	// unauthenticated principal whose subject and email are also empty. Matches is
	// exercised directly here because NewGrantSet rejects such a grant before the
	// evaluator ever sees it, which leaves this guard otherwise untested.
	blank := Grant{Resource: caRes("c"), EntityType: EntityUser, EntityID: "", Role: ResourceRoleCAAdmin}
	for _, id := range []Identity{
		{},
		{Subject: "alice"},
		{Email: "alice@corp.example", EmailVerified: true},
		{Groups: []string{""}},
	} {
		if id.Matches(blank) {
			t.Errorf("identity %+v matched a grant with an empty entity id", id)
		}
	}
	// An entity type outside the recognized set matches nothing: the safe reading
	// of a rule the evaluator does not understand is "grants nothing".
	for _, entityType := range []string{"robot", "", "User", "GROUP", "service"} {
		g := Grant{Resource: caRes("c"), EntityType: entityType, EntityID: "alice", Role: ResourceRoleCAAdmin}
		if (Identity{Subject: "alice", Groups: []string{"alice"}}).Matches(g) {
			t.Errorf("entity type %q must not match", entityType)
		}
		if ValidEntityType(entityType) {
			t.Errorf("ValidEntityType(%q) = true, want false", entityType)
		}
	}
	// End to end: an identity carrying an empty group string (an IdP claim with a
	// blank entry) gains nothing, because the grant that could match it is refused
	// at indexing time.
	gs := NewGrantSet([]Grant{{Resource: caRes("c"), EntityType: EntityGroup, EntityID: "", Role: ResourceRoleCAAdmin}})
	if !gs.Empty() {
		t.Fatalf("a group grant with no entity id was indexed: %v", renderGrants(gs.All()))
	}
	if gs.Allows(caRes("c"), nil, Identity{Groups: []string{""}}, ActionReadAudit) {
		t.Error("an empty group claim must not pick up authority")
	}
}

func TestNilGrantSetAuthorizesNothing(t *testing.T) {
	// grantSetAt returns (nil, err) on a database failure, so every lookup has to
	// be safe and fail closed on a nil set rather than panic in the middle of an
	// authorization decision.
	var nilSet *GrantSet
	id := Identity{Subject: "alice", Email: "alice@corp.example", EmailVerified: true, Groups: []string{"team"}}
	if !nilSet.Empty() {
		t.Error("nil GrantSet should report Empty()")
	}
	if got := nilSet.RolesFor(caRes("sub-b"), []Resource{caRes("root")}, id); got != nil {
		t.Errorf("nil GrantSet RolesFor = %v, want nil", got)
	}
	if got := nilSet.ResourcesFor(ResourceCA, id); got != nil {
		t.Errorf("nil GrantSet ResourcesFor = %v, want nil", got)
	}
	for _, act := range AllActions {
		if nilSet.Allows(caRes("sub-b"), []Resource{caRes("root")}, id, act) {
			t.Errorf("nil GrantSet allowed %s", act)
		}
	}
}

// permuteGrants calls fn with every ordering of gs. fn must not retain the slice.
func permuteGrants(gs []Grant, fn func([]Grant)) {
	n := len(gs)
	var rec func(k int)
	rec = func(k int) {
		if k == n {
			fn(gs)
			return
		}
		for i := k; i < n; i++ {
			gs[k], gs[i] = gs[i], gs[k]
			rec(k + 1)
			gs[k], gs[i] = gs[i], gs[k]
		}
	}
	rec(0)
}
