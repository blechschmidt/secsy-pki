package rbac

import (
	"sort"
	"strings"
	"testing"
)

// Tenant isolation is the mechanism that keeps one tenant's operators out of
// another tenant (see the TenantAssignments doc, rbac.go:357-366): a principal's
// effective capability inside a tenant is the union of its PLATFORM roles, which
// apply in every tenant, and its roles WITHIN that one tenant. Every assertion
// below is a statement about that boundary — a false negative locks an operator
// out, a false positive is a cross-tenant privilege escalation.

const (
	tenantAcme   = "acme"
	tenantGlobex = "globex"
)

// wantRoles asserts an exact role sequence. Order is part of the contract:
// rolesFor documents "dedup preserving order" and callers render the result
// verbatim into audit records through JoinRoles, so a silent reordering turns up
// as a diff in every log line.
func wantRoles(t *testing.T, got []Role, want ...Role) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("roles = %v, want %v", got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("roles = %v, want %v", got, want)
			return
		}
	}
}

// tenantFixture mirrors the wiring in cmd/server/main.go (one platform-wide
// Assignments built from the top-level rbac block, layered over one Assignments
// per configured tenant).
func tenantFixture(t *testing.T) *TenantAssignments {
	t.Helper()
	platform := NewAssignments(
		map[string][]Role{
			"ops-1": {RoleAuditor},
			// Keyed by e-mail rather than by subject, and carrying the most
			// dangerous role in the system: honored only for a VERIFIED address.
			"platform-admin@corp.example": {RoleAdmin},
		},
		map[string][]Role{"platform-oncall": {RoleApprover}},
	)
	acme := NewAssignments(
		map[string][]Role{
			"alice":            {RoleAdmin},
			"bob@acme.example": {RoleIssuer},
		},
		map[string][]Role{
			"acme-issuers": {RoleIssuer},
			// A group identity asserted by an IdP is NOT namespaced per tenant, so
			// the same group name can appear in two tenants' configuration. The
			// lookup must therefore be keyed by tenant and nothing else.
			"shared-team": {RoleAdmin},
		},
	)
	globex := NewAssignments(
		map[string][]Role{"carol": {RoleAdmin}},
		map[string][]Role{"globex-auditors": {RoleAuditor}},
	)
	return NewTenantAssignments(platform, map[string]*Assignments{
		tenantAcme:   acme,
		tenantGlobex: globex,
		// A tenant declared in configuration with no usable rbac index at all: the
		// constructor drops the nil so no lookup can dereference it.
		"dormant": nil,
	})
}

func TestTenantRolesForIsolatesTenants(t *testing.T) {
	ta := tenantFixture(t)
	tests := []struct {
		name          string
		tenant        string
		subject       string
		email         string
		emailVerified bool
		groups        []string
		want          []Role
	}{
		{name: "subject role applies in its own tenant", tenant: tenantAcme, subject: "alice", want: []Role{RoleAdmin}},
		// The headline isolation property: alice administers acme and is a
		// stranger in globex. Returning admin here would be a cross-tenant
		// privilege escalation, not a cosmetic defect.
		{name: "subject role does not cross to another tenant", tenant: tenantGlobex, subject: "alice"},
		{name: "unknown tenant id grants nothing", tenant: "no-such-tenant", subject: "alice"},
		// A request that carries no tenant context must fail closed instead of
		// falling back to "any tenant" or to the platform assignments.
		{name: "empty tenant id grants nothing", tenant: "", subject: "alice"},
		{name: "tenant with no usable index grants nothing", tenant: "dormant", subject: "alice"},
		{name: "group role applies in its own tenant", tenant: tenantAcme, subject: "dave", groups: []string{"acme-issuers"}, want: []Role{RoleIssuer}},
		{name: "group role does not cross tenants", tenant: tenantGlobex, subject: "dave", groups: []string{"acme-issuers"}},
		// Same group NAME configured in both tenants, with different roles: a
		// member of acme's "shared-team" must gain nothing in globex.
		{name: "shared group name grants only in the configuring tenant", tenant: tenantGlobex, subject: "dave", groups: []string{"shared-team"}},
		{name: "shared group name still grants in its own tenant", tenant: tenantAcme, subject: "dave", groups: []string{"shared-team"}, want: []Role{RoleAdmin}},
		// Platform roles are deliberately NOT reported here; the caller unions
		// them in separately (see TestPlatformRolesApplyInEveryTenant).
		{name: "platform-only subject has no tenant roles", tenant: tenantAcme, subject: "ops-1"},
		{name: "platform group role is not a tenant role", tenant: tenantAcme, subject: "x", groups: []string{"platform-oncall"}},
		{name: "verified email role applies in its own tenant", tenant: tenantAcme, subject: "sub-bob", email: "bob@acme.example", emailVerified: true, want: []Role{RoleIssuer}},
		{name: "verified email role does not cross tenants", tenant: tenantGlobex, subject: "sub-bob", email: "bob@acme.example", emailVerified: true},
		{name: "wholly unknown principal gets nothing", tenant: tenantAcme, subject: "mallory", email: "mallory@evil.example", emailVerified: true, groups: []string{"wheel"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ta.TenantRolesFor(tc.tenant, tc.subject, tc.email, tc.emailVerified, tc.groups)
			wantRoles(t, got, tc.want...)
			if len(tc.want) != 0 {
				return
			}
			// The gates ask Can(), not HasRole(): assert at the capability level
			// too, so a leak cannot hide behind an unexpected role name.
			for _, act := range AllActions {
				if Can(got, act) {
					t.Errorf("roles %v in tenant %q must grant nothing, got %s", got, tc.tenant, act)
				}
			}
		})
	}
}

func TestPlatformRolesApplyInEveryTenant(t *testing.T) {
	ta := tenantFixture(t)
	// effective mirrors what the callers do (cmd/server/auth.go, cmd/server/main.go):
	// the union of platform and tenant roles, per rbac.go:357-366.
	effective := func(tenant, subject, email string, verified bool, groups []string) []Role {
		return append(ta.PlatformRolesFor(subject, email, verified, groups),
			ta.TenantRolesFor(tenant, subject, email, verified, groups)...)
	}

	// A platform auditor reads the trail inside every tenant — including a tenant
	// with no role index and one that does not exist at all — but gains no
	// capability beyond the read-only one it was granted.
	for _, tid := range []string{tenantAcme, tenantGlobex, "dormant", "no-such-tenant", ""} {
		roles := effective(tid, "ops-1", "", false, nil)
		if !Can(roles, ActionReadAudit) {
			t.Errorf("platform auditor should hold audit:read in tenant %q, roles = %v", tid, roles)
		}
		if Can(roles, ActionIssue) || Can(roles, ActionManageCA) {
			t.Errorf("platform auditor must not gain issuance/management in tenant %q, roles = %v", tid, roles)
		}
	}
	// A platform role held through a group behaves identically.
	for _, tid := range []string{tenantAcme, tenantGlobex} {
		roles := effective(tid, "oncall-1", "", false, []string{"platform-oncall"})
		if !Can(roles, ActionApprove) {
			t.Errorf("platform approver should hold approval:approve in tenant %q, roles = %v", tid, roles)
		}
	}

	// The union is one-directional. A TENANT admin must never be reported as a
	// platform operator: platform roles are what authorize the cross-tenant
	// endpoints, so leaking one is an escalation out of the tenant sandbox.
	for _, subject := range []string{"alice", "carol"} {
		if roles := ta.PlatformRolesFor(subject, "", false, nil); len(roles) != 0 {
			t.Errorf("tenant admin %q must hold no platform roles, got %v", subject, roles)
		}
	}
	if Can(effective(tenantGlobex, "alice", "", false, nil), ActionManageCA) {
		t.Error("acme's admin must not manage CAs in globex")
	}
	if !Can(effective(tenantAcme, "alice", "", false, nil), ActionManageCA) {
		t.Error("acme's admin must manage CAs in acme")
	}
	// Tenant-scoped group membership is likewise not a platform capability.
	if roles := ta.PlatformRolesFor("dave", "", false, []string{"shared-team", "acme-issuers"}); len(roles) != 0 {
		t.Errorf("tenant group membership must confer no platform roles, got %v", roles)
	}
}

func TestRolesForRequiresVerifiedEmail(t *testing.T) {
	ta := tenantFixture(t)
	// rbac.go:428 — an email-keyed assignment counts only when the identity
	// provider asserted email_verified. In many IdPs an unverified address is
	// attacker-chosen (self-service signup, editable profile), so honoring one
	// would be an authentication bypass: anyone who can type
	// platform-admin@corp.example into a profile field would become admin.
	tests := []struct {
		name     string
		subject  string
		email    string
		verified bool
		want     []Role
	}{
		{name: "verified email matches the assignment", subject: "sub-1", email: "platform-admin@corp.example", verified: true, want: []Role{RoleAdmin}},
		{name: "unverified email grants nothing", subject: "sub-1", email: "platform-admin@corp.example"},
		{name: "empty email with the verified flag set grants nothing", subject: "sub-1", email: "", verified: true},
		{name: "unrelated verified email grants nothing", subject: "sub-1", email: "nobody@corp.example", verified: true},
		{name: "subject assignment is independent of the email flags", subject: "ops-1", email: "platform-admin@corp.example", want: []Role{RoleAuditor}},
		{name: "verified email unions with the subject assignment", subject: "ops-1", email: "platform-admin@corp.example", verified: true, want: []Role{RoleAuditor, RoleAdmin}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ta.PlatformRolesFor(tc.subject, tc.email, tc.verified, nil)
			wantRoles(t, got, tc.want...)
			if len(tc.want) == 0 && AnyPrivilegedRole(got) {
				t.Errorf("unverified/unmatched email must not yield a privileged role, got %v", got)
			}
		})
	}
	// The same gate has to hold on the tenant side, which uses the same helper.
	if roles := ta.TenantRolesFor(tenantAcme, "sub-bob", "bob@acme.example", false, nil); len(roles) != 0 {
		t.Errorf("unverified email must grant no tenant roles, got %v", roles)
	}
	if roles := ta.TenantRolesFor(tenantAcme, "sub-bob", "bob@acme.example", true, nil); !HasRole(roles, RoleIssuer) {
		t.Errorf("verified email should grant the tenant role, got %v", roles)
	}
}

func TestRolesForDedupsWithoutCorruptingTheAssignments(t *testing.T) {
	// A subject, two groups and a verified email that all grant overlapping role
	// sets, so the raw union contains duplicates in several positions. rolesFor
	// dedups in place over the slice it appended to (rbac.go:431-440), which is
	// only safe as long as that slice is not shared with the stored assignments.
	as := NewAssignments(
		map[string][]Role{
			// The duplicate is deliberate: configuration may list a role twice
			// (a copy-paste in YAML), which is what makes the dedup shorten the
			// slice it is walking rather than merely copy it.
			"alice":              {RoleIssuer, RoleIssuer, RoleAuditor},
			"alice@corp.example": {RoleIssuer, RoleAdmin},
		},
		map[string][]Role{
			"g1": {RoleAuditor, RoleApprover},
			"g2": {RoleSigner, RoleIssuer},
		},
	)
	ta := NewTenantAssignments(as, nil)
	groups := []string{"g1", "g2"}

	// rawIntact inspects the stored slices directly rather than the deduplicated
	// view of them: an in-place dedup over an aliased slice can leave a corrupted
	// array that still happens to dedup to the right answer, which would make an
	// assertion on RolesFor alone pass while configuration state was destroyed.
	rawIntact := func(when string) {
		t.Helper()
		for _, c := range []struct {
			in   map[string][]Role
			key  string
			want string
		}{
			{as.bySubject, "alice", "issuer,issuer,auditor"},
			{as.bySubject, "alice@corp.example", "issuer,admin"},
			{as.byGroup, "g1", "auditor,approver"},
			{as.byGroup, "g2", "signer,issuer"},
		} {
			if got := JoinRoles(c.in[c.key]); got != c.want {
				t.Errorf("%s: stored assignment for %q = %q, want %q", when, c.key, got, c.want)
			}
		}
	}
	rawIntact("before any lookup")

	// The narrowest path — subject only, no groups and no email — is where a
	// "just return the stored slice" shortcut is most tempting, and where the
	// in-place dedup would then write straight into the configured assignment.
	wantRoles(t, ta.PlatformRolesFor("alice", "", false, nil), RoleIssuer, RoleAuditor)
	rawIntact("after a subject-only lookup")

	// Subject first, then each group in order, then the verified email; the first
	// occurrence of a role wins and later duplicates disappear.
	want := []Role{RoleIssuer, RoleAuditor, RoleApprover, RoleSigner, RoleAdmin}
	first := ta.PlatformRolesFor("alice", "alice@corp.example", true, groups)
	wantRoles(t, first, want...)

	// Calling again must produce exactly the same answer: the in-place dedup must
	// not have consumed or rearranged anything it does not own.
	wantRoles(t, ta.PlatformRolesFor("alice", "alice@corp.example", true, groups), want...)

	// ... and every stored assignment must still hold its original set. If the
	// `out := roles[:0]` dedup ever aliased a stored slice it would overwrite it
	// in place, and each later lookup would see a truncated or shuffled set.
	wantRoles(t, as.RolesFor("alice", nil), RoleIssuer, RoleAuditor)
	wantRoles(t, as.RolesFor("alice@corp.example", nil), RoleIssuer, RoleAdmin)
	wantRoles(t, as.RolesFor("", []string{"g1"}), RoleAuditor, RoleApprover)
	wantRoles(t, as.RolesFor("", []string{"g2"}), RoleSigner, RoleIssuer)
	rawIntact("after a full subject+group+email lookup")

	// Callers append to the returned slice (cmd/server/auth.go does exactly this
	// to union in the claim-mapped roles). The dedup leaves spare capacity, so
	// that append writes into the returned array: it must not reach any state a
	// later lookup depends on.
	grown := append(first, RoleAdmin, RoleSigner)
	if len(grown) != len(want)+2 {
		t.Fatalf("append to the returned slice produced %v", grown)
	}
	wantRoles(t, ta.PlatformRolesFor("alice", "alice@corp.example", true, groups), want...)
	wantRoles(t, as.RolesFor("alice", nil), RoleIssuer, RoleAuditor)
	rawIntact("after appending to a returned slice")

	// A group asserted twice (an IdP that repeats it across two claims) must not
	// duplicate roles either.
	wantRoles(t, ta.PlatformRolesFor("alice", "", false, []string{"g1", "g1"}),
		RoleIssuer, RoleAuditor, RoleApprover)
	rawIntact("after a repeated-group lookup")
}

func TestTenantAssignmentsNilSafetyAndTenantList(t *testing.T) {
	// The platform block and the individual tenant blocks are all optional, so
	// every accessor has to be safe on a nil receiver and on a nil member.
	var nilTA *TenantAssignments
	if got := nilTA.Platform(); got != nil {
		t.Errorf("nil receiver Platform() = %v, want nil", got)
	}
	if got := nilTA.PlatformRolesFor("alice", "a@b.example", true, []string{"g"}); len(got) != 0 {
		t.Errorf("nil receiver PlatformRolesFor = %v, want none", got)
	}
	if got := nilTA.TenantRolesFor(tenantAcme, "alice", "a@b.example", true, []string{"g"}); len(got) != 0 {
		t.Errorf("nil receiver TenantRolesFor = %v, want none", got)
	}
	if got := nilTA.Tenants(); len(got) != 0 {
		t.Errorf("nil receiver Tenants() = %v, want none", got)
	}

	// The embedded index is nil-safe too: Assignments is documented as usable
	// through a nil pointer (that is what Empty() relies on), and a deployment
	// with no rbac block at all takes exactly this path.
	var nilAssignments *Assignments
	if got := nilAssignments.RolesFor("alice", []string{"g"}); got != nil {
		t.Errorf("nil Assignments RolesFor = %v, want nil", got)
	}
	if got := rolesFor(nil, "alice", "alice@corp.example", true, []string{"g"}); got != nil {
		t.Errorf("rolesFor(nil) = %v, want nil", got)
	}

	// With no platform block, a platform lookup must return nothing rather than
	// falling back to some tenant's assignments.
	tenantOnly := NewTenantAssignments(nil, map[string]*Assignments{
		tenantAcme: NewAssignments(map[string][]Role{"alice": {RoleAdmin}}, nil),
	})
	if got := tenantOnly.Platform(); got != nil {
		t.Errorf("Platform() = %v, want nil when no platform block is configured", got)
	}
	if got := tenantOnly.PlatformRolesFor("alice", "", false, nil); len(got) != 0 {
		t.Errorf("a tenant admin must not become a platform admin, got %v", got)
	}
	wantRoles(t, tenantOnly.TenantRolesFor(tenantAcme, "alice", "", false, nil), RoleAdmin)

	// Platform() hands back the very index it was built with: callers use it to
	// decide whether any platform RBAC is configured at all.
	platform := NewAssignments(map[string][]Role{"ops-1": {RoleAuditor}}, nil)
	if got := NewTenantAssignments(platform, nil).Platform(); got != platform {
		t.Error("Platform() must return the assignments the constructor was given")
	}

	// Tenants lists only the tenants that resolved to a real index; the nil entry
	// is dropped by the constructor so the resolver loops that walk Tenants() and
	// call TenantRolesFor can never dereference one.
	got := tenantFixture(t).Tenants()
	sort.Strings(got)
	if want := []string{tenantAcme, tenantGlobex}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Tenants() = %v, want %v", got, want)
	}
	if got := NewTenantAssignments(nil, nil).Tenants(); len(got) != 0 {
		t.Errorf("Tenants() with no tenants = %v, want none", got)
	}
}

func TestNewAssignmentsDropsUnknownRoleNames(t *testing.T) {
	// rbac.go:305 — "Unknown role names are ignored so a typo cannot silently
	// grant broad access." Each of these is a plausible way to mistype `admin`
	// in YAML; none may confer anything.
	typos := []Role{"Admin", "ADMIN", "admin ", " admin", "admins", "root", "superuser", "*", ""}
	for _, bogus := range typos {
		if ValidRole(bogus) {
			t.Errorf("ValidRole(%q) = true, want false", bogus)
		}
		as := NewAssignments(
			map[string][]Role{"alice": {bogus}},
			map[string][]Role{"grp": {bogus}},
		)
		// An entry whose roles are ALL invalid is omitted entirely, which is what
		// makes Empty() (used to decide whether RBAC is configured at all) honest.
		if !as.Empty() {
			t.Errorf("assignments built only from %q should be Empty()", bogus)
		}
		roles := as.RolesFor("alice", []string{"grp"})
		if len(roles) != 0 {
			t.Errorf("role %q must be dropped, got %v", bogus, roles)
		}
		for _, act := range AllActions {
			if Can(roles, act) {
				t.Errorf("typo role %q must grant nothing, got %s", bogus, act)
			}
		}
		// The typo must not resurrect itself through the tenant layer either.
		ta := NewTenantAssignments(as, map[string]*Assignments{tenantAcme: as})
		if got := ta.PlatformRolesFor("alice", "", false, []string{"grp"}); len(got) != 0 {
			t.Errorf("typo role %q leaked into platform roles: %v", bogus, got)
		}
		if got := ta.TenantRolesFor(tenantAcme, "alice", "", false, []string{"grp"}); len(got) != 0 {
			t.Errorf("typo role %q leaked into tenant roles: %v", bogus, got)
		}
	}

	// A mixed entry keeps its valid roles and loses only the bad ones — the
	// filter must not throw away the whole assignment, or a single typo would
	// lock the operator out of everything.
	mixed := NewAssignments(
		map[string][]Role{"alice": {"Admin", RoleAuditor, "root"}},
		map[string][]Role{"grp": {RoleSigner, "ca-admin"}},
	)
	wantRoles(t, mixed.RolesFor("alice", nil), RoleAuditor)
	wantRoles(t, mixed.RolesFor("alice", []string{"grp"}), RoleAuditor, RoleSigner)
	if Can(mixed.RolesFor("alice", []string{"grp"}), ActionManageCA) {
		t.Error(`"Admin" must not confer admin capability`)
	}
	// A resource role name (grant.go's vocabulary) is not an organization role:
	// the two namespaces are deliberately distinct, so `ca-admin` in an rbac
	// block must be dropped rather than interpreted.
	if HasRole(mixed.RolesFor("alice", []string{"grp"}), Role(ResourceRoleCAAdmin)) {
		t.Error("a resource role name must not be accepted as an organization role")
	}
}

func TestJoinRoles(t *testing.T) {
	// JoinRoles renders the actor's roles into audit and admin records
	// (internal/handlers/rbac_audit.go, internal/handlers/admin.go), which are
	// read back as a comma-separated list: no spaces, no sorting, no trailing
	// separator, and the caller's order preserved.
	tests := []struct {
		name  string
		roles []Role
		want  string
	}{
		{name: "nil", roles: nil, want: ""},
		{name: "empty", roles: []Role{}, want: ""},
		{name: "single", roles: []Role{RoleAdmin}, want: "admin"},
		{name: "several keep the caller's order", roles: []Role{RoleIssuer, RoleAuditor}, want: "issuer,auditor"},
		{name: "order is not normalized", roles: []Role{RoleAuditor, RoleIssuer}, want: "auditor,issuer"},
		{name: "three roles", roles: []Role{RoleAdmin, RoleSigner, RoleApprover}, want: "admin,signer,approver"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := JoinRoles(tc.roles); got != tc.want {
				t.Errorf("JoinRoles(%v) = %q, want %q", tc.roles, got, tc.want)
			}
		})
	}
	// Round-trip: the rendering is the inverse of a plain comma split, so an
	// audit consumer can recover the exact role set.
	roles := []Role{RoleApprover, RoleSigner}
	parts := strings.Split(JoinRoles(roles), ",")
	if len(parts) != len(roles) || parts[0] != string(RoleApprover) || parts[1] != string(RoleSigner) {
		t.Errorf("JoinRoles(%v) does not split back to the input: %q", roles, parts)
	}
}
