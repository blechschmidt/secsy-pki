// Resource-scoped authorization (Task 191).
//
// The role model in rbac.go answers "what class of operator is this?" across a
// whole tenant — a principal holding `admin` in tenant A administers *every* CA
// and key in tenant A. That is too coarse for the common enterprise split:
//
//	the platform team owns the offline root CA, while each product team
//	administers exactly its own subordinate CA and nothing else.
//
// A *grant* expresses that directly. It binds a user or a group to a named
// bundle of capabilities (a ResourceRole) at ONE individually addressed resource
// — a specific X.509 CA, SSH CA, or named signing key — optionally extending to
// that CA's subordinates. Grants are purely additive: they widen what a
// principal may do at a named resource and can never take a capability away, so
// evaluating them can be layered on top of the existing platform/tenant role
// decision without changing any existing outcome.
//
// The decision a caller ultimately asks is:
//
//	root  OR  platform role grants action
//	      OR  tenant role in the resource's tenant grants action
//	      OR  a grant at the resource (or an ancestor, when scope=subtree)
//	          grants action
//
// Grants come from two sources that share this evaluator: the `rbac.grants`
// block in central configuration (declarative, reviewable, survives a database
// rebuild) and the `resource_grants` table (delegated at runtime through the
// API/CLI by whoever holds resource:delegate).
package rbac

import (
	"fmt"
	"sort"
	"strings"
)

// ResourceType names a class of individually-authorizable object. Every type
// here is something an operator can point at by ID and say "this one, not the
// others".
type ResourceType string

const (
	// ResourceCA is a single certification authority — a root or any subordinate
	// — addressed by its CA ID. It covers the authority itself, whichever
	// certificate formats it signs: X.509 and SSH authorities share one table and
	// one ID namespace, so they are deliberately ONE resource type. Splitting them
	// would mean a grant written for an SSH CA silently failing to match the
	// identical ID checked as an X.509 CA.
	ResourceCA ResourceType = "ca"
	// ResourceSigningKey is a single named HSM-backed signing key on the secret
	// layer (Task 155), addressed by its key name. Grants on it delegate use of
	// (or administrative control over) that one key without exposing the tenant's
	// other keys.
	ResourceSigningKey ResourceType = "signing-key"
)

// AllResourceTypes is the set of recognized resource types, used for validation
// and for rendering help text.
var AllResourceTypes = []ResourceType{ResourceCA, ResourceSigningKey}

// ValidResourceType reports whether t is a recognized resource type.
func ValidResourceType(t ResourceType) bool {
	for _, k := range AllResourceTypes {
		if k == t {
			return true
		}
	}
	return false
}

// Resource identifies one individually-authorizable object.
type Resource struct {
	Type ResourceType
	ID   string
}

// String renders the resource in the canonical "<type>/<id>" form used in
// configuration, on the command line, and in audit records.
func (r Resource) String() string { return string(r.Type) + "/" + r.ID }

// Valid reports whether the resource is fully specified and of a known type.
func (r Resource) Valid() bool { return ValidResourceType(r.Type) && r.ID != "" }

// ParseResource parses the canonical "<type>/<id>" form. The ID may itself
// contain slashes (key names are operator-chosen), so only the first separator
// is significant.
func ParseResource(s string) (Resource, error) {
	typ, id, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || typ == "" || id == "" {
		return Resource{}, fmt.Errorf("resource %q must be in the form <type>/<id>, e.g. ca/%s", s, "3f9c…")
	}
	r := Resource{Type: ResourceType(typ), ID: id}
	if !ValidResourceType(r.Type) {
		return Resource{}, fmt.Errorf("unknown resource type %q (want one of %s)", typ, joinResourceTypes(AllResourceTypes))
	}
	// Resource identifiers are UUIDs or operator-chosen key names; whitespace or
	// a control character in one is never legitimate and always indicates a
	// mangled argument (a shell pipeline that captured two lines, say). Rejecting
	// it here keeps such a value out of grant rows, denial messages, and the audit
	// trail, where an embedded newline would forge a record boundary.
	if i := strings.IndexFunc(r.ID, func(c rune) bool { return c < 0x21 || c == 0x7f }); i >= 0 {
		return Resource{}, fmt.Errorf("resource id %q contains whitespace or a control character at offset %d", r.ID, i)
	}
	return r, nil
}

func joinResourceTypes(ts []ResourceType) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = string(t)
	}
	return strings.Join(parts, ", ")
}

// ResourceRole is a named bundle of capabilities granted at a single resource.
//
// The names are deliberately distinct from the platform role names (admin,
// issuer, …) so that a YAML reader can never mistake a grant of `ca-admin` on
// one CA for membership of the platform-wide `admin` role: the former is
// authority over one authority, the latter over the whole deployment.
type ResourceRole string

const (
	// ResourceRoleCAAdmin is full authority over one CA: everything CAManager
	// grants, plus the right to delegate that authority onward to other users and
	// groups (resource:delegate). It is the role handed to the team that owns a
	// subordinate CA end-to-end.
	ResourceRoleCAAdmin ResourceRole = "ca-admin"
	// ResourceRoleCAManager is day-to-day operation of one CA: rotate and retire
	// its key, publish its chain, cross-sign with it, revoke and issue against it,
	// edit its profiles and restriction sets, and read its trail. It deliberately
	// excludes resource:delegate, so a manager cannot widen its own blast radius
	// by granting itself — or anyone else — authority elsewhere.
	ResourceRoleCAManager ResourceRole = "ca-manager"
	// ResourceRoleCAIssuer may issue, renew, and revoke certificates on one CA
	// (still subject to that CA's profiles and restriction sets) and read its
	// trail, but may not administer the authority itself.
	ResourceRoleCAIssuer ResourceRole = "ca-issuer"
	// ResourceRoleCAAuditor is read-only visibility into one CA: its metadata,
	// inventory, and audit trail. It is the least-privilege way to let an auditor
	// see a single authority without granting tenant-wide read.
	ResourceRoleCAAuditor ResourceRole = "ca-auditor"

	// ResourceRoleKeyAdmin is full authority over one named signing key,
	// including delegating that authority onward.
	ResourceRoleKeyAdmin ResourceRole = "key-admin"
	// ResourceRoleKeySigner may sign and verify with one named signing key and
	// export its public half, but may not create, alter, or delegate it.
	ResourceRoleKeySigner ResourceRole = "key-signer"
	// ResourceRoleKeyAuditor is read-only visibility into one named signing key:
	// its metadata, public key, and usage trail.
	ResourceRoleKeyAuditor ResourceRole = "key-auditor"
)

// AllResourceRoles is the set of recognized resource roles, used for validation
// and help text. Ordered most- to least-privileged within each family.
var AllResourceRoles = []ResourceRole{
	ResourceRoleCAAdmin, ResourceRoleCAManager, ResourceRoleCAIssuer, ResourceRoleCAAuditor,
	ResourceRoleKeyAdmin, ResourceRoleKeySigner, ResourceRoleKeyAuditor,
}

// resourceRoleActions is the static capability bundle each resource role grants
// AT THE RESOURCE IT IS GRANTED ON. Nothing here leaks outside that resource:
// the evaluator only ever consults this table after matching a grant to the
// resource under decision.
var resourceRoleActions = map[ResourceRole]map[Action]bool{
	ResourceRoleCAAdmin: {
		ActionManageCA:    true,
		ActionConfigureCA: true,
		ActionIssue:       true,
		ActionReadAudit:   true,
		ActionDelegate:    true,
	},
	ResourceRoleCAManager: {
		ActionManageCA:    true,
		ActionConfigureCA: true,
		ActionIssue:       true,
		ActionReadAudit:   true,
	},
	ResourceRoleCAIssuer: {
		ActionIssue:     true,
		ActionReadAudit: true,
	},
	ResourceRoleCAAuditor: {
		ActionReadAudit: true,
	},
	ResourceRoleKeyAdmin: {
		ActionManageSigningKey: true,
		ActionSign:             true,
		ActionReadAudit:        true,
		ActionDelegate:         true,
	},
	ResourceRoleKeySigner: {
		ActionSign:      true,
		ActionReadAudit: true,
	},
	ResourceRoleKeyAuditor: {
		ActionReadAudit: true,
	},
}

// resourceRoleTypes constrains each role to the resource types it is meaningful
// on, so `key-signer` cannot be granted on a CA (where it would silently grant
// nothing) and `ca-manager` cannot be granted on a signing key.
var resourceRoleTypes = map[ResourceRole][]ResourceType{
	ResourceRoleCAAdmin:    {ResourceCA},
	ResourceRoleCAManager:  {ResourceCA},
	ResourceRoleCAIssuer:   {ResourceCA},
	ResourceRoleCAAuditor:  {ResourceCA},
	ResourceRoleKeyAdmin:   {ResourceSigningKey},
	ResourceRoleKeySigner:  {ResourceSigningKey},
	ResourceRoleKeyAuditor: {ResourceSigningKey},
}

// ValidResourceRole reports whether r is a recognized resource role.
func ValidResourceRole(r ResourceRole) bool {
	_, ok := resourceRoleActions[r]
	return ok
}

// ResourceRoleAppliesTo reports whether role is meaningful on a resource of the
// given type.
func ResourceRoleAppliesTo(role ResourceRole, t ResourceType) bool {
	for _, k := range resourceRoleTypes[role] {
		if k == t {
			return true
		}
	}
	return false
}

// ResourceRolesFor returns the resource roles that may be granted on a resource
// type, most-privileged first. Used by the CLI/console to offer valid choices.
func ResourceRolesFor(t ResourceType) []ResourceRole {
	var out []ResourceRole
	for _, r := range AllResourceRoles {
		if ResourceRoleAppliesTo(r, t) {
			out = append(out, r)
		}
	}
	return out
}

// ResourceRoleGrants reports whether a resource role grants an action at the
// resource it is held on. Unlike the platform `admin` role there is no
// allow-all resource role: a grant is a bounded delegation, so every capability
// it confers is listed explicitly and a newly added Action is denied by default
// until it is deliberately added to a bundle.
func ResourceRoleGrants(role ResourceRole, action Action) bool {
	return resourceRoleActions[role][action]
}

// ResourceRoleActions returns the sorted actions a resource role grants. Used
// for effective-permission introspection and documentation.
func ResourceRoleActions(role ResourceRole) []Action {
	acts := make([]Action, 0, len(resourceRoleActions[role]))
	for a := range resourceRoleActions[role] {
		acts = append(acts, a)
	}
	sort.Slice(acts, func(i, j int) bool { return acts[i] < acts[j] })
	return acts
}

// GrantScope controls how far down a CA hierarchy a grant reaches.
type GrantScope string

const (
	// ScopeSelf confines the grant to exactly the named resource. It is the
	// default and the safe choice: delegating a subordinate CA must not silently
	// hand over authorities created underneath it later.
	ScopeSelf GrantScope = "self"
	// ScopeSubtree extends the grant to the named CA and every CA beneath it in
	// the issuance hierarchy, including ones created later. It expresses "this
	// team owns this branch of the PKI" without re-granting on every new
	// subordinate. It is only meaningful on CA-shaped resources, which are the
	// only ones with a parent/child hierarchy.
	ScopeSubtree GrantScope = "subtree"
)

// ValidGrantScope reports whether s is a recognized scope.
func ValidGrantScope(s GrantScope) bool { return s == ScopeSelf || s == ScopeSubtree }

// Entity types a grant can be bound to.
const (
	// EntityUser binds a grant to a single principal, matched against its subject
	// or its VERIFIED email address (the same rule the platform role assignments
	// use, so an unverified email can never pick up authority).
	EntityUser = "user"
	// EntityGroup binds a grant to a group. Group identity spans both internal
	// groups managed in the database and the groups asserted by the identity
	// provider (OIDC claim / LDAP directory membership), so an existing
	// enterprise group can be handed a CA without being mirrored locally.
	EntityGroup = "group"
)

// ValidEntityType reports whether t is a recognized grant entity type.
func ValidEntityType(t string) bool { return t == EntityUser || t == EntityGroup }

// Grant binds one entity to one resource role at one resource.
type Grant struct {
	Resource   Resource     `json:"resource"`
	EntityType string       `json:"entity_type"`
	EntityID   string       `json:"entity_id"`
	Role       ResourceRole `json:"role"`
	Scope      GrantScope   `json:"scope"`
}

// Validate reports why a grant is not usable, or nil when it is well formed.
// Grants are validated at every entry point (config load, API, CLI) rather than
// silently dropped: a mistyped role in an access-control rule must fail loudly,
// because the failure mode of ignoring it is a team that cannot reach its CA
// and an operator who widens something else to compensate.
func (g Grant) Validate() error {
	if !g.Resource.Valid() {
		return fmt.Errorf("invalid resource %q", g.Resource.String())
	}
	if !ValidEntityType(g.EntityType) {
		return fmt.Errorf("entity_type must be %q or %q, got %q", EntityUser, EntityGroup, g.EntityType)
	}
	if g.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}
	if !ValidResourceRole(g.Role) {
		return fmt.Errorf("unknown role %q (want one of %s)", g.Role, JoinResourceRoles(AllResourceRoles))
	}
	if !ResourceRoleAppliesTo(g.Role, g.Resource.Type) {
		return fmt.Errorf("role %q does not apply to resource type %q (valid roles: %s)",
			g.Role, g.Resource.Type, JoinResourceRoles(ResourceRolesFor(g.Resource.Type)))
	}
	if g.Scope != "" && !ValidGrantScope(g.Scope) {
		return fmt.Errorf("scope must be %q or %q, got %q", ScopeSelf, ScopeSubtree, g.Scope)
	}
	if g.Scope == ScopeSubtree && g.Resource.Type == ResourceSigningKey {
		return fmt.Errorf("scope %q is only meaningful on CA resources, not %q", ScopeSubtree, g.Resource.Type)
	}
	return nil
}

// Normalized returns the grant with defaults applied (an empty scope becomes
// ScopeSelf). Callers store the normalized form so a grant read back from any
// source compares equal to the one that was written.
func (g Grant) Normalized() Grant {
	if g.Scope == "" {
		g.Scope = ScopeSelf
	}
	return g
}

// Key is the natural identity of a grant: two grants with the same key are the
// same rule, whether they arrived from configuration or the database.
func (g Grant) Key() string {
	return strings.Join([]string{g.Resource.String(), g.EntityType, g.EntityID, string(g.Role)}, "|")
}

// Identity is the set of names a principal answers to when grants are matched.
// It is deliberately a value type built at decision time from the authenticated
// principal, so the evaluator holds no reference to request state.
type Identity struct {
	// Subject is the authenticated principal ID (OIDC sub, LDAP DN-derived
	// subject, token subject, mTLS binding subject).
	Subject string
	// Email is the principal's email address; it matches user grants only when
	// EmailVerified is true.
	Email         string
	EmailVerified bool
	// Groups is the union of the principal's internal (database) group IDs and
	// the groups asserted by the identity provider.
	Groups []string
}

// Matches reports whether a grant is bound to this identity.
func (id Identity) Matches(g Grant) bool {
	switch g.EntityType {
	case EntityUser:
		if g.EntityID == "" {
			return false
		}
		if id.Subject != "" && g.EntityID == id.Subject {
			return true
		}
		return id.EmailVerified && id.Email != "" && strings.EqualFold(g.EntityID, id.Email)
	case EntityGroup:
		for _, grp := range id.Groups {
			if grp == g.EntityID {
				return true
			}
		}
	}
	return false
}

// GrantSet is an immutable, indexed view over a collection of grants, safe for
// concurrent lookups. Build one per authorization decision from the union of the
// configured and stored grants that could possibly apply.
type GrantSet struct {
	byResource map[string][]Grant
}

// NewGrantSet indexes grants by resource. Invalid grants are dropped — every
// entry point validates before storing, so reaching here with a bad grant means
// a source was bypassed and the safe reading of an unparseable rule is "grants
// nothing".
func NewGrantSet(grants []Grant) *GrantSet {
	gs := &GrantSet{byResource: make(map[string][]Grant, len(grants))}
	for _, g := range grants {
		g = g.Normalized()
		if g.Validate() != nil {
			continue
		}
		k := g.Resource.String()
		gs.byResource[k] = append(gs.byResource[k], g)
	}
	return gs
}

// Empty reports whether the set carries no grants at all. Callers use it to skip
// the ancestry lookup that subtree evaluation would otherwise require.
func (gs *GrantSet) Empty() bool { return gs == nil || len(gs.byResource) == 0 }

// At returns the grants recorded directly on a resource.
func (gs *GrantSet) At(res Resource) []Grant {
	if gs == nil {
		return nil
	}
	return gs.byResource[res.String()]
}

// All returns every grant in the set, ordered by resource then entity then role
// so output is stable across runs.
func (gs *GrantSet) All() []Grant {
	if gs == nil {
		return nil
	}
	var out []Grant
	for _, gl := range gs.byResource {
		out = append(out, gl...)
	}
	SortGrants(out)
	return out
}

// RolesFor returns the resource roles the identity holds at res. Ancestors are
// the resource's parents ordered nearest-first; a grant recorded on an ancestor
// counts only when it was made with ScopeSubtree.
func (gs *GrantSet) RolesFor(res Resource, ancestors []Resource, id Identity) []ResourceRole {
	if gs == nil {
		return nil
	}
	seen := make(map[ResourceRole]bool)
	var out []ResourceRole
	collect := func(candidates []Grant, subtreeOnly bool) {
		for _, g := range candidates {
			if subtreeOnly && g.Scope != ScopeSubtree {
				continue
			}
			if !id.Matches(g) || seen[g.Role] {
				continue
			}
			seen[g.Role] = true
			out = append(out, g.Role)
		}
	}
	collect(gs.byResource[res.String()], false)
	for _, anc := range ancestors {
		collect(gs.byResource[anc.String()], true)
	}
	return out
}

// Allows reports whether the identity may perform action at res, considering
// grants on the resource itself and — for ScopeSubtree grants — on its
// ancestors (nearest-first). It is purely additive: a false result means "no
// grant says yes", never "a grant says no".
func (gs *GrantSet) Allows(res Resource, ancestors []Resource, id Identity, action Action) bool {
	if gs == nil {
		return false
	}
	for _, role := range gs.RolesFor(res, ancestors, id) {
		if ResourceRoleGrants(role, action) {
			return true
		}
	}
	return false
}

// ResourcesFor returns the resources of the given type on which the identity
// holds at least one grant recorded DIRECTLY (subtree reach is not expanded
// here, because that needs the hierarchy the caller owns). It lets a listing
// endpoint show a delegated operator the authorities it has been given without
// granting it tenant-wide visibility.
func (gs *GrantSet) ResourcesFor(t ResourceType, id Identity) []string {
	if gs == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, gl := range gs.byResource {
		for _, g := range gl {
			if g.Resource.Type != t || seen[g.Resource.ID] || !id.Matches(g) {
				continue
			}
			seen[g.Resource.ID] = true
			out = append(out, g.Resource.ID)
		}
	}
	sort.Strings(out)
	return out
}

// SortGrants orders grants deterministically for display and comparison.
func SortGrants(gs []Grant) {
	sort.Slice(gs, func(i, j int) bool {
		a, b := gs[i], gs[j]
		if a.Resource.Type != b.Resource.Type {
			return a.Resource.Type < b.Resource.Type
		}
		if a.Resource.ID != b.Resource.ID {
			return a.Resource.ID < b.Resource.ID
		}
		if a.EntityType != b.EntityType {
			return a.EntityType < b.EntityType
		}
		if a.EntityID != b.EntityID {
			return a.EntityID < b.EntityID
		}
		return a.Role < b.Role
	})
}

// JoinResourceRoles renders resource roles as a stable comma-separated string.
func JoinResourceRoles(roles []ResourceRole) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}
