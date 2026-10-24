package authn

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ClaimMapping maps an IdP claim to a set of RBAC roles, optionally scoped to a
// tenant. It is the configurable bridge between an identity provider's
// authorization model (groups, roles, entitlements carried as token claims) and
// this system's roles.
//
// A mapping matches in one of two ways, and never both:
//
//   - Exact claim value (Claim/Value). The named claim is read from the
//     verified token/userinfo claims. If it is a string it must equal Value; if
//     it is a list of strings (the common shape for a "groups" claim) it must
//     contain Value.
//   - CEL expression (Expression, Task 214). A boolean expression over the
//     whole identity — see internal/celexpr for the variables and functions
//     available. This is what an organization needs when its group names encode
//     structure (`pki-issuers-acme`, `CN=PKI-Admins-emea,OU=Groups,…`) instead
//     of enumerating one mapping per team.
//
// On a match the mapping contributes Roles either platform-wide (no tenant) or
// within a tenant: the literal Tenant, or every tenant id the TenantExpression
// yields — which is how one mapping serves a directory that encodes the tenant
// in the group name.
type ClaimMapping struct {
	// Claim is the claim name to inspect (e.g. "groups", "roles", "wids"). When
	// empty it defaults to the mapper's configured groups claim. Exact-match only.
	Claim string
	// Value is the exact claim value that triggers this mapping.
	Value string
	// Expression is a CEL boolean expression deciding whether this mapping
	// applies, used instead of Claim/Value. A false result or any evaluation
	// error contributes nothing.
	Expression string
	// Tenant, when non-empty, scopes the granted roles to that tenant id. Empty
	// (with no TenantExpression) grants platform-wide (cross-tenant) roles —
	// reserve these for platform operators.
	Tenant string
	// TenantExpression is a CEL expression yielding the tenant id, or a list of
	// tenant ids, the roles are granted in. Used instead of Tenant. An empty
	// result grants nothing — it is deliberately NOT read as platform-wide, so a
	// pattern that failed to extract a tenant cannot escalate out of its tenant.
	TenantExpression string
	// Roles are the RBAC roles granted on a match. Unknown role names are dropped.
	Roles []rbac.Role
}

// Describe renders the mapping as a single line, for diagnostics and help
// output. A long expression is normally written as a YAML block scalar, so the
// newlines in it are collapsed — a "single line" that wraps would corrupt every
// table and log line this appears in.
func (m ClaimMapping) Describe() string {
	var b strings.Builder
	if m.Expression != "" {
		fmt.Fprintf(&b, "expression=%s", collapseSpace(m.Expression))
	} else {
		claim := m.Claim
		if claim == "" {
			claim = "<groups claim>"
		}
		fmt.Fprintf(&b, "%s=%q", claim, m.Value)
	}
	switch {
	case m.TenantExpression != "":
		fmt.Fprintf(&b, " tenant_expression=%s", collapseSpace(m.TenantExpression))
	case m.Tenant != "":
		fmt.Fprintf(&b, " tenant=%s", m.Tenant)
	default:
		b.WriteString(" tenant=<platform-wide>")
	}
	roles := make([]string, 0, len(m.Roles))
	for _, r := range m.Roles {
		roles = append(roles, string(r))
	}
	fmt.Fprintf(&b, " roles=[%s]", strings.Join(roles, " "))
	return b.String()
}

// collapseSpace folds every run of whitespace into a single space.
func collapseSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// compiledMapping is a validated mapping with its expressions already planned.
// Compilation happens once, at construction, so a login never pays for parsing
// and a bad expression is a startup failure rather than a silent denial.
type compiledMapping struct {
	spec       ClaimMapping
	claim      string
	match      *celexpr.BoolProgram
	tenantExpr *celexpr.StringsProgram
}

// ClaimMapper resolves RBAC roles from an authenticated identity. It is
// immutable after construction and safe for concurrent use. A mapper is
// combined with the subject/email/group assignments in internal/rbac: the
// effective roles are the union of both, so an operator may be granted access
// by their OIDC subject, a verified email, an internal group, or an IdP
// group/role claim.
type ClaimMapper struct {
	// groupsClaim is the default claim inspected by mappings that do not name one,
	// and the claim whose values are exposed as "groups" for the rbac layer.
	groupsClaim  string
	mappings     []compiledMapping
	knownTenants map[string]bool
	onError      func(error)
}

// ClaimMapperOption configures a mapper at construction.
type ClaimMapperOption func(*ClaimMapper)

// WithKnownTenants restricts the tenant ids a TenantExpression may produce to
// the tenants the deployment actually declares. A derived id outside the set
// grants nothing, which turns the typo an expression cannot be type-checked for
// ("ACME" where the tenant is "acme") into a visible no-grant rather than a
// role assignment in a tenant that does not exist — and that would start
// granting the day someone creates it. An empty or omitted set applies no such
// restriction (a deployment with no `tenants:` block has nothing to check
// against); the syntactic check in validDerivedTenantID always applies.
func WithKnownTenants(ids []string) ClaimMapperOption {
	return func(m *ClaimMapper) {
		if len(ids) == 0 {
			return
		}
		known := make(map[string]bool, len(ids))
		for _, id := range ids {
			if id = strings.TrimSpace(id); id != "" {
				known[id] = true
			}
		}
		m.knownTenants = known
	}
}

// WithExpressionErrorHandler installs a hook called with every expression
// evaluation error. Such an error is always fail-closed — the mapping grants
// nothing — but it is also the only sign that an expression is broken rather
// than simply not matching, so the server logs it. The hook must not block.
func WithExpressionErrorHandler(fn func(error)) ClaimMapperOption {
	return func(m *ClaimMapper) { m.onError = fn }
}

// NewClaimMapper builds a mapper. groupsClaim names the token claim carrying
// the caller's group memberships (defaults to "groups"); it is used both as the
// default claim for value mappings and as the source of group ids handed to the
// rbac assignment layer.
//
// Mappings referencing unknown roles keep only their valid roles, and a mapping
// left with no role (or with nothing to match on) is dropped: an inert mapping
// must not look like it authorizes something. A mapping whose expression does
// not compile, or that is internally contradictory (both an exact value and an
// expression, both a literal tenant and a tenant expression), is an error —
// those are configuration mistakes with exactly one safe resolution, which is
// to refuse to start.
func NewClaimMapper(groupsClaim string, mappings []ClaimMapping, opts ...ClaimMapperOption) (*ClaimMapper, error) {
	if strings.TrimSpace(groupsClaim) == "" {
		groupsClaim = "groups"
	}
	m := &ClaimMapper{groupsClaim: groupsClaim}
	for _, o := range opts {
		o(m)
	}
	for i, spec := range mappings {
		cm, keep, err := compileMapping(spec, groupsClaim)
		if err != nil {
			return nil, fmt.Errorf("role_mappings[%d]: %w", i, err)
		}
		if !keep {
			continue
		}
		m.mappings = append(m.mappings, cm)
	}
	return m, nil
}

// compileMapping validates one mapping and plans its expressions. keep is false
// for a mapping that is inert (nothing to match, or nothing to grant).
func compileMapping(spec ClaimMapping, groupsClaim string) (cm compiledMapping, keep bool, err error) {
	spec.Claim = strings.TrimSpace(spec.Claim)
	spec.Expression = strings.TrimSpace(spec.Expression)
	spec.Tenant = strings.TrimSpace(spec.Tenant)
	spec.TenantExpression = strings.TrimSpace(spec.TenantExpression)

	var valid []rbac.Role
	for _, r := range spec.Roles {
		if rbac.ValidRole(r) {
			valid = append(valid, r)
		}
	}
	spec.Roles = valid

	switch {
	case spec.Expression != "" && spec.Value != "":
		return cm, false, fmt.Errorf("value and expression are mutually exclusive")
	case spec.Expression != "" && spec.Claim != "":
		return cm, false, fmt.Errorf("claim applies to an exact-value mapping and cannot be combined with expression")
	case spec.Tenant != "" && spec.TenantExpression != "":
		return cm, false, fmt.Errorf("tenant and tenant_expression are mutually exclusive")
	}
	if len(spec.Roles) == 0 || (spec.Value == "" && spec.Expression == "") {
		// A mapping that grants nothing, or matches nothing, is inert; drop it so
		// it cannot silently appear to authorize access.
		return cm, false, nil
	}

	cm = compiledMapping{spec: spec, claim: spec.Claim}
	if cm.claim == "" {
		cm.claim = groupsClaim
	}
	if spec.Expression != "" {
		if cm.match, err = celexpr.CompileRoleMappingMatch(spec.Expression); err != nil {
			return cm, false, err
		}
	}
	if spec.TenantExpression != "" {
		if cm.tenantExpr, err = celexpr.CompileRoleMappingTenant(spec.TenantExpression); err != nil {
			return cm, false, err
		}
	}
	return cm, true, nil
}

// GroupsClaim returns the configured groups claim name.
func (m *ClaimMapper) GroupsClaim() string {
	if m == nil {
		return "groups"
	}
	return m.groupsClaim
}

// Groups extracts the caller's group memberships from the claims, reading the
// configured groups claim as either a single string or a list of strings. The
// result feeds the rbac group-assignment lookup.
func (m *ClaimMapper) Groups(claims map[string]interface{}) []string {
	if m == nil || claims == nil {
		return nil
	}
	return claimValues(claims[m.groupsClaim])
}

// Identity is the authenticated identity a mapping is evaluated against: the
// verified claim set plus the fields every authentication source resolves,
// however it names them. Exact-value mappings read only Claims; expressions see
// all of it.
type Identity struct {
	// Subject is the stable principal id (OIDC "sub", or the directory subject).
	Subject string
	// Email is the principal's address, as asserted by the IdP or directory.
	Email string
	// EmailVerified reports whether the IdP vouched for that address. A
	// directory-sourced address is authoritative within the organization and is
	// presented as verified.
	EmailVerified bool
	// Name is the display name.
	Name string
	// Username is the directory username or "preferred_username" claim.
	Username string
	// Issuer is the token issuer, empty for a directory login.
	Issuer string
	// Provider is the configured name of the provider that authenticated this
	// principal.
	Provider string
	// Groups are the resolved group memberships — the groups claim, the
	// directory groups, and the internal groups the store records — as the caller
	// assembled them. Empty means "derive from Claims".
	Groups []string
	// Claims is the verified claim set.
	Claims map[string]interface{}
}

// IdentityFromClaims derives an identity from a claim set alone, reading the
// standard OIDC claim names and the mapper's configured groups claim. It is
// what lets a caller holding nothing but claims evaluate the same expressions
// as the login path.
func (m *ClaimMapper) IdentityFromClaims(claims map[string]interface{}) Identity {
	verified, _ := claims["email_verified"].(bool)
	id := Identity{
		Subject:       claimString(claims, "sub"),
		Email:         claimString(claims, "email"),
		EmailVerified: verified,
		Name:          claimString(claims, "name"),
		Username:      claimString(claims, "preferred_username"),
		Issuer:        claimString(claims, "iss"),
		Claims:        claims,
	}
	id.Groups = m.Groups(claims)
	return id
}

// MappingDecision is one mapping's outcome against an identity, as reported by
// Explain. It exists so the dry-run tooling (`secsy-ca role-mapping test`) and
// the login path are not two implementations of the same rules: Resolve is
// written in terms of Explain.
type MappingDecision struct {
	// Index is the mapping's position in the configured list (after inert
	// mappings were dropped).
	Index int
	// Mapping is the mapping as configured.
	Mapping ClaimMapping
	// Fired reports whether the match half applied — the claim value was
	// present, or the expression returned true. It is deliberately separate from
	// Matched: a mapping can fire and still grant nothing (its tenant expression
	// resolved to no usable tenant), and "your pattern matched but the tenant did
	// not" is a different problem from "your pattern did not match".
	Fired bool
	// Matched reports whether the mapping actually granted anything.
	Matched bool
	// Tenants lists the tenant ids the roles were granted in. Empty with
	// Matched true means platform-wide.
	Tenants []string
	// Rejected lists tenant ids an expression produced that were refused — not a
	// known tenant, or not a usable id. They granted nothing.
	Rejected []string
	// Err is the evaluation error, if any. A mapping with an error never grants.
	Err error
}

// Explain evaluates every mapping against an identity and reports what each one
// decided, including the errors Resolve swallows. Used by the dry-run CLI.
func (m *ClaimMapper) Explain(id Identity) []MappingDecision {
	if m == nil {
		return nil
	}
	out := make([]MappingDecision, 0, len(m.mappings))
	activation := m.activation(id)
	for i, mp := range m.mappings {
		d := MappingDecision{Index: i, Mapping: mp.spec}
		matched, err := mp.matches(id, activation)
		if err != nil {
			d.Err = err
			out = append(out, d)
			continue
		}
		if !matched {
			out = append(out, d)
			continue
		}
		d.Fired = true
		d.Matched = true
		if mp.tenantExpr == nil {
			if mp.spec.Tenant != "" {
				d.Tenants = []string{mp.spec.Tenant}
			}
			out = append(out, d)
			continue
		}
		ids, err := mp.tenantExpr.Eval(activation)
		if err != nil {
			// A tenant expression that failed is not a platform-wide grant: the
			// mapping contributes nothing at all.
			d.Matched = false
			d.Err = err
			out = append(out, d)
			continue
		}
		for _, tid := range ids {
			if m.tenantAllowed(tid) {
				d.Tenants = append(d.Tenants, tid)
			} else {
				d.Rejected = append(d.Rejected, tid)
			}
		}
		if len(d.Tenants) == 0 {
			// Matched, but resolved to no usable tenant. Report the match (so the
			// dry-run shows the pattern fired) while granting nothing.
			d.Matched = false
		}
		out = append(out, d)
	}
	return out
}

// matches reports whether the mapping applies: either the exact claim value is
// present, or the compiled expression evaluates to true.
func (mp compiledMapping) matches(id Identity, activation map[string]interface{}) (bool, error) {
	if mp.match != nil {
		return mp.match.Eval(activation)
	}
	return claimContains(id.Claims[mp.claim], mp.spec.Value), nil
}

// Activation renders the identity exactly as an expression of this mapper sees
// it, including the group list derived from this mapper's configured claim when
// the caller resolved none. Exported for the dry-run tooling: a dry-run that
// displayed different inputs than it evaluated would be worse than no dry-run.
func (m *ClaimMapper) Activation(id Identity) map[string]interface{} {
	if m == nil {
		return celexpr.RoleMappingInput{}.Activation()
	}
	return m.activation(id)
}

// activation renders the identity for expression evaluation, filling in the
// group list from the claims when the caller did not resolve one.
func (m *ClaimMapper) activation(id Identity) map[string]interface{} {
	groups := id.Groups
	if len(groups) == 0 {
		groups = m.Groups(id.Claims)
	}
	return celexpr.RoleMappingInput{
		Subject:       id.Subject,
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Name:          id.Name,
		Username:      id.Username,
		Issuer:        id.Issuer,
		Provider:      id.Provider,
		Groups:        groups,
		Claims:        id.Claims,
	}.Activation()
}

// derivedTenantPattern constrains a tenant id produced by an expression. A
// literal tenant in the configuration file was written by an operator and gets
// no such check; a derived one is a function of claim values the IdP (and
// sometimes the user) controls, so it must look like an identifier before it is
// allowed to key a role grant, a log line, and an audit record.
var derivedTenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$`)

// validDerivedTenantID reports whether id is syntactically usable as a tenant id.
func validDerivedTenantID(id string) bool { return derivedTenantPattern.MatchString(id) }

// tenantAllowed reports whether a derived tenant id may be granted in.
func (m *ClaimMapper) tenantAllowed(id string) bool {
	if !validDerivedTenantID(id) {
		return false
	}
	if len(m.knownTenants) == 0 {
		return true
	}
	return m.knownTenants[id]
}

// Resolve maps token claims to platform-wide and per-tenant RBAC roles
// according to the configured mappings, deriving the identity fields from the
// claims themselves (see IdentityFromClaims).
//
// Resolve considers ONLY the claim mappings. Callers union its output with the
// subject/email/group assignments from internal/rbac to obtain a principal's
// full role set.
func (m *ClaimMapper) Resolve(claims map[string]interface{}) (platform []rbac.Role, tenant map[string][]rbac.Role) {
	if m == nil || claims == nil {
		return nil, nil
	}
	return m.ResolveIdentity(m.IdentityFromClaims(claims))
}

// ResolveIdentity maps an authenticated identity to platform-wide and
// per-tenant RBAC roles. The returned platform slice is deduplicated; the
// tenant map holds one deduplicated slice per tenant that received any role.
//
// Every expression failure is fail-closed: the mapping grants nothing, and the
// error goes to the configured error handler rather than to the caller, because
// one broken mapping must not deny a login the other mappings authorize.
func (m *ClaimMapper) ResolveIdentity(id Identity) (platform []rbac.Role, tenant map[string][]rbac.Role) {
	if m == nil {
		return nil, nil
	}
	platSeen := make(map[rbac.Role]bool)
	tenantSeen := make(map[string]map[rbac.Role]bool)
	for _, d := range m.Explain(id) {
		if d.Err != nil && m.onError != nil {
			m.onError(fmt.Errorf("role mapping (%s): %w", d.Mapping.Describe(), d.Err))
		}
		if !d.Matched {
			continue
		}
		if len(d.Tenants) == 0 {
			for _, r := range d.Mapping.Roles {
				if !platSeen[r] {
					platSeen[r] = true
					platform = append(platform, r)
				}
			}
			continue
		}
		for _, tid := range d.Tenants {
			seen := tenantSeen[tid]
			if seen == nil {
				seen = make(map[rbac.Role]bool)
				tenantSeen[tid] = seen
			}
			for _, r := range d.Mapping.Roles {
				if !seen[r] {
					seen[r] = true
					if tenant == nil {
						tenant = make(map[string][]rbac.Role)
					}
					tenant[tid] = append(tenant[tid], r)
				}
			}
		}
	}
	return platform, tenant
}

// Mappings returns the mappings the mapper kept, as configured. Inert mappings
// (no role, nothing to match) are not included — they were dropped at
// construction.
func (m *ClaimMapper) Mappings() []ClaimMapping {
	if m == nil {
		return nil
	}
	out := make([]ClaimMapping, 0, len(m.mappings))
	for _, mp := range m.mappings {
		out = append(out, mp.spec)
	}
	return out
}

// claimContains reports whether the raw claim value (a string, a []string, or a
// []interface{} of strings, as produced by JSON decoding) contains want.
func claimContains(raw interface{}, want string) bool {
	for _, v := range claimValues(raw) {
		if v == want {
			return true
		}
	}
	return false
}

// claimString reads a claim expected to hold a single string, returning "" for
// an absent claim or any other shape.
func claimString(claims map[string]interface{}, name string) string {
	if claims == nil {
		return ""
	}
	s, _ := claims[name].(string)
	return s
}

// claimValues normalizes a claim into a slice of string values, tolerating the
// several shapes a JSON claim may decode to: a bare string, a []string, or a
// []interface{} whose elements are strings.
func claimValues(raw interface{}) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
