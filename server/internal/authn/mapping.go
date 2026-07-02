package authn

import (
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ClaimMapping maps a single IdP claim value to a set of RBAC roles, optionally
// scoped to a tenant. It is the configurable bridge between an identity
// provider's authorization model (groups, roles, entitlements carried as token
// claims) and this system's roles.
//
// Matching semantics: the named Claim is read from the verified token/userinfo
// claims. If the claim is a string it must equal Value; if it is a list of
// strings (the common shape for a "groups" claim) it must contain Value. On a
// match the mapping contributes Roles either platform-wide (Tenant empty) or
// within the named Tenant.
type ClaimMapping struct {
	// Claim is the claim name to inspect (e.g. "groups", "roles", "wids"). When
	// empty it defaults to the mapper's configured groups claim.
	Claim string
	// Value is the exact claim value that triggers this mapping.
	Value string
	// Tenant, when non-empty, scopes the granted roles to that tenant id. Empty
	// grants platform-wide (cross-tenant) roles — reserve these for platform
	// operators.
	Tenant string
	// Roles are the RBAC roles granted on a match. Unknown role names are dropped.
	Roles []rbac.Role
}

// ClaimMapper resolves RBAC roles from IdP token claims. It is immutable after
// construction and safe for concurrent use. A mapper is combined with the
// subject/email/group assignments in internal/rbac: the effective roles are the
// union of both, so an operator may be granted access by their OIDC subject, a
// verified email, an internal group, or an IdP group/role claim.
type ClaimMapper struct {
	// groupsClaim is the default claim inspected by mappings that do not name one,
	// and the claim whose values are exposed as "groups" for the rbac layer.
	groupsClaim string
	mappings    []ClaimMapping
}

// NewClaimMapper builds a mapper. groupsClaim names the token claim carrying the
// caller's group memberships (defaults to "groups"); it is used both as the
// default claim for value mappings and as the source of group ids handed to the
// rbac assignment layer. Mappings referencing unknown roles keep only their
// valid roles.
func NewClaimMapper(groupsClaim string, mappings []ClaimMapping) *ClaimMapper {
	if strings.TrimSpace(groupsClaim) == "" {
		groupsClaim = "groups"
	}
	cleaned := make([]ClaimMapping, 0, len(mappings))
	for _, m := range mappings {
		var valid []rbac.Role
		for _, r := range m.Roles {
			if rbac.ValidRole(r) {
				valid = append(valid, r)
			}
		}
		if len(valid) == 0 || strings.TrimSpace(m.Value) == "" {
			// A mapping that grants nothing, or matches nothing, is inert; drop it so
			// it cannot silently appear to authorize access.
			continue
		}
		claim := strings.TrimSpace(m.Claim)
		if claim == "" {
			claim = groupsClaim
		}
		cleaned = append(cleaned, ClaimMapping{
			Claim:  claim,
			Value:  m.Value,
			Tenant: strings.TrimSpace(m.Tenant),
			Roles:  valid,
		})
	}
	return &ClaimMapper{groupsClaim: groupsClaim, mappings: cleaned}
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

// Resolve maps token claims to platform-wide and per-tenant RBAC roles according
// to the configured mappings. The returned platform slice is deduplicated; the
// tenant map holds one deduplicated slice per tenant that received any role.
//
// Resolve considers ONLY the claim mappings. Callers union its output with the
// subject/email/group assignments from internal/rbac to obtain a principal's
// full role set.
func (m *ClaimMapper) Resolve(claims map[string]interface{}) (platform []rbac.Role, tenant map[string][]rbac.Role) {
	if m == nil || claims == nil {
		return nil, nil
	}
	platSeen := make(map[rbac.Role]bool)
	tenantSeen := make(map[string]map[rbac.Role]bool)
	for _, mp := range m.mappings {
		if !claimContains(claims[mp.Claim], mp.Value) {
			continue
		}
		if mp.Tenant == "" {
			for _, r := range mp.Roles {
				if !platSeen[r] {
					platSeen[r] = true
					platform = append(platform, r)
				}
			}
			continue
		}
		seen := tenantSeen[mp.Tenant]
		if seen == nil {
			seen = make(map[rbac.Role]bool)
			tenantSeen[mp.Tenant] = seen
		}
		for _, r := range mp.Roles {
			if !seen[r] {
				seen[r] = true
				if tenant == nil {
					tenant = make(map[string][]rbac.Role)
				}
				tenant[mp.Tenant] = append(tenant[mp.Tenant], r)
			}
		}
	}
	return platform, tenant
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
