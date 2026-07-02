package spiffe

import (
	"sort"
	"strings"
	"time"
)

// Policy is the trust-domain allowlist enforced before a SPIFFE X.509-SVID is
// minted. It answers "may this authenticated subject request an SVID in this
// trust domain?" and is layered on top of the RBAC issue capability (only
// admins/issuers reach an SVID request at all): RBAC decides who may issue,
// Policy constrains which trust domains they may issue into.
//
// A Policy is built once from configuration and is immutable thereafter, so it
// is safe for concurrent use.
type Policy struct {
	// global is the set of trust domains any authorized issuer may use.
	global map[string]bool
	// bySubject maps an authenticated subject (OIDC sub or verified email) to the
	// additional trust domains it may use beyond the global set.
	bySubject map[string]map[string]bool
	// refreshHint is advertised in the trust bundle so consumers know how often to
	// re-fetch it. Zero omits the hint.
	refreshHint time.Duration
	// defaultCAID is the CA used for SVID issuance and bundle serving when a
	// request does not name one. Empty means the request must name a CA.
	defaultCAID string
}

// PolicyConfig is the plain configuration a Policy is built from.
type PolicyConfig struct {
	// TrustDomains is the global allowlist. Empty means no trust domain is allowed
	// globally (each must be granted per subject) — a fail-closed default.
	TrustDomains []string
	// SubjectTrustDomains grants additional trust domains to specific subjects.
	SubjectTrustDomains map[string][]string
	// RefreshHint is advertised in the bundle (spiffe_refresh_hint).
	RefreshHint time.Duration
	// DefaultCAID is the CA used when a request omits one.
	DefaultCAID string
}

// NewPolicy builds an immutable Policy from configuration. Trust domains are
// canonicalized (lowercased, validated); invalid entries are dropped so a typo
// cannot silently widen access. It never returns nil.
func NewPolicy(cfg PolicyConfig) *Policy {
	p := &Policy{
		global:      make(map[string]bool),
		bySubject:   make(map[string]map[string]bool),
		refreshHint: cfg.RefreshHint,
		defaultCAID: cfg.DefaultCAID,
	}
	for _, td := range cfg.TrustDomains {
		if v, err := validateTrustDomain(td); err == nil {
			p.global[v] = true
		}
	}
	for subject, tds := range cfg.SubjectTrustDomains {
		set := make(map[string]bool)
		for _, td := range tds {
			if v, err := validateTrustDomain(td); err == nil {
				set[v] = true
			}
		}
		if len(set) > 0 {
			p.bySubject[subject] = set
		}
	}
	return p
}

// Allowed reports whether the given subject may request an SVID in trustDomain.
// The subject list may include several identifiers for the same principal (e.g.
// an OIDC subject and a verified email); the request is allowed if any of them,
// or the global allowlist, permits the trust domain. Trust-domain comparison is
// case-insensitive.
func (p *Policy) Allowed(subjects []string, trustDomain string) bool {
	if p == nil {
		return false
	}
	td := strings.ToLower(strings.TrimSpace(trustDomain))
	if p.global[td] {
		return true
	}
	for _, s := range subjects {
		if set := p.bySubject[s]; set != nil && set[td] {
			return true
		}
	}
	return false
}

// RefreshHint returns the configured bundle refresh hint (zero if unset).
func (p *Policy) RefreshHint() time.Duration {
	if p == nil {
		return 0
	}
	return p.refreshHint
}

// DefaultCAID returns the CA used when an SVID request omits one.
func (p *Policy) DefaultCAID() string {
	if p == nil {
		return ""
	}
	return p.defaultCAID
}

// AllowedTrustDomains returns the sorted global allowlist, for diagnostics and
// error messages.
func (p *Policy) AllowedTrustDomains() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.global))
	for td := range p.global {
		out = append(out, td)
	}
	sort.Strings(out)
	return out
}
