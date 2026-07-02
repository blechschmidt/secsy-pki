// Package caa implements DNS Certification Authority Authorization (CAA)
// checking per RFC 8659 (and the issue/issuewild/iodef property tags of RFC
// 8657) as a pre-issuance gate. Given the DNS names a certificate would cover,
// it resolves and evaluates the relevant CAA RRset — walking the domain tree
// and following CNAME/DNAME aliases — and decides whether a CA identified by a
// configured domain identifier is authorized to issue.
//
// The evaluation logic is deliberately transport-agnostic: it operates through
// the Resolver interface, so the same code runs against a real recursive DNS
// resolver in production and an injected fake in tests. The concrete
// system/network resolver lives in resolver.go; a TTL cache wraps it in
// cache.go.
//
// A Policy maps a whole check to an enforcement Mode: under ModeEnforce a
// forbidding CAA set (or a lookup failure) blocks issuance (fail-closed); under
// ModePermissive the same is reported but never blocks; ModeOff disables the
// gate. Policies are configured per issuance profile.
package caa

import (
	"context"
	"strings"
	"time"
)

// Mode is the enforcement mode of a CAA check.
type Mode string

const (
	// ModeEnforce blocks issuance when the relevant CAA set forbids this CA, or
	// when the lookup fails and authorization cannot be established (fail-closed).
	ModeEnforce Mode = "enforce"
	// ModePermissive evaluates and reports CAA but never blocks issuance. Useful
	// for staging a policy or for an internal PKI that wants visibility only.
	ModePermissive Mode = "permissive"
	// ModeOff disables CAA checking for the profile entirely.
	ModeOff Mode = "off"
)

// Property tag names defined by RFC 8659 §4.
const (
	TagIssue     = "issue"
	TagIssueWild = "issuewild"
	TagIodef     = "iodef"
)

// criticalFlag is the "Issuer Critical" bit (RFC 8659 §4.1). A record carrying
// it with a property tag the CA does not recognize forbids issuance.
const criticalFlag = 0x80

// maxClimb bounds the tree-climbing / alias-chasing loop so a malicious or
// misconfigured CNAME cycle cannot hang issuance.
const maxClimb = 40

// Record is a single CAA resource record (RFC 8659 §4.1): an 8-bit flags field,
// a property tag, and its value.
type Record struct {
	Flag  uint8
	Tag   string
	Value string
}

// Resolver resolves the DNS data the tree-climbing algorithm needs. It is the
// single seam between the pure evaluation logic and the network, so tests can
// inject a deterministic fake.
type Resolver interface {
	// LookupCAA returns the CAA RRset published at exactly name (no tree
	// climbing). A recursive resolver transparently follows a CNAME/DNAME at the
	// owner, so records for an aliased name are returned here. An empty slice with
	// a nil error means NODATA/NXDOMAIN (no CAA at that name); a non-nil error
	// signals a transient failure (SERVFAIL, timeout, network) that leaves
	// authorization undetermined.
	LookupCAA(ctx context.Context, name string) ([]Record, error)
	// LookupCNAME returns the canonical target when name is itself an alias, or
	// "" when it is not. It is consulted only when a name has no CAA records, to
	// climb the target's tree rather than the alias's (RFC 8659 §3).
	LookupCNAME(ctx context.Context, name string) (string, error)
}

// Policy configures a CAA check. It is derived from an issuance profile.
type Policy struct {
	// Mode selects enforcement (see the Mode constants). The zero value is
	// ModeEnforce so an unset policy fails closed.
	Mode Mode
	// Identifier is this CA's own CAA domain identifier — the value a domain owner
	// publishes in an `issue "ca.example.com"` record to authorize it (RFC 8659
	// §4.2). Matching is a case-insensitive exact comparison. Enforcement without
	// an identifier authorizes nothing, so callers must set it before enforcing.
	Identifier string
	// Timeout bounds a single evaluation across all its DNS lookups. Zero leaves
	// bounding to the caller's context.
	Timeout time.Duration
}

// Enabled reports whether the policy performs any checking at all.
func (p Policy) Enabled() bool { return p.Mode != ModeOff }

// enforcing reports whether findings block issuance under this policy.
func (p Policy) enforcing() bool { return p.Mode == ModeEnforce }

// Reason classifies why a DNS name failed its CAA check.
type Reason string

const (
	// ReasonForbidden: a relevant CAA set exists and authorizes some CA, but not
	// this one.
	ReasonForbidden Reason = "forbidden"
	// ReasonCriticalUnknown: a critical-flagged record carries a property tag the
	// CA does not understand (RFC 8659 §4.1), which forbids issuance.
	ReasonCriticalUnknown Reason = "critical_unknown"
	// ReasonLookupError: the CAA lookup failed, so authorization could not be
	// established. Blocks only under ModeEnforce.
	ReasonLookupError Reason = "lookup_error"
)

// Finding records one DNS name that does not permit issuance by this CA.
type Finding struct {
	Name   string `json:"name"`
	Reason Reason `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Result is the outcome of evaluating a certificate's DNS names.
type Result struct {
	// Checked lists the DNS names that were evaluated (wildcards normalized).
	Checked []string `json:"checked,omitempty"`
	// Findings lists every name that forbids or could not establish authorization.
	Findings []Finding `json:"findings,omitempty"`
	// Iodef collects the incident-reporting endpoints (mailto:/https:) discovered
	// in the relevant CAA sets, so an operator can honor RFC 8659 §4.4 reporting.
	Iodef []string `json:"iodef,omitempty"`
}

// OK reports whether every checked name permits issuance.
func (r Result) OK() bool { return len(r.Findings) == 0 }

// Forbidden is a synonym for !OK used at the gate for readability.
func (r Result) Forbidden() bool { return len(r.Findings) > 0 }

// Summary renders a compact, audit-friendly one-line description.
func (r Result) Summary() string {
	if r.OK() {
		if len(r.Checked) == 0 {
			return "caa=skip"
		}
		return "caa=ok names=" + itoa(len(r.Checked))
	}
	var names []string
	for _, f := range r.Findings {
		names = append(names, f.Name+"("+string(f.Reason)+")")
	}
	return "caa=forbidden names=" + itoa(len(r.Checked)) + " blocked=[" + strings.Join(names, " ") + "]"
}

// Check evaluates the CAA policy over the given DNS names. Names that are not
// DNS host names (empty) are ignored; IP-only certificates therefore yield an
// empty (OK) result and the caller should record a skip. Check never blocks on
// its own — it reports findings — leaving the block/allow decision to the mode.
func (p Policy) Check(ctx context.Context, r Resolver, names []string) Result {
	var res Result
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}

	seenIodef := map[string]bool{}
	seenName := map[string]bool{}
	for _, raw := range names {
		name, wildcard := normalizeName(raw)
		if name == "" {
			continue
		}
		key := name
		if wildcard {
			key = "*." + name
		}
		if seenName[key] {
			continue
		}
		seenName[key] = true
		res.Checked = append(res.Checked, key)

		set, err := relevantCAASet(ctx, r, name)
		if err != nil {
			res.Findings = append(res.Findings, Finding{
				Name:   key,
				Reason: ReasonLookupError,
				Detail: err.Error(),
			})
			continue
		}
		for _, io := range collectIodef(set) {
			if !seenIodef[io] {
				seenIodef[io] = true
				res.Iodef = append(res.Iodef, io)
			}
		}
		if f, ok := evaluateSet(set, wildcard, p.Identifier); !ok {
			f.Name = key
			res.Findings = append(res.Findings, f)
		}
	}
	return res
}

// relevantCAASet implements RFC 8659 §3: starting at name, return the CAA RRset
// of the closest ancestor that publishes one, following a CNAME/DNAME alias to
// its target's tree when an intermediate name has no CAA records. An empty
// result with nil error means no CAA policy governs the name (issuance allowed).
func relevantCAASet(ctx context.Context, r Resolver, name string) ([]Record, error) {
	domain := name
	visited := map[string]bool{}
	for i := 0; domain != "" && i < maxClimb; i++ {
		set, err := r.LookupCAA(ctx, domain)
		if err != nil {
			return nil, err
		}
		if len(set) > 0 {
			return set, nil
		}
		// No CAA here. If this owner is itself an alias, restart the search at the
		// canonical target's tree (RFC 8659 §3), guarding against alias cycles.
		if !visited[domain] {
			visited[domain] = true
			if target, err := r.LookupCNAME(ctx, domain); err != nil {
				return nil, err
			} else if t, _ := normalizeName(target); t != "" && t != domain && !visited[t] {
				domain = t
				continue
			}
		}
		domain = parentDomain(domain)
	}
	return nil, nil
}

// evaluateSet decides whether the CA (identified by identifier) may issue for a
// name governed by the given CAA set. wildcard selects issuewild semantics. It
// returns ok=true when issuance is permitted; otherwise ok=false with a Finding.
func evaluateSet(set []Record, wildcard bool, identifier string) (Finding, bool) {
	if len(set) == 0 {
		return Finding{}, true // no governing CAA policy → permitted
	}

	// A critical-flagged record with an unrecognized tag forbids issuance.
	for _, rec := range set {
		if rec.Flag&criticalFlag != 0 && !knownTag(rec.Tag) {
			return Finding{Reason: ReasonCriticalUnknown, Detail: "critical tag " + rec.Tag}, false
		}
	}

	// Select the applicable property records. issuewild governs wildcard requests
	// and takes precedence, but falls back to issue when no issuewild is present.
	var issue, issuewild []Record
	for _, rec := range set {
		switch strings.ToLower(rec.Tag) {
		case TagIssue:
			issue = append(issue, rec)
		case TagIssueWild:
			issuewild = append(issuewild, rec)
		}
	}
	relevant := issue
	if wildcard && len(issuewild) > 0 {
		relevant = issuewild
	}
	if len(relevant) == 0 {
		// The set governs the name but carries no applicable issue/issuewild
		// property (e.g. only iodef, or only issuewild for a non-wildcard request):
		// the relevant property type is unrestricted → permitted.
		return Finding{}, true
	}

	for _, rec := range relevant {
		issuer, _ := parseIssueValue(rec.Value)
		if issuer == "" {
			continue // authorizes no CA (e.g. `issue ";"`)
		}
		if domainEqual(issuer, identifier) {
			return Finding{}, true
		}
	}
	return Finding{Reason: ReasonForbidden, Detail: "no issue property authorizes " + quoteIdent(identifier)}, false
}

// parseIssueValue splits an issue/issuewild value into the issuer domain and the
// raw parameter list (RFC 8659 §4.2): `ca.example.com; account=123`. The issuer
// domain is the first semicolon-delimited field; an empty field authorizes no
// CA. Parameters are returned unparsed for the caller to inspect if desired.
func parseIssueValue(value string) (issuer, params string) {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, ';'); i >= 0 {
		return strings.TrimSpace(value[:i]), strings.TrimSpace(value[i+1:])
	}
	return value, ""
}

// collectIodef returns the reporting endpoints from iodef records in the set.
func collectIodef(set []Record) []string {
	var out []string
	for _, rec := range set {
		if strings.EqualFold(rec.Tag, TagIodef) {
			if v := strings.TrimSpace(rec.Value); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func knownTag(tag string) bool {
	switch strings.ToLower(tag) {
	case TagIssue, TagIssueWild, TagIodef:
		return true
	}
	return false
}

// normalizeName lowercases a DNS name, strips a trailing dot, and reports (and
// removes) a leading "*." wildcard label. An empty or malformed name yields "".
func normalizeName(name string) (string, bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	wildcard := false
	if strings.HasPrefix(name, "*.") {
		wildcard = true
		name = name[2:]
	}
	if name == "" || strings.Contains(name, "*") {
		return "", wildcard // reject remaining wildcards / empty
	}
	return name, wildcard
}

// parentDomain returns the name with its left-most label removed, or "" once the
// top-level label is reached (the search climbs to, but not past, the root).
func parentDomain(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// domainEqual compares two DNS names for the exact, case-insensitive match RFC
// 8659 uses between an issue property's issuer domain and the CA identifier.
func domainEqual(a, b string) bool {
	if b == "" {
		return false
	}
	a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
	b = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b)), ".")
	return a == b
}

func quoteIdent(s string) string {
	if s == "" {
		return "<unset>"
	}
	return `"` + s + `"`
}

// itoa is a tiny dependency-free integer formatter for Summary().
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
