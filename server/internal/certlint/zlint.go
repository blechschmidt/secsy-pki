package certlint

import (
	"fmt"
	"sort"
	"strings"
)

// zlint status labels, as emitted by the backend. Only the reportable statuses
// — notice, warn, error, and fatal — cross the build-tag boundary; a lint that
// is not-applicable, not-effective, or passing is dropped in the backend.
const (
	zlintStatusNotice = "notice"
	zlintStatusWarn   = "warn"
	zlintStatusError  = "error"
	zlintStatusFatal  = "fatal"
)

// ZLintCodePrefix namespaces every zlint finding's Code so it is distinguishable
// from a hand-rolled check in audit detail, metrics labels, and per-check
// overrides (e.g. "zlint/e_serial_number_not_positive").
const ZLintCodePrefix = "zlint/"

// modeIgnore is a per-level / per-lint disposition (config value "ignore") that
// drops a zlint finding entirely rather than surfacing it. It is an internal
// mapping outcome and is never stored on a Finding.
const modeIgnore Mode = "ignore"

// ZLintPolicy configures the optional github.com/zmap/zlint industry-standard
// lint backend for a profile. The backend supplements — never replaces — the
// hand-rolled Baseline Requirements checks, and is only effective in a binary
// built with the "zlint" build tag (see ZLintAvailable). Each zlint severity
// level is mapped to this package's enforce / warn / ignore disposition so its
// findings fold into the same fail-closed gate as the hand-rolled checks.
type ZLintPolicy struct {
	// ErrorMode maps zlint "error" and "fatal" results. Empty defaults to
	// ModeEnforce, so a failing error-level lint blocks issuance.
	ErrorMode Mode
	// WarnMode maps zlint "warn" results. Empty defaults to ModeWarn.
	WarnMode Mode
	// NoticeMode maps zlint "notice" results. Empty defaults to "ignore"
	// (notices are informational and, by default, neither block nor warn).
	NoticeMode Mode
	// IncludeSources / ExcludeSources restrict the lint registry by source (e.g.
	// "CABF_BR", "RFC5280", "CABF_SMIME_BR", "Mozilla"). An empty IncludeSources
	// runs every source; ExcludeSources is applied afterwards.
	IncludeSources []string
	ExcludeSources []string
	// IncludeNames / ExcludeNames restrict the registry to / from individual lint
	// names (e.g. "e_dnsname_not_valid_tld").
	IncludeNames []string
	ExcludeNames []string
	// Overrides sets the disposition ("enforce"|"warn"|"ignore") for an
	// individual lint by name, overriding the level mapping.
	Overrides map[string]Mode
}

// ZLintAvailable reports whether the zlint backend was compiled into this binary
// (via the "zlint" build tag). When false, a profile that enables zlint still
// runs the hand-rolled checks; the zlint findings are simply unavailable.
func ZLintAvailable() bool { return zlintCompiledIn }

// filter converts the policy's source/name selectors into the build-boundary
// filter struct.
func (p ZLintPolicy) filter() zlintFilter {
	return zlintFilter{
		IncludeSources: p.IncludeSources,
		ExcludeSources: p.ExcludeSources,
		IncludeNames:   p.IncludeNames,
		ExcludeNames:   p.ExcludeNames,
	}
}

// dispositionFor resolves a zlint result (by lint name and status) to an
// enforcement Mode, or modeIgnore to drop it. A per-lint Override wins over the
// level mapping.
func (p ZLintPolicy) dispositionFor(name, status string) Mode {
	def := p.levelDefault(status)
	if p.Overrides != nil {
		if m, ok := p.Overrides[name]; ok {
			return normalizeMode(m, def)
		}
	}
	return def
}

// levelDefault maps a zlint status to the policy's configured disposition for
// that severity level.
func (p ZLintPolicy) levelDefault(status string) Mode {
	switch status {
	case zlintStatusError, zlintStatusFatal:
		return normalizeMode(p.ErrorMode, ModeEnforce)
	case zlintStatusWarn:
		return normalizeMode(p.WarnMode, ModeWarn)
	case zlintStatusNotice:
		return normalizeMode(p.NoticeMode, modeIgnore)
	default:
		return modeIgnore
	}
}

// normalizeMode canonicalizes a configured mode string, falling back to def when
// empty or unrecognized.
func normalizeMode(m Mode, def Mode) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case ModeEnforce:
		return ModeEnforce
	case ModeWarn:
		return ModeWarn
	case modeIgnore:
		return modeIgnore
	default:
		return def
	}
}

// zlintFilter selects which lints run. It mirrors zlint's FilterOptions but is
// defined here so the mapping logic (and its tests) compile without the backend.
type zlintFilter struct {
	IncludeSources []string
	ExcludeSources []string
	IncludeNames   []string
	ExcludeNames   []string
}

// zlintRaw is one reportable zlint result, decoupled from the zlint package
// types so it crosses the build-tag boundary.
type zlintRaw struct {
	Name     string
	Status   string
	Details  string
	Citation string
	Source   string
}

// ZLintFindings runs the zlint backend against a DER-encoded certificate and
// maps each reportable result to a Finding using the policy's level mapping.
// Results mapped to "ignore" are dropped and the remainder are returned sorted
// by code for deterministic audit/metric output. It returns nil when the backend
// is not compiled in, so callers need not special-case availability.
func ZLintFindings(der []byte, pol ZLintPolicy) []Finding {
	raws, err := runZLint(der, pol.filter())
	if err != nil {
		// A backend/parse failure surfaces as a single enforce-mode finding rather
		// than being silently dropped: a certificate we cannot lint with the
		// requested backend must not sail through a fail-closed gate.
		return []Finding{{
			Code:        ZLintCodePrefix + "backend_error",
			Mode:        ModeEnforce,
			Description: fmt.Sprintf("zlint backend error: %v", err),
		}}
	}
	out := make([]Finding, 0, len(raws))
	for _, r := range raws {
		mode := pol.dispositionFor(r.Name, r.Status)
		if mode == modeIgnore {
			continue
		}
		out = append(out, Finding{
			Code:        ZLintCodePrefix + r.Name,
			Mode:        mode,
			Description: zlintDescription(r),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// zlintDescription renders a compact, audit-friendly description from a raw
// result: the zlint status, source, citation, and any per-result detail.
func zlintDescription(r zlintRaw) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(r.Status))
	if r.Source != "" {
		b.WriteString(" ")
		b.WriteString(r.Source)
	}
	if r.Citation != "" {
		b.WriteString(" (")
		b.WriteString(r.Citation)
		b.WriteString(")")
	}
	if r.Details != "" {
		b.WriteString(": ")
		b.WriteString(r.Details)
	}
	return b.String()
}
