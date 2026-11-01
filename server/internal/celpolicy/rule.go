package celpolicy

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
)

// Effect says how a rule's boolean result is read.
type Effect string

const (
	// EffectRequire is the default: the expression states a condition that must
	// hold. A false result denies the request. It is the safe default because an
	// operator who writes a condition and forgets the effect gets the reading
	// that denies on failure rather than the one that permits on success.
	EffectRequire Effect = "require"
	// EffectDeny inverts that: the expression states a condition that must NOT
	// hold, so a true result denies the request. It is how a blocklist reads
	// naturally — `request.dns_names.exists(d, d.endsWith(".internal"))` — without
	// a negation wrapped around every rule.
	EffectDeny Effect = "deny"
)

// Mode says whether a rule is enforced or merely observed.
type Mode string

const (
	// ModeEnforce rejects the issuance when the rule denies. It is the default.
	ModeEnforce Mode = "enforce"
	// ModeMonitor records the denial — in the decision, the audit event and the
	// metrics — and lets the issuance proceed. It exists so a new rule can be
	// measured against real traffic before it starts refusing certificates,
	// which is the difference between a policy an enterprise can adopt and one
	// it dare not switch on.
	ModeMonitor Mode = "monitor"
)

// Rule is one operator-written restriction.
//
// # The expression and what its result means
//
// Expression is CEL over the variables in Vars. Its result may be:
//
//   - bool — the rule states a condition. Under EffectRequire a false result
//     denies; under EffectDeny a true result denies. The reason given to the
//     requester is Message, or a generated sentence naming the rule when
//     Message is empty.
//   - string — the rule states its own reason. An empty string means satisfied;
//     any other string denies and *is* the reason, so a rule can say
//     "requested 400 days; this profile allows at most 90" instead of leaving
//     the requester to guess. Effect does not apply.
//   - list(string) — the same, for a rule that has several reasons at once
//     (one per offending DNS name, say). An empty list means satisfied.
//
// # Scope
//
// A rule with no selectors applies to every issuance. Profiles and CAs narrow
// it; both are matched case-insensitively and accept shell-style globs, so
// `staging-*` selects a family of CAs without listing them. TenantID restricts
// the rule to one tenant's CAs.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
	// Message is the reason reported when a boolean rule denies. It is ignored
	// for a rule whose expression produces its own text.
	Message string `json:"message,omitempty"`
	Effect  Effect `json:"effect,omitempty"`
	Mode    Mode   `json:"mode,omitempty"`

	// TenantID scopes the rule to one tenant; empty applies it to every tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// Profiles and CAs narrow the rule to certain issuance profiles / issuing
	// CAs (by id or label), matched case-insensitively with glob support. Empty
	// means "every one".
	Profiles []string `json:"profiles,omitempty"`
	CAs      []string `json:"cas,omitempty"`

	// Priority orders evaluation, ascending. It does not change the verdict —
	// every applicable rule is evaluated so the requester learns every reason at
	// once — but it fixes the order the reasons are reported in, so the most
	// important one is read first.
	Priority int `json:"priority"`
	// Enabled is what the console's toggle writes. A disabled rule is kept, not
	// deleted, so a policy can be parked without losing its text.
	Enabled bool `json:"enabled"`
	// FailOpen permits the issuance when this rule's own evaluation fails (a
	// runtime error, an unusable result, the cost ceiling). The default is
	// fail-closed: a rule that cannot be evaluated has not been satisfied.
	FailOpen bool `json:"fail_open,omitempty"`

	CreatedBy string `json:"created_by,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// EffectOrDefault returns the rule's effect, defaulting to EffectRequire.
func (r Rule) EffectOrDefault() Effect {
	if r.Effect == EffectDeny {
		return EffectDeny
	}
	return EffectRequire
}

// ModeOrDefault returns the rule's mode, defaulting to ModeEnforce.
func (r Rule) ModeOrDefault() Mode {
	if r.Mode == ModeMonitor {
		return ModeMonitor
	}
	return ModeEnforce
}

// Validate checks a rule is well-formed and its expression compiles, so a bad
// rule is rejected where it is written (console, CLI, API) instead of denying
// every certificate afterwards.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	if strings.ContainsAny(r.Name, " \t\r\n") {
		return fmt.Errorf("name %q must not contain whitespace: it appears in error messages and audit records", r.Name)
	}
	if strings.TrimSpace(r.Expression) == "" {
		return errors.New("expression is required")
	}
	switch r.Effect {
	case "", EffectRequire, EffectDeny:
	default:
		return fmt.Errorf("effect %q must be %q or %q", r.Effect, EffectRequire, EffectDeny)
	}
	switch r.Mode {
	case "", ModeEnforce, ModeMonitor:
	default:
		return fmt.Errorf("mode %q must be %q or %q", r.Mode, ModeEnforce, ModeMonitor)
	}
	for _, pat := range append(append([]string{}, r.Profiles...), r.CAs...) {
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("selector %q is not a valid pattern: %w", pat, err)
		}
	}
	if err := Validate(r.Expression); err != nil {
		return err
	}
	return nil
}

// Applies reports whether the rule's selectors admit this request. An empty
// selector list means "every one"; a tenant-scoped rule never applies to another
// tenant's CA.
func (r Rule) Applies(req CertRequest) bool {
	if r.TenantID != "" && !strings.EqualFold(r.TenantID, req.CA.Tenant) {
		return false
	}
	if len(r.Profiles) > 0 && !matchesAny(r.Profiles, req.Profile) {
		return false
	}
	if len(r.CAs) > 0 && !matchesAny(r.CAs, req.CA.ID) && !matchesAny(r.CAs, req.CA.Label) {
		return false
	}
	return true
}

// matchesAny reports whether value matches one of the patterns, case-insensitively,
// with shell-style globbing. A malformed pattern matches nothing (it was rejected
// at validation; reaching here means the row predates the check, and a selector
// nobody can parse must not widen a rule's scope).
func matchesAny(patterns []string, value string) bool {
	if value == "" {
		return false
	}
	v := strings.ToLower(value)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == v {
			return true
		}
		if ok, err := path.Match(p, v); err == nil && ok {
			return true
		}
	}
	return false
}

// Violation is one reason a request was refused (or, in monitor mode, would
// have been).
type Violation struct {
	// Rule is the rule's name, so an operator can find the text that produced
	// this and a requester can quote it in a ticket.
	Rule string `json:"rule"`
	// Message is what the requester is told.
	Message string `json:"message"`
	// Mode is the rule's mode; a monitor-mode violation did not block anything.
	Mode Mode `json:"mode"`
	// Error is set when the rule denied because it could not be evaluated,
	// rather than because the request failed it. It is operator-facing detail.
	Error string `json:"error,omitempty"`
}

// Decision is the outcome of evaluating a rule set against one request.
type Decision struct {
	// Allowed is false when at least one enforcing rule denied.
	Allowed bool `json:"allowed"`
	// Violations are every reason found, in rule-priority order — enforcing and
	// monitoring alike, so a dry-run shows what a monitor-mode rule would do.
	Violations []Violation `json:"violations,omitempty"`
	// Evaluated is how many rules applied to this request.
	Evaluated int `json:"evaluated"`
	// Skipped is how many rules were disabled or out of scope.
	Skipped int `json:"skipped"`
}

// Enforced returns only the violations that actually blocked the request.
func (d Decision) Enforced() []Violation {
	out := make([]Violation, 0, len(d.Violations))
	for _, v := range d.Violations {
		if v.Mode != ModeMonitor {
			out = append(out, v)
		}
	}
	return out
}

// Summary renders the blocking reasons as one line, for an audit detail or a log.
func (d Decision) Summary() string {
	v := d.Enforced()
	if len(v) == 0 {
		return "no violations"
	}
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, x.Rule+": "+x.Message)
	}
	return strings.Join(parts, "; ")
}

// ErrDenied is the sentinel every issuance surface tests for, so a policy
// refusal can be mapped to a client error (a 4xx naming the reasons) rather
// than to the 500 an internal failure deserves.
var ErrDenied = errors.New("issuance denied by policy")

// DenyError is the error a denied issuance returns. Its message leads with the
// reasons, because that message is what reaches the requester: the whole point
// of the engine is that "it exceeds the maximum lifetime" travels back instead
// of "forbidden".
type DenyError struct {
	Decision Decision
}

func (e *DenyError) Error() string {
	v := e.Decision.Enforced()
	if len(v) == 0 {
		return ErrDenied.Error()
	}
	if len(v) == 1 {
		return fmt.Sprintf("%s (policy rule %q)", v[0].Message, v[0].Rule)
	}
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, fmt.Sprintf("%s (policy rule %q)", x.Message, x.Rule))
	}
	return "certificate request denied: " + strings.Join(parts, "; ")
}

// Unwrap lets errors.Is(err, ErrDenied) recognize a policy refusal.
func (e *DenyError) Unwrap() error { return ErrDenied }

// Violations returns the blocking reasons, for a surface that renders them as
// structured data rather than as a sentence.
func (e *DenyError) Violations() []Violation { return e.Decision.Enforced() }

// Engine evaluates a rule set. It is stateless apart from the compiled-program
// cache, and is safe for concurrent use.
type Engine struct {
	cache *programCache
}

// NewEngine returns an engine with its own compilation cache.
func NewEngine() *Engine { return &Engine{cache: newProgramCache()} }

// shared is the process-wide engine. Compilation is memoized by expression
// text, so the common case — the same handful of rules evaluated on every
// issuance — costs one map lookup per rule rather than a parse, a type-check
// and a plan.
var shared = NewEngine()

// Shared returns the process-wide engine.
func Shared() *Engine { return shared }

// Evaluate runs every applicable rule against the input and returns the
// decision. Rules are evaluated in priority order and *all* of them run: a
// requester who got three things wrong is told three things, not told one and
// left to discover the rest by retrying.
//
// Evaluation never panics on operator input and never returns an error: a rule
// that cannot be evaluated becomes a violation naming itself (unless it is
// marked fail-open), which is the fail-closed reading. A caller that wants the
// refusal as an error calls Check.
func (e *Engine) Evaluate(rules []Rule, in Input) Decision {
	ordered := make([]Rule, 0, len(rules))
	ordered = append(ordered, rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Name < ordered[j].Name
	})

	d := Decision{Allowed: true}
	act := in.Activation()
	for _, r := range ordered {
		if !r.Enabled || !r.Applies(in.Request) {
			d.Skipped++
			continue
		}
		d.Evaluated++
		for _, v := range e.evaluateRule(r, act) {
			d.Violations = append(d.Violations, v)
			if v.Mode != ModeMonitor {
				d.Allowed = false
			}
		}
	}
	return d
}

// evaluateRule evaluates one rule and returns the violations it produced (none
// when it is satisfied).
func (e *Engine) evaluateRule(r Rule, act map[string]interface{}) []Violation {
	prog, err := e.cache.get(r.Expression)
	if err != nil {
		return e.failure(r, fmt.Sprintf("policy rule %q does not compile", r.Name), err)
	}
	res, err := prog.Eval(act)
	if err != nil {
		return e.failure(r, fmt.Sprintf("policy rule %q could not be evaluated", r.Name), err)
	}

	switch res.Kind {
	case celexpr.KindBool:
		denied := res.Bool
		if r.EffectOrDefault() == EffectRequire {
			denied = !res.Bool
		}
		if !denied {
			return nil
		}
		return []Violation{{Rule: r.Name, Message: r.messageOrDefault(), Mode: r.ModeOrDefault()}}
	default:
		var out []Violation
		for _, m := range res.Strings {
			if m = strings.TrimSpace(m); m == "" {
				continue
			}
			out = append(out, Violation{Rule: r.Name, Message: m, Mode: r.ModeOrDefault()})
		}
		return out
	}
}

// failure renders an un-evaluatable rule. Fail-closed by default: a rule whose
// own evaluation broke has not been satisfied, and issuing because the guard
// crashed is the one outcome a restriction engine must never produce. An
// operator who knows a rule is best-effort marks it fail_open.
func (e *Engine) failure(r Rule, what string, err error) []Violation {
	if r.FailOpen {
		return nil
	}
	return []Violation{{
		Rule:    r.Name,
		Message: what + "; the request is refused because the rule could not be checked",
		Mode:    r.ModeOrDefault(),
		Error:   err.Error(),
	}}
}

// messageOrDefault is the reason a boolean rule reports.
func (r Rule) messageOrDefault() string {
	if m := strings.TrimSpace(r.Message); m != "" {
		return m
	}
	if d := strings.TrimSpace(r.Description); d != "" {
		return d
	}
	if r.EffectOrDefault() == EffectDeny {
		return fmt.Sprintf("the request matches policy rule %q, which forbids it", r.Name)
	}
	return fmt.Sprintf("the request does not satisfy policy rule %q", r.Name)
}

// Check evaluates the rules and returns a *DenyError when an enforcing rule
// denied, so a caller on the issuance path can simply propagate it. The decision
// is returned either way, so a caller that audits monitor-mode findings can see
// them on the allowed path too.
func (e *Engine) Check(rules []Rule, in Input) (Decision, error) {
	d := e.Evaluate(rules, in)
	if !d.Allowed {
		return d, &DenyError{Decision: d}
	}
	return d, nil
}

// programCache memoizes compiled programs by expression text. A cel.Program is
// immutable and safe for concurrent evaluation, so one compile serves every
// issuance until the rule's text changes — at which point the new text is simply
// a different key, which is why no invalidation is needed when an operator edits
// a rule in the console.
type programCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	prog *celexpr.AnyProgram
	err  error
}

// maxCachedPrograms bounds the cache so a surface that evaluates ad-hoc
// expressions (the dry-run endpoint) cannot grow it without limit. Reaching the
// bound clears it rather than evicting cleverly: the working set is a handful of
// stored rules, so a rare full recompile costs less than tracking recency.
const maxCachedPrograms = 512

func newProgramCache() *programCache {
	return &programCache{entries: make(map[string]cacheEntry)}
}

// get returns the compiled program for expr, compiling it on first use. A
// compile failure is cached too: a broken rule must not re-parse on every
// issuance, and it denies either way.
func (c *programCache) get(expr string) (*celexpr.AnyProgram, error) {
	key := strings.TrimSpace(expr)
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		return e.prog, e.err
	}
	prog, err := Compile(key)
	c.mu.Lock()
	if len(c.entries) >= maxCachedPrograms {
		c.entries = make(map[string]cacheEntry, maxCachedPrograms)
	}
	c.entries[key] = cacheEntry{prog: prog, err: err}
	c.mu.Unlock()
	return prog, err
}
