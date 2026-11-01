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

// Kind says which vocabulary a rule is written against — which is to say what
// the rule restricts (Task 224).
//
// One engine, one rule record and one store serve both, because they are the
// same act of policy: a key this deployment is responsible for is asked to
// attest to something, and an operator decides whether it may. What differs is
// the facts, and a rule declares which set it reasons about so a typo in the
// other vocabulary is a compile error rather than a rule that never fires.
type Kind string

const (
	// KindCertificate restricts X.509 certificate generation. Its rules reason
	// about `request` and are enforced by the pre-issuance gate on every
	// issuance surface. It is the default, so a rule stored before kinds existed
	// keeps its meaning.
	KindCertificate Kind = "certificate"
	// KindSigning restricts the other signatures this PKI's keys produce: an
	// OpenSSH certificate, a CMS/CAdES signature over an artifact, a raw
	// signature over caller data. Its rules reason about `signing`.
	KindSigning Kind = "signing"
)

// OrDefault returns the kind, defaulting to KindCertificate.
func (k Kind) OrDefault() Kind {
	if k == KindSigning {
		return KindSigning
	}
	return KindCertificate
}

// Kinds lists the rule kinds in documentation order.
func Kinds() []Kind { return []Kind{KindCertificate, KindSigning} }

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
	ID string `json:"id"`
	// Kind is the vocabulary the expression is written against, defaulting to
	// KindCertificate. It also decides which gate enforces the rule: a signing
	// rule is never consulted on the issuance path, and vice versa.
	Kind        Kind   `json:"kind,omitempty"`
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
	// means "every one". A signing rule reads them too, where the operation has
	// the notion: an SSH certificate has a signing profile and a signing CA.
	Profiles []string `json:"profiles,omitempty"`
	CAs      []string `json:"cas,omitempty"`
	// Keys and Operations narrow a signing rule (they are ignored by a
	// certificate rule, whose key is the subject's and whose operation is
	// always an issuance). Keys matches the key the signature would be made
	// with — by name, by provider label, or by the signing CA's label — and
	// Operations one of the OpSign* identifiers. Both glob.
	Keys       []string `json:"keys,omitempty"`
	Operations []string `json:"operations,omitempty"`

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

// KindOrDefault returns the rule's kind, defaulting to KindCertificate — which
// is what a row written before Task 224 means.
func (r Rule) KindOrDefault() Kind { return r.Kind.OrDefault() }

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
	switch r.Kind {
	case "", KindCertificate, KindSigning:
	default:
		return fmt.Errorf("kind %q must be %q or %q", r.Kind, KindCertificate, KindSigning)
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
	for _, pat := range r.selectors() {
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("selector %q is not a valid pattern: %w", pat, err)
		}
	}
	if r.KindOrDefault() == KindCertificate && (len(r.Keys) > 0 || len(r.Operations) > 0) {
		return errors.New("the keys and operations selectors apply to a signing rule; a certificate rule narrows by profile and CA")
	}
	for _, op := range r.Operations {
		if !knownSigningOperation(op) {
			return fmt.Errorf("operation selector %q is not a signing operation (%s)",
				op, strings.Join(SigningOperations(), ", "))
		}
	}
	if err := ValidateFor(r.KindOrDefault(), r.Expression); err != nil {
		return err
	}
	return nil
}

// selectors is every scope pattern on the rule, for the pattern check.
func (r Rule) selectors() []string {
	out := make([]string, 0, len(r.Profiles)+len(r.CAs)+len(r.Keys)+len(r.Operations))
	out = append(out, r.Profiles...)
	out = append(out, r.CAs...)
	out = append(out, r.Keys...)
	out = append(out, r.Operations...)
	return out
}

// knownSigningOperation reports whether a pattern names (or globs onto) at
// least one signing operation. A selector naming an operation that does not
// exist is rejected where it is written: it would otherwise be a rule that
// looks switched on and silently applies to nothing.
func knownSigningOperation(pattern string) bool {
	for _, op := range SigningOperations() {
		if matchesAny([]string{pattern}, op) {
			return true
		}
	}
	return false
}

// Applies reports whether the rule's selectors admit this request. An empty
// selector list means "every one"; a tenant-scoped rule never applies to another
// tenant's CA.
func (r Rule) Applies(req CertRequest) bool {
	if r.KindOrDefault() != KindCertificate {
		return false
	}
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

// AppliesToSigning reports whether the rule's selectors admit this signing
// operation. The key selector matches on any of the three names a key is known
// by — the name the caller used, the provider label, and (for an SSH
// certificate) the signing CA's label — because an operator writing
// `keys: release-signing` should not have to know which of those the surface
// records.
func (r Rule) AppliesToSigning(req SigningRequest) bool {
	if r.KindOrDefault() != KindSigning {
		return false
	}
	if r.TenantID != "" && !strings.EqualFold(r.TenantID, req.Tenant) && !strings.EqualFold(r.TenantID, req.Key.Tenant) {
		return false
	}
	if len(r.Operations) > 0 && !matchesAny(r.Operations, req.Operation) {
		return false
	}
	if len(r.Keys) > 0 && !matchesAny(r.Keys, req.Key.Name) && !matchesAny(r.Keys, req.Key.Label) &&
		!matchesAny(r.Keys, req.SSH.CA.Label) && !matchesAny(r.Keys, req.SSH.CA.ID) {
		return false
	}
	if len(r.Profiles) > 0 && !matchesAny(r.Profiles, req.SSH.Profile) {
		return false
	}
	if len(r.CAs) > 0 && !matchesAny(r.CAs, req.SSH.CA.ID) && !matchesAny(r.CAs, req.SSH.CA.Label) {
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

// ErrDenied is the sentinel every issuance and signing surface tests for, so a
// policy refusal can be mapped to a client error (a 4xx naming the reasons)
// rather than to the 500 an internal failure deserves.
var ErrDenied = errors.New("issuance denied by policy")

// ErrUnavailable marks the *other* way a gate refuses: the rule set could not be
// read, so nothing could be checked. It is deliberately distinct from ErrDenied
// — both refuse the request, but only this one is the server's fault and only
// this one is worth retrying, so a transport can answer 5xx for it and 4xx for
// a rule that actually said no.
var ErrUnavailable = errors.New("the policy rules could not be evaluated")

// DenyError is the error a denied request returns. Its message leads with the
// reasons, because that message is what reaches the requester: the whole point
// of the engine is that "it exceeds the maximum lifetime" travels back instead
// of "forbidden".
type DenyError struct {
	Decision Decision
	// Subject names what was refused, for the sentence that introduces several
	// reasons at once ("certificate request", "artifact signature"). Empty
	// reads as a certificate request, which is what every pre-Task-224 caller
	// means.
	Subject string
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
	subject := e.Subject
	if subject == "" {
		subject = "certificate request"
	}
	return subject + " denied: " + strings.Join(parts, "; ")
}

// DenySubject names what a signing operation refuses, for a DenyError's
// multi-reason sentence.
func DenySubject(operation string) string {
	switch operation {
	case OpSignSSHCert:
		return "SSH certificate request"
	case OpSignArtifact:
		return "artifact signature request"
	case OpSignData:
		return "signature request"
	case OpSignJWTSVID:
		return "JWT-SVID request"
	}
	return "signing request"
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
	ordered := orderRules(rules)
	return e.evaluate(ordered, in.Activation(), KindCertificate,
		func(r Rule) bool { return r.Applies(in.Request) })
}

// EvaluateSigning runs every applicable signing rule against the input and
// returns the decision (Task 224). It is Evaluate's counterpart: same ordering,
// same all-rules-run reporting, same fail-closed reading — only the vocabulary
// and the selector match differ.
func (e *Engine) EvaluateSigning(rules []Rule, in SigningInput) Decision {
	ordered := orderRules(rules)
	return e.evaluate(ordered, in.Activation(), KindSigning,
		func(r Rule) bool { return r.AppliesToSigning(in.Signing) })
}

// evaluate is the shared loop: every enabled, in-scope rule of the kind runs,
// and its violations accumulate.
func (e *Engine) evaluate(ordered []Rule, act map[string]interface{}, kind Kind, applies func(Rule) bool) Decision {
	d := Decision{Allowed: true}
	for _, r := range ordered {
		if !r.Enabled || !applies(r) {
			d.Skipped++
			continue
		}
		d.Evaluated++
		for _, v := range e.evaluateRule(r, kind, act) {
			d.Violations = append(d.Violations, v)
			if v.Mode != ModeMonitor {
				d.Allowed = false
			}
		}
	}
	return d
}

// orderRules puts a rule set in evaluation order: priority ascending, then name,
// so the reasons a requester reads come back in a stable, operator-chosen order.
func orderRules(rules []Rule) []Rule {
	ordered := make([]Rule, 0, len(rules))
	ordered = append(ordered, rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Name < ordered[j].Name
	})
	return ordered
}

// evaluateRule evaluates one rule and returns the violations it produced (none
// when it is satisfied).
func (e *Engine) evaluateRule(r Rule, kind Kind, act map[string]interface{}) []Violation {
	prog, err := e.cache.get(kind, r.Expression)
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

// CheckSigning evaluates the signing rules and returns a *DenyError when an
// enforcing rule denied, so a caller on a signing path can simply propagate it.
func (e *Engine) CheckSigning(rules []Rule, in SigningInput) (Decision, error) {
	d := e.EvaluateSigning(rules, in)
	if !d.Allowed {
		return d, &DenyError{Decision: d, Subject: DenySubject(in.Signing.Operation)}
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
	entries map[cacheKey]cacheEntry
}

// cacheKey is the expression text *and* the kind it was compiled for: the same
// text means different things in the two environments, and one compiled program
// is only valid in the one it was built from.
type cacheKey struct {
	kind Kind
	expr string
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
	return &programCache{entries: make(map[cacheKey]cacheEntry)}
}

// get returns the compiled program for expr, compiling it on first use. A
// compile failure is cached too: a broken rule must not re-parse on every
// issuance, and it denies either way.
func (c *programCache) get(kind Kind, expr string) (*celexpr.AnyProgram, error) {
	key := cacheKey{kind: kind.OrDefault(), expr: strings.TrimSpace(expr)}
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		return e.prog, e.err
	}
	prog, err := CompileFor(key.kind, key.expr)
	c.mu.Lock()
	if len(c.entries) >= maxCachedPrograms {
		c.entries = make(map[cacheKey]cacheEntry, maxCachedPrograms)
	}
	c.entries[key] = cacheEntry{prog: prog, err: err}
	c.mu.Unlock()
	return prog, err
}
