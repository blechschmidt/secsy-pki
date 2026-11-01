// Package signpolicy is the fail-closed gate that enforces the CEL
// signing-restriction rules (Task 224) on every signature this PKI produces
// outside certificate generation: an OpenSSH certificate signed by an SSH CA, a
// CMS/CAdES signature over a release artifact, a raw signature over caller data
// with a named signing key.
//
// It is the signing counterpart of ca.Manager.checkCELPolicy — same engine
// (internal/celpolicy), same rule table, same effects and modes, same
// fail-closed reading — and it lives in its own package for one reason: the
// services it guards (internal/sshca, internal/signing, internal/secret) have
// no business importing the CA manager, the database or the audit log, and a
// gate they could not reach would be a gate they could bypass.
//
// # Where it runs
//
// Inside each signing service, below every transport. The REST API, the gRPC
// API and the CLI all converge on the same service call, so a rule cannot be
// avoided by asking a different way — the same property that makes the
// certificate gate's position in buildLeaf worth having.
//
// # Fail-closed
//
// A rule set that cannot be loaded, a rule that cannot be compiled and a rule
// that errors at evaluation all refuse the signature (unless the operator
// marked that rule fail-open). A gate that permits what it could not check is
// not a gate.
//
// A *nil* gate is the one deliberate exception: it permits everything, because
// it means no rule store was wired at all (a unit test constructing a service
// directly, a tool with no database). That is the difference between "the
// policy could not be read" and "there is no policy", and only the first is a
// failure.
package signpolicy

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// RuleStore reads the enabled signing rules that could apply to an operation in
// a tenant. It is the narrow slice of *database.DB this package needs, declared
// here so a test can supply a handful of rules without a database.
type RuleStore interface {
	ActiveSigningPolicyRules(tenantID string) ([]celpolicy.Rule, error)
}

// EventSink appends a tamper-evident audit event. *database.DB satisfies it.
type EventSink interface {
	AppendEvent(*audit.Event) error
}

// Gate evaluates the stored signing rules against one operation. It is
// stateless beyond its two collaborators and safe for concurrent use.
type Gate struct {
	store  RuleStore
	events EventSink
}

// NewGate builds a gate over a rule store and an audit sink. The sink may be
// nil, in which case findings are reported through metrics and the refusal
// itself but not written to the audit log — acceptable for a CLI invocation
// against a store it opened read-only, never for the server.
func NewGate(store RuleStore, events EventSink) *Gate {
	if store == nil {
		return nil
	}
	return &Gate{store: store, events: events}
}

// CheckSigning evaluates the rules and returns a *celpolicy.DenyError when an
// enforcing rule refused the operation. The error's message carries the
// operator's own wording, which is what reaches the caller: the point of the
// engine is that "the release-signing key is reserved for the release workflow"
// travels back instead of "forbidden".
//
// It satisfies celpolicy.SigningChecker, which is the interface the signing
// services accept, so none of them needs to import this package.
func (g *Gate) CheckSigning(ctx context.Context, req celpolicy.SigningRequest) error {
	if g == nil {
		return nil
	}
	decision, _, err := g.evaluate(ctx, req)
	if err != nil {
		return err
	}
	if decision.Allowed {
		return nil
	}
	return &celpolicy.DenyError{Decision: decision, Subject: celpolicy.DenySubject(req.Operation)}
}

// evaluate loads the rules, evaluates them, and records the outcome.
func (g *Gate) evaluate(ctx context.Context, req celpolicy.SigningRequest) (celpolicy.Decision, celpolicy.SigningInput, error) {
	rules, err := g.store.ActiveSigningPolicyRules(tenantOf(req))
	if err != nil {
		metrics.SigningPolicyChecks.Inc(operationLabel(req.Operation), "error")
		// Fail closed: without the rule set we cannot prove the signature is
		// permitted, and the store being unreachable is not a licence to sign.
		return celpolicy.Decision{}, celpolicy.SigningInput{},
			fmt.Errorf("pre-signing policy check failed: loading signing restriction rules: %w: %w",
				celpolicy.ErrUnavailable, err)
	}
	in := celpolicy.FromContext(ctx).SigningInput(req)
	if len(rules) == 0 {
		// Counted as a pass, not skipped: "the gate ran and nothing refused" is
		// what the series means, and a deployment with no rules should see its
		// signing traffic in it.
		metrics.SigningPolicyChecks.Inc(operationLabel(req.Operation), "pass")
		return celpolicy.Decision{Allowed: true}, in, nil
	}
	decision := celpolicy.Shared().EvaluateSigning(rules, in)
	g.record(in, decision)
	return decision, in, nil
}

// tenantOf is the tenant whose rules apply: the key's own tenant, falling back
// to the operation's.
func tenantOf(req celpolicy.SigningRequest) string {
	if req.Key.Tenant != "" {
		return req.Key.Tenant
	}
	return req.Tenant
}

// operationLabel keeps the metric's label set bounded. An operation name comes
// from this code, never from a caller, but a typo'd constant must not mint a
// series either.
func operationLabel(op string) string {
	switch op {
	case celpolicy.OpSignSSHCert, celpolicy.OpSignArtifact, celpolicy.OpSignData:
		return op
	}
	return "other"
}

// record publishes metrics for every evaluation and appends an audit event
// whenever a rule produced a finding — blocking or not. A monitor-mode finding
// that never reaches a caller is only useful if it is written down.
func (g *Gate) record(in celpolicy.SigningInput, d celpolicy.Decision) {
	op := operationLabel(in.Signing.Operation)
	switch {
	case !d.Allowed:
		metrics.SigningPolicyChecks.Inc(op, "deny")
	case len(d.Violations) > 0:
		metrics.SigningPolicyChecks.Inc(op, "monitor")
	default:
		metrics.SigningPolicyChecks.Inc(op, "pass")
	}
	for _, v := range d.Violations {
		metrics.SigningPolicyViolations.Inc(v.Rule, string(v.Mode))
		if v.Error != "" {
			metrics.SigningPolicyRuleErrors.Inc(v.Rule)
		}
	}
	if len(d.Violations) == 0 || g.events == nil {
		return
	}
	actor := in.Signing.RequestedBy
	if actor == "" {
		actor = "system"
	}
	result := audit.ResultError
	if d.Allowed {
		// Monitor-mode findings only: the signature was produced.
		result = audit.ResultSuccess
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionSignPolicy,
		Target:     in.Signing.Key.Name,
		TargetName: targetName(in.Signing),
		Result:     result,
		Detail:     Detail(in, d),
	}
	if err := g.events.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append %s audit event: %v", audit.ActionSignPolicy, err)
	}
}

// targetName is the human-readable thing the signature was about: the SSH
// certificate's key ID, the artifact's name, or the key itself.
func targetName(req celpolicy.SigningRequest) string {
	switch {
	case req.SSH.Present && req.SSH.KeyID != "":
		return req.SSH.KeyID
	case req.Artifact.Present && req.Artifact.Name != "":
		return req.Artifact.Name
	}
	return req.Key.Name
}

// Detail renders the audit detail: the operation, the key, and every finding
// with its rule name and mode — the same text the caller received, so the log
// answers "why was this refused" on its own.
func Detail(in celpolicy.SigningInput, d celpolicy.Decision) string {
	parts := []string{
		"operation=" + in.Signing.Operation,
		"source=" + in.Signing.Source,
		"key=" + in.Signing.Key.Name,
		fmt.Sprintf("rules_evaluated=%d", d.Evaluated),
	}
	for _, v := range d.Violations {
		detail := fmt.Sprintf("%s[%s]: %s", v.Rule, v.Mode, v.Message)
		if v.Error != "" {
			detail += " (" + v.Error + ")"
		}
		parts = append(parts, detail)
	}
	return strings.Join(parts, " ")
}
