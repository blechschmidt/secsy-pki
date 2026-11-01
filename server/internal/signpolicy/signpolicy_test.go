package signpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
)

// stubStore serves a fixed rule set, or an error, standing in for the database.
type stubStore struct {
	rules   []celpolicy.Rule
	err     error
	tenants []string // every tenant the gate asked about
}

func (s *stubStore) ActiveSigningPolicyRules(tenantID string) ([]celpolicy.Rule, error) {
	s.tenants = append(s.tenants, tenantID)
	return s.rules, s.err
}

// stubSink collects the audit events the gate appends.
type stubSink struct {
	events []*audit.Event
	err    error
}

func (s *stubSink) AppendEvent(e *audit.Event) error {
	s.events = append(s.events, e)
	return s.err
}

func sshFacts() celpolicy.SigningRequest {
	return celpolicy.SigningRequest{
		Operation:   celpolicy.OpSignSSHCert,
		Source:      celpolicy.SourceREST,
		Tenant:      "acme",
		RequestedBy: "ops@example.com",
		Key:         celpolicy.SigningKeyInfo{Name: "ssh-user-ca", Tenant: "acme"},
		SSH: celpolicy.SSHCertInfo{
			Present:    true,
			CertType:   "user",
			KeyID:      "ops@example.com",
			Principals: []string{"root"},
		},
	}
}

func denyRootRule() celpolicy.Rule {
	return celpolicy.Rule{
		Kind: celpolicy.KindSigning, Name: "no-root", Enabled: true, Effect: celpolicy.EffectDeny,
		Expression: `signing.ssh.principals.exists(p, p == "root")`,
		Message:    "an SSH certificate may not name root",
	}
}

func TestGateRefusesAndExplains(t *testing.T) {
	store := &stubStore{rules: []celpolicy.Rule{denyRootRule()}}
	sink := &stubSink{}
	gate := NewGate(store, sink)

	err := gate.CheckSigning(context.Background(), sshFacts())
	if err == nil {
		t.Fatal("the gate must refuse a certificate naming root")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the refusal must be recognizable as a policy denial: %v", err)
	}
	var deny *celpolicy.DenyError
	if !errors.As(err, &deny) {
		t.Fatalf("expected a *celpolicy.DenyError, got %T", err)
	}
	if got := deny.Violations(); len(got) != 1 || got[0].Message != "an SSH certificate may not name root" {
		t.Errorf("the operator's own wording must reach the caller: %+v", got)
	}
	// The key's tenant is what scopes the rule lookup.
	if len(store.tenants) != 1 || store.tenants[0] != "acme" {
		t.Errorf("rules were loaded for %v, want [acme]", store.tenants)
	}
	// The refusal is written down, with the reason.
	if len(sink.events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.Action != audit.ActionSignPolicy || e.Result != audit.ResultError {
		t.Errorf("event action/result = %s/%s", e.Action, e.Result)
	}
	if e.Actor != "ops@example.com" || e.TargetName != "ops@example.com" {
		t.Errorf("event actor/target = %s/%s", e.Actor, e.TargetName)
	}
	for _, want := range []string{"operation=ssh-certificate", "key=ssh-user-ca", "no-root[enforce]", "may not name root"} {
		if !strings.Contains(e.Detail, want) {
			t.Errorf("audit detail %q should contain %q", e.Detail, want)
		}
	}
}

func TestGatePermitsWhatNoRuleRefuses(t *testing.T) {
	store := &stubStore{rules: []celpolicy.Rule{denyRootRule()}}
	sink := &stubSink{}
	gate := NewGate(store, sink)

	facts := sshFacts()
	facts.SSH.Principals = []string{"deploy"}
	if err := gate.CheckSigning(context.Background(), facts); err != nil {
		t.Fatalf("an ordinary certificate must be permitted: %v", err)
	}
	if len(sink.events) != 0 {
		t.Errorf("a clean evaluation writes no audit event, got %d", len(sink.events))
	}
}

func TestGateFailsClosedWhenRulesCannotBeLoaded(t *testing.T) {
	gate := NewGate(&stubStore{err: errors.New("database is down")}, &stubSink{})
	err := gate.CheckSigning(context.Background(), sshFacts())
	if err == nil {
		t.Fatal("an unreadable rule set must refuse the signature")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial: the caller should see a 5xx, not a 4xx")
	}
	if !strings.Contains(err.Error(), "database is down") {
		t.Errorf("the underlying failure should surface: %v", err)
	}
}

func TestNilGatePermits(t *testing.T) {
	// A service constructed without a rule store — a unit test, a tool — has no
	// policy at all, which is a different thing from a policy that could not be
	// read. celpolicy.Check is the one-liner every signing service calls.
	var gate *Gate
	if err := gate.CheckSigning(context.Background(), sshFacts()); err != nil {
		t.Errorf("a nil gate must permit: %v", err)
	}
	if err := celpolicy.Check(context.Background(), nil, sshFacts()); err != nil {
		t.Errorf("a nil checker must permit: %v", err)
	}
	if NewGate(nil, nil) != nil {
		t.Error("a gate over no store is a nil gate")
	}
}

func TestMonitorModeSignsAndRecords(t *testing.T) {
	rule := denyRootRule()
	rule.Mode = celpolicy.ModeMonitor
	sink := &stubSink{}
	gate := NewGate(&stubStore{rules: []celpolicy.Rule{rule}}, sink)

	if err := gate.CheckSigning(context.Background(), sshFacts()); err != nil {
		t.Fatalf("a monitor-mode rule must not block: %v", err)
	}
	if len(sink.events) != 1 || sink.events[0].Result != audit.ResultSuccess {
		t.Fatalf("a monitor finding must be recorded as a success: %+v", sink.events)
	}
	if !strings.Contains(sink.events[0].Detail, "no-root[monitor]") {
		t.Errorf("the detail should mark the mode: %q", sink.events[0].Detail)
	}
}

func TestGateWithoutSinkStillRefuses(t *testing.T) {
	// A CLI path may hold no audit sink. The refusal must still happen; only the
	// record is missing.
	gate := NewGate(&stubStore{rules: []celpolicy.Rule{denyRootRule()}}, nil)
	if err := gate.CheckSigning(context.Background(), sshFacts()); err == nil {
		t.Error("a gate with no audit sink must still refuse")
	}
}

func TestEvaluateDoesNotRecord(t *testing.T) {
	sink := &stubSink{}
	gate := NewGate(&stubStore{rules: []celpolicy.Rule{denyRootRule()}}, sink)
	d, in, err := gate.Evaluate(context.Background(), sshFacts())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Allowed {
		t.Error("the dry-run should report the same verdict the gate would reach")
	}
	if in.Signing.Operation != celpolicy.OpSignSSHCert {
		t.Errorf("the echoed facts should carry the operation: %q", in.Signing.Operation)
	}
	if len(sink.events) != 0 {
		t.Error("a dry-run must not write audit events")
	}
}

func TestGateIgnoresCertificateRules(t *testing.T) {
	// The store's kind filter is the first line of defence; the engine's is the
	// second. A certificate rule that reached the signing gate would not compile
	// against the signing vocabulary and, fail-closed, would refuse every
	// signature — so this is the test that keeps a mixed rule table safe.
	certRule := celpolicy.Rule{
		Name: "cert-only", Enabled: true,
		Expression: `request.dns_names.size() <= 1`,
	}
	gate := NewGate(&stubStore{rules: []celpolicy.Rule{certRule}}, &stubSink{})
	if err := gate.CheckSigning(context.Background(), sshFacts()); err != nil {
		t.Errorf("a certificate rule must not be evaluated on the signing path: %v", err)
	}
}

func TestTenantFallsBackToTheOperation(t *testing.T) {
	store := &stubStore{}
	gate := NewGate(store, &stubSink{})
	facts := sshFacts()
	facts.Key.Tenant = ""
	facts.Tenant = "other"
	if err := gate.CheckSigning(context.Background(), facts); err != nil {
		t.Fatal(err)
	}
	if len(store.tenants) != 1 || store.tenants[0] != "other" {
		t.Errorf("tenants asked about = %v, want [other]", store.tenants)
	}
}

func TestGateFailureIsDistinguishableFromARefusal(t *testing.T) {
	// A transport has to tell the two apart: a refusal is the caller's request
	// (4xx, do not retry), an unreadable rule set is the server (5xx, retry).
	gate := NewGate(&stubStore{err: errors.New("database is down")}, &stubSink{})
	err := gate.CheckSigning(context.Background(), sshFacts())
	if !errors.Is(err, celpolicy.ErrUnavailable) {
		t.Errorf("a store failure must carry celpolicy.ErrUnavailable: %v", err)
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure must not read as a policy denial")
	}

	denied := NewGate(&stubStore{rules: []celpolicy.Rule{denyRootRule()}}, &stubSink{}).
		CheckSigning(context.Background(), sshFacts())
	if !errors.Is(denied, celpolicy.ErrDenied) {
		t.Errorf("a refusal must carry celpolicy.ErrDenied: %v", denied)
	}
	if errors.Is(denied, celpolicy.ErrUnavailable) {
		t.Error("a refusal must not read as a gate failure")
	}
}
