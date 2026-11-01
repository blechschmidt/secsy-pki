//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Tests for the fail-closed pre-issuance CEL restriction gate (Task 223).
//
// The whole point of these is that the engine is wired into the path that signs:
// an issuance that a rule refuses must come back refused, with the operator's
// own words, and with NO certificate — not a certificate plus a warning. So every
// case here goes through Manager.IssueCertificate against a real CA key and then
// checks both the error and the inventory.

// policyManager builds a Manager with a software-backed root and returns both.
func policyManager(t *testing.T, tag string) (*Manager, *models.CA) {
	t.Helper()
	mgr := newTestManager(t, softwareProvider(t))
	return mgr, newRoot(t, mgr, tag)
}

// addRule stores an enabled rule, failing the test if it does not compile.
func addRule(t *testing.T, mgr *Manager, r celpolicy.Rule) {
	t.Helper()
	if r.ID == "" {
		r.ID = r.Name
	}
	r.Enabled = true
	if err := mgr.db.CreateCELPolicyRule(&r); err != nil {
		t.Fatalf("storing rule %q: %v", r.Name, err)
	}
}

// makeCSRFor is makeCSR without a *testing.T, for use inside helpers.
func makeCSRFor(cn string, dns []string, ips []net.IP) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dns,
		IPAddresses: ips,
	}, key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestGateAllowsWhenNoRulesExist: the engine must be inert until an operator
// writes a rule. Every other issuance test in this package depends on it.
func TestGateAllowsWhenNoRulesExist(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-none")
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err != nil {
		t.Fatalf("issuance with no rules failed: %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("no certificate")
	}
}

// TestGateRefusesWithTheOperatorsWording is the headline behaviour the task asks
// for: the requester learns why.
func TestGateRefusesWithTheOperatorsWording(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-deny")
	addRule(t, mgr, celpolicy.Rule{
		Name: "dns-suffix",
		Expression: `request.dns_names.filter(d, !d.endsWith(".example.com"))` +
			`.map(d, "DNS name " + d + " is outside example.com, which this CA may not certify")`,
	})

	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.evil.test", []string{"www.evil.test"}, nil),
	})
	if err == nil {
		t.Fatal("a forbidden DNS name was certified")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the error is not recognizable as a policy refusal: %v", err)
	}
	var deny *celpolicy.DenyError
	if !errors.As(err, &deny) {
		t.Fatalf("errors.As did not yield a *DenyError: %v", err)
	}
	if !strings.Contains(err.Error(), "www.evil.test is outside example.com") {
		t.Errorf("the refusal does not carry the operator's wording: %v", err)
	}
	if !strings.Contains(err.Error(), "dns-suffix") {
		t.Errorf("the refusal does not name the rule: %v", err)
	}

	// And nothing was signed or recorded.
	certs, err := mgr.db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("a refused request left %d certificates in the inventory", len(certs))
	}

	// The permitted name still issues, so the rule constrains rather than blocks.
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	}); err != nil {
		t.Fatalf("a permitted name was refused: %v", err)
	}
}

// TestGateRefusesOnLifetime covers the task's own example: a maximum lifetime
// whose refusal names the number.
func TestGateRefusesOnLifetime(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-lifetime")
	addRule(t, mgr, celpolicy.Rule{
		Name: "max-lifetime",
		Expression: `request.validity_days <= 30 ? "" : ` +
			`"requested %d days of validity; this profile allows at most 30".format([request.validity_days])`,
	})
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:     root.ID,
		CSRPEM:   makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
		Validity: 90 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("a 90-day request passed a 30-day ceiling")
	}
	if !strings.Contains(err.Error(), "requested 90 days") {
		t.Errorf("the refusal does not quantify the excess: %v", err)
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:     root.ID,
		CSRPEM:   makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
		Validity: 7 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("a 7-day request was refused: %v", err)
	}
}

// TestGateSeesTheResolvedTemplate: the facts are read from what will be signed,
// not from the request JSON — so a validity clamped by the profile, and usages
// the profile assigned, are what a rule sees.
func TestGateSeesTheResolvedTemplate(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-template")
	// One rule per fact, so a failure names the fact that was wrong rather than
	// reporting that a twelve-clause conjunction was false.
	//
	// The "server" profile assigns serverAuth and caps validity at 397 days, so a
	// request for 10 years is clamped before the gate sees it — a rule written
	// against the profile's ceiling must hold, which is the whole point of reading
	// the facts off the resolved template.
	facts := map[string]string{
		"ext key usage":  `"serverAuth" in request.ext_key_usages`,
		"key usage":      `"digitalSignature" in request.key_usages`,
		"clamped days":   `request.validity_days == 397`,
		"clamped window": `request.validity >= duration("9528h") && request.validity <= duration("9529h")`,
		"profile":        `request.profile == "server"`,
		"ca label":       `request.ca.label == "` + root.Label + `"`,
		"ca subject":     `request.ca.subject.contains("Issuance Test Root")`,
		"ca expiry":      `request.ca.not_after > now`,
		"key algorithm":  `request.key.algorithm == "ECDSA" && request.key.size == 256 && request.key.curve == "P-256"`,
		"key print":      `request.key.fingerprint.startsWith("SHA256:")`,
		"serial":         `request.serial != "" && request.serial.matches("^[0-9]+$")`,
		"source":         `request.source == "unknown"`,
		"operation":      `request.operation == "issue"`,
		"requested by":   `request.requested_by == "ops@example.com"`,
		"not a CA":       `!request.is_ca && request.max_path_len == -1`,
		"algorithm":      `request.algorithm == "classical"`,
		"subject":        `request.subject.common_name == "www.example.com" && request.subject.dn.contains("CN=www.example.com")`,
		"san count":      `request.san_count == 1 && !request.wildcard`,
		"timestamps":     `request.not_before < now && request.not_after > now`,
		"crl dp":         `request.extension_oids.size() >= 0`,
	}
	names := make([]string, 0, len(facts))
	for name := range facts {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		addRule(t, mgr, celpolicy.Rule{
			ID:         fmt.Sprintf("fact-%d", i),
			Name:       "fact-" + strings.ReplaceAll(name, " ", "-"),
			Expression: facts[name],
			Message:    "the resolved template's " + name + " is not what the gate should see",
		})
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
		Profile:     "server",
		Validity:    10 * 365 * 24 * time.Hour,
		RequestedBy: "ops@example.com",
	}); err != nil {
		t.Fatalf("a rule over the resolved template failed: %v", err)
	}
}

// TestGateSeesIPSANsAsAddresses proves the network vocabulary works end to end.
func TestGateSeesIPSANsAsAddresses(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-ip")
	addRule(t, mgr, celpolicy.Rule{
		Name: "corporate-ranges",
		Expression: `request.ip_addresses.filter(a, !cidr("10.0.0.0/8").containsIP(a))` +
			`.map(a, "IP address " + a + " is outside 10.0.0.0/8")`,
	})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("host", nil, []net.IP{net.ParseIP("10.1.2.3")}),
	}); err != nil {
		t.Fatalf("an in-range IP SAN was refused: %v", err)
	}
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("host", nil, []net.IP{net.ParseIP("8.8.8.8")}),
	})
	if err == nil {
		t.Fatal("a public IP SAN was certified")
	}
	if !strings.Contains(err.Error(), "8.8.8.8 is outside 10.0.0.0/8") {
		t.Errorf("refusal = %v", err)
	}
}

// TestGateReadsTheRequestContextFacts: the JWT, URL and body facts captured at
// the HTTP edge must reach the gate deep inside the signing path.
func TestGateReadsTheRequestContextFacts(t *testing.T) {
	mgr, root := policyManager(t, "policy-ctx")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "wildcard-entitlement",
		Expression: `!request.wildcard || (has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements)`,
		Message:    "a wildcard certificate requires the pki.wildcard entitlement in your token",
	})
	addRule(t, mgr, celpolicy.Rule{
		Name:       "console-only",
		Expression: `path.startsWith("/api/") && url.method == "POST" && has(body.reason)`,
		Message:    "this CA only certifies requests made through the API with a reason",
	})

	facts := celpolicy.NewFacts()
	facts.SetURL(celpolicy.RequestURL{Present: true, Method: "POST", Path: "/api/keys/" + root.ID + "/issue"})
	facts.SetBody(map[string]interface{}{"reason": "CHG-1"})
	facts.SetJWT(map[string]interface{}{"entitlements": []interface{}{"pki.issue"}})
	ctx := celpolicy.WithFacts(context.Background(), facts)

	// Not a wildcard: both rules hold.
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	}); err != nil {
		t.Fatalf("a non-wildcard request with the right context was refused: %v", err)
	}

	// A wildcard without the entitlement is refused, and the reason is the one
	// about the token — not the one about the URL.
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("*.example.com", []string{"*.example.com"}, nil),
	})
	if err == nil {
		t.Fatal("a wildcard was certified without the entitlement")
	}
	if !strings.Contains(err.Error(), "pki.wildcard entitlement") {
		t.Errorf("refusal = %v", err)
	}

	// Grant the entitlement in the token and the same request succeeds.
	facts.SetJWT(map[string]interface{}{"entitlements": []interface{}{"pki.issue", "pki.wildcard"}})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("*.example.com", []string{"*.example.com"}, nil),
	}); err != nil {
		t.Fatalf("an entitled wildcard was refused: %v", err)
	}

	// With no captured facts at all — an automated enrollment — the URL rule
	// refuses, which is the fail-closed reading.
	_, err = mgr.IssueCertificate(context.Background(), IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err == nil {
		t.Fatal("a request carrying no HTTP facts satisfied a URL rule")
	}
	if !strings.Contains(err.Error(), "through the API with a reason") {
		t.Errorf("refusal = %v", err)
	}
}

// TestGateMonitorModeIssuesAndAudits: the rollout mechanism, proven on the
// signing path rather than only in the engine.
func TestGateMonitorModeIssuesAndAudits(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-monitor")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "future-ban",
		Mode:       celpolicy.ModeMonitor,
		Effect:     celpolicy.EffectDeny,
		Expression: `request.dns_names.exists(d, d.endsWith(".test"))`,
		Message:    "would be refused once this rule is enforced",
	})
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.evil.test", []string{"www.evil.test"}, nil),
	})
	if err != nil {
		t.Fatalf("a monitor-mode rule blocked issuance: %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("no certificate")
	}
	// The finding is written down, with the right result: the certificate was
	// issued, so it is not an error event.
	ev := findPolicyEvent(t, mgr, audit.ResultSuccess)
	if !strings.Contains(ev.Detail, "future-ban[monitor]") {
		t.Errorf("audit detail does not mark the finding as monitor-mode: %q", ev.Detail)
	}
	if !strings.Contains(ev.Detail, "would be refused once this rule is enforced") {
		t.Errorf("audit detail does not carry the reason: %q", ev.Detail)
	}
}

// TestGateAuditsARefusal: the log must answer "why was this refused" on its own.
func TestGateAuditsARefusal(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-audit")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "no-wildcards",
		Effect:     celpolicy.EffectDeny,
		Expression: `request.wildcard`,
		Message:    "wildcard certificates are not issued by this CA",
	})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCSRFor("*.example.com", []string{"*.example.com"}, nil),
		RequestedBy: "ops@example.com",
	}); err == nil {
		t.Fatal("a wildcard was certified")
	}
	ev := findPolicyEvent(t, mgr, audit.ResultError)
	if ev.Actor != "ops@example.com" {
		t.Errorf("actor = %q", ev.Actor)
	}
	if ev.Target != root.ID {
		t.Errorf("target = %q, want the issuing CA", ev.Target)
	}
	if ev.TargetName != "*.example.com" {
		t.Errorf("target_name = %q, want the requested subject", ev.TargetName)
	}
	for _, want := range []string{"no-wildcards[enforce]", "wildcard certificates are not issued", "rules_evaluated=1"} {
		if !strings.Contains(ev.Detail, want) {
			t.Errorf("audit detail is missing %q: %q", want, ev.Detail)
		}
	}
}

// findPolicyEvent returns the single cert.policy audit event with the given
// result, failing the test when there is not exactly one.
func findPolicyEvent(t *testing.T, mgr *Manager, result string) audit.Event {
	t.Helper()
	events, _, err := mgr.db.ListEvents(audit.ActionCertPolicy, "", "", 100, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var found []audit.Event
	for _, e := range events {
		if e.Action == audit.ActionCertPolicy && e.Result == result {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d cert.policy events with result %q, want 1", len(found), result)
	}
	return found[0]
}

// TestGateFailsClosedOnABrokenRule is the safety property that distinguishes a
// restriction engine from a suggestion engine.
func TestGateFailsClosedOnABrokenRule(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-broken")
	// Stored through the store's own guard, so it compiles — and then errors at
	// evaluation, which is the case a compile check cannot catch.
	addRule(t, mgr, celpolicy.Rule{
		Name:       "unguarded-claim",
		Expression: `jwt.department == "pki"`,
	})
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err == nil {
		t.Fatal("a rule that could not be evaluated let the certificate through")
	}
	if !strings.Contains(err.Error(), "could not be checked") {
		t.Errorf("the refusal does not say the rule failed rather than the request: %v", err)
	}
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 0 {
		t.Error("a certificate was issued despite the gate failing")
	}
}

// TestGateFailOpenRule: an operator may mark a rule best-effort.
func TestGateFailOpenRule(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-failopen")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "best-effort",
		Expression: `jwt.department == "pki"`,
		FailOpen:   true,
	})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	}); err != nil {
		t.Fatalf("a fail-open rule blocked on its own error: %v", err)
	}
}

// TestGateScopeSelectorsOnTheIssuancePath: a rule scoped to one profile must not
// govern another.
func TestGateScopeSelectorsOnTheIssuancePath(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-scope")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "server-only",
		Profiles:   []string{"server"},
		Effect:     celpolicy.EffectDeny,
		Expression: `true`,
		Message:    "the server profile is closed on this CA",
	})
	if _, err := issueWithProfile(ctx, mgr, root.ID, "server"); err == nil {
		t.Fatal("the scoped profile was not governed by its rule")
	}
	if _, err := issueWithProfile(ctx, mgr, root.ID, "client"); err != nil {
		t.Fatalf("a rule scoped to the server profile blocked a client certificate: %v", err)
	}

	// A rule scoped to another CA must not govern this one.
	addRule(t, mgr, celpolicy.Rule{
		Name:       "other-ca-only",
		CAs:        []string{"some-other-ca"},
		Effect:     celpolicy.EffectDeny,
		Expression: `true`,
		Message:    "closed",
	})
	if _, err := issueWithProfile(ctx, mgr, root.ID, "client"); err != nil {
		t.Fatalf("a rule scoped to another CA blocked this one: %v", err)
	}
}

func issueWithProfile(ctx context.Context, mgr *Manager, caID, profile string) (*IssueResult, error) {
	return mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    caID,
		CSRPEM:  makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
		Profile: profile,
	})
}

// TestGateDisabledRuleDoesNotApply: switching a policy off must take effect
// without a restart, because the rules are read per issuance.
func TestGateDisabledRuleDoesNotApply(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-toggle")
	addRule(t, mgr, celpolicy.Rule{
		Name: "closed", Effect: celpolicy.EffectDeny, Expression: `true`, Message: "closed",
	})
	if _, err := issueWithProfile(ctx, mgr, root.ID, ""); err == nil {
		t.Fatal("the rule did not apply")
	}
	if ok, err := mgr.db.SetCELPolicyRuleEnabled("closed", false, "ops"); err != nil || !ok {
		t.Fatalf("SetCELPolicyRuleEnabled: %v %v", ok, err)
	}
	if _, err := issueWithProfile(ctx, mgr, root.ID, ""); err != nil {
		t.Fatalf("issuance still blocked after the rule was disabled: %v", err)
	}
}

// TestGateAppliesToRenewal: a renewal re-signs a certificate, so a policy that
// has tightened since must govern it. Otherwise "renew" is a bypass.
func TestGateAppliesToRenewal(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-renew")
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.evil.test", []string{"www.evil.test"}, nil),
	})
	if err != nil {
		t.Fatalf("initial issuance: %v", err)
	}
	addRule(t, mgr, celpolicy.Rule{
		Name:       "no-test-tld",
		Effect:     celpolicy.EffectDeny,
		Expression: `request.dns_names.exists(d, d.endsWith(".test"))`,
		Message:    ".test names are no longer certified",
	})
	_, err = mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: res.Serial.String()})
	if err == nil {
		t.Fatal("a renewal bypassed a policy that was added after issuance")
	}
	if !strings.Contains(err.Error(), "no longer certified") {
		t.Errorf("refusal = %v", err)
	}
}

// TestGateAppliesToSVIDIssuance covers one of the non-REST surfaces, proving the
// gate is in buildLeaf rather than in a handler.
func TestGateAppliesToSVIDIssuance(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-svid")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "spiffe-trust-domain",
		Expression: `request.source != "spiffe" || request.uris.all(u, u.startsWith("spiffe://acme/"))`,
		Message:    "an SVID may only name the acme trust domain",
	})
	_, err := mgr.IssueSVID(ctx, SVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://other/ns/x/sa/y",
		CSRPEM:   makeCSRFor("", nil, nil),
	})
	if err == nil {
		t.Fatal("an SVID in a foreign trust domain was certified")
	}
	if !strings.Contains(err.Error(), "only name the acme trust domain") {
		t.Errorf("refusal = %v", err)
	}
	if _, err := mgr.IssueSVID(ctx, SVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://acme/ns/payments/sa/api",
		CSRPEM:   makeCSRFor("", nil, nil),
	}); err != nil {
		t.Fatalf("a permitted SVID was refused: %v", err)
	}
}

// TestPreviewReportsThePolicyVerdict: the dry-run must agree with the gate, or it
// promises issuances the gate then refuses.
func TestPreviewReportsThePolicyVerdict(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-preview")
	addRule(t, mgr, celpolicy.Rule{
		Name: "dns-suffix",
		Expression: `request.dns_names.filter(d, !d.endsWith(".example.com"))` +
			`.map(d, "DNS name " + d + " is outside example.com")`,
	})

	bad, err := mgr.PreviewIssuance(ctx, PreviewSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.evil.test", []string{"www.evil.test"}, nil),
	})
	if err != nil {
		t.Fatalf("PreviewIssuance: %v", err)
	}
	v := gateVerdict(t, bad, GateCELPolicy)
	if v.Status != GateFail {
		t.Errorf("preview gate status = %q, want fail", v.Status)
	}
	if bad.WouldIssue || bad.Decision != "reject" {
		t.Errorf("preview decision = %q / would_issue = %v", bad.Decision, bad.WouldIssue)
	}
	if len(v.Findings) != 1 || !strings.Contains(v.Findings[0], "www.evil.test") {
		t.Errorf("preview findings = %v", v.Findings)
	}
	// And the real issuance agrees.
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCSRFor("www.evil.test", []string{"www.evil.test"}, nil),
	}); err == nil {
		t.Error("the preview rejected what issuance accepted")
	}

	ok, err := mgr.PreviewIssuance(ctx, PreviewSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := gateVerdict(t, ok, GateCELPolicy); v.Status != GatePass {
		t.Errorf("preview gate status = %q (%s), want pass", v.Status, v.Reason)
	}
	if !ok.WouldIssue {
		t.Error("the preview rejected a permitted request")
	}

	// A preview must not have audited or metered anything as a real refusal: it
	// is a dry-run.
	events, _, err := mgr.db.ListEvents(audit.ActionCertPolicy, "", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(e.Detail, "source=preview") {
			t.Error("a preview wrote a cert.policy audit event")
		}
	}
}

// TestPreviewSkipsWhenNoRuleApplies keeps the dry-run honest about doing nothing.
func TestPreviewSkipsWhenNoRuleApplies(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-preview-skip")
	res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := gateVerdict(t, res, GateCELPolicy); v.Status != GateSkipped {
		t.Errorf("gate status = %q, want skipped when there are no rules", v.Status)
	}
}

// TestPreviewWarnsOnMonitorModeFindings: a monitor-mode rule must show up in a
// dry-run without rejecting it.
func TestPreviewWarnsOnMonitorModeFindings(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-preview-monitor")
	addRule(t, mgr, celpolicy.Rule{
		Name: "watch", Mode: celpolicy.ModeMonitor, Expression: `false`, Message: "noted",
	})
	res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
		CAID:   root.ID,
		CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	v := gateVerdict(t, res, GateCELPolicy)
	if v.Status != GateWarn {
		t.Errorf("gate status = %q, want warn", v.Status)
	}
	if !res.WouldIssue {
		t.Error("a monitor-mode finding rejected the preview")
	}
	if len(v.Findings) != 1 || !strings.Contains(v.Findings[0], "would not block") {
		t.Errorf("findings = %v", v.Findings)
	}
}

// TestPolicyFactsFromCSR is what the console's and CLI's rule tester seeds a
// dry-run with: facts derived by the same code the gate uses.
func TestPolicyFactsFromCSR(t *testing.T) {
	mgr, root := policyManager(t, "policy-facts")
	got, err := mgr.PolicyFactsFromCSR(PreviewSpec{
		CAID:        root.ID,
		CSRPEM:      makeCSRFor("www.example.com", []string{"www.example.com", "*.example.com"}, []net.IP{net.ParseIP("10.1.2.3")}),
		Profile:     "server",
		Validity:    30 * 24 * time.Hour,
		RequestedBy: "ops@example.com",
	})
	if err != nil {
		t.Fatalf("PolicyFactsFromCSR: %v", err)
	}
	if got.Profile != "server" || got.CA.ID != root.ID || got.CA.Label != root.Label {
		t.Errorf("facts = %+v", got)
	}
	if len(got.DNSNames) != 2 || !got.Wildcard || len(got.IPAddresses) != 1 {
		t.Errorf("SAN facts = %+v", got)
	}
	if got.ValidityDays != 30 {
		t.Errorf("validity_days = %d, want 30", got.ValidityDays)
	}
	if got.Operation != celpolicy.OpPreview {
		t.Errorf("operation = %q, want %q", got.Operation, celpolicy.OpPreview)
	}
	if got.CA.Subject == "" || got.CA.NotAfter.IsZero() {
		t.Errorf("the issuing CA facts are incomplete: %+v", got.CA)
	}
	if _, err := mgr.PolicyFactsFromCSR(PreviewSpec{CAID: "nope", CSRPEM: makeCSRFor("x", nil, nil)}); err == nil {
		t.Error("an unknown CA produced facts")
	}
}

// TestGateIsReadAtEveryIssuance: a rule added while the process is running takes
// effect on the next certificate, with no restart and no cache to invalidate.
func TestGateIsReadAtEveryIssuance(t *testing.T) {
	ctx := context.Background()
	mgr, root := policyManager(t, "policy-live")
	if _, err := issueWithProfile(ctx, mgr, root.ID, ""); err != nil {
		t.Fatalf("baseline issuance: %v", err)
	}
	addRule(t, mgr, celpolicy.Rule{
		Name: "closed-now", Effect: celpolicy.EffectDeny, Expression: `true`, Message: "closed",
	})
	if _, err := issueWithProfile(ctx, mgr, root.ID, ""); err == nil {
		t.Fatal("a rule added after startup did not take effect")
	}
	// Editing its text takes effect too — the compiled-program cache is keyed by
	// the text, so there is nothing to invalidate.
	edit := celpolicy.Rule{
		ID: "closed-now", Name: "closed-now", Enabled: true,
		Effect: celpolicy.EffectDeny, Expression: `false`, Message: "closed",
	}
	if ok, err := mgr.db.UpdateCELPolicyRule(&edit); err != nil || !ok {
		t.Fatalf("UpdateCELPolicyRule: %v %v", ok, err)
	}
	if _, err := issueWithProfile(ctx, mgr, root.ID, ""); err != nil {
		t.Fatalf("an edited rule did not take effect: %v", err)
	}
}

// TestGateAgainstSoftHSM runs the refusal path against a real PKCS#11 token, so
// the gate is proven to run before the HSM signature rather than after it.
func TestGateAgainstSoftHSM(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, pkcs11Provider(t))
	root := newRoot(t, mgr, "policy-hsm")
	addRule(t, mgr, celpolicy.Rule{
		Name:       "hsm-no-wildcards",
		Effect:     celpolicy.EffectDeny,
		Expression: `request.wildcard`,
		Message:    "wildcards are not certified",
	})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCSRFor("*.example.com", []string{"*.example.com"}, nil),
	}); err == nil {
		t.Fatal("a wildcard was certified on the HSM path")
	}
	if certs, _ := mgr.db.ListIssuedCertificates(root.ID); len(certs) != 0 {
		t.Error("a refused request left a certificate in the inventory")
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCSRFor("www.example.com", []string{"www.example.com"}, nil),
	}); err != nil {
		t.Fatalf("a permitted request was refused on the HSM path: %v", err)
	}
}
