package caa

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeResolver is a deterministic in-memory Resolver for the evaluation tests.
// caa maps a name to its published RRset, cname maps an alias to its target, and
// errs forces a lookup failure for a name.
type fakeResolver struct {
	caa   map[string][]Record
	cname map[string]string
	errs  map[string]error
}

func (f *fakeResolver) LookupCAA(_ context.Context, name string) ([]Record, error) {
	if f.errs != nil {
		if e, ok := f.errs[name]; ok {
			return nil, e
		}
	}
	return f.caa[name], nil
}

func (f *fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	if f.cname == nil {
		return "", nil
	}
	return f.cname[name], nil
}

func issue(domain string) Record  { return Record{Tag: TagIssue, Value: domain} }
func issuew(domain string) Record { return Record{Tag: TagIssueWild, Value: domain} }

const caID = "ca.example.com"

func TestCheck(t *testing.T) {
	tests := []struct {
		name       string
		policy     Policy
		resolver   *fakeResolver
		names      []string
		reqCtx     RequestContext // RFC 8657 binding facts (zero = non-ACME request)
		wantOK     bool
		wantReason Reason // expected reason of the first finding when !wantOK
		wantIodef  int
	}{
		{
			name:     "no CAA anywhere permits issuance",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},
		{
			name:     "issue authorizes this CA",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {issue(caID)}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},
		{
			name:       "issue authorizes a different CA",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {issue("other.example.net")}}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonForbidden,
		},
		{
			name:       "empty issue value authorizes no CA",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: ";"}}}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonForbidden,
		},
		{
			name:     "identifier match is case-insensitive",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {issue("CA.Example.COM")}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},
		{
			name:     "unrecognized issue parameter is ignored",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; account=12345; policy=ev"}}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},

		// ---- RFC 8657 accounturi binding -----------------------------------
		{
			name:     "accounturi matches the requesting ACME account",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1"}}}},
			names:    []string{"host.example.com"},
			reqCtx:   RequestContext{AccountURI: "https://acme.example/acct/1"},
			wantOK:   true,
		},
		{
			name:       "accounturi does not match the requesting account",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1"}}}},
			names:      []string{"host.example.com"},
			reqCtx:     RequestContext{AccountURI: "https://acme.example/acct/2"},
			wantOK:     false,
			wantReason: ReasonAccountMismatch,
		},
		{
			name:       "accounturi is unsatisfiable on a non-ACME request",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1"}}}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonAccountMismatch,
		},
		{
			name:   "unrestricted record authorizes even when a parameterized one fails",
			policy: Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {
				{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1"},
				{Tag: TagIssue, Value: caID},
			}}},
			names:  []string{"host.example.com"},
			reqCtx: RequestContext{AccountURI: "https://acme.example/acct/2"},
			wantOK: true,
		},

		// ---- RFC 8657 validationmethods binding ----------------------------
		{
			name:     "validationmethods permits the method that was used",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; validationmethods=dns-01,http-01"}}}},
			names:    []string{"host.example.com"},
			reqCtx:   RequestContext{ValidationMethods: map[string]string{"host.example.com": "http-01"}},
			wantOK:   true,
		},
		{
			name:       "validationmethods forbids the method that was used",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; validationmethods=dns-01"}}}},
			names:      []string{"host.example.com"},
			reqCtx:     RequestContext{ValidationMethods: map[string]string{"host.example.com": "http-01"}},
			wantOK:     false,
			wantReason: ReasonValidationMethod,
		},
		{
			name:       "validationmethods is unsatisfiable without a recorded method",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; validationmethods=dns-01"}}}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonValidationMethod,
		},
		{
			name:     "issuewild validationmethods permits dns-01 for a wildcard",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssueWild, Value: caID + "; validationmethods=dns-01"}}}},
			names:    []string{"*.example.com"},
			reqCtx:   RequestContext{ValidationMethods: map[string]string{"example.com": "dns-01"}},
			wantOK:   true,
		},
		{
			name:     "accounturi and validationmethods both satisfied",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1; validationmethods=dns-01"}}}},
			names:    []string{"host.example.com"},
			reqCtx: RequestContext{
				AccountURI:        "https://acme.example/acct/1",
				ValidationMethods: map[string]string{"host.example.com": "dns-01"},
			},
			wantOK: true,
		},
		{
			name:     "combined binding blocks when only the account matches",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; accounturi=https://acme.example/acct/1; validationmethods=dns-01"}}}},
			names:    []string{"host.example.com"},
			reqCtx: RequestContext{
				AccountURI:        "https://acme.example/acct/1",
				ValidationMethods: map[string]string{"host.example.com": "http-01"},
			},
			wantOK:     false,
			wantReason: ReasonValidationMethod,
		},
		{
			name:   "closest CAA set wins over ancestor",
			policy: Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{
				"example.com":      {issue(caID)},
				"host.example.com": {issue("other.example.net")},
			}},
			names:      []string{"x.host.example.com"},
			wantOK:     false,
			wantReason: ReasonForbidden,
		},
		{
			name:       "wildcard uses issuewild and it takes precedence over issue",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {issue(caID), issuew("other.example.net")}}},
			names:      []string{"*.example.com"},
			wantOK:     false,
			wantReason: ReasonForbidden,
		},
		{
			name:     "wildcard falls back to issue when no issuewild present",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {issue(caID)}}},
			names:    []string{"*.example.com"},
			wantOK:   true,
		},
		{
			name:     "non-wildcard ignores issuewild-only set",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {issuew("other.example.net")}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},
		{
			name:       "critical unknown property forbids issuance",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"example.com": {{Flag: criticalFlag, Tag: "mustnot", Value: "x"}, issue(caID)}}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonCriticalUnknown,
		},
		{
			name:     "non-critical unknown property is ignored",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Flag: 0, Tag: "future", Value: "x"}, issue(caID)}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
		},
		{
			name:   "CNAME target tree is climbed for authorization",
			policy: Policy{Identifier: caID},
			resolver: &fakeResolver{
				cname: map[string]string{"www.example.com": "web.example.net"},
				caa:   map[string][]Record{"example.net": {issue(caID)}},
			},
			names:  []string{"www.example.com"},
			wantOK: true,
		},
		{
			name:      "iodef endpoints are collected alongside authorization",
			policy:    Policy{Identifier: caID},
			resolver:  &fakeResolver{caa: map[string][]Record{"example.com": {issue(caID), {Tag: TagIodef, Value: "mailto:sec@example.com"}}}},
			names:     []string{"host.example.com"},
			wantOK:    true,
			wantIodef: 1,
		},
		{
			name:       "lookup error leaves authorization undetermined",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{errs: map[string]error{"host.example.com": errors.New("SERVFAIL")}},
			names:      []string{"host.example.com"},
			wantOK:     false,
			wantReason: ReasonLookupError,
		},
		{
			name:     "IP-only / no DNS names is a clean skip",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{},
			names:    nil,
			wantOK:   true,
		},
		{
			name:       "one forbidden name among several blocks",
			policy:     Policy{Identifier: caID},
			resolver:   &fakeResolver{caa: map[string][]Record{"bad.example.org": {issue("other.example.net")}}},
			names:      []string{"good.example.com", "bad.example.org"},
			wantOK:     false,
			wantReason: ReasonForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.policy.Check(context.Background(), tc.resolver, tc.names, tc.reqCtx)
			if tc.wantOK {
				if !res.OK() {
					t.Fatalf("expected OK, got findings: %s", res.Summary())
				}
			} else {
				if res.OK() {
					t.Fatalf("expected a forbidding finding, got OK: %s", res.Summary())
				}
				if res.Findings[0].Reason != tc.wantReason {
					t.Fatalf("expected reason %q, got %q (%s)", tc.wantReason, res.Findings[0].Reason, res.Summary())
				}
			}
			if len(res.Iodef) != tc.wantIodef {
				t.Fatalf("expected %d iodef endpoints, got %d: %v", tc.wantIodef, len(res.Iodef), res.Iodef)
			}
		})
	}
}

// TestCheckDeduplicatesNames proves repeated SANs are evaluated once.
func TestCheckDeduplicatesNames(t *testing.T) {
	r := &fakeResolver{caa: map[string][]Record{"example.com": {issue(caID)}}}
	res := Policy{Identifier: caID}.Check(context.Background(), r, []string{"host.example.com", "HOST.example.com.", "host.example.com"}, RequestContext{})
	if len(res.Checked) != 1 {
		t.Fatalf("expected 1 checked name after dedup, got %d: %v", len(res.Checked), res.Checked)
	}
}

// TestClimbStopsAtRoot proves the search does not loop past the top-level label.
func TestClimbStopsAtRoot(t *testing.T) {
	r := &fakeResolver{} // no records anywhere
	set, err := relevantCAASet(context.Background(), r, "a.b.c.example.com")
	if err != nil {
		t.Fatalf("relevantCAASet: %v", err)
	}
	if set != nil {
		t.Fatalf("expected empty set, got %v", set)
	}
}

// TestCNAMECycleTerminates proves an alias cycle cannot hang the resolver.
func TestCNAMECycleTerminates(t *testing.T) {
	r := &fakeResolver{cname: map[string]string{
		"a.example.com": "b.example.com",
		"b.example.com": "a.example.com",
	}}
	// Should terminate (via visited-set + maxClimb) and find nothing.
	set, err := relevantCAASet(context.Background(), r, "a.example.com")
	if err != nil {
		t.Fatalf("relevantCAASet: %v", err)
	}
	if set != nil {
		t.Fatalf("expected empty set, got %v", set)
	}
}

// TestParseIssueParams proves the RFC 8657 parameter parser tolerates the
// whitespace RFC 8659 §4.2 permits, lowercases keys for case-insensitive
// matching, keeps the last value on a duplicate key, and skips malformed fields.
func TestParseIssueParams(t *testing.T) {
	got := parseIssueParams("  AccountURI = https://acme.example/acct/1 ;validationmethods=dns-01,http-01; bare ; =noKey; account=1; account=2")
	want := map[string]string{
		"accounturi":        "https://acme.example/acct/1",
		"validationmethods": "dns-01,http-01",
		"account":           "2",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d params, want %d: %#v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("param %q = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["bare"]; ok {
		t.Fatalf("a field without '=' must be skipped, got %#v", got)
	}
}

// TestValidationMethodAllowed proves membership testing trims whitespace, is
// case-insensitive on the method labels, and never matches an empty method.
func TestValidationMethodAllowed(t *testing.T) {
	const list = "dns-01, HTTP-01 ,tls-alpn-01"
	for _, m := range []string{"dns-01", "http-01", "TLS-ALPN-01", " dns-01 "} {
		if !validationMethodAllowed(m, list) {
			t.Fatalf("method %q should be permitted by %q", m, list)
		}
	}
	for _, m := range []string{"", "email-reply-00", "http"} {
		if validationMethodAllowed(m, list) {
			t.Fatalf("method %q should not be permitted by %q", m, list)
		}
	}
}

// blockingResolver stands in for a nameserver that has stopped answering: every
// lookup blocks until the context is done.
type blockingResolver struct{}

func (blockingResolver) LookupCAA(ctx context.Context, _ string) ([]Record, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingResolver) LookupCNAME(ctx context.Context, _ string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// cnameErrResolver publishes no CAA records anywhere and fails every alias
// lookup, isolating the CNAME leg of the tree climb.
type cnameErrResolver struct{ err error }

func (cnameErrResolver) LookupCAA(context.Context, string) ([]Record, error) { return nil, nil }

func (r cnameErrResolver) LookupCNAME(context.Context, string) (string, error) { return "", r.err }

// TestCheckTimeoutBoundsTheWholeEvaluation proves Policy.Timeout caps a stalled
// resolver: the check must come back with a lookup_error per name (fail-closed
// under enforce) instead of hanging issuance. The budget covers the whole
// evaluation, so the second name must not be granted a fresh timeout.
func TestCheckTimeoutBoundsTheWholeEvaluation(t *testing.T) {
	const budget = 150 * time.Millisecond
	p := Policy{Identifier: caID, Timeout: budget}

	start := time.Now()
	res := p.Check(context.Background(), blockingResolver{}, []string{"a.example.com", "b.example.com"}, RequestContext{})
	elapsed := time.Since(start)

	if res.OK() {
		t.Fatalf("a resolver that never answers must not be reported as authorized: %s", res.Summary())
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected a finding per name, got %d: %s", len(res.Findings), res.Summary())
	}
	for _, f := range res.Findings {
		if f.Reason != ReasonLookupError {
			t.Fatalf("finding %+v: expected reason %q", f, ReasonLookupError)
		}
	}
	if elapsed > 4*budget {
		t.Fatalf("Check took %v with a %v budget; the timeout is not shared across names", elapsed, budget)
	}
}

// TestCheckSkipsNonDNSNames proves a SAN that is not a usable DNS name is
// ignored entirely — not resolved, and not counted as checked. Counting one
// would make the audit line claim a name was evaluated when it never was.
func TestCheckSkipsNonDNSNames(t *testing.T) {
	up := newCountingResolver()
	res := Policy{Identifier: caID}.Check(context.Background(), up,
		[]string{"", "   ", ".", "*", "*.", "*.*.example.com", "a*.example.com"}, RequestContext{})

	if !res.OK() {
		t.Fatalf("expected a clean skip, got %s", res.Summary())
	}
	if len(res.Checked) != 0 {
		t.Fatalf("expected no names to be checked, got %v", res.Checked)
	}
	if res.Summary() != "caa=skip" {
		t.Fatalf("Summary() = %q, want caa=skip", res.Summary())
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.caaCalls) != 0 || len(up.cnameCalls) != 0 {
		t.Fatalf("the resolver was consulted for an unusable name: caa=%v cname=%v", up.caaCalls, up.cnameCalls)
	}
}

// TestCNAMELookupFailureIsFailClosed proves an alias lookup failure leaves
// authorization undetermined. Ignoring it would send the climb up the alias's
// own tree, where a permissive ancestor that does not govern the canonical
// target could authorize issuance.
func TestCNAMELookupFailureIsFailClosed(t *testing.T) {
	r := cnameErrResolver{err: errors.New("SERVFAIL")}

	if set, err := relevantCAASet(context.Background(), r, "www.example.com"); err == nil {
		t.Fatalf("expected the alias lookup failure to propagate, got set %+v", set)
	}
	res := Policy{Identifier: caID}.Check(context.Background(), r, []string{"www.example.com"}, RequestContext{})
	if res.OK() {
		t.Fatalf("expected a lookup_error finding, got %s", res.Summary())
	}
	if res.Findings[0].Reason != ReasonLookupError {
		t.Fatalf("reason = %q, want %q", res.Findings[0].Reason, ReasonLookupError)
	}
}

// TestCriticalFlagOnAKnownTag proves the issuer-critical bit only forbids
// issuance when the tag is one the CA does not understand (RFC 8659 §4.1).
// Treating every critical record as unknown would block issuance for every
// domain that (legitimately) marks its issue record critical.
func TestCriticalFlagOnAKnownTag(t *testing.T) {
	tests := []struct {
		name       string
		set        []Record
		wantOK     bool
		wantReason Reason
	}{
		{
			name:   "critical issue naming this CA authorizes",
			set:    []Record{{Flag: criticalFlag, Tag: TagIssue, Value: caID}},
			wantOK: true,
		},
		{
			// Still forbidden — but for naming another CA, not for being critical.
			name:       "critical issue naming another CA forbids as forbidden",
			set:        []Record{{Flag: criticalFlag, Tag: TagIssue, Value: "other.example.net"}},
			wantReason: ReasonForbidden,
		},
		{
			name:   "critical iodef alone leaves issuance unrestricted",
			set:    []Record{{Flag: criticalFlag, Tag: TagIodef, Value: "mailto:sec@example.com"}},
			wantOK: true,
		},
		{
			name:   "critical issuewild does not affect a non-wildcard request",
			set:    []Record{{Flag: criticalFlag, Tag: TagIssueWild, Value: "other.example.net"}},
			wantOK: true,
		},
		{
			name:       "critical unknown tag forbids even beside an authorizing issue",
			set:        []Record{{Flag: criticalFlag, Tag: "newthing", Value: "x"}, issue(caID)},
			wantReason: ReasonCriticalUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeResolver{caa: map[string][]Record{"example.com": tc.set}}
			res := Policy{Identifier: caID}.Check(context.Background(), r, []string{"host.example.com"}, RequestContext{})
			if tc.wantOK {
				if !res.OK() {
					t.Fatalf("expected issuance to be permitted, got %s", res.Summary())
				}
				return
			}
			if res.OK() {
				t.Fatalf("expected a finding, got %s", res.Summary())
			}
			if res.Findings[0].Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q (%s)", res.Findings[0].Reason, tc.wantReason, res.Summary())
			}
		})
	}
}

// TestUnsetIdentifierAuthorizesNothing proves a policy with no CA identifier
// cannot be authorized by any issue record: matching is an exact comparison
// against this CA's own name, and an empty identifier must never match (least of
// all an `issue ""`-style record). A misconfigured deployment therefore fails
// closed instead of accepting everyone's CAA records as its own.
func TestUnsetIdentifierAuthorizesNothing(t *testing.T) {
	governed := &fakeResolver{caa: map[string][]Record{"example.com": {issue("ca.example.com")}}}
	res := Policy{Identifier: ""}.Check(context.Background(), governed, []string{"host.example.com"}, RequestContext{})
	if res.OK() {
		t.Fatalf("an unset identifier must not be authorized: %s", res.Summary())
	}
	if res.Findings[0].Reason != ReasonForbidden {
		t.Fatalf("reason = %q, want %q", res.Findings[0].Reason, ReasonForbidden)
	}
	// The audit detail has to name the misconfiguration.
	if !strings.Contains(res.Findings[0].Detail, "<unset>") {
		t.Fatalf("detail %q does not report the missing identifier", res.Findings[0].Detail)
	}

	// An empty-valued issue record must not be read as matching the empty
	// identifier either.
	empty := &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: ""}}}}
	if res := (Policy{Identifier: ""}).Check(context.Background(), empty, []string{"host.example.com"}, RequestContext{}); res.OK() {
		t.Fatalf("`issue \"\"` must not authorize an unset identifier: %s", res.Summary())
	}

	// With no CAA policy anywhere there is nothing to authorize against, so even
	// an unset identifier is permitted (the gate only blocks on a governing set).
	if res := (Policy{Identifier: ""}).Check(context.Background(), &fakeResolver{}, []string{"host.example.com"}, RequestContext{}); !res.OK() {
		t.Fatalf("an ungoverned name must stay permitted: %s", res.Summary())
	}
}

// TestPolicyModeSemantics pins which modes check and which ones block. The zero
// value matters most: Policy{} is documented to behave like ModeEnforce so an
// unset policy fails closed, and a mode that is enabled but not enforcing means
// "evaluate and report, never block".
func TestPolicyModeSemantics(t *testing.T) {
	tests := []struct {
		name          string
		mode          Mode
		wantEnabled   bool
		wantEnforcing bool
	}{
		{name: "enforce blocks", mode: ModeEnforce, wantEnabled: true, wantEnforcing: true},
		{name: "permissive checks but never blocks", mode: ModePermissive, wantEnabled: true, wantEnforcing: false},
		{name: "off disables the gate", mode: ModeOff, wantEnabled: false, wantEnforcing: false},
		{name: "the zero value fails closed", mode: "", wantEnabled: true, wantEnforcing: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Mode: tc.mode, Identifier: caID}
			if got := p.Enabled(); got != tc.wantEnabled {
				t.Fatalf("Enabled() = %v, want %v", got, tc.wantEnabled)
			}
			if got := p.enforcing(); got != tc.wantEnforcing {
				t.Fatalf("enforcing() = %v, want %v", got, tc.wantEnforcing)
			}
			if tc.wantEnforcing && !tc.wantEnabled {
				t.Fatalf("a mode cannot enforce while disabled")
			}
		})
	}
}

// TestResultForbiddenMirrorsOK proves Forbidden() is exactly !OK(). The issuance
// gate blocks on Forbidden() while the audit trail is keyed off OK(), so any
// divergence would let a blocked issuance be recorded as clean (or vice versa).
func TestResultForbiddenMirrorsOK(t *testing.T) {
	for _, res := range []Result{
		{},
		{Checked: []string{"host.example.com"}},
		{Checked: []string{"host.example.com"}, Findings: []Finding{{Name: "host.example.com", Reason: ReasonForbidden}}},
		{Findings: []Finding{{Reason: ReasonLookupError}, {Reason: ReasonForbidden}}},
		{Iodef: []string{"mailto:sec@example.com"}},
	} {
		if res.OK() == res.Forbidden() {
			t.Fatalf("OK() and Forbidden() agree (%v) for %+v", res.OK(), res)
		}
	}
}

// TestResultSummary pins the one-line audit rendering: it is what lands in the
// audit trail and in the error returned to the client, so an operator reading it
// must be able to tell a skip from a pass from a block, and see which name
// blocked and why.
func TestResultSummary(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want string
	}{
		{
			// No DNS names to check (an IP-only certificate) must not look like a
			// successful CAA evaluation.
			name: "nothing checked is a skip",
			res:  Result{},
			want: "caa=skip",
		},
		{
			name: "all names permitted",
			res:  Result{Checked: []string{"a.example.com", "b.example.com"}},
			want: "caa=ok names=2",
		},
		{
			name: "iodef endpoints do not change the verdict",
			res:  Result{Checked: []string{"a.example.com"}, Iodef: []string{"mailto:sec@example.com"}},
			want: "caa=ok names=1",
		},
		{
			name: "a single blocked name names itself and its reason",
			res: Result{
				Checked:  []string{"host.example.com"},
				Findings: []Finding{{Name: "host.example.com", Reason: ReasonForbidden}},
			},
			want: "caa=forbidden names=1 blocked=[host.example.com(forbidden)]",
		},
		{
			name: "every blocked name is listed",
			res: Result{
				Checked: []string{"a.example.com", "*.b.example.com", "c.example.com"},
				Findings: []Finding{
					{Name: "a.example.com", Reason: ReasonLookupError},
					{Name: "*.b.example.com", Reason: ReasonCriticalUnknown},
				},
			},
			want: "caa=forbidden names=3 blocked=[a.example.com(lookup_error) *.b.example.com(critical_unknown)]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Summary(); got != tc.want {
				t.Fatalf("Summary() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSummaryMatchesCheckResult keeps the rendering tied to a real evaluation
// rather than a hand-built Result.
func TestSummaryMatchesCheckResult(t *testing.T) {
	r := &fakeResolver{caa: map[string][]Record{"example.com": {issue("other.example.net")}}}
	res := Policy{Identifier: caID}.Check(context.Background(), r, []string{"host.example.com"}, RequestContext{})
	if want := "caa=forbidden names=1 blocked=[host.example.com(forbidden)]"; res.Summary() != want {
		t.Fatalf("Summary() = %q, want %q", res.Summary(), want)
	}

	ok := Policy{Identifier: caID}.Check(context.Background(), &fakeResolver{}, nil, RequestContext{})
	if ok.Summary() != "caa=skip" {
		t.Fatalf("Summary() for an empty check = %q, want caa=skip", ok.Summary())
	}
}

// TestItoa checks the dependency-free formatter Summary() relies on against the
// standard library. Its whole domain comes from len(), but it also advertises
// negative support, and it formats into a fixed 20-byte buffer — so the widest
// values are the interesting ones.
func TestItoa(t *testing.T) {
	values := []int{
		0, 1, 7, 9, 10, 11, 99, 100, 101, 1000, 4096, 65535,
		1 << 20, 1<<31 - 1, 1 << 40, math.MaxInt64,
		-1, -9, -10, -12345, -(1 << 40), math.MinInt64 + 1,
	}
	for _, n := range values {
		if got, want := itoa(n), strconv.Itoa(n); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDecodeCAARDATA(t *testing.T) {
	// flags=0, tag="issue" (len 5), value="ca.example.com"
	tag := "issue"
	value := "ca.example.com"
	data := append([]byte{0x00, byte(len(tag))}, tag...)
	data = append(data, value...)
	rec, err := decodeCAARDATA(data)
	if err != nil {
		t.Fatalf("decodeCAARDATA: %v", err)
	}
	if rec.Flag != 0 || rec.Tag != "issue" || rec.Value != value {
		t.Fatalf("unexpected record: %+v", rec)
	}

	if _, err := decodeCAARDATA([]byte{0x00}); err == nil {
		t.Fatal("expected error for short RDATA")
	}
	if _, err := decodeCAARDATA([]byte{0x00, 0x00}); err == nil {
		t.Fatal("expected error for zero tag length")
	}
	if _, err := decodeCAARDATA([]byte{0x00, 0x09, 'x'}); err == nil {
		t.Fatal("expected error for tag length past RDATA end")
	}
}
