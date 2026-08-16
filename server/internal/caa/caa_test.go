package caa

import (
	"context"
	"errors"
	"testing"
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
