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
			name:     "issue value with parameters still matches",
			policy:   Policy{Identifier: caID},
			resolver: &fakeResolver{caa: map[string][]Record{"example.com": {{Tag: TagIssue, Value: caID + "; account=12345; validationmethods=dns-01"}}}},
			names:    []string{"host.example.com"},
			wantOK:   true,
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
			res := tc.policy.Check(context.Background(), tc.resolver, tc.names)
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
	res := Policy{Identifier: caID}.Check(context.Background(), r, []string{"host.example.com", "HOST.example.com.", "host.example.com"})
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
