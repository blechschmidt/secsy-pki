package spiffe

import "testing"

func TestParseIDValid(t *testing.T) {
	cases := []struct {
		in    string
		td    string
		path  string
		canon string
	}{
		{"spiffe://example.org", "example.org", "", "spiffe://example.org"},
		{"spiffe://example.org/ns/prod/sa/web", "example.org", "/ns/prod/sa/web", "spiffe://example.org/ns/prod/sa/web"},
		{"spiffe://Example.ORG/Workload", "example.org", "/Workload", "spiffe://example.org/Workload"},
		{"spiffe://trust-domain_1.example.com/a.b-c_d", "trust-domain_1.example.com", "/a.b-c_d", "spiffe://trust-domain_1.example.com/a.b-c_d"},
	}
	for _, c := range cases {
		id, err := ParseID(c.in)
		if err != nil {
			t.Fatalf("ParseID(%q) unexpected error: %v", c.in, err)
		}
		if id.TrustDomain() != c.td {
			t.Errorf("ParseID(%q) trust domain = %q, want %q", c.in, id.TrustDomain(), c.td)
		}
		if id.Path() != c.path {
			t.Errorf("ParseID(%q) path = %q, want %q", c.in, id.Path(), c.path)
		}
		if id.String() != c.canon {
			t.Errorf("ParseID(%q) canonical = %q, want %q", c.in, id.String(), c.canon)
		}
	}
}

func TestParseIDInvalid(t *testing.T) {
	bad := []string{
		"",
		"https://example.org/foo",       // wrong scheme
		"spiffe://",                     // no trust domain
		"spiffe://example.org:8443/foo", // port
		"spiffe://user@example.org/foo", // userinfo
		"spiffe://example.org/foo?x=1",  // query
		"spiffe://example.org/foo#frag", // fragment
		"spiffe://example.org/foo/",     // trailing slash
		"spiffe://example.org//double",  // empty segment
		"spiffe://example.org/./rel",    // dot segment
		"spiffe://example.org/../rel",   // dotdot segment
		"spiffe://exam ple.org/foo",     // invalid trust-domain char
		"spiffe://example.org/foo bar",  // invalid path char (space)
		"spiffe://example.org/foo/%2e",  // invalid path char after decode
	}
	for _, in := range bad {
		if id, err := ParseID(in); err == nil {
			t.Errorf("ParseID(%q) = %q, want error", in, id.String())
		}
	}
}

func TestMakeID(t *testing.T) {
	id, err := MakeID("Example.org", "ns/prod")
	if err != nil {
		t.Fatalf("MakeID: %v", err)
	}
	if got, want := id.String(), "spiffe://example.org/ns/prod"; got != want {
		t.Errorf("MakeID = %q, want %q", got, want)
	}
	if _, err := MakeID("", "/x"); err == nil {
		t.Error("MakeID with empty trust domain should error")
	}
	if _, err := MakeID("example.org", "/bad seg"); err == nil {
		t.Error("MakeID with invalid path should error")
	}
}

func TestPolicyAllowed(t *testing.T) {
	p := NewPolicy(PolicyConfig{
		TrustDomains:        []string{"Example.org", "prod.example.com"},
		SubjectTrustDomains: map[string][]string{"alice@example.com": {"team.example.net"}},
	})

	if !p.Allowed([]string{"anyone"}, "example.org") {
		t.Error("global trust domain should be allowed for any subject")
	}
	if !p.Allowed([]string{"anyone"}, "PROD.example.com") {
		t.Error("trust-domain match should be case-insensitive")
	}
	if p.Allowed([]string{"bob"}, "team.example.net") {
		t.Error("per-subject trust domain must not be allowed for other subjects")
	}
	if !p.Allowed([]string{"alice@example.com"}, "team.example.net") {
		t.Error("per-subject trust domain should be allowed for its subject")
	}
	if p.Allowed([]string{"anyone"}, "unlisted.example") {
		t.Error("unlisted trust domain must be denied (fail-closed)")
	}
	if (*Policy)(nil).Allowed([]string{"x"}, "example.org") {
		t.Error("nil policy must deny")
	}
}
