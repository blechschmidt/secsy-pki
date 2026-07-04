package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver is a dnsResolver whose record becomes visible only from the
// availableAfter-th lookup onward, simulating propagation lag.
type fakeResolver struct {
	mu             sync.Mutex
	txt            map[string][]string
	calls          int
	availableAfter int // 0 or 1 = available immediately
	err            error
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if r.calls < r.availableAfter {
		return nil, nil
	}
	return r.txt[strings.TrimSuffix(name, ".")], nil
}

func (r *fakeResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// recordingProvider is a DNSProvider that records what it was asked to publish
// and withdraw.
type recordingProvider struct {
	presented  map[string]string
	cleaned    map[string]int
	presentErr error
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{presented: map[string]string{}, cleaned: map[string]int{}}
}

func (p *recordingProvider) Present(_ context.Context, fqdn, value string) error {
	if p.presentErr != nil {
		return p.presentErr
	}
	p.presented[fqdn] = value
	return nil
}

func (p *recordingProvider) CleanUp(_ context.Context, fqdn, _ string) error {
	p.cleaned[fqdn]++
	return nil
}

// newTestSolver wires a solver with a deterministic (fake) clock so propagation
// polling never sleeps on the wall clock.
func newTestSolver(prov DNSProvider, res dnsResolver, timeout, poll time.Duration) *dns01Solver {
	clock := time.Unix(1_700_000_000, 0)
	return &dns01Solver{
		provider:           prov,
		resolver:           res,
		propagationTimeout: timeout,
		pollInterval:       poll,
		now:                func() time.Time { return clock },
		sleep: func(_ context.Context, d time.Duration) error {
			clock = clock.Add(d)
			return nil
		},
	}
}

func TestDNS01SolverPresentWaitsForPropagation(t *testing.T) {
	fqdn := "_acme-challenge.host.example.com."
	value := "the-dns01-digest-value"
	prov := newRecordingProvider()
	res := &fakeResolver{
		txt:            map[string][]string{"_acme-challenge.host.example.com": {"unrelated", value}},
		availableAfter: 3,
	}
	s := newTestSolver(prov, res, 5*time.Second, 10*time.Millisecond)

	if err := s.present(context.Background(), fqdn, value); err != nil {
		t.Fatalf("present: %v", err)
	}
	if prov.presented[fqdn] != value {
		t.Fatalf("provider was not asked to publish %s=%s", fqdn, value)
	}
	if res.callCount() < 3 {
		t.Fatalf("propagation polled %d times, want >= 3", res.callCount())
	}
	if prov.cleaned[fqdn] != 0 {
		t.Fatal("cleanup ran despite successful propagation")
	}
}

func TestDNS01SolverPropagationTimeoutCleansUp(t *testing.T) {
	fqdn := "_acme-challenge.host.example.com."
	value := "never-visible"
	prov := newRecordingProvider()
	res := &fakeResolver{txt: map[string][]string{}} // record never appears
	s := newTestSolver(prov, res, 100*time.Millisecond, 10*time.Millisecond)

	err := s.present(context.Background(), fqdn, value)
	if err == nil {
		t.Fatal("present succeeded even though the record never propagated")
	}
	if !strings.Contains(err.Error(), "did not propagate") {
		t.Fatalf("error = %v, want a propagation-timeout error", err)
	}
	// A failed propagation must withdraw the record it published.
	if prov.cleaned[fqdn] == 0 {
		t.Fatal("record was not withdrawn after propagation timeout")
	}
}

func TestDNS01SolverPropagationSkippedWhenTimeoutZero(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{}}
	s := newTestSolver(newRecordingProvider(), res, 0, 10*time.Millisecond)
	if err := s.present(context.Background(), "_acme-challenge.x.example.com.", "v"); err != nil {
		t.Fatalf("present: %v", err)
	}
	if res.callCount() != 0 {
		t.Fatalf("resolver queried %d times with propagation disabled, want 0", res.callCount())
	}
}

func TestDNS01SolverPropagationSurfacesLookupError(t *testing.T) {
	res := &fakeResolver{err: errors.New("servfail")}
	s := newTestSolver(newRecordingProvider(), res, 30*time.Millisecond, 10*time.Millisecond)
	err := s.waitPropagation(context.Background(), "_acme-challenge.x.example.com.", "v")
	if err == nil || !strings.Contains(err.Error(), "servfail") {
		t.Fatalf("error = %v, want it to mention the lookup failure", err)
	}
}

func TestChallengeRecordName(t *testing.T) {
	cases := map[string]string{
		"example.com":  "_acme-challenge.example.com.",
		"example.com.": "_acme-challenge.example.com.",
		"a.b.example":  "_acme-challenge.a.b.example.",
	}
	for in, want := range cases {
		if got := challengeRecordName(in); got != want {
			t.Errorf("challengeRecordName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":            "1.2.3.4:53",
		"1.2.3.4:5353":       "1.2.3.4:5353",
		"ns.example":         "ns.example:53",
		"2001:db8::1":        "[2001:db8::1]:53",
		"[2001:db8::1]:5353": "[2001:db8::1]:5353",
	}
	for in, want := range cases {
		if got := withDefaultPort(in, "53"); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- dns-01 config validation ----

func dns01ConfigYAML(acmeBlock string) string {
	return `state_dir: /tmp/agent
trust:
  bundle_file: /tmp/trust.pem
acme:
  directory: https://pki.example.test/acme/directory
` + acmeBlock + `
certificates:
  - name: web
    enroll: acme
    dns_names: [web.example.com]
    key_file: /tmp/web.key
    cert_file: /tmp/web.crt
`
}

func TestDNS01ConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		acmeBlock string
		wantErr   string
	}{
		{
			name: "valid rfc2136",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: rfc2136
    rfc2136:
      server: ns.example.com
      tsig_name: acme-key.
      tsig_secret: c2VjcmV0LWtleQ==`,
		},
		{
			name: "valid exec",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: exec
    exec:
      present: /usr/local/bin/present.sh`,
		},
		{
			name: "valid route53",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: route53
    route53:
      hosted_zone_id: Z123`,
		},
		{
			name: "rfc2136 missing server",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: rfc2136
    rfc2136:
      tsig_name: acme-key.
      tsig_secret: c2VjcmV0`,
			wantErr: "rfc2136.server is required",
		},
		{
			name: "rfc2136 missing secret",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: rfc2136
    rfc2136:
      server: ns.example.com
      tsig_name: acme-key.`,
			wantErr: "tsig_secret",
		},
		{
			name: "rfc2136 bad algorithm",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: rfc2136
    rfc2136:
      server: ns.example.com
      tsig_name: acme-key.
      tsig_secret: c2VjcmV0
      tsig_algorithm: hmac-md5`,
			wantErr: "unsupported tsig_algorithm",
		},
		{
			name: "exec missing present",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: exec
    exec:
      cleanup: /bin/true`,
			wantErr: "exec.present command is required",
		},
		{
			name: "unknown provider",
			acmeBlock: `  challenge: dns-01
  dns01:
    provider: cloudflare`,
			wantErr: "unknown provider",
		},
		{
			name: "provider required",
			acmeBlock: `  challenge: dns-01
  dns01: {}`,
			wantErr: "provider is required",
		},
		{
			name: "bad challenge value",
			acmeBlock: `  challenge: tls-alpn-01
  dns01:
    provider: exec
    exec:
      present: /bin/true`,
			wantErr: "acme.challenge must be",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(dns01ConfigYAML(tc.acmeBlock)))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestWildcardRequiresDNS01(t *testing.T) {
	wildcardCert := `
certificates:
  - name: wild
    enroll: acme
    dns_names: ["*.example.com"]
    key_file: /tmp/wild.key
    cert_file: /tmp/wild.crt
`
	// http-01 (default) must reject a wildcard.
	httpCfg := `state_dir: /tmp/agent
trust:
  bundle_file: /tmp/trust.pem
acme:
  directory: https://pki.example.test/acme/directory
` + wildcardCert
	if _, err := ParseConfig([]byte(httpCfg)); err == nil || !strings.Contains(err.Error(), "dns-01") {
		t.Fatalf("wildcard under http-01: error = %v, want a dns-01 requirement", err)
	}

	// dns-01 must accept it.
	dnsCfg := `state_dir: /tmp/agent
trust:
  bundle_file: /tmp/trust.pem
acme:
  directory: https://pki.example.test/acme/directory
  challenge: dns-01
  dns01:
    provider: exec
    exec:
      present: /bin/true
` + wildcardCert
	if _, err := ParseConfig([]byte(dnsCfg)); err != nil {
		t.Fatalf("wildcard under dns-01 should be accepted: %v", err)
	}
}
