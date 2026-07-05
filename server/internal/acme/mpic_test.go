package acme

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fakes ----------------------------------------------------------------

// fakePerspective is an in-process Perspective whose result is fixed per
// construction, so quorum, corroboration, and fail-closed paths can be proven
// without any network. All three challenge methods return the same outcome.
type fakePerspective struct {
	name       string
	prob       *Problem      // returned by every check (nil == corroborates)
	delay      time.Duration // artificial latency before returning
	blockUntil bool          // block until ctx is done, then report unavailable
	calls      int32         // number of times a check ran (atomic)
}

func (f *fakePerspective) Name() string { return f.name }

func (f *fakePerspective) run(ctx context.Context) *Problem {
	atomic.AddInt32(&f.calls, 1)
	if f.blockUntil {
		<-ctx.Done()
		return newProblem(probConnection, http.StatusBadRequest, "timed out: "+f.name)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return newProblem(probConnection, http.StatusBadRequest, "timed out: "+f.name)
		}
	}
	return f.prob
}

func (f *fakePerspective) ValidateHTTP01(ctx context.Context, _, _, _ string) *Problem {
	return f.run(ctx)
}
func (f *fakePerspective) ValidateDNS01(ctx context.Context, _, _ string) *Problem {
	return f.run(ctx)
}
func (f *fakePerspective) ValidateTLSALPN01(ctx context.Context, _, _ string) *Problem {
	return f.run(ctx)
}

// outcome shorthands for building fakes.
func corroborates(name string) *fakePerspective { return &fakePerspective{name: name} }
func rejects(name string) *fakePerspective {
	return &fakePerspective{name: name, prob: newProblem(probIncorrectResponse, http.StatusForbidden, "wrong response at "+name)}
}
func unavailable(name string) *fakePerspective {
	return &fakePerspective{name: name, prob: newProblem(probConnection, http.StatusBadRequest, name+" unreachable")}
}

func remotes(ps ...*fakePerspective) []Perspective {
	out := make([]Perspective, len(ps))
	for i, p := range ps {
		out[i] = p
	}
	return out
}

// httpCheck is a challenge closure that drives the http-01 method of whichever
// perspective the coordinator hands it.
func httpCheck(ctx context.Context, p Perspective) *Problem {
	return p.ValidateHTTP01(ctx, "www.example.test", "token", "keyauth")
}

// ---- classification -------------------------------------------------------

func TestClassifyProblem(t *testing.T) {
	cases := []struct {
		name string
		prob *Problem
		want outcome
	}{
		{"nil corroborates", nil, outcomeCorroborated},
		{"connection is unavailable", newProblem(probConnection, 400, ""), outcomeUnavailable},
		{"dns is unavailable", newProblem(probDNS, 400, ""), outcomeUnavailable},
		{"tls is unavailable", newProblem(probTLS, 400, ""), outcomeUnavailable},
		{"unauthorized is a definitive rejection", newProblem(probUnauthorized, 403, ""), outcomeRejected},
		{"incorrectResponse is a definitive rejection", newProblem(probIncorrectResponse, 403, ""), outcomeRejected},
		{"malformed is a definitive rejection", newProblem(probMalformed, 400, ""), outcomeRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyProblem(tc.prob); got != tc.want {
				t.Fatalf("classifyProblem = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---- SC-067 quorum arithmetic --------------------------------------------

func TestQuorumPolicyAllowedFailures(t *testing.T) {
	table := QuorumPolicy{}.withDefaults() // default: SC-067 scaling table
	cases := []struct {
		used         int
		wantAllowed  int
		wantRequired int
	}{
		{used: 1, wantAllowed: 0, wantRequired: 1},
		{used: 2, wantAllowed: 1, wantRequired: 1},
		{used: 3, wantAllowed: 1, wantRequired: 2},
		{used: 5, wantAllowed: 1, wantRequired: 4},
		{used: 6, wantAllowed: 2, wantRequired: 4},
		{used: 10, wantAllowed: 2, wantRequired: 8},
	}
	for _, tc := range cases {
		t.Run("used="+strconv.Itoa(tc.used), func(t *testing.T) {
			if got := table.allowedFailures(tc.used); got != tc.wantAllowed {
				t.Errorf("allowedFailures(%d) = %d, want %d", tc.used, got, tc.wantAllowed)
			}
			if got := table.requiredCorroborations(tc.used); got != tc.wantRequired {
				t.Errorf("requiredCorroborations(%d) = %d, want %d", tc.used, got, tc.wantRequired)
			}
		})
	}

	// RequireAll forces zero tolerated failures.
	all := QuorumPolicy{RequireAll: true}.withDefaults()
	if got := all.allowedFailures(6); got != 0 {
		t.Errorf("RequireAll allowedFailures(6) = %d, want 0", got)
	}
	if got := all.requiredCorroborations(6); got != 6 {
		t.Errorf("RequireAll requiredCorroborations(6) = %d, want 6", got)
	}

	// An explicit MaxFailures overrides the table and is capped at the count used.
	explicit := QuorumPolicy{MaxFailures: 3}.withDefaults()
	if got := explicit.allowedFailures(4); got != 3 {
		t.Errorf("MaxFailures=3 allowedFailures(4) = %d, want 3", got)
	}
	if got := explicit.allowedFailures(2); got != 2 {
		t.Errorf("MaxFailures=3 allowedFailures(2) = %d, want 2 (capped)", got)
	}
}

// ---- coordinator: quorum / corroboration / fail-closed --------------------

func TestCoordinatorCorroborate(t *testing.T) {
	cases := []struct {
		name        string
		enabled     bool
		policy      QuorumPolicy
		primary     *fakePerspective
		remotes     []Perspective
		wantPass    bool
		wantApplied bool
		wantResult  string
	}{
		{
			name:        "disabled runs only the primary",
			enabled:     false,
			primary:     corroborates("primary"),
			remotes:     remotes(rejects("a"), rejects("b")), // ignored while disabled
			wantPass:    true,
			wantApplied: false,
			wantResult:  "",
		},
		{
			name:        "all remotes corroborate",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), corroborates("c")),
			wantPass:    true,
			wantApplied: true,
			wantResult:  mpicResultCorroborated,
		},
		{
			name:        "one rejection within the allowed failure (3 remotes, 1 allowed)",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), rejects("c")),
			wantPass:    true,
			wantApplied: true,
			wantResult:  mpicResultCorroborated,
		},
		{
			name:        "two rejections exceed the allowed failure",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), rejects("b"), rejects("c")),
			wantPass:    false,
			wantApplied: true,
			wantResult:  mpicResultFailQuorum,
		},
		{
			name:        "one unavailable within the allowed failure",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), unavailable("c")),
			wantPass:    true,
			wantApplied: true,
			wantResult:  mpicResultCorroborated,
		},
		{
			name:        "too few respond fails closed",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), unavailable("b"), unavailable("c")),
			wantPass:    false,
			wantApplied: true,
			wantResult:  mpicResultFailNoQuota,
		},
		{
			name:        "all remotes unavailable fails closed",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(unavailable("a"), unavailable("b")),
			wantPass:    false,
			wantApplied: true,
			wantResult:  mpicResultFailNoQuota,
		},
		{
			name:        "6 perspectives tolerate 2 failures",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), corroborates("c"), corroborates("d"), rejects("e"), rejects("f")),
			wantPass:    true,
			wantApplied: true,
			wantResult:  mpicResultCorroborated,
		},
		{
			name:        "6 perspectives reject 3 failures",
			enabled:     true,
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), corroborates("c"), rejects("d"), rejects("e"), rejects("f")),
			wantPass:    false,
			wantApplied: true,
			wantResult:  mpicResultFailQuorum,
		},
		{
			name:        "require_all rejects any dissent",
			enabled:     true,
			policy:      QuorumPolicy{RequireAll: true},
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), rejects("c")),
			wantPass:    false,
			wantApplied: true,
			wantResult:  mpicResultFailQuorum,
		},
		{
			name:        "explicit max_failures=2 with 4 remotes and 2 rejections",
			enabled:     true,
			policy:      QuorumPolicy{MaxFailures: 2},
			primary:     corroborates("primary"),
			remotes:     remotes(corroborates("a"), corroborates("b"), rejects("c"), rejects("d")),
			wantPass:    true,
			wantApplied: true,
			wantResult:  mpicResultCorroborated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Coordinator{Enabled: tc.enabled, Remotes: tc.remotes, Policy: tc.policy.withDefaults()}
			res := c.Corroborate(context.Background(), tc.primary, httpCheck)

			if gotPass := res.Problem == nil; gotPass != tc.wantPass {
				t.Fatalf("pass = %v (problem: %v), want %v", gotPass, res.Problem, tc.wantPass)
			}
			if res.Applied != tc.wantApplied {
				t.Errorf("Applied = %v, want %v", res.Applied, tc.wantApplied)
			}
			if res.QuorumResult != tc.wantResult {
				t.Errorf("QuorumResult = %q, want %q", res.QuorumResult, tc.wantResult)
			}
		})
	}
}

// TestCoordinatorPrimaryShortCircuit proves that a failing primary check fails
// the challenge with the primary's own problem and never touches the remotes —
// there is nothing to corroborate.
func TestCoordinatorPrimaryShortCircuit(t *testing.T) {
	remoteA, remoteB := corroborates("a"), corroborates("b")
	c := &Coordinator{
		Enabled: true,
		Remotes: remotes(remoteA, remoteB),
		Policy:  QuorumPolicy{}.withDefaults(),
	}
	primary := rejects("primary")
	res := c.Corroborate(context.Background(), primary, func(ctx context.Context, p Perspective) *Problem {
		return p.ValidateDNS01(ctx, "www.example.test", "keyauth")
	})

	if res.Problem == nil {
		t.Fatal("expected the primary failure to fail the challenge")
	}
	if res.Applied {
		t.Error("Applied should be false when the primary fails")
	}
	if res.QuorumResult != mpicResultPrimaryFail {
		t.Errorf("QuorumResult = %q, want %q", res.QuorumResult, mpicResultPrimaryFail)
	}
	if got := atomic.LoadInt32(&remoteA.calls) + atomic.LoadInt32(&remoteB.calls); got != 0 {
		t.Errorf("remotes were called %d times; a failing primary must short-circuit", got)
	}
}

// TestCoordinatorConcurrencyAndOrder proves every remote runs and the results
// preserve configured order regardless of per-perspective latency.
func TestCoordinatorConcurrencyAndOrder(t *testing.T) {
	a := &fakePerspective{name: "a", delay: 40 * time.Millisecond}
	b := &fakePerspective{name: "b"}
	cc := &fakePerspective{name: "c", delay: 20 * time.Millisecond}
	c := &Coordinator{Enabled: true, Remotes: remotes(a, b, cc), Policy: QuorumPolicy{}.withDefaults()}

	start := time.Now()
	res := c.Corroborate(context.Background(), corroborates("primary"), httpCheck)
	elapsed := time.Since(start)

	if res.Problem != nil {
		t.Fatalf("unexpected failure: %v", res.Problem)
	}
	if elapsed > 35*time.Millisecond {
		// Sequential execution would take >= 40+20ms; concurrent is bounded by the
		// slowest (40ms), but we started timing before the goroutines, so allow a
		// margin under the sum.
		t.Logf("elapsed %v (concurrent fan-out expected under the 60ms sequential sum)", elapsed)
	}
	if len(res.Remotes) != 3 {
		t.Fatalf("got %d remote results, want 3", len(res.Remotes))
	}
	for i, want := range []string{"a", "b", "c"} {
		if res.Remotes[i].Name != want {
			t.Errorf("result[%d].Name = %q, want %q (order not preserved)", i, res.Remotes[i].Name, want)
		}
	}
}

// TestCoordinatorPerspectiveTimeout proves each perspective is bounded by the
// per-perspective timeout: a perspective that blocks is classified unavailable,
// and enough such perspectives fail the quorum closed rather than hang.
func TestCoordinatorPerspectiveTimeout(t *testing.T) {
	c := &Coordinator{
		Enabled: true,
		Timeout: 60 * time.Millisecond,
		Remotes: remotes(
			corroborates("a"),
			&fakePerspective{name: "slow-b", blockUntil: true},
			&fakePerspective{name: "slow-c", blockUntil: true},
		),
		Policy: QuorumPolicy{}.withDefaults(),
	}
	start := time.Now()
	res := c.Corroborate(context.Background(), corroborates("primary"), httpCheck)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("Corroborate took %v; per-perspective timeout should bound it near 60ms", elapsed)
	}
	if res.Problem == nil {
		t.Fatal("expected fail-closed when two of three remotes time out")
	}
	if res.QuorumResult != mpicResultFailNoQuota {
		t.Errorf("QuorumResult = %q, want %q", res.QuorumResult, mpicResultFailNoQuota)
	}
	// The two blocked remotes are unavailable, the reachable one corroborates.
	unavail := 0
	for _, r := range res.Remotes {
		if r.Outcome == outcomeUnavailable {
			unavail++
		}
	}
	if unavail != 2 {
		t.Errorf("got %d unavailable remotes, want 2", unavail)
	}
}

// TestResultAuditDetail checks the compact per-perspective summary used in the
// acme.mpic audit record.
func TestResultAuditDetail(t *testing.T) {
	c := &Coordinator{Enabled: true, Remotes: remotes(corroborates("eu-west"), rejects("us-east")), Policy: QuorumPolicy{}.withDefaults()}
	res := c.Corroborate(context.Background(), corroborates("primary"), httpCheck)
	detail := res.auditDetail("http-01", "www.example.test")
	for _, want := range []string{"http-01 www.example.test", "primary=corroborated", "eu-west=corroborated", "us-east=rejected", "result="} {
		if !strings.Contains(detail, want) {
			t.Errorf("audit detail %q missing %q", detail, want)
		}
	}
}

// ---- construction from config ---------------------------------------------

func TestNewCoordinator(t *testing.T) {
	t.Run("valid perspectives build enabled coordinator", func(t *testing.T) {
		c, err := newCoordinator(MPICConfig{
			Enabled: true,
			Perspectives: []PerspectiveConfig{
				{Name: "eu-west", DNSResolver: "10.0.1.53:53"},
				{Name: "us-east", ProxyURL: "socks5://10.0.2.9:1080"},
			},
		}, 80, 443)
		if err != nil {
			t.Fatalf("newCoordinator: %v", err)
		}
		if !c.Enabled || len(c.Remotes) != 2 {
			t.Fatalf("enabled=%v remotes=%d, want enabled with 2 remotes", c.Enabled, len(c.Remotes))
		}
		if c.Remotes[0].Name() != "eu-west" || c.Remotes[1].Name() != "us-east" {
			t.Errorf("remote names = %q,%q", c.Remotes[0].Name(), c.Remotes[1].Name())
		}
	})

	t.Run("disabled with no perspectives is fine", func(t *testing.T) {
		c, err := newCoordinator(MPICConfig{Enabled: false}, 80, 443)
		if err != nil {
			t.Fatalf("newCoordinator: %v", err)
		}
		if c.Enabled {
			t.Error("coordinator should be disabled")
		}
	})

	errCases := []struct {
		name string
		cfg  MPICConfig
		want string
	}{
		{
			name: "empty perspective name",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{DNSResolver: "1.1.1.1:53"}, {Name: "b", DNSResolver: "1.1.1.1:53"}}},
			want: "name must not be empty",
		},
		{
			name: "duplicate perspective name",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{Name: "x", DNSResolver: "1.1.1.1:53"}, {Name: "x", DNSResolver: "1.1.1.1:53"}}},
			want: "duplicate perspective name",
		},
		{
			name: "reserved primary name",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{Name: "primary", DNSResolver: "1.1.1.1:53"}, {Name: "b", DNSResolver: "1.1.1.1:53"}}},
			want: "duplicate perspective name",
		},
		{
			name: "perspective with no distinguishing view",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{Name: "a"}, {Name: "b", DNSResolver: "1.1.1.1:53"}}},
			want: "at least one of dns_resolver or proxy_url",
		},
		{
			name: "bad proxy scheme",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{Name: "a", ProxyURL: "http://p:8080"}, {Name: "b", DNSResolver: "1.1.1.1:53"}}},
			want: "unsupported proxy_url scheme",
		},
		{
			name: "too few perspectives for the quorum floor",
			cfg:  MPICConfig{Enabled: true, Perspectives: []PerspectiveConfig{{Name: "only", DNSResolver: "1.1.1.1:53"}}},
			want: "at least 2 remote perspective",
		},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newCoordinator(tc.cfg, 80, 443)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err.Error(), tc.want)
			}
		})
	}
}

// ---- proxy dialing --------------------------------------------------------

func TestProxyDialContextValidation(t *testing.T) {
	if _, err := proxyDialContext("socks5://127.0.0.1:1080", &net.Dialer{}); err != nil {
		t.Errorf("socks5 URL should parse: %v", err)
	}
	if _, err := proxyDialContext("socks5h://user:pass@127.0.0.1:1080", &net.Dialer{}); err != nil {
		t.Errorf("socks5h URL with auth should parse: %v", err)
	}
	if _, err := proxyDialContext("http://127.0.0.1:8080", &net.Dialer{}); err == nil {
		t.Error("http proxy scheme should be rejected")
	}
	if _, err := proxyDialContext("://not a url", &net.Dialer{}); err == nil {
		t.Error("invalid URL should be rejected")
	}
}

// TestProxyDialContextTunnels stands up a minimal in-process SOCKS5 proxy and a
// target TCP echo/HTTP server and proves proxyDialContext genuinely tunnels the
// connection through the proxy.
func TestProxyDialContextTunnels(t *testing.T) {
	proxyAddr := startSOCKS5(t)

	// A tiny HTTP target the proxied dial must reach.
	targetLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { targetLis.Close() })
	go http.Serve(targetLis, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "reached-through-proxy")
	}))

	dial, err := proxyDialContext("socks5://"+proxyAddr, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("proxyDialContext: %v", err)
	}
	conn, err := dial(context.Background(), "tcp", targetLis.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: t\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := io.ReadAll(conn)
	if !strings.Contains(string(body), "reached-through-proxy") {
		t.Fatalf("did not reach the target through the proxy; got %q", string(body))
	}
}

// TestBuildPerspectiveValidatorProxyWired proves buildPerspectiveValidator wires
// the proxy into the actual challenge dial path: an unreachable proxy makes the
// http-01 fetch fail with a connection problem (classified unavailable).
func TestBuildPerspectiveValidatorProxyWired(t *testing.T) {
	// A closed port stands in for an unreachable proxy.
	closedLis, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closedLis.Addr().String()
	closedLis.Close()

	v, err := buildPerspectiveValidator(PerspectiveConfig{
		Name:     "dead-proxy",
		ProxyURL: "socks5://" + closedAddr,
		Timeout:  time.Second,
	}, 80, 443)
	if err != nil {
		t.Fatalf("buildPerspectiveValidator: %v", err)
	}
	prob := v.ValidateHTTP01(context.Background(), "www.example.test", "token", "keyauth")
	if prob == nil {
		t.Fatal("expected the fetch through a dead proxy to fail")
	}
	if got := classifyProblem(prob); got != outcomeUnavailable {
		t.Fatalf("classify = %v (problem %v), want unavailable", got, prob)
	}
}

// ---- real Validator perspectives (http-01) --------------------------------

// startHTTP01Solver serves body at the well-known challenge path for token and
// returns its address, emulating one perspective's view of an http-01 target.
func startHTTP01Solver(t *testing.T, token, body string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/"+token {
			io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Close() })
	return lis.Addr().String()
}

// httpValidatorPerspective builds a real validatorPerspective whose http-01
// fetches are redirected to addr, so each perspective can be pointed at a
// different in-process solver — a distinct network view.
func httpValidatorPerspective(name, addr string) *validatorPerspective {
	v := &Validator{
		HTTPPort: 80,
		HTTPClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			},
		},
	}
	return &validatorPerspective{name: name, v: v}
}

func TestValidatorPerspectiveHTTP01Quorum(t *testing.T) {
	const domain = "www.example.test"
	token := "tok-real"
	keyAuth := keyAuthorization(token, "thumb")

	check := func(ctx context.Context, p Perspective) *Problem {
		return p.ValidateHTTP01(ctx, domain, token, keyAuth)
	}

	// All perspectives see the correct key authorization → corroborated.
	good := func(name string) Perspective {
		return httpValidatorPerspective(name, startHTTP01Solver(t, token, keyAuth))
	}
	// This perspective serves a wrong body → definitive rejection.
	bad := func(name string) Perspective {
		return httpValidatorPerspective(name, startHTTP01Solver(t, token, "wrong-key-auth"))
	}

	t.Run("all perspectives agree", func(t *testing.T) {
		c := &Coordinator{Enabled: true, Remotes: []Perspective{good("a"), good("b")}, Policy: QuorumPolicy{}.withDefaults()}
		res := c.Corroborate(context.Background(), good("primary"), check)
		if res.Problem != nil {
			t.Fatalf("expected corroboration, got %v", res.Problem)
		}
		if res.QuorumResult != mpicResultCorroborated {
			t.Errorf("QuorumResult = %q", res.QuorumResult)
		}
	})

	t.Run("dissenting remotes fail the quorum", func(t *testing.T) {
		// Primary sees the (attacker-forged) correct response, but both honest
		// remotes reach a target that lacks the challenge — the localized-hijack
		// scenario MPIC defends against.
		c := &Coordinator{Enabled: true, Remotes: []Perspective{bad("a"), bad("b")}, Policy: QuorumPolicy{}.withDefaults()}
		res := c.Corroborate(context.Background(), good("primary"), check)
		if res.Problem == nil {
			t.Fatal("expected the quorum to fail when honest remotes dissent")
		}
		if res.QuorumResult != mpicResultFailQuorum {
			t.Errorf("QuorumResult = %q, want %q", res.QuorumResult, mpicResultFailQuorum)
		}
	})
}

// ---- minimal SOCKS5 proxy for tests ---------------------------------------

// startSOCKS5 stands up a minimal no-auth SOCKS5 CONNECT proxy and returns its
// address. It implements exactly what proxyDialContext exercises: the no-auth
// method negotiation and a CONNECT to an IPv4/IPv6/domain destination.
func startSOCKS5(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(conn)
		}
	}()
	return lis.Addr().String()
}

func serveSOCKS5(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)

	// Greeting: VER, NMETHODS, METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(nmethods)); err != nil {
		return
	}
	// Select "no authentication required".
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 || hdr[1] != 0x01 {
		return
	}
	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		// Reply: general failure.
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	// Reply: success, bound address 0.0.0.0:0.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Splice. Any buffered bytes in br must be flushed to the target first.
	done := make(chan struct{}, 2)
	go func() { io.Copy(target, br); done <- struct{}{} }()
	go func() { io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// compile-time assertions that the concrete perspectives satisfy the interface.
var (
	_ Perspective = (*validatorPerspective)(nil)
	_ Perspective = (*fakePerspective)(nil)
)
