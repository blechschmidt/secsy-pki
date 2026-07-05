package acme

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Multi-Perspective Issuance Corroboration (MPIC), CA/Browser Forum ballot
// SC-067. Domain-control validation performed from a single network vantage
// point is vulnerable to a localized BGP or DNS hijack: an attacker who can
// intercept the CA's validation traffic on one path forges a passing response,
// and the CA cannot tell the difference. MPIC corroborates the same challenge
// check from several independent network perspectives and only accepts the
// result when a quorum of them agree, so a hijack confined to one path is
// outvoted by the honest perspectives that reach the real target.
//
// The layer is pluggable: a Perspective is any vantage point that can perform
// the three domain-control checks (http-01 fetch, dns-01 TXT lookup,
// tls-alpn-01 dial). The built-in implementation wraps a *Validator configured
// with its own resolver and outbound proxy so each perspective sees the network
// from a distinct location; tests inject in-process fakes. Production wiring —
// standing up the remote proxies/resolvers — is entirely a configuration
// concern (acme.mpic), so this package adds no real remote infrastructure.

// Perspective is a single network vantage point that independently performs an
// ACME domain-control challenge check. Each perspective resolves names and
// egresses traffic from its own location, so its view of the target can differ
// from the CA's primary view under a localized hijack. The methods mirror
// *Validator exactly, so a *Validator drives one perspective; the interface
// exists so tests can substitute deterministic fakes and so remote perspectives
// with distinct resolver/dialer configuration are interchangeable.
type Perspective interface {
	// Name identifies the perspective in metrics, audit records, and logs. It
	// must be unique across the primary and all remotes.
	Name() string
	ValidateHTTP01(ctx context.Context, domain, token, keyAuth string) *Problem
	ValidateDNS01(ctx context.Context, domain, keyAuth string) *Problem
	ValidateTLSALPN01(ctx context.Context, identifier, keyAuth string) *Problem
}

// validatorPerspective adapts a *Validator (the concrete network checker) to the
// Perspective interface by pairing it with a stable name.
type validatorPerspective struct {
	name string
	v    *Validator
}

func (p *validatorPerspective) Name() string { return p.name }

func (p *validatorPerspective) ValidateHTTP01(ctx context.Context, domain, token, keyAuth string) *Problem {
	return p.v.ValidateHTTP01(ctx, domain, token, keyAuth)
}

func (p *validatorPerspective) ValidateDNS01(ctx context.Context, domain, keyAuth string) *Problem {
	return p.v.ValidateDNS01(ctx, domain, keyAuth)
}

func (p *validatorPerspective) ValidateTLSALPN01(ctx context.Context, identifier, keyAuth string) *Problem {
	return p.v.ValidateTLSALPN01(ctx, identifier, keyAuth)
}

// outcome classifies one perspective's result for quorum accounting.
type outcome int

const (
	// outcomeCorroborated: the perspective completed the check and agreed the
	// challenge is satisfied (a nil Problem).
	outcomeCorroborated outcome = iota
	// outcomeRejected: the perspective completed the check but got a definitive
	// wrong/absent response (e.g. probUnauthorized, probIncorrectResponse). This
	// is the meaningful dissent signal: under a localized hijack of the primary
	// path the honest remotes reach the real target, find no challenge, and
	// reject.
	outcomeRejected
	// outcomeUnavailable: the perspective could not complete the check at all —
	// a transport/DNS/TLS reachability failure or a timeout. It is not a
	// definitive answer, so it never counts toward corroboration and it is
	// tracked separately so that mass MPIC-infrastructure degradation fails
	// closed rather than silently passing.
	outcomeUnavailable
)

func (o outcome) String() string {
	switch o {
	case outcomeCorroborated:
		return "corroborated"
	case outcomeRejected:
		return "rejected"
	default:
		return "unavailable"
	}
}

// classifyProblem maps a challenge-check Problem to an MPIC outcome. A nil
// problem is corroboration; a connection/DNS/TLS problem is an incomplete check
// (unavailable); anything else is a definitive rejection.
func classifyProblem(p *Problem) outcome {
	if p == nil {
		return outcomeCorroborated
	}
	switch p.Type {
	case probConnection, probDNS, probTLS:
		return outcomeUnavailable
	default:
		return outcomeRejected
	}
}

// perspectiveResult records one perspective's check for reporting.
type perspectiveResult struct {
	Name    string
	Outcome outcome
	Problem *Problem      // nil when corroborated
	Latency time.Duration // wall-clock of this perspective's check
}

// QuorumPolicy expresses the SC-067 corroboration rule: how many distinct remote
// perspectives must agree, and how many may dissent, scaled to the number of
// perspectives used.
type QuorumPolicy struct {
	// MinPerspectives is the minimum number of remote perspectives that must
	// return a *definitive* result (corroboration or rejection — not a
	// transport/timeout failure) before a quorum decision is trusted. If fewer
	// respond, corroboration fails closed: a degraded MPIC deployment must never
	// silently collapse back to single-perspective validation. Default 2.
	MinPerspectives int
	// MaxFailures caps the number of non-corroborating remote perspectives
	// tolerated (rejections and unavailables both count as failures, per SC-067,
	// which treats any non-corroboration alike). A negative value (the default)
	// derives the cap from the SC-067 scaling table via allowedFailures.
	MaxFailures int
	// RequireAll demands that every attempted remote perspective corroborate,
	// ignoring MaxFailures. Off by default; useful for a small, highly-reliable
	// perspective set.
	RequireAll bool
}

// withDefaults fills zero-valued policy fields with their defaults.
func (q QuorumPolicy) withDefaults() QuorumPolicy {
	if q.MinPerspectives <= 0 {
		q.MinPerspectives = 2
	}
	if q.MaxFailures == 0 {
		// Distinguish "explicitly zero" from "unset": zero would mean "no failures
		// allowed", which is RequireAll. Callers wanting zero set RequireAll. An
		// unset MaxFailures (the common case) is expressed as the SC-067 table,
		// which we signal internally with -1.
		q.MaxFailures = -1
	}
	return q
}

// allowedFailures returns the maximum number of non-corroborating remote
// perspectives tolerated for a given count of perspectives actually used,
// implementing the CA/Browser Forum SC-067 scaling table:
//
//	perspectives used   allowed non-corroborations
//	         1                       0
//	       2 – 5                     1
//	        6 +                      2
//
// An explicit non-negative MaxFailures overrides the table; RequireAll forces 0.
func (q QuorumPolicy) allowedFailures(used int) int {
	if q.RequireAll {
		return 0
	}
	if q.MaxFailures >= 0 {
		if q.MaxFailures > used {
			return used
		}
		return q.MaxFailures
	}
	switch {
	case used <= 1:
		return 0
	case used <= 5:
		return 1
	default:
		return 2
	}
}

// requiredCorroborations returns the minimum number of remote perspectives that
// must corroborate for the quorum to hold: the number used minus the failures
// allowed. This is the SC-067 "minimum distinct perspectives that must
// corroborate", never below one when any perspective is used.
func (q QuorumPolicy) requiredCorroborations(used int) int {
	req := used - q.allowedFailures(used)
	if used > 0 && req < 1 {
		req = 1
	}
	return req
}

// quorumStatus is the outcome of evaluating the remote-perspective quorum.
type quorumStatus int

const (
	quorumCorroborated  quorumStatus = iota // enough remotes agreed
	quorumFailedQuorum                      // too many remotes dissented
	quorumFailedNoQuota                     // too few remotes responded (fail-closed)
)

// evaluate applies the quorum policy to the remote perspective results. It first
// enforces the fail-closed floor (enough perspectives must have returned a
// definitive answer), then the SC-067 corroboration count.
func (q QuorumPolicy) evaluate(remotes []perspectiveResult) quorumStatus {
	used := len(remotes)
	corroborated, responded := 0, 0
	for _, r := range remotes {
		switch r.Outcome {
		case outcomeCorroborated:
			corroborated++
			responded++
		case outcomeRejected:
			responded++
		case outcomeUnavailable:
			// neither corroborates nor counts as a definitive response
		}
	}
	// Fail closed if too few perspectives could actually be reached to make a
	// trustworthy determination. This is the guard that keeps a broken MPIC
	// deployment (all proxies down, resolvers unreachable) from silently issuing
	// on the primary alone.
	if responded < q.MinPerspectives {
		return quorumFailedNoQuota
	}
	if corroborated < q.requiredCorroborations(used) {
		return quorumFailedQuorum
	}
	return quorumCorroborated
}

// Result is the aggregate outcome of a corroborated challenge check.
type Result struct {
	// Problem is nil when the challenge is satisfied (primary passed and, when
	// MPIC applies, the remote quorum held); otherwise it is the ACME problem to
	// fail the challenge with.
	Problem *Problem
	// Applied reports whether the SC-067 remote quorum was evaluated. It is false
	// when MPIC is disabled, when no remote perspectives are configured, or when
	// the primary check failed (nothing to corroborate) — in those cases the
	// result is exactly the primary's, preserving pre-MPIC behavior.
	Applied bool
	// QuorumResult labels the decision for metrics/audit: corroborated,
	// primary_failed, failed_quorum, or failed_unresponsive. Empty when MPIC is
	// disabled.
	QuorumResult string
	// Primary is the primary (local) perspective's result.
	Primary perspectiveResult
	// Remotes holds each remote perspective's result, in configured order.
	Remotes []perspectiveResult
}

// Metric label values for ACMEMPICQuorum.QuorumResult.
const (
	mpicResultCorroborated = "corroborated"
	mpicResultPrimaryFail  = "primary_failed"
	mpicResultFailQuorum   = "failed_quorum"
	mpicResultFailNoQuota  = "failed_unresponsive"
)

// auditDetail renders a compact, deterministic per-perspective summary for the
// acme.mpic audit record, e.g.
// "http-01 www.example.com: primary=corroborated remotes=[eu-west=corroborated us-east=rejected]".
func (res *Result) auditDetail(challengeType, identifier string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: primary=%s remotes=[", challengeType, identifier, res.Primary.Outcome)
	for i, r := range res.Remotes {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", r.Name, r.Outcome)
	}
	b.WriteString("] result=")
	b.WriteString(res.QuorumResult)
	return b.String()
}

// Coordinator runs a challenge check across the primary perspective and any
// configured remote perspectives and applies the SC-067 quorum policy. A
// disabled Coordinator (the default) runs only the primary, so behavior is
// identical to the pre-MPIC single-perspective validator.
//
// A Coordinator is safe for concurrent use once constructed.
type Coordinator struct {
	// Enabled turns on remote corroboration. When false, Corroborate runs only
	// the primary perspective.
	Enabled bool
	// Remotes are the operator-configured remote perspectives corroboration is
	// evaluated over.
	Remotes []Perspective
	// Policy is the SC-067 quorum rule applied to the remote results.
	Policy QuorumPolicy
	// Timeout bounds each individual perspective's check (default 10s).
	Timeout time.Duration
}

// mpicDefaultTimeout bounds a single perspective's challenge check when the
// coordinator is not given an explicit per-perspective timeout.
const mpicDefaultTimeout = 10 * time.Second

// perspectiveTimeout returns the effective per-perspective timeout.
func (c *Coordinator) perspectiveTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return mpicDefaultTimeout
}

// checkFunc performs one challenge check against a given perspective. The
// coordinator supplies the perspective; the closure (built per challenge type)
// captures the identifier, token, and key authorization.
type checkFunc func(ctx context.Context, p Perspective) *Problem

// Corroborate runs check against the primary perspective and, when MPIC is
// enabled and remotes are configured, against every remote perspective
// concurrently, then applies the quorum policy. primary is supplied by the
// caller so that an overridden validator (tests, split-horizon deployments)
// flows through transparently. check captures the identifier, token, and key
// authorization; the caller labels metrics/audit by challenge type and
// identifier from the returned Result.
//
// The primary is authoritative: if it does not corroborate, the challenge fails
// with the primary's problem and no remote work is done — there is nothing to
// corroborate, and this is exactly the pre-MPIC behavior. Only a passing primary
// is put to the remote quorum.
func (c *Coordinator) Corroborate(ctx context.Context, primary Perspective, check checkFunc) *Result {
	res := &Result{}
	// The primary runs under the caller's context unchanged — it is the server's
	// own validator, which already carries its own client/dial timeouts, so a
	// disabled coordinator behaves exactly as the pre-MPIC single validator. Only
	// the remote perspectives are additionally bounded by the per-perspective
	// timeout below.
	res.Primary = runCheck(ctx, primary, check)

	// A failing primary short-circuits: no corroboration is possible or needed.
	if res.Primary.Outcome != outcomeCorroborated {
		res.Problem = res.Primary.Problem
		if c.Enabled && len(c.Remotes) > 0 {
			res.QuorumResult = mpicResultPrimaryFail
		}
		return res
	}

	// MPIC off, or no remotes configured: the primary's success stands alone,
	// preserving single-perspective behavior.
	if !c.Enabled || len(c.Remotes) == 0 {
		return res
	}

	res.Applied = true
	res.Remotes = c.runRemotes(ctx, check)

	switch c.Policy.evaluate(res.Remotes) {
	case quorumCorroborated:
		res.QuorumResult = mpicResultCorroborated
	case quorumFailedQuorum:
		res.QuorumResult = mpicResultFailQuorum
		res.Problem = c.quorumProblem(res, false)
	case quorumFailedNoQuota:
		res.QuorumResult = mpicResultFailNoQuota
		res.Problem = c.quorumProblem(res, true)
	}
	return res
}

// runRemotes fans the check out to every remote perspective concurrently, each
// bounded by the per-perspective timeout, preserving configured order in the
// returned slice.
func (c *Coordinator) runRemotes(ctx context.Context, check checkFunc) []perspectiveResult {
	results := make([]perspectiveResult, len(c.Remotes))
	var wg sync.WaitGroup
	for i, p := range c.Remotes {
		wg.Add(1)
		go func(i int, p Perspective) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, c.perspectiveTimeout())
			defer cancel()
			results[i] = runCheck(pctx, p, check)
		}(i, p)
	}
	wg.Wait()
	return results
}

// runCheck executes a single perspective's check and classifies the outcome. The
// caller supplies the context (with whatever deadline applies), so the primary
// runs under the caller's context and remotes run under the per-perspective
// timeout.
func runCheck(ctx context.Context, p Perspective, check checkFunc) perspectiveResult {
	start := time.Now()
	prob := check(ctx, p)
	return perspectiveResult{
		Name:    p.Name(),
		Outcome: classifyProblem(prob),
		Problem: prob,
		Latency: time.Since(start),
	}
}

// quorumProblem builds the ACME problem returned when the remote quorum is not
// met. Domain control could not be corroborated across enough network
// perspectives, so the challenge is unauthorized. The detail names the dissenting
// perspectives so an operator (and the client) can see which vantage points
// disagreed — the localized-hijack fingerprint.
func (c *Coordinator) quorumProblem(res *Result, unresponsive bool) *Problem {
	var dissent []string
	for _, r := range res.Remotes {
		if r.Outcome != outcomeCorroborated {
			dissent = append(dissent, fmt.Sprintf("%s=%s", r.Name, r.Outcome))
		}
	}
	sort.Strings(dissent)
	if unresponsive {
		return newProblem(probUnauthorized, http.StatusForbidden,
			"multi-perspective corroboration failed closed: too few remote perspectives returned a definitive result "+
				"("+strings.Join(dissent, " ")+")")
	}
	return newProblem(probUnauthorized, http.StatusForbidden,
		"domain control could not be corroborated from enough network perspectives (SC-067): "+
			strings.Join(dissent, " "))
}

// ---- construction from config ---------------------------------------------

// MPICConfig configures the Multi-Perspective Issuance Corroboration layer. It
// is disabled by default; when disabled the coordinator runs only the primary
// perspective and behavior is identical to the pre-MPIC validator.
type MPICConfig struct {
	// Enabled turns on remote corroboration.
	Enabled bool
	// Perspectives are the remote vantage points. Each must set at least one of
	// DNSResolver or ProxyURL so its network view actually differs from the
	// primary's.
	Perspectives []PerspectiveConfig
	// Policy is the quorum rule (SC-067). Zero-valued fields take their defaults.
	Policy QuorumPolicy
	// Timeout bounds each perspective's individual check (default 10s). A
	// per-perspective override on PerspectiveConfig wins.
	Timeout time.Duration
}

// PerspectiveConfig describes one remote perspective's distinct network view.
// A remote perspective differs from the primary by resolving names through a
// different DNS server and/or egressing its HTTP/TLS traffic through a different
// outbound proxy, so it reaches the target over an independent network path.
type PerspectiveConfig struct {
	// Name uniquely identifies the perspective (e.g. "eu-west", "us-east").
	Name string
	// DNSResolver (host:port), when set, pins this perspective's dns-01 TXT
	// lookups — and, absent a proxy, its http-01/tls-alpn-01 name resolution — to
	// that DNS server, giving the perspective a distinct DNS view.
	DNSResolver string
	// ProxyURL (socks5://host:port or socks5h://host:port), when set, routes this
	// perspective's http-01 fetches and tls-alpn-01 dials through an outbound
	// SOCKS5 proxy, so the TCP connection to the target egresses from the proxy's
	// network location — a genuinely remote vantage point. With socks5h the proxy
	// also resolves the target hostname, so the connection follows the remote
	// site's DNS/routing view end to end.
	ProxyURL string
	// Timeout overrides the coordinator-wide per-perspective timeout for this
	// perspective (useful when a distant perspective needs a longer budget).
	Timeout time.Duration
}

// newCoordinator builds a Coordinator from configuration. It constructs each
// remote perspective's dedicated *Validator (with its own resolver and outbound
// proxy) using the primary's challenge ports so ports stay consistent across
// perspectives. It returns an error for a structurally invalid perspective so
// misconfiguration surfaces at startup rather than at the first challenge.
func newCoordinator(cfg MPICConfig, httpPort, tlsALPNPort int) (*Coordinator, error) {
	// A disabled block is fully inert: don't build remote dialers or validate
	// perspectives (config.validateACMEMPIC likewise skips a disabled block), so a
	// commented-out or half-drafted perspective list never affects a server that
	// isn't using MPIC.
	if !cfg.Enabled {
		return &Coordinator{Policy: cfg.Policy.withDefaults(), Timeout: cfg.Timeout}, nil
	}
	c := &Coordinator{
		Enabled: cfg.Enabled,
		Policy:  cfg.Policy.withDefaults(),
		Timeout: cfg.Timeout,
	}
	seen := map[string]bool{"primary": true}
	for i, pc := range cfg.Perspectives {
		name := strings.TrimSpace(pc.Name)
		if name == "" {
			return nil, fmt.Errorf("acme.mpic.perspectives[%d]: name must not be empty", i)
		}
		if seen[name] {
			return nil, fmt.Errorf("acme.mpic.perspectives[%d]: duplicate perspective name %q (\"primary\" is reserved)", i, name)
		}
		seen[name] = true
		if pc.DNSResolver == "" && pc.ProxyURL == "" {
			return nil, fmt.Errorf("acme.mpic.perspectives[%q]: set at least one of dns_resolver or proxy_url so the perspective's view differs from the primary", name)
		}
		v, err := buildPerspectiveValidator(pc, httpPort, tlsALPNPort)
		if err != nil {
			return nil, fmt.Errorf("acme.mpic.perspectives[%q]: %w", name, err)
		}
		c.Remotes = append(c.Remotes, &validatorPerspective{name: name, v: v})
	}
	// When enabled, the deployment must actually be able to reach the SC-067
	// floor; a perspective set smaller than the quorum minimum can never
	// corroborate and would fail every issuance closed.
	if c.Enabled && len(c.Remotes) < c.Policy.MinPerspectives {
		return nil, fmt.Errorf("acme.mpic.enabled requires at least %d remote perspective(s) (quorum min_perspectives), got %d",
			c.Policy.MinPerspectives, len(c.Remotes))
	}
	return c, nil
}

// buildPerspectiveValidator constructs the *Validator backing one remote
// perspective, composing an optional pinned DNS resolver and an optional
// outbound SOCKS5 proxy into the HTTP client, DNS resolver, and TLS dialer.
func buildPerspectiveValidator(pc PerspectiveConfig, httpPort, tlsALPNPort int) (*Validator, error) {
	timeout := pc.Timeout
	if timeout <= 0 {
		timeout = mpicDefaultTimeout
	}
	base := &net.Dialer{Timeout: timeout}

	v := &Validator{
		Resolver:    net.DefaultResolver,
		HTTPPort:    httpPort,
		TLSALPNPort: tlsALPNPort,
	}

	// A pinned DNS resolver gives the perspective its own dns-01 TXT view and,
	// when no proxy resolves remotely, its own name→address resolution.
	var pinned *net.Resolver
	if addr := strings.TrimSpace(pc.DNSResolver); addr != "" {
		pinned = pinnedResolver(addr)
		v.Resolver = pinned
	}

	// The dial function used for both the http-01 fetch and the tls-alpn-01
	// handshake. Layered: a SOCKS5 proxy relocates egress; otherwise a pinned
	// resolver (if any) steers name resolution before a direct dial.
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if raw := strings.TrimSpace(pc.ProxyURL); raw != "" {
		pd, err := proxyDialContext(raw, base)
		if err != nil {
			return nil, err
		}
		dial = pd
	} else if pinned != nil {
		dial = resolvingDialContext(pinned)
	} else {
		dial = base.DialContext
	}

	v.HTTPClient = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext:         dial,
			TLSHandshakeTimeout: timeout,
		},
	}
	v.TLSDialContext = dial
	return v, nil
}

// proxyDialContext returns a DialContext that tunnels through the SOCKS5 proxy
// named by rawURL. Only socks5/socks5h are supported: SOCKS5 tunnels arbitrary
// TCP, so a single proxy relocates egress for both the http-01 fetch and the
// tls-alpn-01 handshake. socks5h additionally resolves the destination hostname
// at the proxy, following the remote site's DNS view end to end.
func proxyDialContext(rawURL string, forward *net.Dialer) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy_url %q: %w", rawURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy_url scheme %q (only socks5:// and socks5h:// are supported)", u.Scheme)
	}
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("configuring SOCKS5 proxy %q: %w", u.Host, err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// Every x/net/proxy SOCKS5 dialer implements ContextDialer; guard defensively.
		return func(_ context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}, nil
	}
	return cd.DialContext, nil
}
