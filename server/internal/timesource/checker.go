package timesource

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Default checker tunables. They are deliberately conservative: a threshold
// large enough that ordinary NTP-disciplined clocks never trip it, a refresh
// window that bounds external queries (and audit spam) under a busy TSA, and a
// per-query timeout short enough to fail fast.
const (
	defaultThreshold   = 10 * time.Second
	defaultRefresh     = 60 * time.Second
	defaultFailRefresh = 15 * time.Second
	defaultTimeout     = 5 * time.Second
	defaultMinSources  = 1
)

// CheckerOptions configures a Checker. Threshold is the only field an operator
// must think about; the rest have safe defaults applied by NewChecker.
type CheckerOptions struct {
	// Threshold is the maximum tolerated absolute offset between the host clock
	// and any reachable trusted source before the check fails closed. Defaults to
	// 10s when unset.
	Threshold time.Duration
	// RefreshInterval bounds how often the external source(s) are actually
	// queried: a successful check is cached for this long and reused, so a busy
	// TSA does not hammer the NTS/Roughtime servers (nor spam the audit log) on
	// every request. Defaults to 60s. A failed check is cached for a shorter
	// window so recovery is detected promptly.
	RefreshInterval time.Duration
	// Timeout bounds a single provider query. Defaults to 5s.
	Timeout time.Duration
	// MinSources is the minimum number of reachable sources a check requires;
	// below it the unreachable-source policy applies. Defaults to 1.
	MinSources int
	// FailOpenOnUnreachable selects the unreachable-source policy. False (the
	// default, fail closed) refuses to sign when fewer than MinSources sources
	// are reachable — the safe choice for a trust anchor. True (fail open) lets
	// signing proceed on the host clock when the source(s) cannot be reached,
	// trading trust for availability. Drift beyond Threshold ALWAYS fails closed
	// regardless of this setting.
	FailOpenOnUnreachable bool
	// SourceType labels the check in metrics and audit ("nts"|"roughtime").
	SourceType string
	// Auditor, when non-nil, is invoked with the CheckResult on every fresh
	// (uncached) check that fails closed, so the wiring can append a tamper-
	// evident audit event. The drift metric is recorded regardless.
	Auditor func(CheckResult)
}

// CheckResult is the outcome of one cross-check of the host clock against the
// trusted source(s).
type CheckResult struct {
	// At is the host time at which the check ran.
	At time.Time `json:"at"`
	// SourceType is the configured source kind ("nts"|"roughtime").
	SourceType string `json:"source_type"`
	// Samples holds each source's reading (or its error).
	Samples []Sample `json:"samples"`
	// Offset is the representative (largest-magnitude) signed offset among the
	// reachable sources: positive means the host clock is ahead.
	Offset time.Duration `json:"offset"`
	// Threshold echoes the configured drift threshold.
	Threshold time.Duration `json:"threshold"`
	// Reachable counts sources that returned a good reading.
	Reachable int `json:"reachable"`
	// Passed reports whether the host clock is trusted (within threshold, and
	// enough sources reachable per policy).
	Passed bool `json:"passed"`
	// Cached is true when this result was served from the refresh-window cache
	// rather than a fresh query.
	Cached bool `json:"cached"`
	// Reason classifies a failure: "drift", "unreachable", or "" on success.
	Reason string `json:"reason,omitempty"`
}

// Failure-reason labels (also the reason label on the failure metric).
const (
	reasonDrift       = "drift"
	reasonUnreachable = "unreachable"
)

// Detail renders the result as a compact, credential-free one-liner for audit
// events and logs.
func (r CheckResult) Detail() string {
	var parts []string
	if r.Reason != "" {
		parts = append(parts, "reason="+r.Reason)
	}
	parts = append(parts,
		fmt.Sprintf("source=%s", r.SourceType),
		fmt.Sprintf("offset=%s", r.Offset.Round(time.Millisecond)),
		fmt.Sprintf("threshold=%s", r.Threshold),
		fmt.Sprintf("reachable=%d", r.Reachable))
	for _, s := range r.Samples {
		if s.Err != nil {
			parts = append(parts, fmt.Sprintf("%s=error(%s)", s.Source, s.ErrText))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", s.Source, s.Offset.Round(time.Millisecond)))
	}
	return strings.Join(parts, " ")
}

// DriftError is returned by Checker.Now when the host clock cannot be trusted.
// It carries the offset and threshold so callers (the TSA, the anchor service)
// can surface a precise fail-closed reason.
type DriftError struct {
	Reason    string
	Offset    time.Duration
	Threshold time.Duration
	Source    string
	Detail    string
}

func (e *DriftError) Error() string {
	switch e.Reason {
	case reasonUnreachable:
		return fmt.Sprintf("trusted time source (%s) unreachable: %s", e.Source, e.Detail)
	default:
		return fmt.Sprintf("host clock drift %s exceeds threshold %s against trusted source (%s)",
			e.Offset.Round(time.Millisecond), e.Threshold, e.Source)
	}
}

// Checker cross-checks the host clock against one or more trusted time sources
// and fails closed when the drift exceeds the threshold. It satisfies the Clock
// interface. It is safe for concurrent use.
type Checker struct {
	providers  []Provider
	threshold  time.Duration
	refresh    time.Duration
	timeout    time.Duration
	minSources int
	failOpen   bool
	sourceType string
	auditor    func(CheckResult)

	// now is the host clock, overridable in tests via SetNow.
	now func() time.Time

	mu         sync.Mutex
	last       CheckResult
	lastExpiry time.Time // host time at which the cached result goes stale
}

// NewChecker builds a Checker over the given providers. It panics only on
// programmer error (no providers); callers construct providers from validated
// config, so the provider list is non-empty in practice.
func NewChecker(providers []Provider, opts CheckerOptions) *Checker {
	if opts.Threshold <= 0 {
		opts.Threshold = defaultThreshold
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = defaultRefresh
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MinSources <= 0 {
		opts.MinSources = defaultMinSources
	}
	return &Checker{
		providers:  providers,
		threshold:  opts.Threshold,
		refresh:    opts.RefreshInterval,
		timeout:    opts.Timeout,
		minSources: opts.MinSources,
		failOpen:   opts.FailOpenOnUnreachable,
		sourceType: opts.SourceType,
		auditor:    opts.Auditor,
		now:        time.Now,
	}
}

// SetNow overrides the host clock (tests only), so a fake host time can be
// paired with a fake provider to exercise a precise offset.
func (c *Checker) SetNow(now func() time.Time) { c.now = now }

// Describe returns a short, credential-free description of the configured source.
func (c *Checker) Describe() string {
	names := make([]string, 0, len(c.providers))
	for _, p := range c.providers {
		names = append(names, p.Name())
	}
	return fmt.Sprintf("%s: %s (max drift %s)", c.sourceType, strings.Join(names, ", "), c.threshold)
}

// Now returns the host time to stamp with, having validated it against the
// trusted source(s). It serves a recent successful check from the refresh-window
// cache to bound external queries; otherwise it performs a fresh check. On a
// fail-closed outcome it returns a *DriftError and the caller MUST refuse to
// sign.
func (c *Checker) Now(ctx context.Context) (time.Time, error) {
	host := c.now()

	c.mu.Lock()
	if !c.lastExpiry.IsZero() && host.Before(c.lastExpiry) {
		cached := c.last
		c.mu.Unlock()
		cached.Cached = true
		metrics.TimeChecks.Inc("cached")
		if cached.Passed {
			return host, nil
		}
		return time.Time{}, driftError(cached)
	}
	c.mu.Unlock()

	res := c.check(ctx, host)

	c.mu.Lock()
	c.last = res
	if res.Passed {
		c.lastExpiry = host.Add(c.refresh)
	} else {
		// Cache failures only briefly so a recovered clock is picked up quickly,
		// while still bounding re-query/audit rate under sustained drift.
		window := c.refresh
		if defaultFailRefresh < window {
			window = defaultFailRefresh
		}
		c.lastExpiry = host.Add(window)
	}
	c.mu.Unlock()

	if res.Passed {
		return host, nil
	}
	return time.Time{}, driftError(res)
}

// Probe performs a fresh, uncached cross-check and returns the full result. It
// is the read-only entry point for `secsy-ca doctor` (time.trusted): it records
// the same metrics as Now but hands the caller the per-source detail instead of
// just a pass/fail time.
func (c *Checker) Probe(ctx context.Context) CheckResult {
	return c.check(ctx, c.now())
}

// check queries every provider, computes the representative offset, records
// metrics, invokes the auditor on a fresh failure, and returns the result. It
// never consults or updates the cache — Now and Probe own that.
func (c *Checker) check(ctx context.Context, host time.Time) CheckResult {
	res := CheckResult{
		At:         host,
		SourceType: c.sourceType,
		Threshold:  c.threshold,
		Passed:     true,
	}

	var worst time.Duration // largest-magnitude offset among reachable sources
	for _, p := range c.providers {
		s := c.query(ctx, p)
		res.Samples = append(res.Samples, s)
		if s.Err != nil {
			continue
		}
		res.Reachable++
		// Record each reachable source's measured offset for observability.
		metrics.TimeDriftSeconds.Set(s.Offset.Seconds(), s.Source)
		if abs(s.Offset) > abs(worst) {
			worst = s.Offset
		}
	}
	res.Offset = worst

	switch {
	case res.Reachable < c.minSources:
		if c.failOpen {
			// Fail open: no trusted reading, but the operator chose availability.
			// The metric still records the reachability failure for alerting.
			metrics.TimeCheckFailures.Inc(reasonUnreachable)
			metrics.TimeChecks.Inc("pass")
			return res
		}
		res.Passed = false
		res.Reason = reasonUnreachable
	case abs(worst) > c.threshold:
		res.Passed = false
		res.Reason = reasonDrift
	}

	if res.Passed {
		metrics.TimeChecks.Inc("pass")
		return res
	}
	metrics.TimeChecks.Inc("fail")
	metrics.TimeCheckFailures.Inc(res.Reason)
	if c.auditor != nil {
		c.auditor(res)
	}
	return res
}

// query runs one provider with the per-query timeout and turns its Reading into
// a Sample. The provider measures the host-minus-source offset itself (around
// its tight request/response exchange), so the Checker simply records it.
func (c *Checker) query(ctx context.Context, p Provider) Sample {
	qctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	reading, err := p.Now(qctx)

	s := Sample{Source: p.Name()}
	if err != nil {
		s.Err = err
		s.ErrText = err.Error()
		return s
	}
	s.Time = reading.Time
	s.RTT = reading.RTT
	s.Offset = reading.Offset
	return s
}

// driftError builds the fail-closed error from a failed result, picking the
// worst reachable sample (or the first error) for the human message.
func driftError(res CheckResult) error {
	e := &DriftError{
		Reason:    res.Reason,
		Offset:    res.Offset,
		Threshold: res.Threshold,
		Source:    res.SourceType,
		Detail:    res.Detail(),
	}
	// Prefer a concrete source name and, for unreachable, the first error text.
	sorted := append([]Sample(nil), res.Samples...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return abs(sorted[i].Offset) > abs(sorted[j].Offset)
	})
	for _, s := range sorted {
		if res.Reason == reasonUnreachable && s.Err != nil {
			e.Source = s.Source
			e.Detail = s.ErrText
			break
		}
		if res.Reason == reasonDrift && s.Err == nil {
			e.Source = s.Source
			break
		}
	}
	return e
}
