package timesource

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// fakeProvider is a trusted-time Provider that returns a fixed offset (to inject
// drift) or a fixed error (to simulate unreachability). It counts queries so the
// cache behavior can be verified.
type fakeProvider struct {
	name    string
	offset  time.Duration
	err     error
	queries atomic.Int64
}

func (f *fakeProvider) Now(ctx context.Context) (Reading, error) {
	f.queries.Add(1)
	if f.err != nil {
		return Reading{}, f.err
	}
	// Time is cosmetic; Offset drives the decision.
	return Reading{Time: time.Now().Add(-f.offset), Offset: f.offset}, nil
}

func (f *fakeProvider) Name() string { return f.name }

func TestCheckerWithinThresholdPasses(t *testing.T) {
	p := &fakeProvider{name: "fake", offset: 2 * time.Second}
	c := NewChecker([]Provider{p}, CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"})

	host := time.Unix(1_700_000_000, 0)
	c.SetNow(func() time.Time { return host })

	got, err := c.Now(context.Background())
	if err != nil {
		t.Fatalf("Now within threshold should pass: %v", err)
	}
	if !got.Equal(host) {
		t.Fatalf("Now should return the host clock %v, got %v", host, got)
	}
}

func TestCheckerDriftFailsClosed(t *testing.T) {
	p := &fakeProvider{name: "fake", offset: 90 * time.Second}
	var audited []CheckResult
	c := NewChecker([]Provider{p}, CheckerOptions{
		Threshold:  10 * time.Second,
		SourceType: "fake",
		Auditor:    func(r CheckResult) { audited = append(audited, r) },
	})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	_, err := c.Now(context.Background())
	if err == nil {
		t.Fatal("Now should fail closed when drift exceeds the threshold")
	}
	var de *DriftError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DriftError, got %T: %v", err, err)
	}
	if de.Reason != reasonDrift {
		t.Fatalf("reason = %q, want %q", de.Reason, reasonDrift)
	}
	if len(audited) != 1 {
		t.Fatalf("auditor should fire exactly once on a fresh failure, fired %d times", len(audited))
	}
	if !audited[0].Passed && audited[0].Reason != reasonDrift {
		t.Fatalf("audited result reason = %q", audited[0].Reason)
	}
}

func TestCheckerUnreachableFailClosed(t *testing.T) {
	p := &fakeProvider{name: "fake", err: errors.New("dial timeout")}
	c := NewChecker([]Provider{p}, CheckerOptions{Threshold: 10 * time.Second, SourceType: "nts"})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	_, err := c.Now(context.Background())
	if err == nil {
		t.Fatal("Now should fail closed when the only source is unreachable")
	}
	var de *DriftError
	if !errors.As(err, &de) || de.Reason != reasonUnreachable {
		t.Fatalf("expected unreachable DriftError, got %v", err)
	}
}

func TestCheckerUnreachableFailOpen(t *testing.T) {
	p := &fakeProvider{name: "fake", err: errors.New("dial timeout")}
	host := time.Unix(1_700_000_000, 0)
	c := NewChecker([]Provider{p}, CheckerOptions{
		Threshold:             10 * time.Second,
		SourceType:            "nts",
		FailOpenOnUnreachable: true,
	})
	c.SetNow(func() time.Time { return host })

	got, err := c.Now(context.Background())
	if err != nil {
		t.Fatalf("fail-open should allow signing when the source is unreachable: %v", err)
	}
	if !got.Equal(host) {
		t.Fatalf("Now should return the host clock, got %v", got)
	}
}

func TestCheckerCachesSuccessfulResult(t *testing.T) {
	p := &fakeProvider{name: "fake", offset: 1 * time.Second}
	c := NewChecker([]Provider{p}, CheckerOptions{
		Threshold:       10 * time.Second,
		RefreshInterval: time.Minute,
		SourceType:      "fake",
	})
	base := time.Unix(1_700_000_000, 0)
	now := base
	c.SetNow(func() time.Time { return now })

	if _, err := c.Now(context.Background()); err != nil {
		t.Fatalf("first check: %v", err)
	}
	// Advance the host clock less than the refresh window: no re-query.
	now = base.Add(10 * time.Second)
	if _, err := c.Now(context.Background()); err != nil {
		t.Fatalf("cached check: %v", err)
	}
	if q := p.queries.Load(); q != 1 {
		t.Fatalf("expected 1 provider query within the refresh window, got %d", q)
	}
	// Advance beyond the refresh window: a fresh query happens.
	now = base.Add(2 * time.Minute)
	if _, err := c.Now(context.Background()); err != nil {
		t.Fatalf("refreshed check: %v", err)
	}
	if q := p.queries.Load(); q != 2 {
		t.Fatalf("expected a re-query after the refresh window, got %d queries", q)
	}
}

func TestCheckerMultipleSourcesAnyDisagreementFails(t *testing.T) {
	good := &fakeProvider{name: "good", offset: 1 * time.Second}
	bad := &fakeProvider{name: "bad", offset: 5 * time.Minute}
	c := NewChecker([]Provider{good, bad}, CheckerOptions{Threshold: 10 * time.Second, SourceType: "roughtime"})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	if _, err := c.Now(context.Background()); err == nil {
		t.Fatal("a single disagreeing source must fail the check (conservative)")
	}
}

func TestCheckerMinSourcesQuorum(t *testing.T) {
	reachable := &fakeProvider{name: "up", offset: 1 * time.Second}
	down := &fakeProvider{name: "down", err: errors.New("timeout")}
	// Require 2 reachable sources; only 1 answers → fail closed.
	c := NewChecker([]Provider{reachable, down}, CheckerOptions{
		Threshold:  10 * time.Second,
		MinSources: 2,
		SourceType: "nts",
	})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	_, err := c.Now(context.Background())
	var de *DriftError
	if !errors.As(err, &de) || de.Reason != reasonUnreachable {
		t.Fatalf("min_sources=2 with 1 reachable should fail unreachable, got %v", err)
	}
}

func TestCheckerRecordsMetrics(t *testing.T) {
	p := &fakeProvider{name: "metricsrc", offset: 45 * time.Second}
	c := NewChecker([]Provider{p}, CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	before := scrapeMetric(t, `secsy_time_check_failures_total{reason="drift"}`)
	if _, err := c.Now(context.Background()); err == nil {
		t.Fatal("expected drift failure")
	}
	after := scrapeMetric(t, `secsy_time_check_failures_total{reason="drift"}`)
	if after <= before {
		t.Fatalf("drift failure counter did not increase: before=%v after=%v", before, after)
	}
	// The per-source drift gauge must be exposed for the queried source.
	if !metricPresent(t, `secsy_time_drift_seconds{source="metricsrc"}`) {
		t.Fatal("expected secsy_time_drift_seconds gauge for the source")
	}
}

func TestSystemClockNeverFails(t *testing.T) {
	c := System()
	got, err := c.Now(context.Background())
	if err != nil {
		t.Fatalf("System clock must never fail: %v", err)
	}
	if time.Since(got) > time.Minute {
		t.Fatalf("System clock returned an implausible time: %v", got)
	}
	if c.Describe() == "" {
		t.Fatal("Describe should be non-empty")
	}
}

func TestFixedClock(t *testing.T) {
	want := time.Unix(1234567890, 0)
	c := Fixed(func() time.Time { return want })
	got, err := c.Now(context.Background())
	if err != nil || !got.Equal(want) {
		t.Fatalf("Fixed clock: got %v err %v, want %v", got, err, want)
	}
}

// scrapeMetric returns the value of a single metric series from the default
// registry, or 0 when absent.
func scrapeMetric(t *testing.T, series string) float64 {
	t.Helper()
	for _, line := range strings.Split(scrape(t), "\n") {
		if strings.HasPrefix(line, series+" ") {
			fields := strings.Fields(strings.TrimPrefix(line, series+" "))
			if len(fields) == 0 {
				continue
			}
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return v
			}
		}
	}
	return 0
}

func metricPresent(t *testing.T, series string) bool {
	t.Helper()
	for _, line := range strings.Split(scrape(t), "\n") {
		if strings.HasPrefix(line, series+" ") {
			return true
		}
	}
	return false
}

func scrape(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := metrics.Default.WriteTo(&b); err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	return b.String()
}
