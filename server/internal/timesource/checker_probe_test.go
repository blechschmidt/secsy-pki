package timesource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestCheckerProbeIsAlwaysFresh pins the contract that separates Probe from Now:
// `secsy-ca doctor` uses Probe to answer "is the clock trustworthy right now",
// so it must never be served from (nor poison) the refresh-window cache that Now
// maintains. A cached Probe would report a stale verdict after an operator fixed
// the clock — or, worse, hide a drift that started inside the window.
func TestCheckerProbeIsAlwaysFresh(t *testing.T) {
	p := &fakeProvider{name: "probe-src", offset: 2 * time.Second}
	c := NewChecker([]Provider{p}, CheckerOptions{
		Threshold:       10 * time.Second,
		RefreshInterval: time.Hour,
		SourceType:      "nts",
	})
	host := time.Unix(1_700_000_000, 0)
	c.SetNow(func() time.Time { return host })

	// Prime the cache with a successful Now.
	if _, err := c.Now(context.Background()); err != nil {
		t.Fatalf("priming Now: %v", err)
	}
	if got := p.queries.Load(); got != 1 {
		t.Fatalf("after priming, queries = %d, want 1", got)
	}

	// Each Probe must query again despite the hour-long refresh window.
	for i := 1; i <= 2; i++ {
		res := c.Probe(context.Background())
		if res.Cached {
			t.Fatal("Probe must never report a cached result")
		}
		if !res.Passed {
			t.Fatalf("probe %d should pass at a 2s offset: %s", i, res.Detail())
		}
		if want := int64(1 + i); p.queries.Load() != want {
			t.Fatalf("after probe %d, queries = %d, want %d", i, p.queries.Load(), want)
		}
	}

	// Probe must not have disturbed the cache Now relies on.
	if _, err := c.Now(context.Background()); err != nil {
		t.Fatalf("Now after Probe: %v", err)
	}
	if got := p.queries.Load(); got != 3 {
		t.Fatalf("Now re-queried after Probe (queries = %d, want 3): Probe overwrote the cache window", got)
	}
}

// TestCheckerProbeReportsPerSourceDetail checks the payload doctor renders: a
// probe must carry one sample per configured source, with the error text for the
// unreachable ones, and the representative (largest-magnitude) offset.
func TestCheckerProbeReportsPerSourceDetail(t *testing.T) {
	near := &fakeProvider{name: "near", offset: 1 * time.Second}
	far := &fakeProvider{name: "far", offset: -40 * time.Second}
	down := &fakeProvider{name: "down", err: errors.New("i/o timeout")}

	c := NewChecker([]Provider{near, far, down}, CheckerOptions{
		Threshold:  10 * time.Second,
		SourceType: "roughtime",
	})
	c.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0) })

	res := c.Probe(context.Background())
	if len(res.Samples) != 3 {
		t.Fatalf("Probe returned %d samples, want one per source", len(res.Samples))
	}
	if res.Reachable != 2 {
		t.Fatalf("Reachable = %d, want 2", res.Reachable)
	}
	// The worst offset wins, sign preserved, so a host that is behind is not
	// masked by a source that agrees.
	if res.Offset != -40*time.Second {
		t.Fatalf("Offset = %v, want the largest-magnitude sample (-40s)", res.Offset)
	}
	if res.Passed || res.Reason != reasonDrift {
		t.Fatalf("Probe should fail closed on drift, got passed=%v reason=%q", res.Passed, res.Reason)
	}
	if res.SourceType != "roughtime" || res.Threshold != 10*time.Second {
		t.Fatalf("Probe must echo the configuration, got %q / %v", res.SourceType, res.Threshold)
	}
	var sawErrText bool
	for _, s := range res.Samples {
		if s.Source == "down" {
			if s.Err == nil || !strings.Contains(s.ErrText, "i/o timeout") {
				t.Fatalf("unreachable sample lost its error: %+v", s)
			}
			sawErrText = true
		}
	}
	if !sawErrText {
		t.Fatal("the unreachable source is missing from the samples")
	}
	// Detail is what lands in the audit event; it must name the reason and every
	// source without leaking anything else.
	detail := res.Detail()
	for _, want := range []string{"reason=drift", "source=roughtime", "near=", "far=", "down=error("} {
		if !strings.Contains(detail, want) {
			t.Fatalf("Detail() = %q, want it to contain %q", detail, want)
		}
	}
}

// TestDriftErrorMessage covers both rendering branches of the error the TSA
// surfaces when it refuses to sign. The two cases need different wording: an
// unreachable source is an availability problem an operator fixes at the
// network, while drift is a clock problem.
func TestDriftErrorMessage(t *testing.T) {
	cases := []struct {
		name     string
		err      *DriftError
		contains []string
		absent   []string
	}{
		{
			name: "unreachable names the source and the transport detail",
			err: &DriftError{
				Reason: reasonUnreachable,
				Source: "time.example",
				Detail: "dial udp: i/o timeout",
			},
			contains: []string{"unreachable", "time.example", "dial udp: i/o timeout"},
			absent:   []string{"drift"},
		},
		{
			name: "drift reports the measured offset against the threshold",
			err: &DriftError{
				Reason:    reasonDrift,
				Offset:    90*time.Second + 400*time.Microsecond,
				Threshold: 10 * time.Second,
				Source:    "nts",
			},
			// The offset is rounded to milliseconds for legibility.
			contains: []string{"drift", "1m30s", "exceeds threshold 10s", "nts"},
			absent:   []string{"unreachable"},
		},
		{
			// An empty reason must still render the drift form rather than
			// producing an empty message.
			name:     "unset reason falls back to the drift wording",
			err:      &DriftError{Offset: time.Second, Threshold: 10 * time.Second, Source: "src"},
			contains: []string{"drift", "exceeds threshold"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("DriftError.Error() must not be empty")
			}
			for _, want := range tc.contains {
				if !strings.Contains(msg, want) {
					t.Fatalf("Error() = %q, want it to contain %q", msg, want)
				}
			}
			for _, bad := range tc.absent {
				if strings.Contains(msg, bad) {
					t.Fatalf("Error() = %q, want it not to contain %q", msg, bad)
				}
			}
			// It must satisfy errors.As through the interface, which is how the
			// TSA distinguishes a fail-closed refusal from an internal error.
			var target *DriftError
			if !errors.As(error(tc.err), &target) {
				t.Fatal("a *DriftError must be recoverable with errors.As")
			}
		})
	}
}
