//go:build sqlite

package chaos

// Scenario 4 — rate-limit and HSM concurrency-guard saturation (Task 25).
//
// Drives the real public-endpoint middleware over httptest with a deliberately
// tiny token-bucket and a single-slot concurrency guard, then asserts the
// documented backpressure contract: rate-limit saturation returns 429 and
// guard saturation returns 503, both carrying a Retry-After header, and both
// recording the rejection in the metrics registry. No HSM or DB is involved, so
// this scenario is fully deterministic and always runs.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ratelimit"
)

// okHandler is the downstream the middleware protects; it 200s unless a barrier
// is installed to hold the request open (used to pin the guard's only slot).
func okHandler(hold <-chan struct{}, entered chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if entered != nil {
			entered <- struct{}{}
		}
		if hold != nil {
			<-hold
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestChaosRateLimitReturns429(t *testing.T) {
	// One token of burst on the per-IP tier: the first request is admitted, the
	// second from the same IP is throttled. new-order is an ACME endpoint, so a
	// throttle must be reported as an RFC 8555 problem+json with Retry-After.
	limiter := ratelimit.NewTieredLimiter(ratelimit.LimiterConfig{
		PerIP: ratelimit.Rate{Rate: 1, Burst: 1},
	})
	mw := ratelimit.New(ratelimit.Options{
		Limiter:  limiter,
		Prefixes: ratelimit.Prefixes{ACME: "/acme"},
	})
	h := mw.Handler(okHandler(nil, nil))

	before := metricValue(t, renderMetrics(t), `secsy_ratelimit_throttled_total{endpoint="acme_new_order",tier="per_ip"}`)

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
		r.RemoteAddr = "203.0.113.7:5000" // one host -> one per-IP bucket
		return r
	}

	// First request: admitted (200).
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, newReq())
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", rec1.Code)
	}

	// Second request: throttled (429) with Retry-After and ACME problem+json.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newReq())
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", rec2.Code)
	}
	if ra := rec2.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 response missing a positive Retry-After header (got %q)", ra)
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("ACME throttle Content-Type = %q, want application/problem+json", ct)
	}

	after := metricValue(t, renderMetrics(t), `secsy_ratelimit_throttled_total{endpoint="acme_new_order",tier="per_ip"}`)
	if after-before < 1 {
		t.Errorf("throttle counter delta = %v, want >= 1", after-before)
	}

	// A different source IP is unaffected (the limit is per-key, not global).
	rec3 := httptest.NewRecorder()
	other := newReq()
	other.RemoteAddr = "198.51.100.9:5000"
	h.ServeHTTP(rec3, other)
	if rec3.Code != http.StatusOK {
		t.Errorf("request from a fresh IP = %d, want 200 (limit must be per-key)", rec3.Code)
	}
}

func TestChaosHSMGuardReturns503(t *testing.T) {
	// One in-flight slot, no queue: the first HSM-bound request holds the slot,
	// the second is shed immediately with 503 + Retry-After. TSA is an
	// HSM-bound signing endpoint gated by the guard.
	guard := ratelimit.NewGuard(ratelimit.GuardConfig{MaxInFlight: 1, MaxQueue: 0})
	mw := ratelimit.New(ratelimit.Options{
		Guard:    guard,
		Prefixes: ratelimit.Prefixes{TSA: "/tsa"},
	})

	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	h := mw.Handler(okHandler(hold, entered))

	before := metricValue(t, renderMetrics(t), `secsy_hsm_guard_rejected_total{endpoint="tsa",reason="queue_full"}`)

	// First request grabs the only slot and blocks inside the handler.
	var wg sync.WaitGroup
	wg.Add(1)
	rec1 := httptest.NewRecorder()
	go func() {
		defer wg.Done()
		r := httptest.NewRequest(http.MethodPost, "/tsa", nil)
		h.ServeHTTP(rec1, r)
	}()
	select {
	case <-entered: // handler is now holding the guard slot
	case <-time.After(2 * time.Second):
		close(hold)
		t.Fatal("first request never entered the handler")
	}

	// Second request: the slot is taken and the queue is empty, so it is shed.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/tsa", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		close(hold)
		t.Fatalf("shed request = %d, want 503", rec2.Code)
	}
	if ra := rec2.Header().Get("Retry-After"); ra == "" || ra == "0" {
		close(hold)
		t.Errorf("503 response missing a positive Retry-After header (got %q)", ra)
	}

	// Release the first request and confirm it completed successfully — the
	// guard shed the overflow without harming the admitted request.
	close(hold)
	wg.Wait()
	if rec1.Code != http.StatusOK {
		t.Errorf("admitted request = %d, want 200", rec1.Code)
	}

	after := metricValue(t, renderMetrics(t), `secsy_hsm_guard_rejected_total{endpoint="tsa",reason="queue_full"}`)
	if after-before < 1 {
		t.Errorf("guard-rejected counter delta = %v, want >= 1", after-before)
	}

	// Recovery: with the slot freed, a fresh request is admitted again.
	rec3 := httptest.NewRecorder()
	h3 := mw.Handler(okHandler(nil, nil))
	h3.ServeHTTP(rec3, httptest.NewRequest(http.MethodPost, "/tsa", nil))
	if rec3.Code != http.StatusOK {
		t.Errorf("post-drain request = %d, want 200 (guard must recover)", rec3.Code)
	}
}

// TestChaosGuardAcquireTimeoutSheds asserts the queued-then-timeout path also
// sheds fast (503-class ErrAcquireTimeout) rather than blocking forever, the
// graceful-degradation invariant for a briefly saturated but non-empty queue.
func TestChaosGuardAcquireTimeoutSheds(t *testing.T) {
	guard := ratelimit.NewGuard(ratelimit.GuardConfig{
		MaxInFlight:    1,
		MaxQueue:       4,
		AcquireTimeout: 100 * time.Millisecond,
	})

	// Hold the only slot.
	release, err := guard.Acquire(context.Background())
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	defer release()

	// A second acquire must queue, then time out — not hang.
	start := time.Now()
	_, err = guard.Acquire(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected acquire to time out while the slot was held")
	}
	if err != ratelimit.ErrAcquireTimeout {
		t.Fatalf("acquire error = %v, want ErrAcquireTimeout", err)
	}
	if elapsed > time.Second {
		t.Errorf("acquire took %v to shed; expected ~100ms (must not block indefinitely)", elapsed)
	}

	if inFlight, waiting := guard.Stats(); inFlight != 1 || waiting != 0 {
		t.Errorf("after timeout: inFlight=%d waiting=%d, want 1/0", inFlight, waiting)
	}
}
