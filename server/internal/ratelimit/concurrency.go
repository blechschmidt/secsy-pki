package ratelimit

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Errors returned by Guard.Acquire.
var (
	// ErrQueueFull is returned when the bounded wait queue in front of the HSM
	// is already saturated, so the request is shed immediately rather than
	// queued. This is the fast-fail overload signal.
	ErrQueueFull = errors.New("ratelimit: hsm concurrency queue full")
	// ErrAcquireTimeout is returned when a queued request waited longer than the
	// configured acquire timeout without obtaining a slot.
	ErrAcquireTimeout = errors.New("ratelimit: hsm concurrency acquire timed out")
)

// Guard bounds how many requests may be in flight against the HSM-backed
// session pool at once. It sits in front of the pool so that, under overload,
// excess requests are queued up to a bounded depth and then rejected fast
// (429/503) instead of accumulating as blocked goroutines behind the pool's
// own borrow() backpressure.
//
// A buffered channel of capacity maxInFlight is the semaphore; a separate
// bounded counter caps how many goroutines may wait for a slot. Queue depth and
// in-flight counts are exported as gauges so operators can see saturation
// building before requests are shed.
type Guard struct {
	sem      chan struct{}
	maxQueue int64
	timeout  time.Duration
	waiting  atomic.Int64
	inFlight atomic.Int64
}

// GuardConfig configures a Guard.
type GuardConfig struct {
	// MaxInFlight is the number of concurrent HSM-bound requests allowed. It
	// should be at least the PKCS#11 session pool size; a smaller value would
	// leave pool sessions idle, a much larger value defeats the guard.
	MaxInFlight int
	// MaxQueue is how many requests may wait for a slot before further requests
	// are shed with ErrQueueFull. Zero disables queuing (requests either get an
	// immediate slot or are rejected).
	MaxQueue int
	// AcquireTimeout bounds how long a queued request waits for a slot. Zero
	// means wait until a slot is free or the request context is canceled.
	AcquireTimeout time.Duration
}

// NewGuard builds a Guard. A non-positive MaxInFlight yields a disabled guard
// whose Acquire always succeeds with a no-op release.
func NewGuard(cfg GuardConfig) *Guard {
	if cfg.MaxInFlight <= 0 {
		return &Guard{} // disabled: sem == nil
	}
	g := &Guard{
		sem:      make(chan struct{}, cfg.MaxInFlight),
		maxQueue: int64(cfg.MaxQueue),
		timeout:  cfg.AcquireTimeout,
	}
	return g
}

// Enabled reports whether the guard enforces a limit.
func (g *Guard) Enabled() bool { return g != nil && g.sem != nil }

// noop is the release returned when the guard is disabled.
func noop() {}

// Acquire reserves an in-flight slot. On success it returns a release function
// that must be called exactly once to free the slot. It returns ErrQueueFull
// when the wait queue is saturated, ErrAcquireTimeout when the acquire timeout
// elapses, or ctx.Err() when the request is canceled while waiting.
func (g *Guard) Acquire(ctx context.Context) (release func(), err error) {
	if !g.Enabled() {
		return noop, nil
	}

	// Fast path: a slot is immediately available.
	select {
	case g.sem <- struct{}{}:
		g.inFlight.Add(1)
		metrics.HSMGuardInFlight.Set(float64(g.inFlight.Load()))
		return g.releaser(), nil
	default:
	}

	// No slot free: attempt to enter the bounded wait queue.
	if g.waiting.Add(1) > g.maxQueue {
		g.waiting.Add(-1)
		metrics.HSMGuardQueueDepth.Set(float64(g.waiting.Load()))
		return nil, ErrQueueFull
	}
	metrics.HSMGuardQueueDepth.Set(float64(g.waiting.Load()))
	defer func() {
		g.waiting.Add(-1)
		metrics.HSMGuardQueueDepth.Set(float64(g.waiting.Load()))
	}()

	var timeout <-chan time.Time
	if g.timeout > 0 {
		t := time.NewTimer(g.timeout)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case g.sem <- struct{}{}:
		g.inFlight.Add(1)
		metrics.HSMGuardInFlight.Set(float64(g.inFlight.Load()))
		return g.releaser(), nil
	case <-timeout:
		return nil, ErrAcquireTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// releaser returns a single-use release function for a held slot.
func (g *Guard) releaser() func() {
	var once atomic.Bool
	return func() {
		if !once.CompareAndSwap(false, true) {
			return
		}
		<-g.sem
		g.inFlight.Add(-1)
		metrics.HSMGuardInFlight.Set(float64(g.inFlight.Load()))
	}
}

// Stats reports the current in-flight and queued counts (for tests/introspection).
func (g *Guard) Stats() (inFlight, waiting int64) {
	if !g.Enabled() {
		return 0, 0
	}
	return g.inFlight.Load(), g.waiting.Load()
}
