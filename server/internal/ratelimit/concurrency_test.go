package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardDisabled(t *testing.T) {
	g := NewGuard(GuardConfig{MaxInFlight: 0})
	if g.Enabled() {
		t.Fatal("guard with MaxInFlight 0 should be disabled")
	}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("disabled guard Acquire errored: %v", err)
	}
	release() // must be a safe no-op
}

func TestGuardQueueFull(t *testing.T) {
	g := NewGuard(GuardConfig{MaxInFlight: 1, MaxQueue: 0})
	rel, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	// The single slot is taken and the queue is zero-length, so the next
	// Acquire is shed immediately.
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
	rel()
	// After release the slot is free again.
	rel2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	rel2()
}

func TestGuardAcquireTimeout(t *testing.T) {
	g := NewGuard(GuardConfig{MaxInFlight: 1, MaxQueue: 4, AcquireTimeout: 40 * time.Millisecond})
	rel, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer rel()

	start := time.Now()
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrAcquireTimeout) {
		t.Fatalf("expected ErrAcquireTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("timed out too early after %v", elapsed)
	}
}

func TestGuardContextCancel(t *testing.T) {
	g := NewGuard(GuardConfig{MaxInFlight: 1, MaxQueue: 4})
	rel, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer rel()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, e := g.Acquire(ctx)
		errc <- e
	}()
	// Give the goroutine time to enter the wait queue, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case e := <-errc:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Acquire did not return after cancel")
	}
}

// TestGuardBoundsConcurrency spawns many workers and asserts the number
// simultaneously holding a slot never exceeds MaxInFlight.
func TestGuardBoundsConcurrency(t *testing.T) {
	const maxInFlight = 4
	g := NewGuard(GuardConfig{MaxInFlight: maxInFlight, MaxQueue: 1000, AcquireTimeout: 2 * time.Second})

	var current, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := g.Acquire(context.Background())
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			defer rel()
			n := current.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			current.Add(-1)
		}()
	}
	wg.Wait()

	if peak.Load() > maxInFlight {
		t.Fatalf("peak concurrency %d exceeded MaxInFlight %d", peak.Load(), maxInFlight)
	}
	if inFlight, waiting := g.Stats(); inFlight != 0 || waiting != 0 {
		t.Fatalf("after drain: in-flight=%d waiting=%d, want 0/0", inFlight, waiting)
	}
}

func TestGuardReleaseIdempotent(t *testing.T) {
	g := NewGuard(GuardConfig{MaxInFlight: 1})
	rel, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rel()
	rel() // second call must not free a second (non-existent) slot
	// The slot must be available exactly once.
	rel2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire after idempotent release: %v", err)
	}
	if inFlight, _ := g.Stats(); inFlight != 1 {
		t.Fatalf("in-flight = %d, want 1 (double-release corrupted the count)", inFlight)
	}
	rel2()
}
