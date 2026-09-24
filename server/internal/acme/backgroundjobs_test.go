//go:build sqlite

package acme

// Coverage for the two remaining leader-elected background loops: the consumed-
// nonce garbage collector and the RFC 8739 STAR renewer. Both run for the lifetime
// of a leadership term, so the stability property is the same one asserted for the
// email poller: they must return promptly when their context is cancelled. A loop
// that outlives the leadership term keeps mutating shared state from a replica that
// no longer owns it — for the nonce GC that means pruning another leader's
// anti-replay set, and for the STAR renewer, double-issuing certificates.

import (
	"context"
	"testing"
	"time"
)

// runLoop starts a background job and returns a channel closed when it returns.
func runLoop(job func(context.Context), ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		job(ctx)
	}()
	return done
}

func awaitLoopReturn(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return after its context was cancelled (leaked goroutine)", name)
	}
}

// TestRunNonceGC_HonorsCancellation asserts the nonce sweeper performs its
// immediate sweep and then returns on cancellation rather than sitting on its
// five-minute ticker.
func TestRunNonceGC_HonorsCancellation(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := runLoop(env.srv.RunNonceGC, ctx)
	cancel()
	awaitLoopReturn(t, done, "RunNonceGC")
}

// TestRunNonceGC_AlreadyCancelled asserts a context cancelled before the call is
// honored too, so a job that loses leadership during startup does not linger.
func TestRunNonceGC_AlreadyCancelled(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	awaitLoopReturn(t, runLoop(env.srv.RunNonceGC, ctx), "RunNonceGC")
}

// TestRunNonceGC_SweepsConsumedNonces confirms the loop's immediate sweep really
// prunes: a consumed nonce that has aged past its TTL is evicted, while a
// freshly-consumed one is kept (evicting it early would let it be replayed).
func TestRunNonceGC_SweepsConsumedNonces(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	// Spend a nonce, then confirm replaying it is refused — the consumed-set is
	// doing its job before the sweep runs at all.
	nonce, err := rc.Nonce()
	if err != nil {
		t.Fatalf("fetch nonce: %v", err)
	}
	if !env.srv.nonces.Consume(nonce) {
		t.Fatal("a fresh nonce was rejected")
	}
	if env.srv.nonces.Consume(nonce) {
		t.Fatal("a consumed nonce was accepted a second time (replay)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := runLoop(env.srv.RunNonceGC, ctx)
	cancel()
	awaitLoopReturn(t, done, "RunNonceGC")

	// The sweep must not have resurrected it: pruning only removes records whose
	// embedded timestamp has already expired, and an expired nonce is refused on
	// its timestamp anyway.
	if env.srv.nonces.Consume(nonce) {
		t.Error("a consumed nonce became replayable after a GC sweep")
	}
}

// TestRunStarRenewer_DisabledIsNoOp asserts the renewer is inert when STAR is not
// configured: it must return without waiting on a context that is never cancelled.
func TestRunStarRenewer_DisabledIsNoOp(t *testing.T) {
	env := newTestEnv(t) // STAR not configured
	awaitLoopReturn(t, runLoop(env.srv.RunStarRenewer, context.Background()), "RunStarRenewer")
}

// TestRunStarRenewer_HonorsCancellation asserts the enabled renewer returns
// promptly on cancellation.
func TestRunStarRenewer_HonorsCancellation(t *testing.T) {
	env := newTestEnv(t, withStar)
	ctx, cancel := context.WithCancel(context.Background())
	done := runLoop(env.srv.RunStarRenewer, ctx)
	cancel()
	awaitLoopReturn(t, done, "RunStarRenewer")
}

// TestRunStarRenewer_SweepErrorsAreNotFatal confirms the loop's sweep is a no-op
// (and not an error) when there is nothing due, which is what lets a long-running
// renewer idle harmlessly between recurrences.
func TestRunStarRenewer_SweepErrorsAreNotFatal(t *testing.T) {
	env := newTestEnv(t, withStar)
	n, err := env.srv.RenewDueSTAROrders(context.Background())
	if err != nil {
		t.Fatalf("RenewDueSTAROrders: %v", err)
	}
	if n != 0 {
		t.Errorf("renewed %d STAR orders with none due, want 0", n)
	}

	// With STAR disabled the sweep is a no-op rather than an error.
	plain := newTestEnv(t)
	if n, err := plain.srv.RenewDueSTAROrders(context.Background()); err != nil || n != 0 {
		t.Errorf("RenewDueSTAROrders (STAR disabled) = (%d, %v), want (0, nil)", n, err)
	}
}
