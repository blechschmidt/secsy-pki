package hsmaudit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Collection is driven by the HSM operations themselves rather than by a timer
// (Task 181), and several drains can be in flight at once. These tests cover
// the two halves of that: that a signal actually produces a drain, and that
// concurrent drains cannot corrupt each other or invent a tampering report.

// waitFor polls cond until it holds or the deadline passes. Collection is
// asynchronous by nature, so the alternative to polling is a fixed sleep long
// enough to be slow and short enough to be flaky.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// runCollector starts a collector loop and returns it, stopping it at test end.
func runCollector(t *testing.T, dev Device, store Store, backstop time.Duration) *Collector {
	t.Helper()
	c := NewCollector(dev, store, backstop, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("collector did not stop when its context was cancelled")
		}
	})
	return c
}

// The point of the whole change: an operation's log entry becomes durable
// because the operation said so, not because a timer eventually came round. The
// backstop here is an hour, so a pass cannot be the sweep in disguise.
func TestNotifyDrainsWithoutWaitingForTheBackstop(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)
	c := runCollector(t, dev, store, time.Hour)

	waitFor(t, 2*time.Second, "the collector's first cycle", func() bool {
		return dev.consumedUpTo() == 2
	})

	// A new signature lands in the device's ring.
	n := dev.appendEntry(signEntry(attestedKeyID))
	c.Notify()

	waitFor(t, 2*time.Second, "the signalled entry to be stored", func() bool {
		got, err := store.LogEntries(context.Background())
		return err == nil && len(got) == 3
	})
	if got := dev.consumedUpTo(); got != n {
		t.Fatalf("device acknowledged up to %d, want %d: the entry was stored but its ring slot was not freed", got, n)
	}
}

// Signals coalesce. A burst of issuance must not turn into one device round
// trip per signature — the device is a USB token and the drain is three round
// trips — while still guaranteeing that a signal arriving mid-cycle gets a
// cycle of its own rather than being folded into one that had already read the
// log.
func TestSignalsCoalesceButNeverGetLost(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	// Hold the second fetch open so a burst of signals arrives while a cycle is
	// demonstrably in flight.
	release := make(chan struct{})
	var once sync.Once
	blocked := make(chan struct{})
	dev.mu.Lock()
	dev.beforeFetch = func() {
		once.Do(func() {
			close(blocked)
			<-release
		})
	}
	dev.mu.Unlock()

	c := NewCollector(dev, store, time.Hour, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	<-blocked // the loop's first cycle is parked inside FetchLog

	// A hundred operations complete while that cycle is stuck.
	for i := 0; i < 100; i++ {
		dev.appendEntry(signEntry(attestedKeyID))
		c.Notify()
	}
	close(release)

	waitFor(t, 5*time.Second, "the burst to be collected", func() bool {
		got, err := store.LogEntries(context.Background())
		return err == nil && len(got) == 102
	})

	// One cycle for the burst plus the parked one: a handful, not a hundred.
	if got := dev.fetchCount(); got > 5 {
		t.Fatalf("100 signals produced %d device fetches: they are not coalescing", got)
	}
}

// The backstop still runs with nothing to signal it. It is what covers the
// entries this process's own operations cannot announce — another process's
// commands, a signal lost to a crash — and what keeps an idle deployment
// probing a device that may have wedged.
func TestBackstopDrainsWithoutAnySignal(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)
	runCollector(t, dev, store, 20*time.Millisecond)

	waitFor(t, 2*time.Second, "the first cycle", func() bool { return dev.consumedUpTo() == 2 })

	dev.appendEntry(signEntry(attestedKeyID)) // nobody calls Notify

	waitFor(t, 2*time.Second, "the backstop sweep to collect it", func() bool {
		got, err := store.LogEntries(context.Background())
		return err == nil && len(got) == 3
	})
}

// Concurrent drains must serialize. Without the lock two cycles read the same
// tail, both drain, and the slower one then verifies its segment against a tail
// the faster one has already advanced past — which VerifySegment reports as a
// break in continuity. That is the audit subsystem accusing its own CA of
// tampering because two of its own code paths ran at once, and it is exactly
// the failure this test exists to catch.
func TestConcurrentDrainsDoNotReportAFalseGap(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	const workers = 8
	const rounds = 12

	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				dev.appendEntry(signEntry(attestedKeyID))
				// Every caller builds its own Collector, exactly as provisioning,
				// export, freshness attestation and the CLI do.
				if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent drain reported a failure: %v", err)
	}

	stored, err := store.LogEntries(context.Background())
	if err != nil {
		t.Fatalf("reading stored entries: %v", err)
	}
	if want := 2 + workers*rounds; len(stored) != want {
		t.Fatalf("stored %d entries, want %d: a concurrent drain dropped a segment", len(stored), want)
	}
	// The stored copy must still verify from the pinned anchor, which is the
	// property everything downstream rests on.
	if seg := VerifyChainFromGenesis(stored, Unlogged{}); !seg.OK {
		t.Fatalf("stored chain no longer verifies after concurrent drains: %v", seg.Err())
	}
	st, err := store.LoadAuditState(context.Background())
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if last := stored[len(stored)-1]; st.Tail.Number != last.Number {
		t.Fatalf("tail is entry %d but the last stored entry is %d", st.Tail.Number, last.Number)
	}
}

// A second process holding the lease is made to wait rather than allowed to
// interleave. This is the CLI-versus-server case: an operator running
// `secsy-ca hsm-audit export` while the server drains after every signature.
func TestCollectWaitsForALeaseHeldByAnotherProcess(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	ok, err := store.AcquireCollectionLease(context.Background(), "another-process", time.Minute)
	if err != nil || !ok {
		t.Fatalf("seeding the foreign lease: ok=%v err=%v", ok, err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("drain ran while another process held the lease (err=%v)", err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := store.ReleaseCollectionLease(context.Background(), "another-process"); err != nil {
		t.Fatalf("releasing the foreign lease: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain failed after the lease was released: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not proceed after the lease was released")
	}
}

// A holder that died mid-drain must not wedge collection permanently: the lease
// carries an expiry precisely so the subsystem recovers on its own.
func TestExpiredLeaseIsTakenOver(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	if ok, err := store.AcquireCollectionLease(context.Background(), "crashed-process", time.Minute); err != nil || !ok {
		t.Fatalf("seeding the abandoned lease: ok=%v err=%v", ok, err)
	}
	// Rather than sleeping out the TTL, move the store's clock past it.
	store.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })

	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("drain refused to take over an expired lease: %v", err)
	}
}

// A lease nobody ever releases is reported, not waited on forever. A collector
// blocked in silence looks identical to one that is keeping up.
func TestCollectGivesUpOnALeaseNobodyReleases(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	prevWait, prevPoll := collectionLeaseWait, collectionLeasePoll
	collectionLeaseWait, collectionLeasePoll = 100*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { collectionLeaseWait, collectionLeasePoll = prevWait, prevPoll })

	if ok, err := store.AcquireCollectionLease(context.Background(), "stuck-process", time.Hour); err != nil || !ok {
		t.Fatalf("seeding the stuck lease: ok=%v err=%v", ok, err)
	}

	_, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error when the lease is never released")
	}
	if !strings.Contains(err.Error(), "collection lease") {
		t.Fatalf("error does not name the lease, so an operator cannot act on it: %v", err)
	}
}

// The lease must be released even when the drain fails, or one bad cycle would
// block every later one until the TTL expired.
func TestLeaseIsReleasedAfterAFailedDrain(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	dev.mu.Lock()
	dev.fetchErr = fmt.Errorf("device unplugged")
	dev.mu.Unlock()
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err == nil {
		t.Fatal("expected the drain to fail")
	}

	dev.mu.Lock()
	dev.fetchErr = nil
	dev.mu.Unlock()
	if ok, err := store.AcquireCollectionLease(context.Background(), "someone-else", time.Minute); err != nil || !ok {
		t.Fatalf("lease was not released after a failed drain: ok=%v err=%v", ok, err)
	}
}

// Notify is called from the signing path, where nothing may panic or block.
func TestNotifyIsAlwaysSafe(t *testing.T) {
	var nilCollector *Collector
	nilCollector.Notify() // must not panic: recording can outlive the collector

	c := NewCollector(newFake(chain(testAnchor)), NewMemStore(), 0, discardLogger())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			c.Notify() // nothing is running the loop, so every one of these coalesces
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Notify blocked with no collector loop running: it would stall issuance")
	}
}

// The default backstop is the documented one. A zero here used to mean 60s and
// the server overrode it with 15s; both were guesses at a signing rate, and the
// point of the change is that the cadence no longer has to be guessed.
func TestZeroBackstopSelectsTheDefault(t *testing.T) {
	c := NewCollector(newFake(chain(testAnchor)), NewMemStore(), 0, discardLogger())
	if c.backstop != BackstopInterval {
		t.Fatalf("backstop is %s, want %s", c.backstop, BackstopInterval)
	}
}
