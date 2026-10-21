package hsmaudit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// A drain cycle must not ask for another drain.
//
// It did. Collection follows the operations (Task 181), and the native driver
// announces every command it sends so that the paths which never touch a key
// provider are covered too. The cycle's own traffic was supposed to be excluded
// by command code — GET DEVICE INFO, GET LOG ENTRIES, SET LOG INDEX — but
// reading device info here also reads two device options, because the collector
// checks the force-audit setting, and GET OPTION is an ordinary command no
// exclusion list can quietly swallow. So every cycle signalled the next: an
// idle server drained about eleven times a second, held the cross-process
// collection lease almost continuously, and starved `hsm-audit export`,
// `collect`, `timestamp` and `commit` of it for their full 30-second wait.
//
// The fix is a property of the cycle rather than of a command list: the cycle
// runs under a context that silences the observer. These tests hold both ends
// of that — that the collector really does carry such a context into every
// device call, and that a driver which honours it cannot be made to loop.

// observingDevice stands in for the native driver: each device call announces
// itself to the command observer unless the caller's context silenced it, which
// is exactly what internal/yubihsm's send does.
type observingDevice struct {
	*fakeDevice
	notify      func()
	announced   atomic.Int64
	suppressed  atomic.Int64
	sawPlainCtx atomic.Bool
}

func (d *observingDevice) announce(ctx context.Context) {
	if yubihsm.CommandObserverSuppressed(ctx) {
		d.suppressed.Add(1)
		return
	}
	d.sawPlainCtx.Store(true)
	d.announced.Add(1)
	if d.notify != nil {
		d.notify()
	}
}

// Info announces twice: production reads GET DEVICE INFO, which is excluded by
// code, and then two GET OPTION calls, which are not.
func (d *observingDevice) Info(ctx context.Context) (*DeviceInfo, error) {
	d.announce(ctx)
	d.announce(ctx)
	return d.fakeDevice.Info(ctx)
}

func (d *observingDevice) FetchLog(ctx context.Context) (*hsm.LogResponse, error) {
	d.announce(ctx)
	return d.fakeDevice.FetchLog(ctx)
}

func (d *observingDevice) ConsumeLog(ctx context.Context, upTo uint16) error {
	d.announce(ctx)
	return d.fakeDevice.ConsumeLog(ctx, upTo)
}

func (d *observingDevice) Options(ctx context.Context) (*Options, error) {
	d.announce(ctx)
	return d.fakeDevice.Options(ctx)
}

// An idle collector settles. With a backstop an hour away, the cycles have to
// stop once the ring is empty; anything else is the loop.
func TestAnIdleCollectorStopsDrainingItself(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, fake, store := provisioned(t, entries)

	dev := &observingDevice{fakeDevice: fake}
	c := NewCollector(dev, store, time.Hour, discardLogger())
	// The server's wiring, verbatim: every announced command signals the drain.
	dev.notify = c.Notify

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	waitFor(t, 2*time.Second, "the collector's first cycle", func() bool {
		return dev.fetchCount() >= 1
	})

	// Give the loop every chance to run away. Before the fix this was tens of
	// cycles in the same window — the deployment that reported this saw one
	// every 86 ms.
	settled := dev.fetchCount()
	time.Sleep(300 * time.Millisecond)
	if got := dev.fetchCount(); got > settled {
		t.Fatalf("an idle collector ran %d more cycle(s) in 300ms (%d total): the drain is signalling itself",
			got-settled, got)
	}
	if dev.announced.Load() != 0 {
		t.Fatalf("%d device command(s) of the drain's own were announced to the collector", dev.announced.Load())
	}
	if dev.suppressed.Load() == 0 {
		t.Fatal("test setup: no device call was made under a silenced context")
	}
}

// The signal still works. Silencing the cycle's own traffic must not silence a
// real operation's, or collection would be back to waiting for the backstop.
func TestNotifyStillDrainsAfterTheCycleIsSilenced(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, fake, store := provisioned(t, entries)

	dev := &observingDevice{fakeDevice: fake}
	c := NewCollector(dev, store, time.Hour, discardLogger())
	dev.notify = c.Notify

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	waitFor(t, 2*time.Second, "the collector's first cycle", func() bool {
		return dev.fetchCount() >= 1
	})

	n := dev.appendEntry(signEntry(attestedKeyID))
	c.Notify()

	waitFor(t, 2*time.Second, "the signalled entry to be stored", func() bool {
		got, err := store.LogEntries(context.Background())
		return err == nil && len(got) == 3
	})
	if got := dev.consumedUpTo(); got != n {
		t.Fatalf("device acknowledged up to %d, want %d", got, n)
	}
}

// Every device call a cycle makes carries the silence, not merely the ones the
// fix happened to be written for. This is the invariant that survives somebody
// later reading one more thing from the device inside a cycle.
func TestEveryDeviceCallInACycleIsSilenced(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, fake, store := provisioned(t, entries)

	dev := &observingDevice{fakeDevice: fake}
	c := NewCollector(dev, store, time.Hour, discardLogger())

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if dev.sawPlainCtx.Load() {
		t.Fatal("a drain cycle reached the device with a context that still announces commands")
	}
	if dev.suppressed.Load() < 3 {
		t.Fatalf("only %d device call(s) were silenced; a cycle makes at least three", dev.suppressed.Load())
	}
}

// A stop must hand the lease back.
//
// The server did not handle SIGTERM at all, so a `podman stop` killed it
// mid-cycle with the collection lease held, and the next process that had to
// drain — an operator's `hsm-audit export`, run immediately after the stop —
// waited its full 30 seconds and failed until the lease expired a minute later.
// The process-level half of that is in cmd/server (shutdown.go); this is the
// half that belongs here: a cancelled cycle releases the lease rather than
// leaving it to time out.
func TestACancelledCycleReleasesTheCollectionLease(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	// Hold the cycle open inside the device fetch, which is where a drain spends
	// its time and so where a stop lands.
	inCycle := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	dev.beforeFetch = func() {
		once.Do(func() {
			close(inCycle)
			<-release
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewCollector(dev, store, time.Hour, discardLogger()).Run(ctx)
	}()

	<-inCycle
	if !leaseIsHeld(t, store) {
		t.Fatal("test setup: the cycle is in flight but holds no lease")
	}
	cancel()
	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the collector did not stop when its context was cancelled")
	}
	if leaseIsHeld(t, store) {
		t.Fatal("the collection lease is still held after the collector stopped: " +
			"the next process to drain would wait it out")
	}
}

// leaseIsHeld reports whether the collection lease is held, by asking for it as
// another process would: a store that grants it was free, and giving it straight
// back leaves things as they were.
func leaseIsHeld(t *testing.T, store *MemStore) bool {
	t.Helper()
	const probe = "lease-probe"
	ok, err := store.AcquireCollectionLease(context.Background(), probe, time.Second)
	if err != nil {
		t.Fatalf("probing the collection lease: %v", err)
	}
	if !ok {
		return true
	}
	if err := store.ReleaseCollectionLease(context.Background(), probe); err != nil {
		t.Fatalf("releasing the lease probe: %v", err)
	}
	return false
}
