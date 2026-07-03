package leader

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testLogger returns a discard logger: elector goroutines may outlive the test
// body briefly, so logging must never touch testing.T.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(io.Discard, "", 0)
}

// fakeLock is a test-controllable lease: the test flips whether acquisition
// succeeds and whether confirmation fails, and observes releases.
type fakeLock struct {
	mu         sync.Mutex
	acquirable bool
	confirmErr error
	releases   int
}

func (f *fakeLock) TryAcquire(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acquirable, nil
}

func (f *fakeLock) Confirm(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirmErr
}

func (f *fakeLock) Release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
}

func (f *fakeLock) set(acquirable bool, confirmErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquirable = acquirable
	f.confirmErr = confirmErr
}

// newTestElector builds an elector around a fake lock with test-scale
// intervals.
func newTestElector(t *testing.T, l lock) *Elector {
	t.Helper()
	e, err := New(Config{Mode: ModeStatic, RenewInterval: 10 * time.Millisecond, RetryInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.lock = l
	return e
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNewModeResolution(t *testing.T) {
	cases := []struct {
		mode, driver string
		want         string
		wantErr      bool
	}{
		{"", "postgres", ModePostgres, false},
		{"", "postgresql", ModePostgres, false},
		{"", "sqlite", ModeStatic, false},
		{ModeAuto, "sqlite", ModeStatic, false},
		{ModeAuto, "postgres", ModePostgres, false},
		{ModeStatic, "postgres", ModeStatic, false},
		{ModePostgres, "sqlite", "", true},
		{"raft", "postgres", "", true},
	}
	for _, c := range cases {
		e, err := New(Config{Mode: c.mode, Driver: c.driver, DSN: "postgres://unused"})
		if c.wantErr {
			if err == nil {
				t.Errorf("New(mode=%q, driver=%q): want error, got mode %q", c.mode, c.driver, e.Mode())
			}
			continue
		}
		if err != nil {
			t.Errorf("New(mode=%q, driver=%q): %v", c.mode, c.driver, err)
			continue
		}
		if e.Mode() != c.want {
			t.Errorf("New(mode=%q, driver=%q).Mode() = %q, want %q", c.mode, c.driver, e.Mode(), c.want)
		}
	}
}

func TestLockKeyStable(t *testing.T) {
	// The key is persisted implicitly (it is what replicas of different builds
	// contend on), so it must never change for a given name.
	if got := LockKey(DefaultLockName); got != LockKey(DefaultLockName) {
		t.Fatalf("LockKey not deterministic")
	}
	if LockKey("a") == LockKey("b") {
		t.Fatalf("distinct names must map to distinct keys")
	}
}

// TestStaticElectorRunsJobs proves the single-node fallback: leadership is
// held immediately and every registered job runs, including jobs registered
// after the loop started.
func TestStaticElectorRunsJobs(t *testing.T) {
	e, err := New(Config{Driver: "sqlite", RenewInterval: 10 * time.Millisecond, RetryInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var early, late atomic.Int32
	e.Register("early", func(ctx context.Context) {
		early.Add(1)
		<-ctx.Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	waitFor(t, "leadership", e.IsLeader)
	waitFor(t, "early job start", func() bool { return early.Load() == 1 })

	e.Register("late", func(ctx context.Context) {
		late.Add(1)
		<-ctx.Done()
	})
	waitFor(t, "late job start", func() bool { return late.Load() == 1 })

	if got := e.Transitions(); got != 1 {
		t.Errorf("Transitions() = %d, want 1", got)
	}

	cancel()
	<-done
	if e.IsLeader() {
		t.Errorf("still leader after Run returned")
	}
}

// TestElectorStartsAndStopsJobsOnTransitions drives the full lifecycle through
// a fake lock: gain leadership (jobs start), lose the lease (jobs are
// cancelled and the elector steps down), regain it (jobs restart).
func TestElectorStartsAndStopsJobsOnTransitions(t *testing.T) {
	fl := &fakeLock{}
	e := newTestElector(t, fl)

	var starts, stops atomic.Int32
	e.Register("job", func(ctx context.Context) {
		starts.Add(1)
		<-ctx.Done()
		stops.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	// Not acquirable yet: stays follower, job never starts.
	time.Sleep(50 * time.Millisecond)
	if e.IsLeader() || starts.Load() != 0 {
		t.Fatalf("follower ran jobs: leader=%v starts=%d", e.IsLeader(), starts.Load())
	}

	// Lease becomes available.
	fl.set(true, nil)
	waitFor(t, "leadership gain", e.IsLeader)
	waitFor(t, "job start", func() bool { return starts.Load() == 1 })

	// Lease lost: confirmation fails, jobs must be cancelled.
	fl.set(false, errors.New("lease gone"))
	waitFor(t, "step down", func() bool { return !e.IsLeader() })
	waitFor(t, "job stop", func() bool { return stops.Load() == 1 })

	// Lease available again: jobs restart (idempotent-restart contract).
	fl.set(true, nil)
	waitFor(t, "re-election", e.IsLeader)
	waitFor(t, "job restart", func() bool { return starts.Load() == 2 })

	if got := e.Transitions(); got != 3 { // leader, follower, leader
		t.Errorf("Transitions() = %d, want 3", got)
	}

	cancel()
	<-done
	waitFor(t, "final job stop", func() bool { return stops.Load() == 2 })
}

// TestStepDownWaitsForJobs proves a re-election cannot overlap the previous
// term's jobs on the same replica: stepDown blocks until the job goroutine has
// returned. The transition methods are driven directly (no Run loop) so the
// test observes exactly one term.
func TestStepDownWaitsForJobs(t *testing.T) {
	e := newTestElector(t, &fakeLock{acquirable: true})

	release := make(chan struct{})
	var running atomic.Int32
	e.Register("slow", func(ctx context.Context) {
		running.Add(1)
		<-ctx.Done()
		<-release // simulate slow teardown
		running.Add(-1)
	})

	e.becomeLeader(context.Background())
	waitFor(t, "job start", func() bool { return running.Load() == 1 })

	stepped := make(chan struct{})
	go func() {
		e.stepDown()
		close(stepped)
	}()
	select {
	case <-stepped:
		t.Fatalf("stepDown returned while the job was still tearing down")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-stepped:
	case <-time.After(5 * time.Second):
		t.Fatalf("stepDown never returned after the job exited")
	}
	if running.Load() != 0 {
		t.Fatalf("job still running after stepDown")
	}
}
