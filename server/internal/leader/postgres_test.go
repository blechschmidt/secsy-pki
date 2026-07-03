package leader

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

// pgDSN returns the PostgreSQL DSN for the advisory-lock tests, or skips when
// SECSY_TEST_PG_DSN is unset (matching internal/database and internal/chaos).
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SECSY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL not configured: set SECSY_TEST_PG_DSN to a reachable test database")
	}
	return dsn
}

// newPGElector builds a PostgreSQL elector with test-scale intervals on a
// test-unique lock name, so parallel packages sharing the database never
// contend on each other's leases.
func newPGElector(t *testing.T, dsn, lockName string) *Elector {
	t.Helper()
	e, err := New(Config{
		Mode:          ModePostgres,
		Driver:        "postgres",
		DSN:           dsn,
		LockName:      lockName,
		RenewInterval: 50 * time.Millisecond,
		RetryInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// lockName derives a per-test lock namespace.
func lockName(t *testing.T) string {
	return fmt.Sprintf("secsy-test/%s/%d", t.Name(), time.Now().UnixNano())
}

// TestPostgresElectorExactlyOneLeader runs two electors against one database
// and asserts exactly one wins, the other stays a pure follower, and an
// explicit stop hands leadership over.
func TestPostgresElectorExactlyOneLeader(t *testing.T) {
	dsn := pgDSN(t)
	name := lockName(t)

	a := newPGElector(t, dsn, name)
	b := newPGElector(t, dsn, name)

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	doneA, doneB := make(chan struct{}), make(chan struct{})

	// Start A first so the initial winner is deterministic.
	go func() { a.Run(ctxA); close(doneA) }()
	waitFor(t, "A to acquire leadership", a.IsLeader)

	go func() { b.Run(ctxB); close(doneB) }()

	// B must not become leader while A holds the lease: watch through several
	// of B's retry intervals.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if b.IsLeader() {
			t.Fatalf("two leaders: B acquired the lease while A held it")
		}
		if !a.IsLeader() {
			t.Fatalf("A lost leadership without cause")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Clean stop: A releases explicitly, so B takes over within a retry or two.
	cancelA()
	<-doneA
	waitFor(t, "failover to B", b.IsLeader)
	if a.IsLeader() {
		t.Fatalf("A still reports leadership after stopping")
	}
	if got := b.Transitions(); got != 1 {
		t.Errorf("B transitions = %d, want 1 (single gain)", got)
	}
}

// TestPostgresElectorFailoverOnSessionKill simulates an unclean lease loss:
// the leader's election session is terminated server-side
// (pg_terminate_backend, as a network partition or PostgreSQL failover would).
// The deposed leader must observe the loss and step down, and — since a
// stepped-down replica immediately re-campaigns — the fleet must converge back
// to exactly one leader without ever having two.
func TestPostgresElectorFailoverOnSessionKill(t *testing.T) {
	dsn := pgDSN(t)
	name := lockName(t)
	key := LockKey(name)

	a := newPGElector(t, dsn, name)
	b := newPGElector(t, dsn, name)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	waitFor(t, "A to acquire leadership", a.IsLeader)
	go b.Run(ctx)

	// Kill A's election session from an out-of-band connection, finding it by
	// the advisory-lock key it holds.
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening admin connection: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`
		SELECT pg_terminate_backend(pid) FROM pg_locks
		 WHERE locktype = 'advisory' AND granted
		   AND classid::bigint = $1 AND objid::bigint = $2`,
		int64(uint64(key)>>32), int64(uint64(key)&0xffffffff)); err != nil {
		t.Fatalf("terminating election session: %v", err)
	}

	// A's next lease confirmation fails, so it records the involuntary loss
	// (transition #2 after the initial gain) even if it then wins re-election.
	waitFor(t, "A to observe the lease loss", func() bool { return a.Transitions() >= 2 })

	// The fleet converges to exactly one leader — either B took over or A
	// re-acquired on a fresh session — and never has two.
	waitFor(t, "exactly one leader after the kill", func() bool {
		return a.IsLeader() != b.IsLeader()
	})
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if a.IsLeader() && b.IsLeader() {
			t.Fatalf("split brain: both electors report leadership")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !a.IsLeader() && !b.IsLeader() {
		t.Fatalf("no leader re-emerged after the session kill")
	}
}

// TestPGLockConfirmDetectsLoss exercises the lock backend directly: Confirm
// succeeds while the session holds the lock and fails once the session dies.
func TestPGLockConfirmDetectsLoss(t *testing.T) {
	dsn := pgDSN(t)
	key := LockKey(lockName(t))
	l := newPGLock(dsn, key, 2*time.Second, testLogger(t))
	defer l.Release()

	ctx := context.Background()
	held, err := l.TryAcquire(ctx)
	if err != nil || !held {
		t.Fatalf("TryAcquire = %v, %v; want held", held, err)
	}
	if err := l.Confirm(ctx); err != nil {
		t.Fatalf("Confirm while held: %v", err)
	}

	// A second contender cannot acquire.
	l2 := newPGLock(dsn, key, 2*time.Second, testLogger(t))
	defer l2.Release()
	held2, err := l2.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("contender TryAcquire: %v", err)
	}
	if held2 {
		t.Fatalf("advisory lock granted twice")
	}

	// Kill the holder's session out-of-band; Confirm must fail closed.
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening admin connection: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`
		SELECT pg_terminate_backend(pid) FROM pg_locks
		 WHERE locktype = 'advisory' AND granted
		   AND classid::bigint = $1 AND objid::bigint = $2`,
		int64(uint64(key)>>32), int64(uint64(key)&0xffffffff)); err != nil {
		t.Fatalf("terminating session: %v", err)
	}
	if err := l.Confirm(ctx); err == nil {
		t.Fatalf("Confirm succeeded after its session was terminated")
	}

	// The contender can now take the freed lease.
	waitFor(t, "contender to acquire after session death", func() bool {
		held, err := l2.TryAcquire(ctx)
		return err == nil && held
	})
}
