package leader

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"time"

	// The election opens its own connection, so the package registers the
	// PostgreSQL driver itself rather than relying on the store having done so.
	_ "github.com/blechschmidt/secsy-pki/server/internal/pgdriver"
)

// lock is the mutual-exclusion primitive behind the elector: a lease that at
// most one replica holds at a time.
type lock interface {
	// TryAcquire attempts to take the lease without blocking, reporting whether
	// this replica now holds it. It is only called while not holding the lease.
	TryAcquire(ctx context.Context) (bool, error)
	// Confirm verifies the lease is still held. Any error means leadership must
	// be surrendered locally: either the lease is provably gone or its state
	// cannot be confirmed, and an unconfirmable lease must not keep jobs running.
	Confirm(ctx context.Context) error
	// Release relinquishes the lease, best effort. Safe to call when not held.
	Release()
}

// staticLock is the single-node fallback: the lease is always held. SQLite
// stores cannot be shared between replicas, so the sole process is the leader
// by construction.
type staticLock struct{}

func (staticLock) TryAcquire(context.Context) (bool, error) { return true, nil }
func (staticLock) Confirm(context.Context) error            { return nil }
func (staticLock) Release()                                 {}

// LockKey maps a coordination lock name onto the 64-bit advisory-lock key
// space (FNV-1a). Exported so operators can locate the lease:
//
//	SELECT pid FROM pg_locks
//	 WHERE locktype = 'advisory' AND granted
//	   AND classid::bigint = (key >> 32) AND objid::bigint = (key & 0xffffffff);
func LockKey(name string) int64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	return int64(h.Sum64())
}

// pgLock holds the lease as a session-level PostgreSQL advisory lock on a
// dedicated connection. The session is the lease: PostgreSQL keeps the lock
// exactly as long as the session lives, so there is no timestamp bookkeeping
// to race on, and a crashed leader's lease dies with its connection.
//
// The lock owns a private single-connection pool rather than borrowing from
// the store's: pool lifetime recycling would silently end the session (and the
// lease) mid-flight, and a saturated application pool must not be able to
// starve lease renewal. Whenever the session's state becomes doubtful — a
// failed or timed-out query — the pool is torn down entirely instead of
// returning the connection: a healthy-but-unconfirmed session parked in a
// local pool would keep holding the lock server-side, blocking every other
// replica from taking over while this one believes it is a follower.
type pgLock struct {
	dsn       string
	key       int64
	opTimeout time.Duration
	logger    *log.Logger

	db   *sql.DB   // private one-connection pool; nil until first acquire
	conn *sql.Conn // the lease session; non-nil while campaigning or leading
}

func newPGLock(dsn string, key int64, opTimeout time.Duration, logger *log.Logger) *pgLock {
	return &pgLock{dsn: dsn, key: key, opTimeout: opTimeout, logger: logger}
}

// session returns the dedicated election session, establishing it on demand.
func (l *pgLock) session(ctx context.Context) (*sql.Conn, error) {
	if l.conn != nil {
		return l.conn, nil
	}
	if l.db == nil {
		// pgdriver registers as "postgres"; sql.Open validates the DSN without
		// connecting, so an unreachable server surfaces on first use below.
		db, err := sql.Open("postgres", l.dsn)
		if err != nil {
			return nil, fmt.Errorf("opening election connection: %w", err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		// The session is the lease. Lifetime/idle recycling would close it and
		// drop the advisory lock out from under a healthy leader.
		db.SetConnMaxLifetime(0)
		db.SetConnMaxIdleTime(0)
		l.db = db
	}
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("establishing election session: %w", err)
	}
	l.conn = conn
	return conn, nil
}

// TryAcquire attempts pg_try_advisory_lock on the dedicated session. A false
// return with nil error means another replica holds the lease. The session is
// kept between attempts so followers poll on an established connection; any
// error tears it down so the next attempt starts clean.
func (l *pgLock) TryAcquire(ctx context.Context) (bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, l.opTimeout)
	defer cancel()

	conn, err := l.session(opCtx)
	if err != nil {
		l.discard()
		return false, err
	}
	var held bool
	if err := conn.QueryRowContext(opCtx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&held); err != nil {
		l.discard()
		return false, fmt.Errorf("acquiring advisory lock: %w", err)
	}
	return held, nil
}

// Confirm renews the lease by asking the session's own backend whether it
// still holds the granted advisory lock. A session-level advisory lock cannot
// be lost while its session lives, so this primarily detects a dead or
// restarted backend — but checking pg_locks (rather than just pinging) also
// catches the theoretical lost-lock-with-live-session case, e.g. an operator
// running pg_advisory_unlock_all in a hijacked session.
func (l *pgLock) Confirm(ctx context.Context) error {
	if l.conn == nil {
		return errors.New("no election session")
	}
	opCtx, cancel := context.WithTimeout(ctx, l.opTimeout)
	defer cancel()

	// Advisory locks store the 64-bit key split across two 32-bit oid columns.
	classid := int64(uint64(l.key) >> 32)
	objid := int64(uint64(l.key) & 0xffffffff)
	var held bool
	err := l.conn.QueryRowContext(opCtx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_locks
			 WHERE locktype = 'advisory' AND granted
			   AND classid::bigint = $1 AND objid::bigint = $2
			   AND pid = pg_backend_pid()
		)`, classid, objid).Scan(&held)
	if err != nil {
		l.discard()
		return fmt.Errorf("confirming advisory lock: %w", err)
	}
	if !held {
		l.discard()
		return errors.New("advisory lock is no longer held by the election session")
	}
	return nil
}

// Release unlocks explicitly so a cleanly stopping leader hands over
// immediately, then tears the session down. If the unlock cannot be delivered
// the teardown still closes the connection, and PostgreSQL frees the lock as
// soon as it observes the session end.
func (l *pgLock) Release() {
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), l.opTimeout)
		if _, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, l.key); err != nil {
			l.logger.Printf("leader: releasing advisory lock: %v (session teardown will free it)", err)
		}
		cancel()
	}
	l.discard()
}

// discard closes the session and its private pool. Closing the pool (not just
// returning the connection to it) is what actually ends the PostgreSQL session
// and therefore the lease.
func (l *pgLock) discard() {
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	if l.db != nil {
		_ = l.db.Close()
		l.db = nil
	}
}
