package hsmaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// The collection lease is mutual exclusion between *processes* draining the
// same device.
//
// Two of them routinely exist. The server drains after every operation (see
// collector.go), and an operator running `secsy-ca hsm-audit export`,
// `collect`, `timestamp` or `commit` drains from a second process against the
// same YubiHSM and the same database. Nothing about the leader election covers
// that: the CLI is not a replica and never stood for election.
//
// Left unsynchronized the two interleave badly. Both read the collection tail,
// both fetch the same segment, and whichever finishes second verifies its
// segment against a tail the first has already advanced — which VerifySegment
// reports, correctly by its own lights, as a gap in the device log. The
// subsystem would be accusing its own CA of tampering because two of its tools
// ran at the same time.
//
// The lease is held for the length of one drain cycle and released in a defer.
// It carries an expiry so a process killed mid-cycle cannot wedge collection
// permanently: after CollectionLeaseTTL another drain takes it over. That
// window is the one place this design chooses availability over exclusion, and
// the choice is bounded — a stolen lease can at worst produce the interleaving
// above, which fails closed by refusing to acknowledge rather than by
// acknowledging something unverified.

// LeaseOwner identifies this process to the collection lease. It is stable for
// the process lifetime and unique across processes: host and PID would collide
// across containers reusing PID namespaces, so a random suffix is mixed in.
var LeaseOwner = sync.OnceValue(func() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is not a reason to refuse to drain the audit log; the
		// PID still distinguishes processes on this host, which is where the
		// realistic contention is.
		return fmt.Sprintf("%s/%d", host, os.Getpid())
	}
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), hex.EncodeToString(b[:]))
})

// acquireCollectionLease takes the cross-process drain lease, waiting for a
// concurrent holder to finish, and returns the function that releases it.
//
// Waiting rather than failing is deliberate. The caller's operation is already
// recorded on the device; the only question is which process stores it. If the
// holder's cycle covers it, this cycle finds nothing new and everything is
// still correct — but this cycle has to run to establish that, because the
// holder may equally have read the log before the operation happened.
//
// The returned release is always safe to call, including on the error paths, so
// callers can defer it unconditionally.
func acquireCollectionLease(ctx context.Context, store Store) (release func(), err error) {
	owner := LeaseOwner()
	deadline := time.Now().Add(collectionLeaseWait)

	for {
		ok, err := store.AcquireCollectionLease(ctx, owner, CollectionLeaseTTL)
		if err != nil {
			return func() {}, fmt.Errorf("acquiring the HSM audit collection lease: %w", err)
		}
		if ok {
			var once sync.Once
			return func() {
				once.Do(func() {
					// Release on a context of its own: the caller's may already be
					// cancelled (shutdown), and a lease left behind would block every
					// other drain until it expired.
					rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					_ = store.ReleaseCollectionLease(rctx, owner)
				})
			}, nil
		}
		if err := ctx.Err(); err != nil {
			return func() {}, err
		}
		if time.Now().After(deadline) {
			return func() {}, fmt.Errorf(
				"another process has held the HSM audit collection lease for over %s: "+
					"a `secsy-ca hsm-audit` command may be stuck against the device, or a collector "+
					"crashed mid-drain (the lease frees itself %s after that)",
				collectionLeaseWait, CollectionLeaseTTL)
		}
		select {
		case <-ctx.Done():
			return func() {}, ctx.Err()
		case <-time.After(collectionLeasePoll):
		}
	}
}
