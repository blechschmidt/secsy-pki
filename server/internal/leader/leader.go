// Package leader coordinates a fleet of server replicas so the singleton
// background jobs — expiry monitoring/auto-renewal, CA auto-rotation, OCSP
// pre-signing, scheduled CRL regeneration/publishing, audit-chain anchoring,
// and SIEM export cursor advancement — run on exactly one replica at a time
// (Task 68).
//
// The election is a lease held on the shared PostgreSQL store: a session-level
// advisory lock (pg_try_advisory_lock) taken on a dedicated connection. A
// session lock is held until it is explicitly released or its session ends, so
// the lease survives exactly as long as the leader can keep its dedicated
// connection alive. The leader re-confirms the lease every renew interval and
// steps down the moment it cannot (connection loss, query timeout, PostgreSQL
// restart); followers retry acquisition every retry interval and take over as
// soon as PostgreSQL frees the dead leader's session. Two replicas can never
// hold the lock simultaneously — PostgreSQL grants an advisory lock to at most
// one session — so at most one replica runs jobs at any moment. In-flight work
// on a deposed leader may briefly overlap with the new leader's first cycle,
// which is why every gated job must be idempotent on handover (renewal is
// supersession-checked, anchoring idle-skips an unchanged head, SIEM delivery
// is at-least-once from a durable cursor, publishing is an atomic swap).
//
// For single-node deployments (the embedded SQLite store cannot be shared
// between replicas) a static elector simply holds leadership for the process
// lifetime, preserving the pre-coordination behavior with zero overhead.
package leader

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Election modes. ModeAuto picks by database driver: PostgreSQL elects via the
// advisory lock, SQLite (single-node by construction) holds statically.
const (
	ModeAuto     = "auto"
	ModePostgres = "postgres"
	ModeStatic   = "static"
)

// DefaultLockName namespaces the advisory lock. Deployments sharing one
// PostgreSQL database (e.g. separate staging/prod schemas are separate
// databases, but a shared dev database is not) must give each deployment its
// own coordination.lock_name so their elections stay independent.
const DefaultLockName = "secsy-pki/background-jobs"

const (
	defaultRenewInterval = 5 * time.Second
	defaultRetryInterval = 5 * time.Second
)

// Config assembles an Elector.
type Config struct {
	// Mode selects the election backend: ModeAuto (default), ModePostgres
	// (require advisory-lock election; an error on a non-PostgreSQL driver), or
	// ModeStatic (this replica always leads — single-replica deployments only).
	Mode string
	// Driver and DSN identify the shared store. The PostgreSQL elector opens its
	// own single-connection pool from them: the election session must not be
	// recycled by pool lifetime management or borrowed by queries, since the
	// session itself is the lease.
	Driver string
	DSN    string
	// LockName is hashed into the 64-bit advisory-lock key. Empty selects
	// DefaultLockName.
	LockName string
	// RenewInterval is how often a leader re-confirms its lease; RetryInterval
	// is how often a follower retries acquisition. Both default to 5s, bounding
	// failover to roughly session-teardown + one retry interval.
	RenewInterval time.Duration
	RetryInterval time.Duration
	Logger        *log.Logger
}

// Elector runs the election loop and starts/stops the registered singleton
// jobs as leadership is gained and lost.
type Elector struct {
	lock          lock
	mode          string
	lockName      string
	renewInterval time.Duration
	retryInterval time.Duration
	logger        *log.Logger

	transitions atomic.Uint64

	mu        sync.Mutex
	leader    bool
	jobs      []job
	jobCtx    context.Context
	jobCancel context.CancelFunc
	jobWG     *sync.WaitGroup
}

// job is one registered singleton background job.
type job struct {
	name string
	run  func(ctx context.Context)
}

// New builds an Elector for the deployment's store. It validates the mode but
// performs no I/O: the first acquisition attempt happens inside Run, so a
// PostgreSQL that is briefly unreachable at boot delays leadership rather than
// failing startup.
func New(cfg Config) (*Elector, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeAuto
	}
	isPostgres := cfg.Driver == "postgres" || cfg.Driver == "postgresql"
	switch mode {
	case ModeAuto:
		if isPostgres {
			mode = ModePostgres
		} else {
			mode = ModeStatic
		}
	case ModePostgres:
		if !isPostgres {
			return nil, fmt.Errorf("coordination.mode %q requires a postgres database driver (got %q); use \"static\" or \"auto\" for single-node stores", ModePostgres, cfg.Driver)
		}
	case ModeStatic:
	default:
		return nil, fmt.Errorf("unknown coordination.mode %q (valid: %s, %s, %s)", cfg.Mode, ModeAuto, ModePostgres, ModeStatic)
	}

	e := &Elector{
		mode:          mode,
		lockName:      cfg.LockName,
		renewInterval: cfg.RenewInterval,
		retryInterval: cfg.RetryInterval,
		logger:        cfg.Logger,
	}
	if e.lockName == "" {
		e.lockName = DefaultLockName
	}
	if e.renewInterval <= 0 {
		e.renewInterval = defaultRenewInterval
	}
	if e.retryInterval <= 0 {
		e.retryInterval = defaultRetryInterval
	}
	if e.logger == nil {
		e.logger = log.Default()
	}

	switch mode {
	case ModePostgres:
		e.lock = newPGLock(cfg.DSN, LockKey(e.lockName), lockOpTimeout(e.renewInterval), e.logger)
	default:
		e.lock = staticLock{}
	}
	return e, nil
}

// lockOpTimeout bounds a single lock operation (acquire/confirm/release). It
// tracks the renew interval so a leader that cannot get an answer within one
// renewal cycle steps down instead of blocking the loop, clamped so very short
// test intervals still allow a round-trip and very long renew intervals do not
// leave the loop hung on a black-holed connection.
func lockOpTimeout(renew time.Duration) time.Duration {
	const min, max = time.Second, 10 * time.Second
	switch {
	case renew < min:
		return min
	case renew > max:
		return max
	default:
		return renew
	}
}

// Mode reports the resolved election backend ("postgres" or "static").
func (e *Elector) Mode() string { return e.mode }

// LockName reports the advisory-lock namespace in use.
func (e *Elector) LockName() string { return e.lockName }

// IsLeader reports whether this replica currently holds the job leadership.
func (e *Elector) IsLeader() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leader
}

// Transitions reports how many leadership transitions (gains plus losses) this
// replica has observed since it started.
func (e *Elector) Transitions() uint64 { return e.transitions.Load() }

// Register adds a singleton background job. While this replica is leader, run
// executes in its own goroutine with a context that is cancelled when
// leadership is lost or the elector stops; it must return promptly on
// cancellation and must tolerate being started again on re-election (every
// runner here scans persisted state, so a restart repeats at most one
// idempotent cycle). Jobs may be registered before or after Run: registering
// on a current leader starts the job immediately.
func (e *Elector) Register(name string, run func(ctx context.Context)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	j := job{name: name, run: run}
	e.jobs = append(e.jobs, j)
	if e.leader {
		e.startJobLocked(j)
	}
}

// Run drives the election until ctx is cancelled: campaign while a follower,
// confirm the lease while the leader, and start/stop the registered jobs on
// every transition. It blocks; callers run it in a goroutine for the process
// lifetime. On ctx cancellation it stops the jobs and releases the lock so a
// cleanly terminated leader (e.g. a rolling update) hands over immediately
// rather than after a session timeout.
func (e *Elector) Run(ctx context.Context) {
	metrics.LeaderIsLeader.Set(0)
	e.logger.Printf("leader elector started (mode=%s, lock=%q, renew=%s, retry=%s)",
		e.mode, e.lockName, e.renewInterval, e.retryInterval)

	for ctx.Err() == nil {
		if !e.IsLeader() {
			held, err := e.lock.TryAcquire(ctx)
			if err != nil && ctx.Err() == nil {
				e.logger.Printf("leader: acquisition attempt failed (will retry): %v", err)
			}
			if held {
				e.becomeLeader(ctx)
				continue // straight into the renew cycle, no retry sleep
			}
			if !sleepCtx(ctx, e.retryInterval) {
				break
			}
			continue
		}

		if !sleepCtx(ctx, e.renewInterval) {
			break
		}
		if err := e.lock.Confirm(ctx); err != nil && ctx.Err() == nil {
			e.logger.Printf("leader: lease confirmation failed, stepping down: %v", err)
			e.stepDown()
		}
	}

	// Shutdown: stop jobs first so nothing races the explicit release, then
	// hand the lock back for an immediate takeover elsewhere.
	if e.IsLeader() {
		e.stepDown()
	} else {
		e.lock.Release()
	}
	e.logger.Printf("leader elector stopped")
}

// becomeLeader flips to the leader state and starts every registered job under
// a fresh cancellable context derived from the elector's run context. The
// transition is recorded before the first job starts so an observer never sees
// running jobs with an unrecorded transition.
func (e *Elector) becomeLeader(ctx context.Context) {
	e.mu.Lock()
	e.leader = true
	e.jobCtx, e.jobCancel = context.WithCancel(ctx)
	e.jobWG = &sync.WaitGroup{}
	e.transitions.Add(1)
	metrics.LeaderIsLeader.Set(1)
	metrics.LeaderTransitions.Inc("leader")
	jobs := e.jobs
	for _, j := range jobs {
		e.startJobLocked(j)
	}
	e.mu.Unlock()

	e.logger.Printf("leader: acquired leadership (mode=%s); starting %d singleton job(s)", e.mode, len(jobs))
}

// startJobLocked launches one job under the current leadership term. The
// caller holds e.mu, and e.jobCtx/e.jobWG belong to the current term.
func (e *Elector) startJobLocked(j job) {
	ctx, wg := e.jobCtx, e.jobWG
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.logger.Printf("leader: starting job %q", j.name)
		j.run(ctx)
		e.logger.Printf("leader: job %q stopped", j.name)
	}()
}

// stepDown cancels the running jobs, waits for them to exit, and releases the
// lock. Waiting before returning to the campaign loop guarantees this replica
// never runs two generations of its own jobs concurrently; cross-replica
// exclusion is the advisory lock's job.
func (e *Elector) stepDown() {
	e.mu.Lock()
	if !e.leader {
		e.mu.Unlock()
		return
	}
	e.leader = false
	e.transitions.Add(1)
	metrics.LeaderIsLeader.Set(0)
	metrics.LeaderTransitions.Inc("follower")
	cancel, wg := e.jobCancel, e.jobWG
	e.jobCtx, e.jobCancel, e.jobWG = nil, nil, nil
	e.mu.Unlock()

	cancel()
	wg.Wait()
	e.lock.Release()
	e.logger.Printf("leader: stepped down; singleton jobs stopped")
}

// sleepCtx sleeps for d, returning false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
