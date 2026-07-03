//go:build sqlite

package chaos

// Scenario 6 — multi-replica coordination (Task 68). Two in-process server
// instances share one PostgreSQL: each assembles its own store pool, key
// provider, and leader-gated background jobs (expiry monitor with auto-renew,
// audit-chain anchoring) exactly as cmd/server wires them. Invariants:
//
//   - Exactly one replica holds leadership and runs the singleton jobs; the
//     follower starts none of them.
//   - A certificate due for renewal is renewed exactly once fleet-wide, and a
//     leadership handover does not renew it again (supersession idempotency).
//   - Every audit anchor covers a distinct event-log head; a handover does not
//     re-anchor an unchanged head (idle-skip idempotency).
//   - Stopping the leader fails leadership over to the standby, which then
//     runs the jobs.
//   - The hash-chained audit log stays intact throughout.

import (
	"context"
	"database/sql"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// isolatedPGDatabase creates a throwaway database on the SECSY_TEST_PG_DSN
// server and returns its DSN. The scenario's exactly-once assertions (renewal
// and anchor counts, an idle event-log head) are only sound in a database this
// test fully owns: rows other suites leave behind in the shared test database
// — e.g. certificates whose auto-renewal fails on every scan — append audit
// events on each monitor pass and legitimately move the anchor head.
func isolatedPGDatabase(t *testing.T, baseDSN string) string {
	t.Helper()
	u, err := url.Parse(baseDSN)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		t.Skipf("SECSY_TEST_PG_DSN %q is not URL-form; cannot derive an isolated database", baseDSN)
	}
	name := "secsy_chaos_leader_" + randSuffix(t)

	admin, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("opening admin connection: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Skipf("cannot create isolated database (needs CREATEDB on the test server): %v", err)
	}
	t.Cleanup(func() {
		drop, err := sql.Open("postgres", baseDSN)
		if err != nil {
			return
		}
		defer drop.Close()
		// FORCE disconnects any straggler session so the drop cannot leak the
		// database on a teardown race. Best effort.
		if _, err := drop.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			t.Logf("dropping isolated database %s: %v", name, err)
		}
	})

	iso := *u
	iso.Path = "/" + name
	return iso.String()
}

// chaosTimestamper is an in-process anchor.Timestamper so the anchoring job
// runs without a TSA; the scenario asserts anchor cadence and uniqueness, not
// token cryptography (Task 64's own tests cover that).
type chaosTimestamper struct{}

func (chaosTimestamper) Timestamp(_ context.Context, digest []byte) ([]byte, time.Time, error) {
	return append([]byte("chaos-tst:"), digest...), time.Now().UTC(), nil
}
func (chaosTimestamper) Source() string { return "https://chaos.invalid/tsa" }

// jobReplica is the background-job plane of one in-process server instance.
type jobReplica struct {
	name    string
	db      *database.DB
	elector *leader.Elector

	monitorStarts atomic.Int32
	anchorStarts  atomic.Int32

	cancel context.CancelFunc
	done   chan struct{}
}

// newJobReplica assembles one replica against the shared database and key
// store, mirroring the cmd/server wiring: every singleton job is registered on
// the replica's elector rather than started unconditionally.
func newJobReplica(t *testing.T, name, dsn, keystoreDir, lockName string) *jobReplica {
	t.Helper()

	rdb, err := database.New("postgres", dsn)
	if err != nil {
		t.Fatalf("replica %s: opening store: %v", name, err)
	}
	t.Cleanup(func() { rdb.Close() })

	prov, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: keystoreDir},
	})
	if err != nil {
		t.Fatalf("replica %s: key provider: %v", name, err)
	}
	t.Cleanup(func() { prov.Close() })

	logger := log.New(os.Stderr, "[replica-"+name+"] ", log.Ltime)

	elector, err := leader.New(leader.Config{
		Mode:          leader.ModePostgres,
		Driver:        "postgres",
		DSN:           dsn,
		LockName:      lockName,
		RenewInterval: 50 * time.Millisecond,
		RetryInterval: 50 * time.Millisecond,
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("replica %s: elector: %v", name, err)
	}

	r := &jobReplica{name: name, db: rdb, elector: elector, done: make(chan struct{})}

	// Expiry monitor with auto-renewal. The hour-scale ticker is irrelevant to
	// the scenario: the runner scans immediately whenever the job starts, i.e.
	// on every leadership gain.
	mgr := ca.NewManager(rdb, prov)
	mon := monitor.New(rdb, mgr, rdb, monitor.Options{
		Warning:     30 * 24 * time.Hour,
		Critical:    7 * 24 * time.Hour,
		RenewBefore: 24 * time.Hour,
	})
	runner, err := monitor.NewRunner(mon, config.MonitorConfig{IntervalHours: 1, AutoRenew: true}, logger)
	if err != nil {
		t.Fatalf("replica %s: monitor runner: %v", name, err)
	}
	elector.Register("expiry-monitor", func(ctx context.Context) {
		r.monitorStarts.Add(1)
		runner.Run(ctx)
	})

	// Audit anchoring on a tight interval, so idle-skip (not tick scarcity) is
	// what bounds the anchor count.
	anchorRunner := anchor.NewRunner(anchor.NewService(rdb, chaosTimestamper{}), 200*time.Millisecond, logger)
	elector.Register("audit-anchor", func(ctx context.Context) {
		r.anchorStarts.Add(1)
		anchorRunner.Run(ctx)
	})

	return r
}

// start launches the replica's election loop.
func (r *jobReplica) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		r.elector.Run(ctx)
		close(r.done)
	}()
}

// stop terminates the replica (as a scaled-down or crashed pod would) and
// waits for its election loop — and therefore its jobs — to exit.
func (r *jobReplica) stop() {
	r.cancel()
	<-r.done
}

// TestChaosLeaderElectionTwoReplicas is the Task 68 acceptance scenario: two
// in-process instances against one PostgreSQL, exactly one runs jobs, no
// double-renewal or double-anchor, and leadership fails over when the leader
// stops.
func TestChaosLeaderElectionTwoReplicas(t *testing.T) {
	dsn := isolatedPGDatabase(t, postgresDSN(t))
	keystore := t.TempDir()
	lockName := "secsy-chaos/leader-" + randSuffix(t)
	ctx := context.Background()

	// Seed the shared state through its own connection: a root CA and one leaf
	// one hour from expiry — inside the monitors' 24h renew window.
	seedDB, err := database.New("postgres", dsn)
	if err != nil {
		t.Fatalf("opening seed store: %v", err)
	}
	defer seedDB.Close()
	seedProv, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: keystore},
	})
	if err != nil {
		t.Fatalf("seed key provider: %v", err)
	}
	defer seedProv.Close()
	seedMgr := ca.NewManager(seedDB, seedProv)
	root, err := seedMgr.InitRoot(ctx, ca.RootSpec{
		Label:    "chaos-leader-root-" + randSuffix(t),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Chaos Leader Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	caID := root.ID
	if _, err := seedMgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:     caID,
		CSRPEM:   makeChaosCSR(t),
		Profile:  "server",
		Validity: time.Hour,
	}); err != nil {
		t.Fatalf("issuing expiring leaf: %v", err)
	}

	certCount := func() int {
		certs, err := seedDB.ListIssuedCertificates(caID)
		if err != nil {
			t.Fatalf("listing certificates: %v", err)
		}
		return len(certs)
	}
	anchors := func() []audit.Anchor {
		all, err := seedDB.ListAuditAnchorsAsc()
		if err != nil {
			t.Fatalf("listing anchors: %v", err)
		}
		return all
	}
	baselineAnchors := len(anchors())

	// Two replicas. A starts first so the initial leader is deterministic.
	a := newJobReplica(t, "a", dsn, keystore, lockName)
	b := newJobReplica(t, "b", dsn, keystore, lockName)
	a.start()
	if !waitFor(10*time.Second, a.elector.IsLeader) {
		t.Fatalf("replica A never acquired leadership")
	}
	b.start()

	// The leader's first scan renews the expiring leaf; anchoring covers the
	// resulting head within a tick or two.
	if !waitFor(15*time.Second, func() bool { return certCount() == 2 }) {
		t.Fatalf("leaf was not auto-renewed by the leader (certs=%d)", certCount())
	}
	if !waitFor(15*time.Second, func() bool { return len(anchors()) > baselineAnchors }) {
		t.Fatalf("leader never anchored the audit head")
	}

	// Wait for the anchor cadence to go quiescent. Once every head is covered,
	// idle-skip appends nothing, so the count stops changing: no growth across
	// three anchor intervals means no anchor is in flight either. (A simple
	// point-in-time read could race a final tick that is mid-insert.)
	quiesceAnchors := func() int {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			before := len(anchors())
			time.Sleep(600 * time.Millisecond) // 3 anchor ticks
			if len(anchors()) == before {
				return before
			}
		}
		t.Fatalf("anchor count never went quiescent (idle-skip not converging)")
		return 0
	}
	settled := quiesceAnchors()

	// Both replicas now run steady-state. Watch for over-execution: the cert
	// must be renewed exactly once fleet-wide, the quiescent anchor count must
	// not grow (any new anchor on an unchanged head is a double anchor), and
	// the follower must run no jobs at all.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := certCount(); n != 2 {
			t.Fatalf("double renewal: %d certificates for the CA, want 2", n)
		}
		if n := len(anchors()); n != settled {
			t.Fatalf("double anchor: count grew to %d on an idle log (settled at %d)", n, settled)
		}
		if b.elector.IsLeader() {
			t.Fatalf("two leaders: replica B acquired leadership while A held it")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := b.monitorStarts.Load() + b.anchorStarts.Load(); got != 0 {
		t.Fatalf("follower ran %d job(s); singleton jobs must run on the leader only", got)
	}

	// Fail over: stop the leader. Its clean shutdown releases the advisory
	// lock, so the standby acquires within a retry interval and starts the
	// jobs it had never run.
	preHandover := settled
	a.stop()
	if !waitFor(10*time.Second, b.elector.IsLeader) {
		t.Fatalf("leadership did not fail over to replica B")
	}
	if !waitFor(10*time.Second, func() bool {
		return b.monitorStarts.Load() == 1 && b.anchorStarts.Load() == 1
	}) {
		t.Fatalf("new leader did not start the singleton jobs (monitor=%d anchor=%d)",
			b.monitorStarts.Load(), b.anchorStarts.Load())
	}

	// Handover idempotency: the new leader's immediate scan sees the renewed
	// (superseded) leaf and must not renew again; its anchor ticks see the
	// already-anchored head and must idle-skip.
	deadline = time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := certCount(); n != 2 {
			t.Fatalf("double renewal after handover: %d certificates, want 2", n)
		}
		if n := len(anchors()); n != preHandover {
			t.Fatalf("double anchor after handover: %d anchors, want %d (head unchanged)", n, preHandover)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Every anchor across the whole run covers a distinct head sequence — the
	// database-level "no double anchor" invariant.
	var seqs []string
	for _, an := range anchors() {
		seqs = append(seqs, strconv.FormatInt(an.Seq, 10))
	}
	assertNoDuplicates(t, "anchored head seq", seqs)

	// And the concurrently appended-to audit chain is still contiguous.
	assertAuditChainIntact(t, seedDB)

	b.stop()
	if b.elector.IsLeader() {
		t.Fatalf("replica B still reports leadership after stopping")
	}
}
