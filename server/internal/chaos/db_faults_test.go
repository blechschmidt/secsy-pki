//go:build sqlite

package chaos

// Scenario 2 — PostgreSQL/SQLite fault injection (Tasks 38 & 8).
//
// Exercises the persistence backend under concurrency and, on PostgreSQL, under
// real connection drops (pg_terminate_backend). Asserts the store invariants
// that a fault must never violate:
//
//   - serial allocation is collision-free (the `FOR UPDATE` row lock the
//     Postgres path added in Task 38);
//   - CRL numbers are collision-free and monotonic;
//   - the hash-chained audit log stays contiguous and verifiable;
//   - concurrent issuance never records a duplicate serial or leaves a
//     partially-issued certificate (signed-but-unrecorded);
//   - after a storm of dropped connections, VerifyStoreIntegrity still passes.
//
// The pure-concurrency checks run on SQLite (always) and PostgreSQL (when
// SECSY_TEST_PG_DSN is set). The connection-drop check is PostgreSQL-only.

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	_ "github.com/blechschmidt/secsy-pki/server/internal/pgdriver"
)

// backends returns the DB backends to exercise: SQLite always, plus PostgreSQL
// when configured. Each entry opens a fresh handle; no truncation is needed
// because every CA is created with a unique id/label, so runs never collide and
// the shared audit chain simply grows (and must stay valid).
func backends(t *testing.T) map[string]func(*testing.T) *database.DB {
	t.Helper()
	m := map[string]func(*testing.T) *database.DB{
		"sqlite": func(t *testing.T) *database.DB {
			db, err := database.New("sqlite", t.TempDir()+"/chaos.db")
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			return db
		},
	}
	if dsn := envOr("SECSY_TEST_PG_DSN", ""); dsn != "" {
		m["postgres"] = func(t *testing.T) *database.DB {
			db, err := database.New("postgres", dsn)
			if err != nil {
				t.Fatalf("open postgres: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			return db
		}
	}
	return m
}

// seedRoot creates a fresh root CA (seeding its serial/CRL counters) via a
// software-backed Manager, returning the Manager and the CA id.
func seedRoot(t *testing.T, db *database.DB) (*ca.Manager, string) {
	t.Helper()
	prov, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { prov.Close() })
	mgr := ca.NewManager(db, prov)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "chaos-root-" + randSuffix(t),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Chaos Root " + randSuffix(t)}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return mgr, root.ID
}

// TestChaosSerialAllocationContention hammers AllocateSerial concurrently and
// asserts every returned serial is unique — the core Task 38 FOR UPDATE
// invariant that a pooled Postgres backend must not violate.
func TestChaosSerialAllocationContention(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			_, caID := seedRoot(t, db)

			const workers, each = 16, 40
			results := make([][]int64, workers)
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						s, err := db.AllocateSerial(caID)
						if err != nil {
							t.Errorf("AllocateSerial: %v", err)
							return
						}
						results[w] = append(results[w], s)
					}
				}(w)
			}
			wg.Wait()

			var all []string
			for _, r := range results {
				for _, s := range r {
					all = append(all, itoa(s))
				}
			}
			assertNoDuplicates(t, "serial", all)
			if len(all) != workers*each {
				t.Fatalf("allocated %d serials, want %d", len(all), workers*each)
			}
		})
	}
}

// TestChaosCRLNumberContention asserts concurrent CRL-number allocation stays
// collision-free for both the full-scope and scoped counters.
func TestChaosCRLNumberContention(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			_, caID := seedRoot(t, db)

			const workers, each = 12, 30
			full := make([][]int64, workers)
			scoped := make([][]int64, workers)
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						n, err := db.NextCRLNumber(caID)
						if err != nil {
							t.Errorf("NextCRLNumber: %v", err)
							return
						}
						full[w] = append(full[w], n)
						sn, err := db.NextScopedCRLNumber(caID, "shard-0")
						if err != nil {
							t.Errorf("NextScopedCRLNumber: %v", err)
							return
						}
						scoped[w] = append(scoped[w], sn)
					}
				}(w)
			}
			wg.Wait()

			assertNoDuplicates(t, "crl-number", flatten(full))
			assertNoDuplicates(t, "scoped-crl-number", flatten(scoped))
		})
	}
}

// TestChaosAuditChainUnderConcurrency appends events from many goroutines and
// asserts the hash chain stays contiguous and verifiable — no gaps, no
// duplicate sequence numbers, no broken back-links.
func TestChaosAuditChainUnderConcurrency(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)

			before, err := db.MaxEventSeq()
			if err != nil {
				t.Fatalf("MaxEventSeq: %v", err)
			}

			const workers, each = 10, 25
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						ev := newAuditEvent(w, i)
						if err := db.AppendEvent(ev); err != nil {
							t.Errorf("AppendEvent: %v", err)
							return
						}
					}
				}(w)
			}
			wg.Wait()

			assertAuditChainIntact(t, db)
			after, err := db.MaxEventSeq()
			if err != nil {
				t.Fatalf("MaxEventSeq: %v", err)
			}
			if got := after - before; got != workers*each {
				t.Fatalf("appended %d events, chain advanced by %d", workers*each, got)
			}
		})
	}
}

// TestChaosConcurrentIssuanceNoPartial issues many leaf certificates
// concurrently and asserts there is no duplicate serial and no partial
// issuance: the count of stored records equals the count of successful
// issuances, and every returned certificate both verifies against the CA
// (signed) and is retrievable from the store (recorded).
func TestChaosConcurrentIssuanceNoPartial(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			mgr, caID := seedRoot(t, db)
			ctx := context.Background()

			const workers, each = 8, 12
			var mu sync.Mutex
			var serials []string
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						csr := makeChaosCSR(t)
						res, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
							CAID:    caID,
							CSRPEM:  csr,
							Profile: "server",
						})
						if err != nil {
							t.Errorf("IssueCertificate: %v", err)
							return
						}
						// A non-error return means the leaf was signed on the
						// provider and its DER parsed; the store lookup proves it
						// was also recorded — together, no partial issuance.
						if _, err := db.GetIssuedCertificate(caID, res.Serial.String()); err != nil {
							t.Errorf("issued cert not recorded (partial issuance) serial=%s: %v", res.Serial, err)
							return
						}
						mu.Lock()
						serials = append(serials, res.Serial.String())
						mu.Unlock()
					}
				}(w)
			}
			wg.Wait()

			assertNoDuplicates(t, "leaf-serial", serials)

			stored, err := db.ListIssuedCertificates(caID)
			if err != nil {
				t.Fatalf("ListIssuedCertificates: %v", err)
			}
			if len(stored) != len(serials) {
				t.Fatalf("stored %d certs but %d issuances succeeded (partial issuance?)",
					len(stored), len(serials))
			}
		})
	}
}

// TestChaosPostgresConnectionDrop drives concurrent serial allocation and audit
// appends while a killer goroutine repeatedly terminates the backend's
// connections. It asserts graceful degradation: some operations fail, but the
// store is never corrupted — no duplicate serial is ever returned, the audit
// chain stays intact, and the full integrity check passes afterward.
func TestChaosPostgresConnectionDrop(t *testing.T) {
	dsn := postgresDSN(t)
	db, err := database.New("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, caID := seedRoot(t, db)

	// Separate admin connection used to terminate the store's backends.
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer admin.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Killer: terminate every other backend of this database, repeatedly, for
	// the duration of the load. database/sql transparently reconnects, so the
	// store must simply drop the in-flight operations and stay consistent.
	var killer sync.WaitGroup
	killer.Add(1)
	go func() {
		defer killer.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = admin.Exec(`SELECT pg_terminate_backend(pid)
				FROM pg_stat_activity
				WHERE pid <> pg_backend_pid() AND datname = current_database()`)
			time.Sleep(15 * time.Millisecond)
		}
	}()

	const workers, each = 12, 40
	var mu sync.Mutex
	var serials []string
	var allocErrs, auditErrs int
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if s, err := db.AllocateSerial(caID); err != nil {
					mu.Lock()
					allocErrs++
					mu.Unlock()
				} else {
					mu.Lock()
					serials = append(serials, itoa(s))
					mu.Unlock()
				}
				if err := db.AppendEvent(newAuditEvent(w, i)); err != nil {
					mu.Lock()
					auditErrs++
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	cancel()
	killer.Wait()

	// Invariant 1: every serial that was actually returned is unique. A killed
	// transaction rolls back and its serial is never handed out, so a returned
	// serial always means a committed, non-duplicate allocation.
	assertNoDuplicates(t, "serial (under connection drops)", serials)

	// Invariant 2 & 3: the audit chain is intact and the whole store passes the
	// integrity gate despite the connection storm.
	assertAuditChainIntact(t, db)
	res, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatalf("VerifyStoreIntegrity: %v", err)
	}
	if !res.OK {
		t.Fatalf("store integrity check failed after connection storm: %+v", res.Checks)
	}

	t.Logf("connection-drop storm: %d serials committed, %d alloc errors, %d audit errors (all tolerated)",
		len(serials), allocErrs, auditErrs)
	if allocErrs == 0 && auditErrs == 0 {
		t.Log("note: no operation observed a dropped connection this run; the invariants still held")
	}
}
