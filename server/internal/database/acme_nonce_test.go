//go:build sqlite

package database

import (
	"bytes"
	"testing"
	"time"
)

// TestACMENonceStoreBothBackends exercises the shared/durable anti-replay nonce
// store (Task 97) on SQLite (always) and PostgreSQL (when SECSY_TEST_PG_DSN is
// set) — the two engines a single-node "file" store and a multi-replica HA
// deployment run on. The consumed-set's single-use guarantee and the
// insert-if-absent shared secret both depend on portable INSERT ... ON CONFLICT
// semantics, so cross-engine parity is the point.
func TestACMENonceStoreBothBackends(t *testing.T) {
	backends := []struct {
		name string
		open func(t *testing.T) *DB
	}{
		{"sqlite", func(t *testing.T) *DB { return testDB(t) }},
		{"postgres", freshPostgres},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			t.Run("consume single use", func(t *testing.T) { runNonceConsumeSuite(t, db) })
			t.Run("gc", func(t *testing.T) { runNonceGCSuite(t, db) })
			t.Run("secret stable", func(t *testing.T) { runNonceSecretSuite(t, db) })
		})
	}
}

// runNonceConsumeSuite verifies the consumed-set enforces single use: the first
// Consume of a hash is fresh, any later Consume of the same hash is a replay,
// and distinct hashes are independent.
func runNonceConsumeSuite(t *testing.T, db *DB) {
	exp := time.Now().Add(30 * time.Minute)

	fresh, err := db.ConsumeACMENonce("single-1", exp)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if !fresh {
		t.Fatal("first consume of a nonce must be fresh")
	}

	// Replaying the same nonce hash is rejected, without error.
	fresh, err = db.ConsumeACMENonce("single-1", exp)
	if err != nil {
		t.Fatalf("replay consume: %v", err)
	}
	if fresh {
		t.Fatal("replayed nonce must NOT be fresh")
	}

	// A different nonce hash is independent and fresh.
	fresh, err = db.ConsumeACMENonce("single-2", exp)
	if err != nil {
		t.Fatalf("distinct consume: %v", err)
	}
	if !fresh {
		t.Fatal("a distinct nonce must be fresh")
	}
}

// runNonceGCSuite verifies GC deletes only records past expiry and that a pruned
// record is consumable again (harmless: the acme layer rejects an expired nonce
// by its embedded timestamp before this set is consulted).
func runNonceGCSuite(t *testing.T, db *DB) {
	now := time.Now()

	if _, err := db.ConsumeACMENonce("gc-expired", now.Add(-time.Minute)); err != nil {
		t.Fatalf("consume expired: %v", err)
	}
	if _, err := db.ConsumeACMENonce("gc-valid", now.Add(time.Hour)); err != nil {
		t.Fatalf("consume valid: %v", err)
	}

	// GC at `now` removes only the expired one.
	removed, err := db.GCACMENonces(now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if removed != 1 {
		t.Fatalf("GC removed %d records, want 1", removed)
	}

	// The still-valid record remains consumed (replay still rejected)...
	if fresh, _ := db.ConsumeACMENonce("gc-valid", now.Add(time.Hour)); fresh {
		t.Fatal("still-valid record must remain in the consumed-set")
	}
	// ...while the pruned record is fresh again.
	if fresh, _ := db.ConsumeACMENonce("gc-expired", now.Add(time.Hour)); !fresh {
		t.Fatal("pruned record should be consumable again")
	}
}

// runNonceSecretSuite verifies the signing secret is generated on first use, is
// stable across calls (a replica keeps signing with one key), and is a real,
// sufficiently long random value.
func runNonceSecretSuite(t *testing.T, db *DB) {
	s1, err := db.GetOrCreateACMENonceSecret()
	if err != nil {
		t.Fatalf("first GetOrCreate: %v", err)
	}
	if len(s1) < 16 {
		t.Fatalf("secret too short: %d bytes", len(s1))
	}

	s2, err := db.GetOrCreateACMENonceSecret()
	if err != nil {
		t.Fatalf("second GetOrCreate: %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("nonce secret must be stable across calls (all replicas must agree)")
	}
}
