//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestVerifyStoreIntegrityBothBackends is the HSM-independent disaster-recovery
// gate exercised in CI: it fills a store, asserts every integrity invariant
// holds, and then corrupts each invariant in turn to prove the check trips. It
// runs against SQLite (always) and PostgreSQL (when SECSY_TEST_PG_DSN is set) so
// a schema or migration regression on either backend is caught.
func TestVerifyStoreIntegrityBothBackends(t *testing.T) {
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
			populateStore(t, db)

			// Baseline: a freshly populated store is fully consistent.
			res, err := db.VerifyStoreIntegrity()
			if err != nil {
				t.Fatalf("VerifyStoreIntegrity: %v", err)
			}
			if !res.OK {
				for _, c := range res.Checks {
					t.Logf("  %s ok=%v %s", c.Name, c.OK, c.Detail)
				}
				t.Fatal("baseline store reported not OK")
			}
			// Fingerprint sanity: population created 5 audit events, 2 issued
			// certs (1 revoked), and advanced the counters.
			fp := res.Fingerprint
			if fp.AuditEventCount != 5 || !fp.AuditChainValid {
				t.Errorf("audit fingerprint = %+v, want 5 valid events", fp)
			}
			if fp.IssuedCerts != 2 || fp.RevokedCerts != 1 {
				t.Errorf("cert fingerprint issued=%d revoked=%d, want 2/1", fp.IssuedCerts, fp.RevokedCerts)
			}
			if fp.AuditHeadHash == "" {
				t.Error("audit head hash is empty")
			}
			if fp.SumNextSerial == 0 || fp.SumNextCRLNumber == 0 {
				t.Errorf("counter fingerprint sums must be positive, got serial=%d crl=%d", fp.SumNextSerial, fp.SumNextCRLNumber)
			}

			// The fingerprint must be stable across repeated reads (read-only).
			res2, err := db.VerifyStoreIntegrity()
			if err != nil {
				t.Fatal(err)
			}
			if res2.Fingerprint != fp {
				t.Errorf("fingerprint changed across reads: %+v vs %+v", res2.Fingerprint, fp)
			}
		})
	}
}

// checkNamed returns the named check from a result, failing the test if absent.
func checkNamed(t *testing.T, res *IntegrityResult, name string) IntegrityCheck {
	t.Helper()
	for _, c := range res.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not present in result", name)
	return IntegrityCheck{}
}

// TestVerifyStoreIntegrityDetectsCorruption corrupts each invariant on a SQLite
// store and asserts the corresponding check fails while the store as a whole is
// reported not OK. SQLite is sufficient here — the invariants are backend-neutral
// SQL — and it keeps the negative cases in the no-HSM, no-Postgres CI subset.
func TestVerifyStoreIntegrityDetectsCorruption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("audit_chain", func(t *testing.T) {
		db := testDB(t)
		populateStore(t, db)
		// Tamper with an event's action so its stored hash no longer matches.
		if _, err := db.conn.Exec(`UPDATE event_log SET action = 'forged' WHERE seq = 3`); err != nil {
			t.Fatal(err)
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatal("expected integrity failure after audit tamper")
		}
		if c := checkNamed(t, res, "audit_chain"); c.OK {
			t.Errorf("audit_chain check passed despite tamper: %s", c.Detail)
		}
	})

	t.Run("serial_monotonicity", func(t *testing.T) {
		db := testDB(t)
		populateStore(t, db)
		// Give the intermediate a subordinate CA with a large serial, then rewind
		// the root's serial counter behind it — the split-brain-after-restore case.
		rootID := "root"
		if err := db.CreateCA(&models.CA{ID: "sub", ParentID: &rootID, Label: "Sub CA",
			PKCS11URI: "pkcs11:sub", KeyType: "ecdsa", PublicKey: "SUBKEY", Serial: "500"}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.conn.Exec(`UPDATE ca_serial_counters SET next_serial = 10 WHERE ca_id = 'root'`); err != nil {
			t.Fatal(err)
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			t.Fatal(err)
		}
		if c := checkNamed(t, res, "serial_monotonicity"); c.OK {
			t.Errorf("serial_monotonicity passed despite rewound counter: %s", c.Detail)
		}
	})

	t.Run("crl_continuity", func(t *testing.T) {
		db := testDB(t)
		populateStore(t, db)
		// A published CRL numbered 2 exists (full scope); rewind the counter to 1.
		if _, err := db.conn.Exec(`UPDATE ca_crl_counters SET next_number = 1 WHERE ca_id = 'int'`); err != nil {
			t.Fatal(err)
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			t.Fatal(err)
		}
		if c := checkNamed(t, res, "crl_continuity"); c.OK {
			t.Errorf("crl_continuity passed despite rewound CRL counter: %s", c.Detail)
		}
	})

	t.Run("revocation_missing_from_store", func(t *testing.T) {
		db := testDB(t)
		populateStore(t, db)
		// Mark an issued cert revoked in the inventory without a revocation-store
		// row — CRL/OCSP would then serve it as good.
		if _, err := db.conn.Exec(
			`UPDATE issued_certificates SET status = 'revoked' WHERE ca_id = 'int' AND serial = '1001'`); err != nil {
			t.Fatal(err)
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			t.Fatal(err)
		}
		if c := checkNamed(t, res, "revocation_consistency"); c.OK {
			t.Errorf("revocation_consistency passed despite revoked cert missing from store: %s", c.Detail)
		}
	})

	t.Run("revocation_in_store_but_valid", func(t *testing.T) {
		db := testDB(t)
		populateStore(t, db)
		// Add a revocation-store row for a cert still marked valid.
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: "cert-1003", CAID: "int", Serial: "1003", CommonName: "host1003",
			Certificate: "-----BEGIN CERTIFICATE-----\n1003", NotBefore: now,
			NotAfter: now.Add(time.Hour), Status: models.CertStatusValid,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.conn.Exec(
			`INSERT INTO revoked_certificates (ca_id, serial, revoked_at, reason) VALUES ('int', '1003', ?, 0)`, now); err != nil {
			t.Fatal(err)
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			t.Fatal(err)
		}
		if c := checkNamed(t, res, "revocation_consistency"); c.OK {
			t.Errorf("revocation_consistency passed despite in-store cert still valid: %s", c.Detail)
		}
	})
}

// TestStoreFingerprintContinuity models the PITR continuity comparison the DR
// drill performs: a fingerprint captured before "loss" must be reproduced
// exactly by the restored store, and issuing more work must only advance the
// monotonic counters, never rewind them.
func TestStoreFingerprintContinuity(t *testing.T) {
	db := testDB(t)
	populateStore(t, db)

	before, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a faithful restore by re-reading: fingerprint must be identical.
	after, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatal(err)
	}
	if before.Fingerprint != after.Fingerprint {
		t.Fatalf("faithful restore changed fingerprint:\n before=%+v\n after =%+v", before.Fingerprint, after.Fingerprint)
	}

	// Post-restore activity must strictly advance the counters and event chain.
	if _, err := db.AllocateSerial("int"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NextCRLNumber("int"); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendEvent(&audit.Event{ID: "evt-post", Actor: "op", Action: audit.ActionCertIssue, Target: "int", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	next, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatal(err)
	}
	if !next.OK {
		t.Fatal("store not OK after further issuance")
	}
	if next.Fingerprint.SumNextSerial <= before.Fingerprint.SumNextSerial {
		t.Errorf("serial counter did not advance: %d -> %d", before.Fingerprint.SumNextSerial, next.Fingerprint.SumNextSerial)
	}
	if next.Fingerprint.SumNextCRLNumber <= before.Fingerprint.SumNextCRLNumber {
		t.Errorf("CRL counter did not advance: %d -> %d", before.Fingerprint.SumNextCRLNumber, next.Fingerprint.SumNextCRLNumber)
	}
	if next.Fingerprint.AuditEventCount != before.Fingerprint.AuditEventCount+1 {
		t.Errorf("audit count = %d, want %d", next.Fingerprint.AuditEventCount, before.Fingerprint.AuditEventCount+1)
	}
	if next.Fingerprint.AuditHeadHash == before.Fingerprint.AuditHeadHash {
		t.Error("audit head hash did not change after appending an event")
	}
}
