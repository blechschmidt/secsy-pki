//go:build sqlite

package database

import (
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 82 database-layer tests for the reversible certificate hold
// (certificateHold / removeFromCRL). They run on SQLite always and on
// PostgreSQL when SECSY_TEST_PG_DSN is set, so the ph()/forUpdate() and
// conflict-tolerant insert paths are covered on the real backend too.

func seedHoldCA(t *testing.T, db *DB, caID, serial string) {
	t.Helper()
	if err := db.CreateCA(&models.CA{ID: caID, Label: caID, PKCS11URI: "pkcs11:" + caID, KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x"}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	now := time.Now()
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID: caID + "-cert", CAID: caID, Serial: serial, CommonName: "hold.example.com",
		Profile: "server", Certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), Status: models.CertStatusValid,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}
}

func testHoldStore(t *testing.T, db *DB) {
	const caID, serial = "hold-ca", "000042"
	seedHoldCA(t, db, caID, serial)

	// Suspend: newly held, reason certificateHold, issued row flips to "held".
	newly, err := db.SuspendCertificate(caID, serial, time.Now())
	if err != nil || !newly {
		t.Fatalf("SuspendCertificate: newly=%v err=%v, want newly=true", newly, err)
	}
	rc, err := db.GetRevokedCertificate(caID, serial)
	if err != nil || rc == nil || rc.Reason != reasonCertificateHold {
		t.Fatalf("revocation after suspend = %+v (err %v), want reason certificateHold", rc, err)
	}
	if ic, _ := db.GetIssuedCertificate(caID, serial); ic == nil || ic.Status != models.CertStatusHeld {
		t.Fatalf("issued status after suspend = %v, want held", ic.Status)
	}

	// Suspending again is idempotent.
	if newly, err := db.SuspendCertificate(caID, serial, time.Now()); err != nil || newly {
		t.Fatalf("second suspend: newly=%v err=%v, want newly=false", newly, err)
	}

	// Release: the revocation row is deleted, a released-hold record is written,
	// and the issued row returns to "valid".
	if err := db.ReleaseHold(caID, serial, time.Now()); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if rc, err := db.GetRevokedCertificate(caID, serial); err != nil || rc != nil {
		t.Fatalf("revocation after release = %+v (err %v), want nil", rc, err)
	}
	if ic, _ := db.GetIssuedCertificate(caID, serial); ic == nil || ic.Status != models.CertStatusValid {
		t.Fatalf("issued status after release = %v, want valid", ic.Status)
	}
	released, err := db.ListReleasedHolds(caID)
	if err != nil || len(released) != 1 || released[0].Serial != serial || released[0].Reason != reasonCertificateHold {
		t.Fatalf("ListReleasedHolds = %+v (err %v), want one certificateHold record for %s", released, err, serial)
	}

	// Releasing again is refused: the serial is no longer revoked.
	if err := db.ReleaseHold(caID, serial, time.Now()); !errors.Is(err, ErrNotRevoked) {
		t.Errorf("second release: err = %v, want ErrNotRevoked", err)
	}

	// Re-suspending clears the release marker (no lingering removeFromCRL).
	if _, err := db.SuspendCertificate(caID, serial, time.Now()); err != nil {
		t.Fatalf("re-suspend: %v", err)
	}
	if released, _ := db.ListReleasedHolds(caID); len(released) != 0 {
		t.Errorf("release marker not cleared on re-suspend: %+v", released)
	}
}

func testHoldRejectsPermanent(t *testing.T, db *DB) {
	const caID, serial = "perm-ca", "000007"
	seedHoldCA(t, db, caID, serial)

	// Permanent revocation (keyCompromise).
	if _, err := db.RevokeCertificate(caID, serial, 1, time.Now()); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	// Release is refused with ErrNotOnHold; the revocation is unchanged.
	if err := db.ReleaseHold(caID, serial, time.Now()); !errors.Is(err, ErrNotOnHold) {
		t.Fatalf("release of keyCompromise: err = %v, want ErrNotOnHold", err)
	}
	if rc, _ := db.GetRevokedCertificate(caID, serial); rc == nil || rc.Reason != 1 {
		t.Fatalf("revocation after refused release = %+v, want reason keyCompromise", rc)
	}
	// Suspend of a permanently revoked serial is refused too.
	if _, err := db.SuspendCertificate(caID, serial, time.Now()); err == nil {
		t.Error("suspend of a permanently revoked serial unexpectedly succeeded")
	}

	// Releasing a never-revoked serial is ErrNotRevoked.
	if err := db.ReleaseHold(caID, "999999", time.Now()); !errors.Is(err, ErrNotRevoked) {
		t.Errorf("release of never-revoked serial: err = %v, want ErrNotRevoked", err)
	}
}

// --- SQLite (always) ---

func holdSQLiteDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", t.TempDir()+"/hold-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestHoldStoreSQLite(t *testing.T)            { testHoldStore(t, holdSQLiteDB(t)) }
func TestHoldRejectsPermanentSQLite(t *testing.T) { testHoldRejectsPermanent(t, holdSQLiteDB(t)) }

// --- PostgreSQL (when SECSY_TEST_PG_DSN is set) ---

func TestHoldStorePostgres(t *testing.T)            { testHoldStore(t, freshPostgres(t)) }
func TestHoldRejectsPermanentPostgres(t *testing.T) { testHoldRejectsPermanent(t, freshPostgres(t)) }
