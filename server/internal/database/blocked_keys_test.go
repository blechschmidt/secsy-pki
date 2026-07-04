//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newBlockedKeyTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBlockedKeys_Lifecycle(t *testing.T) {
	db := newBlockedKeyTestDB(t)
	const fp = "SHA256:abc123def456"

	// Absent initially.
	if blocked, err := db.IsKeyBlocked(fp); err != nil || blocked {
		t.Fatalf("IsKeyBlocked before add = (%v, %v), want (false, nil)", blocked, err)
	}
	if got, err := db.GetBlockedKey(fp); err != nil || got != nil {
		t.Fatalf("GetBlockedKey before add = (%v, %v), want (nil, nil)", got, err)
	}

	// Add.
	added, err := db.AddBlockedKey(&models.BlockedKey{Fingerprint: fp, Reason: "compromise", Source: "cli", AddedBy: "alice"})
	if err != nil {
		t.Fatalf("AddBlockedKey: %v", err)
	}
	if !added {
		t.Fatal("AddBlockedKey reported not-newly-added on first insert")
	}

	// Idempotent: adding again reports false, does not duplicate.
	again, err := db.AddBlockedKey(&models.BlockedKey{Fingerprint: fp, Reason: "again"})
	if err != nil {
		t.Fatalf("AddBlockedKey (dup): %v", err)
	}
	if again {
		t.Fatal("AddBlockedKey reported newly-added on a duplicate fingerprint")
	}

	// Present now.
	if blocked, err := db.IsKeyBlocked(fp); err != nil || !blocked {
		t.Fatalf("IsKeyBlocked after add = (%v, %v), want (true, nil)", blocked, err)
	}
	got, err := db.GetBlockedKey(fp)
	if err != nil || got == nil {
		t.Fatalf("GetBlockedKey after add = (%v, %v), want a row", got, err)
	}
	if got.Reason != "compromise" || got.Source != "cli" || got.AddedBy != "alice" {
		t.Errorf("stored fields = %+v, want the first insert's values (conflict must not overwrite)", got)
	}
	if got.AddedAt.IsZero() {
		t.Error("AddedAt not stamped")
	}

	if n, err := db.CountBlockedKeys(); err != nil || n != 1 {
		t.Fatalf("CountBlockedKeys = (%d, %v), want (1, nil)", n, err)
	}
	list, err := db.ListBlockedKeys()
	if err != nil || len(list) != 1 || list[0].Fingerprint != fp {
		t.Fatalf("ListBlockedKeys = (%v, %v), want one entry for %q", list, err, fp)
	}

	// Remove.
	removed, err := db.RemoveBlockedKey(fp)
	if err != nil || !removed {
		t.Fatalf("RemoveBlockedKey = (%v, %v), want (true, nil)", removed, err)
	}
	if again, _ := db.RemoveBlockedKey(fp); again {
		t.Fatal("RemoveBlockedKey reported a removal for an absent fingerprint")
	}
	if blocked, _ := db.IsKeyBlocked(fp); blocked {
		t.Fatal("key still blocked after removal")
	}

	// An empty fingerprint is never blocked (hot-path guard).
	if blocked, err := db.IsKeyBlocked(""); err != nil || blocked {
		t.Fatalf("IsKeyBlocked(\"\") = (%v, %v), want (false, nil)", blocked, err)
	}
}

func TestDistinctSubjectsForKeyFingerprint(t *testing.T) {
	db := newBlockedKeyTestDB(t)

	// Seed a CA and three issued certs: two subjects sharing one key fingerprint,
	// and a third with a different key.
	seedTenantAndCA(t, db, "ca1")
	const sharedFP = "SHA256:shared"
	insertIssuedCert(t, db, "ca1", "10", "CN=alice", sharedFP)
	insertIssuedCert(t, db, "ca1", "11", "CN=bob", sharedFP)
	insertIssuedCert(t, db, "ca1", "12", "CN=carol", "SHA256:other")

	subs, err := db.DistinctSubjectsForKeyFingerprint(sharedFP, "")
	if err != nil {
		t.Fatalf("DistinctSubjectsForKeyFingerprint: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("distinct subjects = %v, want 2 (alice, bob)", subs)
	}

	// Excluding one serial drops its subject if it is otherwise unique for the key.
	subs, err = db.DistinctSubjectsForKeyFingerprint(sharedFP, "10")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0] != "CN=bob" {
		t.Fatalf("with serial 10 excluded, subjects = %v, want [CN=bob]", subs)
	}

	// An empty fingerprint matches nothing.
	if subs, err := db.DistinctSubjectsForKeyFingerprint("", ""); err != nil || subs != nil {
		t.Fatalf("empty fingerprint = (%v, %v), want (nil, nil)", subs, err)
	}
}

// seedTenantAndCA inserts a minimal CA row so issued_certificates' foreign key is
// satisfied (the default tenant is created by database initialization).
func seedTenantAndCA(t *testing.T, db *DB, caID string) {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID: caID, Label: caID, PKCS11URI: "pkcs11:" + caID,
		KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
}

func insertIssuedCert(t *testing.T, db *DB, caID, serial, subject, fp string) {
	t.Helper()
	rec := &models.IssuedCertificate{
		ID: caID + "-" + serial, CAID: caID, Serial: serial, Subject: subject,
		Certificate: "PEM", Status: models.CertStatusValid, PublicKeyFingerprint: fp,
		NotBefore: time.Now().UTC(), NotAfter: time.Now().UTC().Add(time.Hour),
	}
	if err := db.RecordIssuedCertificate(rec); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}
}
