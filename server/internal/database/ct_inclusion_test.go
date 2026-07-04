//go:build sqlite

package database

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// seedCAForInclusion inserts a minimal CA row so sct_inclusion's FK is satisfied.
func seedCAForInclusion(t *testing.T, db *DB, id string) {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID:        id,
		TenantID:  models.DefaultTenantID,
		Label:     id,
		PKCS11URI: "pkcs11:token=" + id,
		KeyType:   "ecdsa",
		PublicKey: "test",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
}

func TestSCTInclusionRoundTrip(t *testing.T) {
	db, err := New("sqlite", filepath.Join(t.TempDir(), "ct.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()
	seedCAForInclusion(t, db, "ca1")

	now := time.Now().UTC().Truncate(time.Second)
	rec := &models.SCTInclusion{
		CAID:           "ca1",
		Serial:         "1001",
		LogID:          "aa11",
		LogName:        "argon2026",
		SCTTimestamp:   now.Add(-48 * time.Hour),
		Status:         models.SCTInclusionPending,
		Checks:         1,
		LastError:      "still merging",
		FirstCheckedAt: &now,
		LastCheckedAt:  &now,
	}
	if err := db.UpsertSCTInclusion(rec); err != nil {
		t.Fatalf("UpsertSCTInclusion insert: %v", err)
	}

	got, err := db.GetSCTInclusion("ca1", "1001", "aa11")
	if err != nil || got == nil {
		t.Fatalf("GetSCTInclusion: %v (got %v)", err, got)
	}
	if got.Status != models.SCTInclusionPending || got.LogName != "argon2026" || got.Checks != 1 {
		t.Fatalf("unexpected row after insert: %+v", got)
	}
	if got.LastError != "still merging" {
		t.Fatalf("last_error not persisted: %q", got.LastError)
	}
	if got.FirstCheckedAt == nil || !got.FirstCheckedAt.Equal(now) {
		t.Fatalf("first_checked_at not persisted: %v", got.FirstCheckedAt)
	}

	// Update to included: identity + first_checked_at preserved, state overwritten.
	included := now.Add(time.Minute)
	rec.Status = models.SCTInclusionIncluded
	rec.TreeSize = 500
	rec.LeafIndex = 123
	rec.Checks = 2
	rec.LastError = ""
	rec.IncludedAt = &included
	rec.LastCheckedAt = &included
	rec.FirstCheckedAt = nil // must not clobber the stored first-check time
	if err := db.UpsertSCTInclusion(rec); err != nil {
		t.Fatalf("UpsertSCTInclusion update: %v", err)
	}
	got, err = db.GetSCTInclusion("ca1", "1001", "aa11")
	if err != nil || got == nil {
		t.Fatalf("GetSCTInclusion after update: %v", err)
	}
	if got.Status != models.SCTInclusionIncluded || got.TreeSize != 500 || got.LeafIndex != 123 {
		t.Fatalf("update not applied: %+v", got)
	}
	if got.LastError != "" {
		t.Fatalf("last_error should be cleared, got %q", got.LastError)
	}
	if got.FirstCheckedAt == nil || !got.FirstCheckedAt.Equal(now) {
		t.Fatalf("first_checked_at must be preserved across update: %v", got.FirstCheckedAt)
	}
	if got.IncludedAt == nil || !got.IncludedAt.Equal(included) {
		t.Fatalf("included_at not persisted: %v", got.IncludedAt)
	}

	// A failed SCT for a second log, and a per-cert + status listing.
	fail := &models.SCTInclusion{
		CAID: "ca1", Serial: "1001", LogID: "bb22", LogName: "nessie",
		SCTTimestamp: now.Add(-72 * time.Hour), Status: models.SCTInclusionFailed,
		LastError: "never included", Alerted: true, LastCheckedAt: &included,
	}
	if err := db.UpsertSCTInclusion(fail); err != nil {
		t.Fatalf("UpsertSCTInclusion fail: %v", err)
	}

	perCert, err := db.ListSCTInclusionForCert("ca1", "1001")
	if err != nil || len(perCert) != 2 {
		t.Fatalf("ListSCTInclusionForCert = %d rows (%v)", len(perCert), err)
	}

	failed, err := db.ListSCTInclusionByStatus(models.SCTInclusionFailed, 0)
	if err != nil || len(failed) != 1 || failed[0].LogID != "bb22" || !failed[0].Alerted {
		t.Fatalf("ListSCTInclusionByStatus(failed) = %+v (%v)", failed, err)
	}

	counts, err := db.CountSCTInclusionByStatus()
	if err != nil {
		t.Fatalf("CountSCTInclusionByStatus: %v", err)
	}
	if counts[models.SCTInclusionIncluded] != 1 || counts[models.SCTInclusionFailed] != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
}
