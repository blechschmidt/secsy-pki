//go:build sqlite

package retention

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const testCA = "runner-ca"

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// seed records one valid (future), one long-expired, and one long-expired+revoked
// certificate relative to now. Two rows (the two long-expired ones) are eligible
// under a 90-day grace window.
func seed(t *testing.T, db *database.DB, now time.Time) {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID: testCA, Label: testCA, PKCS11URI: "pkcs11:" + testCA,
		KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	rec := func(serial string, notAfter time.Time, status models.CertStatus) {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: testCA + "-" + serial, CAID: testCA, Serial: serial,
			CommonName: serial, Profile: "server",
			Certificate: "-----BEGIN CERTIFICATE-----\n" + serial + "\n-----END CERTIFICATE-----\n",
			NotBefore:   notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter, Status: status,
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%s): %v", serial, err)
		}
	}
	rec("2001", now.Add(90*24*time.Hour), models.CertStatusValid)  // valid   -> retained
	rec("2002", now.Add(-200*24*time.Hour), models.CertStatusExpired) // eligible
	rec("2003", now.Add(-200*24*time.Hour), models.CertStatusValid)   // eligible after revoke
	if _, err := db.RevokeCertificate(testCA, "2003", 1, now); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
}

func newRunner(t *testing.T, db *database.DB, cfg config.RetentionConfig, now time.Time) *Runner {
	t.Helper()
	r, err := New(db, cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.SetClock(func() time.Time { return now })
	return r
}

func lastRetentionEvent(t *testing.T, db *database.DB) audit.Event {
	t.Helper()
	events, _, err := db.ListEvents(audit.ActionInventoryRetention, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("inventory.retention events = %d, want exactly 1", len(events))
	}
	return events[0]
}

func TestRunnerArchiveMode(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	seed(t, db, now)
	r := newRunner(t, db, config.RetentionConfig{Enabled: true, Mode: "archive", MinAgeDays: 90}, now)

	res, err := r.RunNow(context.Background())
	if err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if res.Mode != "archive" || res.Archived != 2 || res.Pruned != 0 {
		t.Fatalf("result = %+v, want mode=archive archived=2 pruned=0", res)
	}
	if res.Eligible != 2 || res.Backlog != 0 || res.ArchiveSize != 2 {
		t.Errorf("counts = eligible %d backlog %d archive %d, want 2/0/2", res.Eligible, res.Backlog, res.ArchiveSize)
	}
	if !strings.HasPrefix(res.Digest, "sha256:") || len(res.Digest) < 20 {
		t.Errorf("digest = %q, want a sha256 manifest digest", res.Digest)
	}

	// Eligible rows moved to the archive; the valid one is retained.
	for _, s := range []string{"2002", "2003"} {
		if ic, _ := db.GetIssuedCertificate(testCA, s); ic != nil {
			t.Errorf("serial %s still in hot table", s)
		}
		if ar, _ := db.GetArchivedCertificate(testCA, s); ar == nil {
			t.Errorf("serial %s not archived", s)
		}
	}
	if ic, _ := db.GetIssuedCertificate(testCA, "2001"); ic == nil {
		t.Error("valid serial 2001 was archived")
	}

	// A single tamper-evident audit event carrying the digest.
	ev := lastRetentionEvent(t, db)
	if ev.Result != audit.ResultSuccess {
		t.Errorf("audit result = %q, want success", ev.Result)
	}
	if !strings.Contains(ev.Detail, "mode=archive") || !strings.Contains(ev.Detail, "archived=2") ||
		!strings.Contains(ev.Detail, res.Digest) {
		t.Errorf("audit detail = %q, want mode/archived/digest", ev.Detail)
	}
}

func TestRunnerPruneMode(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	seed(t, db, now)
	r := newRunner(t, db, config.RetentionConfig{Enabled: true, Mode: "prune", MinAgeDays: 90}, now)

	res, err := r.RunNow(context.Background())
	if err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if res.Archived != 2 || res.Pruned != 2 || res.ArchiveSize != 0 {
		t.Fatalf("result = %+v, want archived=2 pruned=2 archive_size=0", res)
	}
	// Eligible rows are gone from both the hot table and the archive...
	for _, s := range []string{"2002", "2003"} {
		if ic, _ := db.GetIssuedCertificate(testCA, s); ic != nil {
			t.Errorf("serial %s still in hot table after prune", s)
		}
		if ar, _ := db.GetArchivedCertificate(testCA, s); ar != nil {
			t.Errorf("serial %s still in archive after prune", s)
		}
	}
	// ...but the revocation of the pruned revoked serial survives (OCSP/CRL intact).
	if rc, _ := db.GetRevokedCertificate(testCA, "2003"); rc == nil {
		t.Error("revocation for pruned serial 2003 was removed — CRL/OCSP would regress")
	}
	if ic, _ := db.GetIssuedCertificate(testCA, "2001"); ic == nil {
		t.Error("valid serial 2001 was pruned")
	}
}

func TestRunnerDryRunDoesNotMutate(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	seed(t, db, now)
	r := newRunner(t, db, config.RetentionConfig{Enabled: true, Mode: "prune", MinAgeDays: 90}, now)

	res, err := r.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !res.DryRun || res.Archived != 2 || res.Pruned != 2 {
		t.Fatalf("dry-run result = %+v, want dry_run archived=2 pruned=2", res)
	}
	// Nothing moved or deleted.
	for _, s := range []string{"2002", "2003"} {
		if ic, _ := db.GetIssuedCertificate(testCA, s); ic == nil {
			t.Errorf("dry-run mutated the hot table: serial %s missing", s)
		}
	}
	if n, _ := db.CountArchivedCertificates(); n != 0 {
		t.Errorf("dry-run populated the archive (size %d)", n)
	}
	if events, _, _ := db.ListEvents(audit.ActionInventoryRetention, "", "", 10, 0); len(events) != 0 {
		t.Errorf("dry-run wrote %d audit events, want 0", len(events))
	}
}

func TestRunnerSnapshot(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	seed(t, db, now)
	r := newRunner(t, db, config.RetentionConfig{Enabled: true, Mode: "prune", MinAgeDays: 90}, now)

	snap, err := r.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Mode != "prune" || snap.Eligible != 2 || snap.ArchiveSize != 0 || snap.Prunable != 2 {
		t.Errorf("snapshot = %+v, want mode=prune eligible=2 archive=0 prunable=2", snap)
	}
	if n, _ := db.CountArchivedCertificates(); n != 0 {
		t.Error("Snapshot mutated the archive")
	}
}

func TestNewRejectsBadMode(t *testing.T) {
	db := newTestDB(t)
	if _, err := New(db, config.RetentionConfig{Mode: "delete-everything"}, nil); err == nil {
		t.Fatal("New accepted an invalid mode")
	}
}

// TestRunnerHonorsGraceWindow proves a certificate that expired more recently
// than the grace window is not eligible (retained), and becomes eligible only
// once the clock advances past it.
func TestRunnerHonorsGraceWindow(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	if err := db.CreateCA(&models.CA{ID: testCA, Label: testCA, PKCS11URI: "pkcs11:x", KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x"}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	// Expired 30 days ago; grace window is 90 days.
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID: testCA + "-3001", CAID: testCA, Serial: "3001", CommonName: "c", Profile: "server",
		Certificate: "x", NotBefore: now.Add(-400 * 24 * time.Hour), NotAfter: now.Add(-30 * 24 * time.Hour),
		Status: models.CertStatusExpired,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	cfg := config.RetentionConfig{Enabled: true, Mode: "archive", MinAgeDays: 90}
	r := newRunner(t, db, cfg, now)
	if res, _ := r.RunNow(context.Background()); res.Archived != 0 {
		t.Fatalf("archived %d within grace window, want 0 (retained)", res.Archived)
	}
	if ic, _ := db.GetIssuedCertificate(testCA, "3001"); ic == nil {
		t.Fatal("serial 3001 archived despite being within the grace window")
	}

	// Advance the clock 90 days: now it is more than 90 days past not_after.
	r.SetClock(func() time.Time { return now.Add(90 * 24 * time.Hour) })
	if res, _ := r.RunNow(context.Background()); res.Archived != 1 {
		t.Fatalf("archived %d after grace elapsed, want 1", res.Archived)
	}
}
