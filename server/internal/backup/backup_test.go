//go:build sqlite

package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

const testKEKLabel = "backup-kek"

// newTestDB opens a file-backed SQLite store (so a VACUUM INTO snapshot has a
// real file to copy) seeded with one CA and a few audit events, and returns the
// handle plus its path.
func newTestDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meta.db")
	db, err := database.New("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.CreateCA(&models.CA{
		ID: "root-ca", Label: "Root CA", PKCS11URI: "software:root-ca",
		KeyType: "ecdsa-p384", PublicKey: "ssh-ed25519 AAAAC3Nz", Certificate: "PEM",
		Subject: "CN=Root CA", Serial: "1",
	}); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: "seed", Actor: "tester", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	return db, path
}

// newTestProvider returns a software key provider with a freshly provisioned RSA
// KEK — no HSM required, so the test runs in ordinary CI.
func newTestProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if _, err := secret.ProvisionKEK(context.Background(), p, testKEKLabel, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("provision KEK: %v", err)
	}
	return p
}

func testRing(t *testing.T, db *database.DB, p keyprovider.Provider) *secret.Ring {
	t.Helper()
	versions, err := db.ListKEKVersions(testKEKLabel)
	if err != nil {
		t.Fatalf("list KEK versions: %v", err)
	}
	ring, err := secret.LoadRing(context.Background(), p, testKEKLabel, versions)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	return ring
}

func backupCfg(keep, maxAgeDays int) config.BackupConfig {
	return config.BackupConfig{
		Enabled:   true,
		Retention: config.BackupRetentionConfig{Keep: keep, MaxAgeDays: maxAgeDays},
	}
}

// TestScheduledBackupCycleAndRestore is the task's end-to-end test: it runs one
// scheduled backup cycle (produce → encrypt → publish with atomic swap + manifest
// → retain → audit), then decrypts the published artifact and verifies it
// restores to a store whose disaster-recovery fingerprint matches the source.
func TestScheduledBackupCycleAndRestore(t *testing.T) {
	ctx := context.Background()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)

	// A config file to bundle into the (encrypted) archive.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgBytes := []byte("server:\n  host: 0.0.0.0\n  port: 8443\n")
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Source DR fingerprint at snapshot time (before RunOnce appends backup.run).
	srcFP, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatalf("source fingerprint: %v", err)
	}

	destDir := t.TempDir()
	store, err := publish.NewDirStore(destDir, 3)
	if err != nil {
		t.Fatalf("dir store: %v", err)
	}
	runner, err := New(Source{DB: db, Provider: provider, ConfigPath: cfgPath}, store, backupCfg(3, 0), testKEKLabel, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runner.RunOnce(ctx)

	// A backup.run success event must have been recorded.
	events, _, err := db.ListEvents(audit.ActionBackupRun, "", "", 10, 0)
	if err != nil {
		t.Fatalf("list backup.run: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultSuccess {
		t.Fatalf("want one successful backup.run event, got %+v", events)
	}

	// The published outer manifest (plaintext) describes an encrypted artifact.
	rawManifest, err := store.Fetch(ctx, publish.ManifestPath)
	if err != nil {
		t.Fatalf("fetch outer manifest: %v", err)
	}
	var outer OuterManifest
	if err := json.Unmarshal(rawManifest, &outer); err != nil {
		t.Fatalf("decode outer manifest: %v", err)
	}
	if !outer.Encrypted || outer.ArtifactFile != ArtifactName || outer.CACount != 1 {
		t.Fatalf("unexpected outer manifest: %+v", outer)
	}

	// Fetch and decrypt the artifact, then verify the archive integrity.
	blob, err := store.Fetch(ctx, ArtifactName)
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	if outer.ArtifactSize != len(blob) {
		t.Fatalf("outer manifest size %d != blob %d", outer.ArtifactSize, len(blob))
	}
	// The blob must be a secret envelope (encrypted), never the plaintext tar:
	// it carries the envelope ciphertext field but none of the archive's own
	// (plaintext-only) manifest markers.
	if indexOf(blob, []byte("ciphertext")) < 0 {
		t.Fatal("published artifact is not a secret envelope")
	}
	if leaksPlaintext(blob) {
		t.Fatal("published artifact leaks plaintext archive content")
	}

	archive, err := Decrypt(ctx, testRing(t, db, provider), blob)
	if err != nil {
		t.Fatalf("decrypt/open archive: %v", err)
	}
	if archive.Manifest.DBDriver != "sqlite" || archive.Manifest.DumpFile != fileSQLite {
		t.Fatalf("unexpected archive manifest: %+v", archive.Manifest)
	}
	if !archive.Manifest.IncludesConfig {
		t.Fatal("archive should include the config")
	}
	if got := archive.Files[fileConfig]; string(got) != string(cfgBytes) {
		t.Fatalf("bundled config mismatch:\n got %q\nwant %q", got, cfgBytes)
	}
	if len(archive.Manifest.CAs) != 1 || archive.Manifest.CAs[0].ID != "root-ca" {
		t.Fatalf("archive CA material wrong: %+v", archive.Manifest.CAs)
	}

	// Restore the SQLite snapshot and verify its DR fingerprint matches the source.
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := archive.RestoreSQLite(restoredPath); err != nil {
		t.Fatalf("restore sqlite: %v", err)
	}
	restored, err := database.OpenExisting("sqlite", restoredPath)
	if err != nil {
		t.Fatalf("open restored db: %v", err)
	}
	defer restored.Close()

	restoredFP, err := restored.VerifyStoreIntegrity()
	if err != nil {
		t.Fatalf("restored fingerprint: %v", err)
	}
	if !restoredFP.OK {
		t.Fatalf("restored store failed integrity: %+v", restoredFP.Checks)
	}
	if restoredFP.Fingerprint.AuditHeadHash != srcFP.Fingerprint.AuditHeadHash {
		t.Fatalf("restored audit head %s != source %s", restoredFP.Fingerprint.AuditHeadHash, srcFP.Fingerprint.AuditHeadHash)
	}
	if restoredFP.Fingerprint.AuditEventCount != srcFP.Fingerprint.AuditEventCount {
		t.Fatalf("restored event count %d != source %d", restoredFP.Fingerprint.AuditEventCount, srcFP.Fingerprint.AuditEventCount)
	}
	if restoredFP.Fingerprint.AuditHeadHash != archive.Manifest.AuditHeadHash {
		t.Fatalf("restored head %s != manifest head %s", restoredFP.Fingerprint.AuditHeadHash, archive.Manifest.AuditHeadHash)
	}

	// The seeded CA must have survived the round-trip.
	ca, err := restored.GetCA("root-ca")
	if err != nil || ca == nil {
		t.Fatalf("seeded CA missing from restored store: ca=%v err=%v", ca, err)
	}
	if ca.Subject != "CN=Root CA" {
		t.Fatalf("restored CA subject wrong: %q", ca.Subject)
	}
}

// TestBackupRetentionKeepN verifies keep-N retention: after more runs than the
// keep count, only the newest N backups remain.
func TestBackupRetentionKeepN(t *testing.T) {
	ctx := context.Background()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)

	const keep = 3
	store, err := publish.NewDirStore(t.TempDir(), keep)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(Source{DB: db, Provider: provider}, store, backupCfg(keep, 0), testKEKLabel, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		runner.RunOnce(ctx)
	}

	snaps, err := store.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != keep {
		t.Fatalf("keep-%d retention: got %d snapshots, want %d", keep, len(snaps), keep)
	}
	// Exactly one is the current (restorable-latest) backup.
	current := 0
	for _, s := range snaps {
		if s.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("want exactly one current snapshot, got %d", current)
	}
}

// TestBackupRetentionMaxAge verifies max-age retention: with a generous keep but
// a short max age, an advanced clock prunes every non-current backup, leaving
// only the current one (a backup is never left with zero restorable copies).
func TestBackupRetentionMaxAge(t *testing.T) {
	ctx := context.Background()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)

	store, err := publish.NewDirStore(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(Source{DB: db, Provider: provider}, store, backupCfg(100, 1 /* day */), testKEKLabel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Two backups at "now".
	runner.RunOnce(ctx)
	runner.RunOnce(ctx)
	if snaps, _ := store.ListSnapshots(ctx); len(snaps) != 2 {
		t.Fatalf("precondition: want 2 snapshots, got %d", len(snaps))
	}

	// Jump the retention clock two days ahead; the two older backups now exceed
	// the 1-day max age. A third run prunes them, keeping only its own (current).
	runner.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	runner.RunOnce(ctx)

	snaps, err := store.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("max-age retention: got %d snapshots, want 1 (current only)", len(snaps))
	}
	if !snaps[0].Current {
		t.Fatal("the surviving snapshot must be the current one")
	}
}

// leaksPlaintext reports whether the (supposedly encrypted) blob contains any
// archive-only plaintext marker — a guard that the publish path really encrypted
// the artifact. These fields live only inside the inner archive manifest, never
// in the envelope wrapper or the plaintext outer manifest.
func leaksPlaintext(blob []byte) bool {
	for _, marker := range [][]byte{[]byte("public_key_fingerprint_sha256"), []byte("dump_file")} {
		if indexOf(blob, marker) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
