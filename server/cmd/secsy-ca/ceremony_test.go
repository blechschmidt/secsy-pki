//go:build sqlite

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// testHarness wires a temp SQLite database, a software key provider, and a CA
// manager for exercising the ceremony/backup/restore commands without an HSM.
type testHarness struct {
	db       *database.DB
	provider keyprovider.Provider
	mgr      *ca.Manager
	cfg      *config.Config
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New("sqlite", filepath.Join(dir, "secsy.db"))
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: filepath.Join(dir, "keys")},
	})
	if err != nil {
		t.Fatalf("building software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	return &testHarness{
		db:       db,
		provider: provider,
		mgr:      ca.NewManager(db, provider),
		cfg:      &config.Config{},
	}
}

// writeConfirmFile writes a name:phrase confirmation file and returns its path.
func writeConfirmFile(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "confirm.txt")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSplitOperatorsAndDigest(t *testing.T) {
	got := splitOperators(" alice , bob,, carol ")
	want := []string{"alice", "bob", "carol"}
	if len(got) != len(want) {
		t.Fatalf("splitOperators = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitOperators[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The digest must be stable and must not echo the phrase back.
	d := confirmationDigest("alice", "s3cret")
	if d == "" || len(d) != 64 {
		t.Fatalf("unexpected digest %q", d)
	}
	if confirmationDigest("alice", "s3cret") != d {
		t.Fatal("digest is not deterministic")
	}
	if confirmationDigest("alice", "other") == d {
		t.Fatal("digest does not depend on the phrase")
	}
}

func TestCeremonyRootQuorumMet(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "alice:phrase-a\nbob:phrase-b\n")
	transcript := filepath.Join(t.TempDir(), "root.json")

	err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "root-ca", "-cn", "Test Root",
		"-key-type", "ecdsa-p256",
		"-operators", "alice,bob,carol", "-quorum", "2",
		"-confirm-file", confirm, "-transcript-out", transcript,
	})
	if err != nil {
		t.Fatalf("cmdCeremony: %v", err)
	}

	// The CA must now exist.
	caRec, err := h.db.GetCAByLabel("root-ca")
	if err != nil || caRec == nil {
		t.Fatalf("expected root-ca to exist: %v", err)
	}

	// The transcript must be present and contain no private key material.
	data, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatalf("reading transcript: %v", err)
	}
	if string(data) == "" {
		t.Fatal("empty transcript")
	}
	if containsPrivateKey(data) {
		t.Fatal("transcript leaked private key material")
	}

	// The audit log must record start, two operator confirmations, the
	// init-root, and completion.
	assertAuditAction(t, h.db, audit.ActionCeremonyStart, 1)
	assertAuditAction(t, h.db, audit.ActionCeremonyOperatorConfirm, 2)
	assertAuditAction(t, h.db, audit.ActionCAInitRoot, 1)
	assertAuditAction(t, h.db, audit.ActionCeremonyComplete, 1)

	if vr, err := h.db.VerifyEventChain(); err != nil || !vr.Valid {
		t.Fatalf("audit chain invalid after ceremony: %+v err=%v", vr, err)
	}
}

func TestCeremonyQuorumNotMet(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "alice:only-me\n")

	err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "should-not-exist", "-cn", "Nope",
		"-operators", "alice,bob,carol", "-quorum", "2",
		"-confirm-file", confirm,
	})
	if err == nil {
		t.Fatal("expected ceremony to fail without quorum")
	}
	if caRec, _ := h.db.GetCAByLabel("should-not-exist"); caRec != nil {
		t.Fatal("CA was created despite quorum failure")
	}
	assertAuditAction(t, h.db, audit.ActionCeremonyAbort, 1)
}

func TestCeremonyRejectsUnenrolledOperator(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "mallory:intruder\n")

	err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "nope-ca", "-cn", "Nope",
		"-operators", "alice,bob", "-quorum", "1",
		"-confirm-file", confirm,
	})
	if err == nil {
		t.Fatal("expected ceremony to reject an unenrolled operator")
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "alice:a\nbob:b\n")

	// Create a root and an intermediate via ceremonies.
	if err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "root-ca", "-cn", "Root",
		"-operators", "alice,bob", "-quorum", "2", "-confirm-file", confirm,
		"-transcript-out", filepath.Join(t.TempDir(), "r.json"),
	}); err != nil {
		t.Fatalf("root ceremony: %v", err)
	}
	if err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "intermediate", "-parent", "root-ca", "-label", "int-ca", "-cn", "Int",
		"-key-type", "ecdsa-p256",
		"-operators", "alice,bob", "-quorum", "2", "-confirm-file", confirm,
		"-transcript-out", filepath.Join(t.TempDir(), "i.json"),
	}); err != nil {
		t.Fatalf("intermediate ceremony: %v", err)
	}

	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := cmdBackup(h.db, h.cfg, h.provider, []string{"-out", backupDir}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	for _, f := range []string{"manifest.json", "cas.json", "events.json", "metadata.db"} {
		if _, err := os.Stat(filepath.Join(backupDir, f)); err != nil {
			t.Fatalf("backup missing %s: %v", f, err)
		}
	}
	// The backup must never contain plaintext private keys.
	assertNoPrivateKeyInDir(t, backupDir)

	// Restore against the same store + provider (keys still present) must verify.
	if err := cmdRestore(h.db, h.cfg, h.provider, []string{"-in", backupDir}); err != nil {
		t.Fatalf("restore verification failed: %v", err)
	}
}

func TestRestoreDetectsMissingKey(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "alice:a\nbob:b\n")
	if err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "root-ca", "-cn", "Root",
		"-operators", "alice,bob", "-quorum", "2", "-confirm-file", confirm,
		"-transcript-out", filepath.Join(t.TempDir(), "r.json"),
	}); err != nil {
		t.Fatalf("root ceremony: %v", err)
	}
	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := cmdBackup(h.db, h.cfg, h.provider, []string{"-out", backupDir}); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Simulate loss of the key material only (metadata intact). Restore must
	// detect that the provider no longer holds the CA key.
	freshProvider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: filepath.Join(t.TempDir(), "empty-keys")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer freshProvider.Close()

	if err := cmdRestore(h.db, h.cfg, freshProvider, []string{"-in", backupDir}); err == nil {
		t.Fatal("expected restore to fail when the key provider is missing the CA key")
	}
}

func TestInventoryListsKeys(t *testing.T) {
	h := newTestHarness(t)
	confirm := writeConfirmFile(t, "alice:a\nbob:b\n")
	if err := cmdCeremony(h.db, h.mgr, h.provider, []string{
		"-role", "root", "-label", "root-ca", "-cn", "Root",
		"-operators", "alice,bob", "-quorum", "2", "-confirm-file", confirm,
		"-transcript-out", filepath.Join(t.TempDir(), "r.json"),
	}); err != nil {
		t.Fatalf("root ceremony: %v", err)
	}
	// A plain inventory listing must succeed.
	if err := cmdInventory(h.db, h.provider, nil); err != nil {
		t.Fatalf("inventory: %v", err)
	}
	// The software provider reports keys as extractable, so -strict must fail —
	// exactly the signal that on-disk keys are unfit for production CA use.
	if err := cmdInventory(h.db, h.provider, []string{"-strict"}); err == nil {
		t.Fatal("expected -strict inventory to fail for the software provider")
	}
}

// assertAuditAction fails if the audit log does not contain exactly want events
// with the given action.
func assertAuditAction(t *testing.T, db *database.DB, action string, want int) {
	t.Helper()
	_, total, err := db.ListEvents(action, "", "", 1, 0)
	if err != nil {
		t.Fatalf("listing events for %q: %v", action, err)
	}
	if total != want {
		t.Fatalf("action %q count = %d, want %d", action, total, want)
	}
}

func containsPrivateKey(data []byte) bool {
	return strings.Contains(string(data), "PRIVATE KEY")
}

func assertNoPrivateKeyInDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if containsPrivateKey(data) {
			t.Fatalf("backup file %s contains private key material", e.Name())
		}
	}
}
