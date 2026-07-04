//go:build sqlite

package main

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/backup"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// TestCmdBackupVerifyRestore exercises the `secsy-ca backup verify-restore` CLI
// handler end-to-end with no HSM: it resolves the store and KEK from config,
// reports a non-zero exit when nothing is published, then verifies a real
// scheduled backup produced into the configured destination and records the
// backup.verify audit event. This proves the config→store wiring the background
// job shares, independent of the internal/backup Verifier's own tests.
func TestCmdBackupVerifyRestore(t *testing.T) {
	h := newTestHarness(t)
	const kek = "cli-verify-kek"
	if _, err := secret.ProvisionKEK(context.Background(), h.provider, kek, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("provision KEK: %v", err)
	}
	// The on-demand CLI works regardless of whether the scheduled job is enabled.
	h.cfg.Secret.KEKLabel = kek
	h.cfg.Backup.Dir.Path = t.TempDir()

	// Nothing published yet: the CLI must report a skip and return non-zero so a
	// DR drill / CI step trips on it.
	if err := cmdBackupVerifyRestore(h.db, h.cfg, h.provider, nil); err == nil {
		t.Fatal("verify-restore with no published backup should return an error")
	}

	// Produce a real scheduled backup into the configured destination.
	store, err := backup.NewStore(h.cfg.Backup)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	runner, err := backup.New(
		backup.Source{DB: h.db, Provider: h.provider, DSN: h.cfg.Database.DSN},
		store, h.cfg.Backup, kek, nil)
	if err != nil {
		t.Fatalf("New runner: %v", err)
	}
	runner.RunOnce(context.Background())

	// Now the CLI verifies it end-to-end and returns success.
	if err := cmdBackupVerifyRestore(h.db, h.cfg, h.provider, nil); err != nil {
		t.Fatalf("verify-restore should succeed on a real backup: %v", err)
	}

	// Exactly one successful backup.verify event (the skip did not audit).
	events, _, err := h.db.ListEvents(audit.ActionBackupVerify, "", "", 10, 0)
	if err != nil {
		t.Fatalf("list backup.verify: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultSuccess {
		t.Fatalf("want one successful backup.verify event, got %+v", events)
	}
}
