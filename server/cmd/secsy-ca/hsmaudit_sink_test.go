//go:build sqlite

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// The append-only file is the Service's, not only the post-command drain's:
// `provision`, `export`, `timestamp` and `commit` each drain the device
// themselves, and before this their entries reached the database and nothing
// else. Provisioning is the one that mattered most — it collects the device-init
// sentinel, and a file that does not start there cannot be pinned to the chain
// anchor at all.
//
// The flip side is that opening the file creates it, which a read-only command
// has no business doing. These two tests hold both ends of the dispatch.

func hsmAuditTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "cli.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// `status` reports on the file — including "not written yet" — and must not
// bring it into existence. An operator inspecting a deployment should not find
// that the inspection created the evidence file, nor that it failed because the
// configured path belongs to a host they are not on.
func TestHSMAuditStatusDoesNotCreateTheLogFile(t *testing.T) {
	resetConfiguredAuditLogFile(t)
	path := filepath.Join(t.TempDir(), "device-log.jsonl")
	cfg := &config.Config{}
	cfg.YubiHSM.AuditLogFile = path

	// Status against an unprovisioned store: it reports that and returns.
	if err := cmdHSMAudit(hsmAuditTestDB(t), cfg, []string{"status"}); err != nil {
		t.Fatalf("hsm-audit status: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("`hsm-audit status` created %s (stat err: %v)", path, err)
	}
}

// A draining subcommand does open it, and a path it cannot append to is refused
// rather than quietly leaving the database as the only copy.
//
// The unopenable path is a file where a directory should be, not a mode: these
// tests run as root often enough (every container build does) that a permission
// bit would not stop the open and the test would pass for the wrong reason.
func TestHSMAuditDrainingSubcommandRefusesAnUnwritableLogFile(t *testing.T) {
	resetConfiguredAuditLogFile(t)
	notADir := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(notADir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.YubiHSM.AuditLogFile = filepath.Join(notADir, "device-log.jsonl")

	err := cmdHSMAudit(hsmAuditTestDB(t), cfg, []string{"export", "-out", filepath.Join(t.TempDir(), "b.json")})
	if err == nil {
		t.Fatal("export ran with an unwritable append-only file, so its entries would reach the database alone")
	}
	if !strings.Contains(err.Error(), "append-only HSM audit log file") {
		t.Fatalf("the failure is not the one being tested: %v", err)
	}
}

// resetConfiguredAuditLogFile clears the process-wide memoized handle, which
// exists so two call sites in one process cannot each hold a writer with its own
// idea of where the file ended.
func resetConfiguredAuditLogFile(t *testing.T) {
	t.Helper()
	reset := func() {
		auditLogFileOnce.mu.Lock()
		defer auditLogFileOnce.mu.Unlock()
		if auditLogFileOnce.file != nil {
			_ = auditLogFileOnce.file.Close()
		}
		auditLogFileOnce.file, auditLogFileOnce.err = nil, nil
	}
	reset()
	t.Cleanup(reset)
}
