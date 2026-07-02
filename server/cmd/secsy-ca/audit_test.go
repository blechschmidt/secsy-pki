//go:build sqlite

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// auditCLITestDB opens a file-backed SQLite DB (so a second raw connection can
// tamper with a stored row, which a shared :memory: DB would not allow) and
// returns both the app handle and the on-disk path.
func auditCLITestDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := database.New("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func appendN(t *testing.T, db *database.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: "e", Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCmdAuditVerifyIntactChain is the happy path: an untouched chain verifies
// and the command returns nil.
func TestCmdAuditVerifyIntactChain(t *testing.T) {
	db, _ := auditCLITestDB(t)
	appendN(t, db, 4)
	if err := cmdAuditVerify(db, nil); err != nil {
		t.Fatalf("intact chain should verify: %v", err)
	}
}

// TestCmdAuditVerifyDetectsTamper is the core tamper-detection test: editing a
// stored row breaks the chain, and the CLI reports failure (non-nil error) so a
// cron job can trip on it.
func TestCmdAuditVerifyDetectsTamper(t *testing.T) {
	db, path := auditCLITestDB(t)
	appendN(t, db, 4)

	// Flip a stored result via a separate connection, without recomputing
	// downstream hashes — exactly what an attacker editing the store would do.
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE event_log SET result = ? WHERE seq = ?`, audit.ResultDenied, 2); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	err = cmdAuditVerify(db, nil)
	if err == nil {
		t.Fatal("tampered chain must fail verification")
	}
	if !strings.Contains(err.Error(), "seq 2") {
		t.Errorf("error should point at the broken seq: %v", err)
	}
}

// TestCmdAuditExportWritesRange verifies offline export writes one record per
// event in the range to the output file.
func TestCmdAuditExportWritesRange(t *testing.T) {
	db, _ := auditCLITestDB(t)
	appendN(t, db, 3)

	out := filepath.Join(t.TempDir(), "export.ndjson")
	if err := cmdAuditExport(db, []string{"-format", "json", "-out", out}); err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("exported %d lines, want 3:\n%s", len(lines), data)
	}
	if !strings.Contains(lines[0], `"seq":1`) {
		t.Errorf("first line missing seq: %s", lines[0])
	}
}
