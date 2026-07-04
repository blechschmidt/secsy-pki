//go:build sqlite

package backup

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// TestBackupRestoreVerificationPostgresRoundTrip exercises the PostgreSQL restore
// path end-to-end against a real server: it builds an encrypted backup from an
// isolated source database (pg_dump), then round-trips it through
// restore-verification, which creates a throwaway scratch database, restores the
// dump with psql, integrity-gates it, matches the audit-head fingerprint, and
// always drops the scratch database — the production analogue of the chaos
// suite's isolatedPGDatabase pattern. It is gated on SECSY_TEST_PG_DSN (set by
// the dr-store-integrity CI job) and on pg_dump/psql being on PATH, so a plain
// `go test` stays green.
func TestBackupRestoreVerificationPostgresRoundTrip(t *testing.T) {
	baseDSN := os.Getenv("SECSY_TEST_PG_DSN")
	if baseDSN == "" {
		t.Skip("SECSY_TEST_PG_DSN not set; skipping PostgreSQL restore-verification test")
	}
	for _, tool := range []string{"pg_dump", "psql"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; skipping PostgreSQL restore-verification test", tool)
		}
	}

	ctx := context.Background()
	// A source database this test fully owns, so its pg_dump is clean and passes
	// the integrity gate independent of whatever other suites leave in the shared
	// test database.
	srcDSN := isolatedPGDatabaseForBackup(t, baseDSN, "secsy_backup_src_")

	db, err := database.New("postgres", srcDSN) // runs migrations
	if err != nil {
		t.Fatalf("open source: %v", err)
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
			ID: uuid.NewString(), Actor: "tester", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}

	provider := newTestProvider(t)

	// Produce and publish the backup (pg_dump runs here).
	store, err := publish.NewDirStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("dir store: %v", err)
	}
	src := Source{DB: db, Provider: provider, DSN: srcDSN}
	runner, err := New(src, store, backupCfg(3, 0), testKEKLabel, nil)
	if err != nil {
		t.Fatalf("New runner: %v", err)
	}
	runner.RunOnce(ctx)

	// Restore-verify. src.DSN is the base server on which the production code
	// creates (and always drops) the isolated scratch database.
	notifier := &fakeVerifyNotifier{}
	verifier, err := NewVerifier(src, store, backupCfg(3, 0), testKEKLabel, notifier, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	scratchBefore := scratchDatabaseSet(t, baseDSN)
	res := verifier.VerifyOnce(ctx)

	if !res.OK() {
		t.Fatalf("PostgreSQL restore-verification failed: skipped=%t stage=%q err=%v", res.Skipped, res.Stage, res.Err)
	}
	if res.Driver != "postgres" {
		t.Fatalf("driver = %q, want postgres", res.Driver)
	}
	if !res.FingerprintMatch {
		t.Fatalf("fingerprint mismatch: restored=%q manifest=%q", res.RestoredHead, res.ManifestHead)
	}
	if len(notifier.failures) != 0 {
		t.Fatalf("a successful verification must not alert, got %d", len(notifier.failures))
	}

	// No scratch database the drill created must survive: the set of
	// secsy_verify_* databases must not have grown (robust against any leftover
	// from a crashed prior run).
	for name := range scratchDatabaseSet(t, baseDSN) {
		if _, existed := scratchBefore[name]; !existed {
			t.Fatalf("restore-verification leaked scratch database %q", name)
		}
	}
}

// isolatedPGDatabaseForBackup creates a throwaway database on the SECSY_TEST_PG_DSN
// server and returns its DSN, dropping it on cleanup. It mirrors the chaos
// suite's isolatedPGDatabase helper.
func isolatedPGDatabaseForBackup(t *testing.T, baseDSN, prefix string) string {
	t.Helper()
	u, err := url.Parse(baseDSN)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		t.Skipf("SECSY_TEST_PG_DSN %q is not URL-form; cannot derive an isolated database", baseDSN)
	}
	name := prefix + strings.ReplaceAll(uuid.NewString(), "-", "")

	admin, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("opening admin connection: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec("CREATE DATABASE " + pgQuoteIdent(name)); err != nil {
		t.Skipf("cannot create isolated database (needs CREATEDB on the test server): %v", err)
	}
	t.Cleanup(func() {
		drop, err := sql.Open("postgres", baseDSN)
		if err != nil {
			return
		}
		defer drop.Close()
		if _, err := drop.Exec("DROP DATABASE IF EXISTS " + pgQuoteIdent(name) + " WITH (FORCE)"); err != nil {
			t.Logf("dropping isolated database %s: %v", name, err)
		}
	})

	iso := *u
	iso.Path = "/" + name
	return iso.String()
}

// scratchDatabaseSet returns the set of restore-verification scratch databases
// currently present on the server.
func scratchDatabaseSet(t *testing.T, baseDSN string) map[string]struct{} {
	t.Helper()
	admin, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("opening admin connection: %v", err)
	}
	defer admin.Close()
	rows, err := admin.Query("SELECT datname FROM pg_database WHERE datname LIKE 'secsy_verify_%'")
	if err != nil {
		t.Fatalf("listing scratch databases: %v", err)
	}
	defer rows.Close()
	names := map[string]struct{}{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scanning database name: %v", err)
		}
		names[n] = struct{}{}
	}
	return names
}
