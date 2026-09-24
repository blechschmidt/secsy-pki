//go:build sqlite

package handlers

// Tests for the disaster-recovery REST surface (Task 198). Two invariants carry
// the file:
//
//   - GET /api/backup NEVER exports private key material. The key-non-extract-
//     ability guarantee is the whole security model of this PKI, and a DR export
//     is the most plausible place to leak it, so the response body is asserted
//     against both the PEM markers and the actual bytes of the on-disk key.
//   - POST /api/backup/verify-restore really restores. The happy path produces a
//     genuine encrypted artifact and drives the endpoint through decrypt →
//     restore → integrity gate → audit-head fingerprint match, because an
//     endpoint that merely reports "verified" would be worse than none.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/backup"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// backupTestKEK is the KEK label the test backups are sealed under.
const backupTestKEK = "backup-api-kek"

// backupFixture is an API backed by a FILE-based SQLite store (a DR snapshot
// needs a real file to VACUUM INTO) and a software key provider whose keystore
// the test can inspect for leaked private material.
type backupFixture struct {
	api      *API
	db       *database.DB
	provider keyprovider.Provider
	keystore string
}

func newBackupFixture(t *testing.T) *backupFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New("sqlite", filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keystore := filepath.Join(dir, "keystore")
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: keystore})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })

	f := &backupFixture{
		api:      NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, ""),
		db:       db,
		provider: prov,
		keystore: keystore,
	}
	// A few hash-chained events, as normal activity would leave: the audit head is
	// the DR anchor both the export and the restore drill are checked against, and
	// an empty log would make both assertions vacuous.
	for i := 0; i < 3; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("backup-api-seed-%d", i), Actor: "tester",
			Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatalf("seeding audit events: %v", err)
		}
	}
	return f
}

// setOps installs the operations dependencies, handing out fresh software
// providers over the same keystore (as the server hands out role-scoped providers
// the handler owns and closes).
func (f *backupFixture) setOps(t *testing.T, cfg *config.Config) {
	t.Helper()
	f.api.SetOps(&OpsDeps{
		Config:     cfg,
		ConfigPath: "/etc/secsy/backup-test.yaml",
		ProviderFor: func(string) (keyprovider.Provider, error) {
			return keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: f.keystore})
		},
	})
}

// seedRootCA provisions a real software-keyed root CA, so the export has genuine
// CA material, a resolvable key label, and a non-empty key inventory.
func (f *backupFixture) seedRootCA(t *testing.T) *models.CA {
	t.Helper()
	root, err := ca.NewManager(f.db, f.provider).InitRoot(context.Background(), ca.RootSpec{
		Label:    "backup-api-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Backup API Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return root
}

// publishOneEncryptedBackup runs one real scheduled-backup cycle into a fresh
// destination directory and returns the matching BackupConfig.
func (f *backupFixture) publishOneEncryptedBackup(t *testing.T) config.BackupConfig {
	t.Helper()
	if _, err := secret.ProvisionKEK(context.Background(), f.provider, backupTestKEK, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	dest := t.TempDir()
	bc := config.BackupConfig{
		Enabled:   true,
		KEKLabel:  backupTestKEK,
		Dir:       config.PublishDirConfig{Path: dest, KeepSnapshots: 3},
		Retention: config.BackupRetentionConfig{Keep: 3},
	}
	store, err := backup.NewStore(bc)
	if err != nil {
		t.Fatalf("backup.NewStore: %v", err)
	}
	runner, err := backup.New(backup.Source{DB: f.db, Provider: f.provider}, store, bc, backupTestKEK,
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("backup.New: %v", err)
	}
	runner.RunOnce(context.Background())
	if _, err := store.Fetch(context.Background(), publish.ManifestPath); err != nil {
		t.Fatalf("the backup cycle published nothing: %v", err)
	}
	return bc
}

func backupExport(api *API, user *models.UserInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.ExportBackup(rec, reqAs(http.MethodGet, "/api/backup", user, "", ""))
	return rec
}

func backupVerifyRestore(api *API, user *models.UserInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.VerifyBackupRestore(rec, reqAs(http.MethodPost, "/api/backup/verify-restore", user, "", ""))
	return rec
}

// TestBackupAuthz pins the gate: the DR export and the restore drill are held at
// hsm:manage (admin), the same level as the key inventory. The export names every
// CA, every key label the token holds, and the deployment's audit head — so an
// auditor's read capability is deliberately NOT enough, and no tenant-scoped role
// reaches either endpoint.
func TestBackupAuthz(t *testing.T) {
	f := newBackupFixture(t)
	f.seedRootCA(t)
	f.setOps(t, &config.Config{}) // no backup destination configured

	for _, tc := range []struct {
		name           string
		user           *models.UserInfo
		export, verify int
	}{
		{"unauthenticated", nil, 403, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403, 403},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 403, 403},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 403, 403},
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 403, 403},
		// Capable callers pass the gate; with no KEK configured the drill itself is
		// unavailable (503), which is exactly how we know authorization succeeded.
		{"platform admin", platformAdmin(), 200, 503},
		{"root", rootUser(), 200, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := backupExport(f.api, tc.user); rec.Code != tc.export {
				t.Errorf("export: got %d, want %d; body=%s", rec.Code, tc.export, rec.Body.String())
			}
			if rec := backupVerifyRestore(f.api, tc.user); rec.Code != tc.verify {
				t.Errorf("verify-restore: got %d, want %d; body=%s", rec.Code, tc.verify, rec.Body.String())
			}
		})
	}
}

// TestBackupWithoutOpsDeps proves both endpoints degrade to 503 rather than
// panicking when the server was started without the operations dependencies, and
// that authorization is decided first.
func TestBackupWithoutOpsDeps(t *testing.T) {
	f := newBackupFixture(t) // no SetOps

	for _, tc := range []struct {
		name string
		call func(*models.UserInfo) *httptest.ResponseRecorder
	}{
		{"export", func(u *models.UserInfo) *httptest.ResponseRecorder { return backupExport(f.api, u) }},
		{"verify-restore", func(u *models.UserInfo) *httptest.ResponseRecorder { return backupVerifyRestore(f.api, u) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := tc.call(rootUser()); rec.Code != http.StatusServiceUnavailable {
				t.Errorf("capable caller: got %d, want 503; body=%s", rec.Code, rec.Body.String())
			}
			if rec := tc.call(&models.UserInfo{Subject: "nobody"}); rec.Code != http.StatusForbidden {
				t.Errorf("roleless caller: got %d, want 403 (authz before wiring); body=%s",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestBackupExportCarriesNoPrivateKeys is the headline invariant. The export
// carries everything a restore needs to VERIFY recovery — CA records, key labels,
// public-key fingerprints, the key inventory's extractability flags, the audit
// anchor — and nothing a restore could use to IMPERSONATE the CA.
func TestBackupExportCarriesNoPrivateKeys(t *testing.T) {
	f := newBackupFixture(t)
	root := f.seedRootCA(t)
	f.setOps(t, &config.Config{Backup: config.BackupConfig{
		Enabled: true,
		Dir:     config.PublishDirConfig{Path: "/var/lib/secsy/backups"},
	}})

	rec := backupExport(f.api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("export: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// (1) No PEM private key of any flavour, anywhere in the response.
	for _, marker := range []string{
		"PRIVATE KEY", "BEGIN RSA PRIVATE", "BEGIN EC PRIVATE", "BEGIN OPENSSH PRIVATE", "BEGIN PRIVATE",
	} {
		if strings.Contains(strings.ToUpper(body), strings.ToUpper(marker)) {
			t.Fatalf("the DR export contains %q — private key material must never leave the process", marker)
		}
	}
	// (2) Nor the actual bytes of the key the software keystore holds on disk.
	for _, keyFile := range backupKeystoreFiles(t, f.keystore) {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatalf("reading %s: %v", keyFile, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if len(line) < 40 || strings.HasPrefix(line, "-----") {
				continue // headers and short lines are not key material
			}
			if strings.Contains(body, line) {
				t.Fatalf("the DR export leaks on-disk key material from %s", filepath.Base(keyFile))
			}
		}
	}

	var resp BackupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	// (3) It still carries what a restore verifies against.
	if resp.Manifest.Version != backupManifestVersion {
		t.Errorf("manifest version = %d, want %d", resp.Manifest.Version, backupManifestVersion)
	}
	if len(resp.Manifest.CAs) != 1 || resp.Manifest.CAs[0].ID != root.ID {
		t.Fatalf("manifest cas = %+v, want the one seeded CA", resp.Manifest.CAs)
	}
	ref := resp.Manifest.CAs[0]
	if ref.KeyLabel == "" || ref.KeyFingerprint == "" || !strings.HasPrefix(ref.KeyFingerprint, "SHA256:") {
		t.Errorf("CA ref = %+v, want a key label and an SHA256 public-key fingerprint (the restore anchor)", ref)
	}
	if len(resp.CAs) != 1 || resp.CAs[0].ID != root.ID || resp.CAs[0].Certificate == "" {
		t.Errorf("cas = %+v, want the full CA record including its certificate", resp.CAs)
	}
	if len(resp.Manifest.KeyInventory) == 0 {
		t.Error("key_inventory is empty — the export cannot prove which keys the token must hold")
	}
	if !resp.Manifest.AuditChainValid || resp.Manifest.AuditEventCount == 0 || resp.Manifest.AuditHeadHash == "" {
		t.Errorf("audit anchor = valid=%v count=%d head=%q, want a verified, non-empty chain",
			resp.Manifest.AuditChainValid, resp.Manifest.AuditEventCount, resp.Manifest.AuditHeadHash)
	}
	if resp.Manifest.KeyProvider == "" || resp.Manifest.DBDriver != "sqlite" {
		t.Errorf("provider=%q driver=%q, want both populated", resp.Manifest.KeyProvider, resp.Manifest.DBDriver)
	}
	// (4) It says what it is NOT, and where the missing pieces live.
	notes := strings.Join(resp.Manifest.Notes, " | ")
	for _, want := range []string{"HSM token state", "/api/events/export", "Private-key material is never included"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes %q do not mention %q", notes, want)
		}
	}
	if resp.ConfigPath != "/etc/secsy/backup-test.yaml" {
		t.Errorf("config_path = %q, want the running process's config file", resp.ConfigPath)
	}
	if resp.ScheduledDestination != "dir:/var/lib/secsy/backups" || !resp.ScheduledBackupEnabled {
		t.Errorf("scheduled destination = %q (enabled=%v), want the configured directory backend",
			resp.ScheduledDestination, resp.ScheduledBackupEnabled)
	}

	// (5) The export is audited under the same action the CLI records.
	events, _, err := f.db.ListEvents(audit.ActionHSMBackup, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultSuccess || !strings.Contains(events[0].Detail, "via=api") {
		t.Fatalf("want one successful hsm.backup event attributed to the API, got %+v", events)
	}
}

// TestBackupVerifyRestoreRoundTrip drives the endpoint over a REAL encrypted
// backup: fetch, digest-check, decrypt through the KEK ring, restore into a
// scratch database, run the integrity gate, and match the restored audit head
// against the artifact manifest.
func TestBackupVerifyRestoreRoundTrip(t *testing.T) {
	f := newBackupFixture(t)
	f.seedRootCA(t)
	bc := f.publishOneEncryptedBackup(t)
	f.setOps(t, &config.Config{Backup: bc})

	rec := backupVerifyRestore(f.api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-restore: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp BackupVerifyRestoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if !resp.OK || resp.Skipped || resp.ErrMsg != "" {
		t.Fatalf("result = ok:%v skipped:%v stage:%q error:%q, want a clean drill",
			resp.OK, resp.Skipped, resp.Stage, resp.ErrMsg)
	}
	if !resp.IntegrityOK || !resp.FingerprintMatch {
		t.Errorf("integrity_ok=%v fingerprint_match=%v, want both true", resp.IntegrityOK, resp.FingerprintMatch)
	}
	if resp.RestoredHead == "" || resp.RestoredHead != resp.ManifestHead {
		t.Errorf("restored head %q != manifest head %q", resp.RestoredHead, resp.ManifestHead)
	}
	if resp.Driver != "sqlite" || resp.Backend != "dir" || resp.ArtifactSize == 0 || resp.ArtifactSHA256 == "" {
		t.Errorf("artifact identity = backend %q driver %q %d bytes sha %q, want it fully reported",
			resp.Backend, resp.Driver, resp.ArtifactSize, resp.ArtifactSHA256)
	}
	if len(resp.Checks) == 0 {
		t.Error("checks is empty — the console cannot show where recovery would break")
	}

	// Both events are recorded: the verifier's own (actor "backup-verify", as the
	// background drill records it) and the operator-attributed one.
	events, _, err := f.db.ListEvents(audit.ActionBackupVerify, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawVerifier, sawOperator bool
	for _, e := range events {
		switch e.Actor {
		case "backup-verify":
			sawVerifier = e.Result == audit.ResultSuccess && strings.Contains(e.Detail, "fingerprint_match=true")
		case "root":
			sawOperator = e.Result == audit.ResultSuccess && strings.Contains(e.Detail, "via=api")
		}
	}
	if !sawVerifier || !sawOperator {
		t.Errorf("backup.verify events = %+v, want both the verifier's and the operator-attributed record", events)
	}
}

// TestBackupVerifyRestoreReusesServingProvider is the HSM session-budget
// invariant for the restore drill, the same one POST /api/publish carries: the
// backup KEK lives with the CA role, which IS the serving provider, so the drill
// must bind it there instead of opening a second session pool.
//
// It matters most here because the drill is the longest-running of these endpoints:
// on a YubiHSM 2 (16 sessions, eight already held by the serving provider) a drill
// opening eight more sits at the device limit for minutes, and two concurrent ones
// starve live CA signing. The counter is the assertion, and the drill still has to
// pass — proving the shared provider really unwrapped the KEK.
func TestBackupVerifyRestoreReusesServingProvider(t *testing.T) {
	f := newBackupFixture(t)
	f.seedRootCA(t)
	bc := f.publishOneEncryptedBackup(t)

	calls := 0
	f.api.SetOps(&OpsDeps{
		Config:     &config.Config{Backup: bc},
		ConfigPath: "/etc/secsy/backup-test.yaml",
		ProviderFor: func(string) (keyprovider.Provider, error) {
			calls++
			return keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: f.keystore})
		},
	})

	rec := backupVerifyRestore(f.api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-restore: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("the drill opened %d extra key provider(s); the CA role is the serving provider and must be reused", calls)
	}
	// release() must be the no-op for a shared provider: the server's own provider
	// is still usable after the drill.
	if _, err := f.api.keyProvider.FindKey(context.Background(), keyprovider.KeyRef{Label: backupTestKEK}); err != nil {
		t.Errorf("the serving key provider was closed by the drill: %v", err)
	}
}

// TestBackupVerifyRestoreNothingPublished separates "no backup to verify" from
// "the backup is broken": an empty destination is a 404 skip, not a failure that
// would page someone about corruption that does not exist.
func TestBackupVerifyRestoreNothingPublished(t *testing.T) {
	f := newBackupFixture(t)
	if _, err := secret.ProvisionKEK(context.Background(), f.provider, backupTestKEK, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	f.setOps(t, &config.Config{Backup: config.BackupConfig{
		Enabled:  true,
		KEKLabel: backupTestKEK,
		Dir:      config.PublishDirConfig{Path: t.TempDir()},
	}})

	rec := backupVerifyRestore(f.api, rootUser())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	var resp BackupVerifyRestoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if !resp.Skipped || resp.OK {
		t.Errorf("result = skipped:%v ok:%v, want a skip", resp.Skipped, resp.OK)
	}
	if !strings.Contains(resp.ErrMsg, "no backup available") {
		t.Errorf("error = %q, want it to say there is nothing to verify", resp.ErrMsg)
	}
}

// backupKeystoreFiles lists the files the software keystore holds, so the export
// can be checked against the real key material on disk.
func backupKeystoreFiles(t *testing.T, keystore string) []string {
	t.Helper()
	entries, err := os.ReadDir(keystore)
	if err != nil {
		t.Fatalf("reading keystore %s: %v", keystore, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(keystore, e.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatalf("keystore %s is empty — the fixture did not create a key", keystore)
	}
	return out
}
