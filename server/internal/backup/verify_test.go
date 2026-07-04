//go:build sqlite

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// fakeVerifyNotifier captures dispatched restore-verification failure alerts.
type fakeVerifyNotifier struct {
	failures []monitor.BackupVerifyFailure
}

func (f *fakeVerifyNotifier) NotifyBackupVerifyFailure(_ context.Context, failures []monitor.BackupVerifyFailure) {
	f.failures = append(f.failures, failures...)
}

// publishOneBackup runs a single scheduled-backup cycle into a fresh directory
// store and returns the store plus the source database. No HSM is involved: a
// software key provider holds the RSA KEK the artifact is sealed under.
func publishOneBackup(t *testing.T) (publish.Store, *sqlTestSource) {
	t.Helper()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)
	destDir := t.TempDir()
	store, err := publish.NewDirStore(destDir, 3)
	if err != nil {
		t.Fatalf("dir store: %v", err)
	}
	src := Source{DB: db, Provider: provider}
	runner, err := New(src, store, backupCfg(3, 0), testKEKLabel, nil)
	if err != nil {
		t.Fatalf("New runner: %v", err)
	}
	runner.RunOnce(context.Background())
	return store, &sqlTestSource{src: src, destDir: destDir}
}

// sqlTestSource bundles the source and its on-disk destination for the tests.
type sqlTestSource struct {
	src     Source
	destDir string
}

// TestBackupRestoreVerificationRoundTrip is the task's hermetic end-to-end test:
// it produces a real encrypted backup artifact, then round-trips it through
// restore-verification with no HSM — decrypt, restore into an isolated scratch
// SQLite database, integrity-gate, and audit-head fingerprint match — and
// asserts the success is metered and audited and raises no alert.
func TestBackupRestoreVerificationRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, ts := publishOneBackup(t)

	notifier := &fakeVerifyNotifier{}
	verifier, err := NewVerifier(ts.src, store, backupCfg(3, 0), testKEKLabel, notifier, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	before := backupVerifyCount(t, metrics.ResultSuccess)
	res := verifier.VerifyOnce(ctx)

	if !res.OK() {
		t.Fatalf("restore-verification failed: skipped=%t stage=%q err=%v", res.Skipped, res.Stage, res.Err)
	}
	if res.Driver != "sqlite" {
		t.Fatalf("driver = %q, want sqlite", res.Driver)
	}
	if !res.IntegrityOK {
		t.Fatalf("restored store did not pass integrity: %+v", res.Checks)
	}
	if !res.FingerprintMatch {
		t.Fatal("fingerprint did not match")
	}
	if res.RestoredHead == "" || res.RestoredHead != res.ManifestHead {
		t.Fatalf("restored head %q != manifest head %q", res.RestoredHead, res.ManifestHead)
	}

	// A successful drill must be counted and must raise no alert.
	if after := backupVerifyCount(t, metrics.ResultSuccess); after != before+1 {
		t.Fatalf("success counter = %v, want %v", after, before+1)
	}
	if len(notifier.failures) != 0 {
		t.Fatalf("a successful verification must not alert; got %d failure alerts", len(notifier.failures))
	}

	// A backup.verify success event must have been recorded on the live store.
	events, _, err := ts.src.DB.ListEvents(audit.ActionBackupVerify, "", "", 10, 0)
	if err != nil {
		t.Fatalf("list backup.verify: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultSuccess {
		t.Fatalf("want one successful backup.verify event, got %+v", events)
	}
	if !strings.Contains(events[0].Detail, "fingerprint_match=true") {
		t.Fatalf("audit detail should record the fingerprint match: %q", events[0].Detail)
	}

	// The scratch database must be gone — the drill leaves nothing behind. The
	// only file the verifier writes is under a temp dir it removes, so nothing new
	// should exist under the backup destination beyond the published snapshot.
	if _, err := os.Stat(filepath.Join(ts.destDir, "restored.db")); !os.IsNotExist(err) {
		t.Fatalf("scratch database leaked into the destination directory")
	}
}

// TestBackupRestoreVerificationDetectsTamperedArtifact corrupts the published
// ciphertext at rest (leaving the manifest's recorded digest unchanged) and
// asserts the drill catches it at the fetch-integrity stage, meters the failure,
// audits it, and raises exactly one alert — the whole point of the drill is that
// an unrestorable backup is detected before a real disaster needs it.
func TestBackupRestoreVerificationDetectsTamperedArtifact(t *testing.T) {
	ctx := context.Background()
	store, ts := publishOneBackup(t)

	// Flip a byte of the published artifact through the `current` snapshot so the
	// fetched bytes no longer match the digest the manifest records.
	artifactPath := filepath.Join(ts.destDir, "current", ArtifactName)
	blob, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read published artifact: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("published artifact is empty")
	}
	blob[0] ^= 0xff
	if err := os.WriteFile(artifactPath, blob, 0o600); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	notifier := &fakeVerifyNotifier{}
	verifier, err := NewVerifier(ts.src, store, backupCfg(3, 0), testKEKLabel, notifier, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	before := backupVerifyCount(t, metrics.ResultError)
	res := verifier.VerifyOnce(ctx)

	if res.OK() || res.Skipped {
		t.Fatalf("tampered artifact should fail verification, got OK=%t skipped=%t", res.OK(), res.Skipped)
	}
	if res.Stage != stageFetch {
		t.Fatalf("failure stage = %q, want %q", res.Stage, stageFetch)
	}
	if after := backupVerifyCount(t, metrics.ResultError); after != before+1 {
		t.Fatalf("error counter = %v, want %v", after, before+1)
	}
	if len(notifier.failures) != 1 {
		t.Fatalf("want exactly one failure alert, got %d", len(notifier.failures))
	}
	if notifier.failures[0].Stage != stageFetch {
		t.Fatalf("alert stage = %q, want %q", notifier.failures[0].Stage, stageFetch)
	}

	events, _, err := ts.src.DB.ListEvents(audit.ActionBackupVerify, "", "", 10, 0)
	if err != nil {
		t.Fatalf("list backup.verify: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultError {
		t.Fatalf("want one errored backup.verify event, got %+v", events)
	}
}

// TestBackupRestoreVerificationDetectsUndecryptableArtifact publishes a
// valid-looking but undecryptable artifact (consistent digest, garbage
// ciphertext) and asserts the drill fails at the decrypt stage — the case where
// the KEK is wrong or the envelope is corrupt end-to-end.
func TestBackupRestoreVerificationDetectsUndecryptableArtifact(t *testing.T) {
	ctx := context.Background()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)
	store, err := publish.NewDirStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("dir store: %v", err)
	}

	// Publish garbage whose outer-manifest digest matches, so the fetch guard
	// passes and the failure surfaces at decrypt.
	garbage := []byte("this is definitely not a secret envelope")
	outer := OuterManifest{
		Version:      ArtifactVersion,
		DBDriver:     "sqlite",
		Encrypted:    true,
		ArtifactFile: ArtifactName,
		ArtifactSize: len(garbage),
	}
	sum := sha256.Sum256(garbage)
	outer.ArtifactSHA256 = hex.EncodeToString(sum[:])
	outerJSON, err := json.MarshalIndent(outer, "", "  ")
	if err != nil {
		t.Fatalf("encode outer manifest: %v", err)
	}
	if err := store.Publish(ctx, outerJSON, []publish.Artifact{{
		Path: ArtifactName, Data: garbage, ContentType: "application/octet-stream", Kind: "backup",
	}}); err != nil {
		t.Fatalf("publish garbage: %v", err)
	}

	notifier := &fakeVerifyNotifier{}
	verifier, err := NewVerifier(Source{DB: db, Provider: provider}, store, backupCfg(3, 0), testKEKLabel, notifier, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res := verifier.VerifyOnce(ctx)

	if res.OK() || res.Skipped {
		t.Fatalf("undecryptable artifact should fail, got OK=%t skipped=%t", res.OK(), res.Skipped)
	}
	if res.Stage != stageDecrypt {
		t.Fatalf("failure stage = %q, want %q (err=%v)", res.Stage, stageDecrypt, res.Err)
	}
	if len(notifier.failures) != 1 {
		t.Fatalf("want one failure alert, got %d", len(notifier.failures))
	}
}

// TestBackupRestoreVerificationSkipsWhenNoBackup asserts that with nothing
// published yet the drill is a benign skip: no audit event, no alert, no metered
// failure (the startup race with the backup writer must not raise a false alarm).
func TestBackupRestoreVerificationSkipsWhenNoBackup(t *testing.T) {
	ctx := context.Background()
	db, _ := newTestDB(t)
	provider := newTestProvider(t)
	store, err := publish.NewDirStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("dir store: %v", err)
	}

	notifier := &fakeVerifyNotifier{}
	verifier, err := NewVerifier(Source{DB: db, Provider: provider}, store, backupCfg(3, 0), testKEKLabel, notifier, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	beforeErr := backupVerifyCount(t, metrics.ResultError)
	res := verifier.VerifyOnce(ctx)

	if !res.Skipped {
		t.Fatalf("expected a skip with no backup published, got skipped=%t err=%v", res.Skipped, res.Err)
	}
	if res.OK() {
		t.Fatal("a skip is not a success")
	}
	if len(notifier.failures) != 0 {
		t.Fatalf("a skip must not alert, got %d", len(notifier.failures))
	}
	if after := backupVerifyCount(t, metrics.ResultError); after != beforeErr {
		t.Fatalf("a skip must not meter a failure: error counter moved %v -> %v", beforeErr, after)
	}
	events, _, err := db.ListEvents(audit.ActionBackupVerify, "", "", 10, 0)
	if err != nil {
		t.Fatalf("list backup.verify: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("a skip must not audit, got %d backup.verify events", len(events))
	}
}

// backupVerifyCount reads the current value of the backup-verify counter for a
// result label from the default registry (0 when the series is absent).
func backupVerifyCount(t *testing.T, result string) float64 {
	t.Helper()
	var buf bytes.Buffer
	if _, err := metrics.Default.WriteTo(&buf); err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	prefix := fmt.Sprintf(`secsy_backup_verify_total{result="%s"}`, result)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
			if err != nil {
				t.Fatalf("parsing counter line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}
