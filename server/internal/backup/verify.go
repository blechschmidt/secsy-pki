package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// verifyActor is the identity restore-verification runs and audits as.
const verifyActor = "backup-verify"

// Verify stages, recorded on the result and in the audit trail / alert so an
// operator can see where recovery would break.
const (
	stageFetch       = "fetch"
	stageDecrypt     = "decrypt"
	stageRestore     = "restore"
	stageIntegrity   = "integrity"
	stageFingerprint = "fingerprint"
)

// Notifier dispatches restore-verification failure alerts. *monitor.Notifier
// satisfies it; it may be nil (a failure is then only logged, audited, and
// counted).
type Notifier interface {
	NotifyBackupVerifyFailure(ctx context.Context, failures []monitor.BackupVerifyFailure)
}

// Verifier is the automated backup restore-verification drill (Task 94). It
// closes the loop on the scheduled backup job (Task 89): an untested backup is
// not a backup. Every cycle it pulls the newest published backup artifact,
// decrypts it via the secret-envelope layer, restores the DB dump into an
// isolated scratch database (a SQLite temp file, or a throwaway PostgreSQL
// database that is always dropped), runs the HSM-independent integrity gate
// (Task 52), and confirms the restored audit-head fingerprint matches the one
// recorded in the artifact manifest.
//
// It is a singleton background job: register its Run on the leader elector so
// exactly one replica verifies at a time. It never touches private key material
// (it only binds the KEK ring to unseal the envelope), never mutates the live
// store beyond appending its own backup.verify audit event, and never blocks
// issuance — the restore happens entirely in the scratch database.
type Verifier struct {
	src      Source
	store    publish.Store
	cfg      config.BackupConfig
	kekLabel string
	notifier Notifier
	logger   *log.Logger
	// now is the clock, overridable in tests.
	now func() time.Time
}

// NewVerifier builds a Verifier. src.DB (for the KEK rotation state and the
// audit trail) and src.Provider (to bind the decryption KEK) are required, as is
// a non-empty kekLabel and a source store. notifier may be nil.
func NewVerifier(src Source, store publish.Store, cfg config.BackupConfig, kekLabel string, notifier Notifier, logger *log.Logger) (*Verifier, error) {
	if src.DB == nil {
		return nil, fmt.Errorf("backup verify: a database is required")
	}
	if src.Provider == nil {
		return nil, fmt.Errorf("backup verify: a key provider is required (to bind the decryption KEK)")
	}
	if store == nil {
		return nil, fmt.Errorf("backup verify: a source store is required")
	}
	if kekLabel == "" {
		return nil, fmt.Errorf("backup verify: a KEK label is required (set backup.kek_label or secret.kek_label)")
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Verifier{src: src, store: store, cfg: cfg, kekLabel: kekLabel, notifier: notifier, logger: logger, now: time.Now}, nil
}

// Run verifies immediately, then on every interval tick, until ctx is cancelled.
// It blocks; callers register it as a leader-elected background job.
func (v *Verifier) Run(ctx context.Context) {
	v.logger.Printf("backup restore-verification started (interval=%s, source=%s, kek=%s)",
		v.cfg.VerifyInterval(), v.store.Name(), v.kekLabel)
	v.VerifyOnce(ctx)

	ticker := time.NewTicker(v.cfg.VerifyInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			v.logger.Printf("backup restore-verification stopped")
			return
		case <-ticker.C:
			v.VerifyOnce(ctx)
		}
	}
}

// VerifyResult summarizes one restore-verification drill.
type VerifyResult struct {
	StartedAt      time.Time `json:"started_at"`
	Backend        string    `json:"backend"`
	Driver         string    `json:"driver,omitempty"`
	ArtifactFile   string    `json:"artifact_file,omitempty"`
	ArtifactSize   int       `json:"artifact_size,omitempty"`
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
	// CreatedAt is when the backup being verified was produced.
	CreatedAt time.Time `json:"backup_created_at,omitempty"`
	// ManifestHead is the audit-chain head hash the artifact manifest recorded;
	// RestoredHead is the head hash the restored scratch store actually has.
	ManifestHead     string                    `json:"manifest_head,omitempty"`
	RestoredHead     string                    `json:"restored_head,omitempty"`
	IntegrityOK      bool                      `json:"integrity_ok"`
	FingerprintMatch bool                      `json:"fingerprint_match"`
	Checks           []database.IntegrityCheck `json:"checks,omitempty"`
	// Skipped is set when there is simply no backup published to verify yet (the
	// benign startup race with the backup writer). A skip is logged only — it is
	// not counted, audited, or alerted.
	Skipped bool `json:"skipped,omitempty"`
	// Stage names where a failure occurred (empty on success/skip).
	Stage string `json:"stage,omitempty"`
	// Err is the failure (nil on success/skip); ErrMsg mirrors it for JSON.
	Err    error  `json:"-"`
	ErrMsg string `json:"error,omitempty"`
}

// OK reports whether the drill proved the backup restorable.
func (r *VerifyResult) OK() bool { return !r.Skipped && r.Err == nil }

// VerifyOnce performs one restore-verification drill, recording metrics and a
// backup.verify audit event and — on failure — dispatching an alert. Like the
// backup runner it never returns an error: a failed or skipped drill is logged
// and (for failures) counted, audited, and alerted so the next tick simply
// retries and a transient failure never tears down the loop. It returns the
// result for the CLI and tests.
func (v *Verifier) VerifyOnce(ctx context.Context) *VerifyResult {
	start := v.now()
	res := &VerifyResult{StartedAt: start, Backend: v.store.Name()}
	v.verify(ctx, res)

	if res.Skipped {
		// Nothing to verify yet (no backup published). Not a failure: log and move
		// on. Staleness climbs and doctor warns until the first real verification.
		v.logger.Printf("backup restore-verification: skipped — %s", res.ErrMsg)
		return res
	}

	metrics.RecordBackupVerify(start, res.Err)
	if res.Err != nil {
		res.ErrMsg = res.Err.Error()
		v.logger.Printf("backup restore-verification: FAILED at stage %q after %s: %v",
			res.Stage, time.Since(start).Round(time.Millisecond), res.Err)
	} else {
		v.logger.Printf("backup restore-verification: ok — restored %s backup (%d bytes, head %s) in %s",
			res.Driver, res.ArtifactSize, shortHex(res.RestoredHead), time.Since(start).Round(time.Millisecond))
	}
	v.recordAudit(res)

	if res.Err != nil && v.notifier != nil {
		v.notifier.NotifyBackupVerifyFailure(ctx, []monitor.BackupVerifyFailure{{
			Backend:        res.Backend,
			Driver:         res.Driver,
			ArtifactSHA256: res.ArtifactSHA256,
			Stage:          res.Stage,
			Reason:         res.Err.Error(),
			At:             v.now(),
		}})
	}
	return res
}

// verify runs one drill and populates res.Stage/Err (or Skipped). It performs no
// metric/audit/alert side effects — VerifyOnce owns those.
func (v *Verifier) verify(ctx context.Context, res *VerifyResult) {
	// 1. Fetch the plaintext outer manifest. Its absence means nothing has been
	//    published yet (or the store is unreadable): a skip, not a failure.
	rawManifest, err := v.store.Fetch(ctx, publish.ManifestPath)
	if err != nil {
		res.Skipped = true
		res.ErrMsg = fmt.Sprintf("no backup available to verify at %s (or store unreadable): %v", v.store.Name(), err)
		return
	}
	var outer OuterManifest
	if err := json.Unmarshal(rawManifest, &outer); err != nil {
		res.Stage, res.Err = stageFetch, fmt.Errorf("decoding outer manifest: %w", err)
		return
	}
	res.Driver = outer.DBDriver
	res.CreatedAt = outer.CreatedAt
	artifactPath := outer.ArtifactFile
	if artifactPath == "" {
		artifactPath = ArtifactName
	}
	res.ArtifactFile = artifactPath

	// 2. Fetch the encrypted artifact and check it against the outer-manifest
	//    digest (fetch integrity, before we spend effort decrypting).
	blob, err := v.store.Fetch(ctx, artifactPath)
	if err != nil {
		res.Stage, res.Err = stageFetch, fmt.Errorf("fetching artifact %q: %w", artifactPath, err)
		return
	}
	res.ArtifactSize = len(blob)
	sum := sha256.Sum256(blob)
	res.ArtifactSHA256 = hex.EncodeToString(sum[:])
	if outer.ArtifactSHA256 != "" && res.ArtifactSHA256 != outer.ArtifactSHA256 {
		res.Stage, res.Err = stageFetch, fmt.Errorf("fetched artifact digest %s does not match the published manifest %s", res.ArtifactSHA256, outer.ArtifactSHA256)
		return
	}

	// 3. Decrypt via the secret-envelope ring under the same KEK the backup was
	//    sealed with, then open (and digest-verify every member of) the archive.
	ring, err := v.loadRing(ctx)
	if err != nil {
		res.Stage, res.Err = stageDecrypt, err
		return
	}
	archive, err := Decrypt(ctx, ring, blob)
	if err != nil {
		res.Stage, res.Err = stageDecrypt, err
		return
	}
	res.Driver = archive.Manifest.DBDriver
	res.ManifestHead = archive.Manifest.AuditHeadHash

	// 4. Restore the DB dump into an isolated scratch database, always torn down.
	target, err := newRestoreTarget(archive.Manifest.DumpFile, v.src.DSN)
	if err != nil {
		res.Stage, res.Err = stageRestore, err
		return
	}
	defer target.cleanup()
	if err := target.restore(ctx, archive); err != nil {
		res.Stage, res.Err = stageRestore, err
		return
	}
	restored, err := target.open()
	if err != nil {
		res.Stage, res.Err = stageRestore, fmt.Errorf("opening restored scratch store: %w", err)
		return
	}
	defer func() { _ = restored.Close() }()

	// 5. Run the HSM-independent integrity gate against the restored store — the
	//    same gate a `secsy-ca db verify` / DR restore uses.
	integ, err := restored.VerifyStoreIntegrity()
	if err != nil {
		res.Stage, res.Err = stageIntegrity, fmt.Errorf("verifying restored store integrity: %w", err)
		return
	}
	res.Checks = integ.Checks
	res.IntegrityOK = integ.OK
	res.RestoredHead = integ.Fingerprint.AuditHeadHash
	if !integ.OK {
		res.Stage, res.Err = stageIntegrity, fmt.Errorf("restored store failed integrity verification: %s", failedChecks(integ))
		return
	}

	// 6. Confirm the restored audit-head fingerprint matches the artifact
	//    manifest — proof the dump really is the state the manifest describes.
	if res.RestoredHead != archive.Manifest.AuditHeadHash {
		res.Stage, res.Err = stageFingerprint, fmt.Errorf("restored audit head %s does not match the manifest head %s", shortHex(res.RestoredHead), shortHex(archive.Manifest.AuditHeadHash))
		return
	}
	if integ.Fingerprint.AuditEventCount != archive.Manifest.Fingerprint.AuditEventCount {
		res.Stage, res.Err = stageFingerprint, fmt.Errorf("restored event count %d does not match the manifest %d", integ.Fingerprint.AuditEventCount, archive.Manifest.Fingerprint.AuditEventCount)
		return
	}
	res.FingerprintMatch = true
}

// loadRing binds the KEK ring the artifact is decrypted under, exactly as the
// backup writer bound it to seal the artifact.
func (v *Verifier) loadRing(ctx context.Context) (*secret.Ring, error) {
	versions, err := v.src.DB.ListKEKVersions(v.kekLabel)
	if err != nil {
		return nil, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	ring, err := secret.LoadRing(ctx, v.src.Provider, v.kekLabel, versions)
	if err != nil {
		return nil, fmt.Errorf("binding backup KEK %q: %w", v.kekLabel, err)
	}
	return ring, nil
}

// recordAudit appends the backup.verify event for one drill, best-effort.
func (v *Verifier) recordAudit(res *VerifyResult) {
	result := audit.ResultSuccess
	detail := fmt.Sprintf("backend=%s driver=%s bytes=%d integrity_ok=%t fingerprint_match=%t restored_head=%s manifest_head=%s",
		res.Backend, res.Driver, res.ArtifactSize, res.IntegrityOK, res.FingerprintMatch, shortHex(res.RestoredHead), shortHex(res.ManifestHead))
	if res.Err != nil {
		result = audit.ResultError
		detail = fmt.Sprintf("backend=%s driver=%s stage=%s error=%s", res.Backend, res.Driver, res.Stage, res.Err.Error())
	}
	if err := v.src.DB.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      verifyActor,
		ActorRoles: "system",
		Action:     audit.ActionBackupVerify,
		Target:     res.Backend,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		v.logger.Printf("backup restore-verification: WARNING: failed to append backup.verify audit event: %v", err)
	}
}

// --- Scratch-database restore targets ---------------------------------------

// restoreTarget is an isolated scratch database an archive's DB dump is restored
// into for verification, then always torn down (cleanup is deferred by the
// caller). Implementations must never touch the live store.
type restoreTarget interface {
	// restore loads the archive's DB dump into the scratch database.
	restore(ctx context.Context, a *Archive) error
	// open opens the restored scratch database WITHOUT migrating or mutating it,
	// exactly as read-only DR tooling would.
	open() (*database.DB, error)
	// cleanup tears the scratch database down (removes the temp file / drops the
	// throwaway database). It must be safe to call even after a failed restore.
	cleanup()
}

// newRestoreTarget picks the scratch backend from the archive's dump type: a
// SQLite snapshot restores into a temp file, a PostgreSQL logical dump into a
// throwaway database on the configured server (baseDSN).
func newRestoreTarget(dumpFile, baseDSN string) (restoreTarget, error) {
	switch dumpFile {
	case fileSQLite:
		return newSQLiteRestoreTarget()
	case filePostgres:
		return newPostgresRestoreTarget(baseDSN)
	default:
		return nil, fmt.Errorf("unsupported dump file %q in archive", dumpFile)
	}
}

// sqliteRestoreTarget restores a SQLite snapshot into a temp file that is deleted
// on cleanup.
type sqliteRestoreTarget struct {
	dir  string
	path string
}

func newSQLiteRestoreTarget() (*sqliteRestoreTarget, error) {
	dir, err := os.MkdirTemp("", "secsy-restore-verify-*")
	if err != nil {
		return nil, fmt.Errorf("creating scratch directory: %w", err)
	}
	return &sqliteRestoreTarget{dir: dir, path: filepath.Join(dir, "restored.db")}, nil
}

func (t *sqliteRestoreTarget) restore(_ context.Context, a *Archive) error {
	return a.RestoreSQLite(t.path)
}

func (t *sqliteRestoreTarget) open() (*database.DB, error) {
	return database.OpenExisting("sqlite", t.path)
}

func (t *sqliteRestoreTarget) cleanup() { _ = os.RemoveAll(t.dir) }

// postgresRestoreTarget restores a PostgreSQL logical dump into a throwaway
// database created on the configured server, always dropped on cleanup. It
// mirrors the chaos suite's isolatedPGDatabase pattern: CREATE DATABASE up
// front, DROP DATABASE ... WITH (FORCE) on teardown so a straggler session
// cannot leak it.
type postgresRestoreTarget struct {
	baseDSN    string
	scratchDSN string
	name       string
}

func newPostgresRestoreTarget(baseDSN string) (*postgresRestoreTarget, error) {
	if baseDSN == "" {
		return nil, fmt.Errorf("restoring a PostgreSQL backup requires the configured database DSN to create an isolated scratch database")
	}
	u, err := url.Parse(baseDSN)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		return nil, fmt.Errorf("cannot derive an isolated scratch database from the configured PostgreSQL DSN (must be URL form)")
	}
	name := "secsy_verify_" + strings.ReplaceAll(uuid.NewString(), "-", "")

	admin, err := sql.Open("postgres", baseDSN)
	if err != nil {
		return nil, fmt.Errorf("opening admin connection: %w", err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.Exec("CREATE DATABASE " + pgQuoteIdent(name)); err != nil {
		return nil, fmt.Errorf("creating scratch database (needs CREATEDB on the configured server): %w", err)
	}

	iso := *u
	iso.Path = "/" + name
	return &postgresRestoreTarget{baseDSN: baseDSN, scratchDSN: iso.String(), name: name}, nil
}

func (t *postgresRestoreTarget) restore(ctx context.Context, a *Archive) error {
	dump, ok := a.PostgresDump()
	if !ok {
		return fmt.Errorf("archive contains no PostgreSQL dump (dump_file=%q)", a.Manifest.DumpFile)
	}
	return pgRestore(ctx, t.scratchDSN, dump)
}

func (t *postgresRestoreTarget) open() (*database.DB, error) {
	return database.OpenExisting("postgres", t.scratchDSN)
}

func (t *postgresRestoreTarget) cleanup() {
	admin, err := sql.Open("postgres", t.baseDSN)
	if err != nil {
		return
	}
	defer func() { _ = admin.Close() }()
	// FORCE disconnects any straggler session so the drop cannot leak the scratch
	// database on a teardown race. Best effort — a leaked throwaway database on
	// the test/DR server is harmless and named recognizably.
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + pgQuoteIdent(t.name) + " WITH (FORCE)"); err != nil {
		log.Printf("backup restore-verification: WARNING: dropping scratch database %s: %v", t.name, err)
	}
}

// pgRestore loads a plain-format pg_dump into dsn by piping it through psql with
// ON_ERROR_STOP so any restore error fails the drill. psql must be on PATH.
func pgRestore(ctx context.Context, dsn string, dump []byte) error {
	cmd := exec.CommandContext(ctx, "psql", "--dbname="+dsn, "--quiet", "--no-psqlrc",
		"--set", "ON_ERROR_STOP=1", "--file", "-")
	cmd.Stdin = bytes.NewReader(dump)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql restore: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// pgQuoteIdent double-quotes a PostgreSQL identifier so a generated database
// name is always used safely, even though the name is a fixed prefix plus hex.
func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// failedChecks renders the failed integrity checks for an error message.
func failedChecks(res *database.IntegrityResult) string {
	var parts []string
	for _, c := range res.Checks {
		if !c.OK {
			parts = append(parts, c.Name+": "+c.Detail)
		}
	}
	return strings.Join(parts, "; ")
}

// shortHex abbreviates a hex hash for logs and audit detail.
func shortHex(h string) string {
	if h == "" {
		return "(empty)"
	}
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
