package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// actor is the identity backups run and audit as.
const actor = "backup"

// encryptionContext binds the backup purpose into the envelope AAD, so a backup
// blob can only be opened with the same context — it cannot be substituted for
// an application secret sealed under the same KEK (or vice versa).
func encryptionContext() []byte { return []byte("secsy-pki/backup/v1") }

// OuterManifest is the plaintext manifest published next to the encrypted
// archive at the store's ManifestPath. It carries only coarse metadata — enough
// to monitor freshness and verify the artifact digest — and deliberately does
// NOT reveal CA identities, which live only inside the encrypted archive.
type OuterManifest struct {
	Version         int       `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	DBDriver        string    `json:"db_driver"`
	KEKLabel        string    `json:"kek_label"`
	KEKVersion      int       `json:"kek_version"`
	Encrypted       bool      `json:"encrypted"`
	ArtifactFile    string    `json:"artifact_file"`
	ArtifactSHA256  string    `json:"artifact_sha256"`
	ArtifactSize    int       `json:"artifact_size"`
	AuditHeadSeq    int64     `json:"audit_head_seq"`
	AuditHeadHash   string    `json:"audit_head_hash"`
	CACount         int       `json:"ca_count"`
	AuditEventCount int       `json:"audit_event_count"`
}

// Runner is the scheduled backup job. It is a singleton background job: register
// its Run on the leader elector so exactly one replica backs up at a time. It
// never blocks issuance (reads plus an online snapshot / MVCC dump) and is a
// no-op on non-leaders (they never call Run).
type Runner struct {
	src      Source
	store    publish.Store
	cfg      config.BackupConfig
	kekLabel string
	logger   *log.Logger
	// now is the clock used for max-age retention; overridable in tests.
	now func() time.Time
}

// New builds a Runner. kekLabel is the resolved secret-layer KEK the artifact is
// encrypted under; it is required — a backup that could not be encrypted would
// defeat the point.
func New(src Source, store publish.Store, cfg config.BackupConfig, kekLabel string, logger *log.Logger) (*Runner, error) {
	if src.DB == nil {
		return nil, fmt.Errorf("backup: a database is required")
	}
	if src.Provider == nil {
		return nil, fmt.Errorf("backup: a key provider is required (to bind the encryption KEK)")
	}
	if store == nil {
		return nil, fmt.Errorf("backup: a destination store is required")
	}
	if kekLabel == "" {
		return nil, fmt.Errorf("backup: a KEK label is required (set backup.kek_label or secret.kek_label)")
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{src: src, store: store, cfg: cfg, kekLabel: kekLabel, logger: logger, now: time.Now}, nil
}

// Run produces a backup immediately, then on every interval tick, until ctx is
// cancelled. It blocks; callers register it as a leader-elected background job.
func (r *Runner) Run(ctx context.Context) {
	r.logger.Printf("scheduled backup started (interval=%s, backend=%s, kek=%s, keep=%d, max_age=%s, include_config=%t)",
		r.cfg.Interval(), r.store.Name(), r.kekLabel, r.cfg.Keep(), humanMaxAge(r.cfg.MaxAge()), r.cfg.IncludeConfigEnabled())
	if _, isPruner := r.store.(publish.SnapshotPruner); !isPruner {
		// A single-current backend (S3 overwrites fixed keys): the newest backup
		// always replaces the previous one, so historical keep-N / max-age is
		// delegated to object-store versioning + lifecycle policies. Log it once
		// so the bounded coverage is never silent.
		r.logger.Printf("scheduled backup: destination %q keeps only the latest backup; configure bucket versioning + lifecycle rules for keep-N/max-age history", r.store.Name())
	}
	r.RunOnce(ctx)

	ticker := time.NewTicker(r.cfg.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("scheduled backup stopped")
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}

// RunOnce produces, encrypts, publishes, and prunes exactly one backup,
// recording metrics and a backup.run audit event. It never returns an error: a
// failed backup is logged, counted, and audited so the next tick simply retries,
// and a transient failure never tears down the loop. It is exported for tests.
func (r *Runner) RunOnce(ctx context.Context) {
	start := time.Now()
	size, retained, err := r.backup(ctx)
	metrics.RecordBackupRun(start, size, retained, err)
	if err != nil {
		r.logger.Printf("scheduled backup: FAILED after %s: %v", time.Since(start).Round(time.Millisecond), err)
	} else {
		r.logger.Printf("scheduled backup: ok — %d bytes to %s, %d retained (%s)",
			size, r.store.Name(), retained, time.Since(start).Round(time.Millisecond))
	}
	r.recordAudit(size, retained, err)
}

// backup runs one cycle, returning the encrypted-artifact size and the retained
// count. Errors are returned for the caller to record; nothing here mutates the
// signing path.
func (r *Runner) backup(ctx context.Context) (size, retained int, err error) {
	// Bind the KEK ring for this run (short-lived HSM session, matching the
	// signing/secret paths). Sealing wraps the DEK under the KEK public key with
	// no HSM round-trip; only the one-time wrap-algorithm negotiation touches the
	// token, so issuance is never blocked.
	versions, err := r.src.DB.ListKEKVersions(r.kekLabel)
	if err != nil {
		return 0, 0, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	ring, err := secret.LoadRing(ctx, r.src.Provider, r.kekLabel, versions)
	if err != nil {
		return 0, 0, fmt.Errorf("binding backup KEK %q: %w", r.kekLabel, err)
	}

	// Build the plaintext archive, stamping the active KEK into its manifest.
	plain, man, err := BuildArtifact(ctx, r.src, r.cfg.IncludeConfigEnabled(), ring.ActiveLabel(), ring.ActiveVersion())
	if err != nil {
		return 0, 0, err
	}

	// Seal under the active KEK version. The destination only ever holds
	// ciphertext.
	blob, err := ring.EncryptToJSON(plain, encryptionContext())
	if err != nil {
		return 0, 0, fmt.Errorf("encrypting backup: %w", err)
	}

	// Publish as a single-artifact snapshot: atomic swap + manifest + integrity
	// readback, reusing the Task 58 sinks.
	outer := buildOuterManifest(man, blob)
	outerJSON, err := json.MarshalIndent(outer, "", "  ")
	if err != nil {
		return len(blob), 0, fmt.Errorf("encoding backup manifest: %w", err)
	}
	artifacts := []publish.Artifact{{
		Path:        ArtifactName,
		Data:        blob,
		ContentType: "application/octet-stream",
		Kind:        "backup",
	}}
	if err := r.store.Publish(ctx, append(outerJSON, '\n'), artifacts); err != nil {
		return len(blob), 0, fmt.Errorf("publishing backup to %s: %w", r.store.Name(), err)
	}

	retained = r.pruneRetention(ctx)
	return len(blob), retained, nil
}

// pruneRetention enforces keep-N and max-age over the destination's retained
// backups, returning the number retained afterward. For a backend that does not
// accumulate history it returns 1 (the single current backup); history there is
// governed by object-store lifecycle policies.
func (r *Runner) pruneRetention(ctx context.Context) int {
	pruner, ok := r.store.(publish.SnapshotPruner)
	if !ok {
		return 1
	}
	snaps, err := pruner.ListSnapshots(ctx)
	if err != nil {
		r.logger.Printf("scheduled backup: WARNING: listing snapshots for retention: %v", err)
		return 0
	}
	keep := r.cfg.Keep()
	maxAge := r.cfg.MaxAge()
	now := r.now()

	kept := 0
	for i := range snaps { // newest first
		s := snaps[i]
		// The current backup is always retained, even past keep-N or max age:
		// there must always be at least one restorable backup.
		if s.Current {
			kept++
			continue
		}
		overCount := i >= keep
		overAge := maxAge > 0 && now.Sub(s.CreatedAt) > maxAge
		if overCount || overAge {
			if derr := pruner.DeleteSnapshot(ctx, s.ID); derr != nil {
				r.logger.Printf("scheduled backup: WARNING: pruning backup %s: %v", s.ID, derr)
				kept++ // still present
			}
			continue
		}
		kept++
	}
	return kept
}

// recordAudit appends the backup.run event for one cycle, best-effort.
func (r *Runner) recordAudit(size, retained int, runErr error) {
	result := audit.ResultSuccess
	detail := fmt.Sprintf("backend=%s driver=%s bytes=%d retained=%d kek=%s",
		r.store.Name(), r.src.DB.Driver(), size, retained, r.kekLabel)
	if runErr != nil {
		result = audit.ResultError
		detail = fmt.Sprintf("backend=%s driver=%s error=%s", r.store.Name(), r.src.DB.Driver(), runErr.Error())
	}
	if err := r.src.DB.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "system",
		Action:     audit.ActionBackupRun,
		Target:     r.store.Name(),
		Result:     result,
		Detail:     detail,
	}); err != nil {
		r.logger.Printf("scheduled backup: WARNING: failed to append backup.run audit event: %v", err)
	}
}

// Decrypt decrypts an encrypted backup blob with the family ring and returns the
// parsed, digest-verified archive. It is the inverse of the runner's seal step
// and the entry point a restore uses.
func Decrypt(ctx context.Context, ring *secret.Ring, encrypted []byte) (*Archive, error) {
	plain, err := ring.DecryptJSON(ctx, encrypted, encryptionContext())
	if err != nil {
		return nil, fmt.Errorf("decrypting backup: %w", err)
	}
	return OpenArchive(plain)
}

// buildOuterManifest derives the plaintext outer manifest from the archive
// manifest and the sealed blob.
func buildOuterManifest(man *ArtifactManifest, blob []byte) OuterManifest {
	sum := sha256.Sum256(blob)
	return OuterManifest{
		Version:         ArtifactVersion,
		CreatedAt:       man.CreatedAt,
		DBDriver:        man.DBDriver,
		KEKLabel:        man.KEKLabel,
		KEKVersion:      man.KEKVersion,
		Encrypted:       true,
		ArtifactFile:    ArtifactName,
		ArtifactSHA256:  hex.EncodeToString(sum[:]),
		ArtifactSize:    len(blob),
		AuditHeadSeq:    man.AuditHeadSeq,
		AuditHeadHash:   man.AuditHeadHash,
		CACount:         len(man.CAs),
		AuditEventCount: man.Fingerprint.AuditEventCount,
	}
}

// humanMaxAge renders a retention max-age for logs ("off" when unbounded).
func humanMaxAge(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	return d.String()
}
