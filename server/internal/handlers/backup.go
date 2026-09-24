package handlers

// REST surface for disaster-recovery export and restore verification
// (`secsy-ca backup`, `secsy-ca backup verify-restore`) — Task 198.
//
// Both halves of DR were shell-only before this. GET /api/backup is the metadata
// bundle: the public CA material plus the DR manifest that ties the metadata
// store, the key inventory, and the audit-chain head together, so a restore can
// be verified end-to-end. POST /api/backup/verify-restore is the drill that
// proves the newest SCHEDULED encrypted backup can actually be restored — an
// untested backup is not a backup, and an operator must be able to run that
// proof (and see where it would break) without shell access to the CA host.
//
// The non-extractability invariant governs the export: private key material is
// NEVER included. Only certificates, key identifiers, public-key fingerprints,
// and the audit anchor leave the process; the HSM token blobs are backed up out
// of band with the token's own tooling, and the scheduled artifact is encrypted
// before it ever reaches its destination. backup_test.go asserts the response
// carries no private key.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/backup"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// backupManifestVersion is the DR manifest schema version, matching the bundle
// `secsy-ca backup -out` writes (manifest.json v1) so the two are readable by
// the same tooling.
const backupManifestVersion = 1

// backupVerifyTimeout bounds one restore-verification drill: it fetches and
// decrypts the newest artifact, restores it into a scratch database, and walks
// the restored store's integrity gate. Generous, because on a large store the
// restore genuinely takes minutes — but not unbounded, because it is a request.
const backupVerifyTimeout = 10 * time.Minute

// BackupManifest is the disaster-recovery anchor: it ties the metadata store, the
// key inventory, and the audit-log head together so a restore can be verified
// end to end. It is the manifest.json of `secsy-ca backup -out`, field for field.
// It never contains private key material.
type BackupManifest struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	// KeyProvider names the backend holding the (non-extractable) private keys
	// this metadata refers to.
	KeyProvider string `json:"key_provider"`
	DBDriver    string `json:"db_driver"`
	// CAs are the restore-verifiable per-CA summaries: identifiers, the provider
	// key label, and the public-key fingerprint a restore matches against the key
	// the token still holds.
	CAs []backup.CARef `json:"cas"`
	// KeyInventory is the provider's key list (labels, types, extractability) —
	// proof of which keys the token must hold after recovery, and that they are
	// non-extractable. Absent when the provider cannot enumerate, or when it is
	// unreachable (then Notes says so and the export still succeeds).
	KeyInventory []keyprovider.KeyDescriptor `json:"key_inventory,omitempty"`
	// Audit anchor: the tip of the tamper-evident log at export time, plus whether
	// the chain verified and how many events it holds.
	AuditHeadSeq    int64  `json:"audit_head_seq"`
	AuditHeadHash   string `json:"audit_head_hash"`
	AuditChainValid bool   `json:"audit_chain_valid"`
	AuditEventCount int    `json:"audit_event_count"`
	// Notes record what is NOT in this bundle and where to get it. Never empty.
	Notes []string `json:"notes"`
}

// BackupResponse is the body of GET /api/backup: the DR manifest plus the full
// CA records, i.e. the manifest.json and cas.json of the CLI bundle delivered as
// one document.
type BackupResponse struct {
	Manifest BackupManifest `json:"manifest"`
	// CAs are the complete CA records — the engine-agnostic recovery input
	// (cas.json). Public material only: certificates, CSRs, external chains,
	// public keys, key URIs.
	CAs []models.CA `json:"cas"`
	// ConfigPath is the configuration file the running process answers for, so a
	// recovery runbook records which config produced this state.
	ConfigPath string `json:"config_path,omitempty"`
	// ScheduledDestination is where the scheduled ENCRYPTED backups are written
	// ("dir:<path>" or "s3://bucket/prefix"), and ScheduledBackupEnabled whether
	// that loop runs at all. Together they tell an operator holding this metadata
	// bundle where the authoritative artifact lives — the piece this response
	// deliberately does not contain.
	ScheduledDestination   string `json:"scheduled_destination,omitempty"`
	ScheduledBackupEnabled bool   `json:"scheduled_backup_enabled"`
}

// BackupVerifyRestoreResponse is the body of POST /api/backup/verify-restore: the
// shared backup.VerifyResult (backend, artifact identity and digest, per-stage
// integrity checks, restored vs. manifest audit head) exactly as
// `secsy-ca backup verify-restore -json` prints it, plus the verdict.
type BackupVerifyRestoreResponse struct {
	*backup.VerifyResult
	// OK is true only when the drill proved the backup restorable.
	OK bool `json:"ok"`
}

// ExportBackup handles GET /api/backup — the REST form of `secsy-ca backup`.
//
// Gated on the platform-wide hsm:manage capability, the same gate as
// /api/inventory/keys: this response names every CA, every key label the token
// holds, and the audit-chain head of the whole deployment. It is the most
// revealing read in the API, it is cross-tenant by nature, and the CLI audits it
// as hsm.backup — so it is held at the DR/HSM administration level rather than
// behind audit:read, and no tenant-scoped role reaches it.
//
// It never returns private key material, and it works during an HSM outage: an
// unreachable provider costs the key inventory (recorded as a note), not the
// export.
func (a *API) ExportBackup(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		a.recordEvent(r, audit.ActionHSMBackup, "", "", audit.ResultDenied, "hsm:manage capability required")
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}
	deps, ok := a.requireOps(w, "the disaster-recovery export")
	if !ok {
		return
	}

	cas, err := a.db.ListCAs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing CAs: %v", err)
		return
	}

	man := BackupManifest{
		Version:     backupManifestVersion,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		KeyProvider: a.keyProvider.Name(),
		DBDriver:    a.db.Driver(),
	}
	for i := range cas {
		man.CAs = append(man.CAs, backupCARef(&cas[i]))
	}

	// Key inventory (labels + extractability), the proof of which keys the token
	// must hold after recovery. The CLI degrades to a note when the provider
	// cannot answer; so does this, which is what keeps the export usable while the
	// HSM is down.
	if lister, isLister := a.keyProvider.(keyprovider.KeyLister); isLister {
		if keys, lerr := lister.ListKeys(r.Context()); lerr == nil {
			man.KeyInventory = keys
		} else {
			man.Notes = append(man.Notes, "key inventory unavailable: "+lerr.Error())
		}
	}

	// Audit anchor: chain verification plus the head, so a restore can confirm the
	// log is intact and no older than this export.
	if vr, verr := a.db.VerifyEventChain(); verr == nil {
		man.AuditChainValid = vr.Valid
		man.AuditEventCount = vr.Count
	}
	if seq, hash, _, herr := a.db.EventLogHead(); herr == nil {
		man.AuditHeadSeq, man.AuditHeadHash = seq, hash
	}

	// What this bundle is NOT. The CLI writes the audit log and (for SQLite) an
	// online store snapshot next to the manifest; a JSON response is the wrong
	// carrier for either — the log is unbounded and the snapshot is a binary
	// database — so both are named here with where to get them instead. The
	// scheduled encrypted artifact (Task 89) is the authoritative full backup.
	man.Notes = append(man.Notes,
		"The complete hash-chained audit log is not inlined: export it from GET /api/events/export (the head hash and event count above anchor it).",
		"The authoritative metadata-store snapshot (driver "+man.DBDriver+") is not inlined: take it from the scheduled encrypted backup, or with the engine's native tooling. The CA records below are the engine-agnostic recovery fallback.",
		// Worded "private-key material" rather than the CLI's "private keys" so the
		// literal string a PEM header would carry never appears in this response at
		// all — backup_test.go asserts exactly that over the whole body.
		"HSM token state (encrypted, non-extractable key blobs) must be backed up separately with the token's own tooling; see the DR runbook. Private-key material is never included in this bundle.")

	a.recordEvent(r, audit.ActionHSMBackup, "", "", audit.ResultSuccess,
		fmt.Sprintf("cas=%d events=%d head_seq=%d keys=%d via=api",
			len(man.CAs), man.AuditEventCount, man.AuditHeadSeq, len(man.KeyInventory)))

	writeJSON(w, http.StatusOK, BackupResponse{
		Manifest:               man,
		CAs:                    cas,
		ConfigPath:             deps.ConfigPath,
		ScheduledDestination:   backupDestination(deps),
		ScheduledBackupEnabled: deps.Config.Backup.Enabled,
	})
}

// VerifyBackupRestore handles POST /api/backup/verify-restore — the REST form of
// `secsy-ca backup verify-restore`.
//
// It drives the SAME backup.Verifier the leader-elected drill uses, over the same
// configured destination and KEK, so the console can never report a different
// recovery posture than the background job: the newest published artifact is
// fetched, digest-checked against the outer manifest, decrypted through the
// secret-envelope ring, restored into an isolated scratch database (always torn
// down), run through the HSM-independent integrity gate, and its restored
// audit-head fingerprint matched against the artifact manifest.
//
// Same gate as the export (platform hsm:manage): it binds the backup KEK on the
// HSM and reads the whole encrypted artifact. It never mutates the live store
// beyond the backup.verify audit event the verifier appends.
//
// Status codes mirror the CLI's exits so a monitoring caller can trip on the
// status alone: 200 when the backup was proven restorable, 404 when there is no
// backup at the destination to verify yet, 500 when the drill ran and FAILED
// (the body then names the stage and the error).
func (a *API) VerifyBackupRestore(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		a.recordEvent(r, audit.ActionBackupVerify, "", "", audit.ResultDenied, "hsm:manage capability required")
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}
	deps, ok := a.requireOps(w, "backup restore-verification")
	if !ok {
		return
	}

	bc := deps.Config.Backup
	kekLabel := bc.EffectiveKEKLabel(deps.Config.Secret.KEKLabel)
	if kekLabel == "" {
		writeError(w, http.StatusServiceUnavailable,
			"backup restore-verification is unavailable: no KEK configured (set backup.kek_label or secret.kek_label)")
		return
	}
	store, err := backup.NewStore(bc)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "opening the backup destination: %v", err)
		return
	}

	// The KEK that seals backups lives with the CA role's provider (which also
	// backs the OCSP responder keys and the secret-envelope ring), exactly as the
	// CLI binds it — and the SERVING provider is reused when the role resolves to
	// the same backend. A separate one would be a second session pool: on a
	// YubiHSM 2 the device allows 16 sessions and the serving provider already holds
	// eight, so a long drill opening eight more sits at the limit and two concurrent
	// ones starve live CA signing. release() closes only a provider it opened.
	provider, release, ok := a.providerForRole(w, "ca", "backup restore-verification")
	if !ok {
		return
	}
	defer release()

	// No notifier: the alerting is the background drill's job (it owns the
	// scheduled cadence). Here the response is the operator's signal.
	verifier, err := backup.NewVerifier(
		backup.Source{DB: a.db, Provider: provider, DSN: deps.Config.Database.DSN},
		store, bc, kekLabel, nil, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}

	// A drill restores a whole database; letting a client disconnect abort it
	// half-way would leave the scratch teardown to a cancelled context, so the
	// work is deliberately detached from the request's cancellation (values —
	// actor, tenant, request id — are kept) and bounded on its own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), backupVerifyTimeout)
	defer cancel()

	// VerifyOnce records the shared backup.verify event (actor "backup-verify")
	// and the verify metrics itself, exactly as the background drill does; the
	// event below adds the one thing that path cannot know — which operator asked.
	res := verifier.VerifyOnce(ctx)
	resp := BackupVerifyRestoreResponse{VerifyResult: res, OK: res.OK()}

	switch {
	case res.Skipped:
		a.recordEvent(r, audit.ActionBackupVerify, res.Backend, "", audit.ResultError,
			fmt.Sprintf("backend=%s skipped=%s via=api", res.Backend, res.ErrMsg))
		writeJSON(w, http.StatusNotFound, resp)
	case res.Err != nil:
		a.recordEvent(r, audit.ActionBackupVerify, res.Backend, "", audit.ResultError,
			fmt.Sprintf("backend=%s driver=%s stage=%s error=%s via=api",
				res.Backend, res.Driver, res.Stage, res.Err.Error()))
		writeJSON(w, http.StatusInternalServerError, resp)
	default:
		a.recordEvent(r, audit.ActionBackupVerify, res.Backend, "", audit.ResultSuccess,
			fmt.Sprintf("backend=%s driver=%s bytes=%d integrity_ok=%t fingerprint_match=%t via=api",
				res.Backend, res.Driver, res.ArtifactSize, res.IntegrityOK, res.FingerprintMatch))
		writeJSON(w, http.StatusOK, resp)
	}
}

// backupCARef builds the restore-verifiable summary of one CA, using the shared
// backup.CARef so the export and the restore path agree on what a restore checks.
func backupCARef(c *models.CA) backup.CARef {
	keyLabel := pki.ExtractKeyLabel(c.PKCS11URI)
	if keyLabel == "" {
		keyLabel = c.Label
	}
	ref := backup.CARef{
		ID:             c.ID,
		Label:          c.Label,
		KeyLabel:       keyLabel,
		Subject:        c.Subject,
		Serial:         c.Serial,
		KeyType:        c.KeyType,
		PKCS11URI:      c.PKCS11URI,
		KeyFingerprint: backupPublicKeyFingerprint(c.PublicKey),
	}
	if c.NotAfter != nil {
		ref.NotAfter = c.NotAfter.Format(time.RFC3339)
	}
	return ref
}

// backupPublicKeyFingerprint returns the SSH SHA-256 fingerprint of a stored
// public key (authorized_keys form) — the same anchor the backup/restore path
// matches a recovered CA against.
func backupPublicKeyFingerprint(authorizedKey string) string {
	if authorizedKey == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "unknown"
	}
	return ssh.FingerprintSHA256(pub)
}

// backupDestination renders where the scheduled encrypted backups are written,
// resolved exactly as backup.NewStore selects the backend.
func backupDestination(deps *OpsDeps) string {
	bc := deps.Config.Backup
	if bc.Backend() == "s3" {
		return "s3://" + bc.S3.Bucket + "/" + strings.Trim(bc.S3.Prefix, "/")
	}
	if bc.Dir.Path == "" {
		return ""
	}
	return "dir:" + bc.Dir.Path
}
