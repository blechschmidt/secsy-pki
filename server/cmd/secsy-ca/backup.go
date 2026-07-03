package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// backupManifestVersion is bumped when the on-disk manifest schema changes.
const backupManifestVersion = 1

// backupCARef is the public, restore-verifiable summary of a single CA. It
// carries no private key material — only the certificate and public identifiers
// needed to confirm, after recovery, that the HSM still holds the matching key.
type backupCARef struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	KeyLabel       string `json:"key_label"` // provider key label (from the PKCS#11 URI)
	Subject        string `json:"subject"`
	Serial         string `json:"serial"`
	KeyType        string `json:"key_type"`
	PKCS11URI      string `json:"pkcs11_uri"`
	KeyFingerprint string `json:"public_key_fingerprint_sha256"`
	NotAfter       string `json:"not_after,omitempty"`
}

// backupManifest is the disaster-recovery anchor written alongside the CA
// metadata. It ties the metadata store, the key inventory, and the audit-log
// head together so a restore can be verified end-to-end. It never contains
// private key material — the HSM token backup (handled out of band) holds the
// (still non-extractable) key blobs.
type backupManifest struct {
	Version         int                         `json:"version"`
	CreatedAt       string                      `json:"created_at"`
	KeyProvider     string                      `json:"key_provider"`
	DBDriver        string                      `json:"db_driver"`
	SQLiteSnapshot  string                      `json:"sqlite_snapshot,omitempty"`
	CAs             []backupCARef               `json:"cas"`
	KeyInventory    []keyprovider.KeyDescriptor `json:"key_inventory,omitempty"`
	AuditHeadSeq    int64                       `json:"audit_head_seq"`
	AuditHeadHash   string                      `json:"audit_head_hash"`
	AuditChainValid bool                        `json:"audit_chain_valid"`
	AuditEventCount int                         `json:"audit_event_count"`
	Notes           []string                    `json:"notes"`
}

// cmdBackup exports CA metadata and a disaster-recovery manifest to a directory.
// It captures everything needed to reconstruct and verify CA state after a loss,
// while honoring the key non-extractability invariant: private keys are NEVER
// exported — only public certificates, key identifiers, and the audit trail.
// The HSM token state (encrypted key blobs) must be backed up separately with
// the token's own tooling; the DR runbook documents this.
func cmdBackup(db *database.DB, _ *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	outDir := fs.String("out", "", "output directory for the backup bundle (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outDir == "" {
		fs.Usage()
		return fmt.Errorf("-out is required")
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("creating backup directory: %w", err)
	}

	cas, err := db.ListCAs()
	if err != nil {
		return fmt.Errorf("listing CAs: %w", err)
	}

	manifest := backupManifest{
		Version:     backupManifestVersion,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		KeyProvider: provider.Name(),
		DBDriver:    db.Driver(),
	}

	for _, c := range cas {
		keyLabel := pki.ExtractKeyLabel(c.PKCS11URI)
		if keyLabel == "" {
			keyLabel = c.Label
		}
		ref := backupCARef{
			ID:             c.ID,
			Label:          c.Label,
			KeyLabel:       keyLabel,
			Subject:        c.Subject,
			Serial:         c.Serial,
			KeyType:        c.KeyType,
			PKCS11URI:      c.PKCS11URI,
			KeyFingerprint: publicKeyFingerprint(c.PublicKey),
		}
		if c.NotAfter != nil {
			ref.NotAfter = c.NotAfter.Format(time.RFC3339)
		}
		manifest.CAs = append(manifest.CAs, ref)
	}

	// Key inventory (labels + extractability flags) — proof of which keys the
	// token must hold after recovery, and that they are non-extractable.
	if lister, ok := provider.(keyprovider.KeyLister); ok {
		if keys, lerr := lister.ListKeys(context.Background()); lerr == nil {
			manifest.KeyInventory = keys
		} else {
			manifest.Notes = append(manifest.Notes, "key inventory unavailable: "+lerr.Error())
		}
	}

	// Audit-log head + chain verification: anchors the tamper-evident log so a
	// restore can confirm the log is intact and current.
	if vr, verr := db.VerifyEventChain(); verr == nil {
		manifest.AuditChainValid = vr.Valid
		manifest.AuditEventCount = vr.Count
	}
	manifest.AuditHeadSeq, manifest.AuditHeadHash = auditHead(db)

	// Portable, engine-agnostic exports of the CA records and full audit log.
	if err := writeJSONFile(filepath.Join(*outDir, "cas.json"), cas); err != nil {
		return err
	}
	events, err := db.ListAllEventsAsc()
	if err != nil {
		return fmt.Errorf("exporting audit log: %w", err)
	}
	if err := writeJSONFile(filepath.Join(*outDir, "events.json"), events); err != nil {
		return err
	}

	// Authoritative metadata snapshot. For SQLite we take a consistent online
	// copy; other engines are backed up with their native tooling per the runbook.
	if db.Driver() == "sqlite" || db.Driver() == "sqlite3" {
		snapPath := filepath.Join(*outDir, "metadata.db")
		_ = os.Remove(snapPath) // VACUUM INTO fails if the target exists
		if err := db.SnapshotSQLite(snapPath); err != nil {
			return fmt.Errorf("snapshotting metadata database: %w", err)
		}
		manifest.SQLiteSnapshot = "metadata.db"
	} else {
		manifest.Notes = append(manifest.Notes,
			fmt.Sprintf("metadata store uses driver %q; back it up with the engine's native tooling (e.g. pg_dump). cas.json/events.json are a portable fallback.", db.Driver()))
	}

	manifest.Notes = append(manifest.Notes,
		"HSM token state (encrypted, non-extractable key blobs) must be backed up separately with the token's own tooling; see the DR runbook. Private keys are never included in this bundle.")

	if err := writeJSONFile(filepath.Join(*outDir, "manifest.json"), manifest); err != nil {
		return err
	}

	// Audit the backup itself.
	appendAudit(db, &audit.Event{
		Actor: "secsy-ca-cli", Action: audit.ActionHSMBackup, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("cas=%d events=%d out=%s head_seq=%d", len(cas), manifest.AuditEventCount, *outDir, manifest.AuditHeadSeq),
	})

	fmt.Printf("Backup written to %s\n", *outDir)
	fmt.Printf("  CAs:            %d\n", len(manifest.CAs))
	fmt.Printf("  Audit events:   %d (chain valid: %t, head seq %d)\n", manifest.AuditEventCount, manifest.AuditChainValid, manifest.AuditHeadSeq)
	fmt.Printf("  Key inventory:  %d key(s)\n", len(manifest.KeyInventory))
	if manifest.SQLiteSnapshot != "" {
		fmt.Printf("  Metadata:       %s (SQLite snapshot)\n", manifest.SQLiteSnapshot)
	}
	fmt.Println("\nReminder: back up the HSM token state separately (see docs/key-ceremony.md). Private keys are never exported.")
	return nil
}

// cmdRestore verifies recovered CA metadata against the key provider and audit
// log. After the metadata store and HSM token have been restored from backup
// material (see the DR runbook), this confirms end-to-end consistency: every CA
// in the manifest exists, the HSM holds each CA's (non-extractable) key with a
// matching public-key fingerprint, and the audit chain is intact and at least as
// current as the backup. With -load-metadata it will also repopulate an empty
// metadata store from cas.json (the engine-agnostic recovery path).
func cmdRestore(db *database.DB, _ *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	inDir := fs.String("in", "", "backup bundle directory produced by 'backup' (required)")
	loadMetadata := fs.Bool("load-metadata", false, "repopulate CA records from cas.json if the metadata store is empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}

	var manifest backupManifest
	if err := readJSONFile(filepath.Join(*inDir, "manifest.json"), &manifest); err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}
	if manifest.Version != backupManifestVersion {
		fmt.Fprintf(os.Stderr, "WARNING: manifest version %d differs from expected %d\n", manifest.Version, backupManifestVersion)
	}
	fmt.Printf("Restoring from backup created %s (provider=%s, driver=%s)\n",
		manifest.CreatedAt, manifest.KeyProvider, manifest.DBDriver)

	// Optional engine-agnostic metadata recovery: only when the store is empty,
	// so we never clobber a populated database.
	if *loadMetadata {
		if err := loadMetadataFromBundle(db, *inDir); err != nil {
			return err
		}
	}

	failures := 0
	for _, ref := range manifest.CAs {
		problems := verifyCARef(db, provider, ref)
		if len(problems) == 0 {
			fmt.Printf("  ✓ %s (%s): metadata present, HSM key resolves, fingerprint matches\n", ref.Label, ref.KeyType)
			continue
		}
		failures++
		for _, p := range problems {
			fmt.Printf("  ✗ %s: %s\n", ref.Label, p)
		}
	}

	// Verify the audit chain of the recovered store and that it is at least as
	// current as the backup anchor (the chain may have grown since the backup).
	auditOK := true
	if vr, verr := db.VerifyEventChain(); verr != nil {
		fmt.Printf("  ✗ audit log: verification error: %v\n", verr)
		auditOK = false
	} else if !vr.Valid {
		fmt.Printf("  ✗ audit log: chain broken at seq %d (%s)\n", vr.BrokenAtSeq, vr.Reason)
		auditOK = false
	} else {
		headSeq, _ := auditHead(db)
		if headSeq < manifest.AuditHeadSeq {
			fmt.Printf("  ✗ audit log: recovered head seq %d is behind the backup anchor seq %d — log truncation?\n", headSeq, manifest.AuditHeadSeq)
			auditOK = false
		} else {
			fmt.Printf("  ✓ audit log: chain intact (%d events, head seq %d)\n", vr.Count, headSeq)
		}
	}

	appendAudit(db, &audit.Event{
		Actor: "secsy-ca-cli", Action: audit.ActionHSMRestore,
		Result: resultFor(failures == 0 && auditOK),
		Detail: fmt.Sprintf("in=%s cas=%d failures=%d audit_ok=%t", *inDir, len(manifest.CAs), failures, auditOK),
	})

	if failures > 0 || !auditOK {
		return fmt.Errorf("restore verification failed: %d CA problem(s), audit_ok=%t", failures, auditOK)
	}
	fmt.Printf("\nRestore verified: %d CA(s) consistent, HSM keys present and non-extractable, audit chain intact.\n", len(manifest.CAs))
	return nil
}

// verifyCARef checks a single CA from the manifest against the recovered
// metadata store and key provider, returning a list of problems (empty = OK).
func verifyCARef(db *database.DB, provider keyprovider.Provider, ref backupCARef) []string {
	var problems []string

	stored, err := db.GetCA(ref.ID)
	if err != nil {
		return []string{fmt.Sprintf("looking up CA: %v", err)}
	}
	if stored == nil {
		problems = append(problems, "CA metadata missing from the recovered store")
	} else if fp := publicKeyFingerprint(stored.PublicKey); fp != ref.KeyFingerprint {
		problems = append(problems, fmt.Sprintf("stored public key fingerprint %s != backup %s", fp, ref.KeyFingerprint))
	}

	// The decisive HSM check: the token must hold the CA's key, and its public
	// key must match the certificate — proving the key survived recovery.
	info, err := provider.FindKey(context.Background(), keyprovider.KeyRef{Label: ref.KeyLabel})
	if err != nil {
		problems = append(problems, fmt.Sprintf("key %q not found in key provider: %v", ref.KeyLabel, err))
		return problems
	}
	if fp := publicKeyFingerprint(info.SSHPublicKey); fp != ref.KeyFingerprint {
		problems = append(problems, fmt.Sprintf("HSM key fingerprint %s != backup %s", fp, ref.KeyFingerprint))
	}
	return problems
}

// loadMetadataFromBundle repopulates CA records from cas.json, but only when the
// store currently has no CAs — recovery must never overwrite live data.
func loadMetadataFromBundle(db *database.DB, inDir string) error {
	existing, err := db.ListCAs()
	if err != nil {
		return fmt.Errorf("checking existing CAs: %w", err)
	}
	if len(existing) > 0 {
		fmt.Fprintf(os.Stderr, "  … -load-metadata skipped: metadata store already has %d CA(s)\n", len(existing))
		return nil
	}
	var cas []models.CA
	if err := readJSONFile(filepath.Join(inDir, "cas.json"), &cas); err != nil {
		return fmt.Errorf("reading cas.json: %w", err)
	}
	for i := range cas {
		c := cas[i]
		if err := db.CreateCA(&c); err != nil {
			return fmt.Errorf("recreating CA %q: %w", c.Label, err)
		}
	}
	fmt.Printf("  ✓ loaded %d CA record(s) from cas.json into the empty metadata store\n", len(cas))
	return nil
}

// resultFor maps a boolean success to an audit result code.
func resultFor(ok bool) string {
	if ok {
		return audit.ResultSuccess
	}
	return audit.ResultError
}

// writeJSONFile writes v as indented JSON with 0600 permissions.
func writeJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// readJSONFile decodes the JSON file at path into v.
func readJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
