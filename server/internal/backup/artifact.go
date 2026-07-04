// Package backup implements the scheduled encrypted-backup job (Task 89): a
// leader-elected background loop that periodically produces the disaster-recovery
// backup artifact, encrypts it with the HSM-backed secret/envelope layer, and
// writes it to a directory or S3-compatible store with atomic swap, a manifest,
// and keep-N / max-age retention.
//
// The artifact is a single uncompressed tar containing:
//
//	manifest.json   self-describing manifest: driver, KEK, audit-chain head, the
//	                Task 52 store fingerprint, CA summaries, and a SHA-256 of every
//	                other member (so a restore verifies the archive end-to-end)
//	cas.json        the full CA records (public CA material — certificates, key
//	                labels, public keys; never private keys)
//	events.json     the complete hash-chained audit log, ascending by sequence
//	config.yaml     the running configuration (optional; see backup.include_config)
//	metadata.db     the authoritative store, as an online SQLite VACUUM INTO
//	                snapshot (SQLite backends), OR
//	postgres.sql    a pg_dump logical dump (PostgreSQL backends)
//
// The tar is then sealed into a secret-layer envelope (AES-256-GCM DEK wrapped
// under the RSA KEK held by the HSM) before it ever leaves the process, so the
// destination only ever holds ciphertext. Private key material is never included
// — the HSM token blobs are backed up separately (see the DR runbook).
package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// ArtifactVersion is bumped when the archive layout or manifest schema changes.
const ArtifactVersion = 1

// ArtifactName is the object path of the encrypted archive within a published
// snapshot (the plaintext outer manifest is written at the store's ManifestPath
// alongside it).
const ArtifactName = "backup.tar.enc"

// Inner archive member names.
const (
	fileManifest = "manifest.json"
	fileCAs      = "cas.json"
	fileEvents   = "events.json"
	fileConfig   = "config.yaml"
	fileSQLite   = "metadata.db"
	filePostgres = "postgres.sql"
)

// Source supplies the state a backup artifact is built from.
type Source struct {
	// DB is the authoritative metadata/audit store to back up.
	DB *database.DB
	// Provider is the key provider holding the KEK; its Name is recorded in the
	// manifest (it holds no private material that is exported).
	Provider keyprovider.Provider
	// DSN is the database connection string, used only for the PostgreSQL
	// pg_dump path (unused for SQLite, whose snapshot goes through the handle).
	DSN string
	// ConfigPath is the running config file bundled into the archive when
	// include_config is on. Empty omits it.
	ConfigPath string
}

// CARef is the public, restore-verifiable summary of one CA. It carries no
// private key material — only the certificate identifiers and the public-key
// fingerprint needed to confirm, after recovery, that the HSM still holds the
// matching key.
type CARef struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	KeyLabel       string `json:"key_label"`
	Subject        string `json:"subject"`
	Serial         string `json:"serial"`
	KeyType        string `json:"key_type"`
	PKCS11URI      string `json:"pkcs11_uri"`
	KeyFingerprint string `json:"public_key_fingerprint_sha256"`
	NotAfter       string `json:"not_after,omitempty"`
}

// FileRef is the integrity record for one archive member.
type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// ArtifactManifest is the self-describing manifest bundled inside the archive.
// It ties the DB dump, config, CA material, and the audit-chain head together
// so a restore is verifiable end-to-end and independent of the HSM.
type ArtifactManifest struct {
	Version        int                       `json:"version"`
	CreatedAt      time.Time                 `json:"created_at"`
	DBDriver       string                    `json:"db_driver"`
	KeyProvider    string                    `json:"key_provider"`
	KEKLabel       string                    `json:"kek_label"`
	KEKVersion     int                       `json:"kek_version"`
	DumpFile       string                    `json:"dump_file"` // metadata.db | postgres.sql
	IncludesConfig bool                      `json:"includes_config"`
	AuditHeadSeq   int64                     `json:"audit_head_seq"`
	AuditHeadHash  string                    `json:"audit_head_hash"`
	Fingerprint    database.StoreFingerprint `json:"fingerprint"`
	CAs            []CARef                   `json:"cas"`
	Files          []FileRef                 `json:"files"`
	Notes          []string                  `json:"notes,omitempty"`
}

// BuildArtifact assembles the plaintext backup archive and returns it together
// with its manifest. It performs only reads and, for SQLite, an online
// VACUUM INTO snapshot; it never touches private key material, so it never
// blocks the HSM-backed issuance path. kekLabel/kekVersion are recorded in the
// manifest as the KEK the archive will be sealed under.
func BuildArtifact(ctx context.Context, src Source, includeConfig bool, kekLabel string, kekVersion int) ([]byte, *ArtifactManifest, error) {
	if src.DB == nil {
		return nil, nil, fmt.Errorf("backup: nil database")
	}

	man := &ArtifactManifest{
		Version:    ArtifactVersion,
		CreatedAt:  time.Now().UTC(),
		DBDriver:   src.DB.Driver(),
		KEKLabel:   kekLabel,
		KEKVersion: kekVersion,
		Notes: []string{
			"Private keys are never included. Back up the HSM token state separately with the token's own tooling; see docs/backup.md and docs/key-ceremony.md.",
		},
	}
	if src.Provider != nil {
		man.KeyProvider = src.Provider.Name()
	}

	// Public CA material — the full records go into cas.json; the manifest carries
	// verifiable summaries.
	cas, err := src.DB.ListCAs()
	if err != nil {
		return nil, nil, fmt.Errorf("listing CAs: %w", err)
	}
	for i := range cas {
		c := &cas[i]
		keyLabel := pki.ExtractKeyLabel(c.PKCS11URI)
		if keyLabel == "" {
			keyLabel = c.Label
		}
		ref := CARef{
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
		man.CAs = append(man.CAs, ref)
	}

	// Audit-chain head + full store fingerprint (the Task 52 DR gate): pins the
	// exact tip of the tamper-evident log and the monotonic counters so a restore
	// can be proven to lose no committed state.
	if fp, ferr := src.DB.VerifyStoreIntegrity(); ferr == nil {
		man.Fingerprint = fp.Fingerprint
		man.AuditHeadHash = fp.Fingerprint.AuditHeadHash
	}
	if seq, _, _, herr := src.DB.EventLogHead(); herr == nil {
		man.AuditHeadSeq = seq
	}

	// Assemble the member payloads (compute digests before writing the tar).
	casJSON, err := marshalJSON(cas)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding cas.json: %w", err)
	}
	events, err := src.DB.ListAllEventsAsc()
	if err != nil {
		return nil, nil, fmt.Errorf("exporting audit log: %w", err)
	}
	eventsJSON, err := marshalJSON(events)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding events.json: %w", err)
	}

	members := []tarMember{
		{name: fileCAs, data: casJSON},
		{name: fileEvents, data: eventsJSON},
	}

	if includeConfig && src.ConfigPath != "" {
		cfgData, cerr := os.ReadFile(src.ConfigPath)
		if cerr != nil {
			return nil, nil, fmt.Errorf("reading config %q: %w", src.ConfigPath, cerr)
		}
		members = append(members, tarMember{name: fileConfig, data: cfgData})
		man.IncludesConfig = true
	}

	// Authoritative store dump: an online SQLite snapshot, or a pg_dump logical
	// dump for networked backends.
	dumpName, dumpData, err := dumpStore(ctx, src.DB, src.DSN)
	if err != nil {
		return nil, nil, err
	}
	man.DumpFile = dumpName
	members = append(members, tarMember{name: dumpName, data: dumpData})

	// Record every member's digest, then emit the manifest and the tar. The
	// manifest necessarily excludes its own digest (a member cannot hash itself).
	for _, m := range members {
		sum := sha256.Sum256(m.data)
		man.Files = append(man.Files, FileRef{Name: m.name, SHA256: hex.EncodeToString(sum[:]), Size: len(m.data)})
	}
	manJSON, err := marshalJSON(man)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding manifest.json: %w", err)
	}
	all := append([]tarMember{{name: fileManifest, data: manJSON}}, members...)

	tarBytes, err := writeTar(all, man.CreatedAt)
	if err != nil {
		return nil, nil, err
	}
	return tarBytes, man, nil
}

// dumpStore produces the authoritative store dump member for the driver.
func dumpStore(ctx context.Context, db *database.DB, dsn string) (name string, data []byte, err error) {
	switch db.Driver() {
	case "sqlite", "sqlite3":
		tmpDir, err := os.MkdirTemp("", "secsy-backup-*")
		if err != nil {
			return "", nil, fmt.Errorf("creating snapshot temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()
		snapPath := filepath.Join(tmpDir, fileSQLite) // VACUUM INTO requires a non-existent target
		if err := db.SnapshotSQLite(snapPath); err != nil {
			return "", nil, fmt.Errorf("snapshotting metadata database: %w", err)
		}
		blob, err := os.ReadFile(snapPath)
		if err != nil {
			return "", nil, fmt.Errorf("reading metadata snapshot: %w", err)
		}
		return fileSQLite, blob, nil
	case "postgres", "postgresql":
		blob, err := pgDump(ctx, dsn)
		if err != nil {
			return "", nil, err
		}
		return filePostgres, blob, nil
	default:
		return "", nil, fmt.Errorf("backup: unsupported database driver %q", db.Driver())
	}
}

// pgDump runs pg_dump against dsn and returns a plain-format logical dump. The
// dump reads from a consistent MVCC snapshot on its own connection, so it never
// blocks issuance. pg_dump must be on PATH.
func pgDump(ctx context.Context, dsn string) ([]byte, error) {
	if dsn == "" {
		return nil, fmt.Errorf("backup: empty PostgreSQL DSN")
	}
	// pg_dump treats a dbname that contains '=' or a URI prefix as a full conninfo
	// string, so the configured DSN is passed through verbatim (credentials and
	// all). --no-owner/--no-privileges keep the dump portable across restore roles.
	cmd := exec.CommandContext(ctx, "pg_dump", "--no-owner", "--no-privileges", "--format=plain", "--dbname="+dsn)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pg_dump: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("pg_dump produced an empty dump")
	}
	return out.Bytes(), nil
}

// Archive is a parsed, digest-verified backup archive.
type Archive struct {
	Manifest ArtifactManifest
	// Files maps each archive member name to its bytes (manifest.json excluded).
	Files map[string][]byte
}

// OpenArchive parses a plaintext (already-decrypted) backup tar, verifying every
// member against the manifest's recorded SHA-256 digests. A digest mismatch or a
// member the manifest does not list is an error, so a tampered or truncated
// archive is rejected before any restore uses it.
func OpenArchive(plaintext []byte) (*Archive, error) {
	tr := tar.NewReader(bytes.NewReader(plaintext))
	raw := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading archive member %q: %w", hdr.Name, err)
		}
		raw[hdr.Name] = data
	}

	manData, ok := raw[fileManifest]
	if !ok {
		return nil, fmt.Errorf("archive has no %s", fileManifest)
	}
	var man ArtifactManifest
	if err := json.Unmarshal(manData, &man); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", fileManifest, err)
	}

	files := make(map[string][]byte, len(man.Files))
	for _, ref := range man.Files {
		data, ok := raw[ref.Name]
		if !ok {
			return nil, fmt.Errorf("archive is missing member %q listed in the manifest", ref.Name)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != ref.SHA256 {
			return nil, fmt.Errorf("integrity check failed for %q: sha256 %s, manifest says %s", ref.Name, got, ref.SHA256)
		}
		if len(data) != ref.Size {
			return nil, fmt.Errorf("integrity check failed for %q: size %d, manifest says %d", ref.Name, len(data), ref.Size)
		}
		files[ref.Name] = data
	}
	return &Archive{Manifest: man, Files: files}, nil
}

// RestoreSQLite writes the archive's SQLite snapshot to destPath (which must not
// already exist), reconstructing the authoritative store. It errors if the
// archive holds a PostgreSQL dump instead.
func (a *Archive) RestoreSQLite(destPath string) error {
	data, ok := a.Files[fileSQLite]
	if !ok {
		return fmt.Errorf("archive contains no SQLite snapshot (dump_file=%q)", a.Manifest.DumpFile)
	}
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %q", destPath)
	}
	if err := os.WriteFile(destPath, data, 0o600); err != nil {
		return fmt.Errorf("writing restored database: %w", err)
	}
	return nil
}

// PostgresDump returns the archive's PostgreSQL logical dump, or false when the
// archive holds a SQLite snapshot instead.
func (a *Archive) PostgresDump() ([]byte, bool) {
	data, ok := a.Files[filePostgres]
	return data, ok
}

// tarMember is one file to write into the archive.
type tarMember struct {
	name string
	data []byte
}

// writeTar packs members into an uncompressed tar with 0600 members.
func writeTar(members []tarMember, modTime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		hdr := &tar.Header{
			Name:    m.name,
			Mode:    0o600,
			Size:    int64(len(m.data)),
			ModTime: modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("writing tar header for %q: %w", m.name, err)
		}
		if _, err := tw.Write(m.data); err != nil {
			return nil, fmt.Errorf("writing tar member %q: %w", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("finalizing tar: %w", err)
	}
	return buf.Bytes(), nil
}

// marshalJSON is indented JSON with a trailing newline, matching the CLI backup.
func marshalJSON(v interface{}) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// publicKeyFingerprint returns the SSH SHA-256 fingerprint of a public key in
// authorized_keys form, matching the CA-backup/restore fingerprint anchor.
func publicKeyFingerprint(authorizedKey string) string {
	if authorizedKey == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "unknown"
	}
	return ssh.FingerprintSHA256(pub)
}
