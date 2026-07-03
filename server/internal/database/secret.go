package database

// Persistence for the secret-layer KEK rotation feature (Task 63): the
// kek_versions rotation lineage and the stored_secrets registry of server-held
// envelopes. Neither table ever contains key material or plaintext — a KEK row
// is only bookkeeping about an HSM-resident key, and a stored secret is the
// same opaque envelope /api/secret/encrypt returns.

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const kekVersionColumns = `family, version, label, status, created_at, rotated_at, retired_at`

// scanKEKVersion reads one kek_versions row selected with kekVersionColumns.
func scanKEKVersion(s caScanner) (*models.KEKVersion, error) {
	var v models.KEKVersion
	var rotated, retired sql.NullTime
	if err := s.Scan(&v.Family, &v.Version, &v.Label, &v.Status, &v.CreatedAt, &rotated, &retired); err != nil {
		return nil, err
	}
	if rotated.Valid {
		t := rotated.Time
		v.RotatedAt = &t
	}
	if retired.Valid {
		t := retired.Time
		v.RetiredAt = &t
	}
	return &v, nil
}

// ListKEKVersions returns a family's rotation lineage ordered by version. An
// empty result means the family has never been rotated (its base key, if any,
// is implicitly version 1 and active).
func (db *DB) ListKEKVersions(family string) ([]models.KEKVersion, error) {
	rows, err := db.query(`SELECT `+kekVersionColumns+` FROM kek_versions WHERE family = ? ORDER BY version`, family)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.KEKVersion
	for rows.Next() {
		v, err := scanKEKVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// ListKEKFamilies returns every KEK family known to the store: families with a
// rotation lineage plus families referenced by stored secrets (covering
// secrets sealed before their family was ever rotated). Used by the monitor to
// refresh the per-family rotation gauges.
func (db *DB) ListKEKFamilies() ([]string, error) {
	rows, err := db.query(
		`SELECT family FROM kek_versions UNION SELECT kek_family FROM stored_secrets ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RotateKEKVersion records a completed KEK rotation atomically: every version
// of the family still marked active becomes retiring (opening the dual-KEK
// decrypt window), and the freshly generated version is inserted as the new
// active one. When the family had no rows at all — a deployment whose base KEK
// predates rotation support — the implicit version 1 (label = family name) is
// backfilled first so the lineage is complete. The (family, version) primary
// key makes two concurrent rotations of the same family collide on insert
// rather than both succeeding.
func (db *DB) RotateKEKVersion(newVersion *models.KEKVersion) error {
	if newVersion == nil || newVersion.Family == "" || newVersion.Label == "" || newVersion.Version < 1 {
		return fmt.Errorf("database: invalid KEK version record")
	}
	now := newVersion.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Backfill the implicit version 1 when this is the family's first recorded
	// rotation, so the superseded key keeps a row describing its status.
	var n int
	if err := tx.QueryRow(db.ph(`SELECT COUNT(*) FROM kek_versions WHERE family = ?`), newVersion.Family).Scan(&n); err != nil {
		return err
	}
	if n == 0 && newVersion.Version > 1 {
		if _, err := tx.Exec(db.ph(
			`INSERT INTO kek_versions (family, version, label, status, created_at) VALUES (?, ?, ?, ?, ?)`),
			newVersion.Family, 1, newVersion.Family, models.KEKStatusActive, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE kek_versions SET status = ?, rotated_at = ? WHERE family = ? AND status = ?`),
		models.KEKStatusRetiring, now, newVersion.Family, models.KEKStatusActive); err != nil {
		return err
	}
	if _, err := tx.Exec(db.ph(
		`INSERT INTO kek_versions (family, version, label, status, created_at) VALUES (?, ?, ?, ?, ?)`),
		newVersion.Family, newVersion.Version, newVersion.Label, models.KEKStatusActive, now); err != nil {
		return err
	}
	return tx.Commit()
}

// SetKEKVersionStatus moves one version of a family to a new lifecycle status,
// stamping retired_at when the target status is retired (and clearing it when
// a retired version is deliberately reinstated to retiring). It reports
// whether a row was updated.
func (db *DB) SetKEKVersionStatus(family string, version int, status string) (bool, error) {
	var retired interface{}
	if status == models.KEKStatusRetired {
		retired = time.Now().UTC()
	}
	res, err := db.exec(
		`UPDATE kek_versions SET status = ?, retired_at = ? WHERE family = ? AND version = ?`,
		status, retired, family, version)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

const storedSecretColumns = `id, tenant_id, name, envelope, kek_family, kek_label, kek_version,
	context_bound, escrowed, created_at, updated_at`

// scanStoredSecret reads one stored_secrets row selected with storedSecretColumns.
func scanStoredSecret(s caScanner) (*models.StoredSecret, error) {
	var sec models.StoredSecret
	if err := s.Scan(&sec.ID, &sec.TenantID, &sec.Name, &sec.Envelope, &sec.KEKFamily,
		&sec.KEKLabel, &sec.KEKVersion, &sec.ContextBound, &sec.Escrowed,
		&sec.CreatedAt, &sec.UpdatedAt); err != nil {
		return nil, err
	}
	return &sec, nil
}

// CreateStoredSecret inserts a stored secret. A duplicate name within the
// tenant fails on the UNIQUE constraint.
func (db *DB) CreateStoredSecret(s *models.StoredSecret) error {
	now := s.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
		s.CreatedAt = now
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = now
	}
	tenant := s.TenantID
	if tenant == "" {
		tenant = models.DefaultTenantID
	}
	_, err := db.exec(
		`INSERT INTO stored_secrets (id, tenant_id, name, envelope, kek_family, kek_label, kek_version,
			context_bound, escrowed, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, tenant, s.Name, s.Envelope, s.KEKFamily, s.KEKLabel, s.KEKVersion,
		s.ContextBound, s.Escrowed, s.CreatedAt, s.UpdatedAt)
	return err
}

// GetStoredSecret resolves a stored secret by ID. Returns (nil, nil) when none
// matches.
func (db *DB) GetStoredSecret(id string) (*models.StoredSecret, error) {
	s, err := scanStoredSecret(db.queryRow(
		`SELECT `+storedSecretColumns+` FROM stored_secrets WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

// GetStoredSecretByName resolves a stored secret by its tenant-scoped name.
// Returns (nil, nil) when none matches.
func (db *DB) GetStoredSecretByName(tenantID, name string) (*models.StoredSecret, error) {
	s, err := scanStoredSecret(db.queryRow(
		`SELECT `+storedSecretColumns+` FROM stored_secrets WHERE tenant_id = ? AND name = ?`, tenantID, name))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

// ListStoredSecrets returns a tenant's stored secrets ordered by name, without
// their envelopes (metadata only; fetch an envelope with GetStoredSecret).
func (db *DB) ListStoredSecrets(tenantID string) ([]models.StoredSecret, error) {
	rows, err := db.query(
		`SELECT id, tenant_id, name, kek_family, kek_label, kek_version, context_bound, escrowed,
			created_at, updated_at
		 FROM stored_secrets WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.StoredSecret
	for rows.Next() {
		var s models.StoredSecret
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.KEKFamily, &s.KEKLabel, &s.KEKVersion,
			&s.ContextBound, &s.Escrowed, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListStoredSecretIDsForRewrap returns the IDs of every stored secret in a KEK
// family whose envelope is NOT wrapped under the given (active) label — the
// work list for a fleet-wide re-wrap. Ordered by ID for a stable batch order.
func (db *DB) ListStoredSecretIDsForRewrap(family, activeLabel string) ([]string, error) {
	rows, err := db.query(
		`SELECT id FROM stored_secrets WHERE kek_family = ? AND kek_label <> ? ORDER BY id`,
		family, activeLabel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// UpdateStoredSecretEnvelope replaces a stored secret's envelope and wrap
// bookkeeping after a re-wrap. The update is optimistic: it applies only while
// the row still carries the expected KEK label, so a re-wrap racing another
// writer (a concurrent re-wrap or a re-encrypt) never clobbers newer
// ciphertext. It reports whether the row was updated.
func (db *DB) UpdateStoredSecretEnvelope(id, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error) {
	res, err := db.exec(
		`UPDATE stored_secrets SET envelope = ?, kek_label = ?, kek_version = ?, updated_at = ?
		 WHERE id = ? AND kek_label = ?`,
		envelope, kekLabel, kekVersion, time.Now().UTC(), id, expectKEKLabel)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteStoredSecret removes a stored secret and reports whether it existed.
func (db *DB) DeleteStoredSecret(id string) (bool, error) {
	res, err := db.exec(`DELETE FROM stored_secrets WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CountStoredSecretsOnKEK returns how many stored secrets are wrapped under
// one specific KEK label — the fail-closed guard consulted before a KEK
// version is retired.
func (db *DB) CountStoredSecretsOnKEK(label string) (int64, error) {
	var n int64
	err := db.queryRow(`SELECT COUNT(*) FROM stored_secrets WHERE kek_label = ?`, label).Scan(&n)
	return n, err
}

// CountStoredSecretsByKEKLabel returns, per KEK label, how many of a family's
// stored secrets are wrapped under it. Feeds the KEK status report and the
// secrets-on-old-KEK gauge.
func (db *DB) CountStoredSecretsByKEKLabel(family string) (map[string]int64, error) {
	rows, err := db.query(
		`SELECT kek_label, COUNT(*) FROM stored_secrets WHERE kek_family = ? GROUP BY kek_label`, family)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var label string
		var n int64
		if err := rows.Scan(&label, &n); err != nil {
			return nil, err
		}
		out[label] = n
	}
	return out, rows.Err()
}
