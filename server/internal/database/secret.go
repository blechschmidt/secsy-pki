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
	context_bound, escrowed, current_version, expires_at, rotate_every_days,
	created_at, updated_at, value_changed_at`

// scanStoredSecret reads one stored_secrets row selected with storedSecretColumns.
func scanStoredSecret(s caScanner) (*models.StoredSecret, error) {
	var sec models.StoredSecret
	var expires, valueChanged sql.NullTime
	if err := s.Scan(&sec.ID, &sec.TenantID, &sec.Name, &sec.Envelope, &sec.KEKFamily,
		&sec.KEKLabel, &sec.KEKVersion, &sec.ContextBound, &sec.Escrowed,
		&sec.CurrentVersion, &expires, &sec.RotateEveryDays,
		&sec.CreatedAt, &sec.UpdatedAt, &valueChanged); err != nil {
		return nil, err
	}
	if expires.Valid {
		t := expires.Time
		sec.ExpiresAt = &t
	}
	if valueChanged.Valid {
		sec.ValueChangedAt = valueChanged.Time
	} else {
		sec.ValueChangedAt = sec.UpdatedAt
	}
	return &sec, nil
}

// CreateStoredSecret inserts a stored secret together with its version-1
// history row, atomically. A duplicate name within the tenant fails on the
// UNIQUE constraint. createdBy/comment annotate the initial version.
func (db *DB) CreateStoredSecret(s *models.StoredSecret, createdBy, comment string) error {
	now := s.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
		s.CreatedAt = now
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = now
	}
	if s.ValueChangedAt.IsZero() {
		s.ValueChangedAt = s.UpdatedAt
	}
	if s.TenantID == "" {
		s.TenantID = models.DefaultTenantID
	}
	s.CurrentVersion = 1

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(db.ph(
		`INSERT INTO stored_secrets (id, tenant_id, name, envelope, kek_family, kek_label, kek_version,
			context_bound, escrowed, current_version, expires_at, rotate_every_days,
			created_at, updated_at, value_changed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.ID, s.TenantID, s.Name, s.Envelope, s.KEKFamily, s.KEKLabel, s.KEKVersion,
		s.ContextBound, s.Escrowed, s.CurrentVersion, nullableTime(s.ExpiresAt), s.RotateEveryDays,
		s.CreatedAt, s.UpdatedAt, s.ValueChangedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(db.ph(
		`INSERT INTO stored_secret_versions (secret_id, version, envelope, kek_family, kek_label,
			kek_version, context_bound, escrowed, created_by, comment, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.ID, 1, s.Envelope, s.KEKFamily, s.KEKLabel, s.KEKVersion,
		s.ContextBound, s.Escrowed, createdBy, comment, s.ValueChangedAt); err != nil {
		return err
	}
	return tx.Commit()
}

// nullableTime maps an optional time to its SQL value.
func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

// ErrSecretVersionConflict reports that a put lost the optimistic version
// check to a concurrent writer; the caller re-reads and retries.
var ErrSecretVersionConflict = fmt.Errorf("database: stored secret was modified concurrently")

// PutSecretVersion carries one value update for PutStoredSecretVersion. The
// KEK fields describe the wrap of the NEW envelope (the family's active KEK at
// seal time). ExpectVersion is the current_version the caller read; the put
// applies only if the row still carries it.
type PutSecretVersion struct {
	ID           string
	Envelope     string
	KEKFamily    string
	KEKLabel     string
	KEKVersion   int
	ContextBound bool
	Escrowed     bool
	CreatedBy    string
	Comment      string
	// ExpectVersion is the optimistic-concurrency guard (the version the caller
	// last read); the new value becomes ExpectVersion+1.
	ExpectVersion int
	// SetExpiresAt/SetRotateEveryDays make the schedule fields explicit
	// tri-state: false keeps the stored value, true overwrites it (ExpiresAt
	// nil with SetExpiresAt=true clears the TTL).
	SetExpiresAt       bool
	ExpiresAt          *time.Time
	SetRotateEveryDays bool
	RotateEveryDays    int
}

// PutStoredSecretVersion appends a new value version to a stored secret: the
// registry row is advanced to the new envelope/version and the version-history
// row is inserted, atomically. Returns ErrSecretVersionConflict when the row's
// current_version no longer matches ExpectVersion (a concurrent put won).
func (db *DB) PutStoredSecretVersion(p *PutSecretVersion) (*models.StoredSecret, error) {
	if p == nil || p.ID == "" || p.Envelope == "" || p.ExpectVersion < 1 {
		return nil, fmt.Errorf("database: invalid stored-secret put")
	}
	now := time.Now().UTC()
	newVersion := p.ExpectVersion + 1

	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Schedule fields: resolve the final values inside the transaction so a
	// put that does not touch them keeps whatever is stored.
	var curExpires sql.NullTime
	var curRotate int
	if err := tx.QueryRow(db.ph(
		`SELECT expires_at, rotate_every_days FROM stored_secrets WHERE id = ?`), p.ID).
		Scan(&curExpires, &curRotate); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("database: no such stored secret %q", p.ID)
		}
		return nil, err
	}
	var expires interface{}
	if curExpires.Valid {
		expires = curExpires.Time
	}
	if p.SetExpiresAt {
		expires = nullableTime(p.ExpiresAt)
	}
	rotate := curRotate
	if p.SetRotateEveryDays {
		rotate = p.RotateEveryDays
	}

	res, err := tx.Exec(db.ph(
		`UPDATE stored_secrets SET envelope = ?, kek_family = ?, kek_label = ?, kek_version = ?,
			context_bound = ?, escrowed = ?, current_version = ?, expires_at = ?, rotate_every_days = ?,
			updated_at = ?, value_changed_at = ?
		 WHERE id = ? AND current_version = ?`),
		p.Envelope, p.KEKFamily, p.KEKLabel, p.KEKVersion,
		p.ContextBound, p.Escrowed, newVersion, expires, rotate,
		now, now, p.ID, p.ExpectVersion)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, ErrSecretVersionConflict
	}
	if _, err := tx.Exec(db.ph(
		`INSERT INTO stored_secret_versions (secret_id, version, envelope, kek_family, kek_label,
			kek_version, context_bound, escrowed, created_by, comment, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		p.ID, newVersion, p.Envelope, p.KEKFamily, p.KEKLabel, p.KEKVersion,
		p.ContextBound, p.Escrowed, p.CreatedBy, p.Comment, now); err != nil {
		return nil, err
	}
	updated, err := scanStoredSecret(tx.QueryRow(db.ph(
		`SELECT ` + storedSecretColumns + ` FROM stored_secrets WHERE id = ?`), p.ID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
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

// storedSecretMetaColumns selects everything except the envelope, for list
// views.
const storedSecretMetaColumns = `id, tenant_id, name, kek_family, kek_label, kek_version,
	context_bound, escrowed, current_version, expires_at, rotate_every_days,
	created_at, updated_at, value_changed_at`

// scanStoredSecretMeta reads one row selected with storedSecretMetaColumns.
func scanStoredSecretMeta(s caScanner) (*models.StoredSecret, error) {
	var sec models.StoredSecret
	var expires, valueChanged sql.NullTime
	if err := s.Scan(&sec.ID, &sec.TenantID, &sec.Name, &sec.KEKFamily, &sec.KEKLabel, &sec.KEKVersion,
		&sec.ContextBound, &sec.Escrowed, &sec.CurrentVersion, &expires, &sec.RotateEveryDays,
		&sec.CreatedAt, &sec.UpdatedAt, &valueChanged); err != nil {
		return nil, err
	}
	if expires.Valid {
		t := expires.Time
		sec.ExpiresAt = &t
	}
	if valueChanged.Valid {
		sec.ValueChangedAt = valueChanged.Time
	} else {
		sec.ValueChangedAt = sec.UpdatedAt
	}
	return &sec, nil
}

// ListStoredSecrets returns a tenant's stored secrets ordered by name, without
// their envelopes (metadata only; fetch an envelope with GetStoredSecret).
func (db *DB) ListStoredSecrets(tenantID string) ([]models.StoredSecret, error) {
	rows, err := db.query(
		`SELECT `+storedSecretMetaColumns+` FROM stored_secrets WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.StoredSecret
	for rows.Next() {
		s, err := scanStoredSecretMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ListStoredSecretsWithSchedule returns, across ALL tenants, the metadata of
// every stored secret that has a TTL or a rotation-reminder period — the
// lifecycle monitor's scan set.
func (db *DB) ListStoredSecretsWithSchedule() ([]models.StoredSecret, error) {
	rows, err := db.query(
		`SELECT ` + storedSecretMetaColumns + ` FROM stored_secrets
		 WHERE expires_at IS NOT NULL OR rotate_every_days > 0
		 ORDER BY tenant_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.StoredSecret
	for rows.Next() {
		s, err := scanStoredSecretMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

const secretVersionMetaColumns = `secret_id, version, kek_family, kek_label, kek_version,
	context_bound, escrowed, created_by, comment, created_at`

// ListStoredSecretVersions returns a secret's value history, newest first,
// without envelopes.
func (db *DB) ListStoredSecretVersions(secretID string) ([]models.StoredSecretVersion, error) {
	rows, err := db.query(
		`SELECT `+secretVersionMetaColumns+` FROM stored_secret_versions
		 WHERE secret_id = ? ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.StoredSecretVersion
	for rows.Next() {
		var v models.StoredSecretVersion
		if err := rows.Scan(&v.SecretID, &v.Version, &v.KEKFamily, &v.KEKLabel, &v.KEKVersion,
			&v.ContextBound, &v.Escrowed, &v.CreatedBy, &v.Comment, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetStoredSecretVersion resolves one history entry including its envelope.
// Returns (nil, nil) when the secret has no such version.
func (db *DB) GetStoredSecretVersion(secretID string, version int) (*models.StoredSecretVersion, error) {
	var v models.StoredSecretVersion
	err := db.queryRow(
		`SELECT secret_id, version, envelope, kek_family, kek_label, kek_version,
			context_bound, escrowed, created_by, comment, created_at
		 FROM stored_secret_versions WHERE secret_id = ? AND version = ?`, secretID, version).
		Scan(&v.SecretID, &v.Version, &v.Envelope, &v.KEKFamily, &v.KEKLabel, &v.KEKVersion,
			&v.ContextBound, &v.Escrowed, &v.CreatedBy, &v.Comment, &v.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
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
// bookkeeping after a re-wrap, mirroring the change into the current
// version-history row so the (secret_id, current_version) entry always equals
// the registry envelope. The update is optimistic: it applies only while the
// row still carries the expected KEK label, so a re-wrap racing another writer
// (a concurrent re-wrap or a put) never clobbers newer ciphertext. It reports
// whether the row was updated. value_changed_at is deliberately untouched —
// a re-wrap changes the wrapping, not the value, so rotation reminders keep
// their reference point.
func (db *DB) UpdateStoredSecretEnvelope(id, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(db.ph(
		`UPDATE stored_secrets SET envelope = ?, kek_label = ?, kek_version = ?, updated_at = ?
		 WHERE id = ? AND kek_label = ?`),
		envelope, kekLabel, kekVersion, time.Now().UTC(), id, expectKEKLabel)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE stored_secret_versions SET envelope = ?, kek_label = ?, kek_version = ?
		 WHERE secret_id = ? AND version = (SELECT current_version FROM stored_secrets WHERE id = ?)`),
		envelope, kekLabel, kekVersion, id, id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ListStoredSecretVersionRefsForRewrap returns the (secret_id, version) pairs
// of HISTORICAL version envelopes in a KEK family not wrapped under the given
// (active) label — the second half of a fleet-wide re-wrap. Current-version
// rows are excluded: they are migrated through UpdateStoredSecretEnvelope
// alongside their registry row.
func (db *DB) ListStoredSecretVersionRefsForRewrap(family, activeLabel string) ([]models.SecretVersionRef, error) {
	rows, err := db.query(
		`SELECT v.secret_id, v.version FROM stored_secret_versions v
		 WHERE v.kek_family = ? AND v.kek_label <> ?
		   AND v.version <> (SELECT s.current_version FROM stored_secrets s WHERE s.id = v.secret_id)
		 ORDER BY v.secret_id, v.version`,
		family, activeLabel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SecretVersionRef
	for rows.Next() {
		var ref models.SecretVersionRef
		if err := rows.Scan(&ref.SecretID, &ref.Version); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// UpdateStoredSecretVersionEnvelope replaces one history entry's envelope and
// wrap bookkeeping after a re-wrap, optimistically guarded on the expected KEK
// label like the registry variant. It reports whether the row was updated.
func (db *DB) UpdateStoredSecretVersionEnvelope(secretID string, version int, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error) {
	res, err := db.exec(
		`UPDATE stored_secret_versions SET envelope = ?, kek_label = ?, kek_version = ?
		 WHERE secret_id = ? AND version = ? AND kek_label = ?`,
		envelope, kekLabel, kekVersion, secretID, version, expectKEKLabel)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteStoredSecret removes a stored secret together with its value history
// and reports whether it existed.
func (db *DB) DeleteStoredSecret(id string) (bool, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(db.ph(`DELETE FROM stored_secret_versions WHERE secret_id = ?`), id); err != nil {
		return false, err
	}
	res, err := tx.Exec(db.ph(`DELETE FROM stored_secrets WHERE id = ?`), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, tx.Commit()
}

// CountStoredSecretsOnKEK returns how many stored ENVELOPES — current
// registry rows plus historical version entries — are wrapped under one
// specific KEK label. This is the fail-closed guard consulted before a KEK
// version is retired: a historical version still on the label would become
// undecryptable (breaking get-by-version and rollback), so it blocks
// retirement exactly like a current envelope. Current-version history rows
// mirror their registry row and are excluded to avoid double counting.
func (db *DB) CountStoredSecretsOnKEK(label string) (int64, error) {
	var n int64
	err := db.queryRow(
		`SELECT (SELECT COUNT(*) FROM stored_secrets WHERE kek_label = ?)
			+ (SELECT COUNT(*) FROM stored_secret_versions v
				WHERE v.kek_label = ?
				  AND v.version <> (SELECT s.current_version FROM stored_secrets s WHERE s.id = v.secret_id))`,
		label, label).Scan(&n)
	return n, err
}

// CountStoredSecretsByKEKLabel returns, per KEK label, how many of a family's
// envelopes (current + historical versions, without double counting the
// mirrored current row) are wrapped under it. Feeds the KEK status report and
// the secrets-on-old-KEK gauge, so "on old KEK" reflects everything a re-wrap
// must drain before the version can retire.
func (db *DB) CountStoredSecretsByKEKLabel(family string) (map[string]int64, error) {
	out := make(map[string]int64)
	collect := func(query string) error {
		rows, err := db.query(query, family)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var label string
			var n int64
			if err := rows.Scan(&label, &n); err != nil {
				return err
			}
			out[label] += n
		}
		return rows.Err()
	}
	if err := collect(
		`SELECT kek_label, COUNT(*) FROM stored_secrets WHERE kek_family = ? GROUP BY kek_label`); err != nil {
		return nil, err
	}
	if err := collect(
		`SELECT v.kek_label, COUNT(*) FROM stored_secret_versions v
		 WHERE v.kek_family = ?
		   AND v.version <> (SELECT s.current_version FROM stored_secrets s WHERE s.id = v.secret_id)
		 GROUP BY v.kek_label`); err != nil {
		return nil, err
	}
	return out, nil
}
