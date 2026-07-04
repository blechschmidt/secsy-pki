package database

import (
	"database/sql"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Operator-managed compromised-key blocklist (Task 120).
//
// One row per public key the CA must never certify again, keyed by its
// SubjectPublicKeyInfo SHA-256 fingerprint ("SHA256:<base64>"). The table holds no
// key material — only the fingerprint and the operator's justification — so it is
// safe to replicate and export. It is deployment-global (a compromised key is
// compromised for every tenant), so there is no tenant scope. added_at is written
// explicitly in UTC (never a column DEFAULT), matching the api_tokens/webhook
// stores so ordering round-trips identically across SQLite and PostgreSQL.

const blockedKeyColumns = `fingerprint, reason, source, added_by, added_at`

// AddBlockedKey inserts a blocklist entry, reporting whether it was newly added
// (false when the fingerprint was already blocked). The insert is conflict-
// tolerant so two operators blocking the same compromised key resolve to exactly
// one "newly added" outcome rather than a primary-key violation on PostgreSQL.
func (db *DB) AddBlockedKey(k *models.BlockedKey) (bool, error) {
	if k.AddedAt.IsZero() {
		k.AddedAt = time.Now().UTC()
	} else {
		k.AddedAt = k.AddedAt.UTC()
	}
	res, err := db.exec(db.insertOrIgnore("blocked_keys", blockedKeyColumns, "?, ?, ?, ?, ?"),
		k.Fingerprint, k.Reason, k.Source, k.AddedBy, k.AddedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetBlockedKey returns a blocklist entry by fingerprint, or (nil, nil) when the
// key is not blocked.
func (db *DB) GetBlockedKey(fingerprint string) (*models.BlockedKey, error) {
	k, err := scanBlockedKey(db.queryRow(
		`SELECT `+blockedKeyColumns+` FROM blocked_keys WHERE fingerprint = ?`, fingerprint))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// IsKeyBlocked is the O(1) hot-path lookup used by the pre-issuance gate: it
// reports whether a fingerprint is present without materializing the row. An
// empty fingerprint is never blocked.
func (db *DB) IsKeyBlocked(fingerprint string) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}
	var one int
	err := db.queryRow(`SELECT 1 FROM blocked_keys WHERE fingerprint = ?`, fingerprint).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListBlockedKeys returns every blocklist entry, newest first.
func (db *DB) ListBlockedKeys() ([]models.BlockedKey, error) {
	rows, err := db.query(`SELECT ` + blockedKeyColumns + ` FROM blocked_keys ORDER BY added_at DESC, fingerprint ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.BlockedKey
	for rows.Next() {
		k, err := scanBlockedKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// RemoveBlockedKey deletes a blocklist entry, reporting whether a row was removed
// (false when the fingerprint was not blocked). Un-blocking is a deliberate,
// audited operator action — e.g. a key mistakenly blocked, or one rotated out of
// service — so the caller can distinguish a no-op from a real removal.
func (db *DB) RemoveBlockedKey(fingerprint string) (bool, error) {
	res, err := db.exec(`DELETE FROM blocked_keys WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountBlockedKeys returns the number of blocklist entries, for the doctor check
// and metrics.
func (db *DB) CountBlockedKeys() (int, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM blocked_keys`).Scan(&n)
	return n, err
}

func scanBlockedKey(s scanner) (*models.BlockedKey, error) {
	var (
		k                       models.BlockedKey
		reason, source, addedBy sql.NullString
	)
	if err := s.Scan(&k.Fingerprint, &reason, &source, &addedBy, &k.AddedAt); err != nil {
		return nil, err
	}
	k.Reason = reason.String
	k.Source = source.String
	k.AddedBy = addedBy.String
	return &k, nil
}
