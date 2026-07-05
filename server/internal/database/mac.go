package database

// Persistence for the keyed-HMAC MAC keys (Task 138): the mac_keys table, one or
// more versioned rows per KEK family. A row never contains plaintext key
// material — envelope is a sealed secret.Envelope over a random seed, useless
// without the family's HSM-held KEK. Multiple versions coexist so a MAC key can
// be rotated while previously issued tokens still verify; the active version
// (the highest-numbered active row) signs new tokens.

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const macKeyColumns = `family, version, envelope, status, created_at`

// scanMACKey reads one mac_keys row selected with macKeyColumns.
func scanMACKey(s caScanner) (*models.MACKey, error) {
	var k models.MACKey
	if err := s.Scan(&k.Family, &k.Version, &k.Envelope, &k.Status, &k.CreatedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

// GetActiveMACKey returns the family's active MAC key (the highest-numbered
// active version), or nil (no error) when the family has none provisioned yet.
func (db *DB) GetActiveMACKey(family string) (*models.MACKey, error) {
	row := db.queryRow(db.ph(
		`SELECT `+macKeyColumns+` FROM mac_keys
		 WHERE family = ? AND status = ?
		 ORDER BY version DESC LIMIT 1`), family, models.MACKeyStatusActive)
	k, err := scanMACKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// GetMACKeyVersion returns a specific MAC-key version for a family (active or
// retired, so an old token still verifies), or nil (no error) when absent.
func (db *DB) GetMACKeyVersion(family string, version int) (*models.MACKey, error) {
	row := db.queryRow(db.ph(
		`SELECT `+macKeyColumns+` FROM mac_keys WHERE family = ? AND version = ?`), family, version)
	k, err := scanMACKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// MaxMACKeyVersion returns the highest MAC-key version present for a family
// (across all statuses), or 0 when the family has none. It bounds the next
// version to allocate when provisioning or rotating.
func (db *DB) MaxMACKeyVersion(family string) (int, error) {
	var v sql.NullInt64
	err := db.queryRow(db.ph(`SELECT MAX(version) FROM mac_keys WHERE family = ?`), family).Scan(&v)
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// InsertMACKey inserts a new MAC-key version. The (family, version) primary key
// makes a concurrent duplicate insert fail rather than clobber, so the lazy
// provisioning path can detect a race and re-read the winner's row. created_at
// defaults to now and status to active when unset.
func (db *DB) InsertMACKey(k *models.MACKey) error {
	if k.Family == "" || k.Version <= 0 || k.Envelope == "" {
		return fmt.Errorf("InsertMACKey: family, positive version and envelope are required")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	if k.Status == "" {
		k.Status = models.MACKeyStatusActive
	}
	_, err := db.exec(db.ph(
		`INSERT INTO mac_keys (`+macKeyColumns+`) VALUES (?, ?, ?, ?, ?)`),
		k.Family, k.Version, k.Envelope, k.Status, k.CreatedAt)
	return err
}
