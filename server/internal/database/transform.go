package database

// Persistence for the format-preserving-encryption / tokenization seed (Task
// 144): the fpe_seeds table, at most one row per KEK family. The row never
// contains plaintext key material — envelope is a sealed secret.Envelope over a
// random seed, useless without the family's HSM-held KEK. A per-template FF1 key
// is HKDF-derived from the seed at request time. The seed does not rotate (its
// derived keys must stay stable so previously issued, un-versioned tokens keep
// decoding); only sealed_under_version advances when the seed is re-sealed onto a
// newer classical KEK version during KEK rotation.

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const fpeSeedColumns = `family, envelope, sealed_under_version, created_at, updated_at`

// scanFPESeed reads one fpe_seeds row selected with fpeSeedColumns.
func scanFPESeed(s caScanner) (*models.FPESeed, error) {
	var k models.FPESeed
	if err := s.Scan(&k.Family, &k.Envelope, &k.SealedUnderVersion, &k.CreatedAt, &k.UpdatedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

// GetFPESeed returns the family's FPE seed, or nil (no error) when the family has
// none provisioned yet.
func (db *DB) GetFPESeed(family string) (*models.FPESeed, error) {
	row := db.queryRow(db.ph(`SELECT `+fpeSeedColumns+` FROM fpe_seeds WHERE family = ?`), family)
	k, err := scanFPESeed(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// InsertFPESeed inserts a family's FPE seed. The family primary key makes a
// concurrent duplicate insert fail rather than clobber, so the lazy provisioning
// path can detect a race and re-read the winner's row. created_at/updated_at
// default to now when unset.
func (db *DB) InsertFPESeed(k *models.FPESeed) error {
	if k.Family == "" || k.Envelope == "" {
		return fmt.Errorf("InsertFPESeed: family and envelope are required")
	}
	now := time.Now().UTC()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	if k.UpdatedAt.IsZero() {
		k.UpdatedAt = now
	}
	if k.SealedUnderVersion <= 0 {
		k.SealedUnderVersion = 1
	}
	_, err := db.exec(db.ph(
		`INSERT INTO fpe_seeds (`+fpeSeedColumns+`) VALUES (?, ?, ?, ?, ?)`),
		k.Family, k.Envelope, k.SealedUnderVersion, k.CreatedAt, k.UpdatedAt)
	return err
}

// UpdateFPESeedEnvelope re-seals a family's FPE seed under a new classical KEK
// version, rewriting only the sealed envelope and its sealing version (the seed
// bytes — and therefore every derived FF1 key — are unchanged, so existing
// tokens still decode). It returns false if the family has no FPE seed.
func (db *DB) UpdateFPESeedEnvelope(family, envelope string, sealedUnderVersion int) (bool, error) {
	res, err := db.exec(db.ph(
		`UPDATE fpe_seeds SET envelope = ?, sealed_under_version = ?, updated_at = ? WHERE family = ?`),
		envelope, sealedUnderVersion, time.Now().UTC(), family)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountFPESeedsOnKEK returns how many FPE seeds are currently sealed under a
// specific classical KEK version, so the retire guard can refuse to withdraw a
// version whose retirement would strand a tokenization seed.
func (db *DB) CountFPESeedsOnKEK(family string, version int) (int64, error) {
	var n int64
	err := db.queryRow(db.ph(
		`SELECT COUNT(*) FROM fpe_seeds WHERE family = ? AND sealed_under_version = ?`),
		family, version).Scan(&n)
	return n, err
}
