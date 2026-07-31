package database

// Persistence for the named HSM-backed asymmetric signing keys of the crypto
// service (Task 153): the signing_keys table, one row per named key. A row holds
// NO private key material — not even a KEK-sealed seed, unlike mac_keys: the
// private key lives non-extractable in the key provider (the HSM under PKCS#11)
// and is addressed only through key_ref. public_key_der is the exported SPKI, so
// verification and public-key export read straight from the row without the HSM.
// Keys are tenant-scoped and addressed by a tenant-unique name.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ErrSigningKeyExists is returned by InsertSigningKey when a key already exists
// with the same (tenant, name). It lets the crypto-service layer map a duplicate
// to a clean client error instead of a generic constraint failure.
var ErrSigningKeyExists = errors.New("signing key with this name already exists for the tenant")

const signingKeyColumns = `id, tenant_id, name, algorithm, key_type, key_ref, public_key_der, provider, created_by, created_at`

// scanSigningKey reads one signing_keys row selected with signingKeyColumns.
func scanSigningKey(s caScanner) (*models.SigningKey, error) {
	var k models.SigningKey
	if err := s.Scan(&k.ID, &k.TenantID, &k.Name, &k.Algorithm, &k.KeyType, &k.KeyRef,
		&k.PublicKeyDER, &k.Provider, &k.CreatedBy, &k.CreatedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

// InsertSigningKey persists a new signing-key row. It returns ErrSigningKeyExists
// when the (tenant, name) pair is already taken (the UNIQUE constraint), so a
// concurrent or repeated create fails cleanly rather than clobbering.
func (db *DB) InsertSigningKey(k *models.SigningKey) error {
	if k.ID == "" || k.TenantID == "" || k.Name == "" || k.Algorithm == "" || k.KeyRef == "" || k.PublicKeyDER == "" {
		return fmt.Errorf("InsertSigningKey: id, tenant_id, name, algorithm, key_ref and public_key_der are required")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	_, err := db.exec(db.ph(
		`INSERT INTO signing_keys (`+signingKeyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		k.ID, k.TenantID, k.Name, k.Algorithm, k.KeyType, k.KeyRef, k.PublicKeyDER, k.Provider, k.CreatedBy, k.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSigningKeyExists
		}
		return err
	}
	return nil
}

// GetSigningKey returns the tenant's signing key with the given name, or nil (no
// error) when the tenant has no such key.
func (db *DB) GetSigningKey(tenantID, name string) (*models.SigningKey, error) {
	row := db.queryRow(db.ph(
		`SELECT `+signingKeyColumns+` FROM signing_keys WHERE tenant_id = ? AND name = ?`), tenantID, name)
	k, err := scanSigningKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// GetSigningKeyByID returns the signing key with the given id, or nil (no error)
// when absent. It is the tenant-independent lookup used by administrative paths.
func (db *DB) GetSigningKeyByID(id string) (*models.SigningKey, error) {
	row := db.queryRow(db.ph(
		`SELECT `+signingKeyColumns+` FROM signing_keys WHERE id = ?`), id)
	k, err := scanSigningKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// ListSigningKeys returns a tenant's signing keys, newest first.
func (db *DB) ListSigningKeys(tenantID string) ([]*models.SigningKey, error) {
	rows, err := db.query(db.ph(
		`SELECT `+signingKeyColumns+` FROM signing_keys WHERE tenant_id = ? ORDER BY created_at DESC, name ASC`), tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*models.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteSigningKey removes a tenant's signing-key metadata row. It does NOT
// destroy the underlying provider/HSM key material (that is a deliberate,
// separately-audited operation); it only forgets the mapping. It reports whether
// a row was deleted.
func (db *DB) DeleteSigningKey(tenantID, name string) (bool, error) {
	res, err := db.exec(db.ph(
		`DELETE FROM signing_keys WHERE tenant_id = ? AND name = ?`), tenantID, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
