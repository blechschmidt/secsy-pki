package database

// Persistence for the post-quantum hybrid ML-KEM key material (Task 137): the
// pqc_hybrid_keys table, one active row per KEK family. The row never contains a
// plaintext ML-KEM private key — only the public encapsulation key and the
// decapsulation-key seed SEALED under the family's classical HSM KEK. The two
// binary columns are base64-encoded TEXT for cross-database portability.

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const pqcHybridKeyColumns = `family, key_id, alg, encap_key, sealed_decap_key, seal_alg, sealed_under_version, status, created_at, updated_at`

// scanPQCHybridKey reads one pqc_hybrid_keys row selected with
// pqcHybridKeyColumns, base64-decoding the binary fields.
func scanPQCHybridKey(s caScanner) (*models.PQCHybridKey, error) {
	var k models.PQCHybridKey
	var encapB64, sealedB64 string
	if err := s.Scan(&k.Family, &k.KeyID, &k.Alg, &encapB64, &sealedB64, &k.SealAlg,
		&k.SealedUnderVersion, &k.Status, &k.CreatedAt, &k.UpdatedAt); err != nil {
		return nil, err
	}
	encap, err := base64.StdEncoding.DecodeString(encapB64)
	if err != nil {
		return nil, fmt.Errorf("decoding PQC encapsulation key for family %q: %w", k.Family, err)
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, fmt.Errorf("decoding PQC sealed decapsulation key for family %q: %w", k.Family, err)
	}
	k.EncapKey = encap
	k.SealedDecapKey = sealed
	return &k, nil
}

// GetPQCHybridKey returns the family's active ML-KEM hybrid key material, or nil
// (no error) when the family has none provisioned.
func (db *DB) GetPQCHybridKey(family string) (*models.PQCHybridKey, error) {
	row := db.queryRow(`SELECT `+pqcHybridKeyColumns+` FROM pqc_hybrid_keys WHERE family = ?`, family)
	k, err := scanPQCHybridKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// PutPQCHybridKey inserts or replaces a family's ML-KEM hybrid key material.
// There is at most one row per family; re-provisioning overwrites it (and
// therefore invalidates any envelopes sealed under the previous key, so callers
// must guard against clobbering in-use material). created_at is preserved across
// an update.
func (db *DB) PutPQCHybridKey(k *models.PQCHybridKey) error {
	if k.Family == "" || k.KeyID == "" || k.Alg == "" {
		return fmt.Errorf("PutPQCHybridKey: family, key_id and alg are required")
	}
	now := time.Now().UTC()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	k.UpdatedAt = now
	if k.Status == "" {
		k.Status = models.PQCKeyStatusActive
	}
	encapB64 := base64.StdEncoding.EncodeToString(k.EncapKey)
	sealedB64 := base64.StdEncoding.EncodeToString(k.SealedDecapKey)
	_, err := db.exec(db.ph(
		`INSERT INTO pqc_hybrid_keys (`+pqcHybridKeyColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (family) DO UPDATE SET
			key_id = excluded.key_id,
			alg = excluded.alg,
			encap_key = excluded.encap_key,
			sealed_decap_key = excluded.sealed_decap_key,
			seal_alg = excluded.seal_alg,
			sealed_under_version = excluded.sealed_under_version,
			status = excluded.status,
			updated_at = excluded.updated_at`),
		k.Family, k.KeyID, k.Alg, encapB64, sealedB64, k.SealAlg,
		k.SealedUnderVersion, k.Status, k.CreatedAt, k.UpdatedAt)
	return err
}

// UpdatePQCSealedKey re-seals a family's ML-KEM decapsulation key under a new
// classical KEK version, rewriting only the sealed material (the public
// encapsulation key and key_id are unchanged, so existing envelopes still
// decapsulate). It returns false if the family has no PQC material.
func (db *DB) UpdatePQCSealedKey(family string, sealedDecapKey []byte, sealAlg string, sealedUnderVersion int) (bool, error) {
	sealedB64 := base64.StdEncoding.EncodeToString(sealedDecapKey)
	res, err := db.exec(db.ph(
		`UPDATE pqc_hybrid_keys SET sealed_decap_key = ?, seal_alg = ?, sealed_under_version = ?, updated_at = ?
		 WHERE family = ?`),
		sealedB64, sealAlg, sealedUnderVersion, time.Now().UTC(), family)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
