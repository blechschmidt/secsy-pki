package database

import (
	"database/sql"
	"time"
)

// PublishedCRL is a persisted base or delta CRL for a single (CA, scope) pair.
// Storing it keeps a base CRL and its delta CRLs a consistent, re-servable pair
// (the delta's Delta CRL Indicator references the stored base's CRLNumber).
type PublishedCRL struct {
	CAID string
	// Scope is the CRL scope: "full" for the unsharded CRL, or "partition:N" for
	// shard N.
	Scope string
	// Kind is "base" or "delta".
	Kind string
	// Number is this CRL's own CRLNumber.
	Number int64
	// BaseNumber is, for a delta CRL, the CRLNumber of the base it is relative to;
	// for a base CRL it equals Number.
	BaseNumber int64
	ThisUpdate time.Time
	NextUpdate time.Time
	// GeneratedAt is the wall-clock time the CRL was cut. A delta CRL covers
	// entries revoked strictly after its base CRL's GeneratedAt.
	GeneratedAt time.Time
	DER         []byte
}

// NextScopedCRLNumber atomically returns the next CRL number for a (CA, scope)
// pair and advances the counter. Used for partitioned CRL scopes; the unsharded
// scope uses NextCRLNumber. Base and delta CRLs for the same scope draw from this
// one sequence so their numbers stay strictly monotonic (RFC 5280 §5.2.3).
func (db *DB) NextScopedCRLNumber(caID, scope string) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var next int64
	err = tx.QueryRow(db.ph(`SELECT next_number FROM ca_scoped_crl_counters WHERE ca_id = ? AND scope = ?`+db.forUpdate()), caID, scope).Scan(&next)
	if err == sql.ErrNoRows {
		next = 1
		if _, err := tx.Exec(db.ph(
			`INSERT INTO ca_scoped_crl_counters (ca_id, scope, next_number) VALUES (?, ?, ?)`), caID, scope, next+1); err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return next, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE ca_scoped_crl_counters SET next_number = ? WHERE ca_id = ? AND scope = ?`), next+1, caID, scope); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// GetPublishedCRL returns the stored CRL for (CA, scope, kind), or nil if none
// has been published yet.
func (db *DB) GetPublishedCRL(caID, scope, kind string) (*PublishedCRL, error) {
	row := db.queryRow(
		`SELECT crl_number, base_number, this_update, next_update, generated_at, der
		   FROM ca_published_crls WHERE ca_id = ? AND scope = ? AND kind = ?`,
		caID, scope, kind)
	c := &PublishedCRL{CAID: caID, Scope: scope, Kind: kind}
	err := row.Scan(&c.Number, &c.BaseNumber, &c.ThisUpdate, &c.NextUpdate, &c.GeneratedAt, &c.DER)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// UpsertPublishedCRL stores (replacing any prior) the latest CRL for its
// (CA, scope, kind).
func (db *DB) UpsertPublishedCRL(c *PublishedCRL) error {
	if db.isPostgres() {
		_, err := db.exec(
			`INSERT INTO ca_published_crls
			   (ca_id, scope, kind, crl_number, base_number, this_update, next_update, generated_at, der)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (ca_id, scope, kind) DO UPDATE SET
			   crl_number = EXCLUDED.crl_number,
			   base_number = EXCLUDED.base_number,
			   this_update = EXCLUDED.this_update,
			   next_update = EXCLUDED.next_update,
			   generated_at = EXCLUDED.generated_at,
			   der = EXCLUDED.der`,
			c.CAID, c.Scope, c.Kind, c.Number, c.BaseNumber, c.ThisUpdate, c.NextUpdate, c.GeneratedAt, c.DER)
		return err
	}
	_, err := db.exec(
		`INSERT OR REPLACE INTO ca_published_crls
		   (ca_id, scope, kind, crl_number, base_number, this_update, next_update, generated_at, der)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CAID, c.Scope, c.Kind, c.Number, c.BaseNumber, c.ThisUpdate, c.NextUpdate, c.GeneratedAt, c.DER)
	return err
}
