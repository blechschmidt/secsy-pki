package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/lib/pq"
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
	return db.nextLazyCounter("ca_scoped_crl_counters",
		[]string{"ca_id", "scope"}, []any{caID, scope})
}

// nextLazyCounter atomically allocates and returns the next value of a monotonic
// counter stored in table.next_number, keyed by keyCols=keyVals, creating the
// row on first use. Concurrent callers race on that first insert: a `SELECT ...
// FOR UPDATE` cannot lock a row that does not exist yet, so two transactions can
// both take the no-row branch and try to INSERT — the loser hits the primary-key
// unique constraint. This helper tolerates that by retrying: the losing
// transaction rolls back and, on the next attempt, finds the now-present row and
// takes the locked update path. On SQLite (pinned to one connection) the race
// cannot occur and the first attempt always wins.
func (db *DB) nextLazyCounter(table string, keyCols []string, keyVals []any) (int64, error) {
	where := make([]string, len(keyCols))
	for i, c := range keyCols {
		where[i] = c + " = ?"
	}
	whereClause := strings.Join(where, " AND ")
	selQ := "SELECT next_number FROM " + table + " WHERE " + whereClause
	updQ := "UPDATE " + table + " SET next_number = ? WHERE " + whereClause
	insCols := append(append([]string{}, keyCols...), "next_number")
	insPlace := strings.TrimSuffix(strings.Repeat("?, ", len(insCols)), ", ")
	insQ := "INSERT INTO " + table + " (" + strings.Join(insCols, ", ") + ") VALUES (" + insPlace + ")"

	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		next, err := db.tryNextCounter(selQ, updQ, insQ, keyVals)
		if err == errCounterConflict {
			continue // row was created concurrently; retry into the update path
		}
		return next, err
	}
	return 0, errors.New("counter " + table + ": exceeded retry attempts under contention")
}

// errCounterConflict signals that nextLazyCounter's INSERT lost the first-insert
// race and the operation should be retried.
var errCounterConflict = errors.New("counter row inserted concurrently")

func (db *DB) tryNextCounter(selQ, updQ, insQ string, keyVals []any) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var next int64
	err = tx.QueryRow(db.ph(selQ+db.forUpdate()), keyVals...).Scan(&next)
	switch {
	case err == sql.ErrNoRows:
		// First use: seed the row (allocating number 1, storing 2 as the next).
		args := append(append([]any{}, keyVals...), int64(2))
		if _, ierr := tx.Exec(db.ph(insQ), args...); ierr != nil {
			if isUniqueViolation(ierr) {
				return 0, errCounterConflict
			}
			return 0, ierr
		}
		if cerr := tx.Commit(); cerr != nil {
			if isUniqueViolation(cerr) {
				return 0, errCounterConflict
			}
			return 0, cerr
		}
		return 1, nil
	case err != nil:
		return 0, err
	default:
		updArgs := append([]any{next + 1}, keyVals...)
		if _, uerr := tx.Exec(db.ph(updQ), updArgs...); uerr != nil {
			return 0, uerr
		}
		if cerr := tx.Commit(); cerr != nil {
			return 0, cerr
		}
		return next, nil
	}
}

// isUniqueViolation reports whether err is a duplicate-key / unique-constraint
// violation from PostgreSQL (SQLSTATE 23505) or SQLite.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key value")
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

// ListPublishedCRLs returns the metadata of every persisted base/delta CRL
// across all CAs and scopes, without the DER payloads (the DER field is left
// nil to keep the scan light). It is the enumeration used by freshness
// diagnostics (`secsy-ca doctor`), which care about the update windows rather
// than the artifact bytes.
func (db *DB) ListPublishedCRLs() ([]PublishedCRL, error) {
	rows, err := db.query(
		`SELECT ca_id, scope, kind, crl_number, base_number, this_update, next_update, generated_at
		   FROM ca_published_crls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishedCRL
	for rows.Next() {
		var c PublishedCRL
		if err := rows.Scan(&c.CAID, &c.Scope, &c.Kind, &c.Number, &c.BaseNumber,
			&c.ThisUpdate, &c.NextUpdate, &c.GeneratedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
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
