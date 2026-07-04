package database

import (
	"database/sql"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// sctInclusionColumns is the canonical column list for sct_inclusion reads. Keep
// it in sync with scanSCTInclusion.
const sctInclusionColumns = `ca_id, serial, log_id, log_name, sct_timestamp, status,
	tree_size, leaf_index, checks, last_error, first_checked_at, last_checked_at,
	included_at, alerted`

// scanSCTInclusion reads one sct_inclusion row selected with sctInclusionColumns.
func scanSCTInclusion(s caScanner) (*models.SCTInclusion, error) {
	var r models.SCTInclusion
	var firstChecked, lastChecked, includedAt sql.NullTime
	if err := s.Scan(
		&r.CAID, &r.Serial, &r.LogID, &r.LogName, &r.SCTTimestamp, &r.Status,
		&r.TreeSize, &r.LeafIndex, &r.Checks, &r.LastError, &firstChecked, &lastChecked,
		&includedAt, &r.Alerted,
	); err != nil {
		return nil, err
	}
	if firstChecked.Valid {
		t := firstChecked.Time
		r.FirstCheckedAt = &t
	}
	if lastChecked.Valid {
		t := lastChecked.Time
		r.LastCheckedAt = &t
	}
	if includedAt.Valid {
		t := includedAt.Time
		r.IncludedAt = &t
	}
	return &r, nil
}

// UpsertSCTInclusion inserts or updates the inclusion-verification state of one
// embedded SCT, keyed by (ca_id, serial, log_id). The immutable identity columns
// (ca_id, serial, log_id, sct_timestamp) and first_checked_at are preserved on
// update; the mutable verification state is overwritten. The inclusion monitor
// calls it after each check.
func (db *DB) UpsertSCTInclusion(r *models.SCTInclusion) error {
	if r.Status == "" {
		r.Status = models.SCTInclusionPending
	}
	_, err := db.exec(db.upsert(
		"sct_inclusion",
		`ca_id, serial, log_id, log_name, sct_timestamp, status, tree_size, leaf_index,
		 checks, last_error, first_checked_at, last_checked_at, included_at, alerted`,
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
		"ca_id, serial, log_id",
		`log_name = excluded.log_name, status = excluded.status, tree_size = excluded.tree_size,
		 leaf_index = excluded.leaf_index, checks = excluded.checks, last_error = excluded.last_error,
		 last_checked_at = excluded.last_checked_at, included_at = excluded.included_at,
		 alerted = excluded.alerted`,
	),
		r.CAID, r.Serial, r.LogID, r.LogName, r.SCTTimestamp.UTC(), r.Status, r.TreeSize, r.LeafIndex,
		r.Checks, r.LastError, nullTime(r.FirstCheckedAt), nullTime(r.LastCheckedAt),
		nullTime(r.IncludedAt), r.Alerted,
	)
	return err
}

// ListCertificatesPendingInclusion returns issued certificates that carry
// embedded SCTs (sct_count > 0) for which at least one SCT has not yet been
// confirmed included — fewer than sct_count of the certificate's SCTs are in the
// 'included' terminal state. A certificate all of whose SCTs are confirmed drops
// out of the result, so the inclusion monitor's per-scan work shrinks as logs
// honor their SCTs; certificates with a 'failed' or still-'pending' SCT stay in,
// so failures are re-observed and late inclusion is picked up. Rows are
// oldest-issued first (their MMD elapsed longest ago) and a non-zero limit
// bounds the scan.
func (db *DB) ListCertificatesPendingInclusion(limit int) ([]models.IssuedCertificate, error) {
	query := `SELECT ` + issuedCertColumns + ` FROM issued_certificates ic
		WHERE ic.sct_count > 0
		  AND (SELECT COUNT(*) FROM sct_inclusion si
		       WHERE si.ca_id = ic.ca_id AND si.serial = ic.serial AND si.status = ?) < ic.sct_count
		ORDER BY ic.not_before ASC`
	args := []interface{}{models.SCTInclusionIncluded}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.IssuedCertificate
	for rows.Next() {
		c, err := scanIssuedCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetSCTInclusion returns the inclusion state of one embedded SCT, or (nil, nil)
// when it has not been recorded yet.
func (db *DB) GetSCTInclusion(caID, serial, logID string) (*models.SCTInclusion, error) {
	r, err := scanSCTInclusion(db.queryRow(
		`SELECT `+sctInclusionColumns+` FROM sct_inclusion WHERE ca_id = ? AND serial = ? AND log_id = ?`,
		caID, serial, logID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ListSCTInclusionForCert returns every recorded SCT inclusion state for one
// certificate, ordered by log name.
func (db *DB) ListSCTInclusionForCert(caID, serial string) ([]models.SCTInclusion, error) {
	return db.querySCTInclusion(
		`SELECT `+sctInclusionColumns+` FROM sct_inclusion WHERE ca_id = ? AND serial = ? ORDER BY log_name, log_id`,
		caID, serial)
}

// ListSCTInclusionByStatus returns recorded SCT inclusion rows, newest-checked
// first. An empty status returns every row; a non-zero limit bounds the result.
func (db *DB) ListSCTInclusionByStatus(status string, limit int) ([]models.SCTInclusion, error) {
	query := `SELECT ` + sctInclusionColumns + ` FROM sct_inclusion`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	// Order by the SCT timestamp (never NULL) so the ordering is identical on
	// SQLite and PostgreSQL, which disagree on default NULL placement.
	query += ` ORDER BY sct_timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	return db.querySCTInclusion(query, args...)
}

// CountSCTInclusionByStatus returns the number of recorded SCT inclusion rows in
// each status, for the doctor check and the read-API/console summary.
func (db *DB) CountSCTInclusionByStatus() (map[string]int, error) {
	rows, err := db.query(`SELECT status, COUNT(*) FROM sct_inclusion GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// querySCTInclusion runs a query returning sct_inclusion rows.
func (db *DB) querySCTInclusion(query string, args ...interface{}) ([]models.SCTInclusion, error) {
	rows, err := db.query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SCTInclusion
	for rows.Next() {
		r, err := scanSCTInclusion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
