package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ersCursorID is the single logical Evidence-Record generation cursor's key.
const ersCursorID = "generation"

const evidenceColumns = `id, scope, description, first_seq, last_seq, object_ids, digest_alg, chains, record, created_at, renewed_at, last_gen_time, tsa_not_after`

// InsertEvidenceRecord persists a newly generated Evidence Record. Timestamps
// are stored UTC/microsecond-truncated so rows read back byte-identical from
// SQLite and PostgreSQL.
func (db *DB) InsertEvidenceRecord(r *models.EvidenceRecord) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	objectIDs, err := json.Marshal(r.ObjectIDs)
	if err != nil {
		return fmt.Errorf("encoding evidence object ids: %w", err)
	}
	_, err = db.exec(
		`INSERT INTO evidence_records (`+evidenceColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Scope, nullString(r.Description), r.FirstSeq, r.LastSeq, string(objectIDs),
		r.DigestAlg, r.Chains, r.Record,
		r.CreatedAt.UTC().Truncate(time.Microsecond),
		nullableTimeTruncated(r.RenewedAt),
		r.LastGenTime.UTC().Truncate(time.Microsecond),
		nullableTimeTruncated(r.TSANotAfter),
	)
	return err
}

// UpdateEvidenceRecord replaces the mutable columns of a record after a renewal:
// the DER, the current chain count and hash algorithm, and the renewal / newest
// timestamp / TSA-expiry metadata. The covered-object range never changes.
func (db *DB) UpdateEvidenceRecord(r *models.EvidenceRecord) error {
	_, err := db.exec(
		`UPDATE evidence_records
		 SET record = ?, digest_alg = ?, chains = ?, renewed_at = ?, last_gen_time = ?, tsa_not_after = ?
		 WHERE id = ?`,
		r.Record, r.DigestAlg, r.Chains,
		nullableTimeTruncated(r.RenewedAt),
		r.LastGenTime.UTC().Truncate(time.Microsecond),
		nullableTimeTruncated(r.TSANotAfter),
		r.ID,
	)
	return err
}

// scanEvidenceRecord reads one row selected with evidenceColumns.
func scanEvidenceRecord(s caScanner) (models.EvidenceRecord, error) {
	var r models.EvidenceRecord
	var description sql.NullString
	var objectIDs string
	var renewedAt, tsaNotAfter sql.NullTime
	if err := s.Scan(&r.ID, &r.Scope, &description, &r.FirstSeq, &r.LastSeq, &objectIDs,
		&r.DigestAlg, &r.Chains, &r.Record, &r.CreatedAt, &renewedAt, &r.LastGenTime, &tsaNotAfter); err != nil {
		return models.EvidenceRecord{}, err
	}
	r.Description = description.String
	if objectIDs != "" {
		if err := json.Unmarshal([]byte(objectIDs), &r.ObjectIDs); err != nil {
			return models.EvidenceRecord{}, fmt.Errorf("decoding evidence object ids: %w", err)
		}
	}
	if renewedAt.Valid {
		t := renewedAt.Time.UTC()
		r.RenewedAt = &t
	}
	if tsaNotAfter.Valid {
		t := tsaNotAfter.Time.UTC()
		r.TSANotAfter = &t
	}
	return r, nil
}

// GetEvidenceRecord returns one Evidence Record by id (nil when absent).
func (db *DB) GetEvidenceRecord(id string) (*models.EvidenceRecord, error) {
	r, err := scanEvidenceRecord(db.queryRow(`SELECT `+evidenceColumns+` FROM evidence_records WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListEvidenceRecords returns records newest-first with a total count, for the
// CLI listing and the console. A limit <= 0 returns all.
func (db *DB) ListEvidenceRecords(limit, offset int) ([]models.EvidenceRecord, int, error) {
	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM evidence_records`).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + evidenceColumns + ` FROM evidence_records ORDER BY created_at DESC, id DESC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = db.query(q+` LIMIT ? OFFSET ?`, limit, offset)
	} else {
		rows, err = db.query(q)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.EvidenceRecord
	for rows.Next() {
		r, err := scanEvidenceRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ListAllEvidenceRecords returns every record ordered by creation, for the
// renewal job's scan. Records are bounded by the number of preservation batches,
// so the full list is materialized.
func (db *DB) ListAllEvidenceRecords() ([]models.EvidenceRecord, error) {
	rows, err := db.query(`SELECT ` + evidenceColumns + ` FROM evidence_records ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.EvidenceRecord
	for rows.Next() {
		r, err := scanEvidenceRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetErsCursor returns the highest event_log.seq already folded into an Evidence
// Record, or 0 when the generation job has never run.
func (db *DB) GetErsCursor() (int64, error) {
	var seq int64
	err := db.queryRow(`SELECT last_seq FROM ers_cursor WHERE id = ?`, ersCursorID).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// ErsCursorInitialized reports whether the generation cursor row exists yet,
// letting the job distinguish "never run" (seed to the current head) from
// "legitimately at seq 0".
func (db *DB) ErsCursorInitialized() (bool, error) {
	var one int
	err := db.queryRow(`SELECT 1 FROM ers_cursor WHERE id = ?`, ersCursorID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetErsCursor durably advances the generation cursor. It is portable across
// SQLite and PostgreSQL via the shared upsert helper.
func (db *DB) SetErsCursor(seq int64) error {
	_, err := db.exec(db.upsert("ers_cursor", "id, last_seq, updated_at", "?, ?, ?",
		"id", "last_seq = excluded.last_seq, updated_at = excluded.updated_at"),
		ersCursorID, seq, time.Now().UTC())
	return err
}

// nullableTimeTruncated renders an optional timestamp as a UTC microsecond-
// truncated value for storage, or NULL when nil.
func nullableTimeTruncated(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Truncate(time.Microsecond)
}
