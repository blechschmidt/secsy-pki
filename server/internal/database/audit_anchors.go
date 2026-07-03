package database

import (
	"database/sql"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// InsertAuditAnchor persists one audit-chain anchor. The head hash is stored
// lowercased so lookups and comparisons are canonical, and timestamps are
// truncated to microseconds so the row reads back byte-identical from both
// SQLite and PostgreSQL (whose TIMESTAMP columns carry microsecond precision).
func (db *DB) InsertAuditAnchor(a *audit.Anchor) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	a.HeadHash = strings.ToLower(a.HeadHash)
	a.GenTime = a.GenTime.UTC().Truncate(time.Microsecond)
	a.CreatedAt = a.CreatedAt.UTC().Truncate(time.Microsecond)
	_, err := db.exec(
		`INSERT INTO audit_anchors (id, seq, head_hash, token, tsa_url, gen_time, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Seq, a.HeadHash, a.Token, nullString(a.TSASource), a.GenTime, a.CreatedAt,
	)
	return err
}

const auditAnchorColumns = `id, seq, head_hash, token, tsa_url, gen_time, created_at`

// scanAuditAnchor reads one audit_anchors row selected with auditAnchorColumns.
func scanAuditAnchor(s caScanner) (audit.Anchor, error) {
	var a audit.Anchor
	var tsaURL sql.NullString
	if err := s.Scan(&a.ID, &a.Seq, &a.HeadHash, &a.Token, &tsaURL, &a.GenTime, &a.CreatedAt); err != nil {
		return audit.Anchor{}, err
	}
	a.TSASource = tsaURL.String
	return a, nil
}

// ListAuditAnchorsAsc returns every anchor ordered by ascending anchored
// sequence number (then creation time, for repeated anchorings of one head),
// the order verification walks them in. Anchors are low-volume (one per
// cadence interval), so the full list is returned.
func (db *DB) ListAuditAnchorsAsc() ([]audit.Anchor, error) {
	rows, err := db.query(`SELECT ` + auditAnchorColumns + ` FROM audit_anchors ORDER BY seq ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anchors []audit.Anchor
	for rows.Next() {
		a, err := scanAuditAnchor(rows)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, a)
	}
	return anchors, rows.Err()
}

// LatestAuditAnchor returns the anchor covering the highest sequence number
// (nil when none exists). The anchor job uses it to decide whether the head
// has moved since the last anchoring.
func (db *DB) LatestAuditAnchor() (*audit.Anchor, error) {
	a, err := scanAuditAnchor(db.queryRow(
		`SELECT ` + auditAnchorColumns + ` FROM audit_anchors ORDER BY seq DESC, created_at DESC LIMIT 1`))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
