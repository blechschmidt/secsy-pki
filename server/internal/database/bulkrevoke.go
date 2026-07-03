package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Bulk revocation (Task 70). These are the store primitives under the
// mass-revocation engine (internal/ca/bulkrevoke.go): a reduced-projection
// candidate listing the engine filters against, and a batched, transactional
// revocation write. Both are written portably for SQLite and PostgreSQL.

// RevocationSelector narrows the issued-certificate inventory to bulk-revocation
// candidates. Only the SQL-expressible filters live here; pattern matching on
// CN/SANs is applied by the engine on the returned projection.
type RevocationSelector struct {
	// CAID is the issuing CA (required).
	CAID string
	// Profile restricts to certificates issued under this profile ("" = any).
	Profile string
	// IssuedAfter/IssuedBefore bound the certificate's NotBefore (inclusive).
	// nil bounds are open.
	IssuedAfter  *time.Time
	IssuedBefore *time.Time
	// IncludeExpired also returns certificates past their NotAfter. By default
	// only certificates still within their validity window are candidates: an
	// RFC 5280 CRL need not carry expired serials, so revoking them only bloats
	// the CRL. Now supplies the expiry cutoff.
	IncludeExpired bool
	Now            time.Time
}

// RevocationCandidate is the reduced projection of an issued certificate the
// bulk-revocation engine plans over — everything the filters and audit trail
// need, without dragging the PEM through memory for very large inventories.
type RevocationCandidate struct {
	Serial     string
	CommonName string
	Subject    string
	SANs       []string
	Profile    string
	Status     models.CertStatus
	NotBefore  time.Time
	NotAfter   time.Time
}

// ListRevocationCandidates returns the not-yet-revoked certificates of a CA
// matching the selector, ordered by serial for deterministic batching. Rows
// whose status is already "revoked" are never returned, which is what makes an
// interrupted bulk revocation naturally resumable: re-running the same
// selection continues with exactly the certificates the previous run did not
// reach.
func (db *DB) ListRevocationCandidates(sel RevocationSelector) ([]RevocationCandidate, error) {
	if sel.CAID == "" {
		return nil, fmt.Errorf("revocation selector requires a CA id")
	}
	now := sel.Now
	if now.IsZero() {
		now = time.Now()
	}

	var b strings.Builder
	b.WriteString(`SELECT serial, common_name, subject, sans, profile, status, not_before, not_after
		FROM issued_certificates WHERE ca_id = ? AND status <> ?`)
	args := []interface{}{sel.CAID, string(models.CertStatusRevoked)}

	if sel.Profile != "" {
		b.WriteString(` AND profile = ?`)
		args = append(args, sel.Profile)
	}
	if sel.IssuedAfter != nil {
		b.WriteString(` AND not_before >= ?`)
		args = append(args, *sel.IssuedAfter)
	}
	if sel.IssuedBefore != nil {
		b.WriteString(` AND not_before <= ?`)
		args = append(args, *sel.IssuedBefore)
	}
	if !sel.IncludeExpired {
		// Compare against the wall clock rather than the lazily maintained
		// "expired" status so unmarked-expired rows are excluded too.
		b.WriteString(` AND not_after > ?`)
		args = append(args, now)
	}
	b.WriteString(` ORDER BY serial`)

	rows, err := db.query(b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RevocationCandidate
	for rows.Next() {
		var c RevocationCandidate
		var commonName, subject, sans, profile sql.NullString
		var status string
		if err := rows.Scan(&c.Serial, &commonName, &subject, &sans, &profile, &status, &c.NotBefore, &c.NotAfter); err != nil {
			return nil, err
		}
		c.CommonName = commonName.String
		c.Subject = subject.String
		c.Profile = profile.String
		c.Status = models.CertStatus(status)
		if sans.Valid && sans.String != "" {
			_ = json.Unmarshal([]byte(sans.String), &c.SANs)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// BulkRevokeCertificates records revocations for a batch of serials under one
// CA in a single transaction, returning the serials that were newly revoked.
//
// Unlike the single-certificate RevokeCertificate — which updates the reason
// and timestamp of an already-revoked serial — an already-revoked serial here
// is left untouched and simply omitted from the returned set. That keeps a
// resumed or concurrently repeated bulk operation idempotent: no CRL entry
// churns its revocation time, and per-certificate audit events are emitted at
// most once per serial across runs.
//
// The batch is applied in sorted serial order so concurrent bulk operations on
// PostgreSQL acquire row locks in a consistent order and cannot deadlock.
func (db *DB) BulkRevokeCertificates(caID string, serials []string, reason int, when time.Time) ([]string, error) {
	if caID == "" {
		return nil, fmt.Errorf("bulk revoke requires a CA id")
	}
	if len(serials) == 0 {
		return nil, nil
	}
	ordered := make([]string, 0, len(serials))
	seen := make(map[string]bool, len(serials))
	for _, s := range serials {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		ordered = append(ordered, s)
	}
	sort.Strings(ordered)

	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	insert, err := tx.Prepare(db.insertOrIgnore("revoked_certificates", "ca_id, serial, revoked_at, reason", "?, ?, ?, ?"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = insert.Close() }()
	update, err := tx.Prepare(db.ph(
		`UPDATE issued_certificates SET status = ?, revoked_at = ?, revocation_reason = ?
		 WHERE ca_id = ? AND serial = ? AND status <> ?`))
	if err != nil {
		return nil, err
	}
	defer func() { _ = update.Close() }()

	applied := make([]string, 0, len(ordered))
	for _, serial := range ordered {
		res, err := insert.Exec(caID, serial, when, reason)
		if err != nil {
			return nil, fmt.Errorf("revoking serial %s: %w", serial, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue // already revoked (possibly by a concurrent single revoke)
		}
		if _, err := update.Exec(string(models.CertStatusRevoked), when, reason, caID, serial,
			string(models.CertStatusRevoked)); err != nil {
			return nil, fmt.Errorf("updating inventory for serial %s: %w", serial, err)
		}
		applied = append(applied, serial)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return applied, nil
}
