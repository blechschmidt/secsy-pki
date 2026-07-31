package database

import (
	"database/sql"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Certificate-inventory retention/archival store layer (Task 157).
//
// A high-volume CA (short-lived STAR/ACME issuance) grows issued_certificates
// unbounded. These methods let the leader-elected retention job safely age out
// long-expired, terminal rows under a fail-safe policy:
//
//   - Eligibility is driven by not_after: a row is eligible only once its
//     validity ended more than the grace window ago (not_after < cutoff). A
//     still-valid or revoked-but-not-yet-expired certificate has a not_after in
//     the future, so it is NEVER selected — this single predicate is what retains
//     the load-bearing certificates the CRL/OCSP responders depend on.
//   - Held (suspended, RFC 5280 certificateHold) certificates are excluded
//     regardless of age: a hold is reversible, so the row is not terminal.
//   - Certificates referenced by an open approval are excluded (see
//     ArchiveRetentionBatch's excludeSerials).
//
// Crucially, retention never reads or writes the authoritative
// revoked_certificates table. OCSP resolves a serial by consulting
// revoked_certificates first (REVOKED) and issued_certificates second (GOOD),
// and CRL generation reads only revoked_certificates. Because a retained serial
// is by definition still valid or revoked-but-unexpired (its row is untouched),
// and because the revocation table is never modified here, OCSP/CRL for every
// retained serial is provably unaffected.

// RetentionCandidate is the minimal projection of an issued (or archived)
// certificate the retention job needs: enough to fold a tamper-evident manifest
// digest of exactly which certificates left the hot inventory, without loading
// the full PEM bodies.
type RetentionCandidate struct {
	ID       string
	CAID     string
	Serial   string
	Status   string
	NotAfter time.Time
}

// inPlaceholders returns "?, ?, ..." with n placeholders for an IN (...) list.
// db.ph rewrites them to $1.. for PostgreSQL.
func inPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// retentionEligiblePredicate is the WHERE clause (sans the not_after bind and
// the optional serial-exclusion list) shared by counting and selection so the
// two can never drift. status <> held keeps suspended certs; the not_after bound
// keeps everything still within its validity plus grace.
const retentionEligiblePredicate = `not_after < ? AND status <> ?`

// CountRetentionEligible counts issued_certificates rows eligible for retention
// under the given cutoff (a row is eligible when not_after < cutoff and it is not
// on hold). It is the backlog/estimate signal; it does not subtract the (in
// practice empty) set of serials pinned by an open approval, which are still
// excluded at mutation time — so this is an upper bound on what a run will move.
func (db *DB) CountRetentionEligible(cutoff time.Time) (int, error) {
	var n int
	err := db.queryRow(
		`SELECT COUNT(*) FROM issued_certificates WHERE `+retentionEligiblePredicate,
		cutoff.UTC(), string(models.CertStatusHeld)).Scan(&n)
	return n, err
}

// CountArchiveEligible counts issued_certificates_archive rows whose not_after is
// older than cutoff — the rows prune mode would hard-delete on its next pass.
func (db *DB) CountArchiveEligible(cutoff time.Time) (int, error) {
	var n int
	err := db.queryRow(
		`SELECT COUNT(*) FROM issued_certificates_archive WHERE not_after < ?`,
		cutoff.UTC()).Scan(&n)
	return n, err
}

// CountArchivedCertificates returns the current size of the archive table.
func (db *DB) CountArchivedCertificates() (int, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM issued_certificates_archive`).Scan(&n)
	return n, err
}

// ListRetentionEligible returns up to limit eligible candidates ordered by
// (ca_id, serial) after the (afterCA, afterSerial) keyset cursor. It is a
// read-only projection used by the dry-run report; the ordering gives a stable
// total order for cursoring even though serial is a decimal string compared as
// text.
func (db *DB) ListRetentionEligible(cutoff time.Time, afterCA, afterSerial string, limit int) ([]RetentionCandidate, error) {
	if limit <= 0 {
		limit = 500
	}
	q := `SELECT id, ca_id, serial, status, not_after FROM issued_certificates WHERE ` + retentionEligiblePredicate
	args := []interface{}{cutoff.UTC(), string(models.CertStatusHeld)}
	if afterCA != "" || afterSerial != "" {
		q += ` AND (ca_id > ? OR (ca_id = ? AND serial > ?))`
		args = append(args, afterCA, afterCA, afterSerial)
	}
	q += ` ORDER BY ca_id, serial LIMIT ?`
	args = append(args, limit)

	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRetentionCandidates(rows)
}

// ArchiveRetentionBatch moves up to limit eligible rows into
// issued_certificates_archive in a single transaction and returns the moved
// candidates (empty when none remain). The archive INSERT and the source DELETE
// run in the same transaction, and the DELETE follows the INSERT, so a row is
// never removed from the hot table without its archive copy committed — the
// fail-safe "delete after successful archive" invariant, even in archive mode.
//
// excludeSerials are serials referenced by an open approval; they are filtered
// out of the SELECT, so a pinned serial is never moved (and, because they are
// filtered in selection rather than skipped after, they never stall the batch
// loop). The caller re-invokes until an empty batch is returned.
func (db *DB) ArchiveRetentionBatch(cutoff time.Time, runID, reason string, now time.Time, excludeSerials []string, limit int) ([]RetentionCandidate, error) {
	if limit <= 0 {
		limit = 500
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	sel := `SELECT id, ca_id, serial, status, not_after FROM issued_certificates WHERE ` + retentionEligiblePredicate
	args := []interface{}{cutoff.UTC(), string(models.CertStatusHeld)}
	if len(excludeSerials) > 0 {
		sel += ` AND serial NOT IN (` + inPlaceholders(len(excludeSerials)) + `)`
		for _, s := range excludeSerials {
			args = append(args, s)
		}
	}
	sel += ` ORDER BY id LIMIT ?`
	args = append(args, limit)

	rows, err := tx.Query(db.ph(sel), args...)
	if err != nil {
		return nil, err
	}
	batch, err := scanRetentionCandidates(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return nil, tx.Commit()
	}

	ids := make([]interface{}, len(batch))
	for i, c := range batch {
		ids[i] = c.ID
	}
	idPH := inPlaceholders(len(ids))

	// INSERT ... SELECT copies full rows (including PEM) inside the engine — the
	// bodies never round-trip through Go — appending the archival bookkeeping.
	ins := `INSERT INTO issued_certificates_archive
		(id, ca_id, serial, subject, common_name, sans, profile, certificate,
		 not_before, not_after, status, revoked_at, revocation_reason, requested_by,
		 created_at, ct_status, sct_count, marker, public_key_fingerprint,
		 archived_at, archive_run_id, archive_reason)
	 SELECT id, ca_id, serial, subject, common_name, sans, profile, certificate,
		 not_before, not_after, status, revoked_at, revocation_reason, requested_by,
		 created_at, ct_status, sct_count, marker, public_key_fingerprint,
		 ?, ?, ?
	 FROM issued_certificates WHERE id IN (` + idPH + `)`
	insArgs := append([]interface{}{now.UTC(), runID, reason}, ids...)
	if _, err := tx.Exec(db.ph(ins), insArgs...); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(db.ph(`DELETE FROM issued_certificates WHERE id IN (`+idPH+`)`), ids...); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return batch, nil
}

// PruneArchiveBatch hard-deletes up to limit rows from
// issued_certificates_archive whose not_after is older than cutoff, returning the
// deleted candidates (empty when none remain). It touches only the archive table
// — never revoked_certificates — so CRL/OCSP correctness is unaffected. The
// caller re-invokes until an empty batch is returned.
func (db *DB) PruneArchiveBatch(cutoff time.Time, limit int) ([]RetentionCandidate, error) {
	if limit <= 0 {
		limit = 500
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(db.ph(
		`SELECT id, ca_id, serial, status, not_after FROM issued_certificates_archive
		  WHERE not_after < ? ORDER BY id LIMIT ?`), cutoff.UTC(), limit)
	if err != nil {
		return nil, err
	}
	batch, err := scanRetentionCandidates(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return nil, tx.Commit()
	}

	ids := make([]interface{}, len(batch))
	for i, c := range batch {
		ids[i] = c.ID
	}
	if _, err := tx.Exec(db.ph(`DELETE FROM issued_certificates_archive WHERE id IN (`+inPlaceholders(len(ids))+`)`), ids...); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return batch, nil
}

// GetArchivedCertificate looks up an archived certificate by (CA, serial),
// returning (nil, nil) if none — so an operator can still resolve a serial that
// has been moved out of the hot inventory.
func (db *DB) GetArchivedCertificate(caID, serial string) (*models.IssuedCertificate, error) {
	row := db.queryRow(
		`SELECT `+issuedCertColumns+` FROM issued_certificates_archive WHERE ca_id = ? AND serial = ?`,
		caID, serial)
	c, err := scanIssuedCert(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// approvalSerialRe extracts a decimal serial pinned in an approval's payload or
// result JSON (e.g. {"serial":"12345"}). It is intentionally strict (decimal
// only) to avoid over-matching.
var approvalSerialRe = regexp.MustCompile(`"serial"\s*:\s*"([0-9]+)"`)

// OpenApprovalSerials returns the set of issued-certificate serials referenced by
// an OPEN (pending or approved) four-eyes approval, extracted from the approval
// payload/result. In the current codebase no open approval pins an already-issued
// serial (a cert.issue approval carries the CA and produces the serial only on
// execution, which is terminal), so this is normally empty — but it makes the
// retention gate future-proof: if any approval class ever parks a specific
// serial, that certificate is protected from archival until the approval closes.
func (db *DB) OpenApprovalSerials() (map[string]struct{}, error) {
	rows, err := db.query(
		`SELECT payload, result FROM pending_approvals WHERE status IN ('pending', 'approved')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var payload, result sql.NullString
		if err := rows.Scan(&payload, &result); err != nil {
			return nil, err
		}
		for _, blob := range []string{payload.String, result.String} {
			for _, m := range approvalSerialRe.FindAllStringSubmatch(blob, -1) {
				out[m[1]] = struct{}{}
			}
		}
	}
	return out, rows.Err()
}

// scanRetentionCandidates scans the (id, ca_id, serial, status, not_after)
// projection shared by the eligibility reads.
func scanRetentionCandidates(rows *sql.Rows) ([]RetentionCandidate, error) {
	var out []RetentionCandidate
	for rows.Next() {
		var c RetentionCandidate
		var na sql.NullTime
		if err := rows.Scan(&c.ID, &c.CAID, &c.Serial, &c.Status, &na); err != nil {
			return nil, err
		}
		if na.Valid {
			c.NotAfter = na.Time
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
