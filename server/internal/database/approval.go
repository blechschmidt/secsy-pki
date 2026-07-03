package database

// Persistence for the four-eyes / maker-checker approval workflow (Task 81).
//
// *DB structurally satisfies approval.Store (the approval package deliberately
// does not import database, so this layer names no approval types — the status
// and decision string literals below mirror the approval package's constants).
// The UNIQUE(approval_id, approver) constraint on approval_decisions is what
// makes the distinct-approver threshold race-free: a repeat vote by the same
// approver is a no-op insert, so N approvals always means N different people.

import (
	"database/sql"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// pendingApprovalSelect selects a request's columns plus the running count of
// DISTINCT approve decisions as a trailing column, so callers get the progress
// (k of N) without a second round trip.
const pendingApprovalSelect = `SELECT p.id, p.tenant_id, p.operation_class, p.resource_key, p.resource_name,
	p.fingerprint, p.summary, p.details, p.requested_by, p.requested_by_name, p.required_approvals,
	p.status, p.created_at, p.expires_at, p.decided_at, p.executed_at, p.payload, p.result,
	(SELECT COUNT(*) FROM approval_decisions d WHERE d.approval_id = p.id AND d.decision = 'approve') AS approvals_count
	FROM pending_approvals p`

// scanPendingApproval reads one row selected with pendingApprovalSelect.
func scanPendingApproval(s caScanner) (*models.PendingApproval, error) {
	var pa models.PendingApproval
	var decidedAt, executedAt sql.NullTime
	if err := s.Scan(&pa.ID, &pa.TenantID, &pa.OperationClass, &pa.ResourceKey, &pa.ResourceName,
		&pa.Fingerprint, &pa.Summary, &pa.Details, &pa.RequestedBy, &pa.RequestedByName, &pa.RequiredApprovals,
		&pa.Status, &pa.CreatedAt, &pa.ExpiresAt, &decidedAt, &executedAt, &pa.Payload, &pa.Result,
		&pa.ApprovalsCount); err != nil {
		return nil, err
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		pa.DecidedAt = &t
	}
	if executedAt.Valid {
		t := executedAt.Time
		pa.ExecutedAt = &t
	}
	return &pa, nil
}

// CreatePendingApproval inserts a new approval request.
func (db *DB) CreatePendingApproval(a *models.PendingApproval) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.TenantID == "" {
		a.TenantID = models.DefaultTenantID
	}
	if a.Status == "" {
		a.Status = "pending"
	}
	_, err := db.exec(
		`INSERT INTO pending_approvals (id, tenant_id, operation_class, resource_key, resource_name,
			fingerprint, summary, details, requested_by, requested_by_name, required_approvals, status,
			created_at, expires_at, decided_at, executed_at, payload, result)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.TenantID, a.OperationClass, a.ResourceKey, a.ResourceName,
		a.Fingerprint, a.Summary, a.Details, a.RequestedBy, a.RequestedByName, a.RequiredApprovals, a.Status,
		a.CreatedAt, a.ExpiresAt, nullableTime(a.DecidedAt), nullableTime(a.ExecutedAt), a.Payload, a.Result)
	return err
}

// GetPendingApproval loads one request by id with its full decision log and the
// distinct approve-count populated. It returns (nil, nil) when absent.
func (db *DB) GetPendingApproval(id string) (*models.PendingApproval, error) {
	pa, err := scanPendingApproval(db.queryRow(pendingApprovalSelect+` WHERE p.id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decs, err := db.ListApprovalDecisions(id)
	if err != nil {
		return nil, err
	}
	pa.Decisions = decs
	return pa, nil
}

// FindOpenApproval returns the newest still-open (pending or approved) request
// for an operation fingerprint, or (nil, nil) when none is open.
func (db *DB) FindOpenApproval(tenantID, class, fingerprint string) (*models.PendingApproval, error) {
	pa, err := scanPendingApproval(db.queryRow(pendingApprovalSelect+`
		WHERE p.tenant_id = ? AND p.operation_class = ? AND p.fingerprint = ?
		  AND p.status IN ('pending', 'approved')
		ORDER BY p.created_at DESC LIMIT 1`, tenantID, class, fingerprint))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pa, nil
}

// ListPendingApprovals lists requests matching the optional filters, newest
// first, capped at limit (0 => 200).
func (db *DB) ListPendingApprovals(tenantID, status, class string, limit int) ([]models.PendingApproval, error) {
	q := pendingApprovalSelect + ` WHERE 1 = 1`
	var args []interface{}
	if tenantID != "" {
		q += ` AND p.tenant_id = ?`
		args = append(args, tenantID)
	}
	if status != "" {
		q += ` AND p.status = ?`
		args = append(args, status)
	}
	if class != "" {
		q += ` AND p.operation_class = ?`
		args = append(args, class)
	}
	q += ` ORDER BY p.created_at DESC`
	if limit <= 0 {
		limit = 200
	}
	q += ` LIMIT ?`
	args = append(args, limit)

	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.PendingApproval
	for rows.Next() {
		pa, err := scanPendingApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *pa)
	}
	return out, rows.Err()
}

// AddApprovalDecision records one approver's decision. inserted is false when
// the approver already decided on the request — the UNIQUE(approval_id,
// approver) constraint turns a repeat vote into a no-op, so the distinct-
// approver threshold cannot be met by one principal voting twice.
func (db *DB) AddApprovalDecision(d *models.ApprovalDecision) (bool, error) {
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	res, err := db.conn.Exec(db.insertOrIgnore("approval_decisions",
		"approval_id, approver, approver_name, decision, comment, created_at",
		"?, ?, ?, ?, ?, ?"),
		d.ApprovalID, d.Approver, d.ApproverName, d.Decision, d.Comment, d.CreatedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountApprovalDecisions counts distinct decisions of a kind for a request.
func (db *DB) CountApprovalDecisions(approvalID, decision string) (int, error) {
	var n int
	err := db.queryRow(
		`SELECT COUNT(*) FROM approval_decisions WHERE approval_id = ? AND decision = ?`,
		approvalID, decision).Scan(&n)
	return n, err
}

// ListApprovalDecisions returns a request's decision log, oldest first.
func (db *DB) ListApprovalDecisions(approvalID string) ([]models.ApprovalDecision, error) {
	rows, err := db.query(
		`SELECT id, approval_id, approver, approver_name, decision, comment, created_at
		 FROM approval_decisions WHERE approval_id = ? ORDER BY created_at ASC, id ASC`, approvalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ApprovalDecision
	for rows.Next() {
		var d models.ApprovalDecision
		if err := rows.Scan(&d.ID, &d.ApprovalID, &d.Approver, &d.ApproverName,
			&d.Decision, &d.Comment, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetApprovalStatus atomically transitions a request from one status to another,
// applying only while the row still carries `from` (optimistic concurrency), and
// stamping decided_at (approved/rejected/expired) or executed_at (executed). It
// reports false without error when the row had already moved on, which callers
// treat as losing a race — the guarantee that an approved request is consumed at
// most once. The status literals mirror the approval package's constants.
func (db *DB) SetApprovalStatus(id, from, to string, at time.Time) (bool, error) {
	q := `UPDATE pending_approvals SET status = ?`
	args := []interface{}{to}
	switch to {
	case "approved", "rejected", "expired":
		q += `, decided_at = ?`
		args = append(args, at)
	case "executed":
		q += `, executed_at = ?`
		args = append(args, at)
	}
	q += ` WHERE id = ? AND status = ?`
	args = append(args, id, from)

	res, err := db.exec(q, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// SetApprovalResult stores the opaque outcome blob against a request (Task 84's
// cert.issue records the issued serial here), so the completed operation's
// artifact can be delivered on later fetches. It is a plain update keyed by id;
// the state transition that authorizes completion is done separately via
// SetApprovalStatus.
func (db *DB) SetApprovalResult(id, result string) error {
	_, err := db.exec(`UPDATE pending_approvals SET result = ? WHERE id = ?`, result, id)
	return err
}

// ListExpirableApprovals returns open requests whose window has elapsed, oldest
// deadline first.
func (db *DB) ListExpirableApprovals(now time.Time) ([]models.PendingApproval, error) {
	rows, err := db.query(pendingApprovalSelect+`
		WHERE p.status IN ('pending', 'approved') AND p.expires_at <= ?
		ORDER BY p.expires_at ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.PendingApproval
	for rows.Next() {
		pa, err := scanPendingApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *pa)
	}
	return out, rows.Err()
}
