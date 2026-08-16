package database

import (
	"database/sql"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Durable outbound webhook subscriptions and their delivery queue (Task 116).
//
// This file backs three tables:
//
//   - webhook_subscriptions — the operator-managed registrations (endpoint, HMAC
//     secret, event-type filter, tenant scope, enabled flag).
//   - webhook_deliveries — the durable outbound queue. One row per (subscription,
//     source event); UNIQUE(subscription_id, event_seq) makes the cursor-swept
//     fan-out idempotent, and the (status, next_attempt_at) index backs the
//     delivery worker's "claim due work" read.
//   - webhook_fanout_cursor — a single-row high-water mark of how far the
//     leader-elected fan-out has scanned the event log (mirrors the SIEM cursor).
//
// Timestamps are written explicitly in UTC (never via a column DEFAULT) so
// created_at ordering and the nullable lifecycle timestamps round-trip
// identically across SQLite and PostgreSQL, exactly as the api_tokens store does.

const webhookSubColumns = `id, tenant_id, scope, url, secret, event_types, enabled,
	description, created_by, created_at, updated_at`

// CreateWebhookSubscription persists a new subscription.
func (db *DB) CreateWebhookSubscription(s *models.WebhookSubscription) error {
	if s.TenantID == "" {
		s.TenantID = models.DefaultTenantID
	}
	if s.Scope == "" {
		s.Scope = models.WebhookScopeTenant
	}
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	} else {
		s.CreatedAt = s.CreatedAt.UTC()
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = s.CreatedAt
	} else {
		s.UpdatedAt = s.UpdatedAt.UTC()
	}
	_, err := db.exec(`INSERT INTO webhook_subscriptions (`+webhookSubColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.TenantID, s.Scope, s.URL, s.Secret, strings.Join(s.EventTypes, ","),
		s.Enabled, s.Description, s.CreatedBy, s.CreatedAt, s.UpdatedAt)
	return err
}

// GetWebhookSubscription loads a subscription by id, or (nil, nil) when absent.
func (db *DB) GetWebhookSubscription(id string) (*models.WebhookSubscription, error) {
	return webhookSubOrNil(db.queryRow(`SELECT `+webhookSubColumns+` FROM webhook_subscriptions WHERE id = ?`, id))
}

func webhookSubOrNil(row *sql.Row) (*models.WebhookSubscription, error) {
	s, err := scanWebhookSub(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListWebhookSubscriptions returns subscriptions ordered newest-first. An empty
// tenantID lists across all tenants (platform-admin view); a non-empty one scopes
// to it.
func (db *DB) ListWebhookSubscriptions(tenantID string) ([]models.WebhookSubscription, error) {
	q := `SELECT ` + webhookSubColumns + ` FROM webhook_subscriptions`
	var args []interface{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY created_at DESC`
	return db.queryWebhookSubs(q, args...)
}

// ListEnabledWebhookSubscriptions returns every enabled subscription across all
// tenants — the fan-out worker's read of the currently-active routing table.
func (db *DB) ListEnabledWebhookSubscriptions() ([]models.WebhookSubscription, error) {
	return db.queryWebhookSubs(`SELECT ` + webhookSubColumns +
		` FROM webhook_subscriptions WHERE enabled = ` + db.boolLiteral(true) + ` ORDER BY created_at ASC`)
}

func (db *DB) queryWebhookSubs(q string, args ...interface{}) ([]models.WebhookSubscription, error) {
	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WebhookSubscription
	for rows.Next() {
		s, err := scanWebhookSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// SetWebhookSubscriptionEnabled toggles a subscription's enabled flag and stamps
// updated_at. It reports whether a row changed (false when the id is unknown or
// the flag already held the requested value), so an enable/disable is idempotent.
func (db *DB) SetWebhookSubscriptionEnabled(id string, enabled bool) (bool, error) {
	res, err := db.exec(
		`UPDATE webhook_subscriptions SET enabled = ?, updated_at = ? WHERE id = ? AND enabled <> ?`,
		enabled, time.Now().UTC(), id, enabled)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteWebhookSubscription removes a subscription and its entire delivery
// history in one transaction, reporting whether the subscription existed. The
// delivery rows are foreign-keyed to the subscription, so they are removed first.
func (db *DB) DeleteWebhookSubscription(id string) (bool, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(db.ph(`DELETE FROM webhook_deliveries WHERE subscription_id = ?`), id); err != nil {
		return false, err
	}
	res, err := tx.Exec(db.ph(`DELETE FROM webhook_subscriptions WHERE id = ?`), id)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// scanWebhookSub reads one row selected with webhookSubColumns.
func scanWebhookSub(s scanner) (*models.WebhookSubscription, error) {
	var (
		sub                             models.WebhookSubscription
		secret, eventTypes, description sql.NullString
		createdBy                       sql.NullString
	)
	if err := s.Scan(&sub.ID, &sub.TenantID, &sub.Scope, &sub.URL, &secret, &eventTypes, &sub.Enabled,
		&description, &createdBy, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
		return nil, err
	}
	sub.Secret = secret.String
	sub.EventTypes = splitCSV(eventTypes.String)
	sub.Description = description.String
	sub.CreatedBy = createdBy.String
	return &sub, nil
}

// --- delivery queue ---

const webhookDeliveryColumns = `id, subscription_id, tenant_id, event_id, event_seq, event_type,
	payload, status, attempts, max_attempts, next_attempt_at, last_attempt_at,
	last_status_code, last_error, created_at, delivered_at`

// EnqueueWebhookDelivery inserts a delivery, ignoring a conflict on
// (subscription_id, event_seq). That makes the cursor-swept fan-out idempotent:
// if the fan-out re-scans a range (e.g. after a crash between enqueue and cursor
// advance), the duplicate insert is silently skipped rather than double-delivered.
func (db *DB) EnqueueWebhookDelivery(d *models.WebhookDelivery) error {
	if d.Status == "" {
		d.Status = models.WebhookDeliveryPending
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	} else {
		d.CreatedAt = d.CreatedAt.UTC()
	}
	if d.NextAttemptAt.IsZero() {
		d.NextAttemptAt = d.CreatedAt
	} else {
		d.NextAttemptAt = d.NextAttemptAt.UTC()
	}
	_, err := db.exec(db.insertOrIgnore("webhook_deliveries", webhookDeliveryColumns,
		`?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`),
		d.ID, d.SubscriptionID, d.TenantID, d.EventID, d.EventSeq, d.EventType,
		d.Payload, d.Status, d.Attempts, d.MaxAttempts, d.NextAttemptAt,
		nullableTime(d.LastAttemptAt), d.LastStatusCode, d.LastError, d.CreatedAt,
		nullableTime(d.DeliveredAt))
	return err
}

// GetWebhookDelivery loads a delivery by id, or (nil, nil) when absent.
func (db *DB) GetWebhookDelivery(id string) (*models.WebhookDelivery, error) {
	d, err := scanWebhookDelivery(db.queryRow(`SELECT `+webhookDeliveryColumns+` FROM webhook_deliveries WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ListDueWebhookDeliveries returns pending deliveries whose next_attempt_at has
// arrived, oldest-due first, bounded by limit. It is the delivery worker's
// claim-due-work read; because that worker is leader-elected and single-threaded
// per batch, no row-level locking is required.
func (db *DB) ListDueWebhookDeliveries(now time.Time, limit int) ([]models.WebhookDelivery, error) {
	q := `SELECT ` + webhookDeliveryColumns + ` FROM webhook_deliveries
		WHERE status = ? AND next_attempt_at <= ? ORDER BY next_attempt_at ASC`
	if limit > 0 {
		q += ` LIMIT ?`
		return db.queryWebhookDeliveries(q, models.WebhookDeliveryPending, now.UTC(), limit)
	}
	return db.queryWebhookDeliveries(q, models.WebhookDeliveryPending, now.UTC())
}

// ListWebhookDeliveries returns a subscription's deliveries, newest-first,
// optionally filtered by status, bounded by limit (0 = a sane default cap).
func (db *DB) ListWebhookDeliveries(subscriptionID, status string, limit int) ([]models.WebhookDelivery, error) {
	q := `SELECT ` + webhookDeliveryColumns + ` FROM webhook_deliveries WHERE subscription_id = ?`
	args := []interface{}{subscriptionID}
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC, event_seq DESC`
	if limit <= 0 {
		limit = 200
	}
	q += ` LIMIT ?`
	args = append(args, limit)
	return db.queryWebhookDeliveries(q, args...)
}

func (db *DB) queryWebhookDeliveries(q string, args ...interface{}) ([]models.WebhookDelivery, error) {
	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WebhookDelivery
	for rows.Next() {
		d, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// MarkWebhookDeliverySucceeded records a terminal successful delivery.
func (db *DB) MarkWebhookDeliverySucceeded(id string, at time.Time, statusCode int) error {
	_, err := db.exec(
		`UPDATE webhook_deliveries
		    SET status = ?, attempts = attempts + 1, last_attempt_at = ?, last_status_code = ?,
		        last_error = '', delivered_at = ?
		  WHERE id = ?`,
		models.WebhookDeliveryDelivered, at.UTC(), statusCode, at.UTC(), id)
	return err
}

// MarkWebhookDeliveryRetry records a failed-but-retryable attempt: it bumps the
// attempt count, records the error, and schedules the next attempt (backed off).
func (db *DB) MarkWebhookDeliveryRetry(id string, at, nextAttempt time.Time, statusCode int, errMsg string) error {
	_, err := db.exec(
		`UPDATE webhook_deliveries
		    SET attempts = attempts + 1, last_attempt_at = ?, last_status_code = ?,
		        last_error = ?, next_attempt_at = ?
		  WHERE id = ?`,
		at.UTC(), statusCode, truncateErr(errMsg), nextAttempt.UTC(), id)
	return err
}

// MarkWebhookDeliveryDead records a terminal failure: the retry budget is
// exhausted and the delivery is moved to the dead-letter state.
func (db *DB) MarkWebhookDeliveryDead(id string, at time.Time, statusCode int, errMsg string) error {
	_, err := db.exec(
		`UPDATE webhook_deliveries
		    SET status = ?, attempts = attempts + 1, last_attempt_at = ?, last_status_code = ?,
		        last_error = ?
		  WHERE id = ?`,
		models.WebhookDeliveryDead, at.UTC(), statusCode, truncateErr(errMsg), id)
	return err
}

// CancelPendingWebhookDeliveries moves all still-pending deliveries of a
// subscription to the terminal canceled state — used when a subscription is
// disabled so no more attempts are made against an endpoint the operator has
// paused. It reports how many rows changed.
func (db *DB) CancelPendingWebhookDeliveries(subscriptionID string) (int64, error) {
	res, err := db.exec(
		`UPDATE webhook_deliveries SET status = ? WHERE subscription_id = ? AND status = ?`,
		models.WebhookDeliveryCanceled, subscriptionID, models.WebhookDeliveryPending)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountWebhookDeliveriesByStatus returns the number of deliveries in each status,
// backing the queue-depth / dead-letter gauges and the doctor check.
func (db *DB) CountWebhookDeliveriesByStatus() (map[string]int, error) {
	rows, err := db.query(`SELECT status, COUNT(*) FROM webhook_deliveries GROUP BY status`)
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

// OldestDeadWebhookDelivery returns the least-recently-created dead-lettered
// delivery, or (nil, nil) when none exist. The doctor check reads it to alert on
// stale dead-letters that an operator has not yet triaged.
func (db *DB) OldestDeadWebhookDelivery() (*models.WebhookDelivery, error) {
	d, err := scanWebhookDelivery(db.queryRow(`SELECT `+webhookDeliveryColumns+
		` FROM webhook_deliveries WHERE status = ? ORDER BY created_at ASC LIMIT 1`, models.WebhookDeliveryDead))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func scanWebhookDelivery(s scanner) (*models.WebhookDelivery, error) {
	var (
		d                  models.WebhookDelivery
		eventID, eventType sql.NullString
		payload, lastError sql.NullString
		lastAttempt        sql.NullTime
		deliveredAt        sql.NullTime
	)
	if err := s.Scan(&d.ID, &d.SubscriptionID, &d.TenantID, &eventID, &d.EventSeq, &eventType,
		&payload, &d.Status, &d.Attempts, &d.MaxAttempts, &d.NextAttemptAt, &lastAttempt,
		&d.LastStatusCode, &lastError, &d.CreatedAt, &deliveredAt); err != nil {
		return nil, err
	}
	d.EventID = eventID.String
	d.EventType = eventType.String
	d.Payload = payload.String
	d.LastError = lastError.String
	if lastAttempt.Valid {
		t := lastAttempt.Time
		d.LastAttemptAt = &t
	}
	if deliveredAt.Valid {
		t := deliveredAt.Time
		d.DeliveredAt = &t
	}
	return &d, nil
}

// --- fan-out cursor ---

// webhookCursorID is the single logical fan-out cursor's primary key.
const webhookCursorID = "fanout"

// GetWebhookCursor returns the highest event sequence number the fan-out has
// processed, or 0 when it has never run (start from the current head — see the
// engine — so a first enablement does not replay the entire certificate history).
func (db *DB) GetWebhookCursor() (int64, error) {
	var seq int64
	err := db.queryRow(`SELECT last_seq FROM webhook_fanout_cursor WHERE id = ?`, webhookCursorID).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// WebhookCursorInitialized reports whether the fan-out cursor row exists yet,
// letting the engine distinguish "never run" (seed to head) from "legitimately
// at seq 0".
func (db *DB) WebhookCursorInitialized() (bool, error) {
	var one int
	err := db.queryRow(`SELECT 1 FROM webhook_fanout_cursor WHERE id = ?`, webhookCursorID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetWebhookCursor durably advances the fan-out cursor. It is portable across
// SQLite and PostgreSQL via the shared upsert helper.
func (db *DB) SetWebhookCursor(seq int64) error {
	_, err := db.exec(db.upsert("webhook_fanout_cursor", "id, last_seq, updated_at", "?, ?, ?",
		"id", "last_seq = excluded.last_seq, updated_at = excluded.updated_at"),
		webhookCursorID, seq, time.Now().UTC())
	return err
}

// splitCSV parses a comma-separated column into a trimmed, non-empty slice.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// truncateErr bounds a stored delivery error so a pathological upstream message
// cannot bloat the row.
func truncateErr(s string) string {
	const max = 1024
	if len(s) > max {
		return s[:max]
	}
	return s
}

// boolLiteral renders a boolean literal for inlining into DDL-adjacent SQL where
// a placeholder is awkward (the enabled filter). SQLite stores booleans as 0/1;
// PostgreSQL uses TRUE/FALSE.
func (db *DB) boolLiteral(v bool) string {
	if db.isPostgres() {
		if v {
			return "TRUE"
		}
		return "FALSE"
	}
	if v {
		return "1"
	}
	return "0"
}
