package database

import (
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Tenant usage accounting (Task 61).
//
// Consumption is accounted in tenant_usage, one row per (tenant, UTC day),
// updated with single atomic statements so it is correct under concurrent
// issuance on both backends: SQLite serializes on its single connection, and on
// PostgreSQL a conditional UPDATE re-evaluates its WHERE clause after acquiring
// the row lock, so two racing consumers can never both take the last unit of a
// quota. The daily quotas are reservation-style — consumed before the HSM signs
// and released if issuance subsequently fails — so the counters track actual
// issuance, not attempts.

// Usage counter kinds. usageColumn whitelists them to concrete column names so
// a counter name can never inject SQL.
const (
	UsageCertsIssued  = "certs_issued"
	UsageCertsRevoked = "certs_revoked"
	UsageSecretOps    = "secret_ops"
)

// usageColumn maps a counter kind to its tenant_usage column.
func usageColumn(counter string) (string, error) {
	switch counter {
	case UsageCertsIssued, UsageCertsRevoked, UsageSecretOps:
		return counter, nil
	default:
		return "", fmt.Errorf("unknown tenant usage counter %q", counter)
	}
}

// UsageDay formats a point in time as the UTC day key used by tenant_usage.
func UsageDay(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// ensureUsageRow makes sure the (tenant, day) accounting row exists so the
// subsequent atomic UPDATE has something to hit. Idempotent under races.
func (db *DB) ensureUsageRow(tenantID, day string) error {
	_, err := db.exec(db.insertOrIgnore("tenant_usage", "tenant_id, day", "?, ?"), tenantID, day)
	return err
}

// AddTenantUsage unconditionally adds to a tenant's daily usage counter. It is
// the pure-accounting path (no quota attached), e.g. counting revocations.
func (db *DB) AddTenantUsage(tenantID, day, counter string, delta int64) error {
	col, err := usageColumn(counter)
	if err != nil {
		return err
	}
	if err := db.ensureUsageRow(tenantID, day); err != nil {
		return err
	}
	_, err = db.exec(
		fmt.Sprintf(`UPDATE tenant_usage SET %s = %s + ? WHERE tenant_id = ? AND day = ?`, col, col),
		delta, tenantID, day)
	return err
}

// ConsumeTenantDailyQuota atomically takes one unit of a tenant's daily
// counter, enforcing the given ceiling. A non-positive limit means unlimited:
// the unit is still recorded (accounting continues) and consumption always
// succeeds. It returns false — with no counter change — when the ceiling has
// been reached. The single conditional UPDATE is what makes enforcement exact
// under concurrency on both SQLite and PostgreSQL.
func (db *DB) ConsumeTenantDailyQuota(tenantID, day, counter string, limit int64) (bool, error) {
	col, err := usageColumn(counter)
	if err != nil {
		return false, err
	}
	if err := db.ensureUsageRow(tenantID, day); err != nil {
		return false, err
	}
	var res interface {
		RowsAffected() (int64, error)
	}
	if limit > 0 {
		res, err = db.exec(
			fmt.Sprintf(`UPDATE tenant_usage SET %s = %s + 1 WHERE tenant_id = ? AND day = ? AND %s < ?`, col, col, col),
			tenantID, day, limit)
	} else {
		res, err = db.exec(
			fmt.Sprintf(`UPDATE tenant_usage SET %s = %s + 1 WHERE tenant_id = ? AND day = ?`, col, col),
			tenantID, day)
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ReleaseTenantDailyQuota hands back one previously consumed unit (compensation
// when an operation fails after its quota reservation). It never drives a
// counter below zero.
func (db *DB) ReleaseTenantDailyQuota(tenantID, day, counter string) error {
	col, err := usageColumn(counter)
	if err != nil {
		return err
	}
	_, err = db.exec(
		fmt.Sprintf(`UPDATE tenant_usage SET %s = %s - 1 WHERE tenant_id = ? AND day = ? AND %s > 0`, col, col, col),
		tenantID, day)
	return err
}

// GetTenantUsageDay reads one day's accounting row. A missing row is zero
// usage, not an error.
func (db *DB) GetTenantUsageDay(tenantID, day string) (models.TenantUsageDay, error) {
	rows, err := db.query(
		`SELECT day, certs_issued, certs_revoked, secret_ops FROM tenant_usage
		 WHERE tenant_id = ? AND day = ?`, tenantID, day)
	if err != nil {
		return models.TenantUsageDay{Day: day}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return models.TenantUsageDay{Day: day}, rows.Err()
	}
	var d models.TenantUsageDay
	if err := rows.Scan(&d.Day, &d.CertsIssued, &d.CertsRevoked, &d.SecretOps); err != nil {
		return models.TenantUsageDay{Day: day}, err
	}
	return d, nil
}

// ListTenantUsageDays returns the accounting rows for a tenant with
// day >= sinceDay, most recent first — the rolling window the usage report
// serves. Days with no activity have no row and are simply absent.
func (db *DB) ListTenantUsageDays(tenantID, sinceDay string) ([]models.TenantUsageDay, error) {
	rows, err := db.query(
		`SELECT day, certs_issued, certs_revoked, secret_ops FROM tenant_usage
		 WHERE tenant_id = ? AND day >= ? ORDER BY day DESC`, tenantID, sinceDay)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []models.TenantUsageDay
	for rows.Next() {
		var d models.TenantUsageDay
		if err := rows.Scan(&d.Day, &d.CertsIssued, &d.CertsRevoked, &d.SecretOps); err != nil {
			return nil, err
		}
		days = append(days, d)
	}
	return days, rows.Err()
}

// CountActiveCertificatesForTenant counts the tenant's unexpired, unrevoked
// X.509 certificates across all its CAs — the inventory the max_active_certs
// ceiling meters. The count is read fresh (not cached) so revocations and
// expirations free quota immediately.
func (db *DB) CountActiveCertificatesForTenant(tenantID string, now time.Time) (int64, error) {
	var n int64
	err := db.queryRow(
		`SELECT COUNT(*) FROM issued_certificates ic
		 JOIN cas c ON ic.ca_id = c.id
		 WHERE c.tenant_id = ? AND ic.status = ? AND ic.not_after > ?`,
		tenantID, models.CertStatusValid, now.UTC()).Scan(&n)
	return n, err
}

// TenantCertificateTotals reports lifetime issuance totals for the usage
// report: every certificate ever recorded for the tenant's CAs and how many of
// those are revoked.
func (db *DB) TenantCertificateTotals(tenantID string) (total, revoked int64, err error) {
	err = db.queryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN ic.status = ? THEN 1 ELSE 0 END), 0)
		 FROM issued_certificates ic
		 JOIN cas c ON ic.ca_id = c.id
		 WHERE c.tenant_id = ?`,
		models.CertStatusRevoked, tenantID).Scan(&total, &revoked)
	return total, revoked, err
}
