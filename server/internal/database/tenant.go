package database

import (
	"database/sql"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// tenantColumns is the canonical column list for tenant reads; keep it in sync
// with scanTenant.
const tenantColumns = `id, slug, name, status, kek_label, created_at,
	max_certs_per_day, max_active_certs, max_secret_ops_per_day,
	rate_limit_per_second, rate_limit_burst`

// scanTenant reads one tenants row selected with tenantColumns.
func scanTenant(s caScanner) (*models.Tenant, error) {
	var t models.Tenant
	var kekLabel sql.NullString
	if err := s.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &kekLabel, &t.CreatedAt,
		&t.Quotas.MaxCertsPerDay, &t.Quotas.MaxActiveCerts, &t.Quotas.MaxSecretOpsPerDay,
		&t.Quotas.RateLimitPerSecond, &t.Quotas.RateLimitBurst); err != nil {
		return nil, err
	}
	t.KEKLabel = kekLabel.String
	if t.Status == "" {
		t.Status = models.TenantStatusActive
	}
	return &t, nil
}

// CreateTenant inserts a new tenant. The caller supplies a unique ID and slug;
// a duplicate slug fails on the UNIQUE constraint.
func (db *DB) CreateTenant(t *models.Tenant) error {
	status := t.Status
	if status == "" {
		status = models.TenantStatusActive
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := db.exec(
		`INSERT INTO tenants (id, slug, name, status, kek_label, created_at,
			max_certs_per_day, max_active_certs, max_secret_ops_per_day,
			rate_limit_per_second, rate_limit_burst)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Slug, t.Name, status, nullString(t.KEKLabel), created,
		t.Quotas.MaxCertsPerDay, t.Quotas.MaxActiveCerts, t.Quotas.MaxSecretOpsPerDay,
		t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst,
	)
	return err
}

// UpdateTenant persists a tenant's mutable fields: display name, KEK label, and
// quotas. Identity (id, slug), lifecycle status, and created_at are managed by
// their dedicated operations and left untouched.
func (db *DB) UpdateTenant(t *models.Tenant) error {
	_, err := db.exec(
		`UPDATE tenants SET name = ?, kek_label = ?,
			max_certs_per_day = ?, max_active_certs = ?, max_secret_ops_per_day = ?,
			rate_limit_per_second = ?, rate_limit_burst = ?
		 WHERE id = ?`,
		t.Name, nullString(t.KEKLabel),
		t.Quotas.MaxCertsPerDay, t.Quotas.MaxActiveCerts, t.Quotas.MaxSecretOpsPerDay,
		t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst,
		t.ID,
	)
	return err
}

// GetTenant resolves a tenant by ID. Returns (nil, nil) when none matches.
func (db *DB) GetTenant(id string) (*models.Tenant, error) {
	t, err := scanTenant(db.queryRow(`SELECT `+tenantColumns+` FROM tenants WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// GetTenantBySlug resolves a tenant by its stable slug. This is the lookup used
// to map a public URL/path segment to a tenant. Returns (nil, nil) if none.
func (db *DB) GetTenantBySlug(slug string) (*models.Tenant, error) {
	t, err := scanTenant(db.queryRow(`SELECT `+tenantColumns+` FROM tenants WHERE slug = ?`, slug))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// ListTenants returns every tenant ordered by slug. This is a platform-level
// (root/platform-admin) view; tenant members do not enumerate other tenants.
func (db *DB) ListTenants() ([]models.Tenant, error) {
	rows, err := db.query(`SELECT ` + tenantColumns + ` FROM tenants ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []models.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, *t)
	}
	return tenants, rows.Err()
}

// SetTenantStatus updates a tenant's lifecycle status (active | suspended).
func (db *DB) SetTenantStatus(id, status string) error {
	_, err := db.exec(`UPDATE tenants SET status = ? WHERE id = ?`, status, id)
	return err
}

// DeleteTenant removes a tenant. It is refused for the built-in default tenant
// and (by the caller) for tenants that still own CAs, so the isolation boundary
// is never left dangling.
func (db *DB) DeleteTenant(id string) error {
	_, err := db.exec(`DELETE FROM tenants WHERE id = ?`, id)
	return err
}

// CountCAsForTenant returns how many CAs a tenant owns. Used to refuse deletion
// of a non-empty tenant.
func (db *DB) CountCAsForTenant(tenantID string) (int, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM cas WHERE tenant_id = ?`, tenantID).Scan(&n)
	return n, err
}
