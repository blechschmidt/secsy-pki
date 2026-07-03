package database

import (
	"database/sql"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Native scoped API tokens / service accounts (Task 86).
//
// The secret is never persisted — only its one-way hash (token_hash), which is
// the O(1) verification lookup key (UNIQUE-indexed). Roles are stored as a
// comma-separated list; scope is 'tenant' or 'platform'. Timestamps are written
// explicitly in UTC (never via a column DEFAULT) so created_at ordering and the
// nullable lifecycle timestamps round-trip identically across SQLite and
// PostgreSQL.

const apiTokenColumns = `id, tenant_id, name, description, prefix, token_hash, roles, scope,
	created_by, created_by_name, created_at, expires_at, last_used_at, last_used_ip, revoked_at, revoked_by`

// CreateAPIToken persists a newly minted token. The caller supplies the id and
// the precomputed token_hash; the plaintext secret is never passed here.
func (db *DB) CreateAPIToken(t *models.APIToken) error {
	if t.TenantID == "" {
		t.TenantID = models.DefaultTenantID
	}
	if t.Scope == "" {
		t.Scope = models.TokenScopeTenant
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	} else {
		t.CreatedAt = t.CreatedAt.UTC()
	}
	_, err := db.exec(`INSERT INTO api_tokens (`+apiTokenColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.TenantID, t.Name, t.Description, t.Prefix, t.TokenHash,
		strings.Join(t.Roles, ","), t.Scope, t.CreatedBy, t.CreatedByName, t.CreatedAt,
		nullableTime(t.ExpiresAt), nullableTime(t.LastUsedAt), t.LastUsedIP,
		nullableTime(t.RevokedAt), t.RevokedBy)
	return err
}

// GetAPITokenByHash resolves a token by its at-rest hash — the verify path's
// lookup. It returns (nil, nil) when no token matches.
func (db *DB) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	return apiTokenOrNil(db.queryRow(`SELECT `+apiTokenColumns+` FROM api_tokens WHERE token_hash = ?`, hash))
}

// GetAPIToken loads a token by id, or (nil, nil) when absent.
func (db *DB) GetAPIToken(id string) (*models.APIToken, error) {
	return apiTokenOrNil(db.queryRow(`SELECT `+apiTokenColumns+` FROM api_tokens WHERE id = ?`, id))
}

func apiTokenOrNil(row *sql.Row) (*models.APIToken, error) {
	tok, err := scanAPIToken(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// ListAPITokens returns tokens ordered newest-first. An empty tenantID lists
// across all tenants (platform-admin view); a non-empty one scopes to it.
func (db *DB) ListAPITokens(tenantID string) ([]models.APIToken, error) {
	q := `SELECT ` + apiTokenColumns + ` FROM api_tokens`
	var args []interface{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := db.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.APIToken
	for rows.Next() {
		tok, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *tok)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token revoked. It is idempotent under concurrency: the
// UPDATE applies only while the token is still un-revoked, so it reports false
// (without error) when the token was already revoked or does not exist.
func (db *DB) RevokeAPIToken(id, by string, at time.Time) (bool, error) {
	res, err := db.exec(
		`UPDATE api_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		at.UTC(), by, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// TouchAPIToken records a successful use (last-used time + client IP). It is
// best-effort and safe to call frequently; the authenticator throttles it.
func (db *DB) TouchAPIToken(id string, at time.Time, ip string) error {
	_, err := db.exec(
		`UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
		at.UTC(), ip, id)
	return err
}

// CountActiveAPITokens returns the number of tokens that would currently
// authenticate: neither revoked nor past expiry. It backs the active-tokens
// gauge.
func (db *DB) CountActiveAPITokens() (int, error) {
	var n int
	err := db.queryRow(
		`SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		time.Now().UTC()).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// scanAPIToken reads one row selected with apiTokenColumns.
func scanAPIToken(s scanner) (*models.APIToken, error) {
	var (
		t                                               models.APIToken
		description, prefix, roles                      sql.NullString
		createdBy, createdByName, lastUsedIP, revokedBy sql.NullString
		expiresAt, lastUsedAt, revokedAt                sql.NullTime
	)
	if err := s.Scan(&t.ID, &t.TenantID, &t.Name, &description, &prefix, &t.TokenHash, &roles, &t.Scope,
		&createdBy, &createdByName, &t.CreatedAt, &expiresAt, &lastUsedAt, &lastUsedIP, &revokedAt, &revokedBy); err != nil {
		return nil, err
	}
	t.Description = description.String
	t.Prefix = prefix.String
	t.Roles = splitTokenRoles(roles.String)
	t.CreatedBy = createdBy.String
	t.CreatedByName = createdByName.String
	t.LastUsedIP = lastUsedIP.String
	t.RevokedBy = revokedBy.String
	if expiresAt.Valid {
		tm := expiresAt.Time
		t.ExpiresAt = &tm
	}
	if lastUsedAt.Valid {
		tm := lastUsedAt.Time
		t.LastUsedAt = &tm
	}
	if revokedAt.Valid {
		tm := revokedAt.Time
		t.RevokedAt = &tm
	}
	return &t, nil
}

// splitTokenRoles parses the comma-separated roles column into a clean slice.
func splitTokenRoles(s string) []string {
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
