//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newTokenTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustCreateToken(t *testing.T, db *DB, id, tenant, hash string, mut func(*models.APIToken)) *models.APIToken {
	t.Helper()
	tok := &models.APIToken{
		ID:        id,
		TenantID:  tenant,
		Name:      id,
		Prefix:    "secsy_pat_" + id,
		TokenHash: hash,
		Roles:     []string{"issuer"},
		Scope:     models.TokenScopeTenant,
		CreatedBy: "cli:test",
	}
	if mut != nil {
		mut(tok)
	}
	if err := db.CreateAPIToken(tok); err != nil {
		t.Fatalf("CreateAPIToken(%s): %v", id, err)
	}
	return tok
}

func TestAPITokenCRUD(t *testing.T) {
	db := newTokenTestDB(t)

	future := time.Now().Add(24 * time.Hour).UTC()
	created := mustCreateToken(t, db, "t1", models.DefaultTenantID, "hash-1", func(x *models.APIToken) {
		x.Roles = []string{"issuer", "auditor"}
		x.ExpiresAt = &future
		x.Description = "ci pipeline"
	})

	// Lookup by hash (the verify path).
	got, err := db.GetAPITokenByHash("hash-1")
	if err != nil || got == nil {
		t.Fatalf("GetAPITokenByHash: %v (got=%v)", err, got)
	}
	if got.ID != created.ID || got.Name != "t1" || got.Description != "ci pipeline" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "issuer" || got.Roles[1] != "auditor" {
		t.Fatalf("roles round-trip = %v", got.Roles)
	}
	if got.ExpiresAt == nil || got.ExpiresAt.Unix() != future.Unix() {
		t.Fatalf("expiry round-trip = %v, want %v", got.ExpiresAt, future)
	}
	if !got.Active(time.Now()) {
		t.Fatalf("token should be active")
	}

	// Unknown hash → (nil, nil), not an error.
	miss, err := db.GetAPITokenByHash("nope")
	if err != nil || miss != nil {
		t.Fatalf("GetAPITokenByHash(miss) = (%v, %v), want (nil, nil)", miss, err)
	}

	// GetAPIToken by id.
	byID, err := db.GetAPIToken("t1")
	if err != nil || byID == nil {
		t.Fatalf("GetAPIToken: %v", err)
	}
}

func TestAPITokenListScoped(t *testing.T) {
	db := newTokenTestDB(t)
	if err := db.CreateTenant(&models.Tenant{ID: "acme", Slug: "acme", Name: "Acme", Status: models.TenantStatusActive}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	mustCreateToken(t, db, "def-1", models.DefaultTenantID, "h-def-1", nil)
	mustCreateToken(t, db, "acme-1", "acme", "h-acme-1", func(x *models.APIToken) { x.TenantID = "acme" })
	mustCreateToken(t, db, "acme-2", "acme", "h-acme-2", func(x *models.APIToken) { x.TenantID = "acme" })

	all, err := db.ListAPITokens("")
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAPITokens(all) = %d tokens (%v)", len(all), err)
	}
	acme, err := db.ListAPITokens("acme")
	if err != nil || len(acme) != 2 {
		t.Fatalf("ListAPITokens(acme) = %d tokens (%v)", len(acme), err)
	}
	for _, tok := range acme {
		if tok.TenantID != "acme" {
			t.Fatalf("tenant filter leaked token %s from tenant %s", tok.ID, tok.TenantID)
		}
	}
}

func TestAPITokenRevokeIdempotent(t *testing.T) {
	db := newTokenTestDB(t)
	mustCreateToken(t, db, "t1", models.DefaultTenantID, "hash-1", nil)

	now := time.Now().UTC()
	ok, err := db.RevokeAPIToken("t1", "admin", now)
	if err != nil || !ok {
		t.Fatalf("first revoke = (%v, %v), want (true, nil)", ok, err)
	}
	// Second revoke is a no-op (already revoked).
	ok, err = db.RevokeAPIToken("t1", "admin", now)
	if err != nil || ok {
		t.Fatalf("second revoke = (%v, %v), want (false, nil)", ok, err)
	}
	got, _ := db.GetAPIToken("t1")
	if got.RevokedAt == nil || got.Active(time.Now()) {
		t.Fatalf("revoked token still active: %+v", got)
	}
}

func TestAPITokenTouchAndCountActive(t *testing.T) {
	db := newTokenTestDB(t)
	past := time.Now().Add(-time.Hour).UTC()
	mustCreateToken(t, db, "active", models.DefaultTenantID, "h-a", nil)
	mustCreateToken(t, db, "expired", models.DefaultTenantID, "h-e", func(x *models.APIToken) { x.ExpiresAt = &past })
	mustCreateToken(t, db, "revoked", models.DefaultTenantID, "h-r", nil)
	if _, err := db.RevokeAPIToken("revoked", "admin", time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Only the un-revoked, un-expired token counts as active.
	n, err := db.CountActiveAPITokens()
	if err != nil || n != 1 {
		t.Fatalf("CountActiveAPITokens = (%d, %v), want (1, nil)", n, err)
	}

	touchAt := time.Now().UTC()
	if err := db.TouchAPIToken("active", touchAt, "198.51.100.9"); err != nil {
		t.Fatalf("TouchAPIToken: %v", err)
	}
	got, _ := db.GetAPIToken("active")
	if got.LastUsedAt == nil || got.LastUsedIP != "198.51.100.9" {
		t.Fatalf("touch not recorded: %+v", got)
	}
}
