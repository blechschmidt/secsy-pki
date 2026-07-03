//go:build sqlite

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func platformAdmin() *models.UserInfo {
	return &models.UserInfo{Subject: "padmin", Roles: []string{"admin"}}
}

// TestCreateTokenReturnsSecretOnce mints a token and proves the secret is
// returned exactly once and only its hash is persisted.
func TestCreateTokenReturnsSecretOnce(t *testing.T) {
	api, db := tenantAPI(t)

	body := `{"name":"ci","roles":["issuer"],"scope":"tenant"}`
	rec := httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", rootUser(), "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
		Prefix string `json:"prefix"`
		Roles  []string
		Scope  string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !authn.LooksLikeToken(resp.Secret) {
		t.Fatalf("response secret %q is not a secsy token", resp.Secret)
	}
	// The stored record holds only the hash of the secret, never the plaintext.
	stored, err := db.GetAPIToken(resp.ID)
	if err != nil || stored == nil {
		t.Fatalf("GetAPIToken: %v", err)
	}
	if stored.TokenHash != authn.HashToken(resp.Secret) {
		t.Fatalf("stored hash does not match the returned secret")
	}
	if stored.TokenHash == resp.Secret {
		t.Fatalf("plaintext secret must never be stored")
	}
	// And the same secret authenticates.
	if _, err := authn.NewTokenAuthenticator(db).Verify(resp.Secret, ""); err != nil {
		t.Fatalf("minted token failed to verify: %v", err)
	}
}

// TestCreateTokenRBAC proves non-admins cannot mint tokens and that a tenant
// admin cannot escalate to a platform-scoped token.
func TestCreateTokenRBAC(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "acme")

	// An issuer (non-admin) is denied.
	rec := httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens",
		&models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, "", `{"name":"x","roles":["issuer"]}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("issuer create: status = %d, want 403", rec.Code)
	}

	// A tenant admin may mint a token within its tenant…
	tadmin := tenantUser("tadmin", "acme", "admin")
	rec = httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", tadmin, "", `{"name":"a","roles":["issuer"],"tenant_id":"acme"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant-admin create: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// …but not a platform-scoped one (privilege escalation), nor a token in
	// another tenant.
	rec = httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", tadmin, "", `{"name":"p","roles":["admin"],"scope":"platform"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-admin platform create: status = %d, want 403", rec.Code)
	}
	rec = httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", tadmin, "", `{"name":"o","roles":["issuer"],"tenant_id":"default"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-admin cross-tenant create: status = %d, want 403", rec.Code)
	}
}

// TestCreateTokenValidation rejects bad input.
func TestCreateTokenValidation(t *testing.T) {
	api, _ := tenantAPI(t)
	cases := []string{
		`{"roles":["issuer"]}`,                             // missing name
		`{"name":"x"}`,                                     // no roles
		`{"name":"x","roles":["wizard"]}`,                  // unknown role
		`{"name":"x","roles":["issuer"],"scope":"galaxy"}`, // bad scope
	}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", rootUser(), "", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}

// TestTokenLifetimePolicy enforces the configured maximum lifetime.
func TestTokenLifetimePolicy(t *testing.T) {
	api, db := tenantAPI(t)
	api.SetAPITokenMaxLifetime(7 * 24 * time.Hour)

	// Over the cap is rejected.
	rec := httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", rootUser(), "", `{"name":"x","roles":["issuer"],"expires_in_days":30}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-cap: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	// Unspecified expiry defaults to the cap (not "never").
	rec = httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", rootUser(), "", `{"name":"y","roles":["issuer"]}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("default expiry: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	tok, _ := db.GetAPIToken(resp.ID)
	if tok.ExpiresAt == nil {
		t.Fatalf("expected a capped expiry, got a non-expiring token")
	}
}

// TestListTokensScoping proves the list is scoped and never leaks secrets.
func TestListTokensScoping(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "acme")
	// Two default-tenant tokens and one acme token.
	mustHandlerCreate(t, api, rootUser(), `{"name":"d1","roles":["issuer"]}`)
	mustHandlerCreate(t, api, rootUser(), `{"name":"d2","roles":["auditor"]}`)
	mustHandlerCreate(t, api, rootUser(), `{"name":"a1","roles":["issuer"],"tenant_id":"acme"}`)

	// Platform admin sees all three.
	rec := httptest.NewRecorder()
	api.ListTokens(rec, reqAs(http.MethodGet, "/api/tokens", platformAdmin(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list all: status = %d", rec.Code)
	}
	if got := countTokens(t, rec); got != 3 {
		t.Fatalf("platform admin list = %d tokens, want 3", got)
	}
	// The raw JSON must never contain a hash field or a secret.
	if body := rec.Body.String(); strings.Contains(body, "token_hash") || strings.Contains(body, `"secret"`) {
		t.Fatalf("list leaked a hash or secret: %s", body)
	}

	// A tenant admin of acme sees only the acme token.
	rec = httptest.NewRecorder()
	api.ListTokens(rec, reqAs(http.MethodGet, "/api/tokens", tenantUser("ta", "acme", "admin"), "", ""))
	if got := countTokens(t, rec); got != 1 {
		t.Fatalf("tenant admin list = %d tokens, want 1", got)
	}
}

// TestRevokeToken covers the revoke lifecycle and its authorization.
func TestRevokeToken(t *testing.T) {
	api, db := tenantAPI(t)
	id := mustHandlerCreate(t, api, rootUser(), `{"name":"r","roles":["issuer"]}`)

	// Non-admin cannot revoke.
	rec := httptest.NewRecorder()
	api.RevokeToken(rec, reqAs(http.MethodDelete, "/api/tokens/"+id, &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, id, ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin revoke: status = %d, want 403", rec.Code)
	}

	// Admin revokes.
	rec = httptest.NewRecorder()
	api.RevokeToken(rec, reqAs(http.MethodDelete, "/api/tokens/"+id, rootUser(), id, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	tok, _ := db.GetAPIToken(id)
	if !tok.Revoked() {
		t.Fatalf("token not marked revoked")
	}
	// Second revoke is idempotent.
	rec = httptest.NewRecorder()
	api.RevokeToken(rec, reqAs(http.MethodDelete, "/api/tokens/"+id, rootUser(), id, ""))
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp["status"] != "already_revoked" {
		t.Fatalf("second revoke = %d %v, want 200 already_revoked", rec.Code, resp)
	}

	// Unknown id → 404.
	rec = httptest.NewRecorder()
	api.RevokeToken(rec, reqAs(http.MethodDelete, "/api/tokens/nope", rootUser(), "nope", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown revoke: status = %d, want 404", rec.Code)
	}
}

// TestCreateSensitiveTokenFourEyes proves a sensitive grant is held for
// four-eyes approval and minted only after the approver threshold is met.
func TestCreateSensitiveTokenFourEyes(t *testing.T) {
	api, db := tenantAPI(t)
	eng := approval.NewEngine(db, db, approval.Policy{Enabled: true, DefaultThreshold: 2, TTL: 72 * time.Hour})
	api.SetApprovals(eng)

	body := `{"name":"admin-bot","roles":["admin"],"scope":"platform"}`

	// 1) Held for approval (202), not minted.
	rec := httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", platformAdmin(), "", body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("sensitive create: status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	approvalID := rec.Header().Get("X-Secsy-Approval-Id")
	if approvalID == "" {
		t.Fatal("202 must carry X-Secsy-Approval-Id")
	}
	if toks, _ := db.ListAPITokens(""); len(toks) != 0 {
		t.Fatalf("no token should exist before approval, found %d", len(toks))
	}

	// 2) Two distinct approvers (neither is the maker) sign off.
	ctx := context.Background()
	if _, err := eng.Approve(ctx, approvalID, "approver-1", "", "", ""); err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	if _, err := eng.Approve(ctx, approvalID, "approver-2", "", "", ""); err != nil {
		t.Fatalf("approve 2: %v", err)
	}

	// 3) Re-run the identical request: the approval is consumed and the token is
	// minted.
	rec = httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", platformAdmin(), "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("post-approval create: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if toks, _ := db.ListAPITokens(""); len(toks) != 1 {
		t.Fatalf("exactly one token should exist after approval, found %d", len(toks))
	}
}

// --- test helpers ---

func mustHandlerCreate(t *testing.T, api *API, user *models.UserInfo, body string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	api.CreateToken(rec, reqAs(http.MethodPost, "/api/tokens", user, "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s: status = %d, want 201; body=%s", body, rec.Code, rec.Body.String())
	}
	var resp struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.ID
}

func countTokens(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	var toks []models.APIToken
	if err := json.Unmarshal(rec.Body.Bytes(), &toks); err != nil {
		t.Fatalf("decode token list: %v (body=%s)", err, rec.Body.String())
	}
	return len(toks)
}
