package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Native scoped API tokens / service accounts (Task 86).
//
// These endpoints let an administrator mint, list, and revoke long-lived
// machine credentials bound to a set of RBAC roles and a tenant scope. Managing
// tokens is an administrative capability (token:manage, admin-only): a token can
// carry any role, so permitting a lesser role to mint tokens would let it
// escalate its own privilege. Tenant admins manage tokens within their tenant;
// platform (cross-tenant) tokens require a platform administrator. When the
// four-eyes gate is enabled, minting a token with a sensitive grant (a
// privileged role or platform scope) additionally requires approver sign-off.

// createTokenRequest is the POST /api/tokens body.
type createTokenRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Roles         []string `json:"roles"`
	TenantID      string   `json:"tenant_id,omitempty"` // id or slug; default tenant when empty
	Scope         string   `json:"scope,omitempty"`     // "tenant" (default) or "platform"
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
}

// apiTokenWithSecret carries the created token together with its one-time secret.
// The secret is present only in the create response and never persisted or
// returned again; the embedded model's token hash is json:"-".
type apiTokenWithSecret struct {
	*models.APIToken
	Secret string `json:"secret"`
}

// CreateToken mints a new scoped API token and returns its secret exactly once.
func (a *API) CreateToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	roles, err := normalizeTokenRoles(req.Roles)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Resolve scope, owning tenant, and the authorization required to grant them.
	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = models.TokenScopeTenant
	}
	var tenantID string
	switch scope {
	case models.TokenScopePlatform:
		// A platform (cross-tenant) token is inherently privileged: only a platform
		// administrator may mint one.
		if !a.isPlatformAdmin(user) {
			a.recordEvent(r, audit.ActionTokenCreate, "", req.Name, audit.ResultDenied, "platform-scoped token requires a platform administrator")
			metrics.RecordAuthTokenOpDenied("create")
			writeError(w, http.StatusForbidden, "creating a platform-scoped token requires a platform administrator")
			return
		}
		tenantID = models.DefaultTenantID
	case models.TokenScopeTenant:
		resolved, ok := a.resolveTenantRef(w, req.TenantID)
		if !ok {
			return
		}
		tenantID = resolved
		middleware.SetTenant(r.Context(), tenantID)
		if !a.canInTenant(user, tenantID, rbac.ActionManageTokens) {
			a.recordEvent(r, audit.ActionTokenCreate, "", req.Name, audit.ResultDenied, "token:manage capability required in tenant "+tenantID)
			metrics.RecordAuthTokenOpDenied("create")
			writeError(w, http.StatusForbidden, "token:manage capability (admin role) required for tenant %q", tenantID)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "scope must be %q or %q", models.TokenScopeTenant, models.TokenScopePlatform)
		return
	}

	// Enforce the configured lifetime policy on the requested expiry.
	lifetimeDays, err := authn.ResolveTokenLifetimeDays(a.apiTokenMaxLifetime, req.ExpiresInDays)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Four-eyes gate: a sensitive grant (privileged role or platform scope) may
	// require approver sign-off. The fingerprint pins the exact grant using the
	// relative lifetime (not an absolute timestamp) so a re-run after approval
	// matches. A read-only, tenant-scoped grant is not sensitive and is not gated.
	if tokenGrantIsSensitive(roles, scope) {
		summary := fmt.Sprintf("Create %s-scoped API token %q with roles [%s]", scope, req.Name, strings.Join(roles, ","))
		params := fmt.Sprintf("name=%s;scope=%s;tenant=%s;roles=%s;lifetime_days=%d",
			req.Name, scope, tenantID, strings.Join(roles, ","), lifetimeDays)
		if !a.guard(w, r, approval.ClassTokenCreate, "token:new:"+tenantID+":"+req.Name, req.Name, summary, params, "") {
			return
		}
	}

	// Mint: the secret exists only here and in the response.
	secret, hash, prefix := authn.GenerateToken()
	tok := &models.APIToken{
		ID:            uuid.New().String(),
		TenantID:      tenantID,
		Name:          req.Name,
		Description:   strings.TrimSpace(req.Description),
		Prefix:        prefix,
		TokenHash:     hash,
		Roles:         roles,
		Scope:         scope,
		CreatedBy:     requestActor(r),
		CreatedByName: userDisplayName(user),
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     lifetimeToExpiry(lifetimeDays),
	}
	if err := a.db.CreateAPIToken(tok); err != nil {
		a.recordEvent(r, audit.ActionTokenCreate, tok.ID, tok.Name, audit.ResultError, err.Error())
		metrics.RecordAuthTokenOp("create", false)
		writeError(w, http.StatusInternalServerError, "failed to create token: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionTokenCreate, tok.ID, tok.Name, audit.ResultSuccess,
		fmt.Sprintf("scope=%s roles=%s tenant=%s expires=%s", scope, strings.Join(roles, ","), tenantID, expiryLabel(tok.ExpiresAt)))
	metrics.RecordAuthTokenOp("create", true)
	a.refreshTokenGauge()

	writeJSON(w, http.StatusCreated, apiTokenWithSecret{APIToken: tok, Secret: secret})
}

// ListTokens returns the tokens the caller is authorized to manage. A platform
// administrator sees all tokens (optionally filtered by ?tenant=); a tenant
// admin sees only the tokens of tenants it administers. Secrets and hashes are
// never included.
func (a *API) ListTokens(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	tenantFilter := r.URL.Query().Get("tenant")

	var out []models.APIToken
	if a.isPlatformAdmin(user) {
		list, err := a.db.ListAPITokens(tenantFilter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list tokens: %v", err)
			return
		}
		out = list
	} else {
		scopes := a.tenantsWithTokenAdmin(user)
		if len(scopes) == 0 {
			writeError(w, http.StatusForbidden, "token:manage capability (admin role) required")
			return
		}
		for _, tid := range scopes {
			if tenantFilter != "" && tenantFilter != tid {
				continue
			}
			list, err := a.db.ListAPITokens(tid)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to list tokens: %v", err)
				return
			}
			out = append(out, list...)
		}
	}
	if out == nil {
		out = []models.APIToken{}
	}
	writeJSON(w, http.StatusOK, out)
}

// RevokeToken revokes a token by id. Revocation is deliberately NOT four-eyes
// gated: it is a de-escalation (it removes access) and must stay fast for
// incident response, mirroring how single-certificate revocation is handled.
func (a *API) RevokeToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	id := r.PathValue("id")

	tok, err := a.db.GetAPIToken(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token lookup failed: %v", err)
		return
	}
	if tok == nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	middleware.SetTenant(r.Context(), tok.TenantID)
	if !a.canManageToken(user, tok) {
		a.recordEvent(r, audit.ActionTokenRevoke, tok.ID, tok.Name, audit.ResultDenied, "token:manage capability required")
		metrics.RecordAuthTokenOpDenied("revoke")
		writeError(w, http.StatusForbidden, "token:manage capability (admin role) required")
		return
	}

	changed, err := a.db.RevokeAPIToken(id, requestActor(r), time.Now().UTC())
	if err != nil {
		a.recordEvent(r, audit.ActionTokenRevoke, tok.ID, tok.Name, audit.ResultError, err.Error())
		metrics.RecordAuthTokenOp("revoke", false)
		writeError(w, http.StatusInternalServerError, "failed to revoke token: %v", err)
		return
	}
	if !changed {
		// Already revoked — report idempotently without a duplicate audit event.
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_revoked"})
		return
	}
	a.recordEvent(r, audit.ActionTokenRevoke, tok.ID, tok.Name, audit.ResultSuccess, "scope="+tok.Scope)
	metrics.RecordAuthTokenOp("revoke", true)
	a.refreshTokenGauge()
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- helpers ---

// normalizeTokenRoles validates, de-duplicates, and sorts the requested roles.
// An unknown role name is rejected so a typo cannot silently grant nothing (or,
// worse, be interpreted loosely elsewhere). At least one role is required.
func normalizeTokenRoles(in []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range in {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !rbac.ValidRole(rbac.Role(name)) {
			return nil, fmt.Errorf("unknown role %q (valid: admin, issuer, signer, auditor, approver)", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one role is required")
	}
	sort.Strings(out)
	return out, nil
}

// tokenGrantIsSensitive reports whether minting a token with these roles and
// scope is a meaningful privilege escalation that the four-eyes gate should
// cover: any platform (cross-tenant) grant, or any privileged role.
func tokenGrantIsSensitive(roles []string, scope string) bool {
	if scope == models.TokenScopePlatform {
		return true
	}
	typed := make([]rbac.Role, len(roles))
	for i, r := range roles {
		typed[i] = rbac.Role(r)
	}
	return rbac.AnyPrivilegedRole(typed)
}

// lifetimeToExpiry converts an effective lifetime in days to an absolute expiry,
// or nil when the token never expires.
func lifetimeToExpiry(days int) *time.Time {
	if days <= 0 {
		return nil
	}
	t := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

// expiryLabel renders an expiry for the audit trail.
func expiryLabel(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// canManageToken reports whether the user may administer a specific token:
// platform tokens require a platform admin; tenant tokens require token:manage
// within the token's tenant.
func (a *API) canManageToken(user *models.UserInfo, tok *models.APIToken) bool {
	if tok.IsPlatform() {
		return a.isPlatformAdmin(user)
	}
	return a.canInTenant(user, tok.TenantID, rbac.ActionManageTokens)
}

// tenantsWithTokenAdmin returns the tenant ids in which the (non-platform-admin)
// user holds the token:manage capability.
func (a *API) tenantsWithTokenAdmin(user *models.UserInfo) []string {
	if user == nil {
		return nil
	}
	var out []string
	for tid := range user.TenantRoles {
		if rbac.Can(tenantRolesFor(user, tid), rbac.ActionManageTokens) {
			out = append(out, tid)
		}
	}
	sort.Strings(out)
	return out
}

// resolveTenantRef resolves a tenant id-or-slug (empty = default tenant) to a
// tenant id, writing a 4xx and returning ok=false on an unknown tenant.
func (a *API) resolveTenantRef(w http.ResponseWriter, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return models.DefaultTenantID, true
	}
	t, err := a.db.GetTenant(ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return "", false
	}
	if t == nil {
		if t, err = a.db.GetTenantBySlug(ref); err != nil {
			writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
			return "", false
		}
	}
	if t == nil {
		writeError(w, http.StatusBadRequest, "unknown tenant %q", ref)
		return "", false
	}
	return t.ID, true
}

// refreshTokenGauge republishes the active-token count metric after a lifecycle
// change. A read error is non-fatal — the gauge is advisory.
func (a *API) refreshTokenGauge() {
	if n, err := a.db.CountActiveAPITokens(); err == nil {
		metrics.SetAuthTokensActive(n)
	}
}

// userDisplayName returns a best-effort human name for the actor.
func userDisplayName(user *models.UserInfo) string {
	if user == nil {
		return ""
	}
	return user.Name
}
