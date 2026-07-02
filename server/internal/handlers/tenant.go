package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// slugPattern constrains a tenant slug to a URL/DNS-safe token so it can be used
// unescaped in public request paths.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// isPlatformAdmin reports whether the user may administer tenants themselves
// (create/list/suspend). Only the root user and holders of a platform-wide admin
// role qualify; a tenant-scoped admin governs resources WITHIN its tenant but
// cannot provision or enumerate other tenants.
func (a *API) isPlatformAdmin(user *models.UserInfo) bool {
	if user == nil {
		return false
	}
	if user.IsRoot {
		return true
	}
	return rbac.HasRole(userRoles(user), rbac.RoleAdmin)
}

// ListTenants returns every tenant. Platform-admin only.
func (a *API) ListTenants(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.isPlatformAdmin(user) {
		writeError(w, http.StatusForbidden, "platform admin required to list tenants")
		return
	}
	tenants, err := a.db.ListTenants()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenants: %v", err)
		return
	}
	if tenants == nil {
		tenants = []models.Tenant{}
	}
	writeJSON(w, http.StatusOK, tenants)
}

// CreateTenant provisions a new tenant. Platform-admin only.
func (a *API) CreateTenant(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.isPlatformAdmin(user) {
		a.recordEvent(r, audit.ActionTenantCreate, "", "", audit.ResultDenied, "platform admin required")
		writeError(w, http.StatusForbidden, "platform admin required to create tenants")
		return
	}

	var req struct {
		Slug     string `json:"slug"`
		Name     string `json:"name"`
		KEKLabel string `json:"kek_label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if !slugPattern.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, "slug must match %s", slugPattern.String())
		return
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	if existing, err := a.db.GetTenantBySlug(req.Slug); err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	} else if existing != nil {
		writeError(w, http.StatusConflict, "a tenant with slug %q already exists", req.Slug)
		return
	}

	t := &models.Tenant{
		ID:       uuid.New().String(),
		Slug:     req.Slug,
		Name:     req.Name,
		Status:   models.TenantStatusActive,
		KEKLabel: req.KEKLabel,
	}
	if err := a.db.CreateTenant(t); err != nil {
		a.recordEvent(r, audit.ActionTenantCreate, t.ID, t.Slug, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create tenant: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionTenantCreate, t.ID, t.Slug, audit.ResultSuccess, "name="+t.Name)
	writeJSON(w, http.StatusCreated, t)
}

// GetTenant returns a single tenant. Platform-admins may read any tenant;
// tenant members may read their own tenant.
func (a *API) GetTenant(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	id := r.PathValue("id")
	t, err := a.db.GetTenant(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	}
	if t == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	if !a.isPlatformAdmin(user) && !a.isTenantMember(user, id) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// SetTenantStatus activates or suspends a tenant. Platform-admin only.
func (a *API) SetTenantStatus(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.isPlatformAdmin(user) {
		writeError(w, http.StatusForbidden, "platform admin required")
		return
	}
	id := r.PathValue("id")
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Status != models.TenantStatusActive && req.Status != models.TenantStatusSuspended {
		writeError(w, http.StatusBadRequest, "status must be active or suspended")
		return
	}
	if id == models.DefaultTenantID && req.Status == models.TenantStatusSuspended {
		writeError(w, http.StatusBadRequest, "the default tenant cannot be suspended")
		return
	}
	if t, err := a.db.GetTenant(id); err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	} else if t == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	if err := a.db.SetTenantStatus(id, req.Status); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update tenant: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionTenantUpdate, id, "", audit.ResultSuccess, "status="+req.Status)
	writeJSON(w, http.StatusOK, map[string]string{"status": req.Status})
}

// DeleteTenant removes an empty tenant. Platform-admin only; the default tenant
// and any tenant that still owns CAs cannot be deleted, so the isolation
// boundary is never left dangling.
func (a *API) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.isPlatformAdmin(user) {
		writeError(w, http.StatusForbidden, "platform admin required")
		return
	}
	id := r.PathValue("id")
	if id == models.DefaultTenantID {
		writeError(w, http.StatusBadRequest, "the default tenant cannot be deleted")
		return
	}
	n, err := a.db.CountCAsForTenant(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "tenant still owns %d CA(s); delete them first", n)
		return
	}
	if err := a.db.DeleteTenant(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete tenant: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionTenantDelete, id, "", audit.ResultSuccess, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
