package handlers

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// userRoles returns the RBAC roles the user holds as typed rbac.Role values.
func userRoles(user *models.UserInfo) []rbac.Role {
	if user == nil {
		return nil
	}
	roles := make([]rbac.Role, 0, len(user.Roles))
	for _, r := range user.Roles {
		roles = append(roles, rbac.Role(r))
	}
	return roles
}

// can reports whether the user is authorized for a coarse-grained action. The
// built-in root user is always a superuser; otherwise the user's RBAC roles are
// consulted. Note this is the ORG-WIDE layer: fine-grained, per-CA permission
// checks (checkPermission) still apply independently where relevant.
func (a *API) can(user *models.UserInfo, action rbac.Action) bool {
	allowed := a.decide(user, action)
	metrics.RecordAuthz(string(action), allowed)
	return allowed
}

// decide is the pure authorization decision, split out from can so the metric
// is recorded exactly once around the real decision (and can be reused without
// double-counting).
func (a *API) decide(user *models.UserInfo, action rbac.Action) bool {
	if user == nil {
		return false
	}
	if user.IsRoot {
		return true
	}
	return rbac.Can(userRoles(user), action)
}

// tenantRolesFor returns the roles the user holds WITHIN a specific tenant as
// typed rbac.Role values.
func tenantRolesFor(user *models.UserInfo, tenantID string) []rbac.Role {
	if user == nil || tenantID == "" {
		return nil
	}
	names := user.TenantRoles[tenantID]
	roles := make([]rbac.Role, 0, len(names))
	for _, r := range names {
		roles = append(roles, rbac.Role(r))
	}
	return roles
}

// canInTenant reports whether the user may perform action against resources of
// the given tenant. Authority comes from being root, holding a PLATFORM-wide
// role (which applies in every tenant), or holding the capability via a role
// WITHIN that specific tenant. A principal with roles only in another tenant is
// therefore denied — the core cross-tenant isolation check. A metric is recorded
// exactly once per decision.
func (a *API) canInTenant(user *models.UserInfo, tenantID string, action rbac.Action) bool {
	allowed := a.decideInTenant(user, tenantID, action)
	metrics.RecordAuthz(string(action), allowed)
	return allowed
}

func (a *API) decideInTenant(user *models.UserInfo, tenantID string, action rbac.Action) bool {
	if user == nil {
		return false
	}
	if user.IsRoot {
		return true
	}
	if rbac.Can(userRoles(user), action) { // platform-wide roles span all tenants
		return true
	}
	return rbac.Can(tenantRolesFor(user, tenantID), action)
}

// isTenantMember reports whether the user has any standing in the tenant: root,
// a platform role, or at least one tenant-scoped role. It gates read visibility
// of a tenant's resources.
func (a *API) isTenantMember(user *models.UserInfo, tenantID string) bool {
	if user == nil {
		return false
	}
	if user.IsRoot || len(user.Roles) > 0 {
		return true
	}
	return len(user.TenantRoles[tenantID]) > 0
}

// canRead gates read-only inventory/listing endpoints (CA inventory, issued and
// revoked certificates, groups and their members, restriction-set policy). Any
// assigned role — admin, issuer, or auditor — may read; an authenticated
// principal holding NO role is denied (deny-by-default). All three roles carry
// the audit:read capability, so it is the natural gate for read visibility.
// Mutating endpoints remain gated by their specific capability.
func (a *API) canRead(user *models.UserInfo) bool {
	allowed := a.canReadAnyTenant(user)
	metrics.RecordAuthz(string(rbac.ActionReadAudit), allowed)
	return allowed
}

// canReadAnyTenant reports whether the user may read in at least one scope:
// root, a platform read capability, or an audit:read-bearing role in any tenant.
// Per-resource handlers still narrow visibility to the specific tenant via
// isTenantMember / authorizeCARead, so this only decides whether the principal
// has any read standing at all.
func (a *API) canReadAnyTenant(user *models.UserInfo) bool {
	if a.decide(user, rbac.ActionReadAudit) {
		return true
	}
	if user == nil {
		return false
	}
	for tid := range user.TenantRoles {
		if rbac.Can(tenantRolesFor(user, tid), rbac.ActionReadAudit) {
			return true
		}
	}
	return false
}

// canIssueOn reports whether the user may perform issuing/signing operations on
// a specific CA. It first resolves the CA's owning tenant and records it on the
// request context so any resulting audit event is attributed to that tenant.
// Access is satisfied by the issue capability WITHIN the CA's tenant (a
// platform/tenant issuer role) OR a per-CA SIGN_CERTIFICATE grant. A principal
// whose roles live in a different tenant is denied here — this is where
// cross-tenant issuance is blocked. Restriction sets are still enforced
// downstream regardless of how access was granted.
func (a *API) canIssueOn(ctx context.Context, user *models.UserInfo, caID string) (bool, error) {
	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		return false, err
	}
	if tenantID != "" {
		middleware.SetTenant(ctx, tenantID)
	}
	if tenantID == "" {
		// The CA does not exist. Preserve prior behavior: a platform issuer may
		// proceed so the downstream manager returns a clean not-found; a
		// tenant-scoped principal is denied rather than allowed to probe.
		return a.can(user, rbac.ActionIssue), nil
	}
	if a.canInTenant(user, tenantID, rbac.ActionIssue) {
		return true, nil
	}
	return a.checkPermission(user, caID, models.PermSignCertificate)
}

// clientIP extracts the best-effort client IP, honoring X-Forwarded-For when
// present (the deployment is expected to terminate TLS at a trusted proxy).
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// recordEvent appends a sealed entry to the tamper-evident audit event log. It
// captures who (from the request context), what, the target, and the result. A
// storage failure is logged but never fails the request — losing the response
// because the log write failed would be worse than a best-effort append, and
// the chain's integrity is independent of any single missing external effect.
func (a *API) recordEvent(r *http.Request, action, target, targetName, result, detail string) {
	user := middleware.GetUserInfo(r.Context())
	e := &audit.Event{
		ID:         uuid.New().String(),
		Action:     action,
		Tenant:     middleware.GetTenant(r.Context()),
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
		RequestID:  middleware.RequestID(r.Context()),
	}
	if user != nil {
		e.Actor = user.Subject
		e.ActorName = user.Name
		if user.IsRoot {
			e.ActorRoles = "root"
		} else {
			e.ActorRoles = rbac.JoinRoles(userRoles(user))
		}
	}
	if err := a.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append audit event %q: %v", action, err)
	}
}

// ListEventLog serves the tamper-evident event log (newest first). Readable by
// admins, auditors, and issuers (audit:read capability).
func (a *API) ListEventLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	action := r.URL.Query().Get("action")
	actor := r.URL.Query().Get("actor")
	// Tenant scoping: a platform operator (root or a platform-wide role) may read
	// across tenants, optionally narrowing with ?tenant=. A tenant-scoped
	// principal is confined to the single tenant it belongs to and cannot widen
	// the view — the audit-read isolation guarantee.
	tenantFilter := r.URL.Query().Get("tenant")
	if !user.IsRoot && len(user.Roles) == 0 {
		member := user.TenantsWithRoles()
		switch len(member) {
		case 0:
			writeError(w, http.StatusForbidden, "no tenant membership")
			return
		case 1:
			tenantFilter = member[0]
		default:
			// A subject scoped to several tenants must name which one to read.
			if tenantFilter == "" {
				writeError(w, http.StatusBadRequest, "tenant query parameter is required")
				return
			}
			if len(user.TenantRoles[tenantFilter]) == 0 {
				writeError(w, http.StatusForbidden, "not a member of tenant %q", tenantFilter)
				return
			}
		}
	}
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	entries, total, err := a.db.ListEvents(action, actor, tenantFilter, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query event log: %v", err)
		return
	}
	if entries == nil {
		entries = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// VerifyEventLog recomputes the event-log hash chain and reports whether it is
// intact. This is the tamper-evidence check: any modification, deletion, or
// reordering of historical entries surfaces here.
func (a *API) VerifyEventLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	result, err := a.db.VerifyEventChain()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to verify event log: %v", err)
		return
	}
	status := http.StatusOK
	if !result.Valid {
		// 409 signals the log's integrity is compromised — an operational alarm.
		status = http.StatusConflict
	}
	writeJSON(w, status, result)
}
