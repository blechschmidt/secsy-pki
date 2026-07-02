package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
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
	if user == nil {
		return false
	}
	if user.IsRoot {
		return true
	}
	return rbac.Can(userRoles(user), action)
}

// canIssueOn reports whether the user may perform issuing/signing operations on
// a specific CA. This is satisfied by the org-wide issue capability (admin or
// issuer role) OR a per-CA SIGN_CERTIFICATE grant. Restriction sets are still
// enforced downstream regardless of how access was granted.
func (a *API) canIssueOn(user *models.UserInfo, caID string) (bool, error) {
	if a.can(user, rbac.ActionIssue) {
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
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
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
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	action := r.URL.Query().Get("action")
	actor := r.URL.Query().Get("actor")
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

	entries, total, err := a.db.ListEvents(action, actor, limit, offset)
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
