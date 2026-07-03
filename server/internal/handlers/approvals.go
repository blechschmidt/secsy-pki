package handlers

// REST surface and the fail-closed chokepoint for the four-eyes / maker-checker
// approval workflow (Task 81). The guard() helper is called at the very start of
// each guarded operation's handler: when the operation is not yet approved it
// records a pending request and answers 202 (the operation does NOT execute);
// once enough distinct approvers have signed off, re-invoking the operation
// consumes the approval and proceeds.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Compile-time guarantee that the concrete store satisfies the engine's
// abstraction; a drifted method breaks the build here rather than at wiring time.
var _ approval.Store = (*database.DB)(nil)

// guard runs the approval gate for a guarded operation about to execute. It
// returns true when the operation may proceed — either the gate is disabled, the
// class is unguarded, or an approved request was consumed. It returns false when
// the operation must NOT execute: a 202 (pending approval) or 500 (gate error)
// has already been written. The caller must have resolved the actor and stamped
// the tenant on the request context (middleware.SetTenant) before calling.
func (a *API) guard(w http.ResponseWriter, r *http.Request, class, resourceKey, resourceName, summary, params, details string) bool {
	if a.approvals == nil {
		return true
	}
	name := ""
	if u := middleware.GetUserInfo(r.Context()); u != nil {
		name = u.Name
	}
	res, err := a.approvals.Guard(r.Context(), approval.GuardRequest{
		Class:        class,
		ResourceKey:  resourceKey,
		ResourceName: resourceName,
		Summary:      summary,
		Params:       params,
		Details:      details,
		Actor:        requestActor(r),
		ActorName:    name,
		Tenant:       middleware.GetTenant(r.Context()),
		IP:           clientIP(r),
	})
	if err != nil {
		// Fail closed: a gate error blocks the operation rather than allowing it.
		writeError(w, http.StatusInternalServerError, "approval gate error: %v", err)
		return false
	}
	if res.Allowed {
		return true
	}
	writeApprovalPending(w, res.Approval)
	return false
}

// writeApprovalPending answers a blocked guarded operation with 202 and the
// request the operator/approvers must act on.
func writeApprovalPending(w http.ResponseWriter, pa *models.PendingApproval) {
	if pa != nil {
		w.Header().Set("X-Secsy-Approval-Id", pa.ID)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":   "pending_approval",
		"message":  approvalPendingMessage(pa),
		"approval": pa,
	})
}

func approvalPendingMessage(pa *models.PendingApproval) string {
	if pa == nil {
		return "operation requires four-eyes approval"
	}
	return fmt.Sprintf("operation held for four-eyes approval: request %s needs %d distinct approver(s) (%d recorded so far); re-run once approved",
		pa.ID, pa.RequiredApprovals, pa.ApprovalsCount)
}

// ListApprovals lists approval requests (GET /api/approvals). A platform
// approval:read capability lists across tenants (optionally filtered by
// ?tenant); a tenant-scoped approver sees only their tenant(s). Filters: status,
// class, limit.
func (a *API) ListApprovals(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if a.approvals == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "requests": []any{}})
		return
	}
	q := r.URL.Query()
	status, class, tenantFilter := q.Get("status"), q.Get("class"), q.Get("tenant")
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	platform := a.decide(user, rbac.ActionReadApproval)
	var scopes []string // tenant ids a tenant-scoped reader may see (nil = all/platform)
	if !platform {
		if user != nil {
			for tid := range user.TenantRoles {
				if rbac.Can(tenantRolesFor(user, tid), rbac.ActionReadApproval) {
					scopes = append(scopes, tid)
				}
			}
		}
		if len(scopes) == 0 {
			writeError(w, http.StatusForbidden, "approval:read capability required")
			return
		}
	}

	var out []models.PendingApproval
	if platform {
		list, err := a.approvals.List(approval.Query{TenantID: tenantFilter, Status: status, Class: class, Limit: limit})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "listing approvals: %v", err)
			return
		}
		out = list
	} else {
		for _, tid := range scopes {
			if tenantFilter != "" && tenantFilter != tid {
				continue
			}
			list, err := a.approvals.List(approval.Query{TenantID: tid, Status: status, Class: class, Limit: limit})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "listing approvals: %v", err)
				return
			}
			out = append(out, list...)
		}
	}
	if out == nil {
		out = []models.PendingApproval{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": a.approvals.Policy().Enabled, "requests": out})
}

// GetApproval returns one request with its full decision log (GET
// /api/approvals/{id}).
func (a *API) GetApproval(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if a.approvals == nil {
		writeError(w, http.StatusNotFound, "the approval workflow is not enabled")
		return
	}
	pa, err := a.approvals.Get(r.PathValue("id"))
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	if !a.decideInTenant(user, pa.TenantID, rbac.ActionReadApproval) {
		writeError(w, http.StatusForbidden, "approval:read capability required")
		return
	}
	writeJSON(w, http.StatusOK, pa)
}

// approvalDecisionRequest is the body of approve/reject.
type approvalDecisionRequest struct {
	Comment string `json:"comment"`
}

// ApproveApproval records the caller's sign-off on a request (POST
// /api/approvals/{id}/approve). Self-approval and repeat votes are refused by
// the engine.
func (a *API) ApproveApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, approval.DecisionApprove)
}

// RejectApproval vetoes a request (POST /api/approvals/{id}/reject).
func (a *API) RejectApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, approval.DecisionReject)
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request, decision string) {
	user := middleware.GetUserInfo(r.Context())
	if a.approvals == nil {
		writeError(w, http.StatusNotFound, "the approval workflow is not enabled")
		return
	}
	id := r.PathValue("id")
	// Resolve the request first so authorization is scoped to its owning tenant.
	pa, err := a.approvals.Get(id)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	middleware.SetTenant(r.Context(), pa.TenantID)

	action := audit.ActionApprovalApprove
	if decision == approval.DecisionReject {
		action = audit.ActionApprovalReject
	}
	// Approve requires the approval:approve capability in the request's tenant.
	// Reject additionally permits the requester to withdraw their own request.
	authorized := a.canInTenant(user, pa.TenantID, rbac.ActionApprove)
	if !authorized && decision == approval.DecisionReject && user != nil && user.Subject == pa.RequestedBy {
		authorized = true
	}
	if !authorized {
		a.recordEvent(r, action, pa.ID, pa.OperationClass+":"+pa.ResourceKey, audit.ResultDenied,
			"approval:approve capability required")
		writeError(w, http.StatusForbidden, "approval:approve capability required")
		return
	}

	var body approvalDecisionRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body) // comment is optional
	}

	name := ""
	if user != nil {
		name = user.Name
	}
	// The engine records the approval.approve/reject (and self-approval-denied)
	// audit events itself, so the handler does not double-record on success.
	if decision == approval.DecisionApprove {
		pa, err = a.approvals.Approve(r.Context(), id, requestActor(r), name, body.Comment, clientIP(r))
	} else {
		pa, err = a.approvals.Reject(r.Context(), id, requestActor(r), name, body.Comment, clientIP(r))
	}
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pa)
}

// writeApprovalError maps engine errors to HTTP status codes.
func writeApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approval.ErrNotFound):
		writeError(w, http.StatusNotFound, "%v", err)
	case errors.Is(err, approval.ErrSelfApproval):
		writeError(w, http.StatusForbidden, "%v", err)
	case errors.Is(err, approval.ErrAlreadyDecided):
		writeError(w, http.StatusConflict, "%v", err)
	case errors.Is(err, approval.ErrExpired):
		writeError(w, http.StatusConflict, "%v", err)
	default:
		var se *approval.StateError
		if errors.As(err, &se) {
			writeError(w, http.StatusConflict, "%v", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
	}
}
