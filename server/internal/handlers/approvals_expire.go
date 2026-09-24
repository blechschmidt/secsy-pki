package handlers

// REST surface for the four-eyes approval expiry sweep (Task 81) — the
// counterpart of `secsy-ca approvals expire` (Task 198).
//
// A request whose approval window has elapsed is treated as expired by the gate
// the moment it is next touched, but until something sweeps it the queue still
// shows it as pending: the console's approval view slowly fills with requests
// that can never execute, and the cert.issue.denied domain event for an expired
// per-profile issuance never fires. The server sweeps on its own schedule; this
// endpoint is the on-demand sweep the CLI already had.

import (
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/issueapproval"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ExpireApprovalsResponse reports how many stale requests were retired. Expired
// carries the same name the CLI's JSON output uses.
type ExpireApprovalsResponse struct {
	// Expired is the number of requests moved from pending/approved to expired by
	// this sweep.
	Expired int `json:"expired"`
	// Enabled echoes whether the approval gate itself is on, so a zero count from
	// a deployment that has since disabled the gate is not mistaken for "nothing
	// to clean up".
	Enabled bool `json:"enabled"`
}

// ExpireApprovals handles POST /api/approvals/expire — the REST form of
// `secsy-ca approvals expire`. It retires every request whose approval window has
// elapsed, firing the same terminal hook the server and the CLI install so the
// cert.issue.denied domain event and metric are emitted for an expired
// per-profile issuance regardless of which surface swept it.
//
// Authorization is the PLATFORM-wide approval:approve capability. The sweep is
// cross-tenant by construction — it walks every expirable request in the
// deployment — so a tenant-scoped approver, who may only decide its own tenant's
// requests, must not be able to trigger it. Like every endpoint in
// approvals.go it reports 503 when the approval workflow was never installed.
func (a *API) ExpireApprovals(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if a.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "the approval workflow is not enabled on this server")
		return
	}
	if !a.can(user, rbac.ActionApprove) {
		a.recordEvent(r, audit.ActionApprovalExpire, "", "", audit.ResultDenied,
			"platform-wide approval:approve capability required")
		writeError(w, http.StatusForbidden, "platform-wide approval:approve capability required")
		return
	}

	// The engine's sweep is a no-op while the gate is disabled. An operator
	// cleaning up requests left behind by a previously-enabled gate still needs it
	// to run, so — exactly as the CLI does — the sweep is driven by a copy of the
	// installed policy with enforcement forced on. Nothing else changes: a sweep
	// can only ever move a request to expired, never authorize an operation.
	pol := a.approvals.Policy()
	enabled := pol.Enabled
	pol.Enabled = true
	eng := approval.NewEngine(a.db, a.db, pol)
	eng.SetTerminalHook(issueapproval.NewTerminalHook(a.db))

	n, err := eng.SweepExpired(r.Context())
	if err != nil {
		a.recordEvent(r, audit.ActionApprovalExpire, "", "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "expiring stale approval requests: %v", err)
		return
	}
	// The engine records one approval.expire event per retired request (the
	// per-request trail). Record the operator-attributed summary only when
	// something actually changed, so polling this endpoint cannot pad the log.
	if n > 0 {
		a.recordEvent(r, audit.ActionApprovalExpire, "", "", audit.ResultSuccess,
			fmt.Sprintf("expired=%d via=api", n))
	}
	writeJSON(w, http.StatusOK, ExpireApprovalsResponse{Expired: n, Enabled: enabled})
}
