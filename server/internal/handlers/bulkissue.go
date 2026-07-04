package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// BulkIssueCertificates is the mass device/service provisioning endpoint
// (Task 101): POST /api/ca/{id}/certificates:bulk.
//
// It accepts an array of independent issue requests (CSR + profile + validity)
// and issues each under the CA's HSM key, returning a per-item result so a
// partial failure never discards the successes. Every item passes the full
// per-issuance gate stack individually — it flows through the same
// ca.Manager.IssueCertificate path a single POST /issue call uses (lint, CAA,
// name constraints, certificate policies, the CEL policy gate, CT, and the
// tenant lifecycle + daily-quota reservation). An item whose profile requires
// manual four-eyes approval (Task 84) is parked and reported "pending" rather
// than failing the batch; the certificate is fetched later from
// /api/approvals/{id}/certificate once approvers sign off.
//
// Authorization deliberately differs from bulk REVOCATION (Task 70): mass
// revocation is an incident-response CA-management operation (ca:manage,
// step-up), whereas mass issuance is provisioning — it requires exactly the
// issue capability a single /issue call needs, so a provisioning service account
// can drive it. The guard against accidental mass issuance is the mandatory
// confirm_count (which must equal the number of items) plus the per-profile
// approval gate for sensitive profiles, not a heavier role.
//
// A dry_run body validates every item (CSR + profile) and returns the plan
// without issuing or parking anything. A real run must carry confirm_count equal
// to the number of items; a mismatch is refused with 409.
func (a *API) BulkIssueCertificates(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	// Resolve and pin the owning tenant up front so authorization, the parked
	// approvals, and the audit events are all attributed to it.
	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error: %v", err)
		return
	}
	if tenantID == "" {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	middleware.SetTenant(r.Context(), tenantID)

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.IssuanceBulk.Inc(metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertIssueBulk, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.BulkIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items is required and must contain at least one certificate request")
		return
	}
	if len(req.Items) > ca.MaxBulkIssueItems {
		writeError(w, http.StatusBadRequest,
			"batch of %d items exceeds the maximum of %d; split it into smaller batches", len(req.Items), ca.MaxBulkIssueItems)
		return
	}

	spec := ca.BulkIssueSpec{
		CAID:        caID,
		RequestedBy: user.Subject,
		OperationID: req.OperationID,
		Concurrency: req.Concurrency,
		Items:       make([]ca.BulkIssueItem, len(req.Items)),
	}
	for i, it := range req.Items {
		spec.Items[i] = ca.BulkIssueItem{
			Ref:     it.Ref,
			CSRPEM:  []byte(it.CSR),
			Profile: it.Profile,
			// Cap each item's requested validity by the global policy maximum, so a
			// batch cannot exceed what a single /issue call could ask for.
			ValidityDays: a.capValidityDays(it.ValidityDays),
		}
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	issuer := ca.NewBulkIssuer(mgr, ca.BulkIssuerConfig{
		ApprovalGate: a.bulkIssueApprovalGate(caID, user, clientIP(r)),
	})

	if req.DryRun {
		plan, err := issuer.Preview(r.Context(), spec)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bulk issuance preview failed: %v", err)
			return
		}
		writeJSON(w, http.StatusOK, plan)
		return
	}

	// The mandatory-confirmation contract: an execution without the item count is
	// refused outright, so no client can skip the deliberate confirmation of how
	// many certificates it intends to issue.
	if req.ConfirmCount == nil {
		writeError(w, http.StatusBadRequest,
			"confirm_count is required: set it to the number of items you intend to issue (%d)", len(req.Items))
		return
	}
	spec.ConfirmCount = *req.ConfirmCount

	a.consumeHSMAuditLogs("")
	result, err := issuer.Execute(r.Context(), spec)
	a.consumeHSMAuditLogs("")
	if err != nil {
		var mismatch *ca.BulkIssueCountMismatchError
		if errors.As(err, &mismatch) {
			a.recordEvent(r, audit.ActionCertIssueBulk, caID, "", audit.ResultDenied,
				fmt.Sprintf("confirm_count=%d actual=%d (re-confirm the item count)", mismatch.Confirmed, mismatch.Actual))
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":         mismatch.Error(),
				"confirm_count": mismatch.Confirmed,
				"actual_count":  mismatch.Actual,
			})
			return
		}
		// Whole-operation failure (empty/oversized batch, non-existent CA). The
		// engine already counted the error metric; no items were issued.
		a.recordEvent(r, audit.ActionCertIssueBulk, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "bulk issuance failed: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// bulkIssueApprovalGate adapts the transport-agnostic per-profile issuance-
// approval gate (Task 84) into the ca.BulkIssueApprovalGate callback the batch
// engine consults per item. When the engine has no approval engine installed,
// a.IssuanceApprovalGate reports the item ungated and it is issued immediately.
// The gate parks (never issues) and emits the cert.issue.pending event/metric
// itself, so the engine records the item "pending" without double-auditing.
func (a *API) bulkIssueApprovalGate(caID string, user *models.UserInfo, ip string) ca.BulkIssueApprovalGate {
	if a.approvals == nil {
		return nil // no gate installed: the engine issues every item immediately
	}
	return func(ctx context.Context, item ca.BulkIssueItem) (ca.BulkIssueGateResult, error, error) {
		pa, gated, clientErr, gateErr := a.IssuanceApprovalGate(
			ctx, caID, item.Profile, string(item.CSRPEM), item.ValidityDays, user, ip)
		if clientErr != nil {
			return ca.BulkIssueGateResult{}, clientErr, nil
		}
		if gateErr != nil {
			return ca.BulkIssueGateResult{}, nil, gateErr
		}
		if !gated {
			return ca.BulkIssueGateResult{Gated: false}, nil, nil
		}
		return ca.BulkIssueGateResult{
			Gated:             true,
			ApprovalID:        pa.ID,
			RequiredApprovals: pa.RequiredApprovals,
			ApprovalsCount:    pa.ApprovalsCount,
		}, nil, nil
	}
}
