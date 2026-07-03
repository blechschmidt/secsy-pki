package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// BulkRevokeCertificates is the incident-response mass-revocation endpoint
// (Task 70): POST /api/ca/{id}/revocations:bulk.
//
// It is deliberately privileged above single revocation: revoking one
// certificate needs the CA's issue capability, but revoking a whole selection
// is a CA-management operation (ca:manage) and is additionally step-up gated
// ("cert.revoke_bulk") for console sessions. The endpoint is an authenticated
// internal path — it is not classified by the public rate limiter, and the
// engine never consults tenant quotas or suspension: a suspended or over-quota
// tenant's certificates must always be revocable within the CA/B 24-hour
// window.
//
// A dry_run body returns the plan (counts + sample) without changing anything.
// A real run must carry confirm_count equal to the dry-run total; when the
// live selection has drifted (concurrent issuance or revocation), the request
// is refused with 409 and the fresh count so the operator re-confirms.
func (a *API) BulkRevokeCertificates(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

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
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		metrics.RevocationsBulk.Inc(metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertRevokeBulk, caID, "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "bulk revocation requires the ca:manage capability for tenant %q", tenantID)
		return
	}

	var req models.BulkRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	spec := ca.BulkRevokeSpec{
		CAID: caID,
		Filter: ca.BulkRevokeFilter{
			Profile:        req.Filter.Profile,
			Pattern:        req.Filter.Pattern,
			IssuedAfter:    req.Filter.IssuedAfter,
			IssuedBefore:   req.Filter.IssuedBefore,
			Serials:        req.Filter.Serials,
			IncludeExpired: req.Filter.IncludeExpired,
		},
		Reason:      req.Reason,
		RequestedBy: user.Subject,
		OperationID: req.OperationID,
		BatchSize:   req.BatchSize,
		ConfirmCount: func() int {
			if req.ConfirmCount != nil {
				return *req.ConfirmCount
			}
			return -1
		}(),
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	revoker := ca.NewBulkRevoker(mgr, ca.BulkRevokerConfig{
		Cache:     a.ocspCache,
		Presigner: a.ocspPresigner,
	})

	if req.DryRun {
		plan, err := revoker.Preview(r.Context(), spec)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bulk revocation preview failed: %v", err)
			return
		}
		writeJSON(w, http.StatusOK, plan)
		return
	}

	// The mandatory-confirmation contract: an execution without the dry-run
	// count is refused outright, so no client can skip the preview step.
	if req.ConfirmCount == nil {
		writeError(w, http.StatusBadRequest,
			"confirm_count is required: run with dry_run first and echo the reported total")
		return
	}

	a.consumeHSMAuditLogs("")
	result, err := revoker.Execute(r.Context(), spec)
	a.consumeHSMAuditLogs("")
	if err != nil {
		var mismatch *ca.BulkCountMismatchError
		if errors.As(err, &mismatch) {
			a.recordEvent(r, audit.ActionCertRevokeBulk, caID, "", audit.ResultDenied,
				fmt.Sprintf("confirm_count=%d actual=%d (selection drifted; re-run dry run)", mismatch.Confirmed, mismatch.Actual))
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":         mismatch.Error(),
				"confirm_count": mismatch.Confirmed,
				"actual_count":  mismatch.Actual,
			})
			return
		}
		if result == nil {
			// The engine records its own summary event once execution starts; a
			// nil result means it never did, so the trail is written here.
			a.recordEvent(r, audit.ActionCertRevokeBulk, caID, "", audit.ResultError, err.Error())
			writeError(w, http.StatusBadRequest, "bulk revocation failed: %v", err)
			return
		}
		// Partial failure: revocations up to the failure point stand and were
		// audited by the engine. Surface both the error and the partial result
		// so the operator can resume.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":  err.Error(),
			"result": result,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
