package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// bulkRevokeParams builds the canonical parameter string that pins a bulk
// revocation's approval to this exact selection. Serials are sorted so the same
// selection fingerprints identically across re-runs (order-independent), while
// any change to the filter, reason, or confirmed count yields a different
// fingerprint — so an approval cannot be reused for a different revocation.
func bulkRevokeParams(caID string, req models.BulkRevokeRequest) string {
	serials := append([]string(nil), req.Filter.Serials...)
	sort.Strings(serials)
	confirm := -1
	if req.ConfirmCount != nil {
		confirm = *req.ConfirmCount
	}
	return fmt.Sprintf("ca=%s;reason=%s;confirm=%d;profile=%s;pattern=%s;after=%s;before=%s;include_expired=%v;serials=%s",
		caID, req.Reason, confirm, req.Filter.Profile, req.Filter.Pattern,
		req.Filter.IssuedAfter, req.Filter.IssuedBefore, req.Filter.IncludeExpired,
		strings.Join(serials, ","))
}

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

	// ca:manage in the CA's tenant, or an administrative resource grant on this
	// specific CA (Task 191) — the team that owns a subordinate may run an
	// incident-response mass revocation on it without tenant-wide authority.
	_, ok := a.authorizeCAManage(w, r, caID, audit.ActionCertRevokeBulk)
	if !ok {
		metrics.RevocationsBulk.Inc(metrics.ResultDenied)
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

	// Four-eyes gate (Task 81): a real bulk revocation cannot execute until the
	// configured number of distinct approvers sign off. The fingerprint pins the
	// exact selection (filter + reason + confirmed count), so approval to revoke
	// one selection cannot authorize a different one.
	if !a.guard(w, r, approval.ClassBulkRevoke, "ca:"+caID, caID,
		fmt.Sprintf("Bulk-revoke %d certificate(s) on CA %s (reason %q)", *req.ConfirmCount, caID, req.Reason),
		bulkRevokeParams(caID, req),
		fmt.Sprintf("filter: profile=%q pattern=%q serials=%d after=%q before=%q include_expired=%v",
			req.Filter.Profile, req.Filter.Pattern, len(req.Filter.Serials),
			req.Filter.IssuedAfter, req.Filter.IssuedBefore, req.Filter.IncludeExpired)) {
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
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  err.Error(),
			"result": result,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
