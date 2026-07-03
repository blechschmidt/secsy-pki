package handlers

// REST surface for Task 84's per-profile manual issuance-approval gate. When a
// certificate profile sets require_approval, operator/API leaf issuance is not
// executed immediately: the request is parked in the four-eyes engine
// (internal/approval) and the certificate is completed and delivered only after
// the approver threshold is met. Approve/deny reuse the existing
// /api/approvals/{id}/approve|reject endpoints; the certificate is fetched from
// /api/approvals/{id}/certificate once approved.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/issueapproval"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// issuanceApprovalRequired resolves the profile and reports whether issuance
// under it must be routed through the manual approval gate: the profile sets
// require_approval AND the four-eyes engine is enabled with the cert.issue class
// guarded. A profile lookup failure (unknown profile) is returned so the caller
// can answer 400 before doing any work.
func (a *API) issuanceApprovalRequired(profileName string) (ca.Profile, bool, error) {
	profile, err := ca.LookupProfile(profileName)
	if err != nil {
		return ca.Profile{}, false, err
	}
	gated := profile.RequireApproval && a.approvals != nil && a.approvals.Policy().Guarded(approval.ClassCertIssue)
	return profile, gated, nil
}

// IssuanceApprovalGate is the transport-agnostic core of Task 84's per-profile
// issuance-approval gate, shared by the REST and gRPC issue paths. It reports
// whether issuance under profileName must be held for manual approval and, when
// it must, parks the request (validating the CSR and recording — or reusing — a
// pending cert.issue approval) WITHOUT issuing anything:
//
//   - gated=false: the caller should issue normally (profile ungated, or the
//     approval engine is disabled / does not guard cert.issue).
//   - gated=true with a non-nil parked request: the caller must NOT issue; direct
//     the requester to have the request approved and then fetch the certificate.
//
// clientErr is a caller-side error (unknown profile or malformed CSR) to map to a
// 4xx; err is a gate/store failure to map to a 5xx. The cert.issue.pending audit
// event and metric are emitted here exactly once per newly created request, so
// both transports record parking identically.
func (a *API) IssuanceApprovalGate(ctx context.Context, caID, profileName, csrPEM string, validityDays int, user *models.UserInfo, ip string) (parked *models.PendingApproval, gated bool, clientErr, err error) {
	profile, isGated, perr := a.issuanceApprovalRequired(profileName)
	if perr != nil {
		return nil, false, perr, nil
	}
	if !isGated {
		return nil, false, nil, nil
	}
	// A malformed CSR is a client error; validate up front so the parked request
	// is always completable and the error maps cleanly to a 4xx.
	if _, cerr := ca.InspectCSRForIssue([]byte(csrPEM)); cerr != nil {
		return nil, true, cerr, nil
	}

	actor, name := "", ""
	if user != nil {
		actor, name = user.Subject, user.Name
	}
	caLabel := ""
	if caRec, _ := a.db.GetCA(caID); caRec != nil {
		caLabel = caRec.Label
	}

	pa, created, perr := issueapproval.Park(ctx, issueapproval.ParkRequest{
		Engine:       a.approvals,
		CAID:         caID,
		CALabel:      caLabel,
		Profile:      profile,
		CSRPEM:       []byte(csrPEM),
		ValidityDays: a.capValidityDays(validityDays),
		Actor:        actor,
		ActorName:    name,
		Tenant:       middleware.GetTenant(ctx),
		IP:           ip,
	})
	if perr != nil {
		return nil, true, nil, perr
	}
	// Emit the domain "parked" event and metric only when a brand-new request was
	// created, not on idempotent re-attempts of an already-parked issuance.
	if created {
		a.recordEventCtx(ctx, ip, audit.ActionCertIssuePending, caID, pa.ID, audit.ResultSuccess,
			"profile="+profile.Name+"; approval="+pa.ID+"; needs "+strconv.Itoa(pa.RequiredApprovals)+" distinct approver(s)")
		metrics.CertIssueApprovals.Inc("pending")
	}
	return pa, true, nil, nil
}

// writeIssuancePending answers a held issuance with 202 and the request the
// operator/approvers must act on, including where to fetch the certificate once
// approved.
func writeIssuancePending(w http.ResponseWriter, pa *models.PendingApproval) {
	if pa == nil {
		writeError(w, http.StatusInternalServerError, "approval gate returned no request")
		return
	}
	w.Header().Set("X-Secsy-Approval-Id", pa.ID)
	certURL := "/api/approvals/" + pa.ID + "/certificate"
	w.Header().Set("Location", certURL)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":             "pending_approval",
		"approval_id":        pa.ID,
		"required_approvals": pa.RequiredApprovals,
		"approvals_count":    pa.ApprovalsCount,
		"certificate_url":    certURL,
		"message": "certificate issuance held for four-eyes approval: request " + pa.ID +
			" needs " + strconv.Itoa(pa.RequiredApprovals) + " distinct approver(s) (" +
			strconv.Itoa(pa.ApprovalsCount) + " recorded so far); once approved, GET " + certURL,
		"approval": pa,
	})
}

// GetApprovalCertificate completes and delivers the certificate for an approved
// cert.issue request (GET /api/approvals/{id}/certificate). While the request is
// still pending it answers 202; once approved it performs the HSM-backed
// issuance from the parked payload (exactly once) and returns the certificate;
// on rejection/expiry it answers 409 and never issues.
func (a *API) GetApprovalCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if a.approvals == nil {
		writeError(w, http.StatusNotFound, "the approval workflow is not enabled")
		return
	}
	id := r.PathValue("id")
	pa, err := a.approvals.Get(id)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	if pa.OperationClass != approval.ClassCertIssue {
		writeError(w, http.StatusBadRequest, "approval %s is not a certificate-issuance request", id)
		return
	}

	// Authorize against the target CA: obtaining the certificate requires the same
	// SIGN_CERTIFICATE capability as requesting it. Scoped to the request's tenant.
	caID := strings.TrimPrefix(pa.ResourceKey, "ca:")
	middleware.SetTenant(r.Context(), pa.TenantID)
	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		a.recordEvent(r, audit.ActionCertIssueApproved, caID, id, audit.ResultDenied,
			"no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	name := ""
	if user != nil {
		name = user.Name
	}
	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	outcome, err := issueapproval.Complete(r.Context(), a.approvals, mgr, a.db, id, requestActor(r), name, clientIP(r))
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeApprovalError(w, err)
		return
	}

	switch outcome.State {
	case issueapproval.StateDelivered:
		writeJSON(w, http.StatusOK, issuedCertificateResponse(outcome.Issued, outcome.ChainPEM))
	case issueapproval.StatePending:
		writeIssuancePending(w, outcome.Approval)
	case issueapproval.StateDenied:
		writeError(w, http.StatusConflict, "issuance was not approved: %s", outcome.Reason)
	case issueapproval.StateFailed:
		writeError(w, http.StatusInternalServerError, "issuance failed after approval: %s", outcome.Err)
	default:
		writeError(w, http.StatusConflict, "%s", outcome.Reason)
	}
}

// issuedCertificateResponse renders a stored issued certificate (plus its chain)
// as the standard issuance response shape, so the delivered certificate looks
// identical to one returned by immediate issuance.
func issuedCertificateResponse(cert *models.IssuedCertificate, chainPEM string) models.IssueCertResponse {
	return models.IssueCertResponse{
		Certificate: cert.Certificate,
		Chain:       chainPEM,
		Serial:      cert.Serial,
		Profile:     cert.Profile,
		NotBefore:   cert.NotBefore.Format(time.RFC3339),
		NotAfter:    cert.NotAfter.Format(time.RFC3339),
	}
}
