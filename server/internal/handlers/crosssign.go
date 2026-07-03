package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// CreateCrossSign cross-signs a subject public key with the issuer CA identified
// by {id}: the issuer's HSM-backed key signs a CA certificate carrying the
// subject's exact DN and public key, producing an alternate chain for bridge-CA
// or root-transition topologies. The subject may be a CA already in this
// deployment, an externally supplied certificate, or a CSR.
func (a *API) CreateCrossSign(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	issuerID := r.PathValue("id")

	// The cross-sign inherits the issuer's tenant; the caller must hold ca:manage
	// within it.
	tenantID, err := a.db.GetCATenant(issuerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issuer CA lookup failed: %v", err)
		return
	}
	if tenantID == "" {
		writeError(w, http.StatusNotFound, "issuer CA %q not found", issuerID)
		return
	}
	middleware.SetTenant(r.Context(), tenantID)
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCACrossSign, issuerID, "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	var req models.CACrossSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	// A locally held subject CA must belong to the issuer's tenant: cross-signing a
	// CA from another tenant would breach isolation.
	if req.SubjectCAID != "" {
		subjectTenant, err := a.db.GetCATenant(req.SubjectCAID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "subject CA lookup failed: %v", err)
			return
		}
		if subjectTenant == "" {
			writeError(w, http.StatusBadRequest, "subject CA %q not found", req.SubjectCAID)
			return
		}
		if subjectTenant != tenantID {
			a.recordEvent(r, audit.ActionCACrossSign, issuerID, req.SubjectCAID, audit.ResultDenied, "cross-tenant cross-sign refused")
			writeError(w, http.StatusForbidden, "subject CA belongs to a different tenant; cross-signing across tenants is not permitted")
			return
		}
	}

	spec := ca.CrossSignSpec{
		IssuerCAID:  issuerID,
		SubjectCAID: req.SubjectCAID,
		CertPEM:     []byte(req.CertificatePEM),
		CSRPEM:      []byte(req.CSRPEM),
		MaxPathLen:  req.MaxPathLen,
		RequestedBy: userSubject(user),
	}
	if req.ValidityDays > 0 {
		spec.Validity = time.Duration(req.ValidityDays) * 24 * time.Hour
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.CrossSign(r.Context(), spec)
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCACrossSign, issuerID, req.SubjectCAID, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to cross-sign: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCACrossSign, issuerID, result.CrossSign.Subject, audit.ResultSuccess,
		"cross_sign_id="+result.CrossSign.ID+" subject_key_id="+result.CrossSign.SubjectKeyID+" source="+result.CrossSign.Source)
	// Serialize with the documented snake_case keys and PEM strings (the manager
	// struct has no JSON tags, and raw []byte would render as base64).
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"cross_sign":      result.CrossSign,
		"certificate_pem": string(result.CertificatePEM),
		"chain_pem":       string(result.ChainPEM),
	})
}

// ListCrossSigns returns the cross-sign relationships related to CA {id}, both
// those it issued and those certifying its key.
func (a *API) ListCrossSigns(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CA lookup failed: %v", err)
		return
	}
	if tenantID == "" {
		writeError(w, http.StatusNotFound, "CA %q not found", caID)
		return
	}
	middleware.SetTenant(r.Context(), tenantID)
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	crossSigns, err := mgr.ListCrossSigns(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list cross-signs: %v", err)
		return
	}
	if crossSigns == nil {
		crossSigns = []models.CrossSign{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cross_signs": crossSigns})
}

// GetAlternateChains returns every publishable trust path for CA {id}: its
// native parent-lineage chain plus one chain per active cross-sign of its key. It
// is public so relying parties can select whichever chain they trust.
func (a *API) GetAlternateChains(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")

	mgr := ca.NewManager(a.db, a.keyProvider)
	chains, err := mgr.AlternateChains(caID)
	if err != nil {
		writeError(w, http.StatusNotFound, "failed to build chains: %v", err)
		return
	}
	if chains == nil {
		chains = []ca.AlternateChain{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"chains": chains})
}

// GetCrossSignChain returns the alternate chain for a single cross-sign as a PEM
// bundle: the cross-certificate followed by the issuer's chain to its anchor. It
// is public, mirroring the CRL/OCSP/chain endpoints.
func (a *API) GetCrossSignChain(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	csID := r.PathValue("csid")

	cs, err := a.db.GetCrossSign(csID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cross-sign lookup failed: %v", err)
		return
	}
	// The cross-sign must belong to the CA in the path, either as its subject or
	// its issuer, so the URL is self-consistent and enumeration is bounded.
	if cs == nil || !crossSignRelatesTo(cs, caID) {
		writeError(w, http.StatusNotFound, "cross-sign %q not found for CA %q", csID, caID)
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	chain, err := mgr.CrossSignChainPEM(csID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build cross-sign chain: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=cross-sign-chain.pem")
	w.Write(chain)
}

// crossSignRelatesTo reports whether a cross-sign involves the given CA id as
// either its issuer or its (local) subject.
func crossSignRelatesTo(cs *models.CrossSign, caID string) bool {
	if cs.IssuerCAID == caID {
		return true
	}
	return cs.SubjectCAID != nil && *cs.SubjectCAID == caID
}

// userSubject returns the acting principal's subject for audit/labelling, or ""
// when the request is unauthenticated (should not happen on protected routes).
func userSubject(user *models.UserInfo) string {
	if user == nil {
		return ""
	}
	return user.Subject
}
