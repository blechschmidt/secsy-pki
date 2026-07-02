package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// requesterIdentities returns the identifiers a user may be matched against in a
// per-subject trust-domain allowlist: its OIDC subject and, only when the IdP
// asserts the address is verified, its e-mail. This mirrors how RBAC honors
// email-keyed assignments, so an unverified email cannot widen SVID access.
func requesterIdentities(user *models.UserInfo) []string {
	if user == nil {
		return nil
	}
	ids := make([]string, 0, 2)
	if user.Subject != "" {
		ids = append(ids, user.Subject)
	}
	if user.EmailVerified && user.Email != "" {
		ids = append(ids, user.Email)
	}
	return ids
}

// IssueSVID mints a SPIFFE X.509-SVID under a CA. Authorization is two-layered:
// the caller must hold the CA's issue capability (canIssueOn), and the requested
// trust domain must be permitted by the SVID trust-domain allowlist (the RBAC
// subject/email-keyed policy). The SVID's sole identity is the spiffe:// URI SAN
// derived from the request; the CSR contributes only its public key.
func (a *API) IssueSVID(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("svid_issue", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSVIDIssue, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.IssueSVIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "csr is required")
		return
	}

	// Resolve the SPIFFE identity from either the full URI or trust-domain + path,
	// validating it strictly per the SPIFFE ID spec.
	var id spiffe.ID
	if req.SpiffeID != "" {
		id, err = spiffe.ParseID(req.SpiffeID)
	} else {
		id, err = spiffe.MakeID(req.TrustDomain, req.Path)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid SPIFFE identity: %v", err)
		return
	}

	// Trust-domain allowlist enforcement (layered on top of the RBAC issue gate).
	if !a.spiffePolicy.Allowed(requesterIdentities(user), id.TrustDomain()) {
		metrics.Certificates.Inc("svid_issue", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSVIDIssue, caID, id.String(), audit.ResultDenied,
			"trust domain "+id.TrustDomain()+" not permitted")
		writeError(w, http.StatusForbidden, "trust domain %q is not permitted for this requester", id.TrustDomain())
		return
	}

	profile := req.Profile
	if profile == "" {
		profile = a.spiffeProfile
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	a.consumeHSMAuditLogs("")
	result, err := mgr.IssueSVID(r.Context(), ca.SVIDSpec{
		CAID:        caID,
		CSRPEM:      []byte(req.CSR),
		SPIFFEID:    id.String(),
		Profile:     profile,
		Validity:    time.Duration(req.TTLSeconds) * time.Second,
		DNSNames:    req.DNSNames,
		RequestedBy: user.Subject,
	})
	a.consumeHSMAuditLogs("")
	metrics.RecordCertificate("svid_issue", err)
	if err != nil {
		a.recordEvent(r, audit.ActionSVIDIssue, caID, id.String(), audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to issue SVID: %v", err)
		return
	}

	// Include the trust bundle so a workload receives its SVID and the trust
	// anchors it needs to verify peers in a single call. A bundle-build failure is
	// non-fatal: the SVID is already minted, so we log it and omit the bundle.
	bundle := ""
	if authorities, berr := mgr.TrustBundleAuthorities(caID); berr == nil {
		if b, berr := spiffe.BuildBundle(authorities, a.spiffePolicy.RefreshHint(), 0); berr == nil {
			bundle = string(b)
		}
	}

	a.recordEvent(r, audit.ActionSVIDIssue, caID, id.String(), audit.ResultSuccess,
		"spiffe_id="+id.String()+" profile="+result.Profile+" serial="+result.Serial.String())

	writeJSON(w, http.StatusCreated, models.IssueSVIDResponse{
		SpiffeID:    id.String(),
		TrustDomain: id.TrustDomain(),
		Certificate: string(result.PEM),
		Chain:       string(result.ChainPEM),
		Bundle:      bundle,
		Serial:      result.Serial.String(),
		Profile:     result.Profile,
		NotBefore:   result.Certificate.NotBefore.Format(time.RFC3339),
		NotAfter:    result.Certificate.NotAfter.Format(time.RFC3339),
	})
}

// GetSVIDBundle serves a CA's SPIFFE trust bundle: its X.509 trust anchors (the
// CA's combined overlap chain) encoded as a JWKS-style SPIFFE bundle. It is a
// public endpoint so relying workloads can fetch the trust anchors without
// authenticating, exactly like the CRL/OCSP/chain endpoints. The response is
// content-typed application/json so SPIRE/go-spiffe consumers parse it directly.
func (a *API) GetSVIDBundle(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")

	mgr := ca.NewManager(a.db, a.keyProvider)
	authorities, err := mgr.TrustBundleAuthorities(caID)
	if err != nil {
		writeError(w, http.StatusNotFound, "failed to build trust bundle: %v", err)
		return
	}
	bundle, err := spiffe.BuildBundle(authorities, a.spiffePolicy.RefreshHint(), 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode trust bundle: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bundle)
}
