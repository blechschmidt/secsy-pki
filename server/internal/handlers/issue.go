package handlers

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// maxOCSPRequestBytes bounds an inbound OCSP request to guard against abuse.
const maxOCSPRequestBytes = 1 << 16 // 64 KiB

// ListProfiles returns the built-in certificate profiles.
func (a *API) ListProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ca.Profiles())
}

// IssueCertificate signs a CSR into an end-entity certificate under a profile,
// using the CA's HSM-held key.
func (a *API) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("issue", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertIssue, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.IssueCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "csr is required")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	a.consumeHSMAuditLogs("")
	result, err := mgr.IssueCertificate(r.Context(), ca.IssueSpec{
		CAID:        caID,
		CSRPEM:      []byte(req.CSR),
		Profile:     req.Profile,
		Validity:    daysToDuration(a.capValidityDays(req.ValidityDays)),
		RequestedBy: user.Subject,
	})
	a.consumeHSMAuditLogs("")
	metrics.RecordCertificate("issue", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertIssue, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to issue certificate: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCertIssue, caID, result.Serial.String(), audit.ResultSuccess, "profile="+result.Profile)
	writeJSON(w, http.StatusCreated, issueResponse(result))
}

// RenewCertificate reissues a previously issued certificate with a fresh serial
// and validity window.
func (a *API) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("renew", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertRenew, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.RenewCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Serial == "" {
		writeError(w, http.StatusBadRequest, "serial is required")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	a.consumeHSMAuditLogs("")
	result, err := mgr.RenewCertificate(r.Context(), ca.RenewSpec{
		CAID:        caID,
		Serial:      req.Serial,
		CSRPEM:      []byte(req.CSR),
		Validity:    daysToDuration(a.capValidityDays(req.ValidityDays)),
		RequestedBy: user.Subject,
	})
	a.consumeHSMAuditLogs("")
	metrics.RecordCertificate("renew", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertRenew, caID, req.Serial, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to renew certificate: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCertRenew, caID, result.Serial.String(), audit.ResultSuccess, "renewed_from="+req.Serial)
	writeJSON(w, http.StatusCreated, issueResponse(result))
}

// RevokeCertificate records a revocation for a certificate serial.
func (a *API) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("revoke", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertRevoke, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.RevokeCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Serial == "" {
		writeError(w, http.StatusBadRequest, "serial is required")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	applied, err := mgr.RevokeCertificate(r.Context(), caID, req.Serial, req.Reason)
	metrics.RecordCertificate("revoke", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertRevoke, caID, req.Serial, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to revoke certificate: %v", err)
		return
	}

	status := "revoked"
	if !applied {
		status = "already-revoked"
	}
	a.recordEvent(r, audit.ActionCertRevoke, caID, req.Serial, audit.ResultSuccess, "reason="+req.Reason+" status="+status)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": status,
		"serial": req.Serial,
	})
}

// ListIssuedCertificates returns the certificates a CA has issued.
func (a *API) ListIssuedCertificates(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	caID := r.PathValue("id")
	// Reflect expiry lazily so listings show accurate status.
	a.db.MarkExpiredCertificates(caID, time.Now())
	certs, err := a.db.ListIssuedCertificates(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list certificates: %v", err)
		return
	}
	if certs == nil {
		certs = []models.IssuedCertificate{}
	}
	writeJSON(w, http.StatusOK, certs)
}

// ListRevokedCertificates returns a CA's revocation records.
func (a *API) ListRevokedCertificates(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	caID := r.PathValue("id")
	revoked, err := a.db.ListRevokedCertificates(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list revocations: %v", err)
		return
	}
	if revoked == nil {
		revoked = []models.RevokedCertificate{}
	}
	writeJSON(w, http.StatusOK, revoked)
}

// GetCRL generates and returns a fresh CRL for a CA. It is a public endpoint so
// relying parties can fetch revocation data without authenticating. The default
// content type is DER (application/pkix-crl); ?format=pem returns PEM.
func (a *API) GetCRL(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	der, err := mgr.GenerateCRL(r.Context(), caID)
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.CRLRequests.Inc(metrics.ResultError)
		writeError(w, http.StatusInternalServerError, "failed to generate CRL: %v", err)
		return
	}
	metrics.CRLRequests.Inc(metrics.ResultSuccess)

	if r.URL.Query().Get("format") == "pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pki.EncodeCRLPEM(der))
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", "attachment; filename=crl.der")
	w.Write(der)
}

// OCSPResponder answers OCSP requests for a CA. It supports both the POST form
// (request body is the DER OCSP request) and the GET form (base64-encoded
// request in the path), per RFC 6960. It is a public endpoint.
func (a *API) OCSPResponder(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")

	var reqDER []byte
	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxOCSPRequestBytes))
		if err != nil {
			writeOCSPMalformed(w)
			return
		}
		reqDER = body
	case http.MethodGet:
		encoded := r.PathValue("req")
		// The base64 may itself be percent-encoded; the router already decodes
		// path segments, so decode base64 directly (std and URL alphabets).
		decoded, err := decodeOCSPGet(encoded)
		if err != nil {
			writeOCSPMalformed(w)
			return
		}
		reqDER = decoded
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if len(reqDER) == 0 {
		writeOCSPMalformed(w)
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	respDER, err := mgr.OCSPRespond(r.Context(), caID, reqDER)
	a.consumeHSMAuditLogs("")
	if err != nil {
		// Signing/lookup failure — return the standard internal-error response.
		metrics.OCSPRequests.Inc(metrics.ResultError)
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(pki.OCSPInternalErrorResponse)
		return
	}

	metrics.OCSPRequests.Inc(metrics.ResultSuccess)
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(respDER)
}

// daysToDuration converts a validity-in-days value to a Duration. Non-positive
// values yield zero, which downstream treats as "use the profile default".
func daysToDuration(days int) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// issueResponse renders an issuance result as the API response shape.
func issueResponse(result *ca.IssueResult) models.IssueCertResponse {
	return models.IssueCertResponse{
		Certificate: string(result.PEM),
		Chain:       string(result.ChainPEM),
		Serial:      result.Serial.String(),
		Profile:     result.Profile,
		NotBefore:   result.Certificate.NotBefore.Format(time.RFC3339),
		NotAfter:    result.Certificate.NotAfter.Format(time.RFC3339),
	}
}

// writeOCSPMalformed emits the standard OCSP "malformed request" response.
func writeOCSPMalformed(w http.ResponseWriter) {
	metrics.OCSPRequests.Inc("malformed")
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(pki.OCSPMalformedResponse)
}

func decodeOCSPGet(encoded string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(encoded)
}
