package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
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

	a.recordEvent(r, audit.ActionCertIssue, caID, result.Serial.String(), audit.ResultSuccess, "profile="+result.Profile+" "+result.CT.Summary())
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

	a.recordEvent(r, audit.ActionCertRenew, caID, result.Serial.String(), audit.ResultSuccess, "renewed_from="+req.Serial+" "+result.CT.Summary())
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

	// Drop any cached "good" OCSP response so the certificate's new revoked
	// status is served immediately rather than after the cache TTL elapses.
	a.ocspCache.Invalidate(caID, req.Serial)

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

// GetChain returns the combined overlap chain (AIA/bundle) for a CA: the active
// intermediate, any overlapping superseded siblings still in their rollover
// window, and the parent chain up to the root — as a single PEM bundle. It is a
// public endpoint so relying parties can fetch the issuer bundle needed to
// validate leaves signed by either key during a key rollover.
func (a *API) GetChain(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")

	mgr := ca.NewManager(a.db, a.keyProvider)
	chain, err := mgr.CombinedChainPEM(caID)
	if err != nil {
		writeError(w, http.StatusNotFound, "failed to build chain: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=chain.pem")
	w.Write(chain)
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

	// Extract the request nonce (RFC 8954). A nonce that violates the length
	// bounds is a malformed request. A valid nonce is echoed in the signed
	// response and forces a fresh signature (the cache is bypassed) so an
	// attacker cannot replay a previously captured response.
	var nonce []byte
	if a.ocspPolicy.NonceEnabled {
		n, err := pki.ExtractOCSPNonce(reqDER)
		if err != nil {
			if errors.Is(err, pki.ErrNonceTooLong) || errors.Is(err, pki.ErrNonceTooShort) {
				metrics.OCSPNonce.Inc("rejected")
				writeOCSPMalformed(w)
				return
			}
			// A nonce-parse failure that is not a length violation means the
			// request itself is malformed.
			metrics.OCSPNonce.Inc("rejected")
			writeOCSPMalformed(w)
			return
		}
		nonce = n
		if len(nonce) > 0 {
			metrics.OCSPNonce.Inc("echoed")
		} else {
			metrics.OCSPNonce.Inc("absent")
		}
	}

	// Serve from the response cache when possible: an OCSP response is a signed
	// object valid until its NextUpdate, so a fresh HSM signature is not needed
	// for every request. The cache is keyed by (CA, serial) and invalidated on
	// revocation. It is bypassed for nonce-bearing requests, whose whole point
	// is a fresh, request-bound signature. Parsing the request to recover the
	// serial is cheap relative to an on-HSM signing round-trip.
	var cacheSerial string
	if len(nonce) == 0 && a.ocspCache.Enabled() {
		if serial, ok := pki.OCSPRequestSerial(reqDER); ok {
			cacheSerial = serial
			if cached, hit := a.ocspCache.Get(caID, cacheSerial); hit {
				metrics.OCSPRequests.Inc(metrics.ResultSuccess)
				w.Header().Set("Content-Type", "application/ocsp-response")
				w.Write(cached)
				return
			}
		}
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	opts := ca.OCSPRespondOptions{Nonce: nonce}
	if len(nonce) > 0 && a.ocspPolicy.NonceMaxAge > 0 {
		opts.Validity = a.ocspPolicy.NonceMaxAge
	}
	// Sign with a short-lived delegated OCSP-signing certificate when enabled,
	// falling back to the CA key if the delegated responder cannot be produced.
	signerLabel := "ca"
	if a.ocspPolicy.Delegated && a.delegatedResponders != nil {
		a.consumeHSMAuditLogs("")
		cert, ref, derr := a.delegatedResponders.Responder(r.Context(), mgr, caID)
		a.consumeHSMAuditLogs("")
		if derr == nil {
			opts.Responder = cert
			opts.ResponderKeyRef = &keyprovider.KeyRef{Label: ref.Label, ID: ref.ID}
			signerLabel = "delegated"
		}
		// On failure we intentionally continue with CA-key signing so revocation
		// data keeps flowing; the CA signer is always available.
	}

	a.consumeHSMAuditLogs("")
	respDER, err := mgr.OCSPRespondWithOptions(r.Context(), caID, reqDER, opts)
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeOCSPError(w, err)
		return
	}

	metrics.OCSPSigner.Inc(signerLabel)
	if cacheSerial != "" {
		a.ocspCache.Put(caID, cacheSerial, respDER)
	}

	metrics.OCSPRequests.Inc(metrics.ResultSuccess)
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(respDER)
}

// writeOCSPError maps a responder error to the correct RFC 6960 §4.2.1 status
// response and records the outcome.
func writeOCSPError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	switch {
	case errors.Is(err, ca.ErrOCSPMalformed):
		metrics.OCSPRequests.Inc("malformed")
		w.Write(pki.OCSPMalformedResponse)
	case errors.Is(err, ca.ErrOCSPUnauthorized):
		metrics.OCSPRequests.Inc("unauthorized")
		w.Write(pki.OCSPUnauthorizedResponse)
	case errors.Is(err, ca.ErrOCSPTryLater):
		metrics.OCSPRequests.Inc("try_later")
		w.Write(pki.OCSPTryLaterResponse)
	default:
		metrics.OCSPRequests.Inc(metrics.ResultError)
		w.Write(pki.OCSPInternalErrorResponse)
	}
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
	resp := models.IssueCertResponse{
		Certificate: string(result.PEM),
		Chain:       string(result.ChainPEM),
		Serial:      result.Serial.String(),
		Profile:     result.Profile,
		NotBefore:   result.Certificate.NotBefore.Format(time.RFC3339),
		NotAfter:    result.Certificate.NotAfter.Format(time.RFC3339),
	}
	if ct := result.CT; ct != nil && ct.Enabled {
		out := &models.CTResponse{
			Enabled:  true,
			Embedded: ct.Embedded,
			SCTCount: ct.SCTCount,
			Status:   result.Record.CTStatus,
		}
		for _, r := range ct.Logs {
			out.Logs = append(out.Logs, models.CTLogOutcome{Log: r.Log, OK: r.OK, Error: r.Error})
		}
		resp.CT = out
	}
	return resp
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
