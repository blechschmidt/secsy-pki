package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
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

	ok, err := a.canIssueOn(r.Context(), user, caID)
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

	// Per-profile manual issuance-approval gate (Task 84): when the selected
	// profile sets require_approval and the four-eyes engine guards cert.issue,
	// hold the request for approval instead of issuing now. Automated protocol
	// flows (ACME/EST/SCEP/CMP) call ca.Manager directly and never reach here.
	pa, gated, clientErr, gateErr := a.IssuanceApprovalGate(
		r.Context(), caID, req.Profile, req.CSR, req.ValidityDays, user, clientIP(r))
	if clientErr != nil {
		writeError(w, http.StatusBadRequest, "%v", clientErr)
		return
	}
	if gateErr != nil {
		writeError(w, http.StatusInternalServerError, "approval gate error: %v", gateErr)
		return
	}
	if gated {
		writeIssuancePending(w, pa)
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
		MustStaple:  req.MustStaple,
		UPNs:        req.UPNs,
		PSD2:        req.PSD2,
	})
	a.consumeHSMAuditLogs("")
	metrics.RecordCertificate("issue", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertIssue, caID, "", audit.ResultError, err.Error())
		if writeTenantLimitError(w, err) { // suspension → 403, quota → 429 + Retry-After
			return
		}
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

	ok, err := a.canIssueOn(r.Context(), user, caID)
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
		if writeTenantLimitError(w, err) { // suspension → 403, quota → 429 + Retry-After
			return
		}
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

	ok, err := a.canIssueOn(r.Context(), user, caID)
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

// ListIssuedCertificates returns a page of the certificates a CA has issued,
// newest first (Task 83). It accepts ?limit, ?cursor, ?status, ?profile, ?q,
// ?serial_prefix, and ?expires_before, and returns {items, next_cursor, total}.
// The page size defaults to database.DefaultPageSize and is capped at
// database.MaxPageSize.
func (a *API) ListIssuedCertificates(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authorizeCARead(w, r, r.PathValue("id")); !ok {
		return
	}
	caID := r.PathValue("id")
	filter, page, clamped, err := parseCertListParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	// Reflect expiry lazily so listings (and the status filter) show accurate
	// state before the page is read.
	_, _ = a.db.MarkExpiredCertificates(caID, time.Now())
	result, err := a.db.PageIssuedCertificates(caID, filter, page)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCursor) {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to list certificates: %v", err)
		return
	}
	if result.Items == nil {
		result.Items = []models.IssuedCertificate{}
	}
	logPageTruncation(r, "issued", len(result.Items), result.Total, clamped, result.HasMore)
	writeJSON(w, http.StatusOK, result)
}

// ListRevokedCertificates returns a page of a CA's revocation records, newest
// revocation first (Task 83). It accepts ?limit, ?cursor, and ?serial_prefix and
// returns {items, next_cursor, total}.
func (a *API) ListRevokedCertificates(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authorizeCARead(w, r, r.PathValue("id")); !ok {
		return
	}
	caID := r.PathValue("id")
	filter, page, clamped, err := parseCertListParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	result, err := a.db.PageRevokedCertificates(caID, filter, page)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCursor) {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to list revocations: %v", err)
		return
	}
	if result.Items == nil {
		result.Items = []models.RevokedCertificate{}
	}
	logPageTruncation(r, "revoked", len(result.Items), result.Total, clamped, result.HasMore)
	writeJSON(w, http.StatusOK, result)
}

// GetCRL returns the complete (base) CRL for a CA. It is a public endpoint so
// relying parties can fetch revocation data without authenticating. The CRL is
// served from the published store and re-signed on the HSM only when stale, so a
// base CRL and the delta CRLs that reference it stay a consistent pair. The
// default content type is DER (application/pkix-crl); ?format=pem returns PEM.
func (a *API) GetCRL(w http.ResponseWriter, r *http.Request) {
	a.serveCRL(w, r, ca.FullScope, false, "crl.der")
}

// GetDeltaCRL returns the delta CRL for a CA's complete scope, relative to the
// current base CRL served by GetCRL.
func (a *API) GetDeltaCRL(w http.ResponseWriter, r *http.Request) {
	a.serveCRL(w, r, ca.FullScope, true, "crl-delta.der")
}

// GetShardCRL returns the base CRL for a single CRL partition (shard). The shard
// index is taken from the path and must be within the configured shard count.
func (a *API) GetShardCRL(w http.ResponseWriter, r *http.Request) {
	shard, ok := parseShard(w, r)
	if !ok {
		return
	}
	a.serveCRL(w, r, shard, false, fmt.Sprintf("crl-%d.der", shard))
}

// GetShardDeltaCRL returns the delta CRL for a single CRL partition (shard).
func (a *API) GetShardDeltaCRL(w http.ResponseWriter, r *http.Request) {
	shard, ok := parseShard(w, r)
	if !ok {
		return
	}
	a.serveCRL(w, r, shard, true, fmt.Sprintf("crl-%d-delta.der", shard))
}

// parseShard extracts and validates the {shard} path value.
func parseShard(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.PathValue("shard")
	shard, err := strconv.Atoi(raw)
	if err != nil || shard < 0 {
		writeError(w, http.StatusBadRequest, "invalid shard %q", raw)
		return 0, false
	}
	return shard, true
}

// serveCRL is the shared body for the base/delta and full/shard CRL endpoints.
func (a *API) serveCRL(w http.ResponseWriter, r *http.Request, shard int, delta bool, filename string) {
	caID := r.PathValue("id")

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	var (
		der []byte
		err error
	)
	if delta {
		der, err = mgr.GetDeltaCRL(r.Context(), caID, shard)
	} else {
		der, err = mgr.GetBaseCRL(r.Context(), caID, shard)
	}
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.CRLRequests.Inc(metrics.ResultError)
		writeError(w, http.StatusInternalServerError, "failed to generate CRL: %v", err)
		return
	}
	metrics.CRLRequests.Inc(metrics.ResultSuccess)

	// Serve the DER by default, PEM on ?format=pem. A CRL is a signed object valid
	// until its nextUpdate, so it is publicly cacheable; derive the caching
	// metadata (RFC 5019 §6.2-style semantics) from the CRL's own validity window.
	pemFormat := r.URL.Query().Get("format") == "pem"
	body := der
	if pemFormat {
		body = pki.EncodeCRLPEM(der)
		w.Header().Set("Content-Type", "application/x-pem-file")
	} else {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	}

	// The ETag folds in the CRL number so a re-signed CRL that happens to carry an
	// identical entry set but a new (monotonic) number still validates as a
	// distinct version; the served bytes make it a strong validator.
	if number, thisUpdate, nextUpdate, ok := pki.CRLValidity(der); ok {
		var numBytes []byte
		if number != nil {
			numBytes = number.Bytes()
		}
		if applyCacheHeaders(w, r, cacheableResponse{
			thisUpdate: thisUpdate,
			nextUpdate: nextUpdate,
			etag:       strongETag(numBytes, body),
			maxAge:     maxCRLCacheAge,
		}) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	_, _ = w.Write(body)
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
	_, _ = w.Write(chain)
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
	// for every request. The cache is keyed by (CA, serial), invalidated on
	// revocation, and — when pre-signing is enabled — batch-filled in the
	// background so this hit path is the norm and the HSM stays off the public
	// hot path entirely. It is bypassed for nonce-bearing requests, whose whole
	// point is a fresh, request-bound signature. Parsing the request to recover
	// the serial is cheap relative to an on-HSM signing round-trip.
	var cacheSerial string
	if a.ocspCache.Enabled() || a.recentOCSP != nil {
		if serial, ok := pki.OCSPRequestSerial(reqDER); ok {
			cacheSerial = serial
			// Feed the presigner's recently-queried set (nonce requests included:
			// the same serial is typically queried nonce-less by other clients).
			a.recentOCSP.Record(caID, serial)
			if len(nonce) == 0 && a.ocspCache.Enabled() {
				if cached, hit := a.ocspCache.Get(caID, cacheSerial); hit {
					metrics.OCSPRequests.Inc(metrics.ResultSuccess)
					a.writeOCSPResponse(w, r, cached, false)
					return
				}
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
	// Never cache a nonce-bearing response: it is bound to one request and
	// replaying it to other clients would defeat RFC 8954.
	if cacheSerial != "" && len(nonce) == 0 {
		a.ocspCache.Put(caID, cacheSerial, respDER)
	}

	metrics.OCSPRequests.Inc(metrics.ResultSuccess)
	a.writeOCSPResponse(w, r, respDER, len(nonce) > 0)
}

// writeOCSPResponse writes a signed OCSP response with the correct HTTP caching
// semantics (RFC 5019 §6.2 Lightweight OCSP Profile).
//
// A response that echoes a nonce is bound to a single request and MUST NOT be
// reused by a shared cache (RFC 8954), so it is marked Cache-Control: no-store on
// every method and carries no validators. A nonce-less GET/HEAD response is the
// cacheable lightweight-profile path: it advertises Cache-Control/Expires/
// Last-Modified and a strong ETag derived from its own thisUpdate/nextUpdate and
// response bytes, and honors conditional requests with 304 Not Modified. A POST
// response is left with only its Content-Type (HTTP intermediaries do not reuse
// POST responses), preserving prior behavior. hasNonce reflects whether the
// response echoes a request nonce.
func (a *API) writeOCSPResponse(w http.ResponseWriter, r *http.Request, respDER []byte, hasNonce bool) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	switch {
	case hasNonce:
		w.Header().Set("Cache-Control", "no-store")
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		if thisUpdate, nextUpdate, ok := pki.OCSPResponseValidity(respDER); ok {
			if applyCacheHeaders(w, r, cacheableResponse{
				thisUpdate: thisUpdate,
				nextUpdate: nextUpdate,
				etag:       strongETag(respDER),
				maxAge:     maxOCSPCacheAge,
			}) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	_, _ = w.Write(respDER)
}

// writeOCSPError maps a responder error to the correct RFC 6960 §4.2.1 status
// response and records the outcome.
func writeOCSPError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	switch {
	case errors.Is(err, ca.ErrOCSPMalformed):
		metrics.OCSPRequests.Inc("malformed")
		_, _ = w.Write(pki.OCSPMalformedResponse)
	case errors.Is(err, ca.ErrOCSPUnauthorized):
		metrics.OCSPRequests.Inc("unauthorized")
		_, _ = w.Write(pki.OCSPUnauthorizedResponse)
	case errors.Is(err, ca.ErrOCSPTryLater):
		metrics.OCSPRequests.Inc("try_later")
		_, _ = w.Write(pki.OCSPTryLaterResponse)
	default:
		metrics.OCSPRequests.Inc(metrics.ResultError)
		_, _ = w.Write(pki.OCSPInternalErrorResponse)
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
	_, _ = w.Write(pki.OCSPMalformedResponse)
}

func decodeOCSPGet(encoded string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(encoded)
}
