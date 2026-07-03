package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// CertificateHoldAction dispatches the reversible certificate-hold endpoints
// (Task 82, RFC 5280 certificateHold / removeFromCRL):
//
//	POST /api/ca/{id}/certificates/{serial}:suspend
//	POST /api/ca/{id}/certificates/{serial}:release
//
// The serial and verb are carried in one path segment ("<serial>:suspend") and
// parsed here rather than by the router: Go's ServeMux requires a path wildcard
// to span a whole segment, so a "{serial}:suspend" pattern is not expressible.
// The colon form mirrors the existing "revocations:bulk" custom-method route.
// Both verbs share the single-revocation RBAC/tenant gate.
func (a *API) CertificateHoldAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	// Serials are decimal integers and never contain a colon, so the first colon
	// cleanly separates the serial from the verb.
	serial, verb, found := strings.Cut(action, ":")
	if !found || serial == "" {
		writeError(w, http.StatusBadRequest,
			"expected /api/ca/{id}/certificates/{serial}:suspend or :release")
		return
	}
	switch verb {
	case "suspend":
		a.suspendCertificate(w, r, serial)
	case "release":
		a.releaseCertificate(w, r, serial)
	default:
		writeError(w, http.StatusBadRequest, "unknown action %q; expected 'suspend' or 'release'", verb)
	}
}

// suspendCertificate places a certificate on hold (reversible revocation with
// reason certificateHold). It is gated by the same SIGN_CERTIFICATE / tenant
// authorization as single revocation.
func (a *API) suspendCertificate(w http.ResponseWriter, r *http.Request, serial string) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("suspend", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertSuspend, caID, serial, audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	applied, err := mgr.SuspendCertificate(r.Context(), caID, serial)
	metrics.RecordCertificate("suspend", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertSuspend, caID, serial, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to suspend certificate: %v", err)
		return
	}

	// Drop any cached "good" OCSP response so the on-hold status is served at once.
	a.ocspCache.Invalidate(caID, serial)

	status := "held"
	if !applied {
		status = "already-held"
	}
	a.recordEvent(r, audit.ActionCertSuspend, caID, serial, audit.ResultSuccess, "reason=certificateHold status="+status)
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "serial": serial})
}

// releaseCertificate removes a certificate hold, returning it to service. It
// succeeds only for a certificate on hold; a permanent revocation is rejected
// with 409 Conflict.
func (a *API) releaseCertificate(w http.ResponseWriter, r *http.Request, serial string) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.Certificates.Inc("release", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionCertRelease, caID, serial, audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	err = mgr.ReleaseCertificate(r.Context(), caID, serial)
	metrics.RecordCertificate("release", err)
	if err != nil {
		a.recordEvent(r, audit.ActionCertRelease, caID, serial, audit.ResultError, err.Error())
		switch {
		case errors.Is(err, ca.ErrNotOnHold):
			writeError(w, http.StatusConflict, "certificate is not on hold; a permanent revocation cannot be released")
		case errors.Is(err, ca.ErrNotRevoked):
			writeError(w, http.StatusConflict, "certificate is not on hold (it is not revoked)")
		default:
			writeError(w, http.StatusBadRequest, "failed to release certificate: %v", err)
		}
		return
	}

	// Drop any cached "revoked" OCSP response so the restored "good" status is
	// served immediately rather than after the cache TTL.
	a.ocspCache.Invalidate(caID, serial)

	a.recordEvent(r, audit.ActionCertRelease, caID, serial, audit.ResultSuccess,
		"removed hold; removeFromCRL appears in the next delta CRL")
	writeJSON(w, http.StatusOK, map[string]string{"status": "released", "serial": serial})
}
