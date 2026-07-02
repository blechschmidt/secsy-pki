package acme

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// ACME Renewal Information (ARI, draft-ietf-acme-ari).
//
// ARI lets a client learn the server's suggested renewal window for a
// certificate and react to forced renewals (e.g. a revocation or an in-progress
// CA key rotation) without waiting for its own static renewal timer. A client
// GETs "<renewalInfo>/<certID>", where certID uniquely identifies the
// certificate by the concatenation of its Authority Key Identifier and Serial
// Number (§4.1):
//
//	certID = base64url(AKI) || "." || base64url(Serial)
//
// The response carries a suggestedWindow [start, end); the client picks a
// uniformly random time within it and renews then, spreading renewal load. When
// the certificate has been revoked or its issuing CA key is being rotated, the
// server returns a window ending at "now" so the client renews immediately.

// CertID returns the ARI CertID (draft-ietf-acme-ari §4.1) that identifies a
// certificate in a renewalInfo request or a newOrder "replaces" field. It is
// exported so ACME clients, the operator console, and tests can address the
// renewalInfo resource for a certificate they hold.
func CertID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("certificate is nil")
	}
	return certIDForCertificate(cert.AuthorityKeyId, cert.SerialNumber)
}

// certIDForCertificate builds the ARI CertID (§4.1) for a parsed certificate:
// base64url(AuthorityKeyIdentifier) "." base64url(SerialNumber), with trailing
// padding stripped. The serial number is encoded as the content octets of its
// DER INTEGER (big-endian, including the leading zero byte a positive integer
// with a high top bit carries), matching the encoding used by Boulder/Pebble.
func certIDForCertificate(aki []byte, serial *big.Int) (string, error) {
	if len(aki) == 0 {
		return "", fmt.Errorf("certificate has no Authority Key Identifier")
	}
	if serial == nil || serial.Sign() < 0 {
		return "", fmt.Errorf("certificate has no valid serial number")
	}
	serialBytes, err := serialContentOctets(serial)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(aki) + "." + enc.EncodeToString(serialBytes), nil
}

// serialContentOctets returns the DER INTEGER content octets of a serial number
// (the value bytes with the ASN.1 tag and length stripped).
func serialContentOctets(serial *big.Int) ([]byte, error) {
	der, err := asn1.Marshal(serial)
	if err != nil {
		return nil, fmt.Errorf("encoding serial number: %w", err)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("decoding serial number: %w", err)
	}
	return raw.Bytes, nil
}

// parsedCertID is a decoded ARI CertID.
type parsedCertID struct {
	AKI    []byte
	Serial *big.Int
}

// parseCertID decodes an ARI CertID of the form base64url(AKI).base64url(Serial)
// into its Authority Key Identifier bytes and serial number.
func parseCertID(s string) (*parsedCertID, error) {
	// Exactly one "." separates the two base64url fields; neither may be empty.
	dot := strings.IndexByte(s, '.')
	if dot <= 0 || dot >= len(s)-1 || strings.IndexByte(s[dot+1:], '.') >= 0 {
		return nil, fmt.Errorf("malformed CertID: expected base64url(AKI).base64url(Serial)")
	}
	enc := base64.RawURLEncoding
	aki, err := enc.DecodeString(s[:dot])
	if err != nil {
		return nil, fmt.Errorf("CertID AKI is not valid base64url: %w", err)
	}
	serialBytes, err := enc.DecodeString(s[dot+1:])
	if err != nil {
		return nil, fmt.Errorf("CertID serial is not valid base64url: %w", err)
	}
	if len(aki) == 0 || len(serialBytes) == 0 {
		return nil, fmt.Errorf("malformed CertID: empty AKI or serial")
	}
	// Serial content octets are an unsigned big-endian integer (serials are
	// positive), so SetBytes reproduces the certificate's serial number.
	return &parsedCertID{AKI: aki, Serial: new(big.Int).SetBytes(serialBytes)}, nil
}

// handleRenewalInfo serves the ARI renewalInfo resource (§4.2). It is an
// unauthenticated GET: the CertID is not a secret and the response reveals only
// a renewal window, so it needs neither a JWS nor a nonce.
func (s *Server) handleRenewalInfo(w http.ResponseWriter, r *http.Request) {
	id, err := parseCertID(r.PathValue("certid"))
	if err != nil {
		metrics.ACMERenewalInfo.Inc(metrics.ResultError, "none")
		s.writeProblemNoNonce(w, newProblem(probMalformed, http.StatusBadRequest, err.Error()))
		return
	}

	cert, caID, prob := s.resolveCertByCertID(id)
	if prob != nil {
		s.writeProblemNoNonce(w, prob)
		return
	}
	if cert == nil {
		metrics.ACMERenewalInfo.Inc(metrics.ResultNotFound, "none")
		s.writeProblemNoNonce(w, newProblem(probMalformed, http.StatusNotFound, "unknown certificate"))
		return
	}

	revoked, rotating := s.renewalSignals(caID, cert)
	now := s.now().UTC()
	start, end := computeRenewalWindow(cert.NotBefore, cert.NotAfter, now, revoked, rotating, s.renewalWindowParams())

	windowKind := "normal"
	switch {
	case revoked:
		windowKind = "revoked"
	case rotating:
		windowKind = "rotating"
	}
	metrics.ACMERenewalInfo.Inc(metrics.ResultSuccess, windowKind)

	// Retry-After tells the client how long to wait before polling again. Poll
	// sooner when a forced-renewal signal is active so a client that cannot renew
	// immediately re-checks quickly.
	retryAfter := s.cfg.RenewalPollInterval
	if revoked || rotating {
		if forced := s.cfg.RenewalPollInterval / 6; forced > 0 && forced < retryAfter {
			retryAfter = forced
		}
	}

	// Audit only forced-renewal signals (revoked / rotating): these are the
	// security-relevant lookups. Routine "normal" polls are frequent and
	// unauthenticated, so metering them via metrics keeps the tamper-evident audit
	// chain from being flooded from a public endpoint.
	if revoked || rotating {
		s.recordRenewalInfoEvent(r, cert, windowKind)
	}

	body := wireRenewalInfo{
		SuggestedWindow: suggestedWindow{Start: rfc3339(start), End: rfc3339(end)},
		ExplanationURL:  s.cfg.ExplanationURL,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	}
	writeJSONBody(w, http.StatusOK, body)
}

// resolveCertByCertID locates the authority's copy of the certificate a CertID
// identifies. The AKI selects the exact issuing CA key (a leaf's AKI equals its
// issuer's Subject Key Identifier, so this resolves the precise key even after a
// same-DN rotation); the serial then keys the issued-certificate row. It returns
// (nil, "", nil) when no certificate matches.
func (s *Server) resolveCertByCertID(id *parsedCertID) (*models.IssuedCertificate, string, *Problem) {
	caID, prob := s.caIDByAKI(id.AKI)
	if prob != nil {
		return nil, "", prob
	}
	if caID == "" {
		return nil, "", nil // unknown issuer → unknown certificate
	}
	serial := id.Serial.String()
	cert, err := s.db.GetIssuedCertificate(caID, serial)
	if err != nil {
		return nil, "", newProblem(probServerInternal, http.StatusInternalServerError, "certificate lookup failed")
	}
	return cert, caID, nil
}

// caIDByAKI returns the id of the CA whose Subject Key Identifier equals aki, or
// "" if none matches. ACME CA counts are small, so a linear scan over the CA
// certificates is cheaper than maintaining a separate SKI index.
func (s *Server) caIDByAKI(aki []byte) (string, *Problem) {
	cas, err := s.db.ListCAs()
	if err != nil {
		return "", newProblem(probServerInternal, http.StatusInternalServerError, "CA lookup failed")
	}
	for i := range cas {
		if cas[i].Certificate == "" {
			continue
		}
		cert, err := pki.ParseCertificatePEM([]byte(cas[i].Certificate))
		if err != nil {
			continue
		}
		if len(cert.SubjectKeyId) > 0 && bytesEqual(cert.SubjectKeyId, aki) {
			return cas[i].ID, nil
		}
	}
	return "", nil
}

// renewalSignals reports whether a certificate should be renewed immediately:
// because it has been revoked, or because its issuing CA key has been superseded
// by a rotation (leaves signed by the old key should migrate to the new key).
func (s *Server) renewalSignals(caID string, cert *models.IssuedCertificate) (revoked, rotating bool) {
	if cert.Status == models.CertStatusRevoked {
		revoked = true
	} else if rc, err := s.db.GetRevokedCertificate(caID, cert.Serial); err == nil && rc != nil {
		revoked = true
	}
	if ca, err := s.db.GetCA(caID); err == nil && ca != nil && ca.Status == models.CAStatusSuperseded {
		rotating = true
	}
	return revoked, rotating
}

// renewalWindowParams captures the tunables for computeRenewalWindow.
type renewalWindowParams struct {
	renewBefore time.Duration // when the normal window ends before expiry (0 = derive)
	windowWidth time.Duration // width of the normal window (0 = derive)
}

func (s *Server) renewalWindowParams() renewalWindowParams {
	return renewalWindowParams{renewBefore: s.cfg.RenewBefore, windowWidth: s.cfg.RenewalWindowWidth}
}

// computeRenewalWindow derives the ARI suggested window for a certificate.
//
// Normal case: the window is a band whose start sits renewBefore before expiry
// and whose width defaults to half of renewBefore, so clients spread renewals
// across the band rather than all renewing at the same instant. When renewBefore
// is unset it defaults to a third of the certificate's lifetime — the widely used
// "renew in the final third" heuristic the expiry monitor also follows.
//
// Forced case (revoked or rotating): the window ends at now and starts shortly
// before it, so the client's random pick lands at or before now and it renews
// immediately.
func computeRenewalWindow(notBefore, notAfter, now time.Time, revoked, rotating bool, p renewalWindowParams) (time.Time, time.Time) {
	notBefore, notAfter = notBefore.UTC(), notAfter.UTC()
	now = now.UTC()

	if revoked || rotating {
		end := now
		start := now.Add(-time.Hour)
		if start.Before(notBefore) {
			start = notBefore
		}
		if !end.After(start) {
			end = start.Add(time.Minute)
		}
		return start, end
	}

	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		// Degenerate validity: suggest renewing now.
		return now, now.Add(time.Minute)
	}

	renewBefore := p.renewBefore
	if renewBefore <= 0 || renewBefore >= lifetime {
		renewBefore = lifetime / 3
	}
	width := p.windowWidth
	if width <= 0 || width > renewBefore {
		width = renewBefore / 2
	}
	if width <= 0 {
		width = time.Minute
	}

	start := notAfter.Add(-renewBefore)
	end := start.Add(width)

	// Keep the window within the certificate's validity period.
	if start.Before(notBefore) {
		start = notBefore
	}
	if end.After(notAfter) {
		end = notAfter
	}
	if !end.After(start) {
		end = start.Add(time.Minute)
		if end.After(notAfter) {
			end = notAfter
		}
	}
	return start, end
}

// recordRenewalInfoEvent appends a best-effort audit event for a served ARI
// lookup. It carries the window kind so forced-renewal signals are auditable.
func (s *Server) recordRenewalInfoEvent(r *http.Request, cert *models.IssuedCertificate, windowKind string) {
	e := &audit.Event{
		ID:         newUUID(),
		Actor:      "acme:anonymous",
		ActorRoles: "acme",
		Action:     audit.ActionACMERenewalInfo,
		Target:     cert.Serial,
		TargetName: cert.CommonName,
		Result:     audit.ResultSuccess,
		Detail:     "window=" + windowKind,
		IP:         clientIP(r),
	}
	if err := s.db.AppendEvent(e); err != nil {
		// Best-effort: a failed audit append must not fail the read.
		return
	}
}

// bytesEqual is a small constant-free byte comparison (the inputs are public
// identifiers, so timing is irrelevant here).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
