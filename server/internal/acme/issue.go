package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/smime"
)

// issuanceProblem maps an issuance failure to its ACME problem document:
// tenant quota exhaustion is an RFC 8555 rateLimited problem (429), a
// suspended tenant is unauthorized (403), anything else stays a server error.
func issuanceProblem(err error) *Problem {
	var quota *models.QuotaExceededError
	if errors.As(err, &quota) {
		return newProblem(probRateLimited, http.StatusTooManyRequests, err.Error())
	}
	var susp *models.TenantSuspendedError
	if errors.As(err, &susp) {
		return newProblem(probUnauthorized, http.StatusForbidden, err.Error())
	}
	return newProblem(probServerInternal, http.StatusInternalServerError, "certificate issuance failed: "+err.Error())
}

// setQuotaRetryAfter adds a Retry-After header when err is a daily-quota
// exhaustion, so compliant ACME clients back off until the window resets.
func setQuotaRetryAfter(w http.ResponseWriter, err error) {
	var quota *models.QuotaExceededError
	if errors.As(err, &quota) && quota.RetryAfter > 0 {
		secs := int(math.Ceil(quota.RetryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
}

// handleFinalize issues the certificate for a ready order from a client CSR.
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	order, prob := s.loadOwnedOrder(r, acct)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	s.refreshOrderStatus(order)

	// Idempotency: a client that retries finalize on an already-issued order
	// should just get the order back.
	if order.Status == models.ACMEOrderStatusValid {
		w.Header().Set("Location", s.orderURL(r, order.ID))
		s.writeOrder(w, r, order)
		return
	}
	if order.Status != models.ACMEOrderStatusReady {
		s.writeProblem(w, newProblem(probOrderNotReady, http.StatusForbidden,
			"order is not ready to be finalized (status: "+order.Status+")"))
		return
	}

	var req finalizeRequest
	if err := json.Unmarshal(payload, &req); err != nil || req.CSR == "" {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "finalize requires a base64url-encoded CSR"))
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.writeProblem(w, newProblem(probBadCSR, http.StatusBadRequest, "CSR is not valid base64url"))
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		s.writeProblem(w, newProblem(probBadCSR, http.StatusBadRequest, "cannot parse CSR: "+err.Error()))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		s.writeProblem(w, newProblem(probBadCSR, http.StatusBadRequest, "CSR signature is invalid"))
		return
	}

	authzs, err := s.db.ListACMEAuthorizationsByOrder(order.ID)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "listing authorizations"))
		return
	}
	if prob := matchCSRToOrder(order, authzs, csr); prob != nil {
		s.writeProblem(w, prob)
		return
	}

	// Mark processing while we sign, so a concurrent poll sees the transition.
	_ = s.db.UpdateACMEOrderStatus(order.ID, models.ACMEOrderStatusProcessing, "")
	order.Status = models.ACMEOrderStatusProcessing

	// Thread the RFC 8657 CAA-binding facts of this ACME request into issuance so
	// the CA's pre-issuance CAA gate can honor accounturi/validationmethods
	// parameters: the requesting account's URI and, per identifier, the challenge
	// type that satisfied it.
	// Issue under the profile selected when the order was created (RFC 9773, the
	// ACME Profiles extension), so the profile the client chose at newOrder governs
	// linting/CAA/name-constraints/cert-policy/CT here at finalize. A legacy order
	// predating the extension has no stored profile, so fall back to the default.
	profileID := order.Profile
	if profileID == "" {
		profileID = s.cfg.Profile
	}
	// Fail-closed gate: an email (S/MIME) order must be issued under an S/MIME
	// profile, so applySMIMEPolicy runs at issuance. newOrder already forces this,
	// so this is defense-in-depth against a legacy/hand-crafted order whose stored
	// profile is not S/MIME.
	if containsEmailIdentifier(order.Identifiers) {
		if p, err := ca.LookupProfile(profileID); err != nil || p.SMIME == nil {
			prob := newProblem(probServerInternal, http.StatusInternalServerError,
				"email order is not bound to an S/MIME issuance profile")
			s.markOrderInvalid(order.ID, prob)
			s.writeProblem(w, prob)
			return
		}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	result, err := s.caMgr.IssueCertificate(r.Context(), ca.IssueSpec{
		CAID:              s.cfg.CAID,
		CSRPEM:            csrPEM,
		Profile:           profileID,
		RequestedBy:       "acme:" + acct.rec.ID,
		ACMEAccountURI:    s.accountURL(r, acct.rec.ID),
		ValidationMethods: s.validationMethods(authzs),
	})
	if err != nil {
		prob := issuanceProblem(err)
		// Quota exhaustion is transient (the window resets at UTC midnight), so
		// the order stays ready and the client may retry finalize after the
		// Retry-After; any other failure invalidates the order as before.
		var quota *models.QuotaExceededError
		if !errors.As(err, &quota) {
			s.markOrderInvalid(order.ID, prob)
		} else {
			_ = s.db.UpdateACMEOrderStatus(order.ID, models.ACMEOrderStatusReady, "")
			order.Status = models.ACMEOrderStatusReady
		}
		s.recordEvent(r, acct.rec.ID, audit.ActionACMEOrderFinalize, order.ID, audit.ResultError, err.Error())
		setQuotaRetryAfter(w, err)
		s.writeProblem(w, prob)
		return
	}

	now := s.now().UTC()
	if err := s.db.FinalizeACMEOrder(order.ID, s.cfg.CAID, result.Serial.String(), string(result.ChainPEM), now); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "recording issued certificate"))
		return
	}
	order.Status = models.ACMEOrderStatusValid
	order.Certificate = string(result.ChainPEM)
	order.Serial = result.Serial.String()
	order.CAID = s.cfg.CAID

	// Per-profile issuance counter (RFC 9773): label by the resolved internal ca
	// profile the certificate was actually issued under, so operators can break
	// ACME issuance down by profile on the metrics endpoint.
	metrics.ACMEIssued.Inc(result.Profile)
	s.recordEvent(r, acct.rec.ID, audit.ActionACMEOrderFinalize, order.ID, audit.ResultSuccess,
		"serial="+result.Serial.String()+" profile="+result.Profile)

	w.Header().Set("Location", s.orderURL(r, order.ID))
	s.writeOrder(w, r, order)
}

// validationMethods maps each DNS identifier in a finalized order to the ACME
// validation method (challenge type) that satisfied its authorization, keyed by
// the normalized identifier the CAA gate uses (lowercased base domain, wildcard
// prefix already stripped on the authorization). It underpins RFC 8657
// "validationmethods" enforcement: the CA checks that the method used to validate
// each name is permitted by that name's CAA record. A finalizable order has a
// valid challenge per authorization; any authorization without one (or a non-DNS
// identifier) is simply omitted. Best-effort — a store error skips that name
// rather than failing issuance, and the CAA gate then treats it as an unrecorded
// method (blocking only if that name's record actually restricts methods).
func (s *Server) validationMethods(authzs []models.ACMEAuthorization) map[string]string {
	methods := make(map[string]string, len(authzs))
	for i := range authzs {
		a := &authzs[i]
		if a.IdentifierType != "dns" {
			continue // CAA governs DNS names only
		}
		challs, err := s.db.ListACMEChallengesByAuthz(a.ID)
		if err != nil {
			continue
		}
		for j := range challs {
			if challs[j].Status == models.ACMEChallengeStatusValid {
				methods[strings.ToLower(strings.TrimSuffix(a.IdentifierValue, "."))] = challs[j].Type
				break
			}
		}
	}
	return methods
}

// handleCertificate serves the default (primary) issued certificate chain
// (POST-as-GET). When cross-signing (Task 47) has produced additional,
// differently-rooted trust paths for the issuing CA, each is advertised on this
// response with a Link rel="alternate" header per RFC 8555 §7.4.2, letting a
// standard ACME client select whichever root a relying party trusts.
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	order, prob := s.loadDownloadableOrder(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	chains := s.orderChains(order)
	// Advertise every alternate chain (indices 1..len-1) on the primary resource.
	s.writeCertLinks(w, r, order.ID, len(chains)-1)
	s.writeCertChain(w, chains[0])
}

// handleAlternateCertificate serves one of the differently-rooted alternate
// certificate chains linked from the primary certificate resource (RFC 8555
// §7.4.2). The trailing "{n}" path segment selects the 1-based alternate index;
// index 0 (the default chain) is served by handleCertificate. Alternate indices
// are stable for a given order: they mirror the native-first ordering of
// ca.Manager.AlternateChains, so a client can re-fetch the same URL and get the
// same chain.
func (s *Server) handleAlternateCertificate(w http.ResponseWriter, r *http.Request) {
	order, prob := s.loadDownloadableOrder(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		s.writeProblem(w, newProblem(probMalformed, http.StatusNotFound, "alternate certificate chain not found"))
		return
	}
	chains := s.orderChains(order)
	if n >= len(chains) {
		s.writeProblem(w, newProblem(probMalformed, http.StatusNotFound, "alternate certificate chain not found"))
		return
	}
	// Alternate resources carry only the rel="index" pointer; alternates are
	// discovered from the primary resource per RFC 8555 §7.4.2.
	s.writeCertLinks(w, r, order.ID, 0)
	s.writeCertChain(w, chains[n])
}

// loadDownloadableOrder authenticates a POST-as-GET certificate download and
// returns the finalized order whose certificate the account is entitled to. The
// certificate URL reuses the order id. It enforces account ownership and that a
// certificate is actually available, mapping each failure to its ACME problem.
func (s *Server) loadDownloadableOrder(r *http.Request) (*models.ACMEOrder, *Problem) {
	acct, _, prob := s.authAccount(r)
	if prob != nil {
		return nil, prob
	}
	order, err := s.db.GetACMEOrder(r.PathValue("id"))
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "order lookup failed")
	}
	if order == nil || order.AccountID != acct.rec.ID {
		return nil, newProblem(probUnauthorized, http.StatusUnauthorized, "certificate not found for this account")
	}
	if order.Status != models.ACMEOrderStatusValid || order.Certificate == "" {
		return nil, newProblem(probMalformed, http.StatusNotFound, "certificate is not available for this order")
	}
	return order, nil
}

// orderChains returns the downloadable certificate chains for a finalized order,
// primary first, then each differently-rooted alternate. The primary is the chain
// stored on the order at finalize (leaf + issuing CA), so its bytes are unchanged
// from before alternate chains existed. Each alternate is the same leaf followed
// by an alternate path the issuing CA's key was cross-signed onto (Task 47),
// terminating at a different trust anchor.
//
// Enumeration is best-effort: if the cross-sign lookup fails, only the primary
// chain is returned so certificate download never breaks. The order preserves
// ca.Manager.AlternateChains' native-first, creation-ordered sequence, so a given
// alternate keeps a stable index (and therefore a stable URL) across requests.
func (s *Server) orderChains(order *models.ACMEOrder) []string {
	chains := []string{order.Certificate}

	leaf := firstPEMCertificate(order.Certificate)
	if leaf == "" {
		return chains
	}
	caID := order.CAID
	if caID == "" {
		caID = s.cfg.CAID
	}
	alts, err := s.caMgr.AlternateChains(caID)
	if err != nil {
		log.Printf("acme: enumerating alternate chains for CA %q (order %s): %v", caID, order.ID, err)
		return chains
	}
	for i := range alts {
		// The native path is already served as the primary chain; only the
		// cross-signed, differently-rooted paths are alternates.
		if alts[i].Native {
			continue
		}
		chains = append(chains, leaf+alts[i].PEM)
	}
	return chains
}

// firstPEMCertificate returns the first CERTIFICATE block of a PEM bundle,
// re-encoded canonically (with a trailing newline) so it concatenates cleanly
// with a following chain. It returns "" when the bundle carries no certificate.
func firstPEMCertificate(bundle string) string {
	rest := []byte(bundle)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return ""
		}
		rest = remaining
		if block.Type == "CERTIFICATE" {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
		}
	}
}

// writeCertLinks emits the Link headers for a certificate response: the
// RFC 8555-recommended rel="index" pointer back to the directory, plus one
// rel="alternate" header per alternate chain (§7.4.2). alternates is the count of
// alternate chains to advertise — non-zero only on the primary resource, where
// alternate i is reachable at /cert/{id}/{i}.
func (s *Server) writeCertLinks(w http.ResponseWriter, r *http.Request, orderID string, alternates int) {
	w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"index\"", s.DirectoryURL(r)))
	for i := 1; i <= alternates; i++ {
		w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"alternate\"", s.altCertURL(r, orderID, i)))
	}
}

// writeCertChain writes a PEM certificate-chain body with a fresh anti-replay
// nonce and the ACME chain content type, preserving the no-store caching behavior
// every ACME response carries.
func (s *Server) writeCertChain(w http.ResponseWriter, chain string) {
	s.addNonce(w)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(chain))
}

// handleRevokeCert revokes a previously issued certificate (RFC 8555 §7.6).
// It accepts either account (kid) authentication — where the account must own
// the order — or certificate-key (jwk) authentication, where the JWS is signed
// by the certificate's own key pair.
func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	d, prob := s.decodeJWS(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	// Determine the verification key and (for kid auth) the account.
	var payload []byte
	var acctID string
	if d.KID != "" {
		acctID = s.accountIDFromKID(d.KID)
		rec, err := s.db.GetACMEAccount(acctID)
		if err != nil || rec == nil {
			s.writeProblem(w, newProblem(probAccountDoesntExist, http.StatusBadRequest, "account does not exist"))
			return
		}
		jwk, prob := parseStoredJWK(rec.JWK)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		payload, prob = d.verify(jwk)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
	} else {
		// Certificate-key authentication: verify with the embedded JWK now; we
		// confirm below that it matches the certificate being revoked.
		payload, prob = d.verify(d.JWK)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
	}

	var req revokeRequest
	if err := json.Unmarshal(payload, &req); err != nil || req.Certificate == "" {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "revoke requires a base64url-encoded certificate"))
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "certificate is not valid base64url"))
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "cannot parse certificate"))
		return
	}
	serial := cert.SerialNumber.String()

	// Find the order that produced this certificate.
	order, prob := s.findOrderBySerial(serial)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	// Authorization check.
	if d.KID != "" {
		if order == nil || order.AccountID != acctID {
			s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "account is not authorized to revoke this certificate"))
			return
		}
	} else {
		// jwk mode: the signing key must be the certificate's public key.
		if !publicKeyMatches(d.JWK, cert) {
			s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "revocation JWS key does not match the certificate"))
			return
		}
	}

	caID := s.cfg.CAID
	if order != nil && order.CAID != "" {
		caID = order.CAID
	}
	reasonName := revocationReasonName(req.Reason)
	if _, err := s.caMgr.RevokeCertificate(r.Context(), caID, serial, reasonName); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "revocation failed: "+err.Error()))
		return
	}
	s.recordEvent(r, acctID, audit.ActionACMECertRevoke, serial, audit.ResultSuccess, "reason="+reasonName)
	s.addNonce(w)
	w.WriteHeader(http.StatusOK)
}

// handleKeyChange rotates an account's key (RFC 8555 §7.3.5). The outer JWS is
// account-authenticated (old key); its payload is an inner JWS signed by the new
// key that names the account and the old key.
func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request) {
	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	inner, err := jose.ParseSignedJSON(string(payload), allowedAlgs)
	if err != nil || len(inner.Signatures) != 1 {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "malformed inner key-change JWS"))
		return
	}
	newKey := inner.Signatures[0].Protected.JSONWebKey
	if newKey == nil || !newKey.IsPublic() {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner JWS must carry the new public key as \"jwk\""))
		return
	}
	// The inner url header must match this key-change URL.
	if u, ok := inner.Signatures[0].Protected.ExtraHeaders[jose.HeaderKey("url")]; ok {
		if str, _ := u.(string); str != "" && !strings.EqualFold(str, s.requestURL(r)) {
			s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner key-change url mismatch"))
			return
		}
	}
	innerPayload, verr := inner.Verify(newKey)
	if verr != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner key-change signature is invalid"))
		return
	}

	var kc keyChangeInner
	if err := json.Unmarshal(innerPayload, &kc); err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "malformed inner key-change payload"))
		return
	}
	if kc.Account != s.accountURL(r, acct.rec.ID) {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner payload account does not match"))
		return
	}
	var oldKey jose.JSONWebKey
	if err := json.Unmarshal(kc.OldKey, &oldKey); err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner payload oldKey is not a JWK"))
		return
	}
	oldTP, _ := jwkThumbprint(&oldKey)
	if oldTP != acct.rec.Thumbprint {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "inner payload oldKey does not match the account key"))
		return
	}

	newTP, err := jwkThumbprint(newKey)
	if err != nil {
		s.writeProblem(w, newProblem(probBadPublicKey, http.StatusBadRequest, "cannot compute new key thumbprint"))
		return
	}
	// The new key must not already be in use by another account.
	if other, _ := s.db.GetACMEAccountByThumbprint(newTP); other != nil && other.ID != acct.rec.ID {
		w.Header().Set("Location", s.accountURL(r, other.ID))
		s.writeProblem(w, newProblem(probMalformed, http.StatusConflict, "the new key is already in use by another account"))
		return
	}

	newKeyJSON, err := json.Marshal(newKey)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "serializing new key"))
		return
	}
	if err := s.db.UpdateACMEAccountKey(acct.rec.ID, string(newKeyJSON), newTP); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "rotating account key"))
		return
	}
	acct.rec.Thumbprint = newTP
	s.writeJSON(w, http.StatusOK, s.wireAccount(r, acct.rec))
}

// writeOrder writes an order object to the response.
func (s *Server) writeOrder(w http.ResponseWriter, r *http.Request, order *models.ACMEOrder) {
	wo, prob := s.wireOrder(r, order)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusOK, wo)
}

// findOrderBySerial locates the order that issued a certificate with the given
// serial. Returns (nil, nil) when unknown (the certificate may still be
// revocable via cert-key auth).
func (s *Server) findOrderBySerial(serial string) (*models.ACMEOrder, *Problem) {
	// Scan recent orders; ACME order volume is modest and this avoids a schema
	// index solely for revocation.
	orders, err := s.db.ListACMEOrders(10000, 0)
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "order lookup failed")
	}
	for i := range orders {
		if orders[i].Serial == serial {
			return &orders[i], nil
		}
	}
	return nil, nil
}

// matchCSRToOrder verifies that the CSR's subject names cover exactly the order's
// authorized identifiers — no more, no fewer (RFC 8555 §7.4, RFC 8823 §3 for
// email identifiers).
func matchCSRToOrder(_ *models.ACMEOrder, authzs []models.ACMEAuthorization, csr *x509.CertificateRequest) *Problem {
	// Build the expected DNS, IP, and email name sets from the authorizations
	// (which carry the wildcard flag).
	expectedDNS := map[string]bool{}
	expectedIP := map[string]bool{}
	expectedEmail := map[string]bool{}
	for _, a := range authzs {
		switch a.IdentifierType {
		case "dns":
			name := a.IdentifierValue
			if a.Wildcard {
				name = "*." + name
			}
			expectedDNS[strings.ToLower(name)] = true
		case "ip":
			expectedIP[a.IdentifierValue] = true
		case "email":
			if mb, err := smime.NormalizeEmail(a.IdentifierValue); err == nil {
				expectedEmail[strings.ToLower(mb.Address())] = true
			}
		}
	}
	emailOrder := len(expectedEmail) > 0

	// SECURITY: a URI SAN is never authorized by an ACME order, and the issuance
	// layer copies CSR SANs into the leaf, so a URI SAN would be an
	// unauthorized-name injection.
	if len(csr.URIs) > 0 {
		return newProblem(probBadCSR, http.StatusBadRequest,
			"CSR contains URI SANs that are not authorized by the order")
	}

	// rfc822Name SANs must match exactly the order's email identifiers (empty for
	// a non-email order, so any email SAN there is rejected).
	gotEmail := map[string]bool{}
	for _, e := range csr.EmailAddresses {
		mb, err := smime.NormalizeEmail(e)
		if err != nil {
			return newProblem(probBadCSR, http.StatusBadRequest, "CSR contains an invalid email SAN: "+err.Error())
		}
		gotEmail[strings.ToLower(mb.Address())] = true
	}
	if !sameStringSet(expectedEmail, gotEmail) {
		return newProblem(probBadCSR, http.StatusBadRequest,
			fmt.Sprintf("CSR email addresses %v do not match the order's identifiers %v", sortedKeys(gotEmail), sortedKeys(expectedEmail)))
	}

	gotDNS := map[string]bool{}
	for _, n := range csr.DNSNames {
		gotDNS[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	// A CN that is a DNS name must also be authorized; fold it into the DNS set.
	// Skipped for email (S/MIME) orders, whose CN is typically a display name or
	// the mailbox rather than a host name and is governed by applySMIMEPolicy.
	if cn := strings.ToLower(strings.TrimSpace(csr.Subject.CommonName)); cn != "" && !emailOrder {
		if strings.Contains(cn, ".") && !strings.ContainsAny(cn, " @") {
			gotDNS[cn] = true
		} else if len(expectedDNS) > 0 || len(expectedIP) > 0 {
			// Non-hostname CN is not permitted for ACME server certs.
			return newProblem(probBadCSR, http.StatusBadRequest, "CSR common name is not an authorized identifier")
		}
	}
	gotIP := map[string]bool{}
	for _, ip := range csr.IPAddresses {
		gotIP[ip.String()] = true
	}

	if !sameStringSet(expectedDNS, gotDNS) {
		return newProblem(probBadCSR, http.StatusBadRequest,
			fmt.Sprintf("CSR DNS names %v do not match the order's identifiers %v", sortedKeys(gotDNS), sortedKeys(expectedDNS)))
	}
	if !sameStringSet(expectedIP, gotIP) {
		return newProblem(probBadCSR, http.StatusBadRequest,
			fmt.Sprintf("CSR IP addresses %v do not match the order's identifiers %v", sortedKeys(gotIP), sortedKeys(expectedIP)))
	}
	return nil
}

// publicKeyMatches reports whether a JWK is the certificate's public key.
func publicKeyMatches(jwk *jose.JSONWebKey, cert *x509.Certificate) bool {
	if jwk == nil {
		return false
	}
	jwkDER, err := x509.MarshalPKIXPublicKey(jwk.Key)
	if err != nil {
		return false
	}
	certDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(jwkDER, certDER)
}

// revocationReasonName maps an RFC 5280 numeric reason code to the reason name
// understood by ca.Manager.RevokeCertificate. Unknown/nil codes map to "".
func revocationReasonName(code *int) string {
	if code == nil {
		return ""
	}
	switch *code {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "caCompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aaCompromise"
	default:
		return ""
	}
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
