package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/smime"
)

// handleNewOrder creates a new order and its per-identifier authorizations.
func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	var req newOrderRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "invalid newOrder payload"))
		return
	}
	if len(req.Identifiers) == 0 {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "order must contain at least one identifier"))
		return
	}

	// Resolve the client-selected issuance profile (RFC 9773, the ACME Profiles
	// extension) against the configured allowlist. An omitted "profile" selects
	// the server default (backward compatible); an unknown value is rejected with
	// an invalidProfile problem naming the advertised profiles. The resolved
	// internal profile id is persisted on the order and threaded into issuance at
	// finalize, so every pre-issuance gate (lint/CAA/name-constraints/cert-policy/
	// CT) uses the chosen profile.
	profileID, ok := s.cfg.resolveProfile(req.Profile)
	if !ok {
		detail := fmt.Sprintf("unknown profile %q", strings.TrimSpace(req.Profile))
		if names := s.cfg.profileNames(); len(names) > 0 {
			detail += " (available: " + strings.Join(names, ", ") + ")"
		}
		s.writeProblem(w, newProblem(probInvalidProfile, http.StatusBadRequest, detail))
		return
	}

	ids := make([]models.ACMEIdentifier, 0, len(req.Identifiers))
	wildcard := make([]bool, 0, len(req.Identifiers))
	for _, id := range req.Identifiers {
		norm, isWild, prob := s.normalizeIdentifier(id)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		ids = append(ids, norm)
		wildcard = append(wildcard, isWild)
	}

	// RFC 8823 email orders (S/MIME) may not be mixed with dns/ip identifiers, and
	// are always issued under an S/MIME profile so applySMIMEPolicy and the S/MIME
	// Baseline-Requirements lint rules gate finalize regardless of the client's
	// (or the default) profile selection.
	if prob := validateEmailOrderIdentifiers(ids); prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if containsEmailIdentifier(ids) {
		emailProfile, prob := s.emailIssuanceProfile(profileID)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		profileID = emailProfile
	}

	// ARI renewal linkage (draft-ietf-acme-ari §5): a "replaces" CertID ties this
	// order to the certificate it renews. Validate and record it before creating
	// the order so a rejected replacement never produces a half-linked order.
	replaces, prob := s.resolveReplaces(r, acct, req.Replaces)
	if prob != nil {
		metrics.ACMEReplaces.Inc("rejected")
		s.writeProblem(w, prob)
		return
	}

	now := s.now().UTC()
	order := &models.ACMEOrder{
		ID:          newUUID(),
		AccountID:   acct.rec.ID,
		Status:      models.ACMEOrderStatusPending,
		Identifiers: ids,
		Expires:     now.Add(s.cfg.OrderValidity),
		Replaces:    replaces,
		Profile:     profileID,
	}
	if err := s.db.CreateACMEOrder(order); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating order"))
		return
	}

	// One authorization (with its challenges) per identifier.
	for i, id := range ids {
		authz := &models.ACMEAuthorization{
			ID:              newUUID(),
			OrderID:         order.ID,
			AccountID:       acct.rec.ID,
			IdentifierType:  id.Type,
			IdentifierValue: id.Value,
			Status:          models.ACMEAuthzStatusPending,
			Expires:         now.Add(s.cfg.AuthzValidity),
			Wildcard:        wildcard[i],
		}
		if err := s.db.CreateACMEAuthorization(authz); err != nil {
			s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating authorization"))
			return
		}
		for _, ct := range s.challengeTypesFor(id, wildcard[i]) {
			chall := &models.ACMEChallenge{
				ID:      newUUID(),
				AuthzID: authz.ID,
				Type:    ct,
				Token:   newToken(),
				Status:  models.ACMEChallengeStatusPending,
			}
			// email-reply-00 (RFC 8823) splits the token: Token is token-part-2
			// (exposed over HTTPS) and EmailToken1 is token-part-1, delivered only
			// in the challenge email's Subject.
			if ct == models.ACMEChallengeEmailReply00 {
				chall.EmailToken1 = newToken()
			}
			if err := s.db.CreateACMEChallenge(chall); err != nil {
				s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating challenge"))
				return
			}
		}
	}

	s.recordEvent(r, acct.rec.ID, audit.ActionACMEOrderNew, order.ID, audit.ResultSuccess,
		"identifiers="+identifierSummary(ids)+" "+orderProfileDetail(req.Profile, profileID))
	if replaces != "" {
		metrics.ACMEReplaces.Inc("linked")
		s.recordEvent(r, acct.rec.ID, audit.ActionACMEOrderReplaces, order.ID, audit.ResultSuccess,
			"replaces="+replaces)
	}

	w.Header().Set("Location", s.orderURL(r, order.ID))
	wo, prob := s.wireOrder(r, order)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusCreated, wo)
}

// handleOrder serves POST-as-GET fetches of an order, refreshing its status.
func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	acct, _, prob := s.authAccount(r)
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
	wo, prob := s.wireOrder(r, order)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusOK, wo)
}

// handleAuthz serves POST-as-GET fetches of an authorization.
func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	acct, _, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	authz, err := s.db.GetACMEAuthorization(r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "authorization lookup failed"))
		return
	}
	if authz == nil || authz.AccountID != acct.rec.ID {
		s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "authorization not found for this account"))
		return
	}
	s.expireAuthzIfNeeded(authz)
	wa, prob := s.wireAuthz(r, authz)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusOK, wa)
}

// handleChallenge serves POST-as-GET fetches and challenge responses.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	chall, err := s.db.GetACMEChallenge(r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "challenge lookup failed"))
		return
	}
	if chall == nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusNotFound, "challenge not found"))
		return
	}
	authz, err := s.db.GetACMEAuthorization(chall.AuthzID)
	if err != nil || authz == nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "authorization lookup failed"))
		return
	}
	if authz.AccountID != acct.rec.ID {
		s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "challenge does not belong to this account"))
		return
	}

	// A "Link" header pointing at the authorization is recommended (RFC 8555 §7.5.1).
	w.Header().Set("Link", fmt.Sprintf("<%s>;rel=\"up\"", s.authzURL(r, authz.ID)))

	// POST-as-GET (empty payload): just report current state.
	if len(payload) == 0 {
		s.writeJSON(w, http.StatusOK, s.wireChallenge(r, chall))
		return
	}

	// Responding to the challenge triggers validation. Idempotent for an already
	// valid challenge.
	if chall.Status == models.ACMEChallengeStatusValid {
		s.writeJSON(w, http.StatusOK, s.wireChallenge(r, chall))
		return
	}
	s.expireAuthzIfNeeded(authz)
	if authz.Status != models.ACMEAuthzStatusPending {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "authorization is not pending (status: "+authz.Status+")"))
		return
	}

	s.validateChallenge(r, acct, authz, chall, payload)

	// Re-read the challenge to reflect its new status.
	updated, _ := s.db.GetACMEChallenge(chall.ID)
	if updated != nil {
		chall = updated
	}
	s.writeJSON(w, http.StatusOK, s.wireChallenge(r, chall))
}

// validateChallenge performs the outbound check for a challenge and persists the
// resulting challenge, authorization, and order statuses.
func (s *Server) validateChallenge(r *http.Request, acct *acmeAccount, authz *models.ACMEAuthorization, chall *models.ACMEChallenge, payload []byte) {
	// email-reply-00 (RFC 8823) is asynchronous: responding dispatches the signed
	// challenge email and leaves the challenge in "processing"; the inbound-mail
	// poller completes it when the mailbox owner's reply arrives. It never
	// validates synchronously here.
	if chall.Type == models.ACMEChallengeEmailReply00 {
		s.sendEmailChallenge(acct.rec.ID, authz, chall)
		return
	}

	// Mark processing before performing the (possibly slow) network check.
	_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusProcessing, nil, "")

	keyAuth := keyAuthorization(chall.Token, acct.rec.Thumbprint)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	var prob *Problem
	switch chall.Type {
	case models.ACMEChallengeHTTP01:
		prob = s.validator.ValidateHTTP01(ctx, authz.IdentifierValue, chall.Token, keyAuth)
	case models.ACMEChallengeDNS01:
		prob = s.validator.ValidateDNS01(ctx, authz.IdentifierValue, keyAuth)
	case models.ACMEChallengeTLSALPN01:
		prob = s.validator.ValidateTLSALPN01(ctx, authz.IdentifierValue, keyAuth)
	case models.ACMEChallengeDeviceAttest01:
		prob = s.validateDeviceAttest01(r, acct, authz, payload, keyAuth)
	default:
		prob = newProblem(probMalformed, http.StatusBadRequest, "unsupported challenge type "+chall.Type)
	}

	now := s.now().UTC()
	if prob != nil {
		metrics.ACMEChallengeValidations.Inc(chall.Type, "invalid")
		errDoc, _ := json.Marshal(prob)
		_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusInvalid, nil, string(errDoc))
		_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusInvalid)
		s.recordEvent(r, acct.rec.ID, audit.ActionACMEChallenge, authz.OrderID, audit.ResultError,
			fmt.Sprintf("%s %s: %s", chall.Type, authz.IdentifierValue, prob.Detail))
		s.markOrderInvalid(authz.OrderID, prob)
		return
	}

	metrics.ACMEChallengeValidations.Inc(chall.Type, "valid")
	_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusValid, &now, "")
	_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusValid)
	s.recordEvent(r, acct.rec.ID, audit.ActionACMEChallenge, authz.OrderID, audit.ResultSuccess,
		fmt.Sprintf("%s %s validated", chall.Type, authz.IdentifierValue))

	// Refresh the parent order — it may now be ready.
	if order, _ := s.db.GetACMEOrder(authz.OrderID); order != nil {
		s.refreshOrderStatus(order)
	}
}

// loadOwnedOrder loads the order named in the request path and confirms the
// authenticated account owns it.
func (s *Server) loadOwnedOrder(r *http.Request, acct *acmeAccount) (*models.ACMEOrder, *Problem) {
	order, err := s.db.GetACMEOrder(r.PathValue("id"))
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "order lookup failed")
	}
	if order == nil || order.AccountID != acct.rec.ID {
		return nil, newProblem(probUnauthorized, http.StatusUnauthorized, "order not found for this account")
	}
	return order, nil
}

// refreshOrderStatus recomputes an order's status from its authorizations and
// persists any transition. Terminal states (valid, invalid) are left untouched.
func (s *Server) refreshOrderStatus(order *models.ACMEOrder) {
	switch order.Status {
	case models.ACMEOrderStatusValid, models.ACMEOrderStatusInvalid, models.ACMEOrderStatusProcessing:
		return
	}
	if s.now().After(order.Expires) {
		_ = s.db.UpdateACMEOrderStatus(order.ID, models.ACMEOrderStatusInvalid, "")
		order.Status = models.ACMEOrderStatusInvalid
		return
	}

	authzs, err := s.db.ListACMEAuthorizationsByOrder(order.ID)
	if err != nil {
		return
	}
	anyInvalid := false
	allValid := true
	for i := range authzs {
		s.expireAuthzIfNeeded(&authzs[i])
		switch authzs[i].Status {
		case models.ACMEAuthzStatusInvalid, models.ACMEAuthzStatusExpired, models.ACMEAuthzStatusRevoked, models.ACMEAuthzStatusDeactivated:
			anyInvalid = true
			allValid = false
		case models.ACMEAuthzStatusValid:
			// ok
		default:
			allValid = false
		}
	}

	var newStatus string
	switch {
	case anyInvalid:
		newStatus = models.ACMEOrderStatusInvalid
	case allValid:
		newStatus = models.ACMEOrderStatusReady
	default:
		newStatus = models.ACMEOrderStatusPending
	}
	if newStatus != order.Status {
		_ = s.db.UpdateACMEOrderStatus(order.ID, newStatus, order.Error)
		order.Status = newStatus
	}
}

// markOrderInvalid transitions an order to invalid and records the error.
func (s *Server) markOrderInvalid(orderID string, prob *Problem) {
	errDoc := ""
	if prob != nil {
		if b, err := json.Marshal(prob); err == nil {
			errDoc = string(b)
		}
	}
	_ = s.db.UpdateACMEOrderStatus(orderID, models.ACMEOrderStatusInvalid, errDoc)
}

// expireAuthzIfNeeded flips a pending authorization to expired past its expiry.
func (s *Server) expireAuthzIfNeeded(authz *models.ACMEAuthorization) {
	if authz.Status == models.ACMEAuthzStatusPending && s.now().After(authz.Expires) {
		_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusExpired)
		authz.Status = models.ACMEAuthzStatusExpired
	}
}

// resolveReplaces validates a newOrder "replaces" ARI CertID (draft-ietf-acme-ari
// §5) and returns the canonical CertID to record on the order, or a Problem if
// the replacement is not permitted. An empty input returns ("", nil) — the field
// is optional.
func (s *Server) resolveReplaces(_ *http.Request, acct *acmeAccount, replaces string) (string, *Problem) {
	if replaces == "" {
		return "", nil
	}
	id, err := parseCertID(replaces)
	if err != nil {
		return "", newProblem(probMalformed, http.StatusBadRequest, "invalid \"replaces\" CertID: "+err.Error())
	}
	cert, caID, prob := s.resolveCertByCertID(id)
	if prob != nil {
		return "", prob
	}
	if cert == nil {
		return "", newProblem(probMalformed, http.StatusBadRequest, "\"replaces\" names an unknown certificate")
	}

	// The predecessor must have been issued to this same account, so a client
	// cannot claim a renewal linkage for a certificate it does not control.
	predOrder, err := s.db.GetACMEOrderByCertificate(caID, cert.Serial)
	if err != nil {
		return "", newProblem(probServerInternal, http.StatusInternalServerError, "\"replaces\" lookup failed")
	}
	if predOrder == nil || predOrder.AccountID != acct.rec.ID {
		return "", newProblem(probUnauthorized, http.StatusForbidden, "the account is not authorized to replace this certificate")
	}

	// Normalize to the CertID recomputed from the decoded fields, so the recorded
	// value is encoding-stable regardless of how the client formatted the input.
	canonical, err := certIDForCertificate(id.AKI, id.Serial)
	if err != nil {
		return "", newProblem(probMalformed, http.StatusBadRequest, "invalid \"replaces\" CertID")
	}

	// A certificate may be replaced only once (ARI §5): reject a second order that
	// names the same predecessor while an earlier replacement is still live.
	count, err := s.db.CountACMEOrdersReplacing(canonical)
	if err != nil {
		return "", newProblem(probServerInternal, http.StatusInternalServerError, "\"replaces\" lookup failed")
	}
	if count > 0 {
		return "", newProblem(probAlreadyReplaced, http.StatusConflict, "this certificate has already been replaced by another order")
	}
	return canonical, nil
}

// ---- identifier / challenge helpers ---------------------------------------

// normalizeIdentifier validates and canonicalizes an order identifier, and
// reports whether it is a wildcard DNS identifier.
func (s *Server) normalizeIdentifier(id wireIdentifier) (models.ACMEIdentifier, bool, *Problem) {
	switch id.Type {
	case "dns":
		value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.Value)), ".")
		wildcard := false
		base := value
		if strings.HasPrefix(value, "*.") {
			wildcard = true
			base = value[2:]
		}
		if base == "" || strings.ContainsAny(base, " \t/") || strings.Contains(base, "*") {
			return models.ACMEIdentifier{}, false, newProblem(probRejectedID, http.StatusBadRequest, "invalid DNS identifier: "+id.Value)
		}
		// Store the base domain; the wildcard flag is carried on the authorization.
		return models.ACMEIdentifier{Type: "dns", Value: base}, wildcard, nil
	case "ip":
		if !s.cfg.AllowIPIdentifiers {
			return models.ACMEIdentifier{}, false, newProblem(probUnsupportedID, http.StatusBadRequest, "IP identifiers are not enabled")
		}
		if net.ParseIP(strings.TrimSpace(id.Value)) == nil {
			return models.ACMEIdentifier{}, false, newProblem(probRejectedID, http.StatusBadRequest, "invalid IP identifier: "+id.Value)
		}
		return models.ACMEIdentifier{Type: "ip", Value: strings.TrimSpace(id.Value)}, false, nil
	case "email":
		// RFC 8823 email identifiers are only accepted when the email-reply-00
		// challenge is fully configured (a sender and an inbound poller); without a
		// way to validate the mailbox the identifier type is unsupported.
		if !s.emailEnabled() {
			return models.ACMEIdentifier{}, false, newProblem(probUnsupportedID, http.StatusBadRequest, "email identifiers are not enabled")
		}
		// A wildcard email address is meaningless; NormalizeEmail also rejects it.
		mb, err := smime.NormalizeEmail(id.Value)
		if err != nil {
			return models.ACMEIdentifier{}, false, newProblem(probRejectedID, http.StatusBadRequest, "invalid email identifier: "+err.Error())
		}
		return models.ACMEIdentifier{Type: "email", Value: mb.Address()}, false, nil
	default:
		return models.ACMEIdentifier{}, false, newProblem(probUnsupportedID, http.StatusBadRequest, "unsupported identifier type: "+id.Type)
	}
}

// containsEmailIdentifier reports whether any identifier is an RFC 8823 email
// identifier.
func containsEmailIdentifier(ids []models.ACMEIdentifier) bool {
	for _, id := range ids {
		if id.Type == "email" {
			return true
		}
	}
	return false
}

// validateEmailOrderIdentifiers rejects an order that mixes email identifiers
// with dns/ip identifiers. RFC 8823 issues S/MIME certificates for one or more
// mailboxes; blending them with server/host names in a single order would
// straddle two different profile families and CSR-matching rules.
func validateEmailOrderIdentifiers(ids []models.ACMEIdentifier) *Problem {
	if !containsEmailIdentifier(ids) {
		return nil
	}
	for _, id := range ids {
		if id.Type != "email" {
			return newProblem(probMalformed, http.StatusBadRequest,
				"an email (S/MIME) order must contain only email identifiers")
		}
	}
	return nil
}

// challengeTypesFor returns the challenge types offered for an identifier.
// Wildcard DNS identifiers may only be validated with dns-01 (RFC 8555 §7.1.3).
//
// When the ACME profile enforces enrollment attestation (Task 49), a
// device-attest-01 challenge (draft-ietf-acme-device-attest) is added: under
// "require" it is the ONLY challenge, so the client must prove control of a
// hardware-resident key; under "permissive" it is offered alongside the standard
// domain-validation challenges.
func (s *Server) challengeTypesFor(id models.ACMEIdentifier, wildcard bool) []string {
	// RFC 8823 "email" identifiers are validated solely by the email-reply-00
	// challenge; the domain-validation and attestation challenges do not apply.
	if id.Type == "email" {
		return []string{models.ACMEChallengeEmailReply00}
	}
	mode := s.attestationMode()
	if mode == attestation.ModeRequire {
		return []string{models.ACMEChallengeDeviceAttest01}
	}
	var out []string
	for _, ct := range s.cfg.ChallengeTypes {
		if ct == models.ACMEChallengeDeviceAttest01 {
			// device-attest-01 is offered by policy below, not via ChallengeTypes.
			continue
		}
		if wildcard && ct != models.ACMEChallengeDNS01 {
			continue
		}
		if id.Type == "ip" && ct == models.ACMEChallengeDNS01 {
			// dns-01 does not apply to IP identifiers.
			continue
		}
		out = append(out, ct)
	}
	if mode == attestation.ModePermissive {
		out = append(out, models.ACMEChallengeDeviceAttest01)
	}
	return out
}

// attestationMode returns the effective attestation mode for the ACME profile.
func (s *Server) attestationMode() attestation.Mode {
	return s.cfg.Attestation.Mode(s.cfg.Profile)
}

// ---- wire rendering -------------------------------------------------------

func (s *Server) wireOrder(r *http.Request, order *models.ACMEOrder) (*wireOrder, *Problem) {
	authzs, err := s.db.ListACMEAuthorizationsByOrder(order.ID)
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "listing authorizations")
	}
	authzURLs := make([]string, 0, len(authzs))
	for _, a := range authzs {
		authzURLs = append(authzURLs, s.authzURL(r, a.ID))
	}
	wo := &wireOrder{
		Status:         order.Status,
		Expires:        rfc3339(order.Expires),
		Identifiers:    s.wireOrderIdentifiers(order, authzs),
		NotBefore:      rfc3339p(order.NotBefore),
		NotAfter:       rfc3339p(order.NotAfter),
		Authorizations: authzURLs,
		Finalize:       s.orderURL(r, order.ID) + "/finalize",
	}
	if order.Status == models.ACMEOrderStatusValid && order.Certificate != "" {
		wo.Certificate = s.certURL(r, order.ID)
	}
	if order.Error != "" {
		var p Problem
		if json.Unmarshal([]byte(order.Error), &p) == nil {
			wo.Error = &p
		}
	}
	return wo, nil
}

// wireOrderIdentifiers reconstructs the order's identifiers as presented by the
// client, re-adding the "*." prefix for wildcard authorizations.
func (s *Server) wireOrderIdentifiers(order *models.ACMEOrder, authzs []models.ACMEAuthorization) []wireIdentifier {
	// Map identifier value -> wildcard, from authorizations.
	wild := make(map[string]bool)
	for _, a := range authzs {
		if a.Wildcard {
			wild[a.IdentifierValue] = true
		}
	}
	out := make([]wireIdentifier, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		value := id.Value
		if id.Type == "dns" && wild[id.Value] {
			value = "*." + id.Value
		}
		out = append(out, wireIdentifier{Type: id.Type, Value: value})
	}
	return out
}

func (s *Server) wireAuthz(r *http.Request, authz *models.ACMEAuthorization) (*wireAuthorization, *Problem) {
	challs, err := s.db.ListACMEChallengesByAuthz(authz.ID)
	if err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "listing challenges")
	}
	wc := make([]wireChallenge, 0, len(challs))
	for i := range challs {
		wc = append(wc, s.wireChallenge(r, &challs[i]))
	}
	value := authz.IdentifierValue
	// The authorization identifier for a wildcard is the base domain (no "*."),
	// with the wildcard flag set (RFC 8555 §7.1.4).
	return &wireAuthorization{
		Identifier: wireIdentifier{Type: authz.IdentifierType, Value: value},
		Status:     authz.Status,
		Expires:    rfc3339(authz.Expires),
		Challenges: wc,
		Wildcard:   authz.Wildcard,
	}, nil
}

func (s *Server) wireChallenge(r *http.Request, chall *models.ACMEChallenge) wireChallenge {
	wc := wireChallenge{
		Type:      chall.Type,
		URL:       s.challURL(r, chall.ID),
		Status:    chall.Status,
		Token:     chall.Token,
		Validated: rfc3339p(chall.Validated),
	}
	// email-reply-00 (RFC 8823 §5) advertises the sender the challenge email
	// comes from so the client can validate the message's origin.
	if chall.Type == models.ACMEChallengeEmailReply00 && s.emailEnabled() {
		wc.From = s.email.from
	}
	if chall.Error != "" {
		var p Problem
		if json.Unmarshal([]byte(chall.Error), &p) == nil {
			wc.Error = &p
		}
	}
	return wc
}

// orderProfileDetail renders the selected issuance profile for an acme.order.new
// audit event: the ACME-visible name the client chose (or "(default)" when the
// newOrder omitted the field) alongside the internal ca profile id it resolved
// to (RFC 9773, the ACME Profiles extension).
func orderProfileDetail(selected, internalID string) string {
	selected = strings.TrimSpace(selected)
	if selected == "" {
		return "profile=" + internalID + " (default)"
	}
	if selected == internalID {
		return "profile=" + internalID
	}
	return "profile=" + selected + " (" + internalID + ")"
}

// identifierSummary renders identifiers compactly for audit detail.
func identifierSummary(ids []models.ACMEIdentifier) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.Type + ":" + id.Value
	}
	return strings.Join(parts, ",")
}
