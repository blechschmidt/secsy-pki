package acme

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// handleNewAuthz implements ACME pre-authorization (RFC 8555 §7.4.1): a client
// POSTs a single identifier object and the server creates a standalone
// Authorization — with the same http-01/dns-01/tls-alpn-01/device-attest-01
// challenges an order authorization would offer — that the client can validate
// ahead of any order. A subsequent newOrder reuses the still-valid authorization
// for a matching identifier instead of validating it again (see
// claimPreAuthorization).
//
// The route is always registered so a server with pre-authorization disabled can
// answer with a proper ACME problem document; when disabled it returns 404 with a
// urn:ietf:params:acme:error problem (the resource is also absent from the
// directory). Identifier validation reuses normalizeIdentifier, so the same gates
// applied at newOrder — unsupported/rejected identifier types, the IP and email
// enablement checks, tenant/rate-limit middleware — apply here too. The CAA and
// tenant-issuance gates run at finalize (buildLeaf), which every pre-authorized
// order still passes through, so pre-authorization never bypasses them.
func (s *Server) handleNewAuthz(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.PreAuthorization {
		// Not advertised in the directory; a direct POST still gets a well-formed
		// ACME problem rather than the framework's plain-text 404.
		s.writeProblem(w, newProblem(probMalformed, http.StatusNotFound, "pre-authorization is not supported by this server"))
		return
	}

	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	var req newAuthzRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "invalid newAuthz payload"))
		return
	}
	if req.Identifier.Type == "" || req.Identifier.Value == "" {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "newAuthz requires an identifier"))
		return
	}

	// Same identifier validation/normalization as newOrder: an unsupported type,
	// a disabled IP/email type, or a malformed value is rejected with the correct
	// ACME problem before anything is persisted.
	norm, wildcard, prob := s.normalizeIdentifier(req.Identifier)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	// Wildcards cannot be pre-authorized (RFC 8555 §7.4.1: "the wildcard is not
	// part of the identifier"), since a bare identifier object carries no wildcard
	// flag. Reject rather than silently issuing a base-domain authorization.
	if wildcard {
		s.writeProblem(w, newProblem(probRejectedID, http.StatusBadRequest, "wildcard identifiers cannot be pre-authorized"))
		return
	}

	now := s.now().UTC()
	authz := &models.ACMEAuthorization{
		ID:              newUUID(),
		OrderID:         "", // standalone until an order claims it
		AccountID:       acct.rec.ID,
		IdentifierType:  norm.Type,
		IdentifierValue: norm.Value,
		Status:          models.ACMEAuthzStatusPending,
		Expires:         now.Add(s.cfg.AuthzValidity),
		Wildcard:        false,
	}
	if err := s.db.CreateACMEAuthorization(authz); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating authorization"))
		return
	}
	// Same challenge set an order authorization for this identifier would carry.
	for _, ct := range s.challengeTypesFor(norm, false) {
		chall := &models.ACMEChallenge{
			ID:      newUUID(),
			AuthzID: authz.ID,
			Type:    ct,
			Token:   newToken(),
			Status:  models.ACMEChallengeStatusPending,
		}
		if ct == models.ACMEChallengeEmailReply00 {
			chall.EmailToken1 = newToken()
		}
		if err := s.db.CreateACMEChallenge(chall); err != nil {
			s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating challenge"))
			return
		}
	}

	s.recordEvent(r, acct.rec.ID, audit.ActionACMEAuthzNew, authzTarget(authz), audit.ResultSuccess,
		"identifier="+norm.Type+":"+norm.Value)

	w.Header().Set("Location", s.authzURL(r, authz.ID))
	wa, prob := s.wireAuthz(r, authz)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusCreated, wa)
}

// claimPreAuthorization reuses a still-valid standalone pre-authorization for an
// identifier by linking it to the order (RFC 8555 §7.4.1 / §7.1.3 authorization
// reuse), so a pre-validated identifier need not be validated again. It reports
// whether it claimed one; false means the caller should create a fresh
// authorization. Reuse is best-effort: any lookup/claim error is logged and
// treated as "no reuse" so a hiccup never fails order creation, only forgoes the
// optimization. Wildcard identifiers never match (pre-authorization excludes them).
func (s *Server) claimPreAuthorization(orderID, accountID string, id models.ACMEIdentifier, wildcard bool) bool {
	if wildcard {
		return false
	}
	authz, err := s.db.FindReusableACMEPreAuthorization(accountID, id.Type, id.Value, false, s.now().UTC())
	if err != nil {
		log.Printf("acme: pre-authorization lookup for %s:%s failed, creating a fresh authorization: %v", id.Type, id.Value, err)
		return false
	}
	if authz == nil {
		return false
	}
	claimed, err := s.db.ClaimACMEPreAuthorization(authz.ID, orderID)
	if err != nil {
		log.Printf("acme: claiming pre-authorization %s failed, creating a fresh authorization: %v", authz.ID, err)
		return false
	}
	return claimed
}

// authzTarget returns the audit-event target for an authorization: the owning
// order when it has one, otherwise the authorization's own id (standalone
// pre-authorizations have no order). Keeps audit records meaningful for both.
func authzTarget(authz *models.ACMEAuthorization) string {
	if authz.OrderID != "" {
		return authz.OrderID
	}
	return "authz:" + authz.ID
}
