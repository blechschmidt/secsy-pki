package acme

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// handleNewAccount registers a new account or returns an existing one keyed by
// the request's embedded account key (RFC 8555 §7.3).
func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	d, prob := s.decodeJWS(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if d.JWK == nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "newAccount must use an embedded \"jwk\", not \"kid\""))
		return
	}
	payload, prob := d.verify(d.JWK)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	var req newAccountRequest
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "invalid newAccount payload"))
			return
		}
	}

	thumbprint, err := jwkThumbprint(d.JWK)
	if err != nil {
		s.writeProblem(w, newProblem(probBadPublicKey, http.StatusBadRequest, "cannot compute key thumbprint"))
		return
	}

	// Look for an existing account bound to this key.
	existing, err := s.db.GetACMEAccountByThumbprint(thumbprint)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "account lookup failed"))
		return
	}
	if existing != nil {
		w.Header().Set("Location", s.accountURL(r, existing.ID))
		s.writeJSON(w, http.StatusOK, s.wireAccount(r, existing))
		return
	}
	if req.OnlyReturnExisting {
		s.writeProblem(w, newProblem(probAccountDoesntExist, http.StatusBadRequest, "no account exists for this key"))
		return
	}

	// Terms of service enforcement.
	if s.cfg.TermsOfService != "" && !req.TermsOfServiceAgreed {
		s.writeProblem(w, newProblem(probUserActionReq, http.StatusBadRequest, "you must agree to the terms of service"))
		return
	}

	// External Account Binding: the ACME analogue of an authorization grant.
	// When required, the account key must be bound to an operator-provisioned
	// HMAC key, so only clients holding valid credentials may register.
	eabKid := ""
	if s.cfg.RequireEAB {
		kid, prob := s.verifyEAB(r, req.ExternalAccountBinding, d.JWK)
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		eabKid = kid
	}

	// Validate the requested contacts before creating the account (RFC 8555 §7.3):
	// only "mailto:" contacts are supported, and each must be a single, header-free
	// address. An unsupported scheme or invalid value is rejected with the matching
	// ACME problem rather than being stored verbatim.
	if prob := validateContacts(req.Contact); prob != nil {
		s.writeProblem(w, prob)
		return
	}

	jwkJSON, err := json.Marshal(d.JWK)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "serializing account key"))
		return
	}
	acct := &models.ACMEAccount{
		ID:               newUUID(),
		Status:           models.ACMEAccountStatusValid,
		Contacts:         req.Contact,
		JWK:              string(jwkJSON),
		Thumbprint:       thumbprint,
		EABKid:           eabKid,
		TermsOfServiceOK: req.TermsOfServiceAgreed,
	}
	if err := s.db.CreateACMEAccount(acct); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "creating account"))
		return
	}
	rec, _ := s.db.GetACMEAccount(acct.ID)
	if rec == nil {
		rec = acct
	}

	s.recordEvent(r, acct.ID, audit.ActionACMEAccountNew, acct.ID, audit.ResultSuccess, "eab_kid="+eabKid)
	w.Header().Set("Location", s.accountURL(r, acct.ID))
	s.writeJSON(w, http.StatusCreated, s.wireAccount(r, rec))
}

// handleAccount serves POST-as-GET (fetch) and account update/deactivation.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	acct, payload, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	id := r.PathValue("id")
	if id != acct.rec.ID {
		s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "account key does not match this account"))
		return
	}

	// POST-as-GET (empty payload) → return current account.
	if len(payload) == 0 {
		s.writeJSON(w, http.StatusOK, s.wireAccount(r, acct.rec))
		return
	}

	var req accountUpdateRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(probMalformed, http.StatusBadRequest, "invalid account update payload"))
		return
	}
	if req.Status == models.ACMEAccountStatusDeactivated {
		acct.rec.Status = models.ACMEAccountStatusDeactivated
	}
	if req.Contact != nil {
		// A contact update carries the full replacement set (RFC 8555 §7.3.2);
		// validate every entry before persisting so a bad value is rejected rather
		// than stored. An empty array clears the account's contacts.
		if prob := validateContacts(req.Contact); prob != nil {
			s.writeProblem(w, prob)
			return
		}
		acct.rec.Contacts = req.Contact
	}
	if err := s.db.UpdateACMEAccount(acct.rec); err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "updating account"))
		return
	}
	s.writeJSON(w, http.StatusOK, s.wireAccount(r, acct.rec))
}

// handleAccountOrders returns the list of an account's order URLs.
func (s *Server) handleAccountOrders(w http.ResponseWriter, r *http.Request) {
	acct, _, prob := s.authAccount(r)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if r.PathValue("id") != acct.rec.ID {
		s.writeProblem(w, newProblem(probUnauthorized, http.StatusUnauthorized, "account key does not match this account"))
		return
	}
	orders, err := s.db.ListACMEOrdersByAccount(acct.rec.ID)
	if err != nil {
		s.writeProblem(w, newProblem(probServerInternal, http.StatusInternalServerError, "listing orders"))
		return
	}
	urls := make([]string, 0, len(orders))
	for _, o := range orders {
		urls = append(urls, s.orderURL(r, o.ID))
	}
	s.writeJSON(w, http.StatusOK, map[string][]string{"orders": urls})
}

// wireAccount renders an account for the wire.
func (s *Server) wireAccount(r *http.Request, a *models.ACMEAccount) wireAccount {
	return wireAccount{
		Status:  a.Status,
		Contact: a.Contacts,
		Orders:  s.accountURL(r, a.ID) + "/orders",
	}
}

// verifyEAB validates an External Account Binding (RFC 8555 §7.3.4). The EAB is
// a compact/JSON JWS keyed by an operator-provisioned HMAC key (kid) whose
// payload is the account's public JWK. Returns the bound key id on success.
func (s *Server) verifyEAB(r *http.Request, eab json.RawMessage, accountKey *jose.JSONWebKey) (string, *Problem) {
	if len(eab) == 0 {
		return "", newProblem(probExternalBinding, http.StatusBadRequest, "an external account binding is required")
	}
	inner, err := jose.ParseSignedJSON(string(eab), []jose.SignatureAlgorithm{jose.HS256})
	if err != nil || len(inner.Signatures) != 1 {
		return "", newProblem(probMalformed, http.StatusBadRequest, "malformed external account binding")
	}
	prot := inner.Signatures[0].Protected
	kid := prot.KeyID
	macB64, ok := s.cfg.EABHMACKeys[kid]
	if !ok {
		return "", newProblem(probUnauthorized, http.StatusUnauthorized, "unknown external account binding key id")
	}
	macKey, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		// Tolerate standard base64 with padding in config.
		macKey, err = base64.StdEncoding.DecodeString(macB64)
		if err != nil {
			return "", newProblem(probServerInternal, http.StatusInternalServerError, "misconfigured EAB key")
		}
	}
	// The EAB url header must match the newAccount URL.
	if u, ok := prot.ExtraHeaders[jose.HeaderKey("url")]; ok {
		if str, _ := u.(string); str != "" && str != s.requestURL(r) {
			return "", newProblem(probMalformed, http.StatusBadRequest, "external account binding url mismatch")
		}
	}
	payload, err := inner.Verify(macKey)
	if err != nil {
		return "", newProblem(probUnauthorized, http.StatusUnauthorized, "external account binding signature is invalid")
	}
	// The EAB payload must be the account key.
	var boundKey jose.JSONWebKey
	if err := json.Unmarshal(payload, &boundKey); err != nil {
		return "", newProblem(probMalformed, http.StatusBadRequest, "external account binding payload is not a JWK")
	}
	tpBound, err1 := jwkThumbprint(&boundKey)
	tpAcct, err2 := jwkThumbprint(accountKey)
	if err1 != nil || err2 != nil || !hmacEqual(tpBound, tpAcct) {
		return "", newProblem(probMalformed, http.StatusBadRequest, "external account binding does not match the account key")
	}
	return kid, nil
}

// hmacEqual compares two thumbprint strings in constant time.
func hmacEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// validateContacts checks the "contact" URLs supplied on newAccount or an
// account update (RFC 8555 §7.3). The server supports only "mailto:" contacts,
// and — following RFC 8555 §7.3 and the mailto grammar of RFC 6068 — a mailto
// contact must carry exactly one address and no header fields ("hfields", the
// "?…" tail). It returns the ACME problem for the first offending entry, or nil
// when every entry is acceptable. A nil/empty list is valid: the account simply
// has no contacts.
func validateContacts(contacts []string) *Problem {
	for _, contact := range contacts {
		if prob := validateContact(contact); prob != nil {
			return prob
		}
	}
	return nil
}

// validateContact validates a single "contact" URL (see validateContacts). A URL
// using an unsupported scheme yields unsupportedContact; a supported "mailto:"
// URL with an invalid value yields invalidContact — matching the two error types
// RFC 8555 §7.3 mandates for these cases.
func validateContact(contact string) *Problem {
	if strings.TrimSpace(contact) == "" {
		return newProblem(probInvalidContact, http.StatusBadRequest, "a contact URL must not be empty")
	}
	u, err := url.Parse(contact)
	if err != nil {
		return newProblem(probInvalidContact, http.StatusBadRequest, "contact is not a valid URL: "+contact)
	}
	// url.Parse lowercases the scheme, so this comparison is effectively
	// case-insensitive; anything but mailto is an unsupported contact method.
	if u.Scheme != "mailto" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = contact
		}
		return newProblem(probUnsupportedContact, http.StatusBadRequest,
			"unsupported contact scheme "+strconv.Quote(scheme)+`; only "mailto:" contacts are supported`)
	}
	// hfields (the "?header=value" tail, RFC 6068 §2) are not permitted: a contact
	// must not smuggle mail headers. ForceQuery covers a bare trailing "?".
	if u.RawQuery != "" || u.ForceQuery {
		return newProblem(probInvalidContact, http.StatusBadRequest,
			"mailto contact must not contain header fields (hfields): "+contact)
	}
	// The mailto body holds the address(es). Percent-decode it (RFC 6068 permits
	// percent-encoding) before validating, so e.g. "%40" is read as "@".
	addr := u.Opaque
	if dec, derr := url.PathUnescape(addr); derr == nil {
		addr = dec
	}
	// Exactly one address: a comma-separated to-list is rejected.
	if strings.Contains(addr, ",") {
		return newProblem(probInvalidContact, http.StatusBadRequest,
			"mailto contact must contain exactly one address: "+contact)
	}
	if _, err := mail.ParseAddress(addr); err != nil {
		return newProblem(probInvalidContact, http.StatusBadRequest,
			"invalid email address in contact "+strconv.Quote(contact))
	}
	return nil
}
