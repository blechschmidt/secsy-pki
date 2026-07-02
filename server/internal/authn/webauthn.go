package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// CredentialStore persists registered WebAuthn passkeys. It is satisfied by
// *database.DB; the interface keeps this package testable with an in-memory fake.
type CredentialStore interface {
	AddWebAuthnCredential(c *models.WebAuthnCredential) error
	ListWebAuthnCredentials(subject string) ([]models.WebAuthnCredential, error)
	GetWebAuthnCredential(id string) (*models.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(id string, count uint32) error
	DeleteWebAuthnCredential(subject, id string) error
}

// WebAuthn implements passkey registration and the step-up assertion ceremony
// used to re-authenticate an operator before a high-risk operation. It is a
// self-contained, dependency-free (no external WebAuthn library) implementation
// reusing this repository's COSE/authenticator-data parsing (internal/attestation).
type WebAuthn struct {
	mgr     *Manager
	rpID    string          // the Relying Party ID (an effective domain, e.g. pki.example.com)
	rpName  string          // human-readable RP name shown by the authenticator
	origins map[string]bool // acceptable clientData origins
	store   CredentialStore

	mu      sync.Mutex
	pending map[string]pendingChallenge // keyed by session id
	now     func() time.Time
}

type pendingChallenge struct {
	challenge string
	purpose   string // "register" | "stepup"
	subject   string
	expires   time.Time
}

const challengeTTL = 2 * time.Minute

// WebAuthnConfig configures the step-up handler.
type WebAuthnConfig struct {
	// RPID is the WebAuthn Relying Party ID: the registrable domain the console is
	// served from (e.g. "pki.example.com"). A credential is bound to it.
	RPID string
	// RPName is the display name presented by the authenticator.
	RPName string
	// Origins are the acceptable clientDataJSON origins (e.g.
	// "https://pki.example.com"). At least one is required.
	Origins []string
	Store   CredentialStore
}

// NewWebAuthn builds the step-up handler bound to mgr.
func NewWebAuthn(mgr *Manager, cfg WebAuthnConfig) (*WebAuthn, error) {
	if strings.TrimSpace(cfg.RPID) == "" {
		return nil, errors.New("authn: webauthn requires an rp_id")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("authn: webauthn requires at least one origin")
	}
	if cfg.Store == nil {
		return nil, errors.New("authn: webauthn requires a credential store")
	}
	origins := make(map[string]bool, len(cfg.Origins))
	for _, o := range cfg.Origins {
		origins[strings.TrimRight(o, "/")] = true
	}
	name := cfg.RPName
	if name == "" {
		name = "Secsy PKI"
	}
	return &WebAuthn{
		mgr:     mgr,
		rpID:    cfg.RPID,
		rpName:  name,
		origins: origins,
		store:   cfg.Store,
		pending: make(map[string]pendingChallenge),
		now:     time.Now,
	}, nil
}

// session loads the caller's live session and enforces CSRF on this POST. It
// writes the error response itself and returns (nil, false) on failure.
func (wa *WebAuthn) session(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess, ok := wa.mgr.currentSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return nil, false
	}
	if !CheckCSRF(r, sess) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return nil, false
	}
	return sess, true
}

func (wa *WebAuthn) putChallenge(sessionID string, c pendingChallenge) {
	c.expires = wa.now().Add(challengeTTL)
	wa.mu.Lock()
	wa.pending[sessionID] = c
	wa.mu.Unlock()
}

// takeChallenge atomically consumes the pending challenge for a session,
// verifying it exists, matches purpose, and has not expired.
func (wa *WebAuthn) takeChallenge(sessionID, purpose string) (pendingChallenge, bool) {
	wa.mu.Lock()
	defer wa.mu.Unlock()
	c, ok := wa.pending[sessionID]
	if !ok {
		return pendingChallenge{}, false
	}
	delete(wa.pending, sessionID)
	if c.purpose != purpose || wa.now().After(c.expires) {
		return pendingChallenge{}, false
	}
	return c, true
}

// --- registration ---

// RegisterBegin returns PublicKeyCredentialCreationOptions for enrolling a new
// passkey for the logged-in operator.
func (wa *WebAuthn) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := wa.session(w, r)
	if !ok {
		return
	}
	challenge := randToken(32)
	wa.putChallenge(sess.ID, pendingChallenge{challenge: challenge, purpose: "register", subject: sess.User.Subject})

	existing, _ := wa.store.ListWebAuthnCredentials(sess.User.Subject)
	exclude := make([]map[string]interface{}, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, map[string]interface{}{"type": "public-key", "id": c.ID})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge": challenge,
		"rp":        map[string]string{"id": wa.rpID, "name": wa.rpName},
		"user": map[string]string{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(sess.User.Subject)),
			"name":        displayName(sess.User),
			"displayName": displayName(sess.User),
		},
		"pubKeyCredParams": []map[string]interface{}{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"excludeCredentials":     exclude,
		"authenticatorSelection": map[string]interface{}{"userVerification": "preferred", "residentKey": "preferred"},
		"timeout":                120000,
		"attestation":            "none",
	})
}

// registerFinishBody is the browser's attestation response, all binary fields
// base64url-encoded by the console JS.
type registerFinishBody struct {
	Name              string `json:"name"`
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

// RegisterFinish verifies a registration response and stores the credential.
func (wa *WebAuthn) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := wa.session(w, r)
	if !ok {
		return
	}
	var body registerFinishBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	chal, ok := wa.takeChallenge(sess.ID, "register")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no pending registration"})
		return
	}
	clientData, err := decodeB64(body.ClientDataJSON)
	if err != nil || !wa.verifyClientData(clientData, "webauthn.create", chal.challenge) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid client data"})
		return
	}
	attObj, err := decodeB64(body.AttestationObject)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation object"})
		return
	}
	ad, err := attestation.ParseWebAuthnAttestationObject(attObj)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "attestation parse: " + err.Error()})
		return
	}
	if !wa.verifyRPIDHash(ad.RPIDHash) || !ad.UserPresent {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authenticator data failed verification"})
		return
	}
	if len(ad.CredentialID) == 0 || ad.PublicKey == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no attested credential"})
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(ad.CredentialID)
	// The credential id the browser reports must match the one inside the
	// authenticated attestation, so the stored id can be trusted for later lookups.
	if body.ID != "" && body.ID != credID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential id mismatch"})
		return
	}
	der, err := x509.MarshalPKIXPublicKey(ad.PublicKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported credential key"})
		return
	}
	cred := &models.WebAuthnCredential{
		ID:           credID,
		Subject:      sess.User.Subject,
		Name:         strings.TrimSpace(body.Name),
		PublicKeyDER: der,
		SignCount:    ad.SignCount,
	}
	if err := wa.store.AddWebAuthnCredential(cred); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store credential"})
		return
	}
	wa.mgr.record(r, sess.User, audit.ActionWebAuthnRegister, cred.ID, audit.ResultSuccess, "name="+cred.Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered", "id": cred.ID})
}

// --- step-up assertion ---

// StepUpBegin returns PublicKeyCredentialRequestOptions for a step-up assertion.
func (wa *WebAuthn) StepUpBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := wa.session(w, r)
	if !ok {
		return
	}
	creds, err := wa.store.ListWebAuthnCredentials(sess.User.Subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load credentials"})
		return
	}
	if len(creds) == 0 {
		writeJSON(w, http.StatusPreconditionRequired, map[string]string{
			"error": "no passkey registered; enroll one before performing high-risk operations",
			"code":  "no_credential",
		})
		return
	}
	allow := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, map[string]interface{}{"type": "public-key", "id": c.ID})
	}
	challenge := randToken(32)
	wa.putChallenge(sess.ID, pendingChallenge{challenge: challenge, purpose: "stepup", subject: sess.User.Subject})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge":        challenge,
		"rpId":             wa.rpID,
		"allowCredentials": allow,
		"userVerification": "preferred",
		"timeout":          120000,
	})
}

type stepUpFinishBody struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

// StepUpFinish verifies a step-up assertion and, on success, marks the session
// as stepped-up for the configured window.
func (wa *WebAuthn) StepUpFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := wa.session(w, r)
	if !ok {
		return
	}
	var body stepUpFinishBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		wa.stepUpFail(w, r, sess.User, "invalid body")
		return
	}
	chal, ok := wa.takeChallenge(sess.ID, "stepup")
	if !ok {
		wa.stepUpFail(w, r, sess.User, "no pending step-up")
		return
	}
	clientData, err := decodeB64(body.ClientDataJSON)
	if err != nil || !wa.verifyClientData(clientData, "webauthn.get", chal.challenge) {
		wa.stepUpFail(w, r, sess.User, "invalid client data")
		return
	}
	cred, err := wa.store.GetWebAuthnCredential(body.ID)
	if err != nil || cred == nil || cred.Subject != sess.User.Subject {
		wa.stepUpFail(w, r, sess.User, "unknown credential")
		return
	}
	authData, err := decodeB64(body.AuthenticatorData)
	if err != nil {
		wa.stepUpFail(w, r, sess.User, "invalid authenticator data")
		return
	}
	ad, err := attestation.ParseWebAuthnAuthData(authData)
	if err != nil || !wa.verifyRPIDHash(ad.RPIDHash) || !ad.UserPresent {
		wa.stepUpFail(w, r, sess.User, "authenticator data failed verification")
		return
	}
	sig, err := decodeB64(body.Signature)
	if err != nil {
		wa.stepUpFail(w, r, sess.User, "invalid signature encoding")
		return
	}
	pub, err := x509.ParsePKIXPublicKey(cred.PublicKeyDER)
	if err != nil {
		wa.stepUpFail(w, r, sess.User, "stored credential key unreadable")
		return
	}
	// WebAuthn assertion signature is over authenticatorData || SHA-256(clientDataJSON).
	clientHash := sha256.Sum256(clientData)
	message := append(append([]byte(nil), authData...), clientHash[:]...)
	if err := verifyWebAuthnSignature(pub, message, sig); err != nil {
		wa.stepUpFail(w, r, sess.User, "signature verification failed")
		return
	}
	// Clone detection: a non-zero counter that fails to advance signals a cloned
	// authenticator. A zero counter (authenticator does not implement one) is
	// exempt.
	if ad.SignCount != 0 && cred.SignCount != 0 && ad.SignCount <= cred.SignCount {
		wa.stepUpFail(w, r, sess.User, "authenticator signature counter did not advance")
		return
	}
	if ad.SignCount > cred.SignCount {
		_ = wa.store.UpdateWebAuthnSignCount(cred.ID, ad.SignCount)
	}

	wa.mgr.sessions.MarkStepUp(sess.ID)
	metrics.RecordAuthStepUp(audit.ResultSuccess)
	wa.mgr.record(r, sess.User, audit.ActionAuthStepUp, cred.ID, audit.ResultSuccess, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "stepped_up",
		"step_up_until": wa.now().Add(wa.mgr.sessions.StepUpTTL()).UTC().Format(time.RFC3339),
	})
}

func (wa *WebAuthn) stepUpFail(w http.ResponseWriter, r *http.Request, user *models.UserInfo, reason string) {
	metrics.RecordAuthStepUp(audit.ResultError)
	wa.mgr.record(r, user, audit.ActionAuthStepUp, "", audit.ResultError, reason)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": reason})
}

// ListCredentials returns the logged-in operator's registered passkeys.
func (wa *WebAuthn) ListCredentials(w http.ResponseWriter, r *http.Request) {
	sess, ok := wa.mgr.currentSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	creds, err := wa.store.ListWebAuthnCredentials(sess.User.Subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load credentials"})
		return
	}
	if creds == nil {
		creds = []models.WebAuthnCredential{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": creds})
}

// --- helpers ---

// verifyClientData validates the decoded clientDataJSON: the ceremony type, the
// challenge (constant-time), and the origin against the configured allowlist.
func (wa *WebAuthn) verifyClientData(raw []byte, wantType, wantChallenge string) bool {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		return false
	}
	if cd.Type != wantType {
		return false
	}
	if !constantTimeEqual(cd.Challenge, wantChallenge) {
		return false
	}
	return wa.origins[strings.TrimRight(cd.Origin, "/")]
}

func (wa *WebAuthn) verifyRPIDHash(got []byte) bool {
	want := sha256.Sum256([]byte(wa.rpID))
	return len(got) == len(want) && constantTimeEqual(string(got), string(want[:]))
}

// verifyWebAuthnSignature verifies an assertion signature over message using the
// stored credential public key. WebAuthn uses ES256 (ASN.1 ECDSA over SHA-256)
// and RS256 (RSA PKCS#1 v1.5 over SHA-256).
func verifyWebAuthnSignature(pub crypto.PublicKey, message, sig []byte) error {
	h := sha256.Sum256(message)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, h[:], sig) {
			return nil
		}
		return errors.New("ecdsa verification failed")
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
	default:
		return errors.New("unsupported credential key type")
	}
}

// decodeB64 decodes a base64url value tolerating optional padding, as browsers
// emit unpadded base64url for WebAuthn ArrayBuffers.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

func displayName(u *models.UserInfo) string {
	if u.Name != "" {
		return u.Name
	}
	if u.Email != "" {
		return u.Email
	}
	return u.Subject
}
