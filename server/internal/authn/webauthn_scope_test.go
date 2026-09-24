package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// These tests cover the ownership boundary of the WebAuthn step-up ceremony: a
// passkey belongs to exactly one operator, so it must not be usable by another,
// and none of the ceremony endpoints may be driven without a live session. They
// reuse the fakes and CBOR/attestation helpers in webauthn_test.go.

const otherSubject = "intruder@example.com"

// sessionFor creates a second console session for another principal on the same
// manager, so cross-operator access can be attempted.
func (e *webauthnTestEnv) sessionFor(subject string) *Session {
	return e.mgr.sessions.Create(&models.UserInfo{Subject: subject, Name: subject}, MethodPassword)
}

// authedPostAs builds a session-authenticated, CSRF-carrying POST for sess.
func authedPostAs(mgr *Manager, sess *Session, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: mgr.SessionCookieName(), Value: sess.ID})
	r.Header.Set(CSRFHeader, sess.CSRFToken)
	return r
}

// seedCredentialFor stores a credential owned by subject, using the env's test key.
func (e *webauthnTestEnv) seedCredentialFor(t *testing.T, id, subject string, signCount uint32) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&e.priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	if err := e.store.AddWebAuthnCredential(&models.WebAuthnCredential{
		ID: id, Subject: subject, PublicKeyDER: der, SignCount: signCount,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

// TestWebAuthnCeremonyRequiresSession asserts every WebAuthn endpoint refuses an
// unauthenticated caller, so a passkey can never be enrolled for — or asserted
// on behalf of — a principal the caller has not logged in as.
func TestWebAuthnCeremonyRequiresSession(t *testing.T) {
	e := newWebAuthnEnv(t)
	e.seedCredentialFor(t, "cred-1", testSubject, 1)

	handlers := map[string]http.HandlerFunc{
		"RegisterBegin":   e.wa.RegisterBegin,
		"RegisterFinish":  e.wa.RegisterFinish,
		"StepUpBegin":     e.wa.StepUpBegin,
		"StepUpFinish":    e.wa.StepUpFinish,
		"ListCredentials": e.wa.ListCredentials,
	}
	requests := map[string]func() *http.Request{
		"no cookie": func() *http.Request {
			return httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
		},
		"unknown session cookie": func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
			r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: "not-a-session"})
			return r
		},
		"logged-out session cookie": func() *http.Request {
			dead := e.sessionFor("gone@example.com")
			e.mgr.sessions.Delete(dead.ID)
			r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
			r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: dead.ID})
			r.Header.Set(CSRFHeader, dead.CSRFToken)
			return r
		},
	}
	for hname, h := range handlers {
		for rname, mk := range requests {
			rec := httptest.NewRecorder()
			h(rec, mk())
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with %s = %d, want 401; body=%s", hname, rname, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "login required") {
				t.Errorf("%s with %s body = %s, want a login-required error", hname, rname, rec.Body.String())
			}
		}
	}
	// No credential may have been created or removed by any of that.
	creds, _ := e.store.ListWebAuthnCredentials(testSubject)
	if len(creds) != 1 {
		t.Errorf("credentials for %s = %d, want the single seeded one", testSubject, len(creds))
	}
}

// TestWebAuthnRegisterRequiresCSRF asserts the enrolment endpoints are not
// forgeable cross-site: a valid session cookie without the synchronizer token
// must not enroll a passkey.
func TestWebAuthnRegisterRequiresCSRF(t *testing.T) {
	e := newWebAuthnEnv(t)
	for name, h := range map[string]http.HandlerFunc{
		"RegisterBegin":  e.wa.RegisterBegin,
		"RegisterFinish": e.wa.RegisterFinish,
	} {
		r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: e.sess.ID})
		rec := httptest.NewRecorder()
		h(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without a CSRF token = %d, want 403", name, rec.Code)
		}
		// A wrong token must fare no better than a missing one.
		r = httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: e.sess.ID})
		r.Header.Set(CSRFHeader, "not-the-token")
		rec = httptest.NewRecorder()
		h(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s with a wrong CSRF token = %d, want 403", name, rec.Code)
		}
	}
	if creds, _ := e.store.ListWebAuthnCredentials(testSubject); len(creds) != 0 {
		t.Errorf("a CSRF-less request enrolled %d credential(s)", len(creds))
	}
}

// TestWebAuthnStepUpRejectsAnotherOperatorsCredential is the ownership check: an
// operator who knows (or steals) another operator's credential id must not be able
// to satisfy step-up with it, even when the assertion signature itself is valid.
// Without this check a single enrolled passkey would step up every account.
func TestWebAuthnStepUpRejectsAnotherOperatorsCredential(t *testing.T) {
	e := newWebAuthnEnv(t)
	const victimCred = "victim-cred"
	e.seedCredentialFor(t, victimCred, testSubject, 5)

	// The intruder has a session and a passkey of their own, so their step-up
	// ceremony starts normally.
	intruder := e.sessionFor(otherSubject)
	e.seedCredentialFor(t, "intruder-cred", otherSubject, 1)

	rec := httptest.NewRecorder()
	e.wa.StepUpBegin(rec, authedPostAs(e.mgr, intruder, "{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("StepUpBegin for the intruder = %d: %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Challenge        string `json:"challenge"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	// The allow-list must only name the intruder's own credential.
	for _, c := range begin.AllowCredentials {
		if c.ID == victimCred {
			t.Fatalf("StepUpBegin offered another operator's credential %q", c.ID)
		}
	}

	// Now assert with the victim's credential id, correctly signed by the shared
	// test key (so only the ownership check can reject it).
	authData := assertionAuthData(testRPID, authDataUP, 6)
	clientData := clientDataJSON("webauthn.get", begin.Challenge)
	sig := e.signAssertion(t, authData, clientData)
	body, _ := json.Marshal(map[string]string{
		"id":                victimCred,
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec = httptest.NewRecorder()
	e.wa.StepUpFinish(rec, authedPostAs(e.mgr, intruder, string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("StepUpFinish with another operator's credential = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.mgr.sessions.Get(intruder.ID); got.StepUpValid() {
		t.Fatal("the intruder's session was stepped up with another operator's passkey")
	}
	if got, _ := e.mgr.sessions.Get(e.sess.ID); got.StepUpValid() {
		t.Fatal("the victim's session was stepped up by someone else's request")
	}
	// The victim's counter must be untouched by the failed attempt.
	if c, _ := e.store.GetWebAuthnCredential(victimCred); c.SignCount != 5 {
		t.Errorf("victim credential sign count = %d, want 5 (unchanged)", c.SignCount)
	}
}

// TestWebAuthnStepUpChallengeIsBoundToTheSession asserts a challenge issued to one
// session cannot be completed by another: the pending challenge is keyed by
// session id, so a stolen challenge is useless without that session.
func TestWebAuthnStepUpChallengeIsBoundToTheSession(t *testing.T) {
	e := newWebAuthnEnv(t)
	e.seedCredentialFor(t, "cred-a", testSubject, 1)
	other := e.sessionFor(otherSubject)
	e.seedCredentialFor(t, "cred-b", otherSubject, 1)

	// Victim begins a step-up and the challenge leaks.
	challenge := e.stepUpBeginChallenge(t)

	// The other session tries to complete it (with its own valid credential).
	authData := assertionAuthData(testRPID, authDataUP, 2)
	clientData := clientDataJSON("webauthn.get", challenge)
	sig := e.signAssertion(t, authData, clientData)
	body, _ := json.Marshal(map[string]string{
		"id":                "cred-b",
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, authedPostAs(e.mgr, other, string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("completing another session's challenge = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.mgr.sessions.Get(other.ID); got.StepUpValid() {
		t.Fatal("a session was stepped up using a challenge issued to a different session")
	}
}

// TestWebAuthnRegisterFinishBindsCredentialToTheCaller asserts a freshly enrolled
// passkey is owned by the session that enrolled it, and is invisible to and
// unusable by anyone else.
func TestWebAuthnRegisterFinishBindsCredentialToTheCaller(t *testing.T) {
	e := newWebAuthnEnv(t)
	// Give the victim a passkey so their own step-up ceremony can start below.
	e.seedCredentialFor(t, "victim-own-cred", testSubject, 1)
	intruder := e.sessionFor(otherSubject)

	// The intruder enrolls a passkey of their own.
	rec := httptest.NewRecorder()
	e.wa.RegisterBegin(rec, authedPostAs(e.mgr, intruder, "{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("RegisterBegin = %d: %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Challenge string            `json:"challenge"`
		User      map[string]string `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	// The user handle the authenticator will bind the passkey to must be the
	// calling session's own principal, not a client-supplied value.
	if got, want := begin.User["id"], b64([]byte(otherSubject)); got != want {
		t.Errorf("creation options user.id = %q, want %q (the caller's subject)", got, want)
	}

	credID := []byte{9, 9, 9, 1}
	authData := registrationAuthData(t, testRPID, credID, &e.priv.PublicKey, 1)
	body, _ := json.Marshal(map[string]string{
		"name":              "Intruder Key",
		"id":                b64(credID),
		"clientDataJSON":    b64(clientDataJSON("webauthn.create", begin.Challenge)),
		"attestationObject": b64(attestationObjectNone(authData)),
	})
	rec = httptest.NewRecorder()
	e.wa.RegisterFinish(rec, authedPostAs(e.mgr, intruder, string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("RegisterFinish = %d: %s", rec.Code, rec.Body.String())
	}

	stored, _ := e.store.GetWebAuthnCredential(b64(credID))
	if stored == nil {
		t.Fatal("credential was not stored")
	}
	if stored.Subject != otherSubject {
		t.Fatalf("credential subject = %q, want the enrolling session's principal %q", stored.Subject, otherSubject)
	}
	// It must not show up for, or be usable by, the other operator.
	victimCreds, _ := e.store.ListWebAuthnCredentials(testSubject)
	if len(victimCreds) != 1 || victimCreds[0].ID != "victim-own-cred" {
		t.Errorf("the enrolment leaked into %s's credentials: %+v", testSubject, victimCreds)
	}
	challenge := e.stepUpBeginChallenge(t) // begins for e.sess (testSubject)
	authData = assertionAuthData(testRPID, authDataUP, 2)
	clientData := clientDataJSON("webauthn.get", challenge)
	sig := e.signAssertion(t, authData, clientData)
	body, _ = json.Marshal(map[string]string{
		"id":                b64(credID),
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec = httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stepping up with another operator's fresh credential = %d, want 401", rec.Code)
	}
}

// TestWebAuthnRegisterFinishRejectsMismatchedCredentialID asserts the browser's
// reported credential id must match the one inside the attested authenticator
// data, so the stored id (used for every later lookup) cannot be chosen freely by
// the client — e.g. set to another operator's credential id.
func TestWebAuthnRegisterFinishRejectsMismatchedCredentialID(t *testing.T) {
	e := newWebAuthnEnv(t)
	const victimCred = "victim-cred"
	e.seedCredentialFor(t, victimCred, testSubject, 7)
	intruder := e.sessionFor(otherSubject)

	rec := httptest.NewRecorder()
	e.wa.RegisterBegin(rec, authedPostAs(e.mgr, intruder, "{}"))
	var begin struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	authData := registrationAuthData(t, testRPID, []byte{4, 4, 4, 4}, &e.priv.PublicKey, 1)
	body, _ := json.Marshal(map[string]string{
		"name":              "Overwrite",
		"id":                victimCred, // not the attested credential id
		"clientDataJSON":    b64(clientDataJSON("webauthn.create", begin.Challenge)),
		"attestationObject": b64(attestationObjectNone(authData)),
	})
	rec = httptest.NewRecorder()
	e.wa.RegisterFinish(rec, authedPostAs(e.mgr, intruder, string(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("RegisterFinish with a mismatched credential id = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// The victim's credential must be intact (not overwritten or re-owned).
	c, _ := e.store.GetWebAuthnCredential(victimCred)
	if c == nil || c.Subject != testSubject || c.SignCount != 7 {
		t.Fatalf("the victim's credential was modified: %+v", c)
	}
}

// TestListCredentialsIsScopedToTheCaller asserts the credential listing only ever
// returns the caller's own passkeys.
func TestListCredentialsIsScopedToTheCaller(t *testing.T) {
	e := newWebAuthnEnv(t)
	e.seedCredentialFor(t, "mine-1", testSubject, 1)
	e.seedCredentialFor(t, "mine-2", testSubject, 1)
	e.seedCredentialFor(t, "theirs-1", otherSubject, 1)

	get := func(sess *Session) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/auth/webauthn/credentials", nil)
		r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: sess.ID})
		rec := httptest.NewRecorder()
		e.wa.ListCredentials(rec, r)
		return rec
	}

	rec := get(e.sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListCredentials = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Credentials []models.WebAuthnCredential `json:"credentials"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) != 2 {
		t.Fatalf("credentials = %d, want 2", len(resp.Credentials))
	}
	for _, c := range resp.Credentials {
		if c.Subject != testSubject {
			t.Errorf("listing leaked a credential owned by %q", c.Subject)
		}
	}
	if strings.Contains(rec.Body.String(), "theirs-1") {
		t.Errorf("listing leaked another operator's credential: %s", rec.Body.String())
	}

	// An operator with no passkeys gets an empty list, not null and not someone
	// else's.
	empty := e.sessionFor("fresh@example.com")
	rec = get(empty)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListCredentials for a fresh operator = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) != 0 {
		t.Errorf("a fresh operator sees %d credential(s): %+v", len(resp.Credentials), resp.Credentials)
	}
	if !strings.Contains(rec.Body.String(), `"credentials":[]`) {
		t.Errorf("empty listing should serialize as [], got %s", rec.Body.String())
	}
}

// TestWebAuthnStepUpRejectsForeignKeySignature asserts the stored public key is
// what verifies the assertion: a syntactically perfect assertion signed by a
// different keypair must fail.
func TestWebAuthnStepUpRejectsForeignKeySignature(t *testing.T) {
	e := newWebAuthnEnv(t)
	e.seedCredentialFor(t, "cred-1", testSubject, 1)
	challenge := e.stepUpBeginChallenge(t)

	authData := assertionAuthData(testRPID, authDataUP, 2)
	clientData := clientDataJSON("webauthn.get", challenge)

	// Sign with an unrelated key.
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	saved := e.priv
	e.priv = foreign
	sig := e.signAssertion(t, authData, clientData)
	e.priv = saved

	body, _ := json.Marshal(map[string]string{
		"id":                "cred-1",
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("assertion signed by a foreign key = %d, want 401", rec.Code)
	}
	if got, _ := e.mgr.sessions.Get(e.sess.ID); got.StepUpValid() {
		t.Fatal("a foreign-key assertion stepped up the session")
	}
}
