package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	testRPID    = "pki.example.com"
	testOrigin  = "https://pki.example.com"
	testSubject = "operator@example.com"
)

// fakeCredStore is an in-memory CredentialStore for the WebAuthn tests.
type fakeCredStore struct {
	creds map[string]*models.WebAuthnCredential
}

func newFakeStore() *fakeCredStore {
	return &fakeCredStore{creds: map[string]*models.WebAuthnCredential{}}
}

func (f *fakeCredStore) AddWebAuthnCredential(c *models.WebAuthnCredential) error {
	cp := *c
	f.creds[c.ID] = &cp
	return nil
}
func (f *fakeCredStore) ListWebAuthnCredentials(subject string) ([]models.WebAuthnCredential, error) {
	var out []models.WebAuthnCredential
	for _, c := range f.creds {
		if c.Subject == subject {
			out = append(out, *c)
		}
	}
	return out, nil
}
func (f *fakeCredStore) GetWebAuthnCredential(id string) (*models.WebAuthnCredential, error) {
	c, ok := f.creds[id]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}
func (f *fakeCredStore) UpdateWebAuthnSignCount(id string, count uint32) error {
	if c, ok := f.creds[id]; ok {
		c.SignCount = count
	}
	return nil
}
func (f *fakeCredStore) DeleteWebAuthnCredential(subject, id string) error {
	delete(f.creds, id)
	return nil
}

// webauthnTestEnv wires a Manager, session, and WebAuthn handler with a fake
// store, plus a simulated authenticator keypair.
type webauthnTestEnv struct {
	wa    *WebAuthn
	mgr   *Manager
	store *fakeCredStore
	sess  *Session
	priv  *ecdsa.PrivateKey
}

func newWebAuthnEnv(t *testing.T) *webauthnTestEnv {
	t.Helper()
	store := newFakeStore()
	sessions := NewSessionStore(time.Hour, 5*time.Minute)
	mgr := NewManager(ManagerOptions{Sessions: sessions, Secure: false})
	wa, err := NewWebAuthn(mgr, WebAuthnConfig{RPID: testRPID, Origins: []string{testOrigin}, Store: store})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	mgr.SetWebAuthn(wa)
	sess := sessions.Create(&models.UserInfo{Subject: testSubject, Name: "Op"}, MethodOIDC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return &webauthnTestEnv{wa: wa, mgr: mgr, store: store, sess: sess, priv: priv}
}

// authedPost builds a session-authenticated, CSRF-carrying POST request.
func (e *webauthnTestEnv) authedPost(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: e.sess.ID})
	r.Header.Set(CSRFHeader, e.sess.CSRFToken)
	return r
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientDataJSON builds a WebAuthn clientDataJSON for the given ceremony type.
func clientDataJSON(typ, challenge string) []byte {
	m := map[string]string{"type": typ, "challenge": challenge, "origin": testOrigin}
	b, _ := json.Marshal(m)
	return b
}

// assertionAuthData builds authenticator data for an assertion (no attested
// credential): rpIdHash(32) || flags || signCount(4).
func assertionAuthData(rpID string, flags byte, signCount uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	out = append(out, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	return out
}

// registerCredential seeds the store with a credential for the test key.
func (e *webauthnTestEnv) seedCredential(t *testing.T, id string, signCount uint32) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&e.priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	e.store.AddWebAuthnCredential(&models.WebAuthnCredential{
		ID: id, Subject: testSubject, PublicKeyDER: der, SignCount: signCount,
	})
}

// signAssertion produces the assertion signature over authData||sha256(clientData).
func (e *webauthnTestEnv) signAssertion(t *testing.T, authData, clientData []byte) []byte {
	t.Helper()
	clientHash := sha256.Sum256(clientData)
	msg := append(append([]byte(nil), authData...), clientHash[:]...)
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, e.priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// stepUpBeginChallenge drives StepUpBegin and returns the issued challenge.
func (e *webauthnTestEnv) stepUpBeginChallenge(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	e.wa.StepUpBegin(rec, e.authedPost("{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("StepUpBegin = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	return resp.Challenge
}

func TestWebAuthnStepUpRoundTrip(t *testing.T) {
	e := newWebAuthnEnv(t)
	const credID = "cred-1"
	e.seedCredential(t, credID, 5)

	challenge := e.stepUpBeginChallenge(t)
	authData := assertionAuthData(testRPID, authDataUP, 6) // counter advances 5 -> 6
	clientData := clientDataJSON("webauthn.get", challenge)
	sig := e.signAssertion(t, authData, clientData)

	body, _ := json.Marshal(map[string]string{
		"id":                credID,
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("StepUpFinish = %d: %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.mgr.sessions.Get(e.sess.ID); !got.StepUpValid() {
		t.Error("session should be stepped up after a valid assertion")
	}
	// The advanced counter must be persisted for clone detection.
	if c, _ := e.store.GetWebAuthnCredential(credID); c.SignCount != 6 {
		t.Errorf("stored sign count = %d, want 6", c.SignCount)
	}
}

func TestWebAuthnStepUpBadSignature(t *testing.T) {
	e := newWebAuthnEnv(t)
	const credID = "cred-1"
	e.seedCredential(t, credID, 0)

	challenge := e.stepUpBeginChallenge(t)
	authData := assertionAuthData(testRPID, authDataUP, 1)
	clientData := clientDataJSON("webauthn.get", challenge)
	sig := e.signAssertion(t, authData, clientData)
	sig[len(sig)-1] ^= 0xff // corrupt the signature

	body, _ := json.Marshal(map[string]string{
		"id":                credID,
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("StepUpFinish with bad signature = %d, want 401", rec.Code)
	}
	if got, _ := e.mgr.sessions.Get(e.sess.ID); got.StepUpValid() {
		t.Error("session must NOT be stepped up after a bad signature")
	}
}

func TestWebAuthnStepUpCloneDetection(t *testing.T) {
	e := newWebAuthnEnv(t)
	const credID = "cred-1"
	e.seedCredential(t, credID, 10)

	challenge := e.stepUpBeginChallenge(t)
	// A non-advancing counter (<= stored) signals a cloned authenticator.
	authData := assertionAuthData(testRPID, authDataUP, 10)
	clientData := clientDataJSON("webauthn.get", challenge)
	sig := e.signAssertion(t, authData, clientData)

	body, _ := json.Marshal(map[string]string{
		"id":                credID,
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("StepUpFinish with non-advancing counter = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

func TestWebAuthnStepUpWrongOrigin(t *testing.T) {
	e := newWebAuthnEnv(t)
	const credID = "cred-1"
	e.seedCredential(t, credID, 0)

	challenge := e.stepUpBeginChallenge(t)
	authData := assertionAuthData(testRPID, authDataUP, 1)
	// clientData with a foreign origin must be rejected.
	cd := map[string]string{"type": "webauthn.get", "challenge": challenge, "origin": "https://evil.example.com"}
	clientData, _ := json.Marshal(cd)
	sig := e.signAssertion(t, authData, clientData)

	body, _ := json.Marshal(map[string]string{
		"id":                credID,
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
	rec := httptest.NewRecorder()
	e.wa.StepUpFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("StepUpFinish with wrong origin = %d, want 401", rec.Code)
	}
}

func TestWebAuthnStepUpNoCredential(t *testing.T) {
	e := newWebAuthnEnv(t) // no credential seeded
	rec := httptest.NewRecorder()
	e.wa.StepUpBegin(rec, e.authedPost("{}"))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("StepUpBegin with no credential = %d, want 428", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no_credential") {
		t.Errorf("expected no_credential code, got %s", rec.Body.String())
	}
}

func TestWebAuthnRequiresCSRF(t *testing.T) {
	e := newWebAuthnEnv(t)
	e.seedCredential(t, "cred-1", 0)
	// A request without the CSRF header must be rejected even with a valid session.
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn", strings.NewReader("{}"))
	r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: e.sess.ID})
	rec := httptest.NewRecorder()
	e.wa.StepUpBegin(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("StepUpBegin without CSRF = %d, want 403", rec.Code)
	}
}

func TestWebAuthnRegisterRoundTrip(t *testing.T) {
	e := newWebAuthnEnv(t)

	// Drive RegisterBegin to obtain the challenge.
	rec := httptest.NewRecorder()
	e.wa.RegisterBegin(rec, e.authedPost("{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("RegisterBegin = %d: %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(rec.Body.Bytes(), &begin)

	// Build an attestation object embedding the test public key as an EC2 COSE key.
	credID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	authData := registrationAuthData(t, testRPID, credID, &e.priv.PublicKey, 1)
	attObj := attestationObjectNone(authData)
	clientData := clientDataJSON("webauthn.create", begin.Challenge)

	body, _ := json.Marshal(map[string]string{
		"name":              "Test Key",
		"id":                b64(credID),
		"clientDataJSON":    b64(clientData),
		"attestationObject": b64(attObj),
	})
	rec = httptest.NewRecorder()
	e.wa.RegisterFinish(rec, e.authedPost(string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("RegisterFinish = %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := e.store.GetWebAuthnCredential(b64(credID))
	if stored == nil {
		t.Fatal("credential was not stored")
	}
	if stored.Subject != testSubject || stored.Name != "Test Key" || stored.SignCount != 1 {
		t.Errorf("unexpected stored credential: %+v", stored)
	}
	// The stored public key must round-trip to the test key.
	pub, err := x509.ParsePKIXPublicKey(stored.PublicKeyDER)
	if err != nil {
		t.Fatalf("parse stored key: %v", err)
	}
	ek, ok := pub.(*ecdsa.PublicKey)
	if !ok || ek.X.Cmp(e.priv.PublicKey.X) != 0 || ek.Y.Cmp(e.priv.PublicKey.Y) != 0 {
		t.Error("stored public key does not match the registered key")
	}
}

// --- minimal CBOR encoding for building test attestation objects ---

const authDataUP = 0x01
const authDataAT = 0x40

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborInt(i int) []byte {
	if i >= 0 {
		return cborHead(0, uint64(i))
	}
	return cborHead(1, uint64(-1-i))
}

func cborBytesEnc(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborTextEnc(s string) []byte  { return append(cborHead(3, uint64(len(s))), []byte(s)...) }

// coseEC2Key encodes an EC2 P-256 COSE key for pub.
func coseEC2Key(pub *ecdsa.PublicKey) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	out := cborHead(5, 5) // map with 5 pairs
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(2)...) // kty EC2
	out = append(out, cborInt(3)...)
	out = append(out, cborInt(-7)...) // alg ES256
	out = append(out, cborInt(-1)...)
	out = append(out, cborInt(1)...) // crv P-256
	out = append(out, cborInt(-2)...)
	out = append(out, cborBytesEnc(x)...)
	out = append(out, cborInt(-3)...)
	out = append(out, cborBytesEnc(y)...)
	return out
}

// registrationAuthData builds authenticator data with attested credential data.
func registrationAuthData(t *testing.T, rpID string, credID []byte, pub *ecdsa.PublicKey, signCount uint32) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, authDataUP|authDataAT)
	out = append(out, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	out = append(out, make([]byte, 16)...) // aaguid
	out = append(out, byte(len(credID)>>8), byte(len(credID)))
	out = append(out, credID...)
	out = append(out, coseEC2Key(pub)...)
	return out
}

// attestationObjectNone wraps authData in a "none"-format attestation object.
func attestationObjectNone(authData []byte) []byte {
	out := cborHead(5, 3) // map with 3 pairs
	out = append(out, cborTextEnc("fmt")...)
	out = append(out, cborTextEnc("none")...)
	out = append(out, cborTextEnc("attStmt")...)
	out = append(out, cborHead(5, 0)...) // empty map
	out = append(out, cborTextEnc("authData")...)
	out = append(out, cborBytesEnc(authData)...)
	return out
}
