// Package authn implements first-class operator authentication for the console
// and API, layered over the existing RBAC authorization (internal/rbac). It
// provides three complementary mechanisms plus the session, CSRF, step-up, and
// audit plumbing that ties them to a principal:
//
//   - OIDC/OAuth2 Authorization-Code login for the operator console, mapping IdP
//     claims and groups to RBAC roles and tenants (oidclogin.go, mapping.go);
//   - mutual-TLS client-certificate authentication for machine/API callers,
//     binding a verified certificate's subject/SAN to a principal (mtls.go);
//   - optional WebAuthn/passkey step-up for high-risk operations such as CA key
//     ceremony, rotation, revocation, and escrow recovery (webauthn.go).
//
// The package holds no authorization logic of its own: it resolves *who* a
// caller is (a models.UserInfo carrying RBAC roles and tenant roles) and hands
// that to the existing middleware/handlers, which decide *what* they may do.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Auth method labels recorded on a session and in login metrics/audit.
const (
	MethodOIDC     = "oidc"
	MethodPassword = "password"
	MethodMTLS     = "mtls"
	MethodLDAP     = "ldap"
)

// Default cookie names. Operators may override the session cookie name via
// config; the CSRF and OIDC-transaction cookies derive from it.
const (
	DefaultSessionCookie = "secsy_session"
	CSRFCookieSuffix     = "_csrf"
	oidcTxCookieSuffix   = "_oidc_tx"
)

// Session is a server-side console session. It is created after a successful
// interactive login (OIDC or password) and referenced by an opaque, random id
// stored in an HttpOnly cookie. The principal's resolved RBAC roles are captured
// at login so every request the session makes is authorized identically to a
// fresh token — without re-contacting the IdP on the hot path.
type Session struct {
	ID     string
	User   *models.UserInfo
	Method string // MethodOIDC | MethodPassword
	// CSRFToken is a per-session synchronizer token. Unsafe (state-changing)
	// requests authenticated by the session cookie must echo it in the
	// X-CSRF-Token header, defeating cross-site request forgery.
	CSRFToken string
	Created   time.Time
	Expires   time.Time
	// StepUpUntil is the instant until which a WebAuthn step-up remains valid for
	// this session. Zero (or past) means no active step-up; a high-risk operation
	// then requires a fresh assertion.
	StepUpUntil time.Time
}

// stepUpValid reports whether the session currently has an unexpired step-up.
func (s *Session) stepUpValid(now time.Time) bool {
	return !s.StepUpUntil.IsZero() && now.Before(s.StepUpUntil)
}

// StepUpValid reports whether the session currently holds a valid WebAuthn
// step-up (as of now).
func (s *Session) StepUpValid() bool {
	return s.stepUpValid(time.Now())
}

// SessionStore is an in-memory, TTL-bounded store of live console sessions. It
// is safe for concurrent use. Sessions are process-local by design: they hold
// no long-lived secret and are cheap to re-establish via SSO, so a restart (or a
// second replica) simply prompts the operator to log in again rather than
// requiring shared session state.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	stepUp   time.Duration
	now      func() time.Time // overridable in tests
}

// NewSessionStore builds a session store. ttl bounds a session's absolute
// lifetime; stepUpTTL bounds how long a WebAuthn step-up remains valid within a
// session. Non-positive values fall back to conservative defaults.
func NewSessionStore(ttl, stepUpTTL time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if stepUpTTL <= 0 {
		stepUpTTL = 5 * time.Minute
	}
	return &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		stepUp:   stepUpTTL,
		now:      time.Now,
	}
}

// StepUpTTL returns the configured step-up validity window.
func (s *SessionStore) StepUpTTL() time.Duration { return s.stepUp }

// Create establishes a new session for user authenticated via method, returning
// it. The caller is responsible for setting the session cookie.
func (s *SessionStore) Create(user *models.UserInfo, method string) *Session {
	now := s.now()
	sess := &Session{
		ID:        randToken(32),
		User:      user,
		Method:    method,
		CSRFToken: randToken(32),
		Created:   now,
		Expires:   now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	metrics.AuthSessionsActive.Set(float64(s.len()))
	return sess
}

// Get returns the live session for id, or (nil, false) if it is unknown or has
// expired. An expired session is evicted lazily on lookup.
func (s *SessionStore) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if now.After(sess.Expires) {
		delete(s.sessions, id)
		metrics.AuthSessionsActive.Set(float64(len(s.sessions)))
		metrics.AuthLogouts.Inc()
		return nil, false
	}
	return sess, true
}

// Delete terminates the session with the given id (logout). It reports whether a
// session was actually removed.
func (s *SessionStore) Delete(id string) bool {
	s.mu.Lock()
	_, ok := s.sessions[id]
	delete(s.sessions, id)
	n := len(s.sessions)
	s.mu.Unlock()
	if ok {
		metrics.AuthSessionsActive.Set(float64(n))
		metrics.AuthLogouts.Inc()
	}
	return ok
}

// MarkStepUp records a successful WebAuthn step-up on the session, extending its
// step-up validity window. It reports whether the session still exists.
func (s *SessionStore) MarkStepUp(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.StepUpUntil = s.now().Add(s.stepUp)
	return true
}

func (s *SessionStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// randToken returns a URL-safe, base64-encoded cryptographically random token of
// n bytes of entropy. It panics only if the platform RNG fails, which is a
// non-recoverable condition.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("authn: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// constantTimeEqual compares two tokens without leaking length-independent
// timing, used for CSRF-token and cookie comparisons.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// setCookie writes a hardened cookie. httpOnly cookies are hidden from
// JavaScript; the CSRF cookie is deliberately readable so the SPA can echo it in
// a header. secure marks the cookie HTTPS-only.
func setCookie(w http.ResponseWriter, name, value string, maxAge int, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCookie expires a cookie by name.
func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
