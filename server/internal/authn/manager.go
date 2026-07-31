package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/google/uuid"
)

// EventSink appends a sealed event to the tamper-evident audit log. It is
// satisfied by *database.DB; declaring it as an interface keeps this package
// free of a database dependency and makes the login/step-up flows unit-testable
// with a fake sink.
type EventSink interface {
	AppendEvent(e *audit.Event) error
}

// Manager owns the shared authentication state (sessions, audit sink, cookie
// policy) and registers the interactive auth endpoints: OIDC login/callback,
// logout, the CSRF-token endpoint, and the WebAuthn step-up ceremony. It is
// constructed in main.go and its optional sub-features (OIDC login, WebAuthn)
// are nil when not configured.
type Manager struct {
	sessions      *SessionStore
	sessionCookie string
	secure        bool
	audit         EventSink
	requestID     func(context.Context) string
	// consoleRedirect is where a successful OIDC login lands the browser.
	consoleRedirect string

	login    *OIDCLogin // nil when interactive OIDC login is not configured
	webauthn *WebAuthn  // nil when WebAuthn step-up is not configured

	// password authenticates a console username/password (the built-in root
	// user), returning the resolved principal. Nil disables password login (only
	// SSO). It lets a password login establish a real session — and therefore CSRF
	// protection and WebAuthn step-up — rather than replaying basic-auth per call.
	password PasswordAuthenticator

	// ldap authenticates a console username/password against an LDAP / Active
	// Directory server, mapping directory groups to RBAC roles (Task 159). Nil when
	// LDAP authentication is not configured. Like password login it establishes a
	// real session, so the interactive directory login also gets CSRF protection
	// and WebAuthn step-up.
	ldap *LDAPAuthenticator
}

// PasswordAuthenticator validates a console username/password and returns the
// resolved principal. It returns (nil, false) on invalid credentials.
type PasswordAuthenticator func(username, password string) (*models.UserInfo, bool)

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	Sessions      *SessionStore
	SessionCookie string
	// Secure marks issued cookies HTTPS-only. It should be true in production; the
	// server refuses cleartext HTTP unless explicitly opted in, so this defaults
	// to true.
	Secure bool
	Audit  EventSink
	// RequestID resolves the correlation id for the in-flight request from its
	// context, injected to avoid an import cycle with the middleware package.
	RequestID       func(context.Context) string
	ConsoleRedirect string
}

// NewManager builds the auth manager. Login and WebAuthn are attached separately
// via SetLogin/SetWebAuthn when their configuration is present.
func NewManager(o ManagerOptions) *Manager {
	cookie := o.SessionCookie
	if cookie == "" {
		cookie = DefaultSessionCookie
	}
	redirect := o.ConsoleRedirect
	if redirect == "" {
		redirect = "/console/"
	}
	reqID := o.RequestID
	if reqID == nil {
		reqID = func(context.Context) string { return "" }
	}
	return &Manager{
		sessions:        o.Sessions,
		sessionCookie:   cookie,
		secure:          o.Secure,
		audit:           o.Audit,
		requestID:       reqID,
		consoleRedirect: redirect,
	}
}

// SetLogin attaches the OIDC interactive-login handler.
func (m *Manager) SetLogin(l *OIDCLogin) { m.login = l }

// SetWebAuthn attaches the WebAuthn step-up handler.
func (m *Manager) SetWebAuthn(w *WebAuthn) { m.webauthn = w }

// SetPasswordAuthenticator attaches the console password authenticator.
func (m *Manager) SetPasswordAuthenticator(p PasswordAuthenticator) { m.password = p }

// SetLDAPAuthenticator attaches the console LDAP / Active Directory authenticator.
func (m *Manager) SetLDAPAuthenticator(l *LDAPAuthenticator) { m.ldap = l }

// LDAPEnabled reports whether interactive LDAP login is configured.
func (m *Manager) LDAPEnabled() bool { return m != nil && m.ldap != nil }

// SessionCookieName returns the configured session cookie name.
func (m *Manager) SessionCookieName() string { return m.sessionCookie }

// csrfCookieName returns the (JS-readable) CSRF cookie name derived from the
// session cookie name.
func (m *Manager) csrfCookieName() string { return m.sessionCookie + CSRFCookieSuffix }

// LoginEnabled reports whether interactive OIDC login is configured.
func (m *Manager) LoginEnabled() bool { return m != nil && m.login != nil }

// WebAuthnEnabled reports whether WebAuthn step-up is configured.
func (m *Manager) WebAuthnEnabled() bool { return m != nil && m.webauthn != nil }

// Register mounts the auth endpoints on mux. Endpoints that require a live
// session (logout, CSRF refresh, WebAuthn) read the session cookie directly; the
// login/callback endpoints are public.
func (m *Manager) Register(mux *http.ServeMux) {
	if m.login != nil {
		mux.HandleFunc("GET /auth/login", m.login.Begin)
		mux.HandleFunc("GET /auth/callback", m.login.Callback)
	}
	mux.HandleFunc("POST /auth/logout", m.Logout)
	mux.HandleFunc("GET /auth/session", m.SessionInfo)
	if m.password != nil {
		mux.HandleFunc("POST /auth/login/password", m.LoginPassword)
	}
	if m.ldap != nil {
		mux.HandleFunc("POST /auth/login/ldap", m.LoginLDAP)
	}
	if m.webauthn != nil {
		mux.HandleFunc("POST /auth/webauthn/register/begin", m.webauthn.RegisterBegin)
		mux.HandleFunc("POST /auth/webauthn/register/finish", m.webauthn.RegisterFinish)
		mux.HandleFunc("POST /auth/webauthn/stepup/begin", m.webauthn.StepUpBegin)
		mux.HandleFunc("POST /auth/webauthn/stepup/finish", m.webauthn.StepUpFinish)
		mux.HandleFunc("GET /auth/webauthn/credentials", m.webauthn.ListCredentials)
	}
}

// currentSession loads the live session referenced by the request's session
// cookie, or (nil, false) when there is none.
func (m *Manager) currentSession(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(m.sessionCookie)
	if err != nil {
		return nil, false
	}
	return m.sessions.Get(c.Value)
}

// startSession creates a session for user, sets the session (HttpOnly) and CSRF
// (JS-readable) cookies, and returns it.
func (m *Manager) startSession(w http.ResponseWriter, user *models.UserInfo, method string) *Session {
	sess := m.sessions.Create(user, method)
	maxAge := int(time.Until(sess.Expires).Seconds())
	setCookie(w, m.sessionCookie, sess.ID, maxAge, true, m.secure)
	setCookie(w, m.csrfCookieName(), sess.CSRFToken, maxAge, false, m.secure)
	return sess
}

// Logout terminates the caller's session and clears the auth cookies.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := m.currentSession(r)
	if ok {
		m.sessions.Delete(sess.ID)
		m.record(r, sess.User, audit.ActionAuthLogout, sess.ID, audit.ResultSuccess, "method="+sess.Method)
	}
	clearCookie(w, m.sessionCookie, m.secure)
	clearCookie(w, m.csrfCookieName(), m.secure)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// LoginPassword authenticates a console username/password and, on success,
// establishes a session (with CSRF token) — the interactive equivalent of the
// stateless basic-auth path, but enabling CSRF protection and WebAuthn step-up.
func (m *Manager) LoginPassword(w http.ResponseWriter, r *http.Request) {
	if m.password == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "password login disabled"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	user, ok := m.password(body.Username, body.Password)
	if !ok {
		recordLoginMetric(MethodPassword, false)
		m.record(r, nil, audit.ActionAuthLoginFailed, "", audit.ResultDenied, "method=password user="+body.Username)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	sess := m.startSession(w, user, MethodPassword)
	recordLoginMetric(MethodPassword, true)
	m.record(r, user, audit.ActionAuthLogin, sess.ID, audit.ResultSuccess, "method=password")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":       user,
		"csrf_token": sess.CSRFToken,
	})
}

// LoginLDAP authenticates a console username/password against the configured LDAP
// / Active Directory server and, on success, establishes a session with a CSRF
// token — the directory equivalent of LoginPassword. It emits login audit and
// metrics consistent with the OIDC path (method=ldap). The error surfaced to the
// caller is deliberately generic (no user-enumeration signal); the audit detail
// carries the reason for operators.
func (m *Manager) LoginLDAP(w http.ResponseWriter, r *http.Request) {
	if m.ldap == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ldap login disabled"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	user, err := m.ldap.Authenticate(r.Context(), body.Username, body.Password)
	if err != nil {
		recordLoginMetric(MethodLDAP, false)
		m.record(r, nil, audit.ActionAuthLoginFailed, "", audit.ResultDenied,
			"method=ldap user="+body.Username+" reason="+ldapFailReason(err))
		status, msg := ldapLoginErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	sess := m.startSession(w, user, MethodLDAP)
	recordLoginMetric(MethodLDAP, true)
	m.record(r, user, audit.ActionAuthLogin, sess.ID, audit.ResultSuccess, "method=ldap")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":       user,
		"csrf_token": sess.CSRFToken,
	})
}

// ldapFailReason classifies an authentication error into a short, non-sensitive
// audit token.
func ldapFailReason(err error) string {
	switch {
	case errors.Is(err, ErrLDAPInvalidCredentials):
		return "invalid_credentials"
	case errors.Is(err, ErrLDAPUnavailable):
		return "directory_unavailable"
	default:
		// A resolver denial (e.g. no RBAC role assigned).
		return "no_access"
	}
}

// ldapLoginErrorResponse maps an authentication error to an HTTP status and a
// client-facing message. Invalid credentials and unreachable-directory both map to
// 401 with a generic message (no enumeration / infrastructure disclosure); a
// resolver denial (no role) maps to 403 and surfaces the resolver's own message.
func ldapLoginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ErrLDAPInvalidCredentials):
		return http.StatusUnauthorized, "invalid credentials"
	case errors.Is(err, ErrLDAPUnavailable):
		return http.StatusUnauthorized, "invalid credentials"
	default:
		return http.StatusForbidden, err.Error()
	}
}

// SessionInfo returns the current session's principal and CSRF token, so the SPA
// can restore state after a redirect-based login without a separate /api/me
// round-trip. It returns 401 when there is no live session.
func (m *Manager) SessionInfo(w http.ResponseWriter, r *http.Request) {
	sess, ok := m.currentSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":       sess.User,
		"csrf_token": sess.CSRFToken,
		"method":     sess.Method,
		"step_up":    sess.stepUpValid(time.Now()),
		"webauthn":   m.WebAuthnEnabled(),
		"expires_at": sess.Expires.UTC().Format(time.RFC3339),
	})
}

// record appends an authentication audit event. A nil sink or a storage failure
// is tolerated: authentication must not fail because the log write did.
func (m *Manager) record(r *http.Request, user *models.UserInfo, action, target, result, detail string) {
	if m.audit == nil {
		return
	}
	e := &audit.Event{
		ID:        uuid.New().String(),
		Action:    action,
		Target:    target,
		Result:    result,
		Detail:    detail,
		IP:        clientIP(r),
		RequestID: m.requestID(r.Context()),
	}
	if user != nil {
		e.Actor = user.Subject
		e.ActorName = user.Name
		if user.IsRoot {
			e.ActorRoles = "root"
		} else {
			e.ActorRoles = joinStrings(user.Roles)
		}
	}
	_ = m.audit.AppendEvent(e)
}

// clientIP extracts a best-effort client IP, honoring X-Forwarded-For when the
// deployment terminates TLS at a trusted proxy.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func joinStrings(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// recordLoginMetric is a small helper so login handlers record consistently.
func recordLoginMetric(method string, ok bool) { metrics.RecordAuthLogin(method, ok) }
