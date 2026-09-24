package authn

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// This file covers the console session lifecycle in manager.go: password login,
// session issuance, SessionInfo, logout, endpoint registration, and the
// feature-enabled accessors. These decide *who is logged in*, so the assertions
// below are written so that a regression (accepting a wrong password, a logout
// that does not invalidate, a SessionInfo that trusts an unknown token, a
// predictable or reused session id) fails the test rather than merely reducing
// coverage.

// --- test doubles and harness ---

// recordingSink is an in-memory EventSink capturing the audit events the auth
// manager appends, so tests can assert on the recorded login/logout trail. It is
// mutex-guarded because the concurrency test drives logins from many goroutines.
type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
	err    error // when non-nil, every append fails (audit outage)
}

func (s *recordingSink) AppendEvent(e *audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, *e)
	return s.err
}

// withAction returns the recorded events for a single audit action.
func (s *recordingSink) withAction(action string) []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []audit.Event
	for _, e := range s.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (s *recordingSink) reset() {
	s.mu.Lock()
	s.events = nil
	s.mu.Unlock()
}

// Console credentials used by the harness' password authenticator.
const (
	opRootUser  = "root"
	opRootPass  = "correct-horse-battery-staple"
	opAliceUser = "alice"
	opAlicePass = "alice-s3cret"
)

// loginEnv wires a Manager with a session store, a recording audit sink, and a
// password authenticator that mirrors the production wiring in
// cmd/server/auth.go (constant-time compare, single (nil,false) rejection for
// every failure mode).
type loginEnv struct {
	mgr      *Manager
	sessions *SessionStore
	sink     *recordingSink

	mu    sync.Mutex
	calls []string // usernames the authenticator was asked about
}

func newLoginEnv(t *testing.T) *loginEnv {
	t.Helper()
	e := &loginEnv{
		sessions: NewSessionStore(time.Hour, 5*time.Minute),
		sink:     &recordingSink{},
	}
	e.mgr = NewManager(ManagerOptions{
		Sessions:  e.sessions,
		Secure:    true,
		Audit:     e.sink,
		RequestID: func(context.Context) string { return "req-abc" },
	})
	e.mgr.SetPasswordAuthenticator(func(u, p string) (*models.UserInfo, bool) {
		e.mu.Lock()
		e.calls = append(e.calls, u)
		e.mu.Unlock()
		switch {
		case subtle.ConstantTimeCompare([]byte(u), []byte(opRootUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(opRootPass)) == 1:
			return &models.UserInfo{Subject: "root", Name: "Root User", IsRoot: true}, true
		case subtle.ConstantTimeCompare([]byte(u), []byte(opAliceUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(opAlicePass)) == 1:
			return &models.UserInfo{Subject: "alice@example.com", Name: "Alice", Roles: []string{"issuer"}}, true
		}
		return nil, false
	})
	return e
}

// postLogin drives POST /auth/login/password with a raw JSON body.
func (e *loginEnv) postLogin(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/auth/login/password", strings.NewReader(body))
	w := httptest.NewRecorder()
	e.mgr.LoginPassword(w, r)
	return w
}

// loginAs performs a successful login and returns the issued session id.
func (e *loginEnv) loginAs(t *testing.T, user, pass string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": user, "password": pass})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	rec := e.postLogin(string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("login as %q: status = %d, want 200; body=%s", user, rec.Code, rec.Body.String())
	}
	c := cookieNamed(rec, e.mgr.SessionCookieName())
	if c == nil || c.Value == "" {
		t.Fatalf("login as %q set no session cookie: %v", user, rec.Result().Cookies())
	}
	return c.Value
}

// sessionInfo drives GET /auth/session carrying the given session cookie value.
// An empty id sends no cookie at all.
func (e *loginEnv) sessionInfo(id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	if id != "" {
		r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: id})
	}
	w := httptest.NewRecorder()
	e.mgr.SessionInfo(w, r)
	return w
}

// logout drives POST /auth/logout carrying the given session cookie value.
func (e *loginEnv) logout(id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	if id != "" {
		r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: id})
	}
	w := httptest.NewRecorder()
	e.mgr.Logout(w, r)
	return w
}

// cookieNamed returns the response's cookie with the given name, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func bodyJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return m
}

// --- LoginPassword: success path ---

// TestLoginPasswordIssuesHardenedSession asserts a successful password login
// establishes exactly one server-side session, binds it to an HttpOnly+Secure
// cookie, and hands the SPA a CSRF token in a deliberately JS-readable cookie.
func TestLoginPasswordIssuesHardenedSession(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.postLogin(`{"username":"root","password":"` + opRootPass + `"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	if n := e.sessions.len(); n != 1 {
		t.Fatalf("session count after login = %d, want 1", n)
	}
	sc := cookieNamed(rec, DefaultSessionCookie)
	if sc == nil {
		t.Fatalf("no session cookie; got %v", rec.Result().Cookies())
	}
	sess, ok := e.sessions.Get(sc.Value)
	if !ok {
		t.Fatalf("session cookie %q does not resolve to a live session", sc.Value)
	}
	if sess.User == nil || sess.User.Subject != "root" || !sess.User.IsRoot {
		t.Errorf("session principal = %+v, want the root user", sess.User)
	}
	if sess.Method != MethodPassword {
		t.Errorf("session method = %q, want %q", sess.Method, MethodPassword)
	}

	// Session cookie must be HttpOnly (unreadable by JS), Secure (HTTPS-only,
	// since the manager was built with Secure: true), SameSite-Lax and root-scoped.
	if !sc.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if !sc.Secure {
		t.Error("session cookie must be Secure when the manager is configured secure")
	}
	if sc.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax", sc.SameSite)
	}
	if sc.Path != "/" {
		t.Errorf("session cookie path = %q, want /", sc.Path)
	}
	if sc.MaxAge <= 0 || sc.MaxAge > int(time.Hour/time.Second) {
		t.Errorf("session cookie MaxAge = %d, want a positive value within the 1h TTL", sc.MaxAge)
	}

	// The CSRF cookie is the synchronizer token and must be readable by the SPA
	// (not HttpOnly) but still Secure, and must match the session's token.
	cc := cookieNamed(rec, DefaultSessionCookie+CSRFCookieSuffix)
	if cc == nil {
		t.Fatalf("no CSRF cookie; got %v", rec.Result().Cookies())
	}
	if cc.HttpOnly {
		t.Error("CSRF cookie must not be HttpOnly: the SPA has to echo it in a header")
	}
	if !cc.Secure {
		t.Error("CSRF cookie must be Secure")
	}
	if cc.Value != sess.CSRFToken {
		t.Errorf("CSRF cookie = %q, want the session token %q", cc.Value, sess.CSRFToken)
	}

	body := bodyJSON(t, rec)
	if got, _ := body["csrf_token"].(string); got != sess.CSRFToken {
		t.Errorf("csrf_token in body = %q, want %q", got, sess.CSRFToken)
	}
	if body["user"] == nil {
		t.Error("response must carry the resolved principal")
	}
	// The credential must never be reflected back to the caller.
	if strings.Contains(rec.Body.String(), opRootPass) {
		t.Errorf("login response echoes the password: %s", rec.Body.String())
	}

	// A successful login is audited with the session id as target.
	ev := e.sink.withAction(audit.ActionAuthLogin)
	if len(ev) != 1 {
		t.Fatalf("auth.login events = %d, want 1", len(ev))
	}
	if ev[0].Result != audit.ResultSuccess || ev[0].Target != sess.ID ||
		ev[0].Actor != "root" || ev[0].ActorRoles != "root" ||
		ev[0].Detail != "method=password" || ev[0].RequestID != "req-abc" {
		t.Errorf("unexpected login audit event: %+v", ev[0])
	}
	if len(e.sink.withAction(audit.ActionAuthLoginFailed)) != 0 {
		t.Error("a successful login must not record a failure event")
	}
}

// --- LoginPassword: rejection paths ---

// TestLoginPasswordRejectsBadCredentials is the core authentication-bypass guard:
// every invalid credential shape must be refused with 401, no session, and no
// cookies.
func TestLoginPasswordRejectsBadCredentials(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"wrong password", `{"username":"root","password":"wrong"}`},
		{"unknown user", `{"username":"nosuchuser","password":"` + opRootPass + `"}`},
		{"empty password", `{"username":"root","password":""}`},
		{"empty username", `{"username":"","password":"` + opRootPass + `"}`},
		{"both empty", `{"username":"","password":""}`},
		{"missing fields", `{}`},
		{"username case differs", `{"username":"ROOT","password":"` + opRootPass + `"}`},
		{"password with trailing space", `{"username":"root","password":"` + opRootPass + ` "}`},
		{"password is a prefix", `{"username":"root","password":"` + opRootPass[:5] + `"}`},
		{"username carries whitespace", `{"username":" root ","password":"` + opRootPass + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t)
			rec := e.postLogin(tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"invalid credentials"}` {
				t.Errorf("body = %s, want the generic invalid-credentials error", got)
			}
			if cs := rec.Result().Cookies(); len(cs) != 0 {
				t.Errorf("a failed login must set no cookies, got %v", cs)
			}
			if n := e.sessions.len(); n != 0 {
				t.Fatalf("a failed login created %d session(s)", n)
			}
			ev := e.sink.withAction(audit.ActionAuthLoginFailed)
			if len(ev) != 1 || ev[0].Result != audit.ResultDenied {
				t.Fatalf("failed login audit = %+v, want a single denied event", ev)
			}
			if ev[0].Actor != "" || ev[0].ActorRoles != "" {
				t.Errorf("a rejected login must not attribute an actor: %+v", ev[0])
			}
			if len(e.sink.withAction(audit.ActionAuthLogin)) != 0 {
				t.Error("a rejected login must not record a success event")
			}
		})
	}
}

// TestLoginPasswordDoesNotEnableUserEnumeration asserts the client-visible
// outcome of "no such user" is byte-identical to "wrong password": status,
// headers that could differ, body, and cookies. A divergence would let an
// unauthenticated attacker enumerate valid console accounts.
func TestLoginPasswordDoesNotEnableUserEnumeration(t *testing.T) {
	e := newLoginEnv(t)
	unknown := e.postLogin(`{"username":"nosuchuser","password":"whatever"}`)
	e.sink.reset()
	wrongPass := e.postLogin(`{"username":"root","password":"whatever"}`)

	if unknown.Code != wrongPass.Code {
		t.Errorf("status differs: unknown user = %d, wrong password = %d", unknown.Code, wrongPass.Code)
	}
	if unknown.Body.String() != wrongPass.Body.String() {
		t.Errorf("response body differs and leaks account existence:\n unknown user  = %s\n wrong password = %s",
			unknown.Body.String(), wrongPass.Body.String())
	}
	if unknown.Header().Get("Content-Type") != wrongPass.Header().Get("Content-Type") {
		t.Error("Content-Type differs between unknown-user and wrong-password")
	}
	if len(unknown.Result().Cookies()) != 0 || len(wrongPass.Result().Cookies()) != 0 {
		t.Error("neither rejection may set a cookie")
	}
	// The authenticator must be consulted for an unknown user too: short-circuiting
	// on "user not found" is what creates a timing oracle.
	e.mu.Lock()
	calls := append([]string(nil), e.calls...)
	e.mu.Unlock()
	if len(calls) != 2 || calls[0] != "nosuchuser" || calls[1] != "root" {
		t.Errorf("authenticator calls = %v, want both attempts to reach the verifier", calls)
	}
}

// TestLoginPasswordDisabled asserts password login is unreachable — at both the
// handler and the routing layer — when no authenticator is configured, so an
// SSO-only deployment cannot be logged into with a password.
func TestLoginPasswordDisabled(t *testing.T) {
	sessions := NewSessionStore(time.Hour, time.Minute)
	mgr := NewManager(ManagerOptions{Sessions: sessions})

	r := httptest.NewRequest(http.MethodPost, "/auth/login/password",
		strings.NewReader(`{"username":"root","password":"`+opRootPass+`"}`))
	w := httptest.NewRecorder()
	mgr.LoginPassword(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when password login is disabled", w.Code)
	}
	if n := sessions.len(); n != 0 {
		t.Fatalf("disabled password login created %d session(s)", n)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("disabled password login must set no cookies")
	}
}

// TestLoginPasswordMalformedBody asserts a body that is not valid JSON is
// refused with 400 before the authenticator is consulted, and creates nothing.
func TestLoginPasswordMalformedBody(t *testing.T) {
	for _, body := range []string{``, `not json`, `{"username":`, `[]`, `{"username":123,"password":"x"}`} {
		e := newLoginEnv(t)
		rec := e.postLogin(body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400 (body=%s)", body, rec.Code, rec.Body.String())
		}
		if n := e.sessions.len(); n != 0 {
			t.Errorf("body %q created %d session(s)", body, n)
		}
		e.mu.Lock()
		calls := len(e.calls)
		e.mu.Unlock()
		if calls != 0 {
			t.Errorf("body %q reached the password authenticator %d time(s)", body, calls)
		}
	}
}

// --- session token properties ---

// TestSessionTokensAreUnpredictableAndUnique asserts every login mints a fresh,
// full-entropy session id and CSRF token. Reuse across logins would be session
// fixation; a short or low-entropy id would be guessable.
func TestSessionTokensAreUnpredictableAndUnique(t *testing.T) {
	e := newLoginEnv(t)
	const logins = 24
	seen := make(map[string]string, logins*2)
	for i := 0; i < logins; i++ {
		rec := e.postLogin(`{"username":"root","password":"` + opRootPass + `"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("login %d: status = %d", i, rec.Code)
		}
		id := cookieNamed(rec, DefaultSessionCookie).Value
		csrf := cookieNamed(rec, DefaultSessionCookie+CSRFCookieSuffix).Value
		if id == csrf {
			t.Fatalf("login %d: session id and CSRF token are the same value", i)
		}
		for kind, tok := range map[string]string{"session id": id, "csrf token": csrf} {
			raw, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil {
				t.Fatalf("login %d: %s %q is not base64url: %v", i, kind, tok, err)
			}
			// 32 bytes = 256 bits of CSPRNG entropy; anything less is guessable.
			if len(raw) != 32 {
				t.Fatalf("login %d: %s carries %d bytes of entropy, want 32", i, kind, len(raw))
			}
			if prev, dup := seen[tok]; dup {
				t.Fatalf("login %d: %s collided with a previously issued %s", i, kind, prev)
			}
			seen[tok] = kind
		}
	}
	// Every session must coexist: a new login must not clobber an existing session.
	if n := e.sessions.len(); n != logins {
		t.Errorf("live sessions = %d, want %d", n, logins)
	}
}

// TestLoginPasswordDoesNotAcceptAttackerSuppliedSessionID asserts the classic
// session-fixation defence: a caller that presents a session cookie of its own
// choosing while logging in gets a brand-new server-issued id, and the presented
// value never becomes a live session.
func TestLoginPasswordDoesNotAcceptAttackerSuppliedSessionID(t *testing.T) {
	e := newLoginEnv(t)
	const planted = "attacker-chosen-session-id"
	r := httptest.NewRequest(http.MethodPost, "/auth/login/password",
		strings.NewReader(`{"username":"root","password":"`+opRootPass+`"}`))
	r.AddCookie(&http.Cookie{Name: e.mgr.SessionCookieName(), Value: planted})
	w := httptest.NewRecorder()
	e.mgr.LoginPassword(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	issued := cookieNamed(w, e.mgr.SessionCookieName())
	if issued == nil || issued.Value == planted {
		t.Fatalf("login must issue a fresh session id, got %v", issued)
	}
	if _, ok := e.sessions.Get(planted); ok {
		t.Fatal("the attacker-supplied session id became a live session (session fixation)")
	}
	if e.sessionInfo(planted).Code != http.StatusUnauthorized {
		t.Fatal("the attacker-supplied session id authenticates a request")
	}
}

// --- SessionInfo ---

// TestSessionInfoRefusesUnknownSessions asserts SessionInfo is fail-closed: any
// token that is not a live session yields a bare 401 with no principal, CSRF
// token, or other session state leaked.
func TestSessionInfoRefusesUnknownSessions(t *testing.T) {
	e := newLoginEnv(t)
	live := e.loginAs(t, opRootUser, opRootPass)
	if rec := e.sessionInfo(live); rec.Code != http.StatusOK {
		t.Fatalf("precondition: live session = %d, want 200", rec.Code)
	}
	liveSess, _ := e.sessions.Get(live)

	flipped := []byte(live)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}

	cases := []struct {
		name string
		id   string
	}{
		{"no cookie", ""},
		{"empty cookie value", " "},
		{"unknown token", "not-a-session"},
		{"one character flipped", string(flipped)},
		{"truncated token", live[:len(live)-1]},
		{"token with trailing junk", live + "x"},
		{"csrf token used as session id", liveSess.CSRFToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.sessionInfo(tc.id)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"no session"}` {
				t.Errorf("body = %s, want the bare no-session error", got)
			}
			// A partially populated response would leak the principal or the CSRF
			// token to an unauthenticated caller.
			for _, leak := range []string{"csrf_token", "user", "root", liveSess.CSRFToken} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Errorf("unauthenticated response leaks %q: %s", leak, rec.Body.String())
				}
			}
		})
	}
}

// TestSessionInfoReportsSessionState asserts the authenticated response reports
// the principal, the session's own CSRF token, the login method, and the
// step-up/WebAuthn state the console gates its UI on.
func TestSessionInfoReportsSessionState(t *testing.T) {
	e := newLoginEnv(t)
	id := e.loginAs(t, opAliceUser, opAlicePass)
	sess, _ := e.sessions.Get(id)

	rec := e.sessionInfo(id)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := bodyJSON(t, rec)
	if got, _ := body["csrf_token"].(string); got != sess.CSRFToken {
		t.Errorf("csrf_token = %q, want %q", got, sess.CSRFToken)
	}
	if got, _ := body["method"].(string); got != MethodPassword {
		t.Errorf("method = %q, want %q", got, MethodPassword)
	}
	if got, _ := body["step_up"].(bool); got {
		t.Error("a fresh session must not report an active step-up")
	}
	if got, _ := body["webauthn"].(bool); got {
		t.Error("webauthn must be false when no WebAuthn handler is configured")
	}
	user, _ := body["user"].(map[string]interface{})
	if sub, _ := user["sub"].(string); sub != "alice@example.com" {
		t.Errorf("user.sub = %q, want alice@example.com", sub)
	}
	exp, err := time.Parse(time.RFC3339, body["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at %v is not RFC3339: %v", body["expires_at"], err)
	}
	if d := exp.Sub(sess.Expires); d > time.Second || d < -time.Second {
		t.Errorf("expires_at = %v, want the session expiry %v", exp, sess.Expires)
	}

	// After a WebAuthn step-up the same endpoint must report it, and report
	// WebAuthn as available once the handler is attached.
	wa, err := NewWebAuthn(e.mgr, WebAuthnConfig{
		RPID: "pki.example.com", Origins: []string{"https://pki.example.com"}, Store: newFakeStore(),
	})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	e.mgr.SetWebAuthn(wa)
	if !e.sessions.MarkStepUp(id) {
		t.Fatal("MarkStepUp on a live session should succeed")
	}
	body = bodyJSON(t, e.sessionInfo(id))
	if got, _ := body["step_up"].(bool); !got {
		t.Error("step_up must be true after MarkStepUp")
	}
	if got, _ := body["webauthn"].(bool); !got {
		t.Error("webauthn must be true once a WebAuthn handler is attached")
	}
}

// TestSessionInfoRefusesExpiredSession asserts an absolute-TTL expiry is
// enforced on read (and the dead session evicted), so a stolen cookie stops
// working when the session times out.
func TestSessionInfoRefusesExpiredSession(t *testing.T) {
	e := newLoginEnv(t)
	base := time.Unix(1_700_000_000, 0)
	e.sessions.now = func() time.Time { return base }
	id := e.loginAs(t, opRootUser, opRootPass)
	if rec := e.sessionInfo(id); rec.Code != http.StatusOK {
		t.Fatalf("precondition: status = %d, want 200", rec.Code)
	}

	// One second before expiry the session is still good; one second after it is not.
	e.sessions.now = func() time.Time { return base.Add(time.Hour - time.Second) }
	if rec := e.sessionInfo(id); rec.Code != http.StatusOK {
		t.Errorf("just before the TTL: status = %d, want 200", rec.Code)
	}
	e.sessions.now = func() time.Time { return base.Add(time.Hour + time.Second) }
	rec := e.sessionInfo(id)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if n := e.sessions.len(); n != 0 {
		t.Errorf("the expired session was not evicted (%d remain)", n)
	}
	// Rolling the clock back must not resurrect it.
	e.sessions.now = func() time.Time { return base }
	if rec := e.sessionInfo(id); rec.Code != http.StatusUnauthorized {
		t.Errorf("evicted session came back: status = %d, want 401", rec.Code)
	}
}

// --- Logout ---

// TestLogoutInvalidatesSessionImmediately asserts logout kills the session
// server-side (not just the browser cookie) and is idempotent.
func TestLogoutInvalidatesSessionImmediately(t *testing.T) {
	e := newLoginEnv(t)
	id := e.loginAs(t, opRootUser, opRootPass)
	if rec := e.sessionInfo(id); rec.Code != http.StatusOK {
		t.Fatalf("precondition: status = %d, want 200", rec.Code)
	}

	rec := e.logout(id)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"status":"logged_out"}` {
		t.Errorf("logout body = %s", got)
	}
	if _, ok := e.sessions.Get(id); ok {
		t.Fatal("the session survived logout server-side")
	}
	if got := e.sessionInfo(id); got.Code != http.StatusUnauthorized {
		t.Fatalf("session still usable after logout: status = %d", got.Code)
	}

	// Both auth cookies must be expired in the response.
	for _, name := range []string{DefaultSessionCookie, DefaultSessionCookie + CSRFCookieSuffix} {
		c := cookieNamed(rec, name)
		if c == nil {
			t.Errorf("logout did not clear cookie %q", name)
			continue
		}
		if c.MaxAge >= 0 || c.Value != "" {
			t.Errorf("cookie %q not expired: value=%q MaxAge=%d", name, c.Value, c.MaxAge)
		}
	}

	ev := e.sink.withAction(audit.ActionAuthLogout)
	if len(ev) != 1 || ev[0].Target != id || ev[0].Result != audit.ResultSuccess ||
		ev[0].Detail != "method=password" || ev[0].Actor != "root" {
		t.Errorf("logout audit = %+v, want one success event for the session", ev)
	}

	// Logging out again with the same (dead) cookie is harmless: still 200, still
	// clears cookies, and records no second logout.
	again := e.logout(id)
	if again.Code != http.StatusOK {
		t.Errorf("second logout status = %d, want 200", again.Code)
	}
	if cookieNamed(again, DefaultSessionCookie) == nil {
		t.Error("second logout should still clear the session cookie")
	}
	if n := len(e.sink.withAction(audit.ActionAuthLogout)); n != 1 {
		t.Errorf("logout audit events = %d, want 1 (no event for a dead session)", n)
	}

	// Logout without any cookie must not panic and must not log an event.
	if none := e.logout(""); none.Code != http.StatusOK {
		t.Errorf("logout with no cookie status = %d, want 200", none.Code)
	}
	if n := len(e.sink.withAction(audit.ActionAuthLogout)); n != 1 {
		t.Errorf("logout audit events = %d after an anonymous logout, want 1", n)
	}
}

// TestLogoutIsScopedToTheCallersSession asserts logging out terminates exactly
// one session: not another operator's, and not the same operator's other device.
func TestLogoutIsScopedToTheCallersSession(t *testing.T) {
	e := newLoginEnv(t)
	root := e.loginAs(t, opRootUser, opRootPass)
	alice := e.loginAs(t, opAliceUser, opAlicePass)
	rootSecondDevice := e.loginAs(t, opRootUser, opRootPass)
	if root == rootSecondDevice {
		t.Fatal("two logins for the same user reused one session id")
	}

	if rec := e.logout(alice); rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rec.Code)
	}
	if rec := e.sessionInfo(alice); rec.Code != http.StatusUnauthorized {
		t.Errorf("alice's session survived her logout: status = %d", rec.Code)
	}
	if rec := e.sessionInfo(root); rec.Code != http.StatusOK {
		t.Errorf("alice's logout invalidated root's session: status = %d", rec.Code)
	}
	if rec := e.sessionInfo(rootSecondDevice); rec.Code != http.StatusOK {
		t.Errorf("alice's logout invalidated root's second session: status = %d", rec.Code)
	}

	// Root logging out one device must leave the other alive.
	e.logout(root)
	if rec := e.sessionInfo(root); rec.Code != http.StatusUnauthorized {
		t.Errorf("root's first session survived its own logout: status = %d", rec.Code)
	}
	if rec := e.sessionInfo(rootSecondDevice); rec.Code != http.StatusOK {
		t.Errorf("logging out one device killed the other: status = %d", rec.Code)
	}
	if n := e.sessions.len(); n != 1 {
		t.Errorf("live sessions = %d, want 1", n)
	}
}

// --- Register (endpoint mounting) ---

// muxProbe reports the status and body of a request against a mux, so a route
// that was never mounted (net/http's own 404 text) can be told apart from a
// mounted handler that answered.
func muxProbe(mux *http.ServeMux, method, path string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// notMounted reports whether the route is absent from the mux (as opposed to
// mounted and answering with a JSON error).
func notMounted(mux *http.ServeMux, method, path string) bool {
	code, body := muxProbe(mux, method, path)
	return code == http.StatusNotFound && strings.Contains(body, "404 page not found")
}

// TestRegisterMountsOnlyConfiguredEndpoints asserts a disabled auth mechanism is
// genuinely unroutable rather than merely hidden: with no password
// authenticator, no LDAP authenticator and no WebAuthn handler, those endpoints
// must not exist, while logout and session-info always must.
func TestRegisterMountsOnlyConfiguredEndpoints(t *testing.T) {
	sessions := NewSessionStore(time.Hour, time.Minute)
	mgr := NewManager(ManagerOptions{Sessions: sessions})
	mux := http.NewServeMux()
	mgr.Register(mux)

	for _, p := range []struct{ method, path string }{
		{http.MethodPost, "/auth/login/password"},
		{http.MethodPost, "/auth/login/ldap"},
		{http.MethodGet, "/auth/login"},
		{http.MethodGet, "/auth/callback"},
		{http.MethodPost, "/auth/webauthn/register/begin"},
		{http.MethodPost, "/auth/webauthn/register/finish"},
		{http.MethodPost, "/auth/webauthn/stepup/begin"},
		{http.MethodPost, "/auth/webauthn/stepup/finish"},
		{http.MethodGet, "/auth/webauthn/credentials"},
	} {
		if !notMounted(mux, p.method, p.path) {
			code, body := muxProbe(mux, p.method, p.path)
			t.Errorf("%s %s must not be mounted when unconfigured (got %d %s)", p.method, p.path, code, body)
		}
	}

	// Logout and session-info are unconditional, and method-restricted.
	if code, body := muxProbe(mux, http.MethodPost, "/auth/logout"); code != http.StatusOK {
		t.Errorf("POST /auth/logout = %d %s, want 200", code, body)
	}
	if code, _ := muxProbe(mux, http.MethodGet, "/auth/session"); code != http.StatusUnauthorized {
		t.Errorf("GET /auth/session without a session = %d, want 401", code)
	}
	if code, _ := muxProbe(mux, http.MethodGet, "/auth/logout"); code != http.StatusMethodNotAllowed {
		t.Errorf("GET /auth/logout = %d, want 405: logout must be a POST", code)
	}
	if code, _ := muxProbe(mux, http.MethodPost, "/auth/session"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /auth/session = %d, want 405", code)
	}
}

// TestRegisterMountsConfiguredEndpoints asserts each configured mechanism's
// endpoints become reachable, and that they are reachable *as their own
// handlers* (answering with the package's JSON errors, not the mux's 404).
func TestRegisterMountsConfiguredEndpoints(t *testing.T) {
	e := newLoginEnv(t)
	wa, err := NewWebAuthn(e.mgr, WebAuthnConfig{
		RPID: "pki.example.com", Origins: []string{"https://pki.example.com"}, Store: newFakeStore(),
	})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	e.mgr.SetWebAuthn(wa)
	e.mgr.SetLogin(newTestOIDCLogin(t, e.mgr))
	mux := http.NewServeMux()
	e.mgr.Register(mux)

	// Password login is mounted: an empty body reaches the handler (400), not the mux 404.
	if code, body := muxProbe(mux, http.MethodPost, "/auth/login/password"); code != http.StatusUnauthorized {
		t.Errorf("POST /auth/login/password with {} = %d %s, want 401 from the handler", code, body)
	}
	// The OIDC login redirect is mounted.
	if code, _ := muxProbe(mux, http.MethodGet, "/auth/login"); code != http.StatusFound {
		t.Errorf("GET /auth/login = %d, want a 302 redirect to the IdP", code)
	}
	// WebAuthn endpoints are mounted and require a session (401 from the handler).
	for _, p := range []struct{ method, path string }{
		{http.MethodPost, "/auth/webauthn/register/begin"},
		{http.MethodPost, "/auth/webauthn/register/finish"},
		{http.MethodPost, "/auth/webauthn/stepup/begin"},
		{http.MethodPost, "/auth/webauthn/stepup/finish"},
		{http.MethodGet, "/auth/webauthn/credentials"},
	} {
		code, body := muxProbe(mux, p.method, p.path)
		if code != http.StatusUnauthorized || !strings.Contains(body, "login required") {
			t.Errorf("%s %s = %d %s, want 401 login required", p.method, p.path, code, body)
		}
	}
}

// --- feature accessors ---

// TestFeatureAccessorsReflectConfiguration asserts the accessors that gate
// security controls report false until the control is actually configured (a
// false "enabled" would advertise an auth mechanism that cannot work; a false
// "WebAuthn enabled" is reported to the console and used by the step-up gate).
func TestFeatureAccessorsReflectConfiguration(t *testing.T) {
	var nilMgr *Manager
	if nilMgr.LoginEnabled() || nilMgr.WebAuthnEnabled() || nilMgr.LDAPEnabled() {
		t.Error("a nil Manager must report every feature disabled")
	}

	e := newLoginEnv(t)
	if e.mgr.LoginEnabled() {
		t.Error("LoginEnabled must be false before SetLogin")
	}
	if e.mgr.WebAuthnEnabled() {
		t.Error("WebAuthnEnabled must be false before SetWebAuthn")
	}
	if e.mgr.LDAPEnabled() {
		t.Error("LDAPEnabled must be false before SetLDAPAuthenticator")
	}

	// Attaching a nil handler (a config path that failed to build one) must not
	// flip the feature on.
	e.mgr.SetLogin(nil)
	if e.mgr.LoginEnabled() {
		t.Error("SetLogin(nil) must leave interactive login disabled")
	}
	e.mgr.SetWebAuthn(nil)
	if e.mgr.WebAuthnEnabled() {
		t.Error("SetWebAuthn(nil) must leave WebAuthn disabled")
	}
	e.mgr.SetLDAPAuthenticator(nil)
	if e.mgr.LDAPEnabled() {
		t.Error("SetLDAPAuthenticator(nil) must leave LDAP disabled")
	}

	e.mgr.SetLogin(newTestOIDCLogin(t, e.mgr))
	if !e.mgr.LoginEnabled() {
		t.Error("LoginEnabled must be true after SetLogin")
	}
	if e.mgr.WebAuthnEnabled() {
		t.Error("attaching OIDC login must not enable WebAuthn")
	}
	wa, err := NewWebAuthn(e.mgr, WebAuthnConfig{
		RPID: "pki.example.com", Origins: []string{"https://pki.example.com"}, Store: newFakeStore(),
	})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	e.mgr.SetWebAuthn(wa)
	if !e.mgr.WebAuthnEnabled() {
		t.Error("WebAuthnEnabled must be true after SetWebAuthn")
	}
}

// TestSetPasswordAuthenticatorSwapsTheVerifier asserts the installed
// authenticator is the one consulted, and that replacing it takes effect — a
// credential accepted by a previous verifier must stop working.
func TestSetPasswordAuthenticatorSwapsTheVerifier(t *testing.T) {
	sessions := NewSessionStore(time.Hour, time.Minute)
	mgr := NewManager(ManagerOptions{Sessions: sessions})
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/auth/login/password", strings.NewReader(body))
		w := httptest.NewRecorder()
		mgr.LoginPassword(w, r)
		return w
	}

	mgr.SetPasswordAuthenticator(func(u, p string) (*models.UserInfo, bool) {
		if u == "a" && p == "1" {
			return &models.UserInfo{Subject: "a"}, true
		}
		return nil, false
	})
	if rec := post(`{"username":"a","password":"1"}`); rec.Code != http.StatusOK {
		t.Fatalf("first verifier: status = %d, want 200", rec.Code)
	}
	mgr.SetPasswordAuthenticator(func(u, p string) (*models.UserInfo, bool) {
		if u == "b" && p == "2" {
			return &models.UserInfo{Subject: "b"}, true
		}
		return nil, false
	})
	if rec := post(`{"username":"a","password":"1"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("the replaced verifier still accepts the old credential: status = %d", rec.Code)
	}
	if rec := post(`{"username":"b","password":"2"}`); rec.Code != http.StatusOK {
		t.Errorf("the new verifier rejects its own credential: status = %d", rec.Code)
	}
}

// TestNewManagerDefaults asserts the cookie names and console redirect fall back
// to safe defaults, and that a custom session cookie name is mirrored by the
// derived CSRF cookie (a mismatch would silently break CSRF validation).
func TestNewManagerDefaults(t *testing.T) {
	sessions := NewSessionStore(time.Hour, time.Minute)
	def := NewManager(ManagerOptions{Sessions: sessions})
	if def.SessionCookieName() != DefaultSessionCookie {
		t.Errorf("default session cookie = %q, want %q", def.SessionCookieName(), DefaultSessionCookie)
	}
	if def.csrfCookieName() != DefaultSessionCookie+CSRFCookieSuffix {
		t.Errorf("default CSRF cookie = %q", def.csrfCookieName())
	}
	if def.consoleRedirect != "/console/" {
		t.Errorf("default console redirect = %q, want /console/", def.consoleRedirect)
	}
	// A nil RequestID must be replaced, not called as nil.
	if got := def.requestID(context.Background()); got != "" {
		t.Errorf("default requestID = %q, want empty", got)
	}

	custom := NewManager(ManagerOptions{Sessions: sessions, SessionCookie: "pki_sess", ConsoleRedirect: "/ui/"})
	custom.SetPasswordAuthenticator(func(string, string) (*models.UserInfo, bool) {
		return &models.UserInfo{Subject: "x"}, true
	})
	if custom.csrfCookieName() != "pki_sess"+CSRFCookieSuffix {
		t.Errorf("custom CSRF cookie = %q", custom.csrfCookieName())
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/login/password", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	custom.LoginPassword(w, r)
	if cookieNamed(w, "pki_sess") == nil || cookieNamed(w, "pki_sess"+CSRFCookieSuffix) == nil {
		t.Errorf("login must set both custom-named cookies, got %v", w.Result().Cookies())
	}
	// Cookies issued by a non-secure manager must not claim Secure (and must still
	// be HttpOnly) — Secure defaults off only for plaintext local testing.
	if c := cookieNamed(w, "pki_sess"); c != nil && (c.Secure || !c.HttpOnly) {
		t.Errorf("insecure-mode session cookie = %+v, want Secure=false HttpOnly=true", c)
	}
}

// --- concurrency ---

// TestConcurrentSessionLifecycle drives the full login/inspect/step-up/logout
// cycle from many goroutines so -race covers the session map's locking and the
// session's mutable step-up state.
func TestConcurrentSessionLifecycle(t *testing.T) {
	e := newLoginEnv(t)
	const workers, rounds = 8, 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			user, pass := opRootUser, opRootPass
			if w%2 == 1 {
				user, pass = opAliceUser, opAlicePass
			}
			body := `{"username":"` + user + `","password":"` + pass + `"}`
			for i := 0; i < rounds; i++ {
				rec := e.postLogin(body)
				if rec.Code != http.StatusOK {
					t.Errorf("worker %d: login status = %d", w, rec.Code)
					return
				}
				id := cookieNamed(rec, DefaultSessionCookie).Value
				if got := e.sessionInfo(id); got.Code != http.StatusOK {
					t.Errorf("worker %d: session info status = %d", w, got.Code)
					return
				}
				e.sessions.MarkStepUp(id)
				if got := e.sessionInfo(id); got.Code != http.StatusOK {
					t.Errorf("worker %d: session info after step-up = %d", w, got.Code)
					return
				}
				if got := e.logout(id); got.Code != http.StatusOK {
					t.Errorf("worker %d: logout status = %d", w, got.Code)
					return
				}
				if got := e.sessionInfo(id); got.Code != http.StatusUnauthorized {
					t.Errorf("worker %d: session usable after logout (status %d)", w, got.Code)
					return
				}
			}
		}(w)
	}
	// Concurrently hammer lookups of tokens that are not sessions.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < workers*rounds; i++ {
			if _, ok := e.sessions.Get("never-a-session"); ok {
				t.Error("an unknown token resolved to a session")
				return
			}
			e.sessions.MarkStepUp("never-a-session")
		}
	}()
	wg.Wait()

	if n := e.sessions.len(); n != 0 {
		t.Errorf("live sessions after all logouts = %d, want 0", n)
	}
	if got := len(e.sink.withAction(audit.ActionAuthLogin)); got != workers*rounds {
		t.Errorf("login audit events = %d, want %d", got, workers*rounds)
	}
	if got := len(e.sink.withAction(audit.ActionAuthLogout)); got != workers*rounds {
		t.Errorf("logout audit events = %d, want %d", got, workers*rounds)
	}
}

// TestConcurrentStepUpAndSessionRead drives one session's step-up state from
// several goroutines at once — the everyday case of a console making parallel
// requests while a WebAuthn ceremony finishes. The step-up deadline is the only
// session field mutated after creation, and it is read on the authorization hot
// path (the step-up gate in internal/middleware), so it must be synchronized:
// under -race an unguarded read/write of that time.Time fails this test.
func TestConcurrentStepUpAndSessionRead(t *testing.T) {
	e := newLoginEnv(t)
	id := e.loginAs(t, opRootUser, opRootPass)
	sess, ok := e.sessions.Get(id)
	if !ok {
		t.Fatal("precondition: the session should be live")
	}

	const workers, rounds = 6, 150
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(3)
		// Writers: a completed step-up ceremony extends the window.
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if !e.sessions.MarkStepUp(id) {
					t.Error("MarkStepUp on a live session failed")
					return
				}
			}
		}()
		// Readers via the exported accessor (what the middleware's gate calls).
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				cur, ok := e.sessions.Get(id)
				if !ok {
					t.Error("the session disappeared")
					return
				}
				_ = cur.StepUpValid()
				_ = sess.StepUpValid()
			}
		}()
		// Readers via the HTTP surface, which reports step_up to the console.
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if rec := e.sessionInfo(id); rec.Code != http.StatusOK {
					t.Errorf("session info during concurrent step-up = %d", rec.Code)
					return
				}
			}
		}()
	}
	wg.Wait()

	// After all the writes the step-up must be active and the session intact.
	if !sess.StepUpValid() {
		t.Error("the session should hold a valid step-up after MarkStepUp")
	}
	body := bodyJSON(t, e.sessionInfo(id))
	if got, _ := body["step_up"].(bool); !got {
		t.Error("session info should report the active step-up")
	}
}
