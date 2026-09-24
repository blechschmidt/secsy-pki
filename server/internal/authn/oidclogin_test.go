package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
)

// These tests cover the interactive OIDC login handler without contacting an
// identity provider: oidc.ProviderConfig builds a Provider from static metadata,
// so Begin (which only mints state/nonce/PKCE and redirects) and every Callback
// rejection path before the code exchange are exercised hermetically. The
// properties asserted are the anti-CSRF/anti-replay guarantees of the
// Authorization-Code flow: the transaction cookie must be unforgeable, the state
// must match, and no failure path may establish a session.

const (
	testIDPAuthURL  = "https://idp.example.com/authorize"
	testRedirectURL = "https://pki.example.com/auth/callback"
)

// newTestOIDCLogin builds an OIDCLogin bound to mgr from static provider
// metadata. No network access occurs: the verifier is never invoked by the code
// paths under test (they all fail before the token exchange).
func newTestOIDCLogin(t *testing.T, mgr *Manager) *OIDCLogin {
	t.Helper()
	provider := (&oidc.ProviderConfig{
		IssuerURL: "https://idp.example.com",
		AuthURL:   testIDPAuthURL,
		TokenURL:  "https://idp.example.com/token",
		JWKSURL:   "https://idp.example.com/jwks",
		Algorithms: []string{
			"RS256",
		},
	}).NewProvider(context.Background())
	l, err := NewOIDCLogin(mgr, OIDCLoginConfig{
		Provider:     provider,
		Verifier:     provider.Verifier(&oidc.Config{ClientID: "console"}),
		ClientID:     "console",
		ClientSecret: "shhh",
		RedirectURL:  testRedirectURL,
		Resolve: func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) {
			return &models.UserInfo{Subject: "sso@example.com", Roles: []string{"issuer"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin: %v", err)
	}
	return l
}

// TestNewOIDCLoginRequiresCompleteConfig asserts the constructor fails closed:
// an incompletely configured login must not produce a handler that would skip
// token verification or redirect to an unintended place.
func TestNewOIDCLoginRequiresCompleteConfig(t *testing.T) {
	provider := (&oidc.ProviderConfig{IssuerURL: "https://idp.example.com", AuthURL: testIDPAuthURL}).
		NewProvider(context.Background())
	verifier := provider.Verifier(&oidc.Config{ClientID: "console"})
	resolve := func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) { return nil, nil }
	mgr := NewManager(ManagerOptions{Sessions: NewSessionStore(time.Hour, time.Minute)})

	cases := []struct {
		name string
		cfg  OIDCLoginConfig
	}{
		{"no provider", OIDCLoginConfig{Verifier: verifier, RedirectURL: testRedirectURL, Resolve: resolve}},
		{"no verifier", OIDCLoginConfig{Provider: provider, RedirectURL: testRedirectURL, Resolve: resolve}},
		{"no redirect url", OIDCLoginConfig{Provider: provider, Verifier: verifier, Resolve: resolve}},
		{"no resolver", OIDCLoginConfig{Provider: provider, Verifier: verifier, RedirectURL: testRedirectURL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if l, err := NewOIDCLogin(mgr, tc.cfg); err == nil {
				t.Fatalf("NewOIDCLogin(%s) = %v, want an error", tc.name, l)
			}
		})
	}

	// A complete config defaults the scopes to an id-token-bearing request.
	l, err := NewOIDCLogin(mgr, OIDCLoginConfig{
		Provider: provider, Verifier: verifier, RedirectURL: testRedirectURL, Resolve: resolve,
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin: %v", err)
	}
	if len(l.oauth.Scopes) == 0 || l.oauth.Scopes[0] != oidc.ScopeOpenID {
		t.Errorf("default scopes = %v, want openid first", l.oauth.Scopes)
	}
	if len(l.txKey) == 0 {
		t.Error("the transaction cookie signing key must be generated")
	}
}

// txCookieOf returns the login transaction cookie from a Begin response.
func txCookieOf(t *testing.T, l *OIDCLogin, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	c := cookieNamed(rec, l.txCookieName())
	if c == nil {
		t.Fatalf("Begin set no transaction cookie: %v", rec.Result().Cookies())
	}
	return c
}

// begin drives GET /auth/login and returns the redirect target plus the tx cookie.
func beginLogin(t *testing.T, l *OIDCLogin) (*url.URL, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	l.Begin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("Begin status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect %q: %v", rec.Header().Get("Location"), err)
	}
	return loc, txCookieOf(t, l, rec)
}

// TestOIDCBeginIssuesFreshStateNoncePKCE asserts each login attempt carries its
// own unguessable state, nonce and PKCE challenge, and that the state is not
// reused across attempts (reuse would make the callback CSRF-checkable only once).
func TestOIDCBeginIssuesFreshStateNoncePKCE(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		loc, cookie := beginLogin(t, l)
		q := loc.Query()
		if !strings.HasPrefix(loc.String(), testIDPAuthURL) {
			t.Fatalf("redirect = %s, want the IdP authorization endpoint", loc)
		}
		if q.Get("response_type") != "code" {
			t.Errorf("response_type = %q, want code", q.Get("response_type"))
		}
		if q.Get("redirect_uri") != testRedirectURL {
			t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), testRedirectURL)
		}
		// PKCE must be S256, never "plain".
		if got := q.Get("code_challenge_method"); got != "S256" {
			t.Errorf("code_challenge_method = %q, want S256", got)
		}
		if q.Get("code_challenge") == "" {
			t.Error("no PKCE code challenge")
		}
		for _, k := range []string{"state", "nonce", "code_challenge"} {
			v := q.Get(k)
			if len(v) < 16 {
				t.Errorf("%s = %q is too short to be unguessable", k, v)
			}
			if seen[v] {
				t.Errorf("%s value %q was reused across login attempts", k, v)
			}
			seen[v] = true
		}
		if !cookie.HttpOnly {
			t.Error("the login transaction cookie must be HttpOnly")
		}
		if cookie.MaxAge <= 0 {
			t.Errorf("transaction cookie MaxAge = %d, want a short positive TTL", cookie.MaxAge)
		}
		// The cookie must be a signed envelope, not a bare payload.
		payload, sig, ok := splitDot(cookie.Value)
		if !ok || payload == "" || sig == "" {
			t.Fatalf("transaction cookie %q is not payload.signature", cookie.Value)
		}
		if sig != l.sign(payload) {
			t.Error("transaction cookie signature does not verify")
		}
	}
}

// resignedTxCookie re-encodes tx and signs it with l's key (the honest server
// behaviour), for tests that need a valid cookie with chosen contents.
func resignedTxCookie(t *testing.T, l *OIDCLogin, tx oidcTx) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	b := base64.RawURLEncoding.EncodeToString(payload)
	return &http.Cookie{Name: l.txCookieName(), Value: b + "." + l.sign(b)}
}

// forgedTxCookie re-encodes tx but signs it with a foreign key, simulating an
// attacker who fabricates a login transaction.
func forgedTxCookie(t *testing.T, l *OIDCLogin, tx oidcTx) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	b := base64.RawURLEncoding.EncodeToString(payload)
	other := &OIDCLogin{txKey: []byte("a-different-signing-key")}
	return &http.Cookie{Name: l.txCookieName(), Value: b + "." + other.sign(b)}
}

// callback drives GET /auth/callback with the given query and cookies.
func callback(l *OIDCLogin, query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	l.Callback(w, r)
	return w
}

// TestOIDCCallbackRejectsForgedOrMismatchedTransactions is the anti-CSRF /
// anti-injection guard on the redirect: no callback that fails state, signature
// or freshness checks may establish a session.
func TestOIDCCallbackRejectsForgedOrMismatchedTransactions(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)
	e.mgr.SetLogin(l)

	// A genuine transaction to build variations from.
	genuine := oidcTx{State: "state-value", Nonce: "nonce-value", Verifier: "pkce-verifier", Issued: time.Now().Unix()}
	good := resignedTxCookie(t, l, genuine)

	// Tamper with the payload while keeping the original signature.
	tamperedPayload := func() *http.Cookie {
		other := resignedTxCookie(t, l, oidcTx{State: "attacker-state", Nonce: "n", Verifier: "v", Issued: genuine.Issued})
		payload, _, _ := splitDot(other.Value)
		_, sig, _ := splitDot(good.Value)
		return &http.Cookie{Name: l.txCookieName(), Value: payload + "." + sig}
	}()

	cases := []struct {
		name   string
		query  string
		cookie *http.Cookie
		status int
		code   string
	}{
		{"idp returned an error", "error=access_denied", good, http.StatusUnauthorized, "idp_error"},
		{"no transaction cookie", "state=state-value&code=abc", nil, http.StatusBadRequest, "bad_tx"},
		{"forged signature", "state=attacker-state&code=abc",
			forgedTxCookie(t, l, oidcTx{State: "attacker-state", Issued: time.Now().Unix()}),
			http.StatusBadRequest, "bad_tx"},
		{"tampered payload keeps old signature", "state=attacker-state&code=abc", tamperedPayload,
			http.StatusBadRequest, "bad_tx"},
		{"unsigned cookie", "state=state-value&code=abc",
			&http.Cookie{Name: l.txCookieName(), Value: "just-a-value"}, http.StatusBadRequest, "bad_tx"},
		{"expired transaction", "state=old-state&code=abc",
			resignedTxCookie(t, l, oidcTx{State: "old-state", Issued: time.Now().Add(-time.Hour).Unix()}),
			http.StatusBadRequest, "bad_tx"},
		{"state mismatch", "state=not-the-state&code=abc", good, http.StatusBadRequest, "state_mismatch"},
		{"empty state", "code=abc", good, http.StatusBadRequest, "state_mismatch"},
		{"missing code", "state=state-value", good, http.StatusBadRequest, "no_code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.sink.reset()
			rec := callback(l, tc.query, tc.cookie)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if body.Code != tc.code {
				t.Errorf("error code = %q, want %q", body.Code, tc.code)
			}
			if n := e.sessions.len(); n != 0 {
				t.Fatalf("a rejected callback created %d session(s)", n)
			}
			if c := cookieNamed(rec, DefaultSessionCookie); c != nil && c.Value != "" {
				t.Fatalf("a rejected callback set a session cookie: %+v", c)
			}
			ev := e.sink.withAction(audit.ActionAuthLoginFailed)
			if len(ev) != 1 || ev[0].Result != audit.ResultDenied ||
				!strings.Contains(ev[0].Detail, "reason="+tc.code) {
				t.Errorf("failed-login audit = %+v, want one denied event naming %q", ev, tc.code)
			}
		})
	}
}

// TestOIDCCallbackClearsTransactionCookie asserts the single-use transaction
// cookie is expired by the callback, so it cannot be replayed for a second
// callback.
func TestOIDCCallbackClearsTransactionCookie(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)
	loc, cookie := beginLogin(t, l)

	// A callback with the right state but no code still consumes the transaction.
	rec := callback(l, "state="+url.QueryEscape(loc.Query().Get("state")), cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing code)", rec.Code)
	}
	cleared := cookieNamed(rec, l.txCookieName())
	if cleared == nil {
		t.Fatal("callback did not clear the transaction cookie")
	}
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("transaction cookie not expired: %+v", cleared)
	}
}

// TestOIDCTxCookieNameDerivesFromSessionCookie asserts the transaction cookie is
// namespaced under the configured session cookie name, so two deployments (or a
// renamed cookie) cannot cross-feed login transactions.
func TestOIDCTxCookieNameDerivesFromSessionCookie(t *testing.T) {
	mgr := NewManager(ManagerOptions{Sessions: NewSessionStore(time.Hour, time.Minute), SessionCookie: "pki_sess"})
	l := newTestOIDCLogin(t, mgr)
	if got, want := l.txCookieName(), "pki_sess"+oidcTxCookieSuffix; got != want {
		t.Errorf("txCookieName = %q, want %q", got, want)
	}
	if l.txCookieName() == mgr.SessionCookieName() || l.txCookieName() == mgr.csrfCookieName() {
		t.Error("the transaction cookie must not collide with the session or CSRF cookie")
	}
}

// TestSplitDot covers the signed-cookie envelope split, including the inputs an
// attacker controls.
func TestSplitDot(t *testing.T) {
	cases := []struct {
		in   string
		a, b string
		ok   bool
	}{
		{"payload.signature", "payload", "signature", true},
		{"a.b.c", "a.b", "c", true}, // last dot wins, so extra dots land in the payload
		{".sig", "", "sig", true},
		{"payload.", "payload", "", true},
		{"nodot", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		a, b, ok := splitDot(tc.in)
		if a != tc.a || b != tc.b || ok != tc.ok {
			t.Errorf("splitDot(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.in, a, b, ok, tc.a, tc.b, tc.ok)
		}
	}
}

// TestOIDCSignIsKeyedAndDeterministic asserts the transaction MAC is
// deterministic for one process and unforgeable across keys — the property that
// makes the stateless transaction cookie safe.
func TestOIDCSignIsKeyedAndDeterministic(t *testing.T) {
	mgr := NewManager(ManagerOptions{Sessions: NewSessionStore(time.Hour, time.Minute)})
	a := newTestOIDCLogin(t, mgr)
	b := newTestOIDCLogin(t, mgr)

	// The two calls are bound to locals so the comparison is not a syntactically
	// identical expression: sign() is a method, and a version of it that mixed in
	// a nonce or a timestamp would break the stateless cookie, so this comparison
	// is a real assertion rather than a tautology.
	first, second := a.sign("payload"), a.sign("payload")
	if first != second {
		t.Error("sign must be deterministic for a given key")
	}
	if other := a.sign("payload2"); first == other {
		t.Error("sign must depend on the payload")
	}
	if theirs := b.sign("payload"); first == theirs {
		t.Error("two logins must use independent signing keys")
	}
	if string(a.txKey) == string(b.txKey) {
		t.Error("transaction signing keys must be random per instance")
	}
}
