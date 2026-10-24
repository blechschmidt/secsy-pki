//go:build sqlite

// This file drives the Task 50 operator console/API authentication end-to-end
// against a stub OpenID Connect provider. It stands up the real handler stack —
// the auth middleware, session/CSRF plumbing, the /auth/* endpoints, and the
// embedded console — behind an httptest server, then performs a full server-side
// OIDC Authorization-Code login:
//
//	GET /auth/login -> redirect to the (stub) IdP -> GET /auth/callback with the
//	authorization code -> the server verifies the id token, maps the IdP group
//	claim to an RBAC role, and establishes a session -> GET /api/me returns the
//	mapped principal, and a CSRF-protected write succeeds only with the token.
//
// It uses a software key provider (no HSM), so it runs under `go test -tags
// sqlite ./...` without SoftHSM.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// stubIDP is an in-process OpenID Connect provider: discovery, JWKS, an
// authorization endpoint, and a token endpoint that mints a signed id token
// carrying the group claim under test.
//
// It ENFORCES PKCE (RFC 7636): /authorize refuses a request without an S256
// code_challenge and records it against the code it issues; /token refuses to
// redeem that code unless the exchange presents a code_verifier hashing to the
// recorded challenge. Driving the authorization hop rather than inventing a code
// is what makes the console's proof-key handling testable at all — against an
// IdP that ignores the challenge, a login that forgot to send the verifier would
// still succeed.
type stubIDP struct {
	srv      *httptest.Server
	signer   jose.Signer
	clientID string
	// clientSecret is empty by default: the console registers as a PUBLIC client,
	// the registration PKCE exists for. A test may set it to model a confidential
	// client, in which case the token endpoint demands it.
	clientSecret string
	sub          string
	// groups is the group claim this IdP asserts. It is a field so a test
	// federating several providers can give each its own groups (Task 212);
	// newStubIDP defaults it to the single-provider fixture's value.
	groups []string
	// issuer is the IdP's issuer URL (== srv.URL), kept so a test can mint tokens
	// directly rather than only through the token endpoint.
	issuer string

	mu sync.Mutex
	// codes maps an issued authorization code to the authorization request that
	// produced it. Entries are deleted on redemption: a code is single-use
	// (RFC 6749 §4.1.2).
	codes map[string]authzRequest
	// exchanges records every token request, so a test can assert the SHAPE of
	// the exchange (which client authentication was used, whether a verifier was
	// present) and not only its outcome.
	exchanges []tokenExchange
}

// authzRequest is what a client committed to at /authorize.
type authzRequest struct {
	challenge   string
	method      string
	nonce       string
	state       string
	redirectURI string
}

// tokenExchange records one attempt at /token.
type tokenExchange struct {
	clientID  string
	verifier  string
	basicAuth bool
	err       string // "" when the exchange was granted
}

// exchangeLog returns a copy of the token requests this IdP has seen.
func (s *stubIDP) exchangeLog() []tokenExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tokenExchange(nil), s.exchanges...)
}

// authorization replays the browser hop to /authorize and returns the code and
// state the IdP handed back. The authorization request is the client's PKCE
// commitment, so this is also where a missing or non-S256 challenge is refused.
func (s *stubIDP) authorization(t *testing.T, authorizeURL string) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET %s: %v", authorizeURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	q := loc.Query()
	if q.Get("code") == "" {
		t.Fatalf("authorize redirect carried no code: %s", loc)
	}
	return q.Get("code"), q.Get("state")
}

// challengeFor returns the PKCE challenge recorded for an issued code.
func (s *stubIDP) challengeFor(code string) (authzRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ar, ok := s.codes[code]
	return ar, ok
}

// s256 is the RFC 7636 code-challenge transform.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthError writes an RFC 6749 §5.2 error response.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code, "error_description": description,
	})
}

// mintIDToken signs an id token for sub and aud carrying the given group claim,
// as this IdP would. It is the machine-axis counterpart to the /token endpoint: a
// Bearer caller presents a token it already holds, with no browser handshake.
// The subject, audience, and groups are all explicit so a test can mint the
// token an impersonation attempt would need.
func (s *stubIDP) mintIDToken(t *testing.T, sub, aud string, groups []string) string {
	t.Helper()
	claims := map[string]interface{}{
		"iss":            s.issuer,
		"aud":            aud,
		"sub":            sub,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "machine@example.com",
		"email_verified": true,
	}
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := s.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize id token: %v", err)
	}
	return compact
}

func newStubIDP(t *testing.T, clientID, sub string) *stubIDP {
	t.Helper()
	priv := testRSAKey(t)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("jose signer: %v", err)
	}
	idp := &stubIDP{
		signer: signer, clientID: clientID, sub: sub,
		groups: []string{"pki-admins"},
		codes:  map[string]authzRequest{},
	}

	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	issuer := idp.srv.URL
	idp.issuer = issuer

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			// RFC 8414 §2 / OpenID Discovery: advertise the proof-key methods, which
			// is what a deployment running with auth.oidc.require_pkce checks at boot.
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: priv.Public(), KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}}
		writeTestJSON(w, jwks)
	})
	// /authorize records the client's PKCE commitment and issues a code bound to
	// it. A request without an S256 challenge is refused outright — this IdP does
	// not serve a flow it could not later verify.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" {
			oauthError(w, http.StatusBadRequest, "unsupported_response_type", q.Get("response_type"))
			return
		}
		if q.Get("client_id") != idp.clientID {
			oauthError(w, http.StatusBadRequest, "unauthorized_client", q.Get("client_id"))
			return
		}
		if q.Get("code_challenge") == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "no code_challenge (PKCE is required)")
			return
		}
		if m := q.Get("code_challenge_method"); m != "S256" {
			oauthError(w, http.StatusBadRequest, "invalid_request",
				"code_challenge_method "+m+" is not accepted; S256 only")
			return
		}
		redirectURI := q.Get("redirect_uri")
		if redirectURI == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "no redirect_uri")
			return
		}
		code := "code-" + randomHexString(t, 8)
		idp.mu.Lock()
		idp.codes[code] = authzRequest{
			challenge:   q.Get("code_challenge"),
			method:      q.Get("code_challenge_method"),
			nonce:       q.Get("nonce"),
			state:       q.Get("state"),
			redirectURI: redirectURI,
		}
		idp.mu.Unlock()
		to, err := url.Parse(redirectURI)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable redirect_uri")
			return
		}
		rq := to.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		to.RawQuery = rq.Encode()
		http.Redirect(w, r, to.String(), http.StatusFound)
	})

	// /token redeems a code exactly once, and only for a caller that proves it
	// began the flow by presenting the verifier behind the recorded challenge
	// (RFC 7636 §4.6).
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ex := tokenExchange{
			clientID: r.PostForm.Get("client_id"),
			verifier: r.PostForm.Get("code_verifier"),
		}
		basicID, basicSecret, hasBasic := r.BasicAuth()
		ex.basicAuth = hasBasic
		fail := func(status int, code, description string) {
			ex.err = code + ": " + description
			idp.mu.Lock()
			idp.exchanges = append(idp.exchanges, ex)
			idp.mu.Unlock()
			oauthError(w, status, code, description)
		}

		// Client authentication. A public client (no registered secret) must put
		// its client_id in the body and must NOT send a Basic header: an
		// empty-password `Basic base64("<id>:")` is a confidential-client
		// credential, and real IdPs answer it with invalid_client.
		if idp.clientSecret == "" {
			if hasBasic {
				fail(http.StatusUnauthorized, "invalid_client",
					"this client is registered as public; do not send an Authorization header")
				return
			}
			if ex.clientID != idp.clientID {
				fail(http.StatusUnauthorized, "invalid_client", "client_id missing from the request body")
				return
			}
		} else {
			okBasic := hasBasic && basicID == idp.clientID && basicSecret == idp.clientSecret
			okBody := ex.clientID == idp.clientID && r.PostForm.Get("client_secret") == idp.clientSecret
			if !okBasic && !okBody {
				fail(http.StatusUnauthorized, "invalid_client", "bad client credentials")
				return
			}
		}

		if gt := r.PostForm.Get("grant_type"); gt != "authorization_code" {
			fail(http.StatusBadRequest, "unsupported_grant_type", gt)
			return
		}
		code := r.PostForm.Get("code")
		idp.mu.Lock()
		ar, known := idp.codes[code]
		delete(idp.codes, code) // single use, redeemed or not
		idp.mu.Unlock()
		if !known {
			fail(http.StatusBadRequest, "invalid_grant", "unknown or already-redeemed authorization code")
			return
		}
		if ex.verifier == "" {
			fail(http.StatusBadRequest, "invalid_grant", "no code_verifier in the token request")
			return
		}
		if s256(ex.verifier) != ar.challenge {
			fail(http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
			return
		}
		if ru := r.PostForm.Get("redirect_uri"); ru != ar.redirectURI {
			fail(http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
			return
		}

		claims := map[string]interface{}{
			"iss":            issuer,
			"aud":            clientID,
			"sub":            idp.sub,
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"nonce":          ar.nonce,
			"email":          "admin@example.com",
			"email_verified": true,
			"name":           "Alice Admin",
			"groups":         idp.groups,
		}
		payload, _ := json.Marshal(claims)
		jws, err := idp.signer.Sign(payload)
		if err != nil {
			fail(http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		compact, _ := jws.CompactSerialize()
		idp.mu.Lock()
		idp.exchanges = append(idp.exchanges, ex)
		idp.mu.Unlock()
		writeTestJSON(w, map[string]interface{}{
			"access_token": "stub-access-token",
			"token_type":   "Bearer",
			"id_token":     compact,
		})
	})
	return idp
}

// randomHexString returns n random bytes as hex, for unguessable stub codes.
func randomHexString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return hex.EncodeToString(b)
}

// consoleLoginEnv is the wired-up app server for the login flow test.
type consoleLoginEnv struct {
	srv *httptest.Server
	idp *stubIDP
}

func setupConsoleLogin(t *testing.T) *consoleLoginEnv {
	t.Helper()
	// No client secret: the console is registered as a public client, the
	// registration PKCE exists for. setupConsoleLoginClient covers the
	// confidential-client case.
	return setupConsoleLoginClient(t, "")
}

// setupConsoleLoginClient is setupConsoleLogin with the client registration
// under test: an empty secret registers a public client, a non-empty one a
// confidential client whose token requests must also carry the secret.
func setupConsoleLoginClient(t *testing.T, clientSecret string) *consoleLoginEnv {
	t.Helper()
	const clientID = "secsy-console"
	idp := newStubIDP(t, clientID, "alice-oidc-subject")
	idp.clientSecret = clientSecret

	db, err := database.New("sqlite", t.TempDir()+"/login.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	api := handlers.NewAPI(db, provider, nil, hsm.Config{}, false, "")
	authMw := middleware.NewAuthMiddleware(nil, "root", "root-pass")

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	// --- operator authentication wiring (mirrors setupOperatorAuth) ---
	sessions := authn.NewSessionStore(time.Hour, 5*time.Minute)
	mgr := authn.NewManager(authn.ManagerOptions{
		Sessions:      sessions,
		SessionCookie: authn.DefaultSessionCookie,
		Secure:        false, // httptest is plain HTTP
		Audit:         db,
		RequestID:     middleware.RequestID,
	})

	oidcProvider, err := oidc.NewProvider(context.Background(), idp.srv.URL)
	if err != nil {
		t.Fatalf("oidc discovery: %v", err)
	}
	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: clientID})

	// Map the IdP "pki-admins" group to the admin RBAC role.
	mapper := authn.NewClaimMapper("groups", []authn.ClaimMapping{
		{Value: "pki-admins", Roles: []rbac.Role{rbac.RoleAdmin}},
	})
	resolve := func(idToken *oidc.IDToken, claims map[string]interface{}) (*models.UserInfo, error) {
		platform, _ := mapper.Resolve(claims)
		roles := make([]string, len(platform))
		for i, r := range platform {
			roles[i] = string(r)
		}
		email, _ := claims["email"].(string)
		name, _ := claims["name"].(string)
		return &models.UserInfo{Subject: idToken.Subject, Email: email, Name: name, Roles: roles}, nil
	}

	login, err := authn.NewOIDCLogin(mgr, authn.OIDCLoginConfig{
		Provider:     oidcProvider,
		Verifier:     verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://app.example/auth/callback",
		Resolve:      resolve,
		// The stub advertises code_challenge_methods_supported: [S256], so the
		// strictest posture a deployment can take is also what the tests run under.
		RequirePKCE: true,
	})
	if err != nil {
		t.Fatalf("oidc login: %v", err)
	}
	mgr.SetLogin(login)
	mgr.Register(mux)
	authMw.SetSessions(sessions, authn.DefaultSessionCookie)
	api.SetAuthInfo(handlers.AuthInfo{OIDCLogin: true, LoginProviders: mgr.LoginProviders()})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &consoleLoginEnv{srv: srv, idp: idp}
}

func TestConsoleOIDCLoginFlow(t *testing.T) {
	env := setupConsoleLogin(t)

	// A client with a cookie jar that does NOT auto-follow redirects, so the test
	// can drive each hop and inspect cookies/locations.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 0. /api/auth/config advertises server-side OIDC login.
	t.Run("AuthConfigAdvertisesLogin", func(t *testing.T) {
		resp, err := client.Get(env.srv.URL + "/api/auth/config")
		if err != nil {
			t.Fatalf("auth config: %v", err)
		}
		defer resp.Body.Close()
		var cfg map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&cfg)
		if cfg["oidc_login_enabled"] != true {
			t.Errorf("expected oidc_login_enabled=true, got %v", cfg)
		}
	})

	// 1. GET /auth/login -> 302 to the IdP authorize endpoint (tx cookie set).
	resp, err := client.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	q := authorizeURL.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing state/nonce/PKCE: %s", authorizeURL)
	}

	// 2. The browser hop to the IdP. It records the PKCE challenge against the
	// code it issues, so the exchange in step 3 only succeeds if the server
	// presents the matching verifier.
	code, state := env.idp.authorization(t, authorizeURL.String())
	if state != q.Get("state") {
		t.Fatalf("the IdP echoed state %q, want %q", state, q.Get("state"))
	}

	// 3. GET /auth/callback?code=..&state=.. -> 302 to /console/, session set.
	cbURL := env.srv.URL + "/auth/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	resp, err = client.Get(cbURL)
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body redirect to console)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/console/") {
		t.Errorf("callback redirect = %q, want /console/", loc)
	}

	// The session cookie must now be present in the jar.
	var haveSession bool
	for _, c := range jar.Cookies(mustParseURL(t, env.srv.URL)) {
		if c.Name == authn.DefaultSessionCookie {
			haveSession = true
		}
	}
	if !haveSession {
		t.Fatal("no session cookie was set after login")
	}

	// 3. GET /api/me with the session cookie -> the mapped principal.
	resp, err = client.Get(env.srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, want 200", resp.StatusCode)
	}
	var me models.UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode /api/me: %v", err)
	}
	if me.Subject != "alice-oidc-subject" {
		t.Errorf("subject = %q, want alice-oidc-subject", me.Subject)
	}
	if len(me.Roles) != 1 || me.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin] (group claim mapped to RBAC role)", me.Roles)
	}

	// 4. /auth/session returns the CSRF token for subsequent writes.
	resp, err = client.Get(env.srv.URL + "/auth/session")
	if err != nil {
		t.Fatalf("GET /auth/session: %v", err)
	}
	var sessInfo struct {
		CSRFToken string `json:"csrf_token"`
	}
	json.NewDecoder(resp.Body).Decode(&sessInfo)
	resp.Body.Close()
	if sessInfo.CSRFToken == "" {
		t.Fatal("no CSRF token returned")
	}

	// 5. A cookie-authenticated write without the CSRF token is refused; with it,
	// it passes the auth/CSRF layer (a bogus CA id then yields a normal 4xx, not
	// 403 CSRF). This proves CSRF protection is enforced for console writes.
	t.Run("CSRFProtectsWrites", func(t *testing.T) {
		noToken, _ := http.NewRequest("POST", env.srv.URL+"/api/tenants", strings.NewReader(`{"id":"x","name":"X"}`))
		noToken.Header.Set("Content-Type", "application/json")
		r1, err := client.Do(noToken)
		if err != nil {
			t.Fatalf("post without csrf: %v", err)
		}
		r1.Body.Close()
		if r1.StatusCode != http.StatusForbidden {
			t.Errorf("write without CSRF = %d, want 403", r1.StatusCode)
		}

		withToken, _ := http.NewRequest("POST", env.srv.URL+"/api/tenants", strings.NewReader(`{"id":"tnt","slug":"tnt","name":"Tenant"}`))
		withToken.Header.Set("Content-Type", "application/json")
		withToken.Header.Set(authn.CSRFHeader, sessInfo.CSRFToken)
		r2, err := client.Do(withToken)
		if err != nil {
			t.Fatalf("post with csrf: %v", err)
		}
		r2.Body.Close()
		if r2.StatusCode == http.StatusForbidden {
			t.Errorf("write with valid CSRF still got 403 (CSRF false-negative)")
		}
	})
}

func writeTestJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return k
}
