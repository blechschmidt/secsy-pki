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
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
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

// stubIDP is an in-process OpenID Connect provider: discovery, JWKS, and a token
// endpoint that mints a signed id token carrying the group claim under test.
type stubIDP struct {
	srv      *httptest.Server
	signer   jose.Signer
	clientID string
	// nonce is set from the authorization request just before the token exchange,
	// so the minted id token echoes it (go-oidc binds the nonce).
	nonce string
	sub   string
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
	idp := &stubIDP{signer: signer, clientID: clientID, sub: sub}

	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	issuer := idp.srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: priv.Public(), KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}}
		writeTestJSON(w, jwks)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]interface{}{
			"iss":            issuer,
			"aud":            clientID,
			"sub":            idp.sub,
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"nonce":          idp.nonce,
			"email":          "admin@example.com",
			"email_verified": true,
			"name":           "Alice Admin",
			"groups":         []string{"pki-admins"},
		}
		payload, _ := json.Marshal(claims)
		jws, err := idp.signer.Sign(payload)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		compact, _ := jws.CompactSerialize()
		writeTestJSON(w, map[string]interface{}{
			"access_token": "stub-access-token",
			"token_type":   "Bearer",
			"id_token":     compact,
		})
	})
	return idp
}

// consoleLoginEnv is the wired-up app server for the login flow test.
type consoleLoginEnv struct {
	srv *httptest.Server
	idp *stubIDP
}

func setupConsoleLogin(t *testing.T) *consoleLoginEnv {
	t.Helper()
	const clientID = "secsy-console"
	idp := newStubIDP(t, clientID, "alice-oidc-subject")

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
		Provider:    oidcProvider,
		Verifier:    verifier,
		ClientID:    clientID,
		RedirectURL: "http://app.example/auth/callback",
		Resolve:     resolve,
	})
	if err != nil {
		t.Fatalf("oidc login: %v", err)
	}
	mgr.SetLogin(login)
	mgr.Register(mux)
	authMw.SetSessions(sessions, authn.DefaultSessionCookie)
	api.SetAuthInfo(handlers.AuthInfo{OIDCLogin: true})

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
	state := q.Get("state")
	if state == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing state/nonce/PKCE: %s", authorizeURL)
	}
	// The IdP will echo this nonce into the id token.
	env.idp.nonce = q.Get("nonce")

	// 2. GET /auth/callback?code=..&state=.. -> 302 to /console/, session set.
	cbURL := env.srv.URL + "/auth/callback?code=stub-code&state=" + url.QueryEscape(state)
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
