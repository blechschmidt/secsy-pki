package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Proof Key for Code Exchange (RFC 7636) on the console's interactive login.
//
// PKCE is what stops a stolen authorization code from being redeemed by anyone
// but the browser that started the login: the authorization request commits to
// S256(verifier), and only the holder of the verifier can complete the exchange.
// The guarantees asserted here are the ones that make that true:
//
//   - the challenge really is the SHA-256 of the verifier sealed in the login
//     transaction cookie (a challenge computed from anything else would bind
//     nothing), and the method is S256, never `plain`;
//   - the verifier is a fresh, high-entropy string of the shape RFC 7636 §4.1
//     allows, so an IdP cannot reject it and no two logins share one;
//   - a public client — the registration PKCE exists for — authenticates its
//     token request in the request body rather than with an empty-password
//     Basic header; and
//   - a deployment can demand that the IdP actually advertise S256 before the
//     server will serve logins through it.
//
// The matching end-to-end proof, where a PKCE-enforcing IdP rejects an exchange
// whose verifier does not match, lives in internal/e2e/console_pkce_test.go.

// unreservedPKCE is the RFC 7636 §4.1 code-verifier alphabet:
// ALPHA / DIGIT / "-" / "." / "_" / "~".
func unreservedPKCE(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '.', r == '_', r == '~':
		return true
	}
	return false
}

// txFromCookie recovers (with signature verification) the login transaction
// sealed in a Begin cookie. It is the signed-envelope counterpart of txOf, which
// decodes a recorder's cookie without verifying it.
func txFromCookie(t *testing.T, l *OIDCLogin, cookie *http.Cookie) oidcTx {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	r.AddCookie(cookie)
	tx, err := l.readTxCookie(r)
	if err != nil {
		t.Fatalf("read transaction cookie: %v", err)
	}
	return tx
}

// TestOIDCBeginBindsChallengeToCookieVerifier is the core PKCE property: the
// code_challenge sent to the IdP is exactly S256 of the verifier this server
// kept, so the exchange can only be completed by presenting that verifier.
func TestOIDCBeginBindsChallengeToCookieVerifier(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		loc, cookie := beginLogin(t, l)
		q := loc.Query()
		tx := txFromCookie(t, l, cookie)

		if got, want := q.Get("code_challenge"), oauth2.S256ChallengeFromVerifier(tx.Verifier); got != want {
			t.Errorf("code_challenge = %q, want S256 of the cookie's verifier (%q)", got, want)
		}
		if q.Get("code_challenge_method") != PKCEMethodS256 {
			t.Errorf("code_challenge_method = %q, want %s", q.Get("code_challenge_method"), PKCEMethodS256)
		}
		// A `plain` challenge is the verifier itself; it must never leave here.
		if q.Get("code_challenge") == tx.Verifier {
			t.Error("the challenge equals the verifier: this is a plain, not an S256, challenge")
		}
		// The verifier never travels in the authorization request — only its hash.
		if strings.Contains(loc.String(), tx.Verifier) {
			t.Error("the authorization URL leaks the code verifier")
		}

		// RFC 7636 §4.1: 43..128 characters from the unreserved alphabet.
		if n := len(tx.Verifier); n < 43 || n > 128 {
			t.Errorf("verifier length = %d, want 43..128 (RFC 7636 §4.1)", n)
		}
		for _, r := range tx.Verifier {
			if !unreservedPKCE(r) {
				t.Fatalf("verifier %q contains %q, outside the unreserved alphabet", tx.Verifier, r)
			}
		}
		if seen[tx.Verifier] {
			t.Errorf("verifier %q was reused across login attempts", tx.Verifier)
		}
		seen[tx.Verifier] = true

		// The verifier is only ever held in the signed, HttpOnly cookie: script in
		// the browser cannot read it, and the server keeps no login state.
		if !cookie.HttpOnly {
			t.Error("the cookie holding the PKCE verifier must be HttpOnly")
		}
	}
}

// TestOIDCCallbackSendsTheVerifier asserts the token request carries the
// verifier from the transaction cookie — the half of PKCE that happens at the
// token endpoint (RFC 7636 §4.5). A stub token endpoint stands in for the IdP
// and records the form it received.
func TestOIDCCallbackSendsTheVerifier(t *testing.T) {
	var gotForm struct {
		verifier string
		clientID string
		basic    bool
		hits     int
	}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm.hits++
		gotForm.verifier = r.PostForm.Get("code_verifier")
		gotForm.clientID = r.PostForm.Get("client_id")
		_, _, gotForm.basic = r.BasicAuth()
		// Fail the exchange: this test is about what was SENT, and an id token
		// would need a signing key the stub does not have. The login fails after
		// the request has been recorded.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer idp.Close()

	e := newLoginEnv(t)
	provider := (&oidc.ProviderConfig{
		IssuerURL: "https://idp.example.com", AuthURL: testIDPAuthURL,
		TokenURL: idp.URL + "/token", JWKSURL: "https://idp.example.com/jwks",
		Algorithms: []string{"RS256"},
	}).NewProvider(context.Background())
	l, err := NewOIDCLogin(e.mgr, OIDCLoginConfig{
		Provider: provider, Verifier: provider.Verifier(&oidc.Config{ClientID: "console"}),
		ClientID: "console", RedirectURL: testRedirectURL,
		Resolve: func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) {
			return &models.UserInfo{Subject: "sso@example.com"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin: %v", err)
	}
	e.mgr.SetLogin(l)

	loc, cookie := beginLogin(t, l)
	tx := txFromCookie(t, l, cookie)
	rec := callback(l, "code=the-code&state="+tx.State, cookie)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("callback status = %d, want 401 (the stub IdP refuses the grant)", rec.Code)
	}
	if gotForm.hits != 1 {
		t.Fatalf("token endpoint hits = %d, want exactly 1", gotForm.hits)
	}
	if gotForm.verifier != tx.Verifier {
		t.Errorf("code_verifier = %q, want the transaction's verifier %q", gotForm.verifier, tx.Verifier)
	}
	if challenge := loc.Query().Get("code_challenge"); oauth2.S256ChallengeFromVerifier(gotForm.verifier) != challenge {
		t.Errorf("the verifier sent to the token endpoint does not hash to the challenge sent to /authorize")
	}
	// This client registered no secret, so the client_id belongs in the body and
	// no empty-password Basic header may be sent (RFC 6749 §2.3.1).
	if gotForm.clientID != "console" {
		t.Errorf("client_id in the token request body = %q, want console", gotForm.clientID)
	}
	if gotForm.basic {
		t.Error("a public client must not authenticate with an HTTP Basic header")
	}
	// A failed exchange establishes nothing.
	if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
		t.Error("a failed code exchange established a session cookie")
	}
}

// TestOIDCPublicClientUsesRequestBodyAuth pins the token-endpoint client
// authentication style. x/oauth2 auto-detects by trying HTTP Basic first; for a
// client with no secret that sends `Basic base64("<id>:")`, which IdPs answer
// with invalid_client — a failed client authentication logged at the IdP on
// every login, before the retry succeeds. A public client says so up front.
func TestOIDCPublicClientUsesRequestBodyAuth(t *testing.T) {
	e := newLoginEnv(t)
	provider := (&oidc.ProviderConfig{
		IssuerURL: "https://idp.example.com", AuthURL: testIDPAuthURL,
		TokenURL: "https://idp.example.com/token", JWKSURL: "https://idp.example.com/jwks",
		Algorithms: []string{"RS256"},
	}).NewProvider(context.Background())
	resolve := func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) { return nil, nil }

	public, err := NewOIDCLogin(e.mgr, OIDCLoginConfig{
		Provider: provider, Verifier: provider.Verifier(&oidc.Config{ClientID: "console"}),
		ClientID: "console", RedirectURL: testRedirectURL, Resolve: resolve,
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin (public): %v", err)
	}
	if !public.PublicClient() {
		t.Error("a login configured without a client secret must report itself a public client")
	}
	if got := public.oauth.Endpoint.AuthStyle; got != oauth2.AuthStyleInParams {
		t.Errorf("public client AuthStyle = %v, want AuthStyleInParams", got)
	}

	confidential, err := NewOIDCLogin(e.mgr, OIDCLoginConfig{
		Provider: provider, Verifier: provider.Verifier(&oidc.Config{ClientID: "console"}),
		ClientID: "console", ClientSecret: "shhh", RedirectURL: testRedirectURL, Resolve: resolve,
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin (confidential): %v", err)
	}
	if confidential.PublicClient() {
		t.Error("a login configured with a client secret is not a public client")
	}
	// A confidential client keeps the library's auto-detection: Basic first, which
	// is what most IdPs prefer for client_secret_basic registrations.
	if got := confidential.oauth.Endpoint.AuthStyle; got != oauth2.AuthStyleAutoDetect {
		t.Errorf("confidential client AuthStyle = %v, want AuthStyleAutoDetect", got)
	}
}

// discoveryIDP serves a minimal OpenID discovery document advertising the given
// code-challenge methods (omitted entirely when methods is nil).
func discoveryIDP(t *testing.T, methods []string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if methods != nil {
			doc["code_challenge_methods_supported"] = methods
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestOIDCRequirePKCEHonoursDiscovery asserts the deployment-level demand: with
// require_pkce set, an IdP that does not advertise S256 may not serve logins —
// because the challenge this server sends would be silently ignored, leaving a
// stolen authorization code sufficient to log in.
func TestOIDCRequirePKCEHonoursDiscovery(t *testing.T) {
	cases := []struct {
		name      string
		methods   []string
		advertise bool
	}{
		{"S256 advertised", []string{"S256"}, true},
		{"S256 among several", []string{"plain", "S256"}, true},
		{"only plain", []string{"plain"}, false},
		{"field omitted", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := discoveryIDP(t, tc.methods)
			provider, err := oidc.NewProvider(context.Background(), idp.URL)
			if err != nil {
				t.Fatalf("discovery: %v", err)
			}
			e := newLoginEnv(t)
			build := func(require bool) (*OIDCLogin, error) {
				return NewOIDCLogin(e.mgr, OIDCLoginConfig{
					Name: "corp", Provider: provider,
					Verifier:    provider.Verifier(&oidc.Config{ClientID: "console"}),
					ClientID:    "console",
					RedirectURL: testRedirectURL,
					RequirePKCE: require,
					Resolve: func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) {
						return nil, nil
					},
				})
			}

			// Without the demand the provider always builds, and still sends S256 —
			// an IdP that ignores the challenge is a weaker IdP, not a broken login.
			l, err := build(false)
			if err != nil {
				t.Fatalf("NewOIDCLogin without require_pkce: %v", err)
			}
			if l.PKCE().Method != PKCEMethodS256 {
				t.Errorf("PKCE method = %q, want S256 regardless of what the IdP advertises", l.PKCE().Method)
			}
			if l.PKCE().Advertised != tc.advertise {
				t.Errorf("PKCE advertised = %v, want %v for %v", l.PKCE().Advertised, tc.advertise, tc.methods)
			}
			loc, _ := beginLogin(t, l)
			if loc.Query().Get("code_challenge_method") != PKCEMethodS256 {
				t.Error("the authorization request dropped its PKCE challenge")
			}

			// With it, only an advertised S256 is allowed to start.
			l, err = build(true)
			switch {
			case tc.advertise && err != nil:
				t.Fatalf("NewOIDCLogin with require_pkce: %v", err)
			case !tc.advertise && err == nil:
				t.Fatalf("NewOIDCLogin with require_pkce = %v, want an error for methods %v", l, tc.methods)
			case !tc.advertise && !strings.Contains(err.Error(), "require_pkce"):
				t.Errorf("error %q does not tell the operator which setting to change", err)
			}
		})
	}
}

// TestLoginProvidersPublishPKCEMethod asserts the public discovery document
// carries the proof-key method, so the sign-in page can state how the handshake
// is protected rather than asserting it from a hard-coded string.
func TestLoginProvidersPublishPKCEMethod(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)
	e.mgr.SetLogin(l)

	providers := e.mgr.LoginProviders()
	if len(providers) != 1 {
		t.Fatalf("LoginProviders() = %#v, want one entry", providers)
	}
	if providers[0].PKCE != PKCEMethodS256 {
		t.Errorf("LoginProviders()[0].PKCE = %q, want %s", providers[0].PKCE, PKCEMethodS256)
	}
}

// TestOIDCTransactionCookieExpiryBoundsVerifierLifetime asserts the verifier is
// short-lived: a transaction cookie older than the window is refused, so a
// verifier recovered from a stale browser profile cannot complete a login.
func TestOIDCTransactionCookieExpiryBoundsVerifierLifetime(t *testing.T) {
	e := newLoginEnv(t)
	l := newTestOIDCLogin(t, e.mgr)
	e.mgr.SetLogin(l)

	stale := resignedTxCookie(t, l, oidcTx{
		State: "s", Nonce: "n", Verifier: oauth2.GenerateVerifier(),
		Issued: time.Now().Add(-11 * time.Minute).Unix(),
	})
	rec := callback(l, "code=abc&state=s", stale)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("stale transaction status = %d, want 400", rec.Code)
	}
	if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
		t.Error("a stale transaction established a session")
	}
}
