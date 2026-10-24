//go:build sqlite

// End-to-end verification that the operator console's OIDC login really runs
// Proof Key for Code Exchange (RFC 7636), driven through the real handler stack
// against the PKCE-enforcing stub IdP in console_login_test.go.
//
// PKCE exists for one threat: an authorization code that leaks — out of a
// browser history, a referrer header, a proxy log, a crafted redirect — must be
// worthless to whoever picks it up. The code is bound to a secret (the verifier)
// that never leaves the server, and only its SHA-256 (the challenge) travels in
// the authorization request. That makes it the protection a PUBLIC client has
// instead of a client secret, and a second lock for a confidential one.
//
// These tests assert the whole chain against an IdP that behaves like a
// conformant authorization server: it refuses an authorization request without
// an S256 challenge, refuses to redeem a code without the matching verifier, and
// refuses to redeem a code twice.
//
//	login     — /auth/login commits S256(verifier); /authorize records it; the
//	            callback exchanges the code WITH the verifier; a session appears
//	shape     — the public client's exchange carries client_id in the body and no
//	            empty-password Basic header, in one request (no failed probe)
//	theft     — the code alone, without the verifier, buys an attacker nothing
//	replay    — a redeemed code cannot be redeemed again
//	discovery — /api/auth/config tells the browser the method is S256
package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
)

// pkceLogin drives a complete console login and returns the client (holding the
// session), the authorization request's query, and the code that was redeemed.
func pkceLogin(t *testing.T, env *consoleLoginEnv) (*http.Client, url.Values, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	q := authorizeURL.Query()

	code, state := env.idp.authorization(t, authorizeURL.String())
	resp, err = client.Get(env.srv.URL + "/auth/callback?code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		t.Fatalf("callback status = %d, want 302; body=%s", resp.StatusCode, body[:n])
	}
	return client, q, code
}

// TestConsolePKCEBindsTheCodeToTheVerifier is the headline property: the login
// completes only because the server presented the verifier behind the challenge
// it committed to at /authorize. The stub IdP enforces the match, so a login
// that skipped or mismatched the verifier would not reach a session at all.
func TestConsolePKCEBindsTheCodeToTheVerifier(t *testing.T) {
	env := setupConsoleLogin(t)
	client, authz, code := pkceLogin(t, env)

	// What the server committed to in the authorization request.
	if got := authz.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	challenge := authz.Get("code_challenge")
	if challenge == "" {
		t.Fatal("the authorization request carried no code_challenge")
	}

	// What the IdP recorded against the code it issued. (The code has been
	// redeemed by now, so the record is gone — which is itself the single-use
	// property asserted below; the challenge is checked through the exchange.)
	if _, stillOpen := env.idp.challengeFor(code); stillOpen {
		t.Error("the authorization code survived its redemption at the IdP")
	}

	// What the server actually sent to the token endpoint.
	log := env.idp.exchangeLog()
	if len(log) != 1 {
		t.Fatalf("token requests = %d, want exactly 1 (%+v)", len(log), log)
	}
	ex := log[0]
	if ex.err != "" {
		t.Fatalf("the exchange was refused: %s", ex.err)
	}
	if ex.verifier == "" {
		t.Fatal("the token request carried no code_verifier")
	}
	if s256(ex.verifier) != challenge {
		t.Errorf("S256(code_verifier) = %q, want the committed challenge %q", s256(ex.verifier), challenge)
	}
	// The verifier is the secret half; it must never have travelled in the
	// browser-visible authorization request.
	if strings.Contains(authz.Encode(), ex.verifier) {
		t.Error("the authorization request leaked the code verifier to the browser")
	}

	// And the login landed: a session carrying the mapped role.
	resp, err := client.Get(env.srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, want 200", resp.StatusCode)
	}
}

// TestConsolePKCEPublicClientExchangeShape pins how a public client
// authenticates its token request. PKCE replaces the client secret, so the
// exchange must carry client_id in the request body (RFC 6749 §2.3.1) and no
// `Basic base64("<id>:")` header — an empty-password credential that IdPs log
// and reject as invalid_client. One request, no failed probe.
func TestConsolePKCEPublicClientExchangeShape(t *testing.T) {
	env := setupConsoleLogin(t)
	pkceLogin(t, env)

	log := env.idp.exchangeLog()
	if len(log) != 1 {
		t.Fatalf("token requests = %d, want exactly 1 — a second request means a "+
			"failed client-authentication probe preceded it (%+v)", len(log), log)
	}
	if log[0].basicAuth {
		t.Error("the public client sent an HTTP Basic header; it has no secret to present")
	}
	if log[0].clientID != "secsy-console" {
		t.Errorf("client_id in the token request body = %q, want secsy-console", log[0].clientID)
	}
}

// TestConsolePKCEConfidentialClientStillProvesPossession asserts PKCE is not
// traded away when a client secret IS configured: the secret authenticates the
// client, the verifier still proves it is the same browser session, and both are
// required.
func TestConsolePKCEConfidentialClientStillProvesPossession(t *testing.T) {
	env := setupConsoleLoginClient(t, "console-client-secret")
	_, authz, _ := pkceLogin(t, env)

	if authz.Get("code_challenge_method") != "S256" {
		t.Error("a confidential client dropped its PKCE challenge")
	}
	log := env.idp.exchangeLog()
	granted := log[len(log)-1]
	if granted.err != "" {
		t.Fatalf("the confidential exchange was refused: %s", granted.err)
	}
	if granted.verifier == "" {
		t.Error("the confidential client's exchange carried no code_verifier")
	}
	if s256(granted.verifier) != authz.Get("code_challenge") {
		t.Error("the confidential client's verifier does not match its challenge")
	}
}

// TestConsolePKCEStolenCodeIsUseless is the threat PKCE exists for. An attacker
// who captures the authorization code — but not the server's HttpOnly
// transaction cookie, and so not the verifier — cannot turn it into anything:
// not at the console's callback (no transaction, then a state mismatch), and not
// at the IdP directly (no verifier that hashes to the challenge).
func TestConsolePKCEStolenCodeIsUseless(t *testing.T) {
	env := setupConsoleLogin(t)

	// A victim begins a login and the code leaks after the IdP issues it.
	victim := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	jar, _ := cookiejar.New(nil)
	victim.Jar = jar
	resp, err := victim.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	authorizeURL, _ := url.Parse(resp.Header.Get("Location"))
	code, state := env.idp.authorization(t, authorizeURL.String())
	challenge := authorizeURL.Query().Get("code_challenge")

	// 1. The attacker replays the code at the callback from their own browser —
	// no transaction cookie at all.
	attacker := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	attackerJar, _ := cookiejar.New(nil)
	attacker.Jar = attackerJar
	resp, err = attacker.Get(env.srv.URL + "/auth/callback?code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("attacker callback: %v", err)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "bad_tx" {
		t.Errorf("attacker callback = %d %v, want 400 bad_tx", resp.StatusCode, body)
	}

	// 2. The attacker starts their own login first (so they do have a valid
	// transaction, with THEIR verifier) and then feeds in the stolen code.
	resp, err = attacker.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("attacker GET /auth/login: %v", err)
	}
	resp.Body.Close()
	attackerAuthz, _ := url.Parse(resp.Header.Get("Location"))
	resp, err = attacker.Get(env.srv.URL + "/auth/callback?code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(attackerAuthz.Query().Get("state")))
	if err != nil {
		t.Fatalf("attacker callback with own transaction: %v", err)
	}
	body = nil
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	// The exchange reaches the IdP and is refused there: the attacker's verifier
	// belongs to the attacker's challenge, not to the victim's code.
	if resp.StatusCode != http.StatusUnauthorized || body["code"] != "exchange_failed" {
		t.Errorf("attacker exchange = %d %v, want 401 exchange_failed", resp.StatusCode, body)
	}
	log := env.idp.exchangeLog()
	last := log[len(log)-1]
	if !strings.Contains(last.err, "code_verifier does not match") {
		t.Errorf("the IdP refused with %q, want a PKCE mismatch", last.err)
	}

	// 3. And the attacker cannot forge a verifier for the victim's challenge: the
	// challenge is a SHA-256 digest, and the stub checks the preimage.
	if s256("an-attacker-chosen-verifier-of-sufficient-length-00") == challenge {
		t.Fatal("impossible: a guessed verifier matched the challenge")
	}

	// No session was established anywhere along the way.
	resp, err = attacker.Get(env.srv.URL + "/auth/session")
	if err != nil {
		t.Fatalf("attacker GET /auth/session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("attacker session status = %d, want 401", resp.StatusCode)
	}
}

// TestConsolePKCECodeIsSingleUse asserts a redeemed code cannot be redeemed
// again (RFC 6749 §4.1.2). PKCE binds a code to a browser; single use bounds how
// long that binding has to hold.
func TestConsolePKCECodeIsSingleUse(t *testing.T) {
	env := setupConsoleLogin(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	authorizeURL, _ := url.Parse(resp.Header.Get("Location"))
	code, state := env.idp.authorization(t, authorizeURL.String())
	callbackURL := env.srv.URL + "/auth/callback?code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(state)

	// First redemption succeeds.
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("first callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first callback status = %d, want 302", resp.StatusCode)
	}

	// The transaction cookie is cleared by the callback, so a replay from the
	// same browser now fails for want of a transaction — before any exchange.
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("replayed callback: %v", err)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Error("a replayed authorization code completed a second login")
	}
	if body["code"] != "bad_tx" {
		t.Errorf("replay rejected with %v, want bad_tx (the transaction cookie is one-shot)", body)
	}

	// At the IdP the code is gone too, so even a caller that kept a transaction
	// could not redeem it twice.
	if _, open := env.idp.challengeFor(code); open {
		t.Error("the IdP still holds the redeemed authorization code")
	}
}

// TestConsolePKCEAdvertisedToTheBrowser asserts the unauthenticated discovery
// document the login page reads states the proof-key method, so the console can
// show how the handshake is protected instead of asserting it from a constant.
func TestConsolePKCEAdvertisedToTheBrowser(t *testing.T) {
	env := setupConsoleLogin(t)

	resp, err := http.Get(env.srv.URL + "/api/auth/config")
	if err != nil {
		t.Fatalf("GET /api/auth/config: %v", err)
	}
	defer resp.Body.Close()
	var cfg struct {
		OIDCLoginEnabled bool                      `json:"oidc_login_enabled"`
		Providers        []authn.LoginProviderInfo `json:"oidc_providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode auth config: %v", err)
	}
	if !cfg.OIDCLoginEnabled || len(cfg.Providers) != 1 {
		t.Fatalf("auth config = %+v, want one interactive login provider", cfg)
	}
	if cfg.Providers[0].PKCE != authn.PKCEMethodS256 {
		t.Errorf("oidc_providers[0].pkce = %q, want S256", cfg.Providers[0].PKCE)
	}
}
