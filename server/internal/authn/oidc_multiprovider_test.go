// Tests for several interactive OIDC login providers on one console (Task 212).
//
// A deployment that federates more than one identity provider — the corporate
// IdP for staff, a second for contractors or a partner — introduces a dispatch
// decision that did not exist with a single provider: which verifier, which
// client credentials, and which claim -> role mapping complete a given callback.
// Getting that wrong is not a cosmetic bug. Completing provider A's authorization
// code at provider B would exchange it with B's client credentials and map A's
// claims through B's role mapping, so a login at a low-trust IdP could resolve to
// roles meant for a high-trust one.
//
// The dispatch key is the provider name sealed inside the HMAC-signed login
// transaction cookie. These tests assert it is written on the way out, honored on
// the way back, and that a transaction arriving at the wrong provider is refused
// rather than completed. No identity provider is contacted: Begin only mints
// state/nonce/PKCE and redirects, and every callback path asserted here fails
// before the token exchange.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
)

// newNamedLogin builds a named login provider against static IdP metadata, so
// each provider in a test has a distinguishable authorization endpoint and client.
func newNamedLogin(t *testing.T, mgr *Manager, name, display, idpBase, clientID string) *OIDCLogin {
	t.Helper()
	provider := (&oidc.ProviderConfig{
		IssuerURL:  idpBase,
		AuthURL:    idpBase + "/authorize",
		TokenURL:   idpBase + "/token",
		JWKSURL:    idpBase + "/jwks",
		Algorithms: []string{"RS256"},
	}).NewProvider(context.Background())
	l, err := NewOIDCLogin(mgr, OIDCLoginConfig{
		Name:        name,
		DisplayName: display,
		Provider:    provider,
		Verifier:    provider.Verifier(&oidc.Config{ClientID: clientID}),
		ClientID:    clientID,
		RedirectURL: "https://pki.example.com/auth/callback",
		Resolve: func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) {
			return &models.UserInfo{Subject: "sso@example.com", Roles: []string{"issuer"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin(%s): %v", name, err)
	}
	return l
}

// twoLoginProviders wires a manager with two named providers, "entra" (default,
// declared first) and "okta".
func twoLoginProviders(t *testing.T) (*loginEnv, *OIDCLogin, *OIDCLogin) {
	t.Helper()
	e := newLoginEnv(t)
	entra := newNamedLogin(t, e.mgr, "entra", "Microsoft Entra ID", "https://entra.example.com", "console-entra")
	okta := newNamedLogin(t, e.mgr, "okta", "Okta", "https://okta.example.com", "console-okta")
	if err := e.mgr.AddLogin(entra); err != nil {
		t.Fatalf("AddLogin(entra): %v", err)
	}
	if err := e.mgr.AddLogin(okta); err != nil {
		t.Fatalf("AddLogin(okta): %v", err)
	}
	return e, entra, okta
}

// beginVia drives GET on the given path/query through the manager's dispatcher.
func beginVia(mgr *Manager, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	// httptest does not populate path wildcards; mirror what ServeMux would do.
	if name, ok := pathProviderOf(target); ok {
		r.SetPathValue("provider", name)
	}
	mgr.OIDCBegin(rec, r)
	return rec
}

// pathProviderOf extracts the provider segment of a /auth/login/oidc/<name> or
// /auth/callback/<name> target.
func pathProviderOf(target string) (string, bool) {
	path := target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, prefix := range []string{"/auth/login/oidc/", "/auth/callback/"} {
		if strings.HasPrefix(path, prefix) {
			if name := strings.TrimPrefix(path, prefix); name != "" {
				return name, true
			}
		}
	}
	return "", false
}

// txOf decodes (without verifying) the login transaction a Begin response sealed
// into its cookie, so a test can assert which provider it names.
func txOf(t *testing.T, mgr *Manager, rec *httptest.ResponseRecorder) oidcTx {
	t.Helper()
	c := cookieNamed(rec, mgr.txCookieName())
	if c == nil {
		t.Fatalf("no transaction cookie was set: %v", rec.Result().Cookies())
	}
	payload, _, ok := splitDot(c.Value)
	if !ok {
		t.Fatalf("transaction cookie %q is not payload.signature", c.Value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode transaction payload: %v", err)
	}
	var tx oidcTx
	if err := json.Unmarshal(raw, &tx); err != nil {
		t.Fatalf("unmarshal transaction: %v", err)
	}
	return tx
}

// txCookieFor returns a validly-signed transaction cookie naming provider, as the
// honest server would have written when that provider began a flow.
func txCookieFor(t *testing.T, mgr *Manager, provider, state string) *http.Cookie {
	t.Helper()
	tx := oidcTx{State: state, Nonce: "nonce", Verifier: "verifier", Issued: time.Now().Unix(), Provider: provider}
	rec := httptest.NewRecorder()
	mgr.setLoginTxCookie(rec, tx, mgr.loginTxKey())
	c := cookieNamed(rec, mgr.txCookieName())
	if c == nil {
		t.Fatal("setLoginTxCookie set no cookie")
	}
	return c
}

// callbackVia drives a callback through the manager's dispatcher.
func callbackVia(mgr *Manager, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if name, ok := pathProviderOf(target); ok {
		r.SetPathValue("provider", name)
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	mgr.OIDCCallback(rec, r)
	return rec
}

// TestLoginDispatchSelectsProvider asserts the three ways to address a provider —
// the default, the query parameter, and the path form — each begin the right IdP's
// flow and seal that provider's name into the transaction.
func TestLoginDispatchSelectsProvider(t *testing.T) {
	e, _, _ := twoLoginProviders(t)

	for _, tc := range []struct {
		target   string
		wantIDP  string
		wantName string
	}{
		{"/auth/login", "https://entra.example.com/authorize", "entra"},
		{"/auth/login?provider=okta", "https://okta.example.com/authorize", "okta"},
		{"/auth/login?provider=entra", "https://entra.example.com/authorize", "entra"},
		{"/auth/login/oidc/okta", "https://okta.example.com/authorize", "okta"},
	} {
		rec := beginVia(e.mgr, tc.target)
		if rec.Code != http.StatusFound {
			t.Fatalf("GET %s: status = %d, want 302; body=%s", tc.target, rec.Code, rec.Body.String())
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, tc.wantIDP) {
			t.Errorf("GET %s redirected to %q, want the %s endpoint", tc.target, loc, tc.wantName)
		}
		if tx := txOf(t, e.mgr, rec); tx.Provider != tc.wantName {
			t.Errorf("GET %s sealed provider %q into the transaction, want %q", tc.target, tx.Provider, tc.wantName)
		}
		// The client id in the authorization request must be the addressed
		// provider's, not the default's.
		if !strings.Contains(loc, "client_id=console-"+tc.wantName) {
			t.Errorf("GET %s authorization URL %q does not carry client_id=console-%s", tc.target, loc, tc.wantName)
		}
	}
}

// TestLoginDispatchRejectsUnknownProvider asserts an unknown name is refused
// instead of silently falling back to the default: a stale console link or a
// renamed provider must not send an operator to a different IdP than the one the
// link named. The response lists the real providers so the console can recover.
func TestLoginDispatchRejectsUnknownProvider(t *testing.T) {
	e, _, _ := twoLoginProviders(t)
	e.sink.reset()

	rec := beginVia(e.mgr, "/auth/login?provider=attacker")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if cookieNamed(rec, e.mgr.txCookieName()) != nil {
		t.Error("a rejected login must not mint a transaction cookie")
	}
	body := bodyJSON(t, rec)
	if body["code"] != "unknown_provider" {
		t.Errorf("code = %v, want unknown_provider", body["code"])
	}
	if providers, ok := body["providers"].([]interface{}); !ok || len(providers) != 2 {
		t.Errorf("providers = %#v, want the two configured providers", body["providers"])
	}
	if got := e.sink.withAction(audit.ActionAuthLoginFailed); len(got) != 1 ||
		!strings.Contains(got[0].Detail, "unknown_provider") {
		t.Errorf("failed-login audit = %+v, want one unknown_provider denial", got)
	}
}

// TestCallbackDispatchesByTransactionProvider asserts a shared redirect URI works:
// the callback recovers the provider from the signed transaction rather than from
// the URL, so both IdPs can be registered against one /auth/callback.
//
// Dispatch is observed through the audit trail of the deliberate `no_code`
// failure — a hermetic way to see which provider handled the request, since
// completing the flow would require the IdP's token endpoint.
func TestCallbackDispatchesByTransactionProvider(t *testing.T) {
	e, _, _ := twoLoginProviders(t)

	for _, name := range []string{"entra", "okta"} {
		e.sink.reset()
		rec := callbackVia(e.mgr, "/auth/callback?state=st-"+name,
			txCookieFor(t, e.mgr, name, "st-"+name))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("callback for %s: status = %d, want 400 (no code); body=%s", name, rec.Code, rec.Body.String())
		}
		if body := bodyJSON(t, rec); body["code"] != "no_code" {
			t.Fatalf("callback for %s: code = %v, want no_code (i.e. it got past state validation)", name, body["code"])
		}
		events := e.sink.withAction(audit.ActionAuthLoginFailed)
		if len(events) != 1 {
			t.Fatalf("callback for %s: audit events = %+v, want one", name, events)
		}
		if !strings.Contains(events[0].Detail, "provider="+name) {
			t.Errorf("callback for %s was handled by the wrong provider: audit detail %q", name, events[0].Detail)
		}
		if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
			t.Error("a failed callback must not establish a session")
		}
	}
}

// TestCallbackRejectsAnotherProvidersTransaction is the provider-confusion test
// for the per-provider callback path: a transaction begun at one IdP must not be
// completed at another's endpoint, because the code would then be exchanged with
// the wrong client credentials and the claims mapped through the wrong role
// mapping.
func TestCallbackRejectsAnotherProvidersTransaction(t *testing.T) {
	e, _, _ := twoLoginProviders(t)
	e.sink.reset()

	rec := callbackVia(e.mgr, "/auth/callback/okta?state=st&code=authz-code",
		txCookieFor(t, e.mgr, "entra", "st"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := bodyJSON(t, rec); body["code"] != "provider_mismatch" {
		t.Errorf("code = %v, want provider_mismatch", body["code"])
	}
	if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
		t.Fatal("a provider mismatch must not establish a session")
	}
	if got := e.sink.withAction(audit.ActionAuthLoginFailed); len(got) != 1 ||
		!strings.Contains(got[0].Detail, "provider_mismatch") {
		t.Errorf("failed-login audit = %+v, want one provider_mismatch denial", got)
	}
}

// TestCallbackHandlerRejectsForeignTransaction asserts the same refusal at the
// provider handler itself, not only at the dispatcher — so the guarantee holds
// however the handler is reached.
func TestCallbackHandlerRejectsForeignTransaction(t *testing.T) {
	e, _, okta := twoLoginProviders(t)
	e.sink.reset()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=st&code=authz-code", nil)
	r.AddCookie(txCookieFor(t, e.mgr, "entra", "st"))
	okta.Callback(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := bodyJSON(t, rec); body["code"] != "provider_mismatch" {
		t.Errorf("code = %v, want provider_mismatch", body["code"])
	}
	if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
		t.Error("a foreign transaction must not establish a session")
	}
}

// TestCallbackRejectsTransactionOfRemovedProvider covers the configuration-change
// case: a transaction in flight when a provider is removed must fail closed, not
// be completed by whichever provider remains.
func TestCallbackRejectsTransactionOfRemovedProvider(t *testing.T) {
	e, _, _ := twoLoginProviders(t)
	e.sink.reset()

	rec := callbackVia(e.mgr, "/auth/callback?state=st&code=authz-code",
		txCookieFor(t, e.mgr, "retired-idp", "st"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := bodyJSON(t, rec); body["code"] != "unknown_provider" {
		t.Errorf("code = %v, want unknown_provider", body["code"])
	}
	if cookieNamed(rec, e.mgr.SessionCookieName()) != nil {
		t.Error("an unknown provider must not establish a session")
	}
}

// TestCallbackWithoutTransactionStillAudits asserts the no-cookie and IdP-error
// paths keep working under dispatch: both are reported and audited rather than
// panicking on a nil provider.
func TestCallbackWithoutTransactionStillAudits(t *testing.T) {
	e, _, _ := twoLoginProviders(t)

	e.sink.reset()
	rec := callbackVia(e.mgr, "/auth/callback?state=st&code=c")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no-cookie callback: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := bodyJSON(t, rec); body["code"] != "bad_tx" {
		t.Errorf("no-cookie callback: code = %v, want bad_tx", body["code"])
	}
	if got := e.sink.withAction(audit.ActionAuthLoginFailed); len(got) != 1 {
		t.Errorf("no-cookie callback audit = %+v, want one denial", got)
	}

	// An IdP-side error has no transaction either; it must be reported by the
	// addressed provider.
	e.sink.reset()
	rec = callbackVia(e.mgr, "/auth/callback/okta?error=access_denied")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("idp-error callback: status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	got := e.sink.withAction(audit.ActionAuthLoginFailed)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "provider=okta") {
		t.Errorf("idp-error callback audit = %+v, want one denial attributed to okta", got)
	}
}

// TestAddLoginRejectsAmbiguousNames asserts the manager refuses a provider set in
// which the transaction cookie could not identify one provider.
func TestAddLoginRejectsAmbiguousNames(t *testing.T) {
	e := newLoginEnv(t)

	if err := e.mgr.AddLogin(newNamedLogin(t, e.mgr, "entra", "Entra", "https://a.example.com", "c1")); err != nil {
		t.Fatalf("AddLogin: %v", err)
	}
	if err := e.mgr.AddLogin(newNamedLogin(t, e.mgr, "entra", "Entra Again", "https://b.example.com", "c2")); err == nil {
		t.Error("a duplicate provider name must be rejected")
	}
	if err := e.mgr.AddLogin(newNamedLogin(t, e.mgr, "", "", "https://c.example.com", "c3")); err == nil {
		t.Error("an unnamed provider must be rejected alongside a named one")
	}
	if err := e.mgr.AddLogin(nil); err != nil {
		t.Errorf("AddLogin(nil) = %v, want a no-op", err)
	}
	if n := len(e.mgr.logins); n != 1 {
		t.Errorf("logins = %d, want only the accepted one", n)
	}

	// The reverse order is equally ambiguous: an unnamed provider already
	// installed means a second one cannot be addressed.
	e2 := newLoginEnv(t)
	e2.mgr.SetLogin(newNamedLogin(t, e2.mgr, "", "", "https://d.example.com", "c4"))
	if err := e2.mgr.AddLogin(newNamedLogin(t, e2.mgr, "okta", "Okta", "https://e.example.com", "c5")); err == nil {
		t.Error("adding a provider alongside an unnamed one must be rejected")
	}
}

// TestSetLoginReplacesProviderSet asserts SetLogin keeps its single-provider
// contract (replace, and nil disables) now that the manager holds a list.
func TestSetLoginReplacesProviderSet(t *testing.T) {
	e, _, _ := twoLoginProviders(t)
	if !e.mgr.LoginEnabled() {
		t.Fatal("two providers should report login enabled")
	}

	only := newNamedLogin(t, e.mgr, "solo", "Solo", "https://solo.example.com", "c")
	e.mgr.SetLogin(only)
	if got := e.mgr.LoginProviders(); len(got) != 1 || got[0].Name != "solo" {
		t.Fatalf("LoginProviders after SetLogin = %+v, want only solo", got)
	}
	if e.mgr.LoginProvider("entra") != nil {
		t.Error("SetLogin must replace the previous provider set, not extend it")
	}

	e.mgr.SetLogin(nil)
	if e.mgr.LoginEnabled() {
		t.Error("SetLogin(nil) must disable interactive login")
	}
}

// TestLoginProvidersDiscovery asserts the shape the console's login page reads:
// one entry per provider, in declaration order, each with the URL that begins its
// flow and the first marked as the default.
func TestLoginProvidersDiscovery(t *testing.T) {
	e, _, _ := twoLoginProviders(t)

	got := e.mgr.LoginProviders()
	if len(got) != 2 {
		t.Fatalf("LoginProviders() = %+v, want 2", got)
	}
	if got[0].Name != "entra" || got[0].DisplayName != "Microsoft Entra ID" {
		t.Errorf("providers[0] = %+v, want the entra entry with its display name", got[0])
	}
	if got[0].LoginURL != "/auth/login?provider=entra" || !got[0].Default {
		t.Errorf("providers[0] = %+v, want the default provider's login URL", got[0])
	}
	if got[1].Name != "okta" || got[1].LoginURL != "/auth/login?provider=okta" || got[1].Default {
		t.Errorf("providers[1] = %+v, want the non-default okta entry", got[1])
	}

	// A lone unnamed provider (the single-provider config form) still advertises a
	// usable login URL and a label.
	e2 := newLoginEnv(t)
	e2.mgr.SetLogin(newTestOIDCLogin(t, e2.mgr))
	solo := e2.mgr.LoginProviders()
	if len(solo) != 1 || solo[0].LoginURL != "/auth/login" || solo[0].DisplayName != "SSO" {
		t.Errorf("single-provider discovery = %+v, want one unnamed /auth/login entry labelled SSO", solo)
	}
}

// TestRegisterMountsProviderRoutes asserts the routes are actually mounted (and
// do not conflict) so the dispatcher is reachable in a real server.
func TestRegisterMountsProviderRoutes(t *testing.T) {
	e, _, _ := twoLoginProviders(t)
	mux := http.NewServeMux()
	e.mgr.Register(mux)

	for _, target := range []string{
		"/auth/login",
		"/auth/login?provider=okta",
		"/auth/login/oidc/okta",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusFound {
			t.Errorf("GET %s through the mux: status = %d, want 302", target, rec.Code)
		}
	}
	// The per-provider callback path is mounted and reaches the dispatcher (it
	// fails on the missing transaction, which proves it was routed).
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback/okta?state=s&code=c", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("GET /auth/callback/okta: status = %d, want 400 from the dispatcher", rec.Code)
	}
}

// TestDispatchWithoutProvidersIs404 asserts the dispatcher is inert when
// interactive login is not configured, rather than panicking on an empty set.
func TestDispatchWithoutProvidersIs404(t *testing.T) {
	e := newLoginEnv(t)
	for _, h := range []http.HandlerFunc{e.mgr.OIDCBegin, e.mgr.OIDCCallback} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 when no provider is configured", rec.Code)
		}
	}
}

// TestDefaultLoginProviderIsExplicitNotPositional asserts `default: true` decides
// which provider a bare /auth/login uses, independently of declaration order —
// otherwise an operator could not list providers in the order the login page
// should show them while pointing the bare URL at a different one.
func TestDefaultLoginProviderIsExplicitNotPositional(t *testing.T) {
	e := newLoginEnv(t)
	first := newNamedLogin(t, e.mgr, "entra", "Entra", "https://entra.example.com", "console-entra")
	second := newNamedLogin(t, e.mgr, "partner", "Partner", "https://partner.example.com", "console-partner")
	second.isDefault = true
	if err := e.mgr.AddLogin(first); err != nil {
		t.Fatalf("AddLogin(entra): %v", err)
	}
	if err := e.mgr.AddLogin(second); err != nil {
		t.Fatalf("AddLogin(partner): %v", err)
	}

	if got := e.mgr.DefaultLoginProvider(); got != second {
		t.Errorf("DefaultLoginProvider() = %v, want the explicitly marked partner", got.Name())
	}

	// A bare /auth/login goes to the marked provider, not the first declared.
	rec := beginVia(e.mgr, "/auth/login")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://partner.example.com/authorize") {
		t.Errorf("bare /auth/login redirected to %q, want the partner IdP", loc)
	}
	if tx := txOf(t, e.mgr, rec); tx.Provider != "partner" {
		t.Errorf("transaction provider = %q, want partner", tx.Provider)
	}

	// Discovery reports the marked provider as the default, in declaration order.
	infos := e.mgr.LoginProviders()
	if len(infos) != 2 || infos[0].Name != "entra" || infos[1].Name != "partner" {
		t.Fatalf("LoginProviders() = %+v, want declaration order", infos)
	}
	if infos[0].Default || !infos[1].Default {
		t.Errorf("default flags = %v/%v, want only partner", infos[0].Default, infos[1].Default)
	}
}

// TestAddLoginRejectsTwoDefaults asserts the manager refuses a provider set where
// two providers claim the bare login URL, rather than silently picking one.
func TestAddLoginRejectsTwoDefaults(t *testing.T) {
	e := newLoginEnv(t)
	a := newNamedLogin(t, e.mgr, "a", "A", "https://a.example.com", "c1")
	a.isDefault = true
	b := newNamedLogin(t, e.mgr, "b", "B", "https://b.example.com", "c2")
	b.isDefault = true
	if err := e.mgr.AddLogin(a); err != nil {
		t.Fatalf("AddLogin(a): %v", err)
	}
	if err := e.mgr.AddLogin(b); err == nil {
		t.Error("a second default provider must be rejected")
	}
}

// TestNewOIDCLoginCarriesDefaultFlag asserts the constructor plumbs the flag, so
// the config value actually reaches the manager.
func TestNewOIDCLoginCarriesDefaultFlag(t *testing.T) {
	e := newLoginEnv(t)
	provider := (&oidc.ProviderConfig{
		IssuerURL: "https://idp.example.com", AuthURL: "https://idp.example.com/authorize",
		TokenURL: "https://idp.example.com/token", JWKSURL: "https://idp.example.com/jwks",
		Algorithms: []string{"RS256"},
	}).NewProvider(context.Background())
	l, err := NewOIDCLogin(e.mgr, OIDCLoginConfig{
		Name: "x", Default: true, Provider: provider,
		Verifier:    provider.Verifier(&oidc.Config{ClientID: "c"}),
		ClientID:    "c",
		RedirectURL: "https://pki.example.com/auth/callback",
		Resolve: func(*oidc.IDToken, map[string]interface{}) (*models.UserInfo, error) {
			return &models.UserInfo{Subject: "s"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOIDCLogin: %v", err)
	}
	if !l.isDefault {
		t.Error("OIDCLoginConfig.Default did not reach the provider")
	}
}
