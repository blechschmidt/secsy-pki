//go:build sqlite

// End-to-end verification that one deployment can federate several OIDC
// providers (Task 212), driven through the real handler stack behind an httptest
// server: the auth middleware, the session/CSRF plumbing, the /auth/* endpoints,
// and the public auth-discovery document.
//
// Two stub identity providers stand in for the pairing the feature exists for: a
// CI forge's workload-identity issuer that may only sign, and a corporate IdP
// whose group claim grants console roles. Both axes are exercised against both
// providers:
//
//	machine  — Authorization: Bearer <jwt> routed by `iss` to one verifier, then
//	           authorized by THAT provider's claim -> role mapping
//	console  — the full Authorization-Code + PKCE handshake, per provider, with
//	           dispatch on the provider sealed into the login transaction cookie
//
// The property under test is isolation: a token from one issuer must not be able
// to borrow the roles mapped for another, however identical its claims. It uses a
// software key provider (no HSM), so it runs under `go test -tags sqlite ./...`.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/coreos/go-oidc/v3/oidc"
)

// The two federated providers, their audiences, and the group each maps to a
// role. `sharedSubject` is asserted by BOTH IdPs: it is how the test shows that
// authorization follows the issuer, not the subject string.
const (
	forgeProvider = "forge"
	forgeAudience = "secsy-pki-signing"
	forgeGroup    = "pipelines"

	corpProvider = "corp"
	corpAudience = "api://secsy-pki"
	corpGroup    = "pki-auditors"

	sharedSubject = "repo:example-org/app:environment:release"
)

// multiOIDCEnv is the wired-up app server plus its two stub IdPs.
type multiOIDCEnv struct {
	srv   *httptest.Server
	forge *stubIDP
	corp  *stubIDP
}

// setupMultiOIDC mirrors the production wiring in cmd/server (setupOperatorAuth
// and the SetBearerClaimResolver installed by main) for two providers: one claim
// mapper per provider, used for both the console resolver and the Bearer hook.
func setupMultiOIDC(t *testing.T) *multiOIDCEnv {
	t.Helper()

	forge := newStubIDP(t, forgeAudience, sharedSubject)
	forge.groups = []string{forgeGroup}
	corp := newStubIDP(t, corpAudience, "corp-operator-subject")
	corp.groups = []string{corpGroup}

	db, err := database.New("sqlite", t.TempDir()+"/multioidc.db")
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

	// --- machine axis: one verifier over both issuers ---
	bearer, provErrs := auth.NewMultiProvider(context.Background(), []auth.ProviderSpec{
		{Name: forgeProvider, IssuerURL: forge.srv.URL, Audiences: []string{forgeAudience}},
		{Name: corpProvider, IssuerURL: corp.srv.URL, Audiences: []string{corpAudience}},
	})
	if len(provErrs) != 0 {
		t.Fatalf("NewMultiProvider: %v", provErrs)
	}

	api := handlers.NewAPI(db, provider, bearer.Primary(), hsm.Config{}, false, "")
	authMw := middleware.NewAuthMiddleware(bearer, "root", "root-pass")

	// One mapper per provider. The forge's pipelines map to `signer`; the
	// corporate IdP's operators map to `auditor`. Neither group is known to the
	// other provider, which is the isolation being asserted.
	mappers := map[string]*authn.ClaimMapper{
		forgeProvider: authn.NewClaimMapper("groups", []authn.ClaimMapping{
			{Value: forgeGroup, Roles: []rbac.Role{rbac.RoleSigner}},
		}),
		corpProvider: authn.NewClaimMapper("groups", []authn.ClaimMapping{
			{Value: corpGroup, Roles: []rbac.Role{rbac.RoleAuditor}},
		}),
	}
	authMw.SetBearerClaimResolver(func(info *models.UserInfo, claims *auth.Claims) {
		mapper := mappers[claims.Provider]
		if mapper == nil {
			return
		}
		platform, _ := mapper.Resolve(claims.Raw)
		for _, r := range platform {
			info.Roles = append(info.Roles, string(r))
		}
		info.Groups = mapper.Groups(claims.Raw)
	})

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	// --- console axis: two interactive login providers ---
	sessions := authn.NewSessionStore(time.Hour, 5*time.Minute)
	mgr := authn.NewManager(authn.ManagerOptions{
		Sessions:      sessions,
		SessionCookie: authn.DefaultSessionCookie,
		Secure:        false, // httptest is plain HTTP
		Audit:         db,
		RequestID:     middleware.RequestID,
	})

	type consoleProvider struct {
		name, display string
		idp           *stubIDP
		audience      string
		mapper        *authn.ClaimMapper
	}
	consoleProviders := []consoleProvider{
		{forgeProvider, "Forge IdP", forge, forgeAudience, mappers[forgeProvider]},
		{corpProvider, "Corporate IdP", corp, corpAudience, mappers[corpProvider]},
	}
	for _, cp := range consoleProviders {
		oidcProvider, err := oidc.NewProvider(context.Background(), cp.idp.srv.URL)
		if err != nil {
			t.Fatalf("oidc discovery (%s): %v", cp.name, err)
		}
		mapper := cp.mapper
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
			Name:        cp.name,
			DisplayName: cp.display,
			Provider:    oidcProvider,
			Verifier:    oidcProvider.Verifier(&oidc.Config{ClientID: cp.audience}),
			ClientID:    cp.audience,
			// Both providers share one registered callback: dispatch comes from the
			// signed login transaction cookie, not the URL.
			RedirectURL: "http://app.example/auth/callback",
			Resolve:     resolve,
		})
		if err != nil {
			t.Fatalf("oidc login (%s): %v", cp.name, err)
		}
		if err := mgr.AddLogin(login); err != nil {
			t.Fatalf("AddLogin(%s): %v", cp.name, err)
		}
	}
	mgr.Register(mux)
	authMw.SetSessions(sessions, authn.DefaultSessionCookie)
	api.SetAuthInfo(handlers.AuthInfo{
		OIDCLogin:       true,
		LoginProviders:  mgr.LoginProviders(),
		BearerProviders: bearer.Providers(),
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &multiOIDCEnv{srv: srv, forge: forge, corp: corp}
}

// get issues a GET with the given Authorization header and returns the status and
// decoded JSON body.
func (e *multiOIDCEnv) get(t *testing.T, path, authorization string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// TestMultiOIDCAuthConfigAdvertisesBothAxes asserts the public discovery document
// describes both federated axes, so the console can render one button per IdP and
// a workload can find its issuer/audience pairing.
func TestMultiOIDCAuthConfigAdvertisesBothAxes(t *testing.T) {
	env := setupMultiOIDC(t)

	status, body := env.get(t, "/api/auth/config", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	logins, _ := body["oidc_providers"].([]interface{})
	if len(logins) != 2 {
		t.Fatalf("oidc_providers = %#v, want both console providers", body["oidc_providers"])
	}
	first, _ := logins[0].(map[string]interface{})
	if first["name"] != forgeProvider || first["login_url"] != "/auth/login?provider="+forgeProvider {
		t.Errorf("oidc_providers[0] = %#v", first)
	}
	if first["display_name"] != "Forge IdP" || first["default"] != true {
		t.Errorf("oidc_providers[0] = %#v, want the labelled default provider", first)
	}

	bearers, _ := body["bearer_providers"].([]interface{})
	if len(bearers) != 2 {
		t.Fatalf("bearer_providers = %#v, want both machine issuers", body["bearer_providers"])
	}
	names := map[string]bool{}
	for _, raw := range bearers {
		entry, _ := raw.(map[string]interface{})
		names[entry["name"].(string)] = true
		if entry["issuer_url"] == "" {
			t.Errorf("bearer provider %#v carries no issuer", entry)
		}
	}
	if !names[forgeProvider] || !names[corpProvider] {
		t.Errorf("bearer_providers names = %v, want both", names)
	}
}

// TestMultiOIDCBearerRoutesAndAuthorizesPerProvider is the machine-axis test: a
// real signed token from each IdP reaches the right verifier through the live
// HTTP stack and is authorized by that provider's mapping — and a token from the
// other issuer asserting the SAME subject gets nothing.
func TestMultiOIDCBearerRoutesAndAuthorizesPerProvider(t *testing.T) {
	env := setupMultiOIDC(t)

	// The forge's pipeline token -> signer.
	status, me := env.get(t, "/api/me", "Bearer "+env.forge.mintIDToken(t, sharedSubject, forgeAudience, []string{forgeGroup}))
	if status != http.StatusOK {
		t.Fatalf("/api/me with a forge token: status = %d, want 200 (%v)", status, me)
	}
	if me["auth_provider"] != forgeProvider {
		t.Errorf("auth_provider = %v, want %q", me["auth_provider"], forgeProvider)
	}
	if roles := rolesOf(me); len(roles) != 1 || roles[0] != "signer" {
		t.Errorf("roles = %v, want [signer] from the forge provider's mapping", roles)
	}

	// The corporate IdP's operator token -> auditor, and it can read the audit log.
	corpToken := "Bearer " + env.corp.mintIDToken(t, "corp-operator-subject", corpAudience, []string{corpGroup})
	status, me = env.get(t, "/api/me", corpToken)
	if status != http.StatusOK {
		t.Fatalf("/api/me with a corp token: status = %d, want 200 (%v)", status, me)
	}
	if me["auth_provider"] != corpProvider {
		t.Errorf("auth_provider = %v, want %q", me["auth_provider"], corpProvider)
	}
	if roles := rolesOf(me); len(roles) != 1 || roles[0] != "auditor" {
		t.Errorf("roles = %v, want [auditor] from the corp provider's mapping", roles)
	}
	if status, body := env.get(t, "/api/audit-log", corpToken); status != http.StatusOK {
		t.Errorf("GET /api/audit-log as the mapped auditor: status = %d, want 200 (%v)", status, body)
	}

	// --- isolation ---
	// A token from the corporate IdP that asserts the forge pipeline's exact
	// subject AND its group claim authenticates (it is a valid token from a
	// trusted issuer) but resolves to NO roles: the forge's mapping belongs to the
	// forge provider, not to the strings in the token.
	impersonating := "Bearer " + env.corp.mintIDToken(t, sharedSubject, corpAudience, []string{forgeGroup})
	status, me = env.get(t, "/api/me", impersonating)
	if status != http.StatusOK {
		t.Fatalf("/api/me with the impersonating token: status = %d, want 200 (%v)", status, me)
	}
	if roles := rolesOf(me); len(roles) != 0 {
		t.Errorf("a corp token asserting the forge subject resolved to %v, want no roles", roles)
	}
	// ...and is therefore refused by the authorization gate.
	if status, _ := env.get(t, "/api/audit-log", impersonating); status != http.StatusForbidden {
		t.Errorf("GET /api/audit-log with the impersonating token: status = %d, want 403", status)
	}

	// A token minted for the other provider's audience does not authenticate at
	// all: the audience binding is what stops a token issued for a different
	// relying party of the same IdP.
	if status, _ := env.get(t, "/api/me",
		"Bearer "+env.corp.mintIDToken(t, "corp-operator-subject", forgeAudience, []string{corpGroup})); status != http.StatusUnauthorized {
		t.Errorf("a cross-audience token got status %d, want 401", status)
	}
}

// TestMultiOIDCConsoleLoginPerProvider is the console-axis test: the full
// Authorization-Code + PKCE handshake completes through each provider, over ONE
// shared callback URL, and the session carries that provider's mapped role.
func TestMultiOIDCConsoleLoginPerProvider(t *testing.T) {
	env := setupMultiOIDC(t)

	for _, tc := range []struct {
		provider string
		idp      *stubIDP
		wantRole string
	}{
		{corpProvider, env.corp, "auditor"},
		{forgeProvider, env.forge, "signer"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			jar, _ := cookiejar.New(nil)
			client := &http.Client{
				Jar:           jar,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}

			// 1. Begin: the addressed provider's authorize endpoint, with PKCE.
			resp, err := client.Get(env.srv.URL + "/auth/login?provider=" + tc.provider)
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
			if !strings.HasPrefix(authorizeURL.String(), tc.idp.srv.URL) {
				t.Fatalf("redirected to %q, want the %s IdP at %s", authorizeURL, tc.provider, tc.idp.srv.URL)
			}
			q := authorizeURL.Query()
			if q.Get("client_id") != tc.idp.clientID {
				t.Errorf("client_id = %q, want this provider's %q", q.Get("client_id"), tc.idp.clientID)
			}
			if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
				t.Fatalf("authorize URL missing state/nonce/PKCE: %s", authorizeURL)
			}
			tc.idp.nonce = q.Get("nonce")

			// 2. Callback on the SHARED path: dispatch comes from the transaction
			// cookie, so no provider hint is present in the URL at all.
			resp, err = client.Get(env.srv.URL + "/auth/callback?code=stub-code&state=" +
				url.QueryEscape(q.Get("state")))
			if err != nil {
				t.Fatalf("GET /auth/callback: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("callback status = %d, want 302 to the console", resp.StatusCode)
			}

			// 3. The session reports this provider and its mapped role.
			resp, err = client.Get(env.srv.URL + "/auth/session")
			if err != nil {
				t.Fatalf("GET /auth/session: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("session status = %d, want 200", resp.StatusCode)
			}
			var info map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
				t.Fatalf("decode session: %v", err)
			}
			if info["auth_provider"] != tc.provider {
				t.Errorf("session auth_provider = %v, want %q", info["auth_provider"], tc.provider)
			}
			user, _ := info["user"].(map[string]interface{})
			if roles := rolesOf(user); len(roles) != 1 || roles[0] != tc.wantRole {
				t.Errorf("session roles = %v, want [%s] from this provider's mapping", roles, tc.wantRole)
			}
		})
	}
}

// TestMultiOIDCConsoleLoginRejectsForeignCallback asserts a transaction begun at
// one provider cannot be completed at another's callback path — otherwise the
// authorization code would be exchanged with the wrong client credentials and the
// claims mapped through the wrong role mapping.
func TestMultiOIDCConsoleLoginRejectsForeignCallback(t *testing.T) {
	env := setupMultiOIDC(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get(env.srv.URL + "/auth/login?provider=" + corpProvider)
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state := authorizeURL.Query().Get("state")
	env.corp.nonce = authorizeURL.Query().Get("nonce")

	// Hand the corporate provider's transaction to the forge provider's callback.
	resp, err = client.Get(env.srv.URL + "/auth/callback/" + forgeProvider +
		"?code=stub-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("GET foreign callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign callback status = %d, want 400", resp.StatusCode)
	}
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != "provider_mismatch" {
		t.Errorf("code = %v, want provider_mismatch", body["code"])
	}

	// No session was established.
	resp2, err := client.Get(env.srv.URL + "/auth/session")
	if err != nil {
		t.Fatalf("GET /auth/session: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("session status = %d, want 401 (no session was created)", resp2.StatusCode)
	}
}

// TestMultiOIDCUnknownProviderRejected asserts an unknown provider name is refused
// rather than silently falling back to the default, so a stale console link cannot
// send an operator to a different IdP than the one it named.
func TestMultiOIDCUnknownProviderRejected(t *testing.T) {
	env := setupMultiOIDC(t)

	resp, err := http.Get(env.srv.URL + "/auth/login?provider=not-configured")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != "unknown_provider" {
		t.Errorf("code = %v, want unknown_provider", body["code"])
	}
}

// rolesOf extracts the string roles from a decoded UserInfo JSON object.
func rolesOf(user map[string]interface{}) []string {
	raw, _ := user["roles"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
