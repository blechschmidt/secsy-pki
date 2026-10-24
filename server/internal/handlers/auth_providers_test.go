package handlers

// Tests for the public authentication-discovery document's multi-provider fields
// (Task 212). /api/auth/config is unauthenticated by design — a browser has to
// read it before it can log in — so what it may and may not disclose matters:
// an issuer and the audience a client should request are public facts a caller
// needs, while a client secret is not and never appears here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
)

// authConfigOf drives GET /api/auth/config against an API carrying info.
func authConfigOf(t *testing.T, info AuthInfo) map[string]interface{} {
	t.Helper()
	api := &API{}
	api.SetAuthInfo(info)
	rec := httptest.NewRecorder()
	api.AuthConfig(rec, httptest.NewRequest(http.MethodGet, "/api/auth/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body: %v; body=%s", err, rec.Body.String())
	}
	return out
}

// TestAuthConfigAdvertisesLoginProviders asserts the console can discover one
// sign-in entry per identity provider, with the URL that begins each flow — the
// data the login page needs to stop hard-coding a single "SSO" button.
func TestAuthConfigAdvertisesLoginProviders(t *testing.T) {
	body := authConfigOf(t, AuthInfo{
		OIDCLogin: true,
		LoginProviders: []authn.LoginProviderInfo{
			{Name: "entra", DisplayName: "Microsoft Entra ID", LoginURL: "/auth/login?provider=entra", Default: true},
			{Name: "okta", DisplayName: "Okta", LoginURL: "/auth/login?provider=okta"},
		},
	})

	providers, ok := body["oidc_providers"].([]interface{})
	if !ok || len(providers) != 2 {
		t.Fatalf("oidc_providers = %#v, want two entries", body["oidc_providers"])
	}
	first, _ := providers[0].(map[string]interface{})
	if first["name"] != "entra" || first["display_name"] != "Microsoft Entra ID" {
		t.Errorf("oidc_providers[0] = %#v", first)
	}
	if first["login_url"] != "/auth/login?provider=entra" || first["default"] != true {
		t.Errorf("oidc_providers[0] = %#v, want the default provider's login URL", first)
	}
	second, _ := providers[1].(map[string]interface{})
	if second["name"] != "okta" {
		t.Errorf("oidc_providers[1] = %#v", second)
	}
	if _, present := second["default"]; present {
		t.Errorf("a non-default provider must not carry default:true, got %#v", second)
	}
}

// TestAuthConfigAdvertisesBearerProviders asserts the machine-token issuers are
// published so a workload can discover which issuer and audience to request a
// token for, instead of that pairing travelling out of band.
func TestAuthConfigAdvertisesBearerProviders(t *testing.T) {
	body := authConfigOf(t, AuthInfo{
		BearerProviders: []auth.ProviderInfo{
			{Name: "github", IssuerURL: "https://token.actions.githubusercontent.com", Audiences: []string{"secsy-pki-signing"}},
			{Name: "entra", IssuerURL: "https://login.microsoftonline.com/tid/v2.0", Audiences: []string{"api://secsy-pki"}},
		},
	})

	providers, ok := body["bearer_providers"].([]interface{})
	if !ok || len(providers) != 2 {
		t.Fatalf("bearer_providers = %#v, want two entries", body["bearer_providers"])
	}
	first, _ := providers[0].(map[string]interface{})
	if first["name"] != "github" || first["issuer_url"] != "https://token.actions.githubusercontent.com" {
		t.Errorf("bearer_providers[0] = %#v", first)
	}
	auds, _ := first["audiences"].([]interface{})
	if len(auds) != 1 || auds[0] != "secsy-pki-signing" {
		t.Errorf("bearer_providers[0].audiences = %#v", first["audiences"])
	}
}

// TestAuthConfigOmitsProviderListsWhenUnconfigured asserts the document keeps its
// previous shape for a deployment that configures no providers, so an existing
// client is not handed empty arrays it never saw before.
func TestAuthConfigOmitsProviderListsWhenUnconfigured(t *testing.T) {
	body := authConfigOf(t, AuthInfo{PasswordLogin: true})

	for _, key := range []string{"oidc_providers", "bearer_providers"} {
		if _, present := body[key]; present {
			t.Errorf("%s is present (%#v) but nothing is configured", key, body[key])
		}
	}
	if body["oidc_enabled"] != false || body["password_login"] != true {
		t.Errorf("the pre-existing fields changed shape: %#v", body)
	}
}

// TestAuthConfigDisclosesOnlyKnownKeys is the disclosure guard on an endpoint
// that is deliberately unauthenticated (a browser must read it before it can log
// in). Pinning the key sets — top level and per provider — means a field added to
// the discovery document later has to be added here too, which is the moment to
// ask whether an anonymous caller should see it. A confidential-client secret, in
// particular, must never appear.
func TestAuthConfigDisclosesOnlyKnownKeys(t *testing.T) {
	api := &API{}
	api.SetAuthInfo(AuthInfo{
		OIDCLogin:     true,
		PasswordLogin: true,
		LoginProviders: []authn.LoginProviderInfo{
			{Name: "entra", DisplayName: "Microsoft Entra ID", LoginURL: "/auth/login?provider=entra", Default: true},
		},
		BearerProviders: []auth.ProviderInfo{
			{Name: "github", IssuerURL: "https://token.actions.githubusercontent.com", Audiences: []string{"a"}},
		},
	})
	rec := httptest.NewRecorder()
	api.AuthConfig(rec, httptest.NewRequest(http.MethodGet, "/api/auth/config", nil))

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	allowed := map[string]bool{
		"oidc_enabled": true, "oidc_login_enabled": true, "password_login": true,
		"ldap_login": true, "webauthn_enabled": true, "issuer_url": true, "client_id": true,
		"oidc_providers": true, "bearer_providers": true,
	}
	for key := range body {
		if !allowed[key] {
			t.Errorf("unexpected key %q in the public auth-discovery document", key)
		}
	}

	assertKeys := func(what string, raw interface{}, allowed map[string]bool) {
		entries, ok := raw.([]interface{})
		if !ok || len(entries) == 0 {
			t.Fatalf("%s = %#v, want a non-empty list", what, raw)
		}
		entry, _ := entries[0].(map[string]interface{})
		for key := range entry {
			if !allowed[key] {
				t.Errorf("unexpected key %q in %s", key, what)
			}
		}
	}
	assertKeys("oidc_providers", body["oidc_providers"],
		map[string]bool{"name": true, "display_name": true, "login_url": true, "default": true})
	assertKeys("bearer_providers", body["bearer_providers"],
		map[string]bool{"name": true, "issuer_url": true, "audiences": true})

	if strings.Contains(strings.ToLower(rec.Body.String()), "client_secret") {
		t.Errorf("the public auth-discovery document mentions a client secret: %s", rec.Body.String())
	}
}
