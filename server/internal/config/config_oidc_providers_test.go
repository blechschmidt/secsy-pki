// Tests for multi-provider OIDC configuration (Task 212): the machine-Bearer
// issuers under `oidc.providers` and the console-login providers under
// `auth.oidc.providers`.
//
// Two things are load-bearing here. First, backward compatibility: thousands of
// words of existing documentation and every deployment in the field use the
// single `oidc.issuer_url` / `auth.oidc.*` form, which must keep resolving to
// exactly the behavior it had. Second, fail-closed validation: a federated
// deployment where two providers share an issuer, or where a provider accepts any
// audience, is a provider-confusion hazard, so it must be a load error rather
// than a runtime surprise.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadYAML writes cfg to a temp file and loads it, returning the config or the
// load error.
func loadYAML(t *testing.T, cfg string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(path)
}

// mustLoadYAML loads cfg and fails the test if it does not load.
func mustLoadYAML(t *testing.T, cfg string) *Config {
	t.Helper()
	c, err := loadYAML(t, cfg)
	if err != nil {
		t.Fatalf("Load: %v\n--- config ---\n%s", err, cfg)
	}
	return c
}

// baseYAML is the minimum a config needs to load, so each case below adds only
// the OIDC block under test.
const baseYAML = `
server:
  host: "127.0.0.1"
  port: 8443
  allow_insecure_http: true
database:
  driver: "sqlite"
  dsn: "test.db"
root_user:
  username: "root"
  password: "test-password"
`

// TestBearerProvidersLegacyFormIsOneProvider asserts the pre-multi-provider form
// resolves to a single provider named "default" — the shape the rest of the
// server now works from, so the legacy configuration takes the identical code
// path as an explicitly declared one.
func TestBearerProvidersLegacyFormIsOneProvider(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
oidc:
  issuer_url: "https://token.actions.githubusercontent.com"
  client_id: "secsy-pki-signing"
`)
	got := c.BearerOIDCProviders()
	if len(got) != 1 {
		t.Fatalf("BearerOIDCProviders() = %+v, want exactly one", got)
	}
	if got[0].Name != DefaultOIDCProviderName {
		t.Errorf("Name = %q, want %q", got[0].Name, DefaultOIDCProviderName)
	}
	if got[0].IssuerURL != "https://token.actions.githubusercontent.com" {
		t.Errorf("IssuerURL = %q", got[0].IssuerURL)
	}
	if aud := got[0].Audience(); len(aud) != 1 || aud[0] != "secsy-pki-signing" {
		t.Errorf("Audience() = %v, want [secsy-pki-signing]", aud)
	}
}

// TestBearerProvidersNoOIDCIsEmpty asserts a deployment with no OIDC configured
// yields no providers (and therefore a nil verifier, root basic-auth only).
func TestBearerProvidersNoOIDCIsEmpty(t *testing.T) {
	if got := mustLoadYAML(t, baseYAML).BearerOIDCProviders(); len(got) != 0 {
		t.Errorf("BearerOIDCProviders() = %+v, want none", got)
	}
}

// TestBearerProvidersFederateSeveralIssuers covers the task's motivating case: a
// forge's workload identity for automated signing alongside a corporate IdP for
// API callers, each with its own audience and its own claim -> role mapping.
func TestBearerProvidersFederateSeveralIssuers(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
oidc:
  providers:
    - name: github
      issuer_url: "https://token.actions.githubusercontent.com"
      client_id: "secsy-pki-signing"
      role_mappings:
        - { claim: "sub", value: "repo:example-org/app:environment:release", roles: ["signer"] }
    - name: entra
      issuer_url: "https://login.microsoftonline.com/tid/v2.0"
      client_id: "api://secsy-pki"
      audiences: ["api://secsy-pki-legacy"]
      groups_claim: "roles"
      role_mappings:
        - { value: "PKI.Issue", roles: ["issuer"] }
`)
	got := c.BearerOIDCProviders()
	if len(got) != 2 {
		t.Fatalf("BearerOIDCProviders() = %+v, want 2", got)
	}
	if got[0].Name != "github" || got[1].Name != "entra" {
		t.Fatalf("names = %q/%q, want declaration order github/entra", got[0].Name, got[1].Name)
	}
	if m := got[0].RoleMappings; len(m) != 1 || m[0].Claim != "sub" || m[0].Roles[0] != "signer" {
		t.Errorf("github role_mappings = %+v, want the sub -> signer mapping", m)
	}
	// client_id and audiences union, deduplicated.
	if aud := got[1].Audience(); len(aud) != 2 || aud[0] != "api://secsy-pki" || aud[1] != "api://secsy-pki-legacy" {
		t.Errorf("entra Audience() = %v, want both audiences with client_id first", aud)
	}
	if got[1].GroupsClaim != "roles" {
		t.Errorf("entra GroupsClaim = %q, want roles", got[1].GroupsClaim)
	}
}

// TestBearerProvidersLegacyUnionsWithList asserts a legacy top-level issuer is not
// dropped when a providers list is added — the migration path is additive, so
// nobody loses their existing machine issuer by federating a second one.
func TestBearerProvidersLegacyUnionsWithList(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
oidc:
  issuer_url: "https://token.actions.githubusercontent.com"
  client_id: "secsy-pki-signing"
  providers:
    - name: gitlab
      issuer_url: "https://gitlab.example.com"
      client_id: "secsy-pki"
`)
	got := c.BearerOIDCProviders()
	if len(got) != 2 {
		t.Fatalf("BearerOIDCProviders() = %+v, want the legacy issuer plus the declared one", got)
	}
	if got[0].Name != DefaultOIDCProviderName || got[1].Name != "gitlab" {
		t.Errorf("names = %q/%q, want default/gitlab", got[0].Name, got[1].Name)
	}
}

// TestBearerProviderValidation asserts the fail-closed rules. Each case is a
// configuration that would be a provider-confusion or over-trust hazard at
// runtime, and must therefore be refused at load.
func TestBearerProviderValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "unnamed provider",
			yaml: `
oidc:
  providers:
    - issuer_url: "https://idp.example.com"
      client_id: "c"
`,
			wantErr: "name is required",
		},
		{
			name: "no issuer",
			yaml: `
oidc:
  providers:
    - name: broken
      client_id: "c"
`,
			wantErr: "issuer_url is required",
		},
		{
			name: "no audience would honor any relying party's token",
			yaml: `
oidc:
  providers:
    - name: wide-open
      issuer_url: "https://idp.example.com"
`,
			wantErr: "client_id or audiences is required",
		},
		{
			name: "duplicate issuer makes routing order-dependent",
			yaml: `
oidc:
  providers:
    - name: a
      issuer_url: "https://idp.example.com"
      client_id: "c1"
    - name: b
      issuer_url: "https://idp.example.com"
      client_id: "c2"
`,
			wantErr: "already declared by",
		},
		{
			name: "duplicate issuer against the legacy form",
			yaml: `
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "c1"
  providers:
    - name: again
      issuer_url: "https://idp.example.com"
      client_id: "c2"
`,
			wantErr: "already declared by oidc.issuer_url",
		},
		{
			name: "duplicate name",
			yaml: `
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "c1"
  providers:
    - name: default
      issuer_url: "https://other.example.com"
      client_id: "c2"
`,
			wantErr: "already used by oidc.issuer_url",
		},
		{
			name: "name that cannot be a URL path segment",
			yaml: `
oidc:
  providers:
    - name: "github/actions"
      issuer_url: "https://idp.example.com"
      client_id: "c"
`,
			wantErr: "must start with a letter or digit",
		},
		{
			name: "name with whitespace",
			yaml: `
oidc:
  providers:
    - name: "git hub"
      issuer_url: "https://idp.example.com"
      client_id: "c"
`,
			wantErr: "must start with a letter or digit",
		},
		{
			name: "unknown role in a provider mapping",
			yaml: `
oidc:
  providers:
    - name: github
      issuer_url: "https://idp.example.com"
      client_id: "c"
      role_mappings:
        - { value: "team", roles: ["superuser"] }
`,
			wantErr: `unknown role "superuser"`,
		},
		{
			name: "mapping with no roles grants nothing",
			yaml: `
oidc:
  providers:
    - name: github
      issuer_url: "https://idp.example.com"
      client_id: "c"
      role_mappings:
        - { value: "team" }
`,
			wantErr: "at least one role is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, baseYAML+tc.yaml)
			if err == nil {
				t.Fatalf("Load succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestConsoleProvidersLegacyForm asserts the single-provider console form still
// resolves, including its long-standing inheritance of the top-level `oidc`
// block's issuer and client when it names neither.
func TestConsoleProvidersLegacyForm(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
oidc:
  issuer_url: "https://idp.example.com"
  client_id: "shared-client"
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    groups_claim: "groups"
    role_mappings:
      - { value: "pki-admins", roles: ["admin"] }
`)
	got := c.ConsoleOIDCProviders()
	if len(got) != 1 {
		t.Fatalf("ConsoleOIDCProviders() = %+v, want one", got)
	}
	p := got[0]
	if p.Name != DefaultOIDCProviderName || !p.Default {
		t.Errorf("provider = %+v, want the default-named default provider", p)
	}
	if p.IssuerURL != "https://idp.example.com" || p.ClientID != "shared-client" {
		t.Errorf("issuer/client = %q/%q, want them inherited from the top-level oidc block", p.IssuerURL, p.ClientID)
	}
	if p.RedirectURL != "https://pki.example.com/auth/callback" {
		t.Errorf("RedirectURL = %q", p.RedirectURL)
	}
	if len(p.RoleMappings) != 1 || p.RoleMappings[0].Value != "pki-admins" {
		t.Errorf("RoleMappings = %+v", p.RoleMappings)
	}
}

// TestConsoleProvidersInheritAndOverride asserts each provider inherits the
// shared settings it omits and overrides the ones it names — so a deployment
// writes the redirect URL and groups claim once.
func TestConsoleProvidersInheritAndOverride(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    scopes: ["openid", "profile", "email", "groups"]
    groups_claim: "groups"
    allow_zero_role: false
    role_mappings:
      - { value: "pki-admins", roles: ["admin"] }
    providers:
      - name: entra
        display_name: "Microsoft Entra ID"
        issuer_url: "https://login.microsoftonline.com/tid/v2.0"
        client_id: "console-entra"
        client_secret: "s3cret"
        role_mappings:
          - { value: "PKI-Issuers", roles: ["issuer"] }
      - name: partner
        issuer_url: "https://partner-idp.example.net"
        client_id: "console-partner"
        redirect_url: "https://pki.example.com/auth/callback/partner"
        scopes: ["openid", "email"]
        groups_claim: "entitlements"
        allow_zero_role: true
        default: true
`)
	got := c.ConsoleOIDCProviders()
	if len(got) != 2 {
		t.Fatalf("ConsoleOIDCProviders() = %+v, want 2", got)
	}
	entra, partner := got[0], got[1]

	// Inherited.
	if entra.RedirectURL != "https://pki.example.com/auth/callback" {
		t.Errorf("entra RedirectURL = %q, want the shared one", entra.RedirectURL)
	}
	if len(entra.Scopes) != 4 || entra.GroupsClaim != "groups" {
		t.Errorf("entra scopes/groups_claim = %v/%q, want the shared ones", entra.Scopes, entra.GroupsClaim)
	}
	if entra.DisplayName != "Microsoft Entra ID" {
		t.Errorf("entra DisplayName = %q", entra.DisplayName)
	}
	// Shared mappings are unioned with the provider's own.
	if len(entra.RoleMappings) != 2 {
		t.Fatalf("entra RoleMappings = %+v, want the shared mapping plus its own", entra.RoleMappings)
	}
	if entra.RoleMappings[0].Value != "pki-admins" || entra.RoleMappings[1].Value != "PKI-Issuers" {
		t.Errorf("entra RoleMappings = %+v, want shared-then-own order", entra.RoleMappings)
	}

	// Overridden.
	if partner.RedirectURL != "https://pki.example.com/auth/callback/partner" {
		t.Errorf("partner RedirectURL = %q, want its own", partner.RedirectURL)
	}
	if len(partner.Scopes) != 2 || partner.GroupsClaim != "entitlements" {
		t.Errorf("partner scopes/groups_claim = %v/%q, want its own", partner.Scopes, partner.GroupsClaim)
	}
	if partner.DisplayName != "partner" {
		t.Errorf("partner DisplayName = %q, want it to default to the name", partner.DisplayName)
	}

	// allow_zero_role is per provider, falling back to the shared setting.
	if c.Auth.OIDC.AllowZeroRoleFor(entra) {
		t.Error("entra should inherit allow_zero_role: false")
	}
	if !c.Auth.OIDC.AllowZeroRoleFor(partner) {
		t.Error("partner should override allow_zero_role to true")
	}

	// `default: true` decides which provider a bare /auth/login uses.
	if entra.Default || !partner.Default {
		t.Errorf("default flags = entra:%v partner:%v, want only partner", entra.Default, partner.Default)
	}
}

// TestConsoleProvidersDefaultsToFirst asserts that without an explicit marker the
// first declared provider is the target of a bare /auth/login.
func TestConsoleProvidersDefaultsToFirst(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: first,  issuer_url: "https://a.example.com", client_id: "c1" }
      - { name: second, issuer_url: "https://b.example.com", client_id: "c2" }
`)
	got := c.ConsoleOIDCProviders()
	if len(got) != 2 {
		t.Fatalf("ConsoleOIDCProviders() = %+v, want 2", got)
	}
	if !got[0].Default || got[1].Default {
		t.Errorf("default flags = %v/%v, want the first provider", got[0].Default, got[1].Default)
	}
	// No phantom "default" entry is synthesized when the legacy fields are unset.
	for _, p := range got {
		if p.Name == DefaultOIDCProviderName {
			t.Errorf("an explicit providers list must not grow a synthesized %q entry", DefaultOIDCProviderName)
		}
	}
}

// TestConsoleProviderValidation asserts a half-configured console provider is
// refused at load, so SSO cannot appear to be configured while being unusable.
func TestConsoleProviderValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "no provider at all",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
`,
			wantErr: "no issuer_url is set",
		},
		{
			name: "missing redirect url",
			yaml: `
auth:
  oidc:
    enabled: true
    providers:
      - { name: entra, issuer_url: "https://a.example.com", client_id: "c1" }
`,
			wantErr: "redirect_url is required",
		},
		{
			name: "missing client id",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: entra, issuer_url: "https://a.example.com" }
`,
			wantErr: "client_id is required",
		},
		{
			name: "unnamed provider cannot be addressed",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { issuer_url: "https://a.example.com", client_id: "c1" }
`,
			wantErr: "name is required",
		},
		{
			name: "two providers on one issuer",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: a, issuer_url: "https://idp.example.com", client_id: "c1" }
      - { name: b, issuer_url: "https://idp.example.com", client_id: "c2" }
`,
			wantErr: "cannot back two console providers",
		},
		{
			name: "duplicate name against the legacy entry",
			yaml: `
auth:
  oidc:
    enabled: true
    issuer_url: "https://legacy.example.com"
    client_id: "c0"
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: default, issuer_url: "https://idp.example.com", client_id: "c1" }
`,
			wantErr: "declared twice",
		},
		{
			name: "console provider name that cannot be addressed",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: "entra id", issuer_url: "https://a.example.com", client_id: "c1" }
`,
			wantErr: "must start with a letter or digit",
		},
		{
			name: "two defaults",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - { name: a, issuer_url: "https://a.example.com", client_id: "c1", default: true }
      - { name: b, issuer_url: "https://b.example.com", client_id: "c2", default: true }
`,
			wantErr: "at most one may be the target",
		},
		{
			name: "unknown role in a provider mapping",
			yaml: `
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - name: a
        issuer_url: "https://a.example.com"
        client_id: "c1"
        role_mappings:
          - { value: "g", roles: ["root"] }
`,
			wantErr: `unknown role "root"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, baseYAML+tc.yaml)
			if err == nil {
				t.Fatalf("Load succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestProviderNamesAcceptSimpleTokens asserts the charset rule is not
// over-tight: the names deployments actually write — dots, dashes, underscores,
// digits — must load.
func TestProviderNamesAcceptSimpleTokens(t *testing.T) {
	c := mustLoadYAML(t, baseYAML+`
oidc:
  providers:
    - { name: "github-actions", issuer_url: "https://a.example.com", client_id: "c1" }
    - { name: "entra.id",       issuer_url: "https://b.example.com", client_id: "c2" }
    - { name: "idp_2",          issuer_url: "https://c.example.com", client_id: "c3" }
`)
	if got := c.BearerOIDCProviders(); len(got) != 3 {
		t.Fatalf("BearerOIDCProviders() = %+v, want all three", got)
	}
}

// TestConsoleProviderRoleMappingsValidatedWhenDisabled asserts a typo in a role
// name is reported even with login switched off, so enabling SSO later does not
// silently drop a mapping an operator believed was in force.
func TestConsoleProviderRoleMappingsValidatedWhenDisabled(t *testing.T) {
	_, err := loadYAML(t, baseYAML+`
auth:
  oidc:
    enabled: false
    providers:
      - name: a
        issuer_url: "https://a.example.com"
        client_id: "c1"
        role_mappings:
          - { value: "g", roles: ["adminn"] }
`)
	if err == nil || !strings.Contains(err.Error(), `unknown role "adminn"`) {
		t.Fatalf("Load error = %v, want the misspelled role reported", err)
	}
}

// TestProviderClientSecretFromFile asserts each console provider's confidential-
// client secret participates in the `*_file` credential convention, so a
// federated deployment keeps every client secret out of config.yaml — not just
// the first one's.
func TestProviderClientSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "entra-client-secret")
	if err := os.WriteFile(secretPath, []byte("entra-s3cret\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	otherPath := filepath.Join(dir, "okta-client-secret")
	if err := os.WriteFile(otherPath, []byte("okta-s3cret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	c := mustLoadYAML(t, baseYAML+`
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - name: entra
        issuer_url: "https://a.example.com"
        client_id: "c1"
        client_secret_file: "`+secretPath+`"
      - name: okta
        issuer_url: "https://b.example.com"
        client_id: "c2"
        client_secret_file: "`+otherPath+`"
`)
	if got := c.Auth.OIDC.Providers[0].ClientSecret; got != "entra-s3cret" {
		t.Errorf("providers[0].ClientSecret = %q, want the file contents minus the trailing newline", got)
	}
	if got := c.Auth.OIDC.Providers[1].ClientSecret; got != "okta-s3cret" {
		t.Errorf("providers[1].ClientSecret = %q", got)
	}

	// And they are masked in a redacted dump.
	red := c.Redacted()
	for i, want := range []string{"entra", "okta"} {
		if got := red.Auth.OIDC.Providers[i].ClientSecret; got != redactedSecret {
			t.Errorf("redacted %s client secret = %q, want %q", want, got, redactedSecret)
		}
	}
	if c.Auth.OIDC.Providers[0].ClientSecret != "entra-s3cret" {
		t.Error("Redacted mutated the original provider list")
	}
}

// TestProviderClientSecretFileConflict asserts the per-provider binding inherits
// the convention's refusal to guess when a provider names both forms.
func TestProviderClientSecretFileConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	_, err := loadYAML(t, baseYAML+`
auth:
  oidc:
    enabled: true
    redirect_url: "https://pki.example.com/auth/callback"
    providers:
      - name: entra
        issuer_url: "https://a.example.com"
        client_id: "c1"
        client_secret: "inline"
        client_secret_file: "`+path+`"
`)
	if err == nil || !strings.Contains(err.Error(), "auth.oidc.providers[0].client_secret") {
		t.Fatalf("Load error = %v, want the conflicting provider keys named", err)
	}
}
