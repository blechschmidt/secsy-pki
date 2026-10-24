package main

// Tests for the per-provider authorization of machine (Bearer) OIDC callers
// (Task 212).
//
// Federating several machine issuers makes the subject string ambiguous across
// providers: GitHub Actions asserts `sub: repo:org/app:environment:release`,
// another forge can assert that exact string, and nothing about the string itself
// says which issuer vouched for it. The defence is that a claim -> role mapping
// is evaluated only for the provider that verified the token. These tests pin
// that down — a mapping declared for one issuer must grant nothing to a token
// from another, however identical its claims.

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// stubGroups is a groupLookup that reports fixed internal group memberships.
type stubGroups map[string][]string

func (s stubGroups) GetUserGroups(subject string) ([]string, error) { return s[subject], nil }

// federatedProviders is the task's motivating configuration: a CI forge whose
// workflow identity may only sign artifacts, and a corporate IdP whose group
// claim grants console roles.
func federatedProviders() []config.OIDCProviderConfig {
	return []config.OIDCProviderConfig{
		{
			Name:      "github",
			IssuerURL: "https://token.actions.githubusercontent.com",
			ClientID:  "secsy-pki-signing",
			RoleMappings: []config.ClaimMappingConfig{
				{Claim: "sub", Value: "repo:example-org/app:environment:release", Roles: []string{"signer"}},
			},
		},
		{
			Name:        "entra",
			IssuerURL:   "https://login.microsoftonline.com/tid/v2.0",
			ClientID:    "api://secsy-pki",
			GroupsClaim: "groups",
			RoleMappings: []config.ClaimMappingConfig{
				{Value: "PKI-Admins", Roles: []string{"admin"}},
				{Value: "Acme-Issuers", Tenant: "acme", Roles: []string{"issuer"}},
			},
		},
	}
}

// resolverFor builds the middleware hook over the given providers with empty
// central rbac assignments, so only the per-provider mappings can grant anything.
func resolverFor(t *testing.T, providers []config.OIDCProviderConfig, groups groupLookup) func(*models.UserInfo, *auth.Claims) {
	t.Helper()
	ta := rbac.NewTenantAssignments(rbac.NewAssignments(nil, nil), nil)
	return bearerClaimResolver(mustBearerMappers(t, providers), ta, groups)
}

// mustBearerMappers builds the per-provider mappers, failing the test when a
// mapping is rejected (a malformed CEL expression, Task 214).
func mustBearerMappers(t *testing.T, providers []config.OIDCProviderConfig) map[string]*authn.ClaimMapper {
	t.Helper()
	mappers, err := buildBearerClaimMappers(&config.Config{}, providers)
	if err != nil {
		t.Fatalf("buildBearerClaimMappers: %v", err)
	}
	return mappers
}

// TestBearerClaimResolverAppliesVerifyingProvidersMapping asserts each provider's
// own mapping is applied to tokens it verified.
func TestBearerClaimResolverAppliesVerifyingProvidersMapping(t *testing.T) {
	resolve := resolverFor(t, federatedProviders(), nil)

	// The CI workflow identity resolves to exactly `signer`.
	ci := &models.UserInfo{Subject: "repo:example-org/app:environment:release"}
	resolve(ci, &auth.Claims{
		Provider: "github",
		Subject:  ci.Subject,
		Raw:      map[string]interface{}{"sub": ci.Subject},
	})
	if len(ci.Roles) != 1 || ci.Roles[0] != "signer" {
		t.Errorf("CI principal roles = %v, want [signer]", ci.Roles)
	}
	if len(ci.TenantRoles) != 0 {
		t.Errorf("CI principal tenant roles = %v, want none", ci.TenantRoles)
	}

	// The corporate operator resolves to admin platform-wide plus issuer in one
	// tenant, from its group claim.
	op := &models.UserInfo{Subject: "00000000-aaaa", Email: "op@example.com", EmailVerified: true}
	resolve(op, &auth.Claims{
		Provider: "entra",
		Subject:  op.Subject,
		Raw: map[string]interface{}{
			"sub":    op.Subject,
			"groups": []interface{}{"PKI-Admins", "Acme-Issuers", "Everyone"},
		},
	})
	if len(op.Roles) != 1 || op.Roles[0] != "admin" {
		t.Errorf("operator roles = %v, want [admin]", op.Roles)
	}
	if got := op.TenantRoles["acme"]; len(got) != 1 || got[0] != "issuer" {
		t.Errorf("operator tenant roles = %v, want acme:[issuer]", op.TenantRoles)
	}
	// Group identities are carried onto the principal: resource-scoped grants may
	// name an IdP group, and that membership is only knowable at authentication.
	if len(op.Groups) != 3 {
		t.Errorf("operator groups = %v, want all three asserted groups", op.Groups)
	}
}

// TestBearerClaimResolverIsolatesProviders is the provider-confusion test. A
// token from the corporate IdP that asserts the CI workflow's exact subject must
// get nothing, and a CI token asserting the corporate admin group must get
// nothing — the mapping belongs to the issuer, not to the string.
func TestBearerClaimResolverIsolatesProviders(t *testing.T) {
	resolve := resolverFor(t, federatedProviders(), nil)

	impersonatingSub := &models.UserInfo{Subject: "repo:example-org/app:environment:release"}
	resolve(impersonatingSub, &auth.Claims{
		Provider: "entra",
		Subject:  impersonatingSub.Subject,
		Raw:      map[string]interface{}{"sub": impersonatingSub.Subject},
	})
	if len(impersonatingSub.Roles) != 0 || len(impersonatingSub.TenantRoles) != 0 {
		t.Errorf("a token from entra asserting the github workflow subject got %v / %v, want nothing",
			impersonatingSub.Roles, impersonatingSub.TenantRoles)
	}

	impersonatingGroup := &models.UserInfo{Subject: "repo:someone-else/evil:environment:release"}
	resolve(impersonatingGroup, &auth.Claims{
		Provider: "github",
		Subject:  impersonatingGroup.Subject,
		Raw: map[string]interface{}{
			"sub":    impersonatingGroup.Subject,
			"groups": []interface{}{"PKI-Admins"},
		},
	})
	if len(impersonatingGroup.Roles) != 0 || len(impersonatingGroup.TenantRoles) != 0 {
		t.Errorf("a github token asserting the corporate admin group got %v / %v, want nothing",
			impersonatingGroup.Roles, impersonatingGroup.TenantRoles)
	}
}

// TestBearerClaimResolverUnionsCentralAssignments asserts the per-provider
// mapping composes with (rather than replaces) the central rbac subject/email/
// group assignments, including groups asserted by the token and groups recorded
// internally.
func TestBearerClaimResolverUnionsCentralAssignments(t *testing.T) {
	assignments := rbac.NewAssignments(
		map[string][]rbac.Role{"op@example.com": {rbac.RoleAuditor}},
		map[string][]rbac.Role{"idp-group": {rbac.RoleIssuer}, "internal-group": {rbac.RoleSigner}},
	)
	ta := rbac.NewTenantAssignments(assignments, nil)
	providers := []config.OIDCProviderConfig{{
		Name:      "entra",
		IssuerURL: "https://idp.example.com",
		ClientID:  "api://secsy-pki",
		RoleMappings: []config.ClaimMappingConfig{
			{Value: "PKI-Admins", Roles: []string{"admin"}},
		},
	}}
	resolve := bearerClaimResolver(
		mustBearerMappers(t, providers), ta,
		stubGroups{"sub-1": {"internal-group"}},
	)

	info := &models.UserInfo{Subject: "sub-1", Email: "op@example.com", EmailVerified: true}
	resolve(info, &auth.Claims{
		Provider: "entra",
		Subject:  info.Subject,
		Email:    info.Email,
		Raw: map[string]interface{}{
			"sub":    info.Subject,
			"email":  info.Email,
			"groups": []interface{}{"idp-group", "PKI-Admins"},
		},
	})

	want := map[string]bool{"auditor": true, "issuer": true, "signer": true, "admin": true}
	if len(info.Roles) != len(want) {
		t.Fatalf("roles = %v, want the union %v", info.Roles, want)
	}
	for _, r := range info.Roles {
		if !want[r] {
			t.Errorf("unexpected role %q in %v", r, info.Roles)
		}
	}
}

// TestBearerClaimResolverEmailMustBeVerified asserts the resolver inherits the
// rule that an email-keyed assignment is only honored for a verified email — an
// IdP where the user can set their own email address must not let them claim
// another principal's roles.
func TestBearerClaimResolverEmailMustBeVerified(t *testing.T) {
	ta := rbac.NewTenantAssignments(
		rbac.NewAssignments(map[string][]rbac.Role{"admin@example.com": {rbac.RoleAdmin}}, nil), nil)
	resolve := bearerClaimResolver(
		mustBearerMappers(t, []config.OIDCProviderConfig{{Name: "idp"}}), ta, nil)

	info := &models.UserInfo{Subject: "attacker", Email: "admin@example.com", EmailVerified: false}
	resolve(info, &auth.Claims{Provider: "idp", Subject: info.Subject, Email: info.Email,
		Raw: map[string]interface{}{"sub": info.Subject, "email": info.Email}})
	if len(info.Roles) != 0 {
		t.Errorf("roles = %v, want none for an unverified email", info.Roles)
	}

	info.EmailVerified = true
	resolve(info, &auth.Claims{Provider: "idp", Subject: info.Subject, Email: info.Email, EmailVerified: true,
		Raw: map[string]interface{}{"sub": info.Subject, "email": info.Email, "email_verified": true}})
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin] once the email is verified", info.Roles)
	}
}

// TestBearerClaimResolverUnknownProviderIsInert asserts an unrecognized provider
// name (a token verified by a provider with no mapper, which should not happen)
// leaves the principal exactly as the central resolvers built it, rather than
// defaulting to some other provider's mapping.
func TestBearerClaimResolverUnknownProviderIsInert(t *testing.T) {
	resolve := resolverFor(t, federatedProviders(), nil)

	info := &models.UserInfo{Subject: "x", Roles: []string{"auditor"}}
	resolve(info, &auth.Claims{Provider: "nope", Subject: "x",
		Raw: map[string]interface{}{"sub": "x", "groups": []interface{}{"PKI-Admins"}}})
	if len(info.Roles) != 1 || info.Roles[0] != "auditor" {
		t.Errorf("roles = %v, want the untouched [auditor]", info.Roles)
	}
	// And a nil principal must not panic.
	resolve(nil, &auth.Claims{Provider: "github"})
}

// TestBearerClaimResolverNeverDenies asserts a machine caller that resolves to no
// role is still authenticated: refusal is the authorization gate's job, as it has
// always been on the Bearer path. (allow_zero_role is a console-login policy.)
func TestBearerClaimResolverNeverDenies(t *testing.T) {
	resolve := resolverFor(t, federatedProviders(), nil)

	info := &models.UserInfo{Subject: "repo:unknown/repo:ref:refs/heads/main"}
	resolve(info, &auth.Claims{Provider: "github", Subject: info.Subject,
		Raw: map[string]interface{}{"sub": info.Subject}})
	if info.Subject != "repo:unknown/repo:ref:refs/heads/main" {
		t.Errorf("subject was altered: %q", info.Subject)
	}
	if len(info.Roles) != 0 {
		t.Errorf("roles = %v, want none", info.Roles)
	}
}

// TestBearerProviderSpecsFromConfig asserts the config -> verifier translation:
// every configured issuer becomes a spec, and each spec's accepted audiences are
// its client_id unioned with its audiences list.
func TestBearerProviderSpecsFromConfig(t *testing.T) {
	cfg := &config.Config{OIDC: config.OIDCConfig{
		IssuerURL: "https://legacy.example.com",
		ClientID:  "legacy-aud",
		Providers: []config.OIDCProviderConfig{{
			Name:      "github",
			IssuerURL: "https://token.actions.githubusercontent.com",
			ClientID:  "secsy-pki-signing",
			Audiences: []string{"secsy-pki-signing", "secsy-pki-alt"},
		}},
	}}

	specs := bearerProviderSpecs(cfg)
	if len(specs) != 2 {
		t.Fatalf("specs = %+v, want the legacy issuer plus the declared one", specs)
	}
	if specs[0].Name != config.DefaultOIDCProviderName || len(specs[0].Audiences) != 1 {
		t.Errorf("specs[0] = %+v, want the legacy provider with one audience", specs[0])
	}
	if specs[1].Name != "github" {
		t.Fatalf("specs[1] = %+v, want github", specs[1])
	}
	// client_id duplicated in audiences must not appear twice.
	if len(specs[1].Audiences) != 2 {
		t.Errorf("specs[1].Audiences = %v, want the deduplicated pair", specs[1].Audiences)
	}
}

// TestBuildBearerClaimMappersCoversEveryProvider asserts each provider gets a
// mapper even with no role mappings — the mapper is also what extracts the
// caller's groups under that provider's configured groups claim, which the
// central group assignments and resource-scoped grants both need.
func TestBuildBearerClaimMappersCoversEveryProvider(t *testing.T) {
	mappers := mustBearerMappers(t, []config.OIDCProviderConfig{
		{Name: "plain", IssuerURL: "https://a.example.com", ClientID: "c"},
		{Name: "custom-claim", IssuerURL: "https://b.example.com", ClientID: "c", GroupsClaim: "wids"},
	})
	if len(mappers) != 2 {
		t.Fatalf("mappers = %d, want one per provider", len(mappers))
	}
	if got := mappers["plain"].GroupsClaim(); got != "groups" {
		t.Errorf("plain groups claim = %q, want the \"groups\" default", got)
	}
	if got := mappers["custom-claim"].GroupsClaim(); got != "wids" {
		t.Errorf("custom groups claim = %q, want wids", got)
	}
	got := mappers["custom-claim"].Groups(map[string]interface{}{"wids": []interface{}{"g1", "g2"}})
	if len(got) != 2 {
		t.Errorf("Groups() = %v, want both values read from the configured claim", got)
	}
}
