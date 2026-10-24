// Wiring tests for CEL role mappings (Task 214): config -> newClaimMapper ->
// the resolver the auth middleware applies.
//
// The expression semantics are covered in internal/authn and internal/celexpr.
// What is asserted here is the half only this package can get wrong: that the
// config fields reach the mapper at all, that the tenant ids an expression may
// derive are bounded by the tenants THIS config declares, and that a mapping
// which does not compile stops the server instead of quietly granting nothing.
package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// celBearerProvider is a machine-token provider whose mappings are expressions:
// a CI pipeline identified by its workload-identity subject gets signer, and a
// group name encoding a tenant gets issuer in that tenant.
func celBearerProvider() []config.OIDCProviderConfig {
	return []config.OIDCProviderConfig{{
		Name:      "forge",
		IssuerURL: "https://token.actions.githubusercontent.com",
		ClientID:  "secsy-pki",
		RoleMappings: []config.ClaimMappingConfig{
			{
				Expression: `subject.matches("^repo:example-org/[a-z-]+:environment:release$")`,
				Roles:      []string{"signer"},
			},
			{
				Expression: `groups.exists(g, g.startsWith("pki-issuers-"))`,
				TenantExpression: `groups.filter(g, g.startsWith("pki-issuers-"))
				                         .map(g, g.replace("pki-issuers-", ""))`,
				Roles: []string{"issuer"},
			},
		},
	}}
}

// celTenantConfig declares the tenants a derived id may name.
func celTenantConfig(ids ...string) *config.Config {
	cfg := &config.Config{}
	for _, id := range ids {
		cfg.Tenants = append(cfg.Tenants, config.TenantConfig{ID: id})
	}
	return cfg
}

// TestBearerCELMappingGrantsRoles asserts a machine caller's roles come out of
// the expressions, through the same resolver the middleware installs.
func TestBearerCELMappingGrantsRoles(t *testing.T) {
	mappers, err := buildBearerClaimMappers(celTenantConfig("acme-corp", "globex"), celBearerProvider())
	if err != nil {
		t.Fatalf("buildBearerClaimMappers: %v", err)
	}
	ta := rbac.NewTenantAssignments(rbac.NewAssignments(nil, nil), nil)
	resolve := bearerClaimResolver(mappers, ta, nil)

	info := &models.UserInfo{Subject: "repo:example-org/app:environment:release"}
	resolve(info, &auth.Claims{
		Provider: "forge",
		Subject:  info.Subject,
		Raw: map[string]interface{}{
			"sub":    info.Subject,
			"iss":    "https://token.actions.githubusercontent.com",
			"groups": []interface{}{"pki-issuers-acme-corp", "pki-issuers-nosuchtenant"},
		},
	})

	if got := sortedCopy(info.Roles); len(got) != 1 || got[0] != "signer" {
		t.Errorf("platform roles = %v, want [signer] from the subject expression", got)
	}
	if got := info.TenantRoles["acme-corp"]; len(got) != 1 || got[0] != "issuer" {
		t.Errorf("acme-corp roles = %v, want [issuer] from the derived tenant", got)
	}
	if _, ok := info.TenantRoles["nosuchtenant"]; ok {
		t.Error("a derived tenant id outside the declared tenants granted a role")
	}
	if len(info.TenantRoles) != 1 {
		t.Errorf("tenant roles = %v, want only acme-corp", info.TenantRoles)
	}
}

// TestBearerCELMappingGrantsNothingToAnotherIdentity asserts the anchored
// subject pattern does not match a neighbouring repository or environment —
// the failure mode an unanchored pattern would have.
func TestBearerCELMappingGrantsNothingToAnotherIdentity(t *testing.T) {
	mappers, err := buildBearerClaimMappers(celTenantConfig("acme-corp"), celBearerProvider())
	if err != nil {
		t.Fatalf("buildBearerClaimMappers: %v", err)
	}
	ta := rbac.NewTenantAssignments(rbac.NewAssignments(nil, nil), nil)
	resolve := bearerClaimResolver(mappers, ta, nil)

	for _, sub := range []string{
		"repo:example-org/app:environment:staging",
		"repo:attacker-org/app:environment:release",
		"repo:example-org/app:environment:release:extra",
		"prefix-repo:example-org/app:environment:release",
	} {
		info := &models.UserInfo{Subject: sub}
		resolve(info, &auth.Claims{Provider: "forge", Subject: sub,
			Raw: map[string]interface{}{"sub": sub}})
		if len(info.Roles) != 0 || len(info.TenantRoles) != 0 {
			t.Errorf("subject %q resolved to %v / %v, want nothing", sub, info.Roles, info.TenantRoles)
		}
	}
}

// TestBuildBearerClaimMappersRefusesBadExpression asserts a mapping that does
// not compile is a startup error naming the provider, not a mapper that grants
// nothing at runtime.
func TestBuildBearerClaimMappersRefusesBadExpression(t *testing.T) {
	providers := []config.OIDCProviderConfig{{
		Name: "forge", IssuerURL: "https://idp.example.com", ClientID: "c",
		RoleMappings: []config.ClaimMappingConfig{
			{Expression: `size(groups)`, Roles: []string{"signer"}},
		},
	}}
	_, err := buildBearerClaimMappers(&config.Config{}, providers)
	if err == nil {
		t.Fatal("buildBearerClaimMappers accepted an expression that is not a bool")
	}
	for _, want := range []string{`"forge"`, "role_mappings[0]", "must evaluate to bool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// TestBuildClaimMappingsCarriesExpressions asserts the config -> authn
// translation does not drop the new fields. Without this the mappings would
// silently degrade to "nothing to match" and be dropped as inert.
func TestBuildClaimMappingsCarriesExpressions(t *testing.T) {
	got := buildClaimMappings([]config.ClaimMappingConfig{{
		Expression:       `true`,
		TenantExpression: `"acme"`,
		Roles:            []string{"issuer"},
	}})
	if len(got) != 1 {
		t.Fatalf("mappings = %d, want 1", len(got))
	}
	if got[0].Expression != `true` || got[0].TenantExpression != `"acme"` {
		t.Errorf("mapping = %+v, want both expressions carried", got[0])
	}
}

// TestNewClaimMapperBoundsDerivedTenantsToTheConfig asserts the known-tenant
// restriction comes from the configuration rather than from a static list.
func TestNewClaimMapperBoundsDerivedTenantsToTheConfig(t *testing.T) {
	mappings := []config.ClaimMappingConfig{{
		Expression:       `size(groups) > 0`,
		TenantExpression: `groups[0]`,
		Roles:            []string{"issuer"},
	}}
	id := func() map[string]interface{} {
		return map[string]interface{}{"groups": []interface{}{"declared"}}
	}

	withTenant, err := newClaimMapper(celTenantConfig("declared"), "p", "groups", mappings)
	if err != nil {
		t.Fatalf("newClaimMapper: %v", err)
	}
	if _, tenant := withTenant.Resolve(id()); len(tenant["declared"]) != 1 {
		t.Errorf("tenant roles = %v, want issuer in the declared tenant", tenant)
	}

	other, err := newClaimMapper(celTenantConfig("something-else"), "p", "groups", mappings)
	if err != nil {
		t.Fatalf("newClaimMapper: %v", err)
	}
	if platform, tenant := other.Resolve(id()); len(platform) != 0 || len(tenant) != 0 {
		t.Errorf("roles = %v / %v, want none when the derived id is not a declared tenant", platform, tenant)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
