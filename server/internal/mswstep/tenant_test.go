//go:build sqlite

package mswstep

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestRST_TenantSuspended verifies enrollment on a suspended tenant's CA fails
// closed with a 403, even for a token that would otherwise be authorized — the
// tenant-lifecycle gate inside ca.Manager surfaced as a SOAP fault.
func TestRST_TenantSuspended(t *testing.T) {
	const tenant = "acme"
	env := newTestEnv(t, softwareProvider(t), tenant, nil)
	secret := env.mintToken(t, tenant, models.TokenScopeTenant, "issuer")

	// Sanity: the token can enroll while the tenant is active.
	_, csrDER := makeCSR(t, "before-suspend")
	body := rstEnvelope("urn:uuid:pre", base64.StdEncoding.EncodeToString(csrDER), "")
	if status, resp := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret)); status != 200 {
		t.Fatalf("pre-suspend status = %d, want 200\n%s", status, resp)
	}

	// Suspend the tenant; enrollment must now be refused.
	if err := env.db.SetTenantStatus(tenant, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	_, csrDER2 := makeCSR(t, "after-suspend")
	body2 := rstEnvelope("urn:uuid:post", base64.StdEncoding.EncodeToString(csrDER2), "")
	status, resp := postSOAP(t, env.ts.URL+"/mswstep/enroll", body2, tokenAuth(secret))
	if status != 403 {
		t.Fatalf("suspended-tenant status = %d, want 403\n%s", status, resp)
	}
	if !strings.Contains(strings.ToLower(string(resp)), "suspend") {
		t.Errorf("fault did not mention suspension:\n%s", resp)
	}
}

// TestRST_CrossTenantTokenDenied verifies a token whose issuer role lives in a
// different tenant cannot enroll on this CA — the RBAC cross-tenant isolation
// check, enforced before any issuance work.
func TestRST_CrossTenantTokenDenied(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "acme", nil)
	// A token scoped to a different tenant, even with the issuer role.
	if err := env.db.CreateTenant(&models.Tenant{
		ID: "other", Slug: "other", Name: "other", Status: models.TenantStatusActive,
	}); err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	secret := env.mintToken(t, "other", models.TokenScopeTenant, "issuer")

	_, csrDER := makeCSR(t, "cross-tenant")
	body := rstEnvelope("urn:uuid:cross", base64.StdEncoding.EncodeToString(csrDER), "")
	status, resp := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
	if status != 403 {
		t.Fatalf("cross-tenant status = %d, want 403\n%s", status, resp)
	}
}

// TestRST_PlatformTokenAllowed verifies a platform-scoped issuer token may enroll
// on any tenant's CA (platform roles span every tenant).
func TestRST_PlatformTokenAllowed(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "acme", nil)
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopePlatform, "issuer")

	_, csrDER := makeCSR(t, "platform-issued")
	body := rstEnvelope("urn:uuid:plat", base64.StdEncoding.EncodeToString(csrDER), "")
	status, resp := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
	if status != 200 {
		t.Fatalf("platform-token status = %d, want 200\n%s", status, resp)
	}
	leaf := parseRSTR(t, resp).issuedCert(t)
	if leaf.Subject.CommonName != "platform-issued" {
		t.Errorf("issued CN = %q, want platform-issued", leaf.Subject.CommonName)
	}
}
