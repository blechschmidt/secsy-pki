//go:build sqlite

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func tenantAPI(t *testing.T) (*API, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	return NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, ""), db
}

func mkTenant(t *testing.T, db *database.DB, id string) {
	t.Helper()
	if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
		t.Fatalf("CreateTenant(%s): %v", id, err)
	}
}

func mkTenantCA(t *testing.T, db *database.DB, tenantID, id string) {
	t.Helper()
	ca := &models.CA{
		ID: id, TenantID: tenantID, Label: id,
		PKCS11URI: "pkcs11:object=" + id, KeyType: "ecdsa-p256", PublicKey: "k",
		Certificate: "x", // marks it an X.509 CA for downstream code paths
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatalf("CreateCA(%s): %v", id, err)
	}
}

// reqAs builds a request carrying the given authenticated user and an id path
// value, with a tenant holder installed as the middleware would.
func reqAs(method, target string, user *models.UserInfo, id, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), middleware.UserInfoKey, user)
	ctx = middleware.WithTenantHolder(ctx)
	r = r.WithContext(ctx)
	if id != "" {
		r.SetPathValue("id", id)
	}
	return r
}

// tenantUser builds a user holding a single role within one tenant only.
func tenantUser(sub, tenantID, role string) *models.UserInfo {
	return &models.UserInfo{
		Subject:     sub,
		TenantRoles: map[string][]string{tenantID: {role}},
	}
}

// TestCrossTenantIssueDenied is the headline isolation proof: an issuer of
// tenant A is denied issuance on a CA owned by tenant B, while being authorized
// on its own tenant's CA.
func TestCrossTenantIssueDenied(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	mkTenantCA(t, db, "a", "ca-a")
	mkTenantCA(t, db, "b", "ca-b")

	aliceA := tenantUser("alice", "a", "issuer")

	// Cross-tenant: alice (tenant a) tries to issue on tenant b's CA -> 403.
	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/ca-b/issue", aliceA, "ca-b", `{"csr":"dummy"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant issue: status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// Same-tenant: alice on tenant a's CA passes authorization (fails later on the
	// bogus CSR with a 4xx that is NOT 403), proving she is authorized here.
	rec = httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/ca-a/issue", aliceA, "ca-a", `{"csr":"not-a-real-csr"}`))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("same-tenant issue was denied: body=%s", rec.Body.String())
	}
}

// TestCrossTenantReadReturns404 proves a non-member cannot even confirm the
// existence of another tenant's CA (404, not 403).
func TestCrossTenantReadReturns404(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	mkTenantCA(t, db, "b", "ca-b")

	aliceA := tenantUser("alice", "a", "auditor")

	rec := httptest.NewRecorder()
	api.GetCA(rec, reqAs(http.MethodGet, "/api/keys/ca-b", aliceA, "ca-b", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestListCAsScopedToTenant proves ListCAs returns only the caller's tenant's
// CAs for a tenant-scoped principal, but all CAs for a platform operator.
func TestListCAsScopedToTenant(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	mkTenantCA(t, db, "a", "ca-a")
	mkTenantCA(t, db, "b", "ca-b")

	aliceA := tenantUser("alice", "a", "auditor")
	rec := httptest.NewRecorder()
	api.ListCAs(rec, reqAs(http.MethodGet, "/api/keys", aliceA, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ca-a") || strings.Contains(body, "ca-b") {
		t.Fatalf("tenant-scoped ListCAs leaked or missed CAs: %s", body)
	}

	// Root sees both.
	root := &models.UserInfo{Subject: "root", IsRoot: true}
	rec = httptest.NewRecorder()
	api.ListCAs(rec, reqAs(http.MethodGet, "/api/keys", root, "", ""))
	if b := rec.Body.String(); !strings.Contains(b, "ca-a") || !strings.Contains(b, "ca-b") {
		t.Fatalf("root ListCAs = %s, want both CAs", b)
	}
}

// TestAuditLogTenantScoped proves a tenant-scoped auditor sees only its own
// tenant's audit events, never another tenant's.
func TestAuditLogTenantScoped(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	if err := db.AppendEvent(&audit.Event{ID: "1", Actor: "alice", Action: audit.ActionCertIssue, Tenant: "a", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendEvent(&audit.Event{ID: "2", Actor: "bob", Action: audit.ActionCertIssue, Tenant: "b", Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}

	aliceA := tenantUser("alice", "a", "auditor")
	rec := httptest.NewRecorder()
	api.ListEventLog(rec, reqAs(http.MethodGet, "/api/events", aliceA, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "alice") || strings.Contains(body, "bob") {
		t.Fatalf("tenant-a auditor saw cross-tenant events: %s", body)
	}
}

// TestTenantAdminIsPlatformScoped proves a tenant-scoped admin cannot provision
// or enumerate tenants (that is a platform-operator capability).
func TestTenantAdminIsPlatformScoped(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	adminA := tenantUser("carol", "a", "admin")

	rec := httptest.NewRecorder()
	api.ListTenants(rec, reqAs(http.MethodGet, "/api/tenants", adminA, "", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped admin listed tenants: status = %d", rec.Code)
	}

	// The platform root may.
	root := &models.UserInfo{Subject: "root", IsRoot: true}
	rec = httptest.NewRecorder()
	api.ListTenants(rec, reqAs(http.MethodGet, "/api/tenants", root, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("root list tenants: status = %d", rec.Code)
	}
}

// TestAuditEventStampedWithTenant proves that when a CA-scoped action is
// authorized, the resulting audit event is attributed to the CA's tenant via
// the request-context tenant holder.
func TestAuditEventStampedWithTenant(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "a")
	mkTenantCA(t, db, "a", "ca-a")
	aliceA := tenantUser("alice", "a", "issuer")

	// A denied cross-check first would not stamp; use a same-tenant revoke which
	// resolves the tenant during authorization. Missing serial -> handled, but the
	// tenant is set on the holder regardless once canIssueOn runs.
	r := reqAs(http.MethodPost, "/api/ca/ca-a/revoke", aliceA, "ca-a", `{"serial":"01"}`)
	rec := httptest.NewRecorder()
	api.RevokeCertificate(rec, r)

	events, total, err := db.ListEvents("", "", "a", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || len(events) == 0 {
		t.Fatalf("no tenant-a audit events recorded (total=%d)", total)
	}
	for _, e := range events {
		if e.Tenant != "a" {
			t.Errorf("event %s tenant = %q, want a", e.ID, e.Tenant)
		}
	}
}
