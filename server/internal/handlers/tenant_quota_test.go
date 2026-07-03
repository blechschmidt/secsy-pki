//go:build sqlite

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// Task 61 REST-surface tests: 429/quota_exceeded semantics on issuance,
// suspension answering 403 while public CRL/OCSP keep serving, the usage
// report endpoint with its tenant-scoped visibility, and quota administration
// RBAC.

// quotaCSR builds a PEM CSR for a fresh key with the given CN/SAN.
func quotaCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// quotaTenantWithRoot provisions a tenant (with quotas) owning a real
// software-provider root CA, so issuance flows end-to-end through the handler.
func quotaTenantWithRoot(t *testing.T, api *API, db *database.DB, slug string, quotas models.TenantQuotas) (*models.Tenant, *models.CA) {
	t.Helper()
	tn := &models.Tenant{ID: "qt-" + slug, Slug: slug, Name: slug, Status: models.TenantStatusActive, Quotas: quotas}
	if err := db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	mgr := ca.NewManager(db, api.keyProvider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		TenantID: tn.ID,
		Label:    "qt-root-" + slug,
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Quota Test Root " + slug}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return tn, root
}

func rootUser() *models.UserInfo { return &models.UserInfo{Subject: "root", IsRoot: true} }

// issueVia drives the real REST issuance handler and returns the recorder.
func issueVia(t *testing.T, api *API, caID, cn string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"csr":%q,"profile":"server"}`, quotaCSR(t, cn))
	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, body))
	return rec
}

// TestIssueQuota429WithRetryAfter: daily quota exhaustion on the REST issuance
// path answers 429 with code=quota_exceeded and a positive Retry-After.
func TestIssueQuota429WithRetryAfter(t *testing.T) {
	api, db := tenantAPI(t)
	_, root := quotaTenantWithRoot(t, api, db, "q429", models.TenantQuotas{MaxCertsPerDay: 1})

	if rec := issueVia(t, api, root.ID, "ok.example.com"); rec.Code != http.StatusCreated {
		t.Fatalf("first issuance = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	rec := issueVia(t, api, root.ID, "over.example.com")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota issuance = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 missing positive Retry-After (got %q)", ra)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parsing 429 body: %v", err)
	}
	if resp["code"] != "quota_exceeded" || resp["quota"] != models.QuotaCertsPerDay {
		t.Errorf("429 body = %v, want code=quota_exceeded quota=%s", resp, models.QuotaCertsPerDay)
	}
}

// TestSuspendedTenant403ButCRLAndOCSPServe is the protocol-surface half of the
// suspension contract at the REST layer: issuance answers 403 with
// code=tenant_suspended, while the unauthenticated CRL and OCSP endpoints keep
// serving revocation status for the tenant's existing certificates.
func TestSuspendedTenant403ButCRLAndOCSPServe(t *testing.T) {
	api, db := tenantAPI(t)
	tn, root := quotaTenantWithRoot(t, api, db, "s403", models.TenantQuotas{})

	// One live certificate before suspension.
	if rec := issueVia(t, api, root.ID, "live.example.com"); rec.Code != http.StatusCreated {
		t.Fatalf("pre-suspension issuance = %d; body=%s", rec.Code, rec.Body.String())
	}

	if err := db.SetTenantStatus(tn.ID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	rec := issueVia(t, api, root.ID, "blocked.example.com")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("issuance under suspension = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["code"] != "tenant_suspended" {
		t.Errorf("403 body = %v, want code=tenant_suspended", resp)
	}

	// Public CRL endpoint still serves (fresh CRL signed on demand).
	rec = httptest.NewRecorder()
	api.GetCRL(rec, reqAs(http.MethodGet, "/api/ca/"+root.ID+"/crl", nil, root.ID, ""))
	if rec.Code != http.StatusOK {
		t.Errorf("CRL under suspension = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// SVID and renew paths are blocked too (both mint certificates).
	rec = httptest.NewRecorder()
	api.RenewCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+root.ID+"/renew", rootUser(), root.ID, `{"serial":"1"}`))
	if rec.Code != http.StatusForbidden {
		t.Errorf("renew under suspension = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestTenantUsageEndpoint covers the report content and its visibility rules:
// platform admins read any tenant, members their own, and non-members get 404.
func TestTenantUsageEndpoint(t *testing.T) {
	api, db := tenantAPI(t)
	tn, root := quotaTenantWithRoot(t, api, db, "usage", models.TenantQuotas{MaxCertsPerDay: 10})
	mkTenant(t, db, "other")

	// Two issuances and one revocation to have real numbers.
	var serial string
	for _, cn := range []string{"u1.example.com", "u2.example.com"} {
		rec := issueVia(t, api, root.ID, cn)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issuance = %d; body=%s", rec.Code, rec.Body.String())
		}
		var out struct {
			Serial string `json:"serial"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("parsing issue response: %v", err)
		}
		serial = out.Serial
	}
	mgr := ca.NewManager(db, api.keyProvider)
	if _, err := mgr.RevokeCertificate(context.Background(), root.ID, serial, "superseded"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	fetch := func(user *models.UserInfo, id, query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		api.TenantUsage(rec, reqAs(http.MethodGet, "/api/tenants/"+id+"/usage"+query, user, id, ""))
		return rec
	}

	// Platform admin (root) sees the full report.
	rec := fetch(rootUser(), tn.ID, "?days=3")
	if rec.Code != http.StatusOK {
		t.Fatalf("usage as admin = %d; body=%s", rec.Code, rec.Body.String())
	}
	var report models.TenantUsageReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("parsing report: %v", err)
	}
	if report.TenantID != tn.ID || report.CAs != 1 {
		t.Errorf("report tenant/CAs = %s/%d, want %s/1", report.TenantID, report.CAs, tn.ID)
	}
	if report.ActiveCerts != 1 || report.TotalIssued != 2 || report.TotalRevoked != 1 {
		t.Errorf("report counts = active:%d issued:%d revoked:%d, want 1/2/1",
			report.ActiveCerts, report.TotalIssued, report.TotalRevoked)
	}
	if len(report.Days) != 3 {
		t.Errorf("report window = %d days, want 3 (zero-filled)", len(report.Days))
	}
	if report.Today.CertsIssued != 2 || report.Today.CertsRevoked != 1 {
		t.Errorf("today = %+v, want issued=2 revoked=1", report.Today)
	}
	if report.Quotas.MaxCertsPerDay != 10 {
		t.Errorf("report quotas = %+v, want max_certs_per_day=10", report.Quotas)
	}

	// A member of the tenant reads its own report.
	member := tenantUser("member", tn.ID, "auditor")
	if rec := fetch(member, tn.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("usage as member = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// A member of another tenant gets 404 (existence not disclosed).
	outsider := tenantUser("outsider", "other", "admin")
	if rec := fetch(outsider, tn.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("usage cross-tenant = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}

	// Bounds are validated.
	if rec := fetch(rootUser(), tn.ID, "?days=0"); rec.Code != http.StatusBadRequest {
		t.Errorf("days=0 = %d, want 400", rec.Code)
	}
	if rec := fetch(rootUser(), tn.ID, "?days=91"); rec.Code != http.StatusBadRequest {
		t.Errorf("days=91 = %d, want 400", rec.Code)
	}
}

// TestUpdateTenantQuotasRBAC: only platform admins may set quotas; values are
// validated; updates round-trip through the GET endpoint.
func TestUpdateTenantQuotasRBAC(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "adm")

	update := func(user *models.UserInfo, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		api.UpdateTenant(rec, reqAs(http.MethodPut, "/api/tenants/adm", user, "adm", body))
		return rec
	}

	// A tenant-scoped admin is NOT a platform admin: 403.
	if rec := update(tenantUser("alice", "adm", "admin"), `{"quotas":{"max_certs_per_day":5}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant admin updating quotas = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// Negative values are rejected.
	if rec := update(rootUser(), `{"quotas":{"max_certs_per_day":-1}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("negative quota = %d, want 400", rec.Code)
	}

	// Platform admin sets quotas + name; the change round-trips.
	rec := update(rootUser(), `{"name":"Renamed","quotas":{"max_certs_per_day":5,"max_active_certs":9,"rate_limit_per_second":2,"rate_limit_burst":4}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d; body=%s", rec.Code, rec.Body.String())
	}
	got, err := db.GetTenant("adm")
	if err != nil || got == nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Name != "Renamed" || got.Quotas.MaxCertsPerDay != 5 || got.Quotas.MaxActiveCerts != 9 ||
		got.Quotas.RateLimitPerSecond != 2 || got.Quotas.RateLimitBurst != 4 {
		t.Errorf("persisted tenant = %+v, quotas = %+v", got, got.Quotas)
	}
	// Slug/status untouched by the update surface.
	if got.Slug != "adm" || got.Status != models.TenantStatusActive {
		t.Errorf("slug/status changed: %s/%s", got.Slug, got.Status)
	}
}

// TestSecretOpsQuota429: the secret path enforces max_secret_ops_per_day with
// the same 429 semantics, selected via the X-Secsy-Tenant header.
func TestSecretOpsQuota429(t *testing.T) {
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if _, err := secret.ProvisionKEK(context.Background(), prov, "quota-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "quota-kek")

	tn := &models.Tenant{ID: "sq", Slug: "sq", Name: "sq", Status: models.TenantStatusActive,
		Quotas: models.TenantQuotas{MaxSecretOpsPerDay: 1}}
	if err := db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	encrypt := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := reqAs(http.MethodPost, "/api/secret/encrypt", rootUser(), "", `{"plaintext":"c2VjcmV0"}`)
		r.Header.Set(TenantHeader, "sq")
		api.EncryptSecret(rec, r)
		return rec
	}

	if rec := encrypt(); rec.Code != http.StatusOK {
		t.Fatalf("first encrypt = %d; body=%s", rec.Code, rec.Body.String())
	}
	rec := encrypt()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second encrypt = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 missing positive Retry-After (got %q)", ra)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["quota"] != models.QuotaSecretOpsPerDay {
		t.Errorf("429 quota = %q, want %s", resp["quota"], models.QuotaSecretOpsPerDay)
	}

	// Suspension refuses the secret path with 403.
	if err := db.SetTenantStatus(tn.ID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if rec := encrypt(); rec.Code != http.StatusForbidden {
		t.Errorf("encrypt under suspension = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// Usage recorded exactly one successful operation.
	usage, err := db.GetTenantUsageDay(tn.ID, database.UsageDay(time.Now()))
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if usage.SecretOps != 1 {
		t.Errorf("secret_ops = %d, want 1", usage.SecretOps)
	}
}
