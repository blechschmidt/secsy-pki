//go:build sqlite

package ca

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// newTenant creates a tenant with the given quotas and returns it.
func newTenant(t *testing.T, mgr *Manager, slug string, quotas models.TenantQuotas) *models.Tenant {
	t.Helper()
	tn := &models.Tenant{
		ID:     "tenant-" + slug,
		Slug:   slug,
		Name:   strings.ToUpper(slug),
		Status: models.TenantStatusActive,
		Quotas: quotas,
	}
	if err := mgr.db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant(%s): %v", slug, err)
	}
	return tn
}

// newTenantRoot initializes a root CA owned by the given tenant.
func newTenantRoot(t *testing.T, mgr *Manager, tenantID, tag string) *models.CA {
	t.Helper()
	root, err := mgr.InitRoot(context.Background(), RootSpec{
		TenantID: tenantID,
		Label:    uniqueLabel(t, tag+"-root"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Tenant Gate Root " + tag}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return root
}

func issueOne(t *testing.T, mgr *Manager, caID, cn string) (*IssueResult, error) {
	t.Helper()
	return mgr.IssueCertificate(context.Background(), IssueSpec{
		CAID:    caID,
		CSRPEM:  makeCSR(t, cn, []string{cn}),
		Profile: "server",
	})
}

// TestTenantSuspensionBlocksIssuanceButNotRevocationStatus is the core
// lifecycle contract: a suspended tenant cannot mint certificates through any
// manager path, while CRL generation, OCSP service, and revocation for its
// already-issued certificates keep working. Reactivation restores issuance.
func TestTenantSuspensionBlocksIssuanceButNotRevocationStatus(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	tn := newTenant(t, mgr, "susp", models.TenantQuotas{})
	root := newTenantRoot(t, mgr, tn.ID, "susp")
	rootCert := mustParse(t, root.Certificate)

	// Issue one certificate while active — this is the credential that must
	// keep validating after suspension.
	issued, err := issueOne(t, mgr, root.ID, "pre-suspend.example.com")
	if err != nil {
		t.Fatalf("issuing before suspension: %v", err)
	}

	if err := mgr.db.SetTenantStatus(tn.ID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspending: %v", err)
	}

	// CSR-based issuance is refused with the typed error.
	_, err = issueOne(t, mgr, root.ID, "post-suspend.example.com")
	var susp *models.TenantSuspendedError
	if !errors.As(err, &susp) {
		t.Fatalf("issue under suspension: err = %v, want TenantSuspendedError", err)
	}
	if susp.TenantID != tn.ID {
		t.Errorf("suspended error names tenant %q, want %q", susp.TenantID, tn.ID)
	}

	// Renewal of the existing certificate is refused too (it mints a new cert).
	if _, err := mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: issued.Serial.String()}); !errors.As(err, &susp) {
		t.Errorf("renew under suspension: err = %v, want TenantSuspendedError", err)
	}

	// Template-based issuance (the CMP path) is refused.
	leafCert := issued.Certificate
	if _, err := mgr.IssueCertificateFromTemplate(ctx, TemplateIssueSpec{
		CAID:      root.ID,
		Subject:   leafCert.Subject,
		PublicKey: leafCert.PublicKey,
		DNSNames:  []string{"tmpl.example.com"},
	}); !errors.As(err, &susp) {
		t.Errorf("template issue under suspension: err = %v, want TenantSuspendedError", err)
	}

	// CRL generation still works and is signed by the suspended tenant's CA.
	if _, err := mgr.GenerateCRL(ctx, root.ID); err != nil {
		t.Errorf("GenerateCRL under suspension: %v (must keep working)", err)
	}

	// OCSP still answers for the pre-suspension certificate.
	reqDER, err := pki.BuildOCSPRequest(issued.Certificate, rootCert)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	respDER, err := mgr.OCSPRespond(ctx, root.ID, reqDER)
	if err != nil {
		t.Fatalf("OCSPRespond under suspension: %v (must keep working)", err)
	}
	parsed, err := ocsp.ParseResponse(respDER, rootCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("OCSP status = %d, want Good", parsed.Status)
	}

	// Revocation must remain possible while suspended (withdrawing a suspended
	// tenant's credentials is a security operation).
	applied, err := mgr.RevokeCertificate(ctx, root.ID, issued.Serial.String(), "cessationOfOperation")
	if err != nil || !applied {
		t.Fatalf("revoke under suspension: applied=%v err=%v (must keep working)", applied, err)
	}
	// And OCSP now reports the revocation.
	respDER, err = mgr.OCSPRespond(ctx, root.ID, reqDER)
	if err != nil {
		t.Fatalf("OCSPRespond after revoke: %v", err)
	}
	if parsed, err = ocsp.ParseResponse(respDER, rootCert); err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if parsed.Status != ocsp.Revoked {
		t.Errorf("OCSP status after revoke = %d, want Revoked", parsed.Status)
	}

	// Reactivation restores issuance.
	if err := mgr.db.SetTenantStatus(tn.ID, models.TenantStatusActive); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
	if _, err := issueOne(t, mgr, root.ID, "post-reactivate.example.com"); err != nil {
		t.Errorf("issue after reactivation: %v", err)
	}

	// The refusals were audited.
	events, _, err := mgr.db.ListEvents("tenant.quota", "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) == 0 {
		t.Error("no tenant.quota audit events recorded for suspension refusals")
	}
}

// TestTenantCertsPerDayQuota exercises daily-quota exhaustion: the ceiling
// holds, the error carries a reset hint, another tenant is unaffected, and a
// failed issuance releases its reservation.
func TestTenantCertsPerDayQuota(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	tnA := newTenant(t, mgr, "quota-a", models.TenantQuotas{MaxCertsPerDay: 2})
	tnB := newTenant(t, mgr, "quota-b", models.TenantQuotas{})
	rootA := newTenantRoot(t, mgr, tnA.ID, "qa")
	rootB := newTenantRoot(t, mgr, tnB.ID, "qb")

	// Two issuances fit the quota.
	for i, cn := range []string{"one.example.com", "two.example.com"} {
		if _, err := issueOne(t, mgr, rootA.ID, cn); err != nil {
			t.Fatalf("issuance %d within quota: %v", i+1, err)
		}
	}

	// The third is refused with the typed error and a positive Retry-After.
	_, err := issueOne(t, mgr, rootA.ID, "three.example.com")
	var quota *models.QuotaExceededError
	if !errors.As(err, &quota) {
		t.Fatalf("over-quota issue: err = %v, want QuotaExceededError", err)
	}
	if quota.Quota != models.QuotaCertsPerDay || quota.Limit != 2 {
		t.Errorf("quota error = %+v, want kind=%s limit=2", quota, models.QuotaCertsPerDay)
	}
	if quota.RetryAfter <= 0 || quota.RetryAfter > 24*time.Hour {
		t.Errorf("RetryAfter = %v, want within (0, 24h]", quota.RetryAfter)
	}

	// Renewal counts as issuance and is refused by the same exhausted quota.
	if _, err := mgr.RenewCertificate(context.Background(), RenewSpec{CAID: rootA.ID, Serial: "1"}); !errors.As(err, &quota) {
		// Serial "1" doesn't exist, but the quota gate runs first — the point is
		// that renewal cannot bypass an exhausted daily quota.
		t.Errorf("renew over quota: err = %v, want QuotaExceededError", err)
	}

	// Tenant B is unaffected — quota state is per tenant, not global.
	if _, err := issueOne(t, mgr, rootB.ID, "b.example.com"); err != nil {
		t.Errorf("tenant B issuance while A exhausted: %v", err)
	}

	// A's counter reflects exactly the two successes (the refusals and the
	// failed renewal released/never took units).
	day := database.UsageDay(time.Now())
	usage, err := mgr.db.GetTenantUsageDay(tnA.ID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if usage.CertsIssued != 2 {
		t.Errorf("tenant A certs_issued = %d, want 2 (reservations must be released on failure)", usage.CertsIssued)
	}
}

// TestTenantQuotaReleasedOnFailedIssuance proves the reservation-style
// accounting: an issuance that passes the tenant gate but then fails a later
// pre-issuance gate hands its daily unit back. The name-constraints gate runs
// inside buildLeaf — after the tenant gate — and is always enforced, so an
// intermediate permitting only *.allowed.test deterministically rejects any
// other DNS name at exactly the right point.
func TestTenantQuotaReleasedOnFailedIssuance(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	tn := newTenant(t, mgr, "release", models.TenantQuotas{MaxCertsPerDay: 2})
	root := newTenantRoot(t, mgr, tn.ID, "rel")

	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID: root.ID,
		Label:    uniqueLabel(t, "rel-nc-inter"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Release Test Constrained Intermediate"}),
		Validity: 2 * 365 * 24 * time.Hour,
		NameConstraints: nameconstraints.Constraints{
			Permitted: nameconstraints.Subtrees{DNS: []string{"allowed.test"}},
			Critical:  true,
		},
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	// Root issuance to the intermediate consumed one daily unit (intermediates
	// are not leaves and are not gated; only leaf issuance is). Verify the
	// baseline is zero before the failing attempt.
	day := database.UsageDay(time.Now())
	base, err := mgr.db.GetTenantUsageDay(tn.ID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}

	// A leaf outside the permitted subtree passes the tenant gate, then fails
	// the name-constraints gate — the reservation must be handed back.
	if _, err := issueOne(t, mgr, inter.ID, "forbidden.example.com"); err == nil {
		t.Fatal("expected issuance outside the permitted subtree to fail the name-constraints gate")
	}
	after, err := mgr.db.GetTenantUsageDay(tn.ID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if after.CertsIssued != base.CertsIssued {
		t.Fatalf("certs_issued changed %d -> %d across a failed issuance (reservation must be released)",
			base.CertsIssued, after.CertsIssued)
	}

	// The quota is intact: two valid issuances still fit the limit of 2.
	for _, cn := range []string{"a.allowed.test", "b.allowed.test"} {
		if _, err := issueOne(t, mgr, inter.ID, cn); err != nil {
			t.Fatalf("issuing %s after released reservation: %v", cn, err)
		}
	}
}

// TestTenantActiveCertCeiling exercises the inventory ceiling: it blocks when
// reached and frees room on revocation.
func TestTenantActiveCertCeiling(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	tn := newTenant(t, mgr, "active", models.TenantQuotas{MaxActiveCerts: 1})
	root := newTenantRoot(t, mgr, tn.ID, "act")

	first, err := issueOne(t, mgr, root.ID, "a1.example.com")
	if err != nil {
		t.Fatalf("first issuance: %v", err)
	}

	_, err = issueOne(t, mgr, root.ID, "a2.example.com")
	var quota *models.QuotaExceededError
	if !errors.As(err, &quota) || quota.Quota != models.QuotaActiveCerts {
		t.Fatalf("issue at ceiling: err = %v, want QuotaExceededError{active_certs}", err)
	}
	if quota.RetryAfter != 0 {
		t.Errorf("active-ceiling RetryAfter = %v, want 0 (not time-based)", quota.RetryAfter)
	}

	// Revoking the first certificate frees room immediately.
	if _, err := mgr.RevokeCertificate(context.Background(), root.ID, first.Serial.String(), "superseded"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := issueOne(t, mgr, root.ID, "a3.example.com"); err != nil {
		t.Errorf("issuance after revocation freed the ceiling: %v", err)
	}

	// Revocation accounting recorded the withdrawal.
	day := database.UsageDay(time.Now())
	usage, err := mgr.db.GetTenantUsageDay(tn.ID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if usage.CertsRevoked != 1 {
		t.Errorf("certs_revoked = %d, want 1", usage.CertsRevoked)
	}
	if usage.CertsIssued != 2 {
		t.Errorf("certs_issued = %d, want 2", usage.CertsIssued)
	}
}

// TestTenantUsageAccountsUnlimitedTenants: accounting continues when no quota
// is configured, so usage reports work for unlimited tenants too.
func TestTenantUsageAccountsUnlimitedTenants(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	tn := newTenant(t, mgr, "unlim", models.TenantQuotas{})
	root := newTenantRoot(t, mgr, tn.ID, "unlim")

	for _, cn := range []string{"u1.example.com", "u2.example.com", "u3.example.com"} {
		if _, err := issueOne(t, mgr, root.ID, cn); err != nil {
			t.Fatalf("issuing %s: %v", cn, err)
		}
	}
	day := database.UsageDay(time.Now())
	usage, err := mgr.db.GetTenantUsageDay(tn.ID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if usage.CertsIssued != 3 {
		t.Errorf("certs_issued = %d, want 3", usage.CertsIssued)
	}
	active, err := mgr.db.CountActiveCertificatesForTenant(tn.ID, time.Now())
	if err != nil {
		t.Fatalf("CountActiveCertificatesForTenant: %v", err)
	}
	if active != 3 {
		t.Errorf("active certs = %d, want 3", active)
	}
}
