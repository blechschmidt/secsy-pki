package ca

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Per-tenant issuance gate (Task 61).
//
// Every certificate-minting path — REST issue/renew, ACME finalize, SCEP, EST,
// CMP, gRPC, SVID (all of which funnel into issueLeaf / the PQC leaf paths) and
// the SSH CA — passes through this gate before the HSM signs anything. It
// enforces, fail-closed:
//
//   - tenant lifecycle: a suspended tenant cannot obtain new certificates. Its
//     existing certificates keep working, and the revocation/CRL/OCSP paths are
//     deliberately NOT gated so relying parties can still validate (and the
//     operator can still revoke) while the tenant is suspended;
//   - max_active_certs: a ceiling on the tenant's live X.509 inventory;
//   - max_certs_per_day: a reservation-style daily counter — consumed before
//     signing and released again if issuance fails afterwards, so the counter
//     tracks certificates actually issued.
//
// "Fail-closed" means any error reading tenant or quota state refuses issuance
// rather than admitting it; a store outage can therefore pause issuance but can
// never let a suspended or over-quota tenant mint certificates.

// UntilNextUTCDay reports how long until the daily quota windows reset (UTC
// midnight), used as the Retry-After hint on quota-exceeded responses.
func UntilNextUTCDay(now time.Time) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	return next.Sub(now)
}

// GateTenantIssuance checks the issuing CA's tenant against its lifecycle
// state and issuance quotas, reserving one unit of the daily certificate
// quota. On admission it returns a non-nil done callback the caller MUST
// invoke with the final issuance error: done(nil) commits the reservation (and
// the per-tenant metric); done(err) releases it so failed signings do not burn
// quota. It is shared by every X.509 leaf path via Manager and by the SSH
// certificate authority, which mints from the same tenant-owned CA records.
func GateTenantIssuance(db *database.DB, issuerCA *models.CA, requestedBy string) (done func(issueErr error), err error) {
	tenantID := issuerCA.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}

	tenant, err := db.GetTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant state unavailable, refusing issuance (fail-closed): %w", err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant %q of CA %q not found, refusing issuance (fail-closed)", tenantID, issuerCA.Label)
	}

	if tenant.Status != models.TenantStatusActive {
		recordTenantGateEvent(db, tenant, issuerCA, requestedBy, "status="+tenant.Status)
		metrics.TenantDenied.Inc(metrics.TenantLabel(tenantID), "suspended")
		return nil, &models.TenantSuspendedError{TenantID: tenantID}
	}

	now := time.Now()

	// Inventory ceiling. Checked read-only against the live certificate count;
	// revocation or expiry frees room immediately. Retrying is only useful after
	// that happens, so no Retry-After window is suggested.
	if max := tenant.Quotas.MaxActiveCerts; max > 0 {
		active, err := db.CountActiveCertificatesForTenant(tenantID, now)
		if err != nil {
			return nil, fmt.Errorf("active-certificate count unavailable, refusing issuance (fail-closed): %w", err)
		}
		if active >= max {
			recordTenantGateEvent(db, tenant, issuerCA, requestedBy,
				fmt.Sprintf("quota=%s active=%d limit=%d", models.QuotaActiveCerts, active, max))
			metrics.TenantDenied.Inc(metrics.TenantLabel(tenantID), models.QuotaActiveCerts)
			return nil, &models.QuotaExceededError{TenantID: tenantID, Quota: models.QuotaActiveCerts, Limit: max}
		}
	}

	// Daily issuance counter: reserve one unit atomically. With no ceiling
	// configured this still increments, so usage reporting keeps working for
	// unlimited tenants.
	day := database.UsageDay(now)
	limit := tenant.Quotas.MaxCertsPerDay
	ok, err := db.ConsumeTenantDailyQuota(tenantID, day, database.UsageCertsIssued, limit)
	if err != nil {
		return nil, fmt.Errorf("issuance quota state unavailable, refusing issuance (fail-closed): %w", err)
	}
	if !ok {
		recordTenantGateEvent(db, tenant, issuerCA, requestedBy,
			fmt.Sprintf("quota=%s limit=%d day=%s", models.QuotaCertsPerDay, limit, day))
		metrics.TenantDenied.Inc(metrics.TenantLabel(tenantID), models.QuotaCertsPerDay)
		return nil, &models.QuotaExceededError{
			TenantID:   tenantID,
			Quota:      models.QuotaCertsPerDay,
			Limit:      limit,
			RetryAfter: UntilNextUTCDay(now),
		}
	}

	return func(issueErr error) {
		if issueErr != nil {
			if relErr := db.ReleaseTenantDailyQuota(tenantID, day, database.UsageCertsIssued); relErr != nil {
				log.Printf("WARNING: failed to release tenant %q daily issuance quota: %v", tenantID, relErr)
			}
			return
		}
		metrics.TenantCertsIssued.Inc(metrics.TenantLabel(tenantID))
	}, nil
}

// gateTenantIssuance is the Manager-bound convenience over GateTenantIssuance.
func (m *Manager) gateTenantIssuance(_ context.Context, issuerCA *models.CA, requestedBy string) (func(error), error) {
	return GateTenantIssuance(m.db, issuerCA, requestedBy)
}

// ensureTenantActive checks only the issuing CA's tenant lifecycle state,
// fail-closed, without reserving any quota. It is used by issuance paths that
// mint ephemeral, non-inventory credentials (JWT-SVIDs) which must still be
// frozen for a suspended tenant but must not consume the certificate quota.
func (m *Manager) ensureTenantActive(issuerCA *models.CA) error {
	tenantID := issuerCA.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	tenant, err := m.db.GetTenant(tenantID)
	if err != nil {
		return fmt.Errorf("tenant state unavailable, refusing issuance (fail-closed): %w", err)
	}
	if tenant == nil {
		return fmt.Errorf("tenant %q of CA %q not found, refusing issuance (fail-closed)", tenantID, issuerCA.Label)
	}
	if tenant.Status != models.TenantStatusActive {
		return &models.TenantSuspendedError{TenantID: tenantID}
	}
	return nil
}

// accountTenantRevocation records a revocation in the tenant's daily usage
// counters. Pure accounting — revocation is never quota-gated (a suspended or
// over-quota tenant must always be able to revoke).
func (m *Manager) accountTenantRevocation(caID string) {
	tenantID, err := m.db.GetCATenant(caID)
	if err != nil || tenantID == "" {
		if err != nil {
			log.Printf("WARNING: could not resolve tenant of CA %q for revocation accounting: %v", caID, err)
		}
		return
	}
	if err := m.db.AddTenantUsage(tenantID, database.UsageDay(time.Now()), database.UsageCertsRevoked, 1); err != nil {
		log.Printf("WARNING: failed to account revocation for tenant %q: %v", tenantID, err)
	}
}

// recordTenantGateEvent appends a tamper-evident audit event for a refusal by
// the tenant issuance gate.
func recordTenantGateEvent(db *database.DB, tenant *models.Tenant, issuerCA *models.CA, requestedBy, detail string) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionTenantQuota,
		Tenant:     tenant.ID,
		Target:     issuerCA.ID,
		TargetName: issuerCA.Label,
		Result:     audit.ResultDenied,
		Detail:     detail,
	}
	if err := db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append tenant.quota audit event: %v", err)
	}
}
