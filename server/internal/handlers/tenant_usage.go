package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Tenant quotas and usage (Task 61): the REST surface over the fail-closed
// issuance/secret gates — quota administration, the usage report, and the
// shared HTTP error mapping for gate refusals.

// writeTenantLimitError maps a tenant-gate refusal to its HTTP semantics:
// suspension → 403, quota exhaustion → 429 with a code of "quota_exceeded" and
// a Retry-After header when the quota window resets on its own (daily quotas
// reset at UTC midnight; the active-certificate ceiling does not, so it carries
// no Retry-After). It reports whether err was such a refusal; any other error
// is left for the caller's default handling.
func writeTenantLimitError(w http.ResponseWriter, err error) bool {
	var susp *models.TenantSuspendedError
	if errors.As(err, &susp) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": susp.Error(),
			"code":  "tenant_suspended",
		})
		return true
	}
	var quota *models.QuotaExceededError
	if errors.As(err, &quota) {
		if quota.RetryAfter > 0 {
			secs := int(math.Ceil(quota.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": quota.Error(),
			"code":  "quota_exceeded",
			"quota": quota.Quota,
		})
		return true
	}
	return false
}

// gateTenantIssuance exposes the shared tenant issuance gate to handlers whose
// local CA variable shadows the ca package name.
func (a *API) gateTenantIssuance(caRec *models.CA, requestedBy string) (func(error), error) {
	return ca.GateTenantIssuance(a.db, caRec, requestedBy)
}

// requireActiveTenant loads a tenant and refuses suspended ones with the typed
// gate error, for mutating operations outside the issuance path (CA creation).
func (a *API) requireActiveTenant(tenantID string) (*models.Tenant, error) {
	t, err := a.db.GetTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant lookup failed: %w", err)
	}
	if t == nil {
		return nil, nil
	}
	if t.Status != models.TenantStatusActive {
		metrics.TenantDenied.Inc(metrics.TenantLabel(t.ID), "suspended")
		return nil, &models.TenantSuspendedError{TenantID: t.ID}
	}
	return t, nil
}

// consumeSecretOpQuota reserves one unit of the tenant's daily secret-op quota
// (fail-closed). On admission it returns a done callback the handler must
// invoke with the operation's final error: done(nil) commits the unit and the
// per-tenant metric, done(err) releases the reservation.
func (a *API) consumeSecretOpQuota(r *http.Request, tenant *models.Tenant, operation string) (func(opErr error), error) {
	return a.consumeSecretOpQuotaCtx(r.Context(), clientIP(r), tenant, operation)
}

// consumeSecretOpQuotaCtx is the context-based core of consumeSecretOpQuota so a
// non-HTTP transport (the gRPC SecretService, Task 138) meters the same
// per-tenant daily secret-op quota. ip is the client address recorded on the
// denied audit event.
func (a *API) consumeSecretOpQuotaCtx(ctx context.Context, ip string, tenant *models.Tenant, operation string) (func(opErr error), error) {
	now := time.Now()
	day := database.UsageDay(now)
	limit := tenant.Quotas.MaxSecretOpsPerDay
	ok, err := a.db.ConsumeTenantDailyQuota(tenant.ID, day, database.UsageSecretOps, limit)
	if err != nil {
		return nil, fmt.Errorf("secret-op quota state unavailable, refusing operation (fail-closed): %w", err)
	}
	if !ok {
		metrics.TenantDenied.Inc(metrics.TenantLabel(tenant.ID), models.QuotaSecretOpsPerDay)
		a.recordEventCtx(ctx, ip, audit.ActionTenantQuota, tenant.ID, tenant.Slug, audit.ResultDenied,
			fmt.Sprintf("quota=%s limit=%d day=%s", models.QuotaSecretOpsPerDay, limit, day))
		return nil, &models.QuotaExceededError{
			TenantID:   tenant.ID,
			Quota:      models.QuotaSecretOpsPerDay,
			Limit:      limit,
			RetryAfter: ca.UntilNextUTCDay(now),
		}
	}
	return func(opErr error) {
		if opErr != nil {
			if relErr := a.db.ReleaseTenantDailyQuota(tenant.ID, day, database.UsageSecretOps); relErr != nil {
				log.Printf("WARNING: failed to release tenant %q secret-op quota: %v", tenant.ID, relErr)
			}
			return
		}
		metrics.TenantSecretOps.Inc(metrics.TenantLabel(tenant.ID), operation)
	}, nil
}

// UpdateTenant modifies a tenant's display name, KEK label, and/or quotas.
// Platform-admin only, audited. Fields absent from the request are left
// unchanged; quotas, when present, replace the whole quota set (zero values
// mean unlimited).
func (a *API) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.isPlatformAdmin(user) {
		a.recordEvent(r, audit.ActionTenantUpdate, r.PathValue("id"), "", audit.ResultDenied, "platform admin required")
		writeError(w, http.StatusForbidden, "platform admin required to update tenants")
		return
	}
	id := r.PathValue("id")
	t, err := a.db.GetTenant(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	}
	if t == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}

	var req struct {
		Name     *string              `json:"name"`
		KEKLabel *string              `json:"kek_label"`
		Quotas   *models.TenantQuotas `json:"quotas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Name != nil {
		if *req.Name == "" {
			writeError(w, http.StatusBadRequest, "name cannot be empty")
			return
		}
		t.Name = *req.Name
	}
	if req.KEKLabel != nil {
		t.KEKLabel = *req.KEKLabel
	}
	if req.Quotas != nil {
		q := *req.Quotas
		if q.MaxCertsPerDay < 0 || q.MaxActiveCerts < 0 || q.MaxSecretOpsPerDay < 0 ||
			q.RateLimitPerSecond < 0 || q.RateLimitBurst < 0 {
			writeError(w, http.StatusBadRequest, "quota values cannot be negative (0 = unlimited)")
			return
		}
		t.Quotas = q
	}

	if err := a.db.UpdateTenant(t); err != nil {
		a.recordEvent(r, audit.ActionTenantUpdate, t.ID, t.Slug, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to update tenant: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionTenantUpdate, t.ID, t.Slug, audit.ResultSuccess,
		fmt.Sprintf("name=%s quotas={certs_per_day:%d active:%d secret_ops:%d rate:%g burst:%g}",
			t.Name, t.Quotas.MaxCertsPerDay, t.Quotas.MaxActiveCerts, t.Quotas.MaxSecretOpsPerDay,
			t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst))
	writeJSON(w, http.StatusOK, t)
}

// maxUsageReportDays bounds the rolling window a usage report may cover.
const maxUsageReportDays = 90

// TenantUsage serves the per-tenant usage report: live inventory counts plus a
// rolling window of daily accounting rows. Platform admins may read any
// tenant; tenant members only their own (others 404, not 403, so tenant
// existence is not disclosed — matching GetTenant).
func (a *API) TenantUsage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	id := r.PathValue("id")
	t, err := a.db.GetTenant(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant lookup failed: %v", err)
		return
	}
	if t == nil || (!a.isPlatformAdmin(user) && !a.isTenantMember(user, id)) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	middleware.SetTenant(r.Context(), t.ID)

	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxUsageReportDays {
			writeError(w, http.StatusBadRequest, "days must be an integer between 1 and %d", maxUsageReportDays)
			return
		}
		days = n
	}

	report, err := a.buildTenantUsageReport(t, days, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "building usage report: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// buildTenantUsageReport assembles the usage report for a tenant covering the
// last `days` UTC days (today included). Days without recorded activity are
// filled with zero rows so the window is always dense and ordered (newest
// first).
func (a *API) buildTenantUsageReport(t *models.Tenant, days int, now time.Time) (*models.TenantUsageReport, error) {
	nowUTC := now.UTC()
	since := database.UsageDay(nowUTC.AddDate(0, 0, -(days - 1)))

	recorded, err := a.db.ListTenantUsageDays(t.ID, since)
	if err != nil {
		return nil, fmt.Errorf("reading usage window: %w", err)
	}
	byDay := make(map[string]models.TenantUsageDay, len(recorded))
	for _, d := range recorded {
		byDay[d.Day] = d
	}
	window := make([]models.TenantUsageDay, 0, days)
	for i := 0; i < days; i++ {
		day := database.UsageDay(nowUTC.AddDate(0, 0, -i))
		if d, ok := byDay[day]; ok {
			window = append(window, d)
		} else {
			window = append(window, models.TenantUsageDay{Day: day})
		}
	}

	active, err := a.db.CountActiveCertificatesForTenant(t.ID, nowUTC)
	if err != nil {
		return nil, fmt.Errorf("counting active certificates: %w", err)
	}
	total, revoked, err := a.db.TenantCertificateTotals(t.ID)
	if err != nil {
		return nil, fmt.Errorf("reading certificate totals: %w", err)
	}
	cas, err := a.db.CountCAsForTenant(t.ID)
	if err != nil {
		return nil, fmt.Errorf("counting CAs: %w", err)
	}

	return &models.TenantUsageReport{
		TenantID:     t.ID,
		Slug:         t.Slug,
		Status:       t.Status,
		ActiveCerts:  active,
		TotalIssued:  total,
		TotalRevoked: revoked,
		CAs:          cas,
		Today:        window[0],
		Days:         window,
		Quotas:       t.Quotas,
		GeneratedAt:  nowUTC,
	}, nil
}
