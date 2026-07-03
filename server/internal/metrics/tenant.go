package metrics

import "sync"

// Tenant-labeled metrics (Task 61).
//
// Unlike every other label in this registry, a tenant ID is operator data, not
// a bounded enum — an unbounded label would let tenant churn (or a
// misconfigured client spraying selectors) grow the registry without limit, the
// classic Prometheus cardinality blowout. TenantLabel is the guard: it admits
// up to maxTenantLabelSeries distinct tenant values and folds everything beyond
// into the single "_other_" bucket. Admission is first-come-first-served and
// permanent for the process lifetime, which keeps series stable for dashboards.

// maxTenantLabelSeries bounds how many distinct tenant label values may exist.
// Deployments with more active tenants than this see the busiest newcomers
// aggregated under "_other_"; per-tenant exactness is then available from the
// usage API rather than metrics.
const maxTenantLabelSeries = 100

// TenantOverflowLabel is the fold-over bucket for tenants beyond the guard.
const TenantOverflowLabel = "_other_"

var tenantLabelMu sync.Mutex
var tenantLabelSeen = make(map[string]struct{})

// TenantLabel returns the metric label to use for a tenant ID, applying the
// cardinality guard. An empty ID reports as "unknown".
func TenantLabel(tenantID string) string {
	if tenantID == "" {
		return "unknown"
	}
	tenantLabelMu.Lock()
	defer tenantLabelMu.Unlock()
	if _, ok := tenantLabelSeen[tenantID]; ok {
		return tenantID
	}
	if len(tenantLabelSeen) >= maxTenantLabelSeries {
		return TenantOverflowLabel
	}
	tenantLabelSeen[tenantID] = struct{}{}
	return tenantID
}

// resetTenantLabels clears the guard (tests only).
func resetTenantLabels() {
	tenantLabelMu.Lock()
	defer tenantLabelMu.Unlock()
	tenantLabelSeen = make(map[string]struct{})
}

var (
	// TenantCertsIssued counts certificates issued per tenant (X.509 leaves and
	// SSH certificates), incremented on successful issuance.
	TenantCertsIssued = NewCounter(Default,
		"secsy_tenant_certificates_issued_total",
		"Certificates issued per tenant (cardinality-guarded label).",
		"tenant")
	// TenantSecretOps counts envelope operations per tenant.
	TenantSecretOps = NewCounter(Default,
		"secsy_tenant_secret_ops_total",
		"Envelope encrypt/decrypt operations per tenant (cardinality-guarded label).",
		"tenant", "operation")
	// TenantDenied counts operations refused by tenant lifecycle or quota
	// enforcement. reason is bounded: suspended|certs_per_day|active_certs|
	// secret_ops_per_day|rate_limit.
	TenantDenied = NewCounter(Default,
		"secsy_tenant_denied_total",
		"Operations refused by tenant suspension or quota enforcement, by tenant and reason.",
		"tenant", "reason")
)
