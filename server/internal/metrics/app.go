package metrics

import "time"

// Default is the process-wide registry that all application metrics register on
// and that the /metrics endpoint serves.
var Default = NewRegistry()

// Result label values shared across counters so dashboards can slice by outcome
// consistently.
const (
	ResultSuccess = "success"
	ResultError   = "error"
	ResultDenied  = "denied"
)

// The application metrics. They are package-level so any layer (handlers, CA
// manager, keyprovider wrapper, middleware) can record without threading a
// registry through every call site — matching how the audit log and RBAC are
// reached. All are registered on Default at init.
var (
	// HTTP request accounting.
	HTTPRequests = NewCounter(Default,
		"secsy_http_requests_total",
		"Total HTTP requests handled, partitioned by method, route, and status code.",
		"method", "route", "status")
	HTTPDuration = NewHistogram(Default,
		"secsy_http_request_duration_seconds",
		"HTTP request handling latency in seconds, partitioned by method and route.",
		DefBuckets, "method", "route")
	HTTPInFlight = NewGauge(Default,
		"secsy_http_requests_in_flight",
		"Number of HTTP requests currently being served.")

	// Certificate lifecycle. The "operation" label is issue|renew|revoke and the
	// "result" label is success|error|denied.
	Certificates = NewCounter(Default,
		"secsy_certificates_total",
		"Certificate lifecycle operations, partitioned by operation and result.",
		"operation", "result")

	// Revocation-data serving.
	OCSPRequests = NewCounter(Default,
		"secsy_ocsp_requests_total",
		"OCSP responder requests, partitioned by result.",
		"result")
	CRLRequests = NewCounter(Default,
		"secsy_crl_requests_total",
		"CRL distribution requests, partitioned by result.",
		"result")

	// HSM / key-provider operations. The "operation" label is sign|decrypt|
	// generate|find|public_key; "result" is success|error.
	HSMOperations = NewCounter(Default,
		"secsy_hsm_operations_total",
		"Key-provider (HSM/PKCS#11 or software) operations, by operation and result.",
		"operation", "result")
	HSMDuration = NewHistogram(Default,
		"secsy_hsm_operation_duration_seconds",
		"Key-provider operation latency in seconds, partitioned by operation.",
		DefBuckets, "operation")

	// Envelope encryption for the secret feature. "operation" is encrypt|decrypt.
	Envelope = NewCounter(Default,
		"secsy_envelope_operations_total",
		"HSM-backed envelope encryption operations, by operation and result.",
		"operation", "result")

	// RBAC authorization decisions. "action" is the coarse capability checked;
	// "decision" is allow|deny.
	AuthzDecisions = NewCounter(Default,
		"secsy_authz_decisions_total",
		"RBAC authorization decisions, partitioned by action and decision.",
		"action", "decision")

	// Readiness. 1 = the dependency is healthy, 0 = unhealthy.
	Up = NewGauge(Default,
		"secsy_component_up",
		"Health of a subsystem probed by the readiness check (1 = up, 0 = down).",
		"component")

	// Certificate expiry monitoring. CertsExpiring is refreshed on every monitor
	// scan and reports how many unexpired certificates fall into each severity
	// window (warning|critical) plus how many have already expired. It lets
	// dashboards alert on an approaching expiry cliff.
	CertsExpiring = NewGauge(Default,
		"secsy_certificates_expiring",
		"Certificates within a monitored expiry window as of the last scan, by severity (warning|critical|expired).",
		"severity")
	// AutoRenewals counts certificates the monitor reissued ahead of expiry,
	// partitioned by outcome (success|error).
	AutoRenewals = NewCounter(Default,
		"secsy_certificate_auto_renewals_total",
		"Certificates auto-renewed by the expiry monitor, by result.",
		"result")
	// MonitorScans counts monitor scan cycles, partitioned by outcome.
	MonitorScans = NewCounter(Default,
		"secsy_certificate_monitor_scans_total",
		"Certificate-expiry monitor scan cycles, by result.",
		"result")
	// MonitorLastScan records the wall-clock time of the last completed scan so
	// operators can alert if the monitor stops running.
	MonitorLastScan = NewGauge(Default,
		"secsy_certificate_monitor_last_scan_timestamp_seconds",
		"Unix timestamp (seconds) of the last completed certificate-expiry monitor scan.")
)

// Decision label values for AuthzDecisions.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// ObserveHSM records the latency and outcome of a key-provider operation. Pass
// the operation name (sign, decrypt, generate, find, public_key), the time the
// operation started, and whether it errored.
func ObserveHSM(operation string, start time.Time, err error) {
	HSMDuration.Observe(time.Since(start).Seconds(), operation)
	if err != nil {
		HSMOperations.Inc(operation, ResultError)
	} else {
		HSMOperations.Inc(operation, ResultSuccess)
	}
}

// RecordAuthz records an RBAC decision.
func RecordAuthz(action string, allowed bool) {
	if allowed {
		AuthzDecisions.Inc(action, DecisionAllow)
	} else {
		AuthzDecisions.Inc(action, DecisionDeny)
	}
}

// resultLabel maps an error to the success/error result label.
func resultLabel(err error) string {
	if err != nil {
		return ResultError
	}
	return ResultSuccess
}

// RecordCertificate records a certificate lifecycle operation outcome.
func RecordCertificate(operation string, err error) {
	Certificates.Inc(operation, resultLabel(err))
}

// RecordEnvelope records an envelope encrypt/decrypt outcome.
func RecordEnvelope(operation string, err error) {
	Envelope.Inc(operation, resultLabel(err))
}

// RecordAutoRenew records the outcome of an auto-renewal attempt.
func RecordAutoRenew(err error) {
	AutoRenewals.Inc(resultLabel(err))
}
