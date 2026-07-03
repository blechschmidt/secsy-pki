package metrics

import "time"

// Default is the process-wide registry that all application metrics register on
// and that the /metrics endpoint serves.
var Default = NewRegistry()

// Result label values shared across counters so dashboards can slice by outcome
// consistently.
const (
	ResultSuccess  = "success"
	ResultError    = "error"
	ResultDenied   = "denied"
	ResultNotFound = "not_found"
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

	// Pre-issuance certificate linting (CA/Browser Forum Baseline Requirements
	// gate). CertificateLints counts every lint run by outcome: "result" is
	// pass|warn|fail (fail = an enforce-mode check blocked signing).
	// CertificateLintFindings counts individual findings by check "code" and
	// "mode" (enforce|warn) for fine-grained alerting on policy violations.
	CertificateLints = NewCounter(Default,
		"secsy_certificate_lints_total",
		"Pre-issuance certificate lint runs, partitioned by outcome (pass|warn|fail).",
		"result")
	CertificateLintFindings = NewCounter(Default,
		"secsy_certificate_lint_findings_total",
		"Pre-issuance certificate lint findings, partitioned by check code and mode.",
		"code", "mode")

	// Pre-issuance CAA checking (RFC 8659 Certification Authority Authorization
	// gate). CertificateCAAChecks counts every check run by outcome: "result" is
	// pass|fail|skip|error (fail = a forbidding CAA set blocked signing under
	// enforce mode, skip = the certificate had no DNS-name SANs, error = a lookup
	// or configuration failure). CertificateCAAFindings counts individual
	// forbidding names by "reason" (forbidden|critical_unknown|lookup_error).
	CertificateCAAChecks = NewCounter(Default,
		"secsy_certificate_caa_checks_total",
		"Pre-issuance CAA checks, partitioned by outcome (pass|fail|skip|error).",
		"result")
	CertificateCAAFindings = NewCounter(Default,
		"secsy_certificate_caa_findings_total",
		"Pre-issuance CAA findings that forbid issuance, partitioned by reason.",
		"reason")

	// Pre-issuance Name Constraints checking (RFC 5280 §4.2.1.10 gate).
	// CertificateNameConstraintChecks counts every run by outcome: "result" is
	// pass|fail|error (fail = the issuing CA's constraints rejected the leaf,
	// error = the CA's own extension could not be parsed — fail-closed).
	// CertificateNameConstraintViolations counts individual forbidding names by
	// "kind" ("<type>:<reason>", e.g. "dns:not-permitted", "ip:excluded").
	CertificateNameConstraintChecks = NewCounter(Default,
		"secsy_certificate_name_constraint_checks_total",
		"Pre-issuance name-constraint checks, partitioned by outcome (pass|fail|error).",
		"result")
	CertificateNameConstraintViolations = NewCounter(Default,
		"secsy_certificate_name_constraint_violations_total",
		"Pre-issuance name-constraint violations that forbid issuance, partitioned by kind.",
		"kind")

	// Enrollment key-attestation checking (Task 49 gate on the EST/SCEP/ACME
	// device-enrollment paths). AttestationChecks counts every check by protocol
	// ("est"|"scep"|"acme"), the applied "mode" (off|permissive|require), and the
	// outcome "result": "pass" (a hardware attestation verified), "missing" (no
	// attestation was presented), "invalid" (an attestation was present but did
	// not verify), or "skip" (mode was off). AttestationVerified breaks verified
	// attestations down by hardware "format" (yubikey-piv|tpm|apple|cert-chain).
	AttestationChecks = NewCounter(Default,
		"secsy_attestation_checks_total",
		"Enrollment key-attestation checks, partitioned by protocol, mode, and result.",
		"protocol", "mode", "result")
	AttestationVerified = NewCounter(Default,
		"secsy_attestation_verified_total",
		"Verified enrollment key attestations, partitioned by hardware format.",
		"format")
	// AttestationDenied counts enrollments blocked fail-closed because a required
	// attestation was missing or invalid, partitioned by protocol.
	AttestationDenied = NewCounter(Default,
		"secsy_attestation_denied_total",
		"Enrollments denied because a required key attestation was missing or invalid, by protocol.",
		"protocol")

	// SSH certificate authority (Task 57). SSHCertificates counts signing
	// operations by certificate "type" (user|host) and "result"; SSHRevocations
	// counts revocation operations by result; SSHKRLRequests counts KRL builds/
	// fetches by result, tracking how relying hosts consume revocation data.
	SSHCertificates = NewCounter(Default,
		"secsy_ssh_certificates_total",
		"SSH certificate signing operations, partitioned by certificate type and result.",
		"type", "result")
	SSHRevocations = NewCounter(Default,
		"secsy_ssh_revocations_total",
		"SSH certificate revocations, partitioned by result.",
		"result")
	SSHKRLRequests = NewCounter(Default,
		"secsy_ssh_krl_requests_total",
		"SSH key-revocation-list (KRL) generations and fetches, partitioned by result.",
		"result")

	// Revocation-data serving.
	OCSPRequests = NewCounter(Default,
		"secsy_ocsp_requests_total",
		"OCSP responder requests, partitioned by result.",
		"result")
	// OCSPNonce counts OCSP requests by how their nonce was handled: "echoed"
	// (a valid nonce was reflected in the signed response), "absent" (no nonce
	// present), or "rejected" (a nonce violated the RFC 8954 length bounds and
	// the request was answered malformed). A nonce-bearing request bypasses the
	// response cache, so this also tracks cache-bypass demand.
	OCSPNonce = NewCounter(Default,
		"secsy_ocsp_nonce_total",
		"OCSP requests partitioned by nonce handling (echoed|absent|rejected).",
		"handling")
	// OCSPSigner counts signed OCSP responses by which key signed them: the CA
	// key directly ("ca") or a short-lived delegated OCSP-signing certificate
	// ("delegated").
	OCSPSigner = NewCounter(Default,
		"secsy_ocsp_signer_total",
		"Signed OCSP responses partitioned by signing key (ca|delegated).",
		"signer")
	// OCSPStaples counts TLS OCSP staples produced for the server's own
	// certificate(s), by result.
	OCSPStaples = NewCounter(Default,
		"secsy_ocsp_staples_total",
		"TLS OCSP staples generated for the server's own certificate, by result.",
		"result")
	CRLRequests = NewCounter(Default,
		"secsy_crl_requests_total",
		"CRL distribution requests, partitioned by result.",
		"result")
	// CRLGenerated counts freshly HSM-signed CRLs by "kind" (base|delta) and
	// "scope" (full|partition). Because base/delta CRLs are cached and re-served
	// between regenerations, this tracks HSM signing load, not request volume.
	CRLGenerated = NewCounter(Default,
		"secsy_crl_generated_total",
		"CRLs freshly signed on the HSM, by kind (base|delta) and scope (full|partition).",
		"kind", "scope")

	// RFC 3161 time-stamping. "result" is granted|rejected|error; the token is
	// signed on the HSM, so this tracks TSA demand and rejection rates.
	TimestampRequests = NewCounter(Default,
		"secsy_timestamp_requests_total",
		"RFC 3161 time-stamp requests, partitioned by result (granted|rejected|error).",
		"result")

	// ACME Renewal Information (ARI, draft-ietf-acme-ari). ACMERenewalInfo counts
	// renewalInfo lookups by "result": hit (window served), not_found (unknown
	// certificate), or error. The "window" label distinguishes a normal suggested
	// window from a shortened one (normal|revoked|rotating) so operators can see
	// forced-renewal signals. ACMEReplaces counts newOrder requests that carried a
	// "replaces" ARI CertID, by "result" (linked|rejected).
	ACMERenewalInfo = NewCounter(Default,
		"secsy_acme_renewal_info_total",
		"ACME Renewal Information (ARI) lookups served, by result and suggested-window kind.",
		"result", "window")
	ACMEReplaces = NewCounter(Default,
		"secsy_acme_order_replaces_total",
		"ACME newOrder requests carrying an ARI \"replaces\" CertID, by result (linked|rejected).",
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

	// Multi-token HSM high availability (Task 44). When several PKCS#11 tokens
	// stand behind one provider, these expose per-token health and failover
	// activity so operators can alert when a token drops out and confirm the
	// backup is carrying the load.
	//
	// HSMTokenUp is each token's live health: 1 = healthy and in rotation, 0 =
	// marked unhealthy and failed over away from. HSMTokenFailovers counts
	// operations that erred on a token and were retried on another, labelled by
	// the token that was failed away from. HSMTokenErrors counts operation errors
	// charged to a token's health (logical key-not-found is excluded), by token.
	HSMTokenUp = NewGauge(Default,
		"secsy_hsm_token_up",
		"Per-token HSM health for multi-token failover (1 = healthy/in rotation, 0 = unhealthy).",
		"token")
	HSMTokenFailovers = NewCounter(Default,
		"secsy_hsm_token_failovers_total",
		"Key-provider operations that failed on a token and were retried on another, by the token failed away from.",
		"token")
	HSMTokenErrors = NewCounter(Default,
		"secsy_hsm_token_errors_total",
		"Key-provider operation errors charged to a token's health (excludes key-not-found), by token.",
		"token")

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

	// Operator authentication (Task 50). AuthLogins counts login attempts by
	// method (oidc|password|mtls) and result (success|error). AuthLogouts counts
	// session terminations. AuthStepUps counts WebAuthn step-up outcomes by result
	// (success|error|denied). AuthSessionsActive tracks live console sessions.
	AuthLogins = NewCounter(Default,
		"secsy_auth_logins_total",
		"Operator authentication attempts, partitioned by method and result.",
		"method", "result")
	AuthLogouts = NewCounter(Default,
		"secsy_auth_logouts_total",
		"Operator session terminations (logout or expiry).")
	AuthStepUps = NewCounter(Default,
		"secsy_auth_step_ups_total",
		"WebAuthn step-up attempts for high-risk operations, partitioned by result.",
		"result")
	AuthSessionsActive = NewGauge(Default,
		"secsy_auth_sessions_active",
		"Number of live operator console sessions.")

	// Rate limiting for the public endpoints. Throttled counts requests rejected
	// by a token-bucket tier, partitioned by endpoint class (acme_new_order,
	// ocsp, enroll, ...) and the tier that rejected it (global|per_ip|
	// per_account). Admitted counts requests that passed all tiers, by endpoint.
	RateLimitThrottled = NewCounter(Default,
		"secsy_ratelimit_throttled_total",
		"Public-endpoint requests rejected by a rate-limit tier, by endpoint class and tier.",
		"endpoint", "tier")
	RateLimitAdmitted = NewCounter(Default,
		"secsy_ratelimit_admitted_total",
		"Public-endpoint requests admitted by the rate limiter (passed all tiers), by endpoint class.",
		"endpoint")

	// HSM in-flight concurrency guard. Rejected counts requests shed before
	// reaching the session pool, by endpoint and reason (queue_full|timeout|
	// canceled). InFlight and QueueDepth expose live saturation so operators can
	// alert before requests are shed.
	HSMGuardRejected = NewCounter(Default,
		"secsy_hsm_guard_rejected_total",
		"Requests rejected by the HSM in-flight concurrency guard, by endpoint and reason.",
		"endpoint", "reason")
	HSMGuardInFlight = NewGauge(Default,
		"secsy_hsm_guard_in_flight",
		"HSM-bound requests currently holding a concurrency-guard slot.")
	HSMGuardQueueDepth = NewGauge(Default,
		"secsy_hsm_guard_queue_depth",
		"HSM-bound requests currently waiting for a concurrency-guard slot.")

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

	// Audit-log SIEM export. Each series is partitioned by the sink name so an
	// operator can tell which downstream (syslog/CEF/webhook) is falling behind.
	//
	// AuditExportLag is the number of sealed audit events not yet acknowledged by
	// the sink (head sequence minus the durable cursor). It is the primary alert
	// signal: a steadily climbing lag means a sink is down or backpressured.
	AuditExportLag = NewGauge(Default,
		"secsy_audit_export_lag_events",
		"Audit events sealed but not yet delivered to a SIEM sink (head seq minus cursor), by sink.",
		"sink")
	// AuditExportCursor exposes the durable cursor (last successfully delivered
	// sequence number) so restarts and redelivery windows are observable.
	AuditExportCursor = NewGauge(Default,
		"secsy_audit_export_cursor_seq",
		"Highest audit event sequence number durably delivered to a SIEM sink, by sink.",
		"sink")
	// AuditExportEvents counts individual audit events handed to a sink, by
	// outcome. delivered = acknowledged (cursor advanced); failed = a delivery
	// attempt errored and will be retried (at-least-once).
	AuditExportEvents = NewCounter(Default,
		"secsy_audit_export_events_total",
		"Audit events processed by the SIEM exporter, by sink and result (delivered|failed).",
		"sink", "result")
	// AuditExportBatchFailures counts failed delivery attempts (batches), by sink.
	// Distinct from AuditExportEvents{result=failed}, which counts events.
	AuditExportBatchFailures = NewCounter(Default,
		"secsy_audit_export_batch_failures_total",
		"Failed SIEM export delivery attempts (batches) that will be retried, by sink.",
		"sink")
	// AuditExportLastSuccess records when a sink last acknowledged a batch, so an
	// operator can alert on a stalled exporter even when lag is briefly zero.
	AuditExportLastSuccess = NewGauge(Default,
		"secsy_audit_export_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last acknowledged SIEM export batch, by sink.",
		"sink")
)

// Export result label values for AuditExportEvents.
const (
	ExportDelivered = "delivered"
	ExportFailed    = "failed"
)

// RecordAuditExportSuccess records a batch acknowledged by a sink: it advances
// the observable cursor, resets lag, bumps the delivered counter, and stamps the
// last-success time. head is the current tail sequence of the log.
func RecordAuditExportSuccess(sink string, cursor, head int64, delivered int, at time.Time) {
	if delivered > 0 {
		AuditExportEvents.Add(uint64(delivered), sink, ExportDelivered)
	}
	AuditExportCursor.Set(float64(cursor), sink)
	lag := head - cursor
	if lag < 0 {
		lag = 0
	}
	AuditExportLag.Set(float64(lag), sink)
	AuditExportLastSuccess.Set(float64(at.Unix()), sink)
}

// RecordAuditExportFailure records a failed delivery attempt for a sink over the
// given number of pending events, so both batch- and event-level failure rates
// are visible.
func RecordAuditExportFailure(sink string, pending int) {
	AuditExportBatchFailures.Inc(sink)
	if pending > 0 {
		AuditExportEvents.Add(uint64(pending), sink, ExportFailed)
	}
}

// RecordAuditExportLag refreshes the lag gauge for a sink without a delivery
// (e.g. after an idle poll finds the sink caught up, or before the first
// delivery). head is the tail sequence; cursor is the durable position.
func RecordAuditExportLag(sink string, cursor, head int64) {
	AuditExportCursor.Set(float64(cursor), sink)
	lag := head - cursor
	if lag < 0 {
		lag = 0
	}
	AuditExportLag.Set(float64(lag), sink)
}

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

// SetHSMTokenUp records a token's HA health (true = healthy and in rotation).
func SetHSMTokenUp(token string, up bool) {
	v := 0.0
	if up {
		v = 1
	}
	HSMTokenUp.Set(v, token)
}

// RecordHSMTokenFailover records that an operation failed on token and was
// retried on another token in the HA set.
func RecordHSMTokenFailover(token string) { HSMTokenFailovers.Inc(token) }

// RecordHSMTokenError records an operation error charged to a token's health.
func RecordHSMTokenError(token string) { HSMTokenErrors.Inc(token) }

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

// RecordAuthLogin records an operator login attempt by method (oidc|password|
// mtls) and success.
func RecordAuthLogin(method string, ok bool) {
	if ok {
		AuthLogins.Inc(method, ResultSuccess)
	} else {
		AuthLogins.Inc(method, ResultError)
	}
}

// RecordAuthStepUp records the outcome of a WebAuthn step-up. result is one of
// success|error|denied.
func RecordAuthStepUp(result string) { AuthStepUps.Inc(result) }
