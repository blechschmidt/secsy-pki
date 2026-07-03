package metrics

import (
	"sync/atomic"
	"time"
)

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

	// Pre-issuance S/MIME checking (mailbox validation gate for
	// email-protection profiles). CertificateSMIMEChecks counts every run on an
	// S/MIME profile by outcome: "result" is pass|fail (fail = a malformed
	// rfc822Name or a domain outside the profile/tenant allowlists blocked
	// signing). CertificateSMIMEFindings partitions failures by "reason"
	// (syntax|domain|config).
	CertificateSMIMEChecks = NewCounter(Default,
		"secsy_certificate_smime_checks_total",
		"Pre-issuance S/MIME mailbox checks, partitioned by outcome (pass|fail).",
		"result")
	CertificateSMIMEFindings = NewCounter(Default,
		"secsy_certificate_smime_findings_total",
		"Pre-issuance S/MIME findings that blocked issuance, partitioned by reason.",
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
	// OCSP pre-signing (Task 58). The presigner batch-signs a response for every
	// known serial on a schedule so the public responder serves from cache and
	// never touches the HSM on the hot path. OCSPPresignBatchDuration times each
	// batch (all CAs); OCSPPresignResponses counts individual responses signed by
	// result (signed|error); OCSPPresignedCached is the number of unexpired
	// pre-signed responses currently servable from the cache; and
	// OCSPPresignLastSuccess / the secsy_ocsp_presign_staleness_seconds FuncGauge
	// (below) expose when the pre-signed set was last refreshed, the primary
	// alert signal — a climbing staleness means responses are aging toward their
	// NextUpdate with no fresh batch behind them.
	OCSPPresignBatchDuration = NewHistogram(Default,
		"secsy_ocsp_presign_batch_duration_seconds",
		"Duration of OCSP pre-signing batches (all CAs) in seconds.",
		BatchBuckets)
	OCSPPresignResponses = NewCounter(Default,
		"secsy_ocsp_presign_responses_total",
		"OCSP responses produced by the pre-signing batches, partitioned by result.",
		"result")
	OCSPPresignedCached = NewGauge(Default,
		"secsy_ocsp_presigned_responses",
		"Unexpired pre-signed OCSP responses currently servable from the response cache.")
	OCSPPresignLastSuccess = NewGauge(Default,
		"secsy_ocsp_presign_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last successful OCSP pre-signing batch.")
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

	// Bulk revocation (Task 70, incident response). RevocationsBulk counts
	// mass-revocation operations by result (success|error|denied); dry-run
	// previews are not counted. RevocationsBulkCertificates counts the
	// certificates newly revoked by those operations (idempotent re-runs only
	// count serials not already revoked). RevocationsBulkDuration times the
	// whole operation — batched store updates, per-certificate audit events,
	// the single end-of-run CRL+delta regeneration, and the OCSP presign
	// refresh — which is the number to watch against the CA/B Forum 24-hour
	// key-compromise revocation obligation.
	RevocationsBulk = NewCounter(Default,
		"secsy_revocations_bulk_total",
		"Bulk-revocation operations, partitioned by result (success|error|denied).",
		"result")
	RevocationsBulkCertificates = NewCounter(Default,
		"secsy_revocations_bulk_certificates_total",
		"Certificates newly revoked by bulk-revocation operations.")
	RevocationsBulkDuration = NewHistogram(Default,
		"secsy_revocations_bulk_duration_seconds",
		"End-to-end duration of bulk-revocation operations in seconds.",
		BatchBuckets)

	// RFC 3161 time-stamping. "result" is granted|rejected|error; the token is
	// signed on the HSM, so this tracks TSA demand and rejection rates.
	TimestampRequests = NewCounter(Default,
		"secsy_timestamp_requests_total",
		"RFC 3161 time-stamp requests, partitioned by result (granted|rejected|error).",
		"result")

	// Artifact (code) signing. ArtifactSignatures counts CMS detached-signature
	// operations by signer name and result (success|denied|error) — each success
	// is one HSM signature (plus one more on the TSA key when countersigned).
	// ArtifactVerifications counts verification outcomes (valid|invalid|error).
	// ArtifactTimestamps tracks the embedded RFC 3161 countersignature sub-step
	// of signing (success|error), separating TSA trouble from signing trouble.
	ArtifactSignatures = NewCounter(Default,
		"secsy_artifact_signatures_total",
		"Artifact (code) signing operations, partitioned by signer and result (success|denied|error).",
		"signer", "result")
	ArtifactVerifications = NewCounter(Default,
		"secsy_artifact_verifications_total",
		"Artifact signature verifications, partitioned by result (valid|invalid|error).",
		"result")
	ArtifactTimestamps = NewCounter(Default,
		"secsy_artifact_timestamps_total",
		"RFC 3161 timestamp countersignatures embedded during artifact signing, by result (success|error).",
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

	// Secret-layer KEK rotation (Task 63). SecretRewrap counts individual DEK
	// re-wraps by result (ok|conflict|error). SecretRewrapPending is the size of
	// the remaining re-wrap work list for a family, live during a batch and
	// refreshed by the expiry monitor between batches. SecretsOnOldKEK is the
	// number of stored secrets whose envelope is still wrapped under a
	// non-active KEK version of the family — the drain-to-zero gauge a rotation
	// is finished by, refreshed on every monitor tick and after each
	// rotate/re-wrap/retire operation. SecretKEKActiveVersion exposes the
	// family's current version number so dashboards can annotate rotations.
	SecretRewrap = NewCounter(Default,
		"secsy_secret_rewrap_total",
		"Stored-secret DEK re-wrap operations, by result (ok|conflict|error).",
		"result")
	SecretRewrapPending = NewGauge(Default,
		"secsy_secret_rewrap_pending",
		"Stored secrets remaining in the current re-wrap work list, by KEK family.",
		"family")
	SecretsOnOldKEK = NewGauge(Default,
		"secsy_secret_on_old_kek",
		"Stored secrets still wrapped under a non-active KEK version, by KEK family.",
		"family")
	SecretKEKActiveVersion = NewGauge(Default,
		"secsy_secret_kek_active_version",
		"Active KEK rotation version of a family, by KEK family.",
		"family")

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

	// Multi-replica coordination (Task 68). LeaderIsLeader is this replica's
	// current leadership over the singleton background jobs; summed across the
	// fleet it should always be exactly 1 (0 means jobs are paused — e.g. the
	// election store is unreachable). LeaderTransitions counts this replica's
	// gains ("leader") and losses ("follower"); a fleet-wide burst indicates
	// leadership flapping, typically a struggling database or an overloaded
	// leader missing lease renewals.
	LeaderIsLeader = NewGauge(Default,
		"secsy_leader_is_leader",
		"Whether this replica currently leads the singleton background jobs (1 = leader, 0 = follower).")
	LeaderTransitions = NewCounter(Default,
		"secsy_leader_transitions_total",
		"Leadership transitions observed by this replica, by direction (leader = acquired, follower = lost or stepped down).",
		"to")

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

	// Audit-chain anchoring (Task 64). AuditAnchors counts every anchoring
	// attempt: success = an anchor was persisted, error = obtaining or storing
	// the token failed, skipped = nothing new to anchor (idle log). The failure
	// series is the alert signal for a broken TSA path.
	AuditAnchors = NewCounter(Default,
		"secsy_audit_anchors_total",
		"Audit-chain anchoring attempts, by result (success|error|skipped).",
		"result")
	// AuditAnchorLastSuccess records when the newest anchor was persisted;
	// seeded from the store at startup so restarts do not blank it.
	AuditAnchorLastSuccess = NewGauge(Default,
		"secsy_audit_anchor_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the most recent persisted audit-chain anchor.")
	// AuditAnchorHeadSeq is the event-log sequence number the newest anchor
	// covers — everything up to it is externally attested.
	AuditAnchorHeadSeq = NewGauge(Default,
		"secsy_audit_anchor_head_seq",
		"Event-log sequence number covered by the most recent audit-chain anchor.")
	// AuditAnchorPending is the unattested tail: events appended since the last
	// anchor (head seq minus anchored seq), refreshed on every anchor run. A
	// value of 1 is steady-state (the anchor's own audit record); alerts pair it
	// with the age gauge so an idle log never pages.
	AuditAnchorPending = NewGauge(Default,
		"secsy_audit_anchor_pending_events",
		"Audit events appended since the last anchor (event-log head seq minus anchored seq).")
)

// Static artifact publishing (Task 58). The publisher writes CRLs, chains, and
// pre-signed OCSP responses as static artifacts to a directory or S3-compatible
// store for CDN fronting. PublishRuns/PublishDuration track each run by backend
// (dir|s3); PublishArtifacts is the artifact count of the last successful
// snapshot by kind; PublishLastSuccess plus the staleness FuncGauge expose how
// long the published snapshot has been aging.
var (
	PublishRuns = NewCounter(Default,
		"secsy_publish_runs_total",
		"Static artifact publishing runs, partitioned by backend and result.",
		"backend", "result")
	PublishDuration = NewHistogram(Default,
		"secsy_publish_duration_seconds",
		"Duration of static artifact publishing runs in seconds, by backend.",
		BatchBuckets, "backend")
	PublishArtifacts = NewGauge(Default,
		"secsy_publish_artifacts",
		"Artifacts written by the last successful publish snapshot, by kind (crl|delta_crl|chain|ca_cert|ocsp|manifest).",
		"kind")
	PublishLastSuccess = NewGauge(Default,
		"secsy_publish_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last successful static artifact publish, by backend.",
		"backend")
)

// BatchBuckets covers background batch work (pre-signing, publishing), which
// runs from well under a second on small deployments to minutes on large ones —
// a range DefBuckets (tuned for per-request latency) tops out far below.
var BatchBuckets = []float64{
	0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300,
}

// Staleness gauges, computed at scrape time from the last-success instants so
// they climb continuously rather than in refresh-interval steps. Both stay
// absent (header only) until the first successful run, so alerts can key on
// their existence.
var (
	ocspPresignLastSuccessNano atomic.Int64
	publishLastSuccessNano     atomic.Int64
	auditAnchorLastNano        atomic.Int64

	_ = NewFuncGauge(Default,
		"secsy_ocsp_presign_staleness_seconds",
		"Seconds since the last successful OCSP pre-signing batch. Absent until the first batch succeeds.",
		func() (float64, bool) { return sinceNano(ocspPresignLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_publish_staleness_seconds",
		"Seconds since the last successful static artifact publish (any backend). Absent until the first publish succeeds.",
		func() (float64, bool) { return sinceNano(publishLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_audit_anchor_age_seconds",
		"Seconds since the most recent audit-chain anchor was persisted (seeded from the store at startup). Absent until an anchor exists.",
		func() (float64, bool) { return sinceNano(auditAnchorLastNano.Load()) })
)

func sinceNano(nano int64) (float64, bool) {
	if nano == 0 {
		return 0, false
	}
	return time.Since(time.Unix(0, nano)).Seconds(), true
}

// RecordOCSPPresignBatch records a completed pre-signing batch: its duration,
// the per-response outcome counts, and — when the batch succeeded — the
// last-success instant the staleness gauge derives from and the servable
// pre-signed entry count. A batch that signed nothing because there are no CAs
// still counts as success (staleness resets: the presigner is live).
func RecordOCSPPresignBatch(start time.Time, signed, failed int, err error) {
	OCSPPresignBatchDuration.Observe(time.Since(start).Seconds())
	if signed > 0 {
		OCSPPresignResponses.Add(uint64(signed), ResultSuccess)
	}
	if failed > 0 {
		OCSPPresignResponses.Add(uint64(failed), ResultError)
	}
	if err == nil {
		now := time.Now()
		OCSPPresignLastSuccess.Set(float64(now.Unix()))
		ocspPresignLastSuccessNano.Store(now.UnixNano())
	}
}

// SetOCSPPresignedCached refreshes the servable pre-signed response gauge.
func SetOCSPPresignedCached(n int) { OCSPPresignedCached.Set(float64(n)) }

// RecordPublishRun records a completed publish run against a backend, stamping
// the last-success instants on success.
func RecordPublishRun(backend string, start time.Time, err error) {
	PublishDuration.Observe(time.Since(start).Seconds(), backend)
	if err != nil {
		PublishRuns.Inc(backend, ResultError)
		return
	}
	PublishRuns.Inc(backend, ResultSuccess)
	now := time.Now()
	PublishLastSuccess.Set(float64(now.Unix()), backend)
	publishLastSuccessNano.Store(now.UnixNano())
}

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

// AnchorSkipped is the AuditAnchors result label for a run that found nothing
// new to anchor.
const AnchorSkipped = "skipped"

// RecordAuditAnchorSuccess records a persisted anchor covering seq at time at:
// the pending tail drops to zero by construction (the anchored seq WAS the
// head when the token was requested).
func RecordAuditAnchorSuccess(seq int64, at time.Time) {
	AuditAnchors.Inc(ResultSuccess)
	AuditAnchorLastSuccess.Set(float64(at.Unix()))
	AuditAnchorHeadSeq.Set(float64(seq))
	AuditAnchorPending.Set(0)
	auditAnchorLastNano.Store(at.UnixNano())
}

// RecordAuditAnchorSkipped records an anchor run that found nothing new:
// anchoredSeq is the newest anchored sequence (0 when none), head the current
// log tail. The pending gauge still refreshes so the unattested tail stays
// observable between anchors.
func RecordAuditAnchorSkipped(anchoredSeq, head int64) {
	AuditAnchors.Inc(AnchorSkipped)
	setAuditAnchorPending(anchoredSeq, head)
}

// RecordAuditAnchorFailure counts a failed anchoring attempt (token fetch or
// persistence).
func RecordAuditAnchorFailure() {
	AuditAnchors.Inc(ResultError)
}

// SeedAuditAnchor initializes the last-anchor gauges from persisted state at
// startup, so the age/head metrics reflect reality before the first new anchor.
func SeedAuditAnchor(seq int64, at time.Time) {
	AuditAnchorLastSuccess.Set(float64(at.Unix()))
	AuditAnchorHeadSeq.Set(float64(seq))
	auditAnchorLastNano.Store(at.UnixNano())
}

func setAuditAnchorPending(anchoredSeq, head int64) {
	pending := head - anchoredSeq
	if pending < 0 {
		pending = 0
	}
	AuditAnchorPending.Set(float64(pending))
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
