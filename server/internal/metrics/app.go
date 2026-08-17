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

	// Certificate lifecycle. The "operation" label is issue|renew|revoke|suspend|
	// release (suspend/release are the reversible certificateHold path, Task 82)
	// and the "result" label is success|error|denied.
	Certificates = NewCounter(Default,
		"secsy_certificates_total",
		"Certificate lifecycle operations, partitioned by operation and result.",
		"operation", "result")

	// Per-profile manual issuance-approval gate (Task 84). CertIssueApprovals
	// counts each transition of an operator/API leaf-issuance request routed
	// through the four-eyes engine: "result" is pending (parked for approval),
	// approved (certificate completed and delivered), denied (rejected or expired
	// — never issued), or error (issuance failed after approval). It lets
	// operators alert on a growing approval backlog or post-approval failures
	// distinctly from ordinary issuance.
	CertIssueApprovals = NewCounter(Default,
		"secsy_cert_issue_approvals_total",
		"Operator/API leaf-issuance requests routed through the manual approval gate, by outcome (pending|approved|denied|error).",
		"result")

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
	// forbidding names by "reason" (forbidden|critical_unknown|lookup_error|
	// account_mismatch|validation_method — the last two are RFC 8657 accounturi/
	// validationmethods binding failures).
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

	// Pre-issuance UPN checking (Task 122, smartcard-logon / Kerberos PKINIT
	// profiles). CertificateUPNChecks counts every run of the gate by outcome:
	// "result" is pass|fail (fail = a malformed UPN, a realm outside the
	// profile/tenant allowlists, a UPN on a non-UPN profile, or a missing required
	// UPN blocked signing). CertificateUPNFindings partitions failures by "reason"
	// (required|not_permitted|syntax|config|realm).
	CertificateUPNChecks = NewCounter(Default,
		"secsy_certificate_upn_checks_total",
		"Pre-issuance UPN (smartcard-logon/PKINIT) checks, partitioned by outcome (pass|fail).",
		"result")
	CertificateUPNFindings = NewCounter(Default,
		"secsy_certificate_upn_findings_total",
		"Pre-issuance UPN findings that blocked issuance, partitioned by reason.",
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

	// Certificate Transparency log-operator diversity achieved per CT-enabled
	// issuance (Task 150). Observed once for every issuance that reaches the CT
	// gate: the number of DISTINCT log operators that returned a usable SCT (two
	// logs run by the same operator count once). Modern CT policies (Chrome,
	// Apple) require SCTs from a minimum number of INDEPENDENT operators; a
	// per-profile min_distinct_operators enforces it. The observation is recorded
	// even when the policy fails (fail-closed reject) or fail-open ships anyway,
	// so a live log set that has degraded to a single operator is visible here
	// even while the raw SCT count is still met. Alert on the lower quantiles
	// falling toward 1 (histogram_quantile(0.1, ...) or _bucket{le="1"} rising).
	CTDistinctOperators = NewHistogram(Default,
		"secsy_ct_distinct_operators",
		"Distinct CT log operators that returned a usable SCT, observed once per CT-enabled issuance.",
		[]float64{0, 1, 2, 3, 4, 5})

	// Pre-issuance key-quality checking (Task 120, CA/Browser Forum BR §6.1.1.3
	// weak/compromised-key gate). CertificateKeyChecks counts every run by outcome:
	// "result" is pass|warn|fail (fail = an enforce-mode finding blocked signing).
	// CertificateKeyCheckFindings counts individual findings by check "code" (roca,
	// weak_exponent, small_modulus, even_modulus, debian_weak_key, blocked_key,
	// duplicate_key) and "mode" (enforce|warn) for fine-grained alerting.
	CertificateKeyChecks = NewCounter(Default,
		"secsy_certificate_key_checks_total",
		"Pre-issuance subject public-key quality checks, partitioned by outcome (pass|warn|fail).",
		"result")
	CertificateKeyCheckFindings = NewCounter(Default,
		"secsy_certificate_key_check_findings_total",
		"Pre-issuance key-quality findings, partitioned by check code and mode.",
		"code", "mode")

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

	// BRSKI (RFC 8995) zero-touch device onboarding (Task 87). VoucherRequests
	// counts registrar /requestvoucher outcomes by "result" (success|denied|
	// error); denied is a fail-closed policy refusal (untrusted IDevID, failed
	// proximity/serial assertion), error is a malformed request or a MASA that
	// declined. VouchersIssued counts vouchers minted by the built-in MASA.
	// StatusReports counts pledge voucher_status/enrollstatus telemetry by "kind"
	// (voucher|enroll) and reported "status" (success|failure). EnrollAuthorized
	// counts EST-handoff authorization checks by whether the presenter was a
	// currently-bootstrapped pledge.
	BRSKIVoucherRequests = NewCounter(Default,
		"secsy_brski_voucher_requests_total",
		"BRSKI registrar voucher requests, partitioned by result.",
		"result")
	BRSKIVouchersIssued = NewCounter(Default,
		"secsy_brski_vouchers_issued_total",
		"BRSKI vouchers issued by the built-in MASA, partitioned by result.",
		"result")
	BRSKIStatusReports = NewCounter(Default,
		"secsy_brski_status_reports_total",
		"BRSKI pledge status-telemetry reports, partitioned by kind and reported status.",
		"kind", "status")
	BRSKIEnrollAuthorized = NewCounter(Default,
		"secsy_brski_enroll_authorized_total",
		"BRSKI EST-handoff authorization checks, partitioned by result.",
		"result")

	// Microsoft Windows autoenrollment web services (Task 162: MS-XCEP policy +
	// MS-WSTEP enrollment). MSXCEPPolicies counts GetPolicies (CEP) responses by
	// result; MSWSTEPRequests counts RequestSecurityToken (CES) issuance attempts
	// by result (success|denied|error), mirroring the other enrollment protocols.
	MSXCEPPolicies = NewCounter(Default,
		"secsy_mswstep_getpolicies_total",
		"MS-XCEP GetPolicies (certificate enrollment policy) responses, partitioned by result.",
		"result")
	MSWSTEPRequests = NewCounter(Default,
		"secsy_mswstep_requests_total",
		"MS-WSTEP RequestSecurityToken issuance requests, partitioned by result.",
		"result")

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

	// Batch / bulk issuance (Task 101, mass device/service provisioning).
	// IssuanceBulk counts batch-issuance operations by result (success|error|
	// denied); a "success" is a completed operation regardless of how many of its
	// items individually failed. Like bulk revocation, batch items are tracked on
	// this dedicated pair rather than the per-operation secsy_certificates_total
	// counter: IssuanceBulkCertificates counts the certificates actually issued
	// across these operations (excludes items parked for approval or failed).
	// IssuanceBulkDuration times the whole operation — the approval-gate pass plus
	// the bounded-concurrency issuance of every item — so operators can size
	// batches against provisioning windows.
	IssuanceBulk = NewCounter(Default,
		"secsy_issuance_bulk_total",
		"Batch-issuance operations, partitioned by result (success|error).",
		"result")
	IssuanceBulkCertificates = NewCounter(Default,
		"secsy_issuance_bulk_certificates_total",
		"Certificates issued by batch-issuance operations (excludes parked/failed items).")
	IssuanceBulkDuration = NewHistogram(Default,
		"secsy_issuance_bulk_duration_seconds",
		"End-to-end duration of batch-issuance operations in seconds.",
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
	// ACMEAuthzDeactivations counts RFC 8555 §7.5.2 authorization-deactivation
	// requests by "result": deactivated (an owned, still-live authorization was
	// relinquished by the account) or rejected (the authorization was in a state it
	// cannot be deactivated from — already invalid/expired/revoked). A client
	// deactivating authorizations is the signal that an identifier is being
	// decommissioned.
	ACMEAuthzDeactivations = NewCounter(Default,
		"secsy_acme_authz_deactivations_total",
		"ACME authorization deactivations (RFC 8555 §7.5.2), by result (deactivated|rejected).",
		"result")
	// ACMEChallengeValidations counts identifier-validation challenge attempts by
	// challenge "type" (http-01|dns-01|tls-alpn-01) and "result" (valid|invalid),
	// giving each challenge type observable parity on the issuance path.
	ACMEChallengeValidations = NewCounter(Default,
		"secsy_acme_challenge_validations_total",
		"ACME challenge validation attempts, by challenge type and result (valid|invalid).",
		"type", "result")
	// ACMEIssued counts certificates issued through the ACME finalize path, by the
	// internal issuance "profile" the certificate was signed under. With the ACME
	// Profiles extension (RFC 9773) a single endpoint offers several
	// client-selectable profiles; this label breaks issuance volume down by the
	// profile actually used, whether the client selected it or took the default.
	ACMEIssued = NewCounter(Default,
		"secsy_acme_certificates_issued_total",
		"Certificates issued via the ACME finalize path, by issuance profile.",
		"profile")
	// ACMEEmailChallenge counts RFC 8823 email-reply-00 challenge lifecycle
	// events (S/MIME issuance via ACME), by "event": sent (a signed challenge
	// email dispatched to the mailbox), reply_matched (an inbound reply threaded
	// back to a pending challenge), send_error (the challenge email could not be
	// dispatched), or no_match (an inbound reply matched no pending challenge and
	// was discarded). The valid/invalid outcome of a matched reply is additionally
	// recorded on ACMEChallengeValidations with type "email-reply-00", giving the
	// challenge parity with the domain-validation challenges.
	ACMEEmailChallenge = NewCounter(Default,
		"secsy_acme_email_challenge_total",
		"ACME email-reply-00 (RFC 8823) challenge lifecycle events, by event.",
		"event")
	// ACMEStarOrders counts RFC 8739 STAR (short-term auto-renewed) order lifecycle
	// events (Task 136), by "event": created (first certificate issued at finalize),
	// renewed (the background renewer re-issued ahead of expiry), renew_failed (a
	// renewal attempt errored — the order keeps its deadline and is retried),
	// canceled (the client canceled the recurrence), or ended (the recurrence
	// reached its end-date and the renewer stopped). A rising renew_failed is the
	// signal that STAR subscribers are silently losing coverage.
	ACMEStarOrders = NewCounter(Default,
		"secsy_acme_star_orders_total",
		"ACME STAR (RFC 8739) short-term auto-renewed order lifecycle events, by event.",
		"event")

	// ACMEMPICPerspective counts per-perspective challenge checks performed by the
	// Multi-Perspective Issuance Corroboration layer (Task 142, CA/Browser Forum
	// SC-067), by "perspective" (the vantage-point name, e.g. primary|eu-west),
	// "challenge" type, and "result": corroborated (the perspective agreed the
	// challenge passes), rejected (the check ran and returned a definitive failure —
	// the localized-hijack signal when honest perspectives dissent), or unavailable
	// (the perspective could not complete its check — timeout/transport error). A
	// perspective persistently "unavailable" is a broken remote vantage; a
	// perspective that "rejected" while others corroborated points at a localized
	// BGP/DNS interception of the CA's primary path.
	ACMEMPICPerspective = NewCounter(Default,
		"secsy_acme_mpic_perspective_checks_total",
		"ACME MPIC (SC-067) per-perspective challenge checks, by perspective, challenge type, and result (corroborated|rejected|unavailable).",
		"perspective", "challenge", "result")
	// ACMEMPICQuorum counts MPIC quorum decisions (Task 142) by "challenge" type and
	// "result": corroborated (the primary passed and the remote perspectives met the
	// SC-067 quorum), primary_failed (the primary check itself failed — nothing to
	// corroborate, identical to pre-MPIC single-perspective behavior), failed_quorum
	// (too many remote perspectives dissented for the quorum to hold), or
	// failed_unresponsive (too few remote perspectives returned a definitive result,
	// so corroboration failed closed rather than silently degrade to one vantage). A
	// rising failed_quorum is the primary MPIC alert signal.
	ACMEMPICQuorum = NewCounter(Default,
		"secsy_acme_mpic_quorum_total",
		"ACME MPIC (SC-067) quorum decisions, by challenge type and result (corroborated|primary_failed|failed_quorum|failed_unresponsive).",
		"challenge", "result")

	// ACMENonces tracks the shared/durable anti-replay nonce store (Task 97) by
	// "result": issued (a nonce minted), valid (a nonce consumed on its first use),
	// replayed (rejected because it was already consumed — the multi-replica
	// correctness signal a per-instance map could not surface), expired (rejected
	// as past its TTL), invalid (rejected as malformed or bearing a bad HMAC —
	// forged or signed with a foreign/rotated secret), or error (a store failure,
	// which fails closed to badNonce). A rising "replayed" or "invalid" rate points
	// at genuine replay/attack; a rising "expired" rate at slow clients or clock
	// skew across replicas.
	ACMENonces = NewCounter(Default,
		"secsy_acme_nonces_total",
		"ACME anti-replay nonce store operations, by result (issued|valid|replayed|expired|invalid|error).",
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

	// Secret lifecycle (Task 73). SecretsLifecycleDue is the number of stored
	// secrets currently in each lifecycle state (expiring|expired|rotation_due),
	// refreshed on every monitor tick; SecretLifecycleNotifications counts
	// reminder notifications actually dispatched (post storm-filtering).
	// SecretStoreOps counts stored-secret registry mutations
	// (put|rollback|delete) by result.
	SecretsLifecycleDue = NewGauge(Default,
		"secsy_secrets_lifecycle_due",
		"Stored secrets in each lifecycle state (expiring|expired|rotation_due).",
		"state")
	SecretLifecycleNotifications = NewCounter(Default,
		"secsy_secret_lifecycle_notifications_total",
		"Secret TTL/rotation reminder notifications dispatched, by state.",
		"state")
	SecretStoreOps = NewCounter(Default,
		"secsy_secret_store_operations_total",
		"Stored-secret registry mutations, by operation (put|rollback|delete) and result.",
		"operation", "result")

	// Stateless crypto service (Task 138): the non-storing data-key, keyed-HMAC,
	// and random-bytes endpoints that round out the secret layer alongside
	// encrypt/decrypt/rewrap. SecretDataKey counts data-key mints; SecretHMAC
	// counts HMAC generate|verify by operation; SecretRandom counts random-bytes
	// draws by their entropy source (hsm|software), so operators can confirm the
	// HSM RNG is actually in the path.
	SecretDataKey = NewCounter(Default,
		"secsy_secret_datakey_operations_total",
		"Data-key generation operations, by result.",
		"result")
	SecretHMAC = NewCounter(Default,
		"secsy_secret_hmac_operations_total",
		"Keyed-HMAC operations, by operation (generate|verify) and result.",
		"operation", "result")
	SecretRandom = NewCounter(Default,
		"secsy_secret_random_operations_total",
		"CSPRNG random-bytes operations, by entropy source (hsm|software) and result.",
		"source", "result")

	// Format-preserving encryption / tokenization (Task 144). SecretTransform
	// counts FF1 encode|decode operations, partitioned by transform template and
	// result, so operators can see per-template usage without any plaintext ever
	// touching the metric.
	SecretTransform = NewCounter(Default,
		"secsy_secret_transform_operations_total",
		"Format-preserving-encryption transform operations, by template, operation (encode|decode) and result.",
		"template", "operation", "result")

	// Named HSM-backed asymmetric signing keys (Task 153). SecretSigningKey counts
	// signing-key creations by result; SecretSign counts sign|verify operations by
	// operation and result, so operators can see signing throughput distinct from
	// the symmetric crypto-service traffic.
	SecretSigningKey = NewCounter(Default,
		"secsy_secret_signing_key_operations_total",
		"Signing-key management operations (create), by result.",
		"result")
	SecretSign = NewCounter(Default,
		"secsy_secret_sign_operations_total",
		"Asymmetric sign/verify operations, by operation (sign|verify) and result.",
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

	// Native scoped API tokens / service accounts (Task 86). AuthTokenOps counts
	// token lifecycle operations (create|revoke) by result; AuthTokenVerifications
	// counts machine authentication attempts by outcome
	// (success|expired|revoked|unknown|error); AuthTokensActive tracks the number
	// of currently valid (unrevoked, unexpired) tokens.
	AuthTokenOps = NewCounter(Default,
		"secsy_auth_token_operations_total",
		"Scoped API token lifecycle operations, partitioned by operation and result.",
		"operation", "result")
	AuthTokenVerifications = NewCounter(Default,
		"secsy_auth_token_verifications_total",
		"Scoped API token verification attempts, partitioned by outcome.",
		"result")
	AuthTokensActive = NewGauge(Default,
		"secsy_auth_tokens_active",
		"Number of currently valid (unrevoked, unexpired) scoped API tokens.")

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

	// Synthetic issuance canary (Task 71). Each probe runs the full certificate
	// lifecycle against one CA: issue → chain verify → OCSP good → CRL freshness
	// → revoke → revoked propagation. CanaryLastSuccess is the primary alert
	// signal: a stale (or never-set) per-CA timestamp means the issuance path has
	// stopped being proven healthy. CanaryFailures pinpoints the broken stage.
	CanaryProbes = NewCounter(Default,
		"secsy_canary_probes_total",
		"Synthetic issuance-canary probes, partitioned by CA label and result (success|error).",
		"ca", "result")
	CanaryFailures = NewCounter(Default,
		"secsy_canary_failures_total",
		"Synthetic issuance-canary probe failures, partitioned by CA label and the stage that failed (issue|chain|ocsp_good|crl|revoke|ocsp_revoked).",
		"ca", "stage")
	CanaryLastSuccess = NewGauge(Default,
		"secsy_canary_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last fully successful issuance-canary probe, by CA label. Absent for a CA until its first success.",
		"ca")
	CanaryStageDuration = NewHistogram(Default,
		"secsy_canary_stage_duration_seconds",
		"Duration of individual issuance-canary probe stages in seconds, by stage.",
		DefBuckets, "stage")

	// Self-managed serving-TLS certificate (Task 118). When server.tls.self_issue
	// is enabled the server dogfoods its own HTTPS listener certificate from an
	// internal CA — the private key stays in the configured key provider — and a
	// background loop auto-rotates it before expiry, swapping it hitlessly through
	// the tls.Config.GetCertificate hook.
	//
	// ServingCertExpiry is the NotAfter of the certificate currently served, as a
	// Unix timestamp. It is the primary alert signal: `expiry - now` dropping below
	// a threshold means rotation has stalled (the loop is wedged or issuance is
	// failing) since a healthy loop keeps re-issuing a long-dated certificate.
	// ServingCertRotations counts (re)issues by result so a run of errors is
	// visible even while the last good certificate keeps being served.
	ServingCertExpiry = NewGauge(Default,
		"secsy_serving_cert_expiry_timestamp_seconds",
		"NotAfter of the self-issued serving-TLS certificate currently served, as a Unix timestamp (seconds). Absent until the first successful self-issue.")
	ServingCertRotations = NewCounter(Default,
		"secsy_serving_cert_rotations_total",
		"Self-issued serving-TLS certificate (re)issues, partitioned by result (success|error).",
		"result")

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

// Trusted external time source (Task 163). Before the TSA signs a time-stamp
// token or the audit-chain anchor is created, the host clock is cross-checked
// against the configured trusted source(s) (authenticated NTP/NTS or
// Roughtime). TimeDriftSeconds is the last measured host-minus-source offset per
// source (positive: host ahead) — the value the fail-closed threshold is
// applied to. TimeChecks counts every cross-check by result (pass|fail|cached),
// and TimeCheckFailures is the fail-closed alert signal, by reason
// (drift|unreachable). All three stay absent until an external source is
// configured and first queried, so a system-clock (zero-config) deployment
// exposes nothing here.
var (
	TimeDriftSeconds = NewGauge(Default,
		"secsy_time_drift_seconds",
		"Measured offset between the host clock and a trusted external time source, in seconds (positive: host ahead), per source.",
		"source")
	TimeChecks = NewCounter(Default,
		"secsy_time_checks_total",
		"Trusted-time cross-checks of the host clock, partitioned by result (pass|fail|cached).",
		"result")
	TimeCheckFailures = NewCounter(Default,
		"secsy_time_check_failures_total",
		"Trusted-time cross-checks that could not confirm the host clock, by reason (drift|unreachable). Under the default fail-closed policy each such check also refuses to sign (see secsy_time_checks_total{result=\"fail\"}).",
		"reason")
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

// Backup* track the scheduled encrypted-backup job (Task 89): BackupRuns counts
// completed runs by result; BackupDuration times them; BackupArtifactBytes is
// the size of the most recent encrypted artifact; BackupRetainedSnapshots is
// how many backups the destination held after the last retention pass;
// BackupLastSuccess plus the staleness FuncGauge expose how long since a backup
// last succeeded.
var (
	BackupRuns = NewCounter(Default,
		"secsy_backup_runs_total",
		"Scheduled encrypted-backup runs, partitioned by result (success|error).",
		"result")
	BackupDuration = NewHistogram(Default,
		"secsy_backup_duration_seconds",
		"Duration of scheduled encrypted-backup runs in seconds.",
		BatchBuckets)
	BackupArtifactBytes = NewGauge(Default,
		"secsy_backup_artifact_bytes",
		"Size in bytes of the most recent successful encrypted backup artifact.")
	BackupRetainedSnapshots = NewGauge(Default,
		"secsy_backup_retained_snapshots",
		"Number of backups retained at the destination after the last successful retention pass.")
	BackupLastSuccess = NewGauge(Default,
		"secsy_backup_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last successful scheduled backup.")
)

// Ers* track the RFC 4998 Evidence-Record preservation job (Task 161): the
// leader-elected loop generates new Evidence Records over recent audit events
// and renews existing ones — time-stamp renewal before TSA-certificate expiry
// and hash-tree renewal on algorithm deprecation. ErsGenerated / ErsRenewed
// count minted / renewed records (the latter labelled by kind timestamp|hashtree),
// ErsCycleErrors counts failed cycles, ErsRecordsTotal is the standing record
// count, and ErsLastSuccess plus the staleness FuncGauge expose freshness.
var (
	ErsGenerated = NewCounter(Default,
		"secsy_ers_generated_total",
		"Evidence Records minted by the preservation job.")
	ErsRenewed = NewCounter(Default,
		"secsy_ers_renewed_total",
		"Evidence-Record renewals, partitioned by kind (timestamp|hashtree).",
		"kind")
	ErsCycleErrors = NewCounter(Default,
		"secsy_ers_cycle_errors_total",
		"Evidence-Record preservation cycles (generation or renewal) that failed.")
	ErsCycleDuration = NewHistogram(Default,
		"secsy_ers_cycle_duration_seconds",
		"Duration of Evidence-Record preservation cycles in seconds.",
		BatchBuckets)
	ErsRecordsTotal = NewGauge(Default,
		"secsy_ers_records_total",
		"Total Evidence Records currently persisted.")
	ErsLastSuccess = NewGauge(Default,
		"secsy_ers_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last successful Evidence-Record preservation cycle.")
)

// BackupVerify* track the automated backup restore-verification drill (Task 94):
// the leader-elected verifier (and the `secsy-ca backup verify-restore` CLI)
// pulls the newest published backup artifact, decrypts it, restores the DB dump
// into an isolated scratch database, runs the HSM-independent integrity gate,
// and matches the restored audit-head fingerprint against the manifest. An
// untested backup is not a backup, so a failure here is the operator's signal
// that recovery would not actually work. BackupVerifyRuns is the verified/failed
// counter; BackupVerifyDuration times each drill; BackupVerifyLastSuccess plus
// the restore-verified staleness FuncGauge expose how long since a backup was
// last proven restorable.
var (
	BackupVerifyRuns = NewCounter(Default,
		"secsy_backup_verify_total",
		"Automated backup restore-verification drills, partitioned by result (success|error).",
		"result")
	BackupVerifyDuration = NewHistogram(Default,
		"secsy_backup_verify_duration_seconds",
		"Duration of backup restore-verification drills in seconds.",
		BatchBuckets)
	BackupVerifyLastSuccess = NewGauge(Default,
		"secsy_backup_verify_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last successfully verified backup restore.")
)

// InventoryRetention* track the certificate-inventory retention/archival job
// (Task 157): a leader-elected loop that ages out long-expired, terminal
// issued-certificate rows so a high-volume CA's issued_certificates table does
// not grow unbounded. InventoryRetentionRuns counts completed runs by result;
// InventoryRetentionDuration times them; the Archived/Pruned counters accumulate
// how many rows were moved to the archive table and hard-deleted; the last-run
// timestamp gauge plus the staleness and backlog FuncGauges expose freshness and
// how many eligible rows still await processing.
var (
	InventoryRetentionRuns = NewCounter(Default,
		"secsy_inventory_retention_runs_total",
		"Certificate-inventory retention runs, partitioned by result (success|error).",
		"result")
	InventoryRetentionDuration = NewHistogram(Default,
		"secsy_inventory_retention_duration_seconds",
		"Duration of certificate-inventory retention runs in seconds.",
		BatchBuckets)
	InventoryRetentionArchived = NewCounter(Default,
		"secsy_inventory_retention_archived_total",
		"Total issued-certificate rows moved to the archive table by the retention job.")
	InventoryRetentionPruned = NewCounter(Default,
		"secsy_inventory_retention_pruned_total",
		"Total archived issued-certificate rows hard-deleted by the retention job (prune mode).")
	InventoryRetentionArchiveSize = NewGauge(Default,
		"secsy_inventory_retention_archive_size",
		"Number of rows currently held in issued_certificates_archive after the last successful retention run.")
	InventoryRetentionLastRun = NewGauge(Default,
		"secsy_inventory_retention_last_run_timestamp_seconds",
		"Unix timestamp (seconds) of the last successful certificate-inventory retention run.")
)

// CT SCT inclusion-proof monitoring (Task 93). The leader-elected monitor
// verifies that logs honor the SCTs embedded at issuance (Task 26): once a log's
// Maximum Merge Delay has elapsed it fetches the log's signed tree head and a
// get-proof-by-hash Merkle audit path and verifies the entry is in the tree.
//
// CTLogMisbehavior is the primary alert signal — an SCT a log failed to honor
// (never included after MMD, or an inclusion proof that did not chain to the
// log's signed root), which is a mis-issuance / log-misbehavior event, by log.
// CTInclusionChecks counts every per-SCT check by outcome; CTInclusionPending /
// CTInclusionFailed are the live backlog gauges refreshed each scan; and
// CTMonitorRuns / CTMonitorLastRun plus the staleness FuncGauge expose scan
// liveness so an alert can fire if the monitor stops running.
var (
	CTInclusionChecks = NewCounter(Default,
		"secsy_ct_inclusion_checks_total",
		"Certificate Transparency SCT inclusion-proof checks, partitioned by log and outcome (included|pending|failed|error|unknown_log).",
		"log", "result")
	CTLogMisbehavior = NewCounter(Default,
		"secsy_ct_log_misbehavior_total",
		"Certificate Transparency SCTs a log failed to honor by its Maximum Merge Delay (never included, or an invalid inclusion proof) — a mis-issuance / log-misbehavior signal, by log.",
		"log")
	CTInclusionPending = NewGauge(Default,
		"secsy_ct_inclusion_pending",
		"Embedded SCTs still awaiting a verified inclusion proof as of the last CT inclusion-monitor scan.")
	CTInclusionFailed = NewGauge(Default,
		"secsy_ct_inclusion_failed",
		"Embedded SCTs a log has failed to honor as of the last CT inclusion-monitor scan (log misbehavior).")
	CTMonitorRuns = NewCounter(Default,
		"secsy_ct_inclusion_monitor_runs_total",
		"CT inclusion-monitor scan cycles, partitioned by result (success|error).",
		"result")
	CTMonitorLastRun = NewGauge(Default,
		"secsy_ct_inclusion_monitor_last_run_timestamp_seconds",
		"Unix timestamp (seconds) of the last completed CT inclusion-monitor scan.")
)

// Operator live audit-event feed (Task 90/104). The SSE endpoint
// GET /api/events/stream fans the tamper-evident audit log out to operators
// watching the console in real time. EventStreamSubscribers is the live count of
// connected subscribers (a gauge, set by the Publisher as connections open and
// close). EventStreamConnections counts every subscription opened, so a rate of
// short-lived connections (reconnect storms) is observable distinctly from the
// live gauge. EventStreamDropped counts audit events evicted from a slow
// subscriber's bounded ring buffer — the liveness-over-completeness trade-off the
// feed makes so a stalled browser can never block the audit-append hot path; a
// rising rate means subscribers are lagging (undersized buffer, slow client, or
// an event storm).
var (
	EventStreamSubscribers = NewGauge(Default,
		"secsy_event_stream_subscribers",
		"Operators currently connected to the live audit-event SSE feed (GET /api/events/stream).")
	EventStreamConnections = NewCounter(Default,
		"secsy_event_stream_connections_total",
		"Total live audit-event SSE subscriptions opened since startup.")
	EventStreamDropped = NewCounter(Default,
		"secsy_event_stream_dropped_total",
		"Audit events dropped from a slow SSE subscriber's ring buffer (subscriber lagged; the feed favors liveness over completeness).")
)

// SetEventStreamSubscribers publishes the current number of connected live
// audit-event SSE subscribers.
func SetEventStreamSubscribers(n int) { EventStreamSubscribers.Set(float64(n)) }

// RecordEventStreamConnection counts one live audit-event SSE subscription being
// opened.
func RecordEventStreamConnection() { EventStreamConnections.Inc() }

// RecordEventStreamDropped counts one audit event evicted from a slow
// subscriber's bounded ring buffer (the subscriber lagged).
func RecordEventStreamDropped() { EventStreamDropped.Inc() }

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
	ocspPresignLastSuccessNano  atomic.Int64
	publishLastSuccessNano      atomic.Int64
	auditAnchorLastNano         atomic.Int64
	backupLastSuccessNano       atomic.Int64
	backupVerifyLastSuccessNano atomic.Int64
	ctMonitorLastRunNano        atomic.Int64
	hsmAuditLastCollectNano     atomic.Int64
	hsmAuditLastAttestNano      atomic.Int64
	hsmAuditLastCommitNano      atomic.Int64

	inventoryRetentionLastRunNano atomic.Int64
	inventoryRetentionBacklog     atomic.Int64

	ersLastSuccessNano atomic.Int64
	ersBacklog         atomic.Int64

	_ = NewFuncGauge(Default,
		"secsy_ocsp_presign_staleness_seconds",
		"Seconds since the last successful OCSP pre-signing batch. Absent until the first batch succeeds.",
		func() (float64, bool) { return sinceNano(ocspPresignLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_publish_staleness_seconds",
		"Seconds since the last successful static artifact publish (any backend). Absent until the first publish succeeds.",
		func() (float64, bool) { return sinceNano(publishLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_backup_staleness_seconds",
		"Seconds since the last successful scheduled encrypted backup. Absent until the first backup succeeds.",
		func() (float64, bool) { return sinceNano(backupLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_backup_restore_verified_staleness_seconds",
		"Seconds since a backup was last proven restorable by the restore-verification drill (Task 94). Absent until the first verification succeeds.",
		func() (float64, bool) { return sinceNano(backupVerifyLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_audit_anchor_age_seconds",
		"Seconds since the most recent audit-chain anchor was persisted (seeded from the store at startup). Absent until an anchor exists.",
		func() (float64, bool) { return sinceNano(auditAnchorLastNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_hsm_audit_collection_staleness_seconds",
		"Seconds since the HSM device audit log was last successfully drained into durable storage (Task 167). "+
			"The device log is a 62-entry ring and a force-audited HSM refuses every auditable command once it fills, "+
			"so growth here precedes an issuance outage as well as an audit gap. Absent until the first drain succeeds.",
		func() (float64, bool) { return sinceNano(hsmAuditLastCollectNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_hsm_audit_attestation_age_seconds",
		"Seconds since a timestamp authority last attested to the HSM audit head (Task 167), measured against the "+
			"TSA's own clock. Once this exceeds the auditor's freshness threshold an exported audit bundle can no "+
			"longer prove it is current, so it stops bounding what the HSM has signed recently. Absent until the "+
			"first attestation succeeds.",
		func() (float64, bool) { return sinceNano(hsmAuditLastAttestNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_hsm_audit_commitment_age_seconds",
		"Seconds since the HSM last signed a commitment binding the audit head to its own serial number (Task 178), "+
			"measured against the timestamp authority's clock. A YubiHSM audit log carries no device identity and no "+
			"signature, so beyond this point the log is connected to the hardware by nothing but the CA's own word. "+
			"Absent until the first commitment succeeds.",
		func() (float64, bool) { return sinceNano(hsmAuditLastCommitNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_ct_inclusion_monitor_staleness_seconds",
		"Seconds since the last completed CT inclusion-monitor scan. Absent until the first scan completes.",
		func() (float64, bool) { return sinceNano(ctMonitorLastRunNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_inventory_retention_staleness_seconds",
		"Seconds since the last successful certificate-inventory retention run. Absent until the first run succeeds.",
		func() (float64, bool) { return sinceNano(inventoryRetentionLastRunNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_inventory_retention_backlog",
		"Certificates eligible for retention still awaiting processing after the last run (should trend to zero). Absent until the first run completes.",
		func() (float64, bool) {
			if inventoryRetentionLastRunNano.Load() == 0 {
				return 0, false
			}
			return float64(inventoryRetentionBacklog.Load()), true
		})
	_ = NewFuncGauge(Default,
		"secsy_ers_staleness_seconds",
		"Seconds since the last successful Evidence-Record generation or renewal cycle (RFC 4998, seeded from the store at startup). Absent until the first cycle succeeds.",
		func() (float64, bool) { return sinceNano(ersLastSuccessNano.Load()) })
	_ = NewFuncGauge(Default,
		"secsy_ers_records_pending_renewal",
		"Evidence Records past their renewal threshold still awaiting renewal after the last cycle (should trend to zero). Absent until the first cycle completes.",
		func() (float64, bool) {
			if ersLastSuccessNano.Load() == 0 {
				return 0, false
			}
			return float64(ersBacklog.Load()), true
		})
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

// RecordBackupRun records a completed scheduled-backup run: its duration and
// result, and — on success — the artifact size, the retained-backup count, and
// the last-success instants the timestamp and staleness gauges derive from. A
// failed run leaves the last-success gauges untouched so the staleness gauge
// keeps climbing, which is the operator's alert signal.
func RecordBackupRun(start time.Time, artifactBytes, retained int, err error) {
	BackupDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		BackupRuns.Inc(ResultError)
		return
	}
	BackupRuns.Inc(ResultSuccess)
	if artifactBytes > 0 {
		BackupArtifactBytes.Set(float64(artifactBytes))
	}
	BackupRetainedSnapshots.Set(float64(retained))
	now := time.Now()
	BackupLastSuccess.Set(float64(now.Unix()))
	backupLastSuccessNano.Store(now.UnixNano())
}

// RecordBackupVerify records a completed backup restore-verification drill: its
// duration and result, and — on success — the last-success instants the
// timestamp and restore-verified staleness gauges derive from. A failed drill
// leaves the last-success gauges untouched so the staleness gauge keeps climbing,
// which is the operator's alert signal that recovery is unproven. A skipped drill
// (nothing published to verify yet) records nothing.
func RecordBackupVerify(start time.Time, err error) {
	BackupVerifyDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		BackupVerifyRuns.Inc(ResultError)
		return
	}
	BackupVerifyRuns.Inc(ResultSuccess)
	now := time.Now()
	BackupVerifyLastSuccess.Set(float64(now.Unix()))
	backupVerifyLastSuccessNano.Store(now.UnixNano())
}

// RecordInventoryRetention records a completed certificate-inventory retention
// run: its duration and result, and — on success — the archived/pruned deltas,
// the resulting archive-table size, the remaining backlog, and the last-run
// instant the timestamp, staleness, and backlog gauges derive from. A failed run
// leaves the last-run gauges untouched so the staleness gauge keeps climbing,
// which is the operator's alert signal that inventory is no longer being aged
// out. Counts are the additions from this run (they feed cumulative counters).
func RecordInventoryRetention(start time.Time, archived, pruned, backlog, archiveSize int, err error) {
	InventoryRetentionDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		InventoryRetentionRuns.Inc(ResultError)
		return
	}
	InventoryRetentionRuns.Inc(ResultSuccess)
	if archived > 0 {
		InventoryRetentionArchived.Add(uint64(archived))
	}
	if pruned > 0 {
		InventoryRetentionPruned.Add(uint64(pruned))
	}
	InventoryRetentionArchiveSize.Set(float64(archiveSize))
	inventoryRetentionBacklog.Store(int64(backlog))
	now := time.Now()
	InventoryRetentionLastRun.Set(float64(now.Unix()))
	inventoryRetentionLastRunNano.Store(now.UnixNano())
}

// RecordCTMonitorRun records a completed CT inclusion-monitor scan: it refreshes
// the pending/failed backlog gauges (always, so they reflect the store even on a
// failed run) and, on success, stamps the last-run instants the timestamp and
// staleness gauges derive from. A run that surfaced log misbehavior is counted
// as an error so the failure series and staleness both drive alerts.
func RecordCTMonitorRun(start time.Time, pending, failed int, err error) {
	CTInclusionPending.Set(float64(pending))
	CTInclusionFailed.Set(float64(failed))
	if err != nil {
		CTMonitorRuns.Inc(ResultError)
		return
	}
	CTMonitorRuns.Inc(ResultSuccess)
	now := time.Now()
	CTMonitorLastRun.Set(float64(now.Unix()))
	ctMonitorLastRunNano.Store(now.UnixNano())
}

// HSM audit-log collection (Task 167).
var (
	// HSMAuditCollectionFailures counts drain cycles that could not establish
	// device-log continuity. Each one means the device log was left
	// unacknowledged on purpose, so a sustained non-zero rate ends in the HSM
	// refusing to sign — which is the safe failure, but an incident either way.
	HSMAuditCollectionFailures = NewCounter(Default,
		"secsy_hsm_audit_collection_failures_total",
		"HSM device audit-log drain cycles that failed continuity verification and were not acknowledged.")
	// HSMAuditEntries counts device log entries durably collected, and
	// HSMAuditSignatures how many of them were successful signing operations —
	// the numerator of the reconciliation an auditor performs.
	HSMAuditEntries = NewCounter(Default,
		"secsy_hsm_audit_entries_total",
		"HSM device audit-log entries durably collected.")
	HSMAuditSignatures = NewCounter(Default,
		"secsy_hsm_audit_signatures_total",
		"Successful HSM signing operations observed in the device audit log.")
	// HSMAuditAttestations counts RFC 3161 freshness attestations over the audit
	// head, by result. These are what let a remote auditor tell a current export
	// from a stale one, so a sustained error rate means exports are quietly
	// losing their ability to prove they are recent — while every other check
	// keeps reporting OK.
	HSMAuditAttestations = NewCounter(Default,
		"secsy_hsm_audit_attestations_total",
		"RFC 3161 freshness attestations over the HSM audit head, partitioned by result.",
		"result")
	// HSMAuditCommitments counts device-signed serial bindings of the audit head,
	// by result. Where the attestations above say when a head existed, these say
	// which device asserted it — so a sustained error rate means the log is
	// accumulating history that no hardware has vouched for, again while every
	// other check keeps reporting OK.
	HSMAuditCommitments = NewCounter(Default,
		"secsy_hsm_audit_commitments_total",
		"Device-signed commitments binding the HSM audit head to the device serial, partitioned by result.",
		"result")

	// YubiHSM key attestation (Task 168). KeyAttestations counts every
	// attestation checked, by "result": "verified", "failed" (obtained but the
	// policy was not satisfied), or "error" (the device or the input was
	// unusable). KeyAttestationFindings breaks failures down by the property
	// that could not be shown, which is the series worth alerting on — an
	// "exportable" finding on a CA key means that key can leave the HSM.
	KeyAttestations = NewCounter(Default,
		"secsy_hsm_key_attestations_total",
		"YubiHSM key attestations checked, partitioned by result.",
		"result")
	KeyAttestationFindings = NewCounter(Default,
		"secsy_hsm_key_attestation_findings_total",
		"Properties a YubiHSM key attestation failed to establish, partitioned by finding.",
		"finding")
)

// KeyAttestationResult is the subset of a key-attestation verdict this package
// needs. It is an interface rather than the concrete type so that
// internal/metrics keeps no dependency on internal/hsmattest, which config
// already imports.
type KeyAttestationResult interface {
	IsVerified() bool
	IsNonExportable() bool
	IsGeneratedOnDevice() bool
	IsDeviceBound() bool
	IsChainAnchored() bool
}

// RecordKeyAttestation records one checked key attestation.
//
// Findings are counted whenever the property is absent, not only when the
// policy required it. A deployment that relaxed the exportability check to run
// a migration still needs the count of exportable keys to be visible, and a
// series that goes quiet because someone loosened policy is the worst possible
// behaviour for this particular signal.
func RecordKeyAttestation(res KeyAttestationResult) {
	if res == nil {
		return
	}
	if res.IsVerified() {
		KeyAttestations.Inc("verified")
	} else {
		KeyAttestations.Inc("failed")
	}
	if !res.IsNonExportable() {
		KeyAttestationFindings.Inc("exportable")
	}
	if !res.IsGeneratedOnDevice() {
		KeyAttestationFindings.Inc("not-generated-on-device")
	}
	if !res.IsDeviceBound() {
		KeyAttestationFindings.Inc("unauthenticated")
	}
	if !res.IsChainAnchored() {
		KeyAttestationFindings.Inc("unanchored-chain")
	}
}

// RecordHSMAuditCollection records one successful device-log drain.
func RecordHSMAuditCollection(entries, signatures int) {
	if entries > 0 {
		HSMAuditEntries.Add(uint64(entries))
		HSMAuditSignatures.Add(uint64(signatures))
	}
	hsmAuditLastCollectNano.Store(time.Now().UnixNano())
}

// RecordHSMAuditAttestation records one freshness-attestation attempt. genTime
// is the TSA-asserted time on success; a non-nil err marks a failure.
//
// The staleness gauge is stamped with the TSA's clock rather than the host's.
// The host clock is precisely the thing an attestation exists to stop anyone
// having to trust, and seeding the gauge from it would let a skewed server
// report a fresh audit state it has no evidence for.
func RecordHSMAuditAttestation(genTime time.Time, err error) {
	if err != nil {
		HSMAuditAttestations.Inc("error")
		return
	}
	HSMAuditAttestations.Inc("success")
	hsmAuditLastAttestNano.Store(genTime.UnixNano())
}

// RecordHSMAuditCommitment records one device serial-binding attempt. genTime is
// the TSA-asserted time on success; a non-nil err marks a failure.
//
// The age gauge is stamped with the TSA's clock for the same reason the
// attestation gauge is: the host clock is one of the things the commitment
// exists to stop anyone having to trust.
// A zero genTime means the binding was made but not dated, which is not evidence
// and so must not advance the gauge — that would report a freshly bound log while
// an auditor's verdict is that nothing bounds it in time.
func RecordHSMAuditCommitment(genTime time.Time, err error) {
	if err != nil || genTime.IsZero() {
		HSMAuditCommitments.Inc("error")
		return
	}
	HSMAuditCommitments.Inc("success")
	hsmAuditLastCommitNano.Store(genTime.UnixNano())
}

// RecordCTLogMisbehavior counts one SCT a log failed to honor (never included
// after MMD, or an invalid inclusion proof) — the dedicated log-misbehavior
// signal — by log name.
func RecordCTLogMisbehavior(log string) { CTLogMisbehavior.Inc(log) }

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

// Evidence-Record (RFC 4998) preservation-job recorders.

// RecordErsGenerated counts one newly minted Evidence Record.
func RecordErsGenerated() { ErsGenerated.Inc() }

// RecordErsRenewed counts one Evidence-Record renewal of the given kind
// ("timestamp" or "hashtree").
func RecordErsRenewed(kind string) { ErsRenewed.Inc(kind) }

// RecordErsCycle records the outcome of one preservation cycle: its duration,
// any error, and — on success — the freshness timestamp, the standing record
// count, and how many records remain past their renewal threshold.
func RecordErsCycle(start time.Time, total, pendingRenewal int, err error) {
	ErsCycleDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		ErsCycleErrors.Inc()
		return
	}
	now := time.Now()
	ErsLastSuccess.Set(float64(now.Unix()))
	ersLastSuccessNano.Store(now.UnixNano())
	ErsRecordsTotal.Set(float64(total))
	ersBacklog.Store(int64(pendingRenewal))
}

// SeedErs initializes the Evidence-Record gauges from persisted state at
// startup, so the record count and staleness reflect reality before the first
// cycle. at is the newest record's created/renewed time (zero when none).
func SeedErs(total int, at time.Time) {
	ErsRecordsTotal.Set(float64(total))
	if !at.IsZero() {
		ErsLastSuccess.Set(float64(at.Unix()))
		ersLastSuccessNano.Store(at.UnixNano())
	}
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

// Token verification outcome labels (Task 86).
const (
	TokenVerifySuccess = "success"
	TokenVerifyExpired = "expired"
	TokenVerifyRevoked = "revoked"
	TokenVerifyUnknown = "unknown"
	TokenVerifyError   = "error"
)

// RecordAuthTokenOp records a scoped API token lifecycle operation by name
// (create|revoke) and success.
func RecordAuthTokenOp(operation string, ok bool) {
	if ok {
		AuthTokenOps.Inc(operation, ResultSuccess)
	} else {
		AuthTokenOps.Inc(operation, ResultError)
	}
}

// RecordAuthTokenOpDenied records a token lifecycle operation rejected by
// authorization or the approval gate.
func RecordAuthTokenOpDenied(operation string) { AuthTokenOps.Inc(operation, ResultDenied) }

// RecordAuthTokenVerify records the outcome of an API token verification. result
// is one of the TokenVerify* constants.
func RecordAuthTokenVerify(result string) { AuthTokenVerifications.Inc(result) }

// SetAuthTokensActive publishes the current count of valid API tokens.
func SetAuthTokensActive(n int) { AuthTokensActive.Set(float64(n)) }

// BRSKI result / status labels (Task 87).
const (
	BRSKIResultSuccess = "success"
	BRSKIResultDenied  = "denied"
	BRSKIResultError   = "error"
	BRSKIStatusSuccess = "success"
	BRSKIStatusFailure = "failure"
)

// RecordBRSKIVoucherRequest records a registrar voucher-request outcome. result
// is one of the BRSKIResult* constants.
func RecordBRSKIVoucherRequest(result string) { BRSKIVoucherRequests.Inc(result) }

// RecordBRSKIVoucherIssued records a built-in-MASA voucher issuance outcome.
func RecordBRSKIVoucherIssued(err error) { BRSKIVouchersIssued.Inc(resultLabel(err)) }

// RecordBRSKIStatusReport records a pledge status-telemetry report. kind is
// "voucher" or "enroll"; status is one of the BRSKIStatus* constants.
func RecordBRSKIStatusReport(kind, status string) { BRSKIStatusReports.Inc(kind, status) }

// RecordBRSKIEnrollAuthorized records an EST-handoff authorization check outcome.
func RecordBRSKIEnrollAuthorized(result string) { BRSKIEnrollAuthorized.Inc(result) }

// MS-WSTEP / MS-XCEP result labels (Task 162), shared by the Microsoft Windows
// autoenrollment web services.
const (
	MSWSTEPResultSuccess = "success"
	MSWSTEPResultDenied  = "denied"
	MSWSTEPResultError   = "error"
)

// RecordMSXCEPGetPolicies records an MS-XCEP GetPolicies (CEP) response outcome.
func RecordMSXCEPGetPolicies(result string) { MSXCEPPolicies.Inc(result) }

// RecordMSWSTEPRequest records an MS-WSTEP RequestSecurityToken (CES) issuance
// outcome. result is one of the MSWSTEPResult* constants.
func RecordMSWSTEPRequest(result string) { MSWSTEPRequests.Inc(result) }

// Durable outbound webhook subscriptions (Task 116). WebhookDeliveries counts
// terminal/retry delivery attempt outcomes (delivered|retry|dead|canceled);
// WebhookDeliveryDuration times each HTTP POST; WebhookQueueDepth and
// WebhookDeadLetters expose the durable-queue backlog and the dead-letter pile
// (the primary alert signal — an endpoint that has failed past its retry budget);
// WebhookSubscriptionsActive is the enabled-subscription count; the staleness
// FuncGauge (registered below) measures how long since the last acknowledged
// delivery.
var (
	WebhookDeliveries = NewCounter(Default,
		"secsy_webhook_deliveries_total",
		"Outbound webhook delivery attempt outcomes, by result (delivered|retry|dead|canceled).",
		"result")
	WebhookDeliveryDuration = NewHistogram(Default,
		"secsy_webhook_delivery_duration_seconds",
		"Duration of outbound webhook HTTP POST attempts in seconds.",
		DefBuckets)
	WebhookQueueDepth = NewGauge(Default,
		"secsy_webhook_queue_depth",
		"Pending outbound webhook deliveries awaiting first attempt or retry.")
	WebhookDeadLetters = NewGauge(Default,
		"secsy_webhook_dead_letters",
		"Outbound webhook deliveries in the dead-letter state (retry budget exhausted).")
	WebhookSubscriptionsActive = NewGauge(Default,
		"secsy_webhook_subscriptions_active",
		"Configured, enabled outbound webhook subscriptions.")
	WebhookLastSuccess = NewGauge(Default,
		"secsy_webhook_last_success_timestamp_seconds",
		"Unix timestamp (seconds) of the last acknowledged outbound webhook delivery.")
)

// webhookLastSuccessNano and its staleness FuncGauge follow the same
// scrape-time-computed pattern as the backup/publish/CT staleness gauges: absent
// until the first successful delivery, then climbing continuously.
var (
	webhookLastSuccessNano atomic.Int64

	_ = NewFuncGauge(Default,
		"secsy_webhook_staleness_seconds",
		"Seconds since the last acknowledged outbound webhook delivery. Absent until the first delivery succeeds.",
		func() (float64, bool) { return sinceNano(webhookLastSuccessNano.Load()) })
)

// Webhook delivery result label values.
const (
	WebhookResultDelivered = "delivered"
	WebhookResultRetry     = "retry"
	WebhookResultDead      = "dead"
	WebhookResultCanceled  = "canceled"
)

// RecordWebhookDelivered records a delivery acknowledged by an endpoint: it
// counts the outcome, observes the attempt duration, and stamps the last-success
// instants the timestamp and staleness gauges derive from.
func RecordWebhookDelivered(dur time.Duration) {
	WebhookDeliveries.Inc(WebhookResultDelivered)
	WebhookDeliveryDuration.Observe(dur.Seconds())
	now := time.Now()
	WebhookLastSuccess.Set(float64(now.Unix()))
	webhookLastSuccessNano.Store(now.UnixNano())
}

// RecordWebhookRetry records a failed-but-retryable delivery attempt.
func RecordWebhookRetry(dur time.Duration) {
	WebhookDeliveries.Inc(WebhookResultRetry)
	WebhookDeliveryDuration.Observe(dur.Seconds())
}

// RecordWebhookDead records a delivery moved to the dead-letter state.
func RecordWebhookDead(dur time.Duration) {
	WebhookDeliveries.Inc(WebhookResultDead)
	WebhookDeliveryDuration.Observe(dur.Seconds())
}

// RecordWebhookCanceled counts a pending delivery canceled because its
// subscription was disabled or deleted mid-flight.
func RecordWebhookCanceled(n int) {
	if n > 0 {
		WebhookDeliveries.Add(uint64(n), WebhookResultCanceled)
	}
}

// SetWebhookQueueGauges refreshes the durable-queue backlog gauges: pending
// deliveries awaiting work and dead-lettered deliveries awaiting triage.
func SetWebhookQueueGauges(pending, deadLetters int) {
	WebhookQueueDepth.Set(float64(pending))
	WebhookDeadLetters.Set(float64(deadLetters))
}

// SetWebhookSubscriptionsActive refreshes the enabled-subscription gauge.
func SetWebhookSubscriptionsActive(n int) { WebhookSubscriptionsActive.Set(float64(n)) }
