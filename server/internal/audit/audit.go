// Package audit provides a tamper-evident, append-only event log for all
// security-sensitive operations (key generation, CA setup, certificate
// issuance/renewal/revocation, secret encryption/decryption, and access-control
// changes).
//
// Each event records who did what, when, against which target, and with what
// result. Events are linked into a hash chain: every entry stores the SHA-256
// hash of its canonical serialization concatenated with the previous entry's
// hash. Altering, reordering, or deleting any historical entry breaks the chain
// from that point forward, which VerifyChain detects. This gives append-only
// integrity without depending on the underlying store being immutable.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenesisHash is the synthetic "previous hash" of the very first event. Using a
// fixed, well-known value anchors the chain so the first entry is covered by the
// same hashing rule as every subsequent one.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Result classifies the outcome of an audited operation.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied" // authorization was refused
	ResultError   = "error"  // the operation was authorized but failed
)

// Common action identifiers. Handlers may use any string, but sharing these
// constants keeps the log queryable and consistent.
const (
	ActionCACreate            = "ca.create"
	ActionCAInitRoot          = "ca.init_root"
	ActionCAIssueIntermediate = "ca.issue_intermediate"
	ActionCADelete            = "ca.delete"
	// Tenant lifecycle (Task 43). These are platform-level events (no owning
	// tenant of their own beyond the one they mutate).
	ActionTenantCreate = "tenant.create"
	ActionTenantUpdate = "tenant.update"
	ActionTenantDelete = "tenant.delete"
	// ActionTenantQuota records the fail-closed per-tenant issuance/secret gate
	// (Task 61) refusing an operation: ResultDenied with a detail naming the
	// exhausted quota (certs_per_day|active_certs|secret_ops_per_day) or the
	// suspended lifecycle state.
	ActionTenantQuota = "tenant.quota"
	ActionCertIssue   = "cert.issue"
	ActionCertRenew   = "cert.renew"
	ActionCertRevoke  = "cert.revoke"
	// ActionCertRevokeBulk records the summary of a bulk-revocation operation
	// (Task 70): the operation id, filters, and revoked/skipped counts. Each
	// certificate revoked by the operation additionally gets its own
	// cert.revoke event carrying the same operation id in its detail, so the
	// full set is reconstructable from the log.
	ActionCertRevokeBulk = "cert.revoke_bulk"
	// ActionCertIssueBulk records the summary of a batch-issuance operation
	// (Task 101): the operation id and the requested/issued/pending/failed
	// counts. Each certificate issued by the operation additionally gets its own
	// cert.issue event carrying the same operation id (bulk_op) in its detail, so
	// the full set is reconstructable from the log — exactly as bulk revocation
	// pairs cert.revoke_bulk with per-certificate cert.revoke events.
	ActionCertIssueBulk = "cert.issue_bulk"
	// ActionCertSuspend records a reversible certificate hold (RFC 5280
	// certificateHold, Task 82): the certificate is revoked with reason
	// certificateHold and can be returned to service with a release.
	ActionCertSuspend = "cert.suspend"
	// ActionCertRelease records the removal of a certificate hold, returning the
	// certificate to service (OCSP good, dropped from the base CRL, removeFromCRL
	// emitted in the next delta CRL).
	ActionCertRelease = "cert.release"
	// ActionSVIDIssue records the minting of a SPIFFE X.509-SVID. The detail
	// carries the spiffe:// identity, trust domain, and profile.
	ActionSVIDIssue = "svid.issue"
	// ActionSVIDIssueJWT records the minting of a SPIFFE JWT-SVID. The detail
	// carries the spiffe:// identity, trust domain, audience, and kid.
	ActionSVIDIssueJWT = "svid.issue_jwt"
	// ActionCRLPublish records the HSM-signed generation of a base or delta CRL
	// for a CA scope (full or a partition shard). The detail carries the scope,
	// kind, CRL number, and entry count.
	ActionCRLPublish = "crl.publish"
	// ActionCertLint records the outcome of the pre-issuance lint gate when it
	// produces findings: ResultError when an enforce-mode check blocked signing
	// (fail-closed), ResultSuccess when only warnings were emitted.
	ActionCertLint = "cert.lint"
	// ActionCertCAA records the outcome of the pre-issuance CAA gate (RFC 8659)
	// when it produces findings: ResultError when an enforce-mode check blocked
	// issuance (fail-closed), ResultSuccess when a permissive-mode check reported
	// a forbidding record without blocking.
	ActionCertCAA = "cert.caa"
	// ActionCertNameConstraint records the pre-issuance Name Constraints gate (RFC
	// 5280 §4.2.1.10) blocking a leaf whose subject or SAN falls outside the
	// issuing CA's permitted subtrees or inside an excluded subtree (fail-closed).
	ActionCertNameConstraint = "cert.nameconstraint"
	// ActionCertSMIME records the pre-issuance S/MIME gate blocking an
	// email-protection leaf whose rfc822Name SANs are malformed or whose e-mail
	// domains fall outside the profile or tenant allowlists (fail-closed).
	ActionCertSMIME = "cert.smime"
	// ActionCertUPN records the pre-issuance UPN gate (Task 122, smartcard-logon /
	// PKINIT profiles) blocking a leaf whose User Principal Name SAN is malformed,
	// whose realm falls outside the profile or tenant realm allowlists, that
	// carries a UPN on a non-UPN profile, or that omits a required UPN (fail-closed).
	ActionCertUPN = "cert.upn"
	// ActionCertKeyCheck records the outcome of the pre-issuance key-quality gate
	// (Task 120, CA/Browser Forum BR §6.1.1.3) when it produces findings: ResultError
	// when an enforce-mode check blocked issuance (fail-closed) — a weak (ROCA /
	// weak-exponent / small-or-even-modulus) or known-compromised (Debian weak-key /
	// operator-blocked / reused) subject key — ResultSuccess when a warn-mode check
	// reported findings without blocking. The detail carries the profile, the
	// key-fingerprint, and the finding codes.
	ActionCertKeyCheck = "cert.keycheck"
	// ActionKeyBlock / ActionKeyUnblock record operator management of the
	// compromised-key blocklist (Task 120): adding a public key the CA must never
	// certify again, or removing one. The target is the key fingerprint; the detail
	// carries the reason.
	ActionKeyBlock   = "key.block"
	ActionKeyUnblock = "key.unblock"
	// ActionCertAttestation records the outcome of the enrollment key-attestation
	// gate (Task 49) on the EST/SCEP/ACME device-enrollment paths: ResultSuccess
	// when a hardware attestation verified (or a permissive-mode check let a
	// missing/invalid attestation through), ResultDenied when a required
	// attestation was missing or failed to verify and enrollment was blocked
	// fail-closed. The detail carries the format, manufacturer, and device serial.
	ActionCertAttestation = "cert.attestation"
	// ActionCertBRSKI records a BRSKI (RFC 8995) zero-touch onboarding event on
	// the registrar: ResultSuccess when a voucher was issued and the pledge
	// authorized to EST-enroll, ResultDenied when the pledge's IDevID was
	// untrusted / the proximity or serial assertion failed, ResultError when the
	// request was malformed or the MASA declined. voucher_status / enrollstatus
	// telemetry reports are logged under the same action. The detail carries the
	// pledge serial, profile, and the specific reason. Actor is "brski-pledge:<serial>".
	ActionCertBRSKI = "cert.brski"
	// ActionCertAutoRenew records a certificate reissued automatically by the
	// expiry monitor (actor "monitor"), ahead of its expiry.
	ActionCertAutoRenew = "cert.auto_renew"
	// ActionCertExpiryScan records a completed expiry-monitor scan cycle.
	ActionCertExpiryScan = "cert.expiry_scan"
	// ActionCertDiscover records a completed external certificate discovery scan
	// (Task 54). The detail carries the endpoint/stored/rogue/expiring counts.
	ActionCertDiscover = "cert.discover"
	// ActionCanaryProbe records one synthetic issuance-canary probe (Task 71):
	// issue → chain verify → OCSP good → CRL freshness → revoke → revoked
	// propagation against one CA. Result is success or error; the detail carries
	// the probed serial, per-stage timings, and (on error) the failed stage.
	// `secsy-ca doctor` reads the newest of these to surface the last canary
	// outcome.
	ActionCanaryProbe = "canary.probe"
	// ActionCTInclusion records one Certificate Transparency SCT inclusion-proof
	// verification scan (Task 93): the monitor fetches each log's signed tree head
	// and the get-proof-by-hash Merkle audit path for embedded SCTs whose log
	// Maximum Merge Delay has elapsed, and verifies inclusion against the SCT's
	// log id and timestamp. Result is success when the scan completed with no log
	// misbehavior, or error when a log failed to honor an SCT it issued (never
	// included, or an inclusion proof that did not verify — a mis-issuance
	// signal). The detail carries the checked/included/pending/failed counts.
	// `secsy-ca doctor` reads the newest to surface inclusion-monitor freshness.
	ActionCTInclusion  = "ct.inclusion"
	ActionCertSignSSH  = "cert.sign_ssh"
	ActionCertSignX509 = "cert.sign_x509"
	// ActionCertPKCS12 records a server-side-keygen PKCS#12 (.p12/.pfx) export
	// (Task 80): a subject keypair is generated, a leaf is issued, and the leaf,
	// key, and full chain are packed into a password-protected bundle. The detail
	// carries the profile, key type, and encoder; a paired secret.escrow event is
	// emitted when the subject key is additionally escrowed under the M-of-N
	// policy.
	ActionCertPKCS12 = "cert.pkcs12"

	// ActionCertDelegatedCredential records the minting of an RFC 9345 TLS
	// delegated credential (Task 133): a short-lived credential signed by an
	// end-entity certificate's private key, which the system recovers from the
	// PKCS#12 escrow (Task 33) for this endpoint. Target is the issuing CA; the
	// certificate serial, validity, and signature scheme travel in the detail. A
	// paired secret.recover event records the escrow-recovery ceremony.
	ActionCertDelegatedCredential = "cert.delegated_credential"

	// Per-profile manual issuance-approval gate (Task 84). When a certificate
	// profile sets require_approval, operator/API-driven leaf issuance is routed
	// through the four-eyes engine instead of executing immediately.
	// ActionCertIssuePending records a leaf-issuance request parked for approval
	// (the certificate is NOT issued yet); ActionCertIssueApproved records the
	// certificate being completed and delivered once the approver threshold was
	// met; ActionCertIssueDenied records a request that will never issue because
	// it was rejected or expired. These complement the generic approval.* events
	// the engine records for every guarded class. Target is the issuing CA; the
	// approval request id travels in the detail.
	ActionCertIssuePending  = "cert.issue.pending"
	ActionCertIssueApproved = "cert.issue.approved"
	ActionCertIssueDenied   = "cert.issue.denied"

	// SSH certificate authority (Task 57). ActionSSHCAInit records creation of
	// an HSM-backed SSH CA. ActionSSHSign records an OpenSSH user/host
	// certificate signed under a profile (target: CA; detail: serial, type, key
	// ID, principals). ActionSSHRevoke records a revocation by serial or key ID
	// — the entries a generated KRL publishes to relying hosts.
	ActionSSHCAInit = "ssh.ca_init"
	ActionSSHSign   = "ssh.sign"
	ActionSSHRevoke = "ssh.revoke"

	ActionSecretEncrypt = "secret.encrypt"
	ActionSecretDecrypt = "secret.decrypt"
	// ActionSecretEscrow records that a secret was sealed with an M-of-N key
	// escrow (the DEK Shamir-split across recovery agents). The target is the KEK
	// label; the detail records the threshold, agent count, and agent IDs.
	ActionSecretEscrow = "secret.escrow"
	// ActionSecretRecover records an escrow recovery ceremony: reconstructing a
	// data key from a quorum of recovery agents and decrypting the secret. The
	// detail records the participating agent IDs and the threshold met. Recovery
	// is a privileged, dual-control break-glass operation, logged distinctly from
	// routine secret.decrypt so it stands out in the audit trail.
	ActionSecretRecover = "secret.recover"
	// Secret-layer KEK rotation lifecycle (Task 63). ActionSecretKEKRotate
	// records that a family's next versioned wrapping key was generated in the
	// HSM and made active (target: family; detail: old/new version and label).
	// ActionSecretRewrap records a DEK re-wrap batch migrating stored secrets
	// onto the active KEK (detail: per-result counts). ActionSecretKEKRetire
	// records that a superseded KEK version was withdrawn from service —
	// decryption under it is refused fail-closed from then on.
	ActionSecretKEKRotate = "secret.kek_rotate"
	ActionSecretRewrap    = "secret.rewrap"
	ActionSecretKEKRetire = "secret.kek_retire"
	// ActionSecretStore / ActionSecretStoreDelete record the lifecycle of
	// server-held envelopes in the stored-secret registry (the encryption
	// itself is additionally recorded as secret.encrypt).
	ActionSecretStore       = "secret.store"
	ActionSecretStoreDelete = "secret.store_delete"
	// Stored-secret value lifecycle (Task 73). ActionSecretPut records a new
	// value version being written (target: KEK family; target name: secret
	// name; detail: id and new version). ActionSecretRollback records the
	// current value being reverted to an earlier version — implemented as an
	// append, so the detail carries both the source and the new version.
	// ActionSecretExec records secrets being decrypted for injection into a
	// child process environment via `secsy-secret exec`; the detail lists the
	// secret NAMES and the command, never any plaintext.
	ActionSecretPut         = "secret.put"
	ActionSecretRollback    = "secret.rollback"
	ActionSecretExec        = "secret.exec"
	ActionPermissionGrant   = "permission.grant"
	ActionPermissionRevoke  = "permission.revoke"
	ActionGroupCreate       = "group.create"
	ActionGroupDelete       = "group.delete"
	ActionHSMProvisionAudit = "hsm.provision_audit"
	ActionHSMFactoryReset   = "hsm.factory_reset"
	// Key-ceremony, backup, and disaster-recovery lifecycle operations. A
	// ceremony records its start, each operator's M-of-N confirmation, and its
	// completion (or abort) alongside the underlying ca.init_root /
	// ca.issue_intermediate events. Backup/restore record DR bundle creation and
	// verification. None of these ever handle private key material.
	ActionCeremonyStart           = "ceremony.start"
	ActionCeremonyOperatorConfirm = "ceremony.operator_confirm"
	ActionCeremonyComplete        = "ceremony.complete"
	ActionCeremonyAbort           = "ceremony.abort"
	ActionHSMBackup               = "hsm.backup"
	ActionHSMRestore              = "hsm.restore"
	// Scheduled encrypted-backup job (Task 89): one backup.run event per
	// completed cycle of the leader-elected backup loop, recording the driver,
	// artifact size, audit-chain head, and retention outcome (or the failure).
	ActionBackupRun = "backup.run"
	// Automated backup restore-verification (Task 94): one backup.verify event
	// per restore-verification drill — the newest published backup artifact is
	// decrypted, restored into an isolated scratch database, integrity-checked,
	// and its restored audit-head fingerprint matched against the manifest. The
	// result is success or error (an unrestorable / tampered backup).
	ActionBackupVerify = "backup.verify"
	// Intermediate-CA key rotation / rollover (Task 24). Rotate records a new key
	// being cross-signed under the parent and the old key entering the overlap
	// window; Retire records the old key being revoked under its parent after the
	// overlap drains. No private key material is ever handled.
	ActionCARotate = "ca.rotate"
	ActionCARetire = "ca.retire"
	// ActionCACrossSign records an issuer CA cross-signing a subject public key
	// (Task 47): a second certificate for the same subordinate key, enabling
	// bridge-CA and root-transition alternate chains. No private key material is
	// handled; the subject key is certified, not imported.
	ActionCACrossSign = "ca.cross_sign"
	// Externally-signed subordinate CA flow (Task 69). CSR records an HSM-backed
	// CA key being generated and its PKCS#10 request emitted for an external
	// parent (offline corporate root / third-party bridge); ImportCert records
	// the externally signed certificate being validated and installed. Only the
	// CSR and certificates cross the trust boundary — never key material.
	ActionCACSR        = "ca.csr"
	ActionCAImportCert = "ca.import_cert"
	// ACME (RFC 8555) protocol operations. The actor for these is the ACME
	// account ("acme:<account-id>") rather than an OIDC/root principal, since
	// ACME clients authenticate with their own account keys.
	ActionACMEAccountNew    = "acme.account.new"
	ActionACMEOrderNew      = "acme.order.new"
	ActionACMEOrderFinalize = "acme.order.finalize"
	ActionACMEChallenge     = "acme.challenge"
	ActionACMECertRevoke    = "acme.cert.revoke"
	// ActionACMERenewalInfo records a served ARI (draft-ietf-acme-ari) renewal-info
	// lookup, and ActionACMEOrderReplaces records a newOrder that linked to a
	// predecessor certificate via the "replaces" field.
	ActionACMERenewalInfo   = "acme.renewal_info"
	ActionACMEOrderReplaces = "acme.order.replaces"
	// ActionACMEEmail records the lifecycle of an RFC 8823 email-reply-00
	// challenge for an "email"-type identifier (S/MIME issuance via ACME): the
	// signed challenge email being dispatched to the mailbox, and the mailbox
	// owner's reply being validated (or rejected) against the expected
	// key-authorization digest.
	ActionACMEEmail = "cert.acme_email"

	// SCEP (RFC 8894) and EST (RFC 7030) device-enrollment actions. The actor is
	// the enrollment grant / authenticated principal rather than an OIDC subject,
	// since these protocols authenticate with a challenge password, HTTP Basic, or
	// a TLS client certificate.
	ActionSCEPGetCACert   = "scep.get_ca_cert"
	ActionSCEPEnroll      = "scep.enroll"
	ActionSCEPRenew       = "scep.renew"
	ActionESTCACerts      = "est.cacerts"
	ActionESTCSRAttrs     = "est.csrattrs"
	ActionESTEnroll       = "est.simpleenroll"
	ActionESTReenroll     = "est.simplereenroll"
	ActionESTServerKeyGen = "est.serverkeygen"

	// RFC 3161 Time-Stamp Authority. A timestamp is issued anonymously (the
	// public /tsa endpoint), so the actor is a fixed pseudo-principal and the
	// target is the issued token serial.
	ActionTSATimestamp = "tsa.timestamp"

	// ActionAuditAnchor records an anchoring of this very log's head hash into
	// an RFC 3161 timestamp token (Task 64): ResultSuccess with the covered
	// (seq, head hash), token genTime, and TSA source in the detail, or
	// ResultError when obtaining/persisting the token failed. Because the event
	// itself is chained (and exported to SIEM sinks), it doubles as an external
	// record of the anchored head even if the local anchor row is later deleted.
	ActionAuditAnchor = "audit.anchor"

	// Artifact (code) signing (Task 60). ActionArtifactSign records a CMS
	// detached signature produced with an HSM-held code-signing key: the target
	// is the signer name, the detail carries the artifact digest, digest
	// algorithm, and whether an RFC 3161 countersignature was embedded — enough
	// to later answer "what exactly did we sign, when, and with which key".
	// ActionArtifactVerify records a verification request and its outcome.
	ActionArtifactSign   = "artifact.sign"
	ActionArtifactVerify = "artifact.verify"

	// Lightweight CMP (RFC 9483) certificate-management actions. The actor is the
	// shared-secret reference value (PBM) or the subject of the signing
	// certificate, since CMP authenticates with its own message protection rather
	// than an OIDC subject.
	ActionCMPInitialization = "cmp.ir"
	ActionCMPCertification  = "cmp.cr"
	ActionCMPKeyUpdate      = "cmp.kur"
	ActionCMPRevocation     = "cmp.rr"
	ActionCMPCertConfirm    = "cmp.certconf"

	// Operator authentication (Task 50). These record how a console/API principal
	// authenticated and any subsequent step-up. The actor is the resolved
	// principal (OIDC subject, mTLS-bound identity, or "root"); a failed login has
	// no established actor and records the attempted identity in Detail. The target
	// is the session id (opaque) so a login can be correlated with its logout.
	ActionAuthLogin        = "auth.login"          // a session was established
	ActionAuthLoginFailed  = "auth.login_failed"   // authentication was rejected
	ActionAuthLogout       = "auth.logout"         // a session was terminated
	ActionAuthStepUp       = "auth.step_up"        // WebAuthn step-up satisfied
	ActionAuthStepUpDenied = "auth.step_up_denied" // a high-risk op lacked step-up
	// WebAuthn passkey lifecycle for step-up authentication.
	ActionWebAuthnRegister = "webauthn.register" // a passkey was enrolled
	ActionWebAuthnRemove   = "webauthn.remove"   // a passkey was removed

	// Native scoped API tokens / service accounts (Task 86). ActionTokenCreate
	// records minting a token (Detail carries the granted roles, scope, and
	// expiry; the secret is never logged); ActionTokenRevoke records revoking one.
	// The token id is the Target so a token and its lifecycle events correlate.
	// Verification failures are surfaced via metrics rather than the audit log to
	// avoid unbounded, actor-less noise from probing.
	ActionTokenCreate = "token.create" // an API token / service account was minted
	ActionTokenRevoke = "token.revoke" // an API token was revoked

	// Durable outbound webhook subscriptions (Task 116). ActionWebhookCreate
	// records registering an external endpoint; ActionWebhookUpdate records an
	// enable/disable toggle; ActionWebhookDelete records removing one.
	// ActionWebhookDeliver records a terminal delivery outcome (ResultSuccess when
	// the endpoint acknowledged the event, ResultError when the retry budget was
	// exhausted and the delivery was dead-lettered); transient, retryable failures
	// are not audited to avoid flooding the chain. The subscription id is the
	// Target so a subscription and all deliveries to it correlate.
	ActionWebhookCreate  = "webhook.create"
	ActionWebhookUpdate  = "webhook.update"
	ActionWebhookDelete  = "webhook.delete"
	ActionWebhookDeliver = "webhook.deliver"

	// Four-eyes / maker-checker approval workflow (Task 81). ActionApprovalRequest
	// records a guarded operation being held at the gate (a request created);
	// ActionApprovalApprove and ActionApprovalReject record each approver's
	// decision (a self-approval attempt is ResultDenied); ActionApprovalExecute
	// records the gate consuming an approved request to authorize the operation;
	// ActionApprovalExpire records a stale request being retired. The request id
	// is the Target so a request and all decisions on it correlate.
	ActionApprovalRequest = "approval.request"
	ActionApprovalApprove = "approval.approve"
	ActionApprovalReject  = "approval.reject"
	ActionApprovalExecute = "approval.execute"
	ActionApprovalExpire  = "approval.expire"
)

// Event is a single entry in the tamper-evident audit log. Seq is a
// monotonically increasing sequence number assigned by the store; PrevHash and
// Hash form the tamper-evidence chain and are populated by Seal.
type Event struct {
	Seq        int64     `json:"seq"`
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"` // authenticated subject (OIDC sub or "root")
	ActorName  string    `json:"actor_name,omitempty"`
	ActorRoles string    `json:"actor_roles,omitempty"` // roles held at the time of the action
	Action     string    `json:"action"`                // e.g. "cert.issue"
	// Tenant is the owning tenant of the acted-on resource (empty for
	// platform-level events not scoped to any tenant). It is bound into the hash
	// chain (see canonicalBytes) so an event cannot be silently re-attributed to a
	// different tenant, and the listing API filters on it so one tenant's auditors
	// never see another tenant's trail.
	Tenant     string `json:"tenant,omitempty"`
	Target     string `json:"target,omitempty"`      // stable id of the object acted on (CA id, serial)
	TargetName string `json:"target_name,omitempty"` // human label (CA label, common name)
	Result     string `json:"result"`                // ResultSuccess | ResultDenied | ResultError
	Detail     string `json:"detail,omitempty"`
	IP         string `json:"ip,omitempty"`
	// RequestID correlates this event with the structured request log line for
	// the HTTP request that produced it. It is contextual metadata and is
	// deliberately NOT part of the hash-chain canonicalization (see
	// canonicalBytes): it does not affect tamper-evidence, and excluding it keeps
	// the chain hashing rule stable and backward-compatible with logs written
	// before this field existed.
	RequestID string `json:"request_id,omitempty"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// canonicalBytes produces a deterministic, unambiguous serialization of the
// event's content bound to prevHash. Every field is length-prefixed so that no
// combination of field values can be rearranged to collide with another
// event (e.g. actor="ab", action="c" must not hash-equal actor="a", action="bc").
func canonicalBytes(e *Event, prevHash string) []byte {
	var b bytes.Buffer
	writeField := func(s string) {
		var lenbuf [4]byte
		binary.BigEndian.PutUint32(lenbuf[:], uint32(len(s)))
		b.Write(lenbuf[:])
		b.WriteString(s)
	}
	var seqbuf [8]byte
	binary.BigEndian.PutUint64(seqbuf[:], uint64(e.Seq))
	b.Write(seqbuf[:])
	writeField(prevHash)
	writeField(e.ID)
	// RFC3339Nano in UTC is a stable, round-trippable timestamp encoding.
	writeField(e.Timestamp.UTC().Format(time.RFC3339Nano))
	writeField(e.Actor)
	writeField(e.ActorName)
	writeField(e.ActorRoles)
	writeField(e.Action)
	writeField(e.Target)
	writeField(e.TargetName)
	writeField(e.Result)
	writeField(e.Detail)
	writeField(e.IP)
	// Tenant is appended conditionally: events written before multi-tenancy (and
	// platform-level events with no tenant) have an empty Tenant and hash exactly
	// as before, keeping historical chains verifiable. A tenant-scoped event binds
	// its tenant into the chain under a domain-separating "tenant" tag so it cannot
	// be re-attributed to another tenant without breaking verification.
	if e.Tenant != "" {
		writeField("tenant")
		writeField(e.Tenant)
	}
	return b.Bytes()
}

// ComputeHash returns the chain hash for an event given the previous entry's
// hash. It is deterministic and depends on every content field plus prevHash.
func ComputeHash(e *Event, prevHash string) string {
	sum := sha256.Sum256(canonicalBytes(e, prevHash))
	return hex.EncodeToString(sum[:])
}

// Seal assigns the sequence number, links the event to prevHash, and computes
// its hash. The store calls this inside the same critical section that reads the
// previous hash and inserts the row, so the chain stays consistent under
// concurrency.
func Seal(e *Event, seq int64, prevHash string) {
	if prevHash == "" {
		prevHash = GenesisHash
	}
	e.Seq = seq
	e.PrevHash = prevHash
	e.Hash = ComputeHash(e, prevHash)
}

// VerifyResult reports the outcome of verifying a chain.
type VerifyResult struct {
	Valid       bool   `json:"valid"`
	Count       int    `json:"count"`
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"` // sequence number of the first bad entry
	Reason      string `json:"reason,omitempty"`
}

// VerifyFullChain verifies a COMPLETE log (from the genesis entry onward). In
// addition to the checks in VerifyChain it requires the first entry to be the
// genesis (Seq == 1 with PrevHash == GenesisHash). This additionally detects
// head deletion and whole-log re-genesis, which VerifyChain (which tolerates a
// tail slice starting at an arbitrary Seq) cannot. Callers verifying the entire
// stored log should use this.
//
// Note: neither function can detect truncation of the newest entries without an
// externally anchored head checkpoint. Deployments needing that guarantee
// should periodically anchor the current (seq, hash) out-of-band — the
// HSM-signed audit log provides exactly such an Ed25519-signed anchor.
func VerifyFullChain(events []Event) VerifyResult {
	if len(events) > 0 {
		first := events[0]
		if first.Seq != 1 || !strings.EqualFold(first.PrevHash, GenesisHash) {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: first.Seq,
				Reason: "log does not start at the genesis entry (seq 1); head entries may have been deleted"}
		}
	}
	return VerifyChain(events)
}

// VerifyChain recomputes the hash chain over events (which must be ordered by
// ascending Seq) and reports the first inconsistency, if any. It detects
// content tampering, hash forgery, broken back-links, and reordering/deletion
// (via non-contiguous sequence numbers).
func VerifyChain(events []Event) VerifyResult {
	prevHash := GenesisHash
	var prevSeq int64
	for i := range events {
		e := &events[i]

		// Sequence numbers must be strictly increasing and, for a complete log
		// starting at the genesis, contiguous — a gap means an entry was
		// removed. We allow the first observed Seq to be any value so a caller
		// can verify a tail slice, but within the slice they must be contiguous.
		if i > 0 && e.Seq != prevSeq+1 {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: fmt.Sprintf("non-contiguous sequence: expected %d, got %d", prevSeq+1, e.Seq)}
		}
		// The recorded back-link must match the running hash.
		if i > 0 && e.PrevHash != prevHash {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: "prev_hash does not match preceding entry"}
		}
		want := ComputeHash(e, e.PrevHash)
		if !strings.EqualFold(want, e.Hash) {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: "content hash mismatch (entry was modified)"}
		}
		prevHash = e.Hash
		prevSeq = e.Seq
	}
	return VerifyResult{Valid: true, Count: len(events)}
}
