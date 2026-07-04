package database

import (
	"context"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Store is the persistence abstraction for the PKI's shared state. It captures
// every operation the higher layers (CA/issuance, revocation, ACME, audit, and
// secret-metadata subsystems) require of the backing store, independent of the
// concrete engine behind it.
//
// The embedded SQLite implementation is the default, self-contained "file store"
// suitable for a single node; the PostgreSQL implementation backs multi-replica
// high availability. Both are provided by the same *DB type — the driver is
// selected at construction (see New / NewWithOptions) and every query is written
// portably (placeholder rebinding in ph, dialect-aware DDL in migrate). Defining
// the contract as an interface lets callers depend on the capability rather than
// the engine, documents the surface a new backend must satisfy, and makes the
// store mockable in tests.
//
// The compile-time assertion below guarantees *DB continues to satisfy Store as
// the schema evolves; a missing or drifted method breaks the build here rather
// than at a distant call site.
type Store interface {
	Lifecycle
	TenantStore
	CAStore
	CrossSignStore
	InventoryStore
	DiscoveryStore
	RevocationStore
	CRLStore
	SSHStore
	ACMEStore
	ACMENonceStore
	AuditStore
	RBACStore
	SecretStore
	ApprovalStore
	APITokenStore
	CTInclusionStore
	WebhookStore
	BlockedKeyStore
}

// BlockedKeyStore persists the operator-managed compromised-key blocklist (Task
// 120): public keys the CA must never certify again, keyed by their
// SubjectPublicKeyInfo SHA-256 fingerprint. It holds no key material. IsKeyBlocked
// is the O(1) lookup on the fail-closed pre-issuance path; AddBlockedKey and
// RemoveBlockedKey report whether they changed anything so blocking/un-blocking is
// idempotent and auditable. DistinctSubjectsForKeyFingerprint (on InventoryStore)
// backs the companion duplicate/reused-subject-key detection.
type BlockedKeyStore interface {
	AddBlockedKey(k *models.BlockedKey) (bool, error)
	GetBlockedKey(fingerprint string) (*models.BlockedKey, error)
	IsKeyBlocked(fingerprint string) (bool, error)
	ListBlockedKeys() ([]models.BlockedKey, error)
	RemoveBlockedKey(fingerprint string) (bool, error)
	CountBlockedKeys() (int, error)
}

// WebhookStore persists durable outbound webhook subscriptions and their
// delivery queue (Task 116). It is deliberately at-least-once and crash-safe:
// the fan-out (event log → deliveries) is idempotent through
// UNIQUE(subscription_id, event_seq) so a re-scanned range never double-enqueues,
// and the delivery worker's terminal/retry transitions are single writes so a
// leadership handover at worst redelivers the last unacknowledged attempt (which
// the HMAC-signed, EventID-keyed payload lets receivers deduplicate). The fan-out
// cursor is the shared high-water mark that makes the whole pipeline resumable.
type WebhookStore interface {
	CreateWebhookSubscription(s *models.WebhookSubscription) error
	GetWebhookSubscription(id string) (*models.WebhookSubscription, error)
	ListWebhookSubscriptions(tenantID string) ([]models.WebhookSubscription, error)
	ListEnabledWebhookSubscriptions() ([]models.WebhookSubscription, error)
	SetWebhookSubscriptionEnabled(id string, enabled bool) (bool, error)
	DeleteWebhookSubscription(id string) (bool, error)

	EnqueueWebhookDelivery(d *models.WebhookDelivery) error
	GetWebhookDelivery(id string) (*models.WebhookDelivery, error)
	ListDueWebhookDeliveries(now time.Time, limit int) ([]models.WebhookDelivery, error)
	ListWebhookDeliveries(subscriptionID, status string, limit int) ([]models.WebhookDelivery, error)
	MarkWebhookDeliverySucceeded(id string, at time.Time, statusCode int) error
	MarkWebhookDeliveryRetry(id string, at, nextAttempt time.Time, statusCode int, errMsg string) error
	MarkWebhookDeliveryDead(id string, at time.Time, statusCode int, errMsg string) error
	CancelPendingWebhookDeliveries(subscriptionID string) (int64, error)
	CountWebhookDeliveriesByStatus() (map[string]int, error)
	OldestDeadWebhookDelivery() (*models.WebhookDelivery, error)

	GetWebhookCursor() (int64, error)
	WebhookCursorInitialized() (bool, error)
	SetWebhookCursor(seq int64) error
}

// ACMENonceStore persists the shared, durable anti-replay nonce state (Task 97)
// so the ACME server is correct across replicas. It holds two pieces of shared
// state: the server-wide HMAC secret every replica uses to mint and verify
// self-authenticating nonces, and the consumed-set that enforces true single use
// — a nonce minted by one replica is accepted by another exactly once, and any
// later replay (on any replica) is rejected. The consumed-set is the only durable
// write on the nonce path; issuance and every rejected (malformed/forged/expired)
// nonce are validated in-process without touching the store.
type ACMENonceStore interface {
	// GetOrCreateACMENonceSecret returns the shared nonce-signing secret,
	// generating a fresh random one on first use. Concurrent callers across
	// replicas converge on a single value (insert-if-absent, then read).
	GetOrCreateACMENonceSecret() ([]byte, error)
	// ConsumeACMENonce atomically records a nonce as consumed, returning true the
	// first time it is seen (valid, single use) and false if it was already
	// present (replay). expiresAt bounds how long the record is retained for GC.
	ConsumeACMENonce(nonceHash string, expiresAt time.Time) (bool, error)
	// GCACMENonces deletes consumed-nonce records whose expiry has passed and
	// reports how many were removed. Pruning an expired record is safe: an expired
	// nonce is rejected by its embedded-timestamp check before the consumed-set is
	// consulted.
	GCACMENonces(now time.Time) (int64, error)
}

// CTInclusionStore persists the Certificate Transparency SCT inclusion-proof
// verification state (Task 93): one row per embedded SCT, upserted by the
// leader-elected inclusion monitor each time it checks whether a log has honored
// an SCT it issued. A 'failed' row is the mis-issuance / log-misbehavior signal
// surfaced through the read API, the doctor check, and the alert sinks.
type CTInclusionStore interface {
	UpsertSCTInclusion(r *models.SCTInclusion) error
	GetSCTInclusion(caID, serial, logID string) (*models.SCTInclusion, error)
	ListSCTInclusionForCert(caID, serial string) ([]models.SCTInclusion, error)
	ListSCTInclusionByStatus(status string, limit int) ([]models.SCTInclusion, error)
	CountSCTInclusionByStatus() (map[string]int, error)
	ListCertificatesPendingInclusion(limit int) ([]models.IssuedCertificate, error)
}

// APITokenStore persists native scoped API tokens / service accounts (Task 86):
// the opaque credential's one-way hash, its RBAC-role/tenant-scope binding, and
// its lifecycle (expiry, last-used, revocation). The plaintext secret is never
// stored; GetAPITokenByHash is the O(1) verification lookup, and revocation is
// idempotent (RevokeAPIToken applies only while the token is un-revoked).
type APITokenStore interface {
	CreateAPIToken(t *models.APIToken) error
	GetAPITokenByHash(hash string) (*models.APIToken, error)
	GetAPIToken(id string) (*models.APIToken, error)
	ListAPITokens(tenantID string) ([]models.APIToken, error)
	RevokeAPIToken(id, by string, at time.Time) (bool, error)
	TouchAPIToken(id string, at time.Time, ip string) error
	CountActiveAPITokens() (int, error)
}

// ApprovalStore persists the four-eyes / maker-checker approval workflow (Task
// 81): pending high-risk-operation requests and the per-approver decisions on
// them. The distinct-approver threshold is enforced by the
// UNIQUE(approval_id, approver) constraint, and status transitions are
// optimistic (SetApprovalStatus applies only from the expected prior status) so
// an approved request is consumed at most once under concurrency. It structurally
// satisfies approval.Store; the method set is kept in lockstep with it.
type ApprovalStore interface {
	CreatePendingApproval(a *models.PendingApproval) error
	GetPendingApproval(id string) (*models.PendingApproval, error)
	FindOpenApproval(tenantID, class, fingerprint string) (*models.PendingApproval, error)
	ListPendingApprovals(tenantID, status, class string, limit int) ([]models.PendingApproval, error)
	ListApprovalDecisions(approvalID string) ([]models.ApprovalDecision, error)
	AddApprovalDecision(d *models.ApprovalDecision) (bool, error)
	CountApprovalDecisions(approvalID, decision string) (int, error)
	SetApprovalStatus(id, from, to string, at time.Time) (bool, error)
	ListExpirableApprovals(now time.Time) ([]models.PendingApproval, error)
}

// SecretStore persists the secret-layer KEK rotation state (Task 63): the
// versioned key-encryption-key lineage per family and the registry of
// server-held envelopes, which is what makes fleet-wide re-wrap ("which
// secrets still sit on an old KEK?") an enumerable operation. Neither table
// ever holds key material or plaintext.
type SecretStore interface {
	// KEK rotation lineage. RotateKEKVersion atomically supersedes the active
	// version (active → retiring) and installs the new one, backfilling the
	// implicit version 1 on a family's first rotation.
	ListKEKVersions(family string) ([]models.KEKVersion, error)
	ListKEKFamilies() ([]string, error)
	RotateKEKVersion(newVersion *models.KEKVersion) error
	SetKEKVersionStatus(family string, version int, status string) (bool, error)

	// Server-held envelopes. UpdateStoredSecretEnvelope is optimistic (applies
	// only while the row still carries the expected KEK label) so concurrent
	// re-wraps never clobber newer ciphertext.
	CreateStoredSecret(s *models.StoredSecret, createdBy, comment string) error
	GetStoredSecret(id string) (*models.StoredSecret, error)
	GetStoredSecretByName(tenantID, name string) (*models.StoredSecret, error)
	ListStoredSecrets(tenantID string) ([]models.StoredSecret, error)
	ListStoredSecretsWithSchedule() ([]models.StoredSecret, error)
	PutStoredSecretVersion(p *PutSecretVersion) (*models.StoredSecret, error)
	ListStoredSecretVersions(secretID string) ([]models.StoredSecretVersion, error)
	GetStoredSecretVersion(secretID string, version int) (*models.StoredSecretVersion, error)
	ListStoredSecretIDsForRewrap(family, activeLabel string) ([]string, error)
	UpdateStoredSecretEnvelope(id, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error)
	ListStoredSecretVersionRefsForRewrap(family, activeLabel string) ([]models.SecretVersionRef, error)
	UpdateStoredSecretVersionEnvelope(secretID string, version int, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error)
	DeleteStoredSecret(id string) (bool, error)
	CountStoredSecretsOnKEK(label string) (int64, error)
	CountStoredSecretsByKEKLabel(family string) (map[string]int64, error)
}

// TenantStore persists the top-level isolation boundary. Every deployment has
// the built-in default tenant; additional tenants let one deployment serve
// several isolated organizations. Tenant-scoped resources (CAs, restriction
// sets, groups, audit events) carry the owning tenant, and the higher layers
// forbid a principal from reaching a tenant it is not a member of.
type TenantStore interface {
	CreateTenant(t *models.Tenant) error
	GetTenant(id string) (*models.Tenant, error)
	GetTenantBySlug(slug string) (*models.Tenant, error)
	ListTenants() ([]models.Tenant, error)
	SetTenantStatus(id, status string) error
	UpdateTenant(t *models.Tenant) error
	DeleteTenant(id string) error
	CountCAsForTenant(tenantID string) (int, error)

	// Usage accounting and quota consumption (Task 61). Daily counters live in
	// tenant_usage keyed by (tenant, UTC day); ConsumeTenantDailyQuota is an
	// atomic take-if-below-ceiling so per-tenant quotas hold under concurrent
	// issuance on both SQLite and PostgreSQL, and ReleaseTenantDailyQuota is the
	// compensating credit when an operation fails after its reservation.
	AddTenantUsage(tenantID, day, counter string, delta int64) error
	ConsumeTenantDailyQuota(tenantID, day, counter string, limit int64) (bool, error)
	ReleaseTenantDailyQuota(tenantID, day, counter string) error
	GetTenantUsageDay(tenantID, day string) (models.TenantUsageDay, error)
	ListTenantUsageDays(tenantID, sinceDay string) ([]models.TenantUsageDay, error)
	CountActiveCertificatesForTenant(tenantID string, now time.Time) (int64, error)
	TenantCertificateTotals(tenantID string) (total, revoked int64, err error)
}

// Lifecycle covers connection management and health/identity introspection.
type Lifecycle interface {
	Close() error
	Ping(ctx context.Context) error
	Driver() string
}

// CAStore persists certificate-authority definitions and the monotonic serial
// allocator that guarantees unique, non-repeating certificate serial numbers.
type CAStore interface {
	CreateCA(ca *models.CA) error
	GetCA(id string) (*models.CA, error)
	GetCAByLabel(label string) (*models.CA, error)
	ListCAs() ([]models.CA, error)
	// ListCAsForTenant returns only the CAs owned by the given tenant.
	ListCAsForTenant(tenantID string) ([]models.CA, error)
	// GetCATenant resolves the owning tenant of a CA (""/nil if it does not
	// exist). It is the authorization lookup for CA-scoped requests.
	GetCATenant(caID string) (string, error)
	GetChildren(parentID string) ([]models.CA, error)
	DeleteCA(id string) error
	SetCAStatus(id, status string) error
	SetCADefaultRestrictionSet(caID string, rsType string, rsID *string) error
	MarkCARotated(oldID, newID string, retireAfter *time.Time) error
	// AllocateSerial atomically returns the next unused serial for a CA; the
	// increment is transactional so concurrent issuance never reuses a serial.
	AllocateSerial(caID string) (int64, error)
}

// CrossSignStore persists cross-signing relationships: certificates an issuer CA
// has signed for a subject public key that is (or may be) certified by another
// issuer as well. These records drive alternate-chain selection for bridge-CA and
// root-transition topologies. Every record is tenant-scoped through its issuer CA.
type CrossSignStore interface {
	CreateCrossSign(cs *models.CrossSign) error
	GetCrossSign(id string) (*models.CrossSign, error)
	// ListCrossSignsForSubjectKey returns every cross-sign certifying the given
	// Subject Key Identifier (hex), the join used to build alternate chains.
	ListCrossSignsForSubjectKey(subjectKeyID string) ([]models.CrossSign, error)
	// ListCrossSignsBySubjectCA returns cross-signs whose subject is the given
	// local CA.
	ListCrossSignsBySubjectCA(subjectCAID string) ([]models.CrossSign, error)
	// ListCrossSignsByIssuer returns cross-signs an issuer CA has produced.
	ListCrossSignsByIssuer(issuerCAID string) ([]models.CrossSign, error)
	SetCrossSignStatus(id, status string) error
}

// InventoryStore persists the authoritative record of every issued leaf
// certificate, used for renewal, expiry monitoring, and reporting.
type InventoryStore interface {
	RecordIssuedCertificate(c *models.IssuedCertificate) error
	GetIssuedCertificate(caID, serial string) (*models.IssuedCertificate, error)
	ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error)
	// PageIssuedCertificates is the paginated, filtered read behind the list
	// endpoints (Task 83). It returns one bounded, keyset-ordered page plus a
	// continuation cursor and the total matching count; the unbounded
	// ListIssuedCertificates remains for internal full-scan consumers (reporting,
	// monitoring, rotation).
	PageIssuedCertificates(caID string, f CertFilter, p CertPageRequest) (IssuedCertPage, error)
	MarkExpiredCertificates(caID string, now time.Time) (int64, error)
	// DistinctSubjectsForKeyFingerprint returns the distinct subject DNs certified
	// under a subject public-key fingerprint (excluding one serial), backing the
	// pre-issuance gate's duplicate/reused-subject-key detection (Task 120).
	DistinctSubjectsForKeyFingerprint(fingerprint, excludeSerial string) ([]string, error)
}

// DiscoveryStore persists certificates observed on external TLS endpoints by the
// discovery scanner (Task 54). These are not the authority's own issued
// certificates; they are the shadow/rogue, expiring, weak, or otherwise notable
// certificates found in the field, recorded so operators can inventory and alert
// on them. Records are upserted on (endpoint, fingerprint) so re-scanning updates
// in place rather than accumulating duplicates.
type DiscoveryStore interface {
	RecordDiscoveredCertificate(d *models.DiscoveredCertificate) error
	ListDiscoveredCertificates(tenantID string) ([]models.DiscoveredCertificate, error)
	// PageDiscoveredCertificates is the paginated, filtered read behind the
	// discovery list endpoint (Task 83).
	PageDiscoveredCertificates(tenantID string, f CertFilter, p CertPageRequest) (DiscoveredCertPage, error)
	DeleteDiscoveredCertificate(id string) error
}

// RevocationStore persists revoked-certificate records and the per-CA monotonic
// CRL number that establishes CRL ordering and freshness.
type RevocationStore interface {
	RevokeCertificate(caID, serial string, reason int, when time.Time) (bool, error)
	GetRevokedCertificate(caID, serial string) (*models.RevokedCertificate, error)
	ListRevokedCertificates(caID string) ([]models.RevokedCertificate, error)
	// PageRevokedCertificates is the paginated, filtered read behind the revoked
	// list endpoint (Task 83). ListRevokedCertificates remains the full-scan input
	// to CRL generation.
	PageRevokedCertificates(caID string, f CertFilter, p CertPageRequest) (RevokedCertPage, error)
	// Reversible certificate hold (Task 82, RFC 5280 certificateHold /
	// removeFromCRL). SuspendCertificate places a serial on hold; ReleaseHold
	// removes the hold only when the current reason is certificateHold (rejecting
	// permanent revocations with ErrNotOnHold / ErrNotRevoked); ListReleasedHolds
	// feeds the removeFromCRL entries of delta CRL generation.
	SuspendCertificate(caID, serial string, when time.Time) (bool, error)
	ReleaseHold(caID, serial string, when time.Time) error
	ListReleasedHolds(caID string) ([]models.ReleasedHold, error)
	// Bulk revocation (Task 70). ListRevocationCandidates projects the
	// not-yet-revoked inventory matching a selector for the mass-revocation
	// engine; BulkRevokeCertificates applies one batch transactionally and
	// reports only the serials newly revoked (already-revoked ones are left
	// untouched, keeping resumed operations idempotent).
	ListRevocationCandidates(sel RevocationSelector) ([]RevocationCandidate, error)
	BulkRevokeCertificates(caID string, serials []string, reason int, when time.Time) ([]string, error)
	// NextCRLNumber returns the next full-scope CRL number, incremented atomically.
	NextCRLNumber(caID string) (int64, error)
	// NextScopedCRLNumber returns the next CRL number for a partition/delta scope,
	// incremented atomically and independently of other scopes.
	NextScopedCRLNumber(caID, scope string) (int64, error)
}

// CRLStore persists published CRLs (base and delta, full and per-partition) so a
// restarted or newly scheduled replica can serve the latest CRL immediately.
type CRLStore interface {
	GetPublishedCRL(caID, scope, kind string) (*PublishedCRL, error)
	UpsertPublishedCRL(c *PublishedCRL) error
}

// SSHStore persists the SSH certificate authority's state (Task 57): the record
// of every OpenSSH certificate signed and the revocations published to relying
// hosts as a KRL. SSH serials draw from the same per-CA AllocateSerial counter
// as X.509 issuance, so no separate allocator is needed here.
type SSHStore interface {
	RecordSSHCertificate(c *models.SSHCertificate) error
	GetSSHCertificate(caID, serial string) (*models.SSHCertificate, error)
	ListSSHCertificates(caID string) ([]models.SSHCertificate, error)
	// RevokeSSHCertificate records a revocation by serial or key ID and reports
	// whether it is newly effective (false when the target was already revoked).
	RevokeSSHCertificate(rev *models.SSHRevocation) (bool, error)
	GetSSHRevocationBySerial(caID, serial string) (*models.SSHRevocation, error)
	// IsSSHCertificateRevoked reports whether a certificate is revoked, by
	// serial or through a key-ID revocation.
	IsSSHCertificateRevoked(caID, serial, keyID string) (bool, error)
	ListSSHRevocations(caID string) ([]models.SSHRevocation, error)
	// CountSSHRevocations doubles as the monotonic KRL version: revocations are
	// only ever added.
	CountSSHRevocations(caID string) (int64, error)
}

// ACMEStore persists ACME account, order, authorization, and challenge state so
// that any replica can advance a client's in-flight order.
type ACMEStore interface {
	CreateACMEAccount(a *models.ACMEAccount) error
	GetACMEAccount(id string) (*models.ACMEAccount, error)
	GetACMEAccountByThumbprint(thumbprint string) (*models.ACMEAccount, error)
	ListACMEAccounts(limit, offset int) ([]models.ACMEAccount, error)
	UpdateACMEAccount(a *models.ACMEAccount) error
	UpdateACMEAccountKey(id, jwk, thumbprint string) error

	CreateACMEOrder(o *models.ACMEOrder) error
	GetACMEOrder(id string) (*models.ACMEOrder, error)
	GetACMEOrderByCertificate(caID, serial string) (*models.ACMEOrder, error)
	CountACMEOrdersReplacing(certID string) (int, error)
	ListACMEOrdersByAccount(accountID string) ([]models.ACMEOrder, error)
	ListACMEOrders(limit, offset int) ([]models.ACMEOrder, error)
	UpdateACMEOrderStatus(id, status, errDoc string) error
	FinalizeACMEOrder(id, caID, serial, chainPEM string, finalizedAt time.Time) error

	CreateACMEAuthorization(a *models.ACMEAuthorization) error
	GetACMEAuthorization(id string) (*models.ACMEAuthorization, error)
	ListACMEAuthorizationsByOrder(orderID string) ([]models.ACMEAuthorization, error)
	UpdateACMEAuthorizationStatus(id, status string) error

	CreateACMEChallenge(c *models.ACMEChallenge) error
	GetACMEChallenge(id string) (*models.ACMEChallenge, error)
	ListACMEChallengesByAuthz(authzID string) ([]models.ACMEChallenge, error)
	UpdateACMEChallenge(id, status string, validated *time.Time, errDoc string) error
}

// AuditStore persists the tamper-evident, hash-chained event log and the SIEM
// export cursor. AppendEvent must preserve gap-free sequencing and correct
// chaining even under concurrent writers; the implementation guarantees this.
type AuditStore interface {
	AppendEvent(e *audit.Event) error
	ListEvents(action, actor, tenant string, limit, offset int) ([]audit.Event, int, error)
	ListAllEventsAsc() ([]audit.Event, error)
	ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error)
	ListEventsByTimeRange(from, to time.Time) ([]audit.Event, error)
	MaxEventSeq() (int64, error)
	VerifyEventChain() (audit.VerifyResult, error)
	GetSIEMCursor(sink string) (int64, error)
	SetSIEMCursor(sink string, seq int64) error

	// Audit-chain anchors (Task 64): periodic RFC 3161 attestations of the
	// event-log head that make whole-chain truncation/rewrite detectable.
	// EventLogHead reports the newest entry (seq, hash, action) so the anchor
	// job knows what to attest.
	EventLogHead() (seq int64, hash, action string, err error)
	InsertAuditAnchor(a *audit.Anchor) error
	ListAuditAnchorsAsc() ([]audit.Anchor, error)
	LatestAuditAnchor() (*audit.Anchor, error)
}

// RBACStore persists authorization state: groups, memberships, per-CA
// permissions, and the restriction sets that constrain what a subject may issue.
type RBACStore interface {
	CreateGroup(g *models.Group) error
	GetGroup(id string) (*models.Group, error)
	ListGroups() ([]models.Group, error)
	ListGroupsForTenant(tenantID string) ([]models.Group, error)
	DeleteGroup(id string) error
	AddGroupMember(groupID, userSub string) error
	RemoveGroupMember(groupID, userSub string) error
	GetGroupMembers(groupID string) ([]string, error)
	GetUserGroups(userSub string) ([]string, error)

	GrantPermission(p *models.PermissionEntry) error
	RevokePermission(caID, entityType, entityID string, perm models.Permission) error
	GetPermissions(caID string) ([]models.PermissionEntry, error)
	HasPermission(caID, userSub string, perm models.Permission, groupIDs []string) (bool, error)

	CreateRestrictionSet(rs *models.RestrictionSet) error
	UpdateRestrictionSet(rs *models.RestrictionSet) error
	GetRestrictionSet(id string) (*models.RestrictionSet, error)
	ListAllRestrictionSets() ([]models.RestrictionSet, error)
	ListRestrictionSets(caID string) ([]models.RestrictionSet, error)
	ListRestrictionSetsForTenant(tenantID string) ([]models.RestrictionSet, error)
	DeleteRestrictionSet(id string) error
	GetEffectiveRestrictionSet(caID, userSub string, groupIDs []string, certFormat string) (*models.RestrictionSet, error)
}

// Compile-time guarantee that the concrete engine satisfies the abstraction for
// both the SQLite (default/file) and PostgreSQL (HA) drivers.
var _ Store = (*DB)(nil)
