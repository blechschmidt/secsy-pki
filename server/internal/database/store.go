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
	InventoryStore
	RevocationStore
	CRLStore
	ACMEStore
	AuditStore
	RBACStore
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
	DeleteTenant(id string) error
	CountCAsForTenant(tenantID string) (int, error)
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

// InventoryStore persists the authoritative record of every issued leaf
// certificate, used for renewal, expiry monitoring, and reporting.
type InventoryStore interface {
	RecordIssuedCertificate(c *models.IssuedCertificate) error
	GetIssuedCertificate(caID, serial string) (*models.IssuedCertificate, error)
	ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error)
	MarkExpiredCertificates(caID string, now time.Time) (int64, error)
}

// RevocationStore persists revoked-certificate records and the per-CA monotonic
// CRL number that establishes CRL ordering and freshness.
type RevocationStore interface {
	RevokeCertificate(caID, serial string, reason int, when time.Time) (bool, error)
	GetRevokedCertificate(caID, serial string) (*models.RevokedCertificate, error)
	ListRevokedCertificates(caID string) ([]models.RevokedCertificate, error)
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
