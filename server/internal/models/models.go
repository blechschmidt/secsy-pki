// Package models defines the shared data types persisted and exchanged across secsy-pki.
package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
)

// DefaultTenantID is the reserved identifier of the built-in tenant. Every
// deployment always has this tenant; single-organization installs use it
// implicitly and all pre-multi-tenancy resources are backfilled to it, so the
// tenant concept is fully backward compatible. Its slug is also "default".
const DefaultTenantID = "default"

// Tenant lifecycle states.
const (
	// TenantStatusActive is the default state: the tenant may own CAs, issue
	// certificates, and authenticate its members.
	TenantStatusActive = "active"
	// TenantStatusSuspended means the tenant still exists (its CAs and audit
	// history are preserved) but issuance and mutating operations are refused.
	TenantStatusSuspended = "suspended"
)

// Tenant is a first-class isolation boundary: a single deployment can serve
// several independent organizations, each owning its own CAs, issuance
// profiles/restriction sets, revocation state, secret envelopes, RBAC role
// assignments, and audit trail. Every tenant-scoped resource carries the owning
// tenant's ID, and authorization forbids a principal from reaching resources of
// a tenant it is not a member of (platform admins excepted).
type Tenant struct {
	ID     string `json:"id" db:"id"`
	Slug   string `json:"slug" db:"slug"`     // stable URL/CLI-friendly identifier (unique)
	Name   string `json:"name" db:"name"`     // human-readable display name
	Status string `json:"status" db:"status"` // active | suspended
	// KEKLabel optionally names the HSM key-encryption key used to seal this
	// tenant's secret envelopes. When empty the deployment-wide default KEK is
	// used. Scoping the KEK per tenant keeps one tenant's secrets cryptographically
	// separable from another's.
	KEKLabel  string    `json:"kek_label,omitempty" db:"kek_label"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// Quotas caps this tenant's consumption (Task 61). The zero value means
	// "unlimited" for every dimension, preserving pre-quota behavior.
	Quotas TenantQuotas `json:"quotas"`
}

// TenantQuotas bounds a tenant's resource consumption. Every field treats zero
// (or negative) as unlimited so existing tenants are unaffected until an
// operator explicitly sets a ceiling. Enforcement is fail-closed: when quota
// state cannot be read the operation is refused, never silently admitted.
type TenantQuotas struct {
	// MaxCertsPerDay caps how many certificates (X.509 leaves and SSH
	// certificates) the tenant may have issued per UTC day, across all its CAs
	// and every enrollment protocol (REST, ACME, SCEP, EST, CMP, gRPC).
	MaxCertsPerDay int64 `json:"max_certs_per_day,omitempty" db:"max_certs_per_day"`
	// MaxActiveCerts caps the tenant's inventory of unexpired, unrevoked X.509
	// certificates. New issuance is refused while the ceiling is reached;
	// revocation or expiry frees room.
	MaxActiveCerts int64 `json:"max_active_certs,omitempty" db:"max_active_certs"`
	// MaxSecretOpsPerDay caps envelope encrypt/decrypt operations per UTC day.
	MaxSecretOpsPerDay int64 `json:"max_secret_ops_per_day,omitempty" db:"max_secret_ops_per_day"`
	// RateLimitPerSecond / RateLimitBurst override the deployment-wide
	// per-tenant request rate tier for this tenant's public enrollment
	// endpoints. Zero inherits the rate_limit.per_tenant configuration.
	RateLimitPerSecond float64 `json:"rate_limit_per_second,omitempty" db:"rate_limit_per_second"`
	RateLimitBurst     float64 `json:"rate_limit_burst,omitempty" db:"rate_limit_burst"`
}

// Quota kinds, used as the QuotaExceededError discriminator, the audit-event
// detail, and the "quota" metric label. Bounded set — safe as a label.
const (
	QuotaCertsPerDay     = "certs_per_day"
	QuotaActiveCerts     = "active_certs"
	QuotaSecretOpsPerDay = "secret_ops_per_day"
)

// TenantSuspendedError reports that an operation was refused because the
// owning tenant is suspended. Protocol layers map it to HTTP 403 (or the
// protocol's equivalent) while leaving OCSP/CRL service for already-issued
// certificates untouched.
type TenantSuspendedError struct {
	TenantID string
}

func (e *TenantSuspendedError) Error() string {
	return fmt.Sprintf("tenant %q is suspended; new issuance and secret operations are disabled", e.TenantID)
}

// QuotaExceededError reports that a per-tenant quota is exhausted. Protocol
// layers map it to HTTP 429 with a Retry-After of RetryAfter (the time until
// the daily window resets; zero for inventory ceilings, where retrying only
// helps after certificates are revoked or expire).
type QuotaExceededError struct {
	TenantID string
	// Quota is one of the Quota* kind constants.
	Quota string
	// Limit is the configured ceiling that was hit.
	Limit int64
	// RetryAfter suggests when capacity may be available again (daily windows
	// reset at UTC midnight). Zero means "not time-based".
	RetryAfter time.Duration
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("tenant %q quota %s exceeded (limit %d)", e.TenantID, e.Quota, e.Limit)
}

// TenantUsageDay is one UTC day's accounted consumption for a tenant.
type TenantUsageDay struct {
	Day          string `json:"day" db:"day"` // UTC date, YYYY-MM-DD
	CertsIssued  int64  `json:"certs_issued" db:"certs_issued"`
	CertsRevoked int64  `json:"certs_revoked" db:"certs_revoked"`
	SecretOps    int64  `json:"secret_ops" db:"secret_ops"`
}

// TenantUsageReport is the operator-facing usage summary served by
// GET /api/tenants/{id}/usage: point-in-time inventory counts plus a rolling
// window of daily accounting rows.
type TenantUsageReport struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug"`
	Status   string `json:"status"`
	// ActiveCerts / TotalIssued / TotalRevoked are inventory counts across all
	// the tenant's CAs (X.509; SSH certificates are accounted in the daily
	// counters but carry their own inventory).
	ActiveCerts  int64 `json:"active_certs"`
	TotalIssued  int64 `json:"total_issued"`
	TotalRevoked int64 `json:"total_revoked"`
	CAs          int   `json:"cas"`
	// Today is the current UTC day's accounting (the window the daily quotas
	// meter), also present in Days.
	Today TenantUsageDay `json:"today"`
	// Days is the rolling usage window, most recent day first.
	Days        []TenantUsageDay `json:"days"`
	Quotas      TenantQuotas     `json:"quotas"`
	GeneratedAt time.Time        `json:"generated_at"`
}

type Permission string

const (
	PermSignCertificate   Permission = "SIGN_CERTIFICATE"
	PermManagePermissions Permission = "MANAGE_PERMISSIONS"
	PermConfigureCA       Permission = "CONFIGURE_CA"
)

var AllPermissions = []Permission{
	PermSignCertificate,
	PermManagePermissions,
	PermConfigureCA,
}

type CA struct {
	ID string `json:"id" db:"id"`
	// TenantID is the owning tenant. It is assigned at creation and never changes;
	// a subordinate CA always inherits its parent's tenant. All certificates,
	// revocation/CRL state, and serial allocation under a CA are scoped by it, so
	// this single field transitively tenant-scopes the entire issuance subtree.
	TenantID                    string    `json:"tenant_id" db:"tenant_id"`
	ParentID                    *string   `json:"parent_id,omitempty" db:"parent_id"`
	Label                       string    `json:"label" db:"label"`
	PKCS11URI                   string    `json:"pkcs11_uri" db:"pkcs11_uri"`
	KeyType                     string    `json:"key_type" db:"key_type"`
	PublicKey                   string    `json:"public_key" db:"public_key"`
	DefaultSSHRestrictionSetID  *string   `json:"default_ssh_restriction_set_id,omitempty" db:"default_ssh_restriction_set_id"`
	DefaultX509RestrictionSetID *string   `json:"default_x509_restriction_set_id,omitempty" db:"default_x509_restriction_set_id"`
	CreatedAt                   time.Time `json:"created_at" db:"created_at"`

	// X.509 CA-certificate metadata. These are populated when a CA is created as
	// an X.509 root or intermediate authority (see the ca package). They are
	// empty for CAs that exist only as SSH signing keys.
	Certificate string     `json:"certificate,omitempty" db:"certificate"` // PEM-encoded X.509 CA certificate
	Subject     string     `json:"subject,omitempty" db:"subject"`         // certificate subject DN
	Serial      string     `json:"serial,omitempty" db:"serial"`           // the CA certificate's own serial number (decimal)
	NotBefore   *time.Time `json:"not_before,omitempty" db:"not_before"`
	NotAfter    *time.Time `json:"not_after,omitempty" db:"not_after"`
	MaxPathLen  *int       `json:"max_path_len,omitempty" db:"max_path_len"` // nil = unconstrained

	// Externally-signed subordinate CA state (Task 69). CSR is the PKCS#10
	// request emitted for the CA's HSM-backed key, kept so an operator can
	// re-download it while the CA is pending external signature (and as
	// provenance afterwards). ExternalChain is the PEM bundle of the external
	// issuing chain — the offline/third-party parent(s) up to and including the
	// external root — imported alongside the signed certificate so chain serving
	// can include the external parent. Both are empty for locally signed CAs.
	CSR           string `json:"csr,omitempty" db:"csr"`
	ExternalChain string `json:"external_chain,omitempty" db:"external_chain"`

	// Key-rotation / rollover state. These track an intermediate CA's position in
	// a signing-key rollover (see the ca package's rotation support). A freshly
	// created CA is CAStatusActive with no predecessor or successor.
	Status        string     `json:"status,omitempty" db:"status"`                 // active | superseded | retired
	SuccessorID   *string    `json:"successor_id,omitempty" db:"successor_id"`     // CA that replaced this one (set on the old CA when rotated out)
	PredecessorID *string    `json:"predecessor_id,omitempty" db:"predecessor_id"` // CA this one replaced (set on the new CA)
	RetireAfter   *time.Time `json:"retire_after,omitempty" db:"retire_after"`     // earliest time the superseded key can be safely retired (max NotAfter of outstanding leaves at rotation time)
}

// CA rollover lifecycle states.
const (
	// CAStatusActive is the default state: the CA is the current signing key for
	// its subject and new certificates are issued under it.
	CAStatusActive = "active"
	// CAStatusSuperseded means a newer key has been rotated in for the same
	// subject. The superseded CA still validates its previously issued
	// certificates during the overlap window but no longer issues new leaves.
	CAStatusSuperseded = "superseded"
	// CAStatusRetired means the superseded key has been decommissioned: its
	// certificate has been revoked under the parent and it neither issues nor is
	// expected to validate new chains.
	CAStatusRetired = "retired"
	// CAStatusPending means the CA's HSM-backed key exists and a PKCS#10 CSR has
	// been emitted, but the externally signed certificate has not been imported
	// yet (see the ca package's external-CA support). A pending CA cannot issue
	// anything until "ca import-cert" installs its certificate.
	CAStatusPending = "pending"
)

// CASubject describes the distinguished-name fields for a CA certificate in API
// and CLI requests.
type CASubject struct {
	CommonName         string `json:"cn"`
	Organization       string `json:"o,omitempty"`
	OrganizationalUnit string `json:"ou,omitempty"`
	Country            string `json:"c,omitempty"`
	Province           string `json:"st,omitempty"`
	Locality           string `json:"l,omitempty"`
}

// CAInitRootRequest initializes a self-signed root CA. The private key is
// generated inside the configured key provider (HSM) and never leaves it.
type CAInitRootRequest struct {
	// TenantID assigns the root (and its entire subtree) to a tenant. Empty
	// defaults to the built-in default tenant.
	TenantID     string    `json:"tenant_id,omitempty"`
	Label        string    `json:"label"`
	KeyType      string    `json:"key_type"`
	Subject      CASubject `json:"subject"`
	ValidityDays int       `json:"validity_days"`
	MaxPathLen   *int      `json:"max_path_len,omitempty"` // nil = unconstrained
	// NameConstraints, when set, emits an RFC 5280 Name Constraints extension
	// (2.5.29.30) on the root. Roots are usually left unconstrained; scoping is
	// normally applied to intermediates.
	NameConstraints *nameconstraints.Config `json:"name_constraints,omitempty"`
	// Policies, when set, emits the certificate-policy family of extensions on the
	// root certificate.
	Policies *certpolicy.PolicyConfig `json:"policies,omitempty"`
}

// CAIssueIntermediateRequest issues an intermediate CA certificate signed by an
// existing parent CA. The intermediate's key is generated inside the provider.
type CAIssueIntermediateRequest struct {
	ParentID     string    `json:"parent_id"`
	Label        string    `json:"label"`
	KeyType      string    `json:"key_type"`
	Subject      CASubject `json:"subject"`
	ValidityDays int       `json:"validity_days"`
	MaxPathLen   *int      `json:"max_path_len,omitempty"` // nil = unconstrained
	// NameConstraints scopes the identities certificates below this intermediate
	// may assert (permitted/excluded DNS, IP, email, URI, and dirName subtrees).
	NameConstraints *nameconstraints.Config `json:"name_constraints,omitempty"`
	// Policies emits certificatePolicies / policyMappings / policyConstraints on
	// the intermediate certificate.
	Policies *certpolicy.PolicyConfig `json:"policies,omitempty"`
}

// CAExternalCSRRequest generates an HSM-backed subordinate-CA key and emits a
// PKCS#10 CSR carrying CA basicConstraints/keyUsage attributes, for signature by
// an external parent (offline corporate root or third-party bridge). The CA is
// created in the "pending" state until the signed certificate is imported.
type CAExternalCSRRequest struct {
	// TenantID assigns the CA to a tenant. Empty defaults to the built-in
	// default tenant.
	TenantID string    `json:"tenant_id,omitempty"`
	Label    string    `json:"label"`
	KeyType  string    `json:"key_type"`
	Subject  CASubject `json:"subject"`
	// MaxPathLen is the path-length constraint requested in the CSR's
	// basicConstraints attribute (nil = unconstrained). The external parent may
	// override it; the issued certificate's value is authoritative after import.
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

// CAExternalCSRResponse returns the pending CA record and its PKCS#10 CSR.
type CAExternalCSRResponse struct {
	CA     *CA    `json:"ca"`
	CSRPEM string `json:"csr_pem"`
}

// CAImportCertRequest installs the externally signed certificate for a pending
// CA ({id} in the request path). The certificate's public key must match the
// CA's HSM-backed key. ChainPEM optionally imports the external issuing chain
// (intermediates and root) so /api/ca/{id}/chain can serve the full path to the
// external trust anchor; when the certificate PEM itself is a bundle, the
// certificates after the first are treated as chain too.
type CAImportCertRequest struct {
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	// Replace permits re-importing onto an already-active externally-signed CA
	// (renewed certificate for the same key, or adding the chain later).
	Replace bool `json:"replace,omitempty"`
}

// CAImportCertResponse returns the now-active CA, any non-fatal validation
// warnings, and the combined chain as served to relying parties.
type CAImportCertResponse struct {
	CA       *CA      `json:"ca"`
	Warnings []string `json:"warnings,omitempty"`
	ChainPEM string   `json:"chain_pem"`
}

// CertStatus is the lifecycle status of an issued end-entity certificate.
type CertStatus string

const (
	CertStatusValid   CertStatus = "valid"
	CertStatusRevoked CertStatus = "revoked"
	CertStatusExpired CertStatus = "expired"
	// CertStatusHeld marks a certificate that has been suspended (placed on hold
	// with RFC 5280 reason certificateHold). Unlike CertStatusRevoked the state
	// is reversible: releasing the hold returns the certificate to
	// CertStatusValid. A held certificate is treated as revoked by OCSP and the
	// base CRL for as long as the hold stands.
	CertStatusHeld CertStatus = "held"
)

// Cross-sign lifecycle states.
const (
	// CrossSignStatusActive means the cross-signed certificate is published and
	// its alternate chain may be served.
	CrossSignStatusActive = "active"
	// CrossSignStatusRevoked means the cross-signed certificate has been revoked
	// under its issuer; its alternate chain should no longer be served.
	CrossSignStatusRevoked = "revoked"
)

// Cross-sign subject sources.
const (
	// CrossSignSourceLocalCA cross-signs a CA that already exists in this
	// deployment, identified by its CA id/label.
	CrossSignSourceLocalCA = "local-ca"
	// CrossSignSourceCertificate cross-signs an externally supplied certificate
	// (its subject DN and public key are reproduced).
	CrossSignSourceCertificate = "certificate"
	// CrossSignSourceCSR cross-signs an externally supplied certificate signing
	// request.
	CrossSignSourceCSR = "csr"
)

// CrossSign records that an issuer CA (using its HSM-backed signing key) has
// signed a certificate for a subject public key that is (or may be) also
// certified by a different issuer. Cross-signing enables bridge-CA topologies
// and root-transition trust: the same subordinate key holds multiple issued
// certificates, so a relying party can be served whichever alternate chain it
// trusts. Cross-sign records are tenant-scoped through their issuer CA.
type CrossSign struct {
	ID string `json:"id" db:"id"`
	// TenantID is the owning tenant, inherited from the issuer CA. A cross-sign
	// never crosses the tenant isolation boundary.
	TenantID string `json:"tenant_id" db:"tenant_id"`
	// IssuerCAID is the local CA whose HSM-backed key signed the cross-certificate.
	IssuerCAID string `json:"issuer_ca_id" db:"issuer_ca_id"`
	// SubjectCAID is the local CA that was cross-signed, when the subject key
	// belongs to a CA in this deployment. It is nil for externally imported
	// subjects (a foreign certificate or CSR).
	SubjectCAID *string `json:"subject_ca_id,omitempty" db:"subject_ca_id"`
	// SubjectKeyID is the hex-encoded Subject Key Identifier of the cross-signed
	// public key. It groups every certificate — native and cross-signed — that
	// certifies the same subject key, and is the join key for alternate-chain
	// selection.
	SubjectKeyID string `json:"subject_key_id" db:"subject_key_id"`
	// Subject is the cross-signed certificate's subject DN (string form).
	Subject string `json:"subject" db:"subject"`
	// Serial is the cross-signed certificate's serial in the issuer's namespace
	// (decimal string).
	Serial string `json:"serial" db:"serial"`
	// Certificate is the PEM-encoded cross-signed certificate.
	Certificate string    `json:"certificate" db:"certificate"`
	NotBefore   time.Time `json:"not_before" db:"not_before"`
	NotAfter    time.Time `json:"not_after" db:"not_after"`
	// Source records how the subject was supplied (see CrossSignSource*).
	Source string `json:"source" db:"source"`
	// Status is the cross-sign lifecycle state (see CrossSignStatus*).
	Status      string    `json:"status" db:"status"`
	RequestedBy string    `json:"requested_by,omitempty" db:"requested_by"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// CACrossSignRequest asks an issuer CA to cross-sign a subject public key. Exactly
// one of SubjectCAID, CertificatePEM, or CSRPEM must be provided. The issuer CA is
// identified by the request path ({id}); its HSM-backed key performs the signing.
type CACrossSignRequest struct {
	// SubjectCAID cross-signs a CA that exists in this deployment (by id or label).
	SubjectCAID string `json:"subject_ca_id,omitempty"`
	// CertificatePEM cross-signs an externally supplied certificate (PEM).
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// CSRPEM cross-signs an externally supplied CSR (PEM).
	CSRPEM string `json:"csr_pem,omitempty"`
	// ValidityDays bounds the cross-signed certificate's lifetime. When omitted for
	// a certificate/local-CA subject the subject's own validity span is reused;
	// for a CSR subject it is required. The lifetime is always clamped to the
	// issuer's own expiry.
	ValidityDays int `json:"validity_days,omitempty"`
	// MaxPathLen overrides the cross-signed certificate's path-length constraint.
	// When omitted the subject certificate's constraint is preserved.
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

// CTStatus is the Certificate Transparency outcome recorded for an issued
// certificate.
type CTStatus string

const (
	// CTStatusNone means CT was not requested for the profile (or was requested
	// but no SCTs were embedded and the certificate was not issued fail-open).
	CTStatusNone CTStatus = "none"
	// CTStatusSubmitted means an SCT list was embedded in the certificate.
	CTStatusSubmitted CTStatus = "submitted"
	// CTStatusFailedOpen means the SCT policy was not met but the certificate was
	// issued anyway because the profile is configured fail-open.
	CTStatusFailedOpen CTStatus = "failed_open"
)

// CertMarkerCanary marks certificates minted by the synthetic issuance canary
// (Task 71). Marked certificates are operational self-test artifacts, not real
// credentials: the expiry monitor neither warns on nor auto-renews them, and
// inventory/compliance reports exclude them by default.
const CertMarkerCanary = "canary"

// CertMarkerServingTLS marks the self-managed serving-TLS certificate the server
// issues from an internal CA for its own HTTPS listener (Task 118). Like the
// canary marker it flags an operational artifact rather than a user-facing
// credential, so inventory/compliance reports exclude it; the doctor
// serving-cert freshness check locates the newest such record by this marker.
const CertMarkerServingTLS = "serving-tls"

// IssuedCertificate records an end-entity certificate minted by a CA. It is the
// authority's copy used for renewal, listing, and (via revocation) CRL/OCSP.
type IssuedCertificate struct {
	ID          string     `json:"id" db:"id"`
	CAID        string     `json:"ca_id" db:"ca_id"`
	Serial      string     `json:"serial" db:"serial"` // decimal string
	Subject     string     `json:"subject" db:"subject"`
	CommonName  string     `json:"common_name" db:"common_name"`
	SANs        []string   `json:"sans,omitempty" db:"-"`
	Profile     string     `json:"profile" db:"profile"`
	Certificate string     `json:"certificate" db:"certificate"` // PEM
	NotBefore   time.Time  `json:"not_before" db:"not_before"`
	NotAfter    time.Time  `json:"not_after" db:"not_after"`
	Status      CertStatus `json:"status" db:"status"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	// RevocationReason is an RFC 5280 CRL reason code, meaningful when revoked.
	RevocationReason int       `json:"revocation_reason,omitempty" db:"revocation_reason"`
	RequestedBy      string    `json:"requested_by,omitempty" db:"requested_by"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	// CTStatus records the Certificate Transparency outcome for this certificate.
	CTStatus CTStatus `json:"ct_status,omitempty" db:"ct_status"`
	// SCTCount is the number of embedded SCTs (0 unless CTStatus is submitted).
	SCTCount int `json:"sct_count,omitempty" db:"sct_count"`
	// CTLogs names the CT logs that returned an embedded SCT.
	CTLogs []string `json:"ct_logs,omitempty" db:"-"`
	// Marker tags synthetic certificates (e.g. CertMarkerCanary). Empty for
	// ordinary certificates.
	Marker string `json:"marker,omitempty" db:"marker"`
}

// SCT inclusion-proof verification states (Task 93). Recorded per embedded SCT
// by the CT inclusion monitor once a log's Maximum Merge Delay has elapsed.
const (
	// SCTInclusionPending means the SCT has been recorded but not yet confirmed
	// included: either the log's MMD has not elapsed, or a verification attempt
	// has not yet succeeded (a transient fetch error is still being retried).
	SCTInclusionPending = "pending"
	// SCTInclusionIncluded means the log served a valid Merkle audit path for the
	// SCT's precertificate entry, verified against a signature-checked Signed Tree
	// Head. Terminal success.
	SCTInclusionIncluded = "included"
	// SCTInclusionFailed means that after the log's MMD elapsed the log did not
	// honor the SCT — no inclusion proof, or a proof that did not chain to the
	// log's signed root. A genuine mis-issuance / log-misbehavior signal.
	SCTInclusionFailed = "failed"
	// SCTInclusionUnknownLog means the SCT names a log id not present in the
	// configured registry (or a log with no public key), so inclusion cannot be
	// cryptographically verified. A configuration gap, not misbehavior.
	SCTInclusionUnknownLog = "unknown_log"
)

// SCTInclusion records the Certificate Transparency inclusion-proof state of one
// SCT embedded in an issued certificate (Task 93): one row per (issuing CA,
// certificate serial, log id). Task 26 embeds SCTs at issuance — a log's signed
// promise to publicly log the certificate within its Maximum Merge Delay; this
// row is the audited answer to whether the log kept that promise. The inclusion
// monitor upserts it each time it checks (fetching the log's STH and the
// get-proof-by-hash Merkle audit path and verifying the path against the SCT's
// log id and timestamp). A Status of SCTInclusionFailed is the alert signal.
type SCTInclusion struct {
	CAID string `json:"ca_id" db:"ca_id"`
	// Serial is the issued certificate's serial (decimal string); (CAID, Serial)
	// join back to issued_certificates.
	Serial string `json:"serial" db:"serial"`
	// LogID is the hex-encoded SHA-256 of the log's SubjectPublicKeyInfo — the
	// same id the SCT carries.
	LogID string `json:"log_id" db:"log_id"`
	// LogName is the operator-facing log name resolved from the registry (empty
	// when the log id is unknown).
	LogName string `json:"log_name,omitempty" db:"log_name"`
	// SCTTimestamp is the SCT's asserted time; the MMD deadline is measured from it.
	SCTTimestamp time.Time `json:"sct_timestamp" db:"sct_timestamp"`
	// Status is one of the SCTInclusion* constants.
	Status string `json:"status" db:"status"`
	// TreeSize / LeafIndex describe the successful inclusion proof (0 until included).
	TreeSize  int64 `json:"tree_size,omitempty" db:"tree_size"`
	LeafIndex int64 `json:"leaf_index,omitempty" db:"leaf_index"`
	// Checks counts verification attempts made against this SCT.
	Checks int `json:"checks" db:"checks"`
	// LastError is the most recent verification error (empty on success).
	LastError string `json:"last_error,omitempty" db:"last_error"`
	// FirstCheckedAt / LastCheckedAt / IncludedAt track the verification timeline.
	FirstCheckedAt *time.Time `json:"first_checked_at,omitempty" db:"first_checked_at"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty" db:"last_checked_at"`
	IncludedAt     *time.Time `json:"included_at,omitempty" db:"included_at"`
	// Alerted records that a log-misbehavior alert has already been dispatched for
	// this SCT, so a persistent failure alerts once rather than every scan.
	Alerted bool `json:"alerted" db:"alerted"`
}

// DiscoveredCertificate is the persisted record of a certificate observed on an
// external TLS endpoint by the discovery scanner (Task 54). Unlike an
// IssuedCertificate — the authority's own copy of something it minted — a
// discovered certificate may have been issued by anyone; the scanner records its
// leaf details and the security flags it triggered so operators can spot expiring,
// weak, or rogue/shadow certificates that this PKI did not issue. Records are keyed
// on (endpoint, fingerprint) so re-scanning the same endpoint updates in place.
type DiscoveredCertificate struct {
	ID         string `json:"id" db:"id"`
	TenantID   string `json:"tenant_id" db:"tenant_id"`
	Endpoint   string `json:"endpoint" db:"endpoint"`       // host:port scanned
	ServerName string `json:"server_name" db:"server_name"` // SNI presented
	// Leaf certificate details.
	Subject            string    `json:"subject" db:"subject"`
	CommonName         string    `json:"common_name" db:"common_name"`
	SANs               []string  `json:"sans,omitempty" db:"-"`
	Issuer             string    `json:"issuer" db:"issuer"`
	Serial             string    `json:"serial" db:"serial"`
	NotBefore          time.Time `json:"not_before" db:"not_before"`
	NotAfter           time.Time `json:"not_after" db:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm" db:"key_algorithm"`
	KeySize            int       `json:"key_size" db:"key_size"`
	SignatureAlgorithm string    `json:"signature_algorithm" db:"signature_algorithm"`
	ChainLength        int       `json:"chain_length" db:"chain_length"`
	ChainComplete      bool      `json:"chain_complete" db:"chain_complete"`
	Fingerprint        string    `json:"fingerprint" db:"fingerprint"` // sha256 hex of leaf DER
	Certificate        string    `json:"certificate,omitempty" db:"certificate"`
	// Security flags raised during analysis.
	IssuedByPKI      bool      `json:"issued_by_pki" db:"issued_by_pki"`
	Rogue            bool      `json:"rogue" db:"rogue"` // served leaf NOT issued by this PKI
	SelfSigned       bool      `json:"self_signed" db:"self_signed"`
	WeakKey          bool      `json:"weak_key" db:"weak_key"`
	SHA1Signature    bool      `json:"sha1_signature" db:"sha1_signature"`
	HostnameMismatch bool      `json:"hostname_mismatch" db:"hostname_mismatch"`
	ExpiringSoon     bool      `json:"expiring_soon" db:"expiring_soon"`
	Severity         string    `json:"severity" db:"severity"` // ok | warning | critical
	Flags            []string  `json:"flags,omitempty" db:"-"` // human-readable flag list
	DiscoveredAt     time.Time `json:"discovered_at" db:"discovered_at"`
}

// RevokedCertificate is a single entry in a CA's revocation store. It is kept
// even for serials not present in issued_certificates so that externally issued
// certificates can still be revoked and published.
type RevokedCertificate struct {
	CAID      string    `json:"ca_id" db:"ca_id"`
	Serial    string    `json:"serial" db:"serial"` // decimal string
	RevokedAt time.Time `json:"revoked_at" db:"revoked_at"`
	Reason    int       `json:"reason" db:"reason"`
}

// ReleasedHold records a certificate that was on hold (RFC 5280 certificateHold)
// and has since been released. The row is retained after the hold is removed so
// delta CRL generation can emit the removeFromCRL (reason 8) entry that tells
// relying parties holding an older base CRL — one that still lists the hold — to
// drop the serial (RFC 5280 §5.2.4). It is not part of the current revocation
// set: OCSP reports the serial "good" and the base CRL omits it.
type ReleasedHold struct {
	CAID       string    `json:"ca_id" db:"ca_id"`
	Serial     string    `json:"serial" db:"serial"` // decimal string
	Reason     int       `json:"reason" db:"reason"` // the hold reason (certificateHold)
	HeldAt     time.Time `json:"held_at" db:"held_at"`
	ReleasedAt time.Time `json:"released_at" db:"released_at"`
}

// SSHCertificate is the authoritative record of an OpenSSH certificate signed by
// an HSM-backed SSH CA (Task 57). Serials are allocated from the CA's monotonic
// serial counter, so (ca_id, serial) uniquely identifies a certificate and is
// the revocation key a KRL serial entry refers to.
type SSHCertificate struct {
	CAID string `json:"ca_id" db:"ca_id"`
	// TenantID mirrors the issuing CA's tenant so inventory queries can be
	// tenant-scoped without a join.
	TenantID string `json:"tenant_id" db:"tenant_id"`
	Serial   string `json:"serial" db:"serial"`       // decimal uint64
	CertType string `json:"cert_type" db:"cert_type"` // "user" or "host"
	KeyID    string `json:"key_id" db:"key_id"`
	// Principals are the user names (user certs) or host names (host certs) the
	// certificate is valid for.
	Principals []string `json:"principals,omitempty" db:"-"`
	Profile    string   `json:"profile" db:"profile"`
	// PublicKeyFingerprint is the SHA256:… fingerprint of the certified subject
	// key, for correlating a certificate with the key it certifies.
	PublicKeyFingerprint string `json:"public_key_fingerprint" db:"public_key_fingerprint"`
	// Certificate is the single-line authorized_keys encoding of the signed
	// certificate (e.g. "ssh-ed25519-cert-v01@openssh.com AAAA…").
	Certificate string     `json:"certificate" db:"certificate"`
	ValidAfter  time.Time  `json:"valid_after" db:"valid_after"`
	ValidBefore time.Time  `json:"valid_before" db:"valid_before"`
	Status      CertStatus `json:"status" db:"status"`
	IssuedBy    string     `json:"issued_by,omitempty" db:"issued_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// SSHRevocation is one entry in an SSH CA's revocation store, published to
// relying hosts as an OpenSSH KRL. A revocation targets either a certificate
// serial (the common case) or a certificate key ID (revoking every certificate
// issued for an identity); exactly one of Serial and KeyID is set.
type SSHRevocation struct {
	CAID      string    `json:"ca_id" db:"ca_id"`
	Serial    string    `json:"serial,omitempty" db:"serial"` // decimal uint64; "" for key-ID revocations
	KeyID     string    `json:"key_id,omitempty" db:"key_id"` // "" for serial revocations
	Reason    string    `json:"reason,omitempty" db:"reason"`
	RevokedBy string    `json:"revoked_by,omitempty" db:"revoked_by"`
	RevokedAt time.Time `json:"revoked_at" db:"revoked_at"`
}

// IssueCertRequest asks a CA to sign a CSR into an end-entity certificate under
// a named profile. SANs and subject fields are taken from the CSR; the profile
// governs key usage, extended key usage, and validity bounds.
type IssueCertRequest struct {
	CSR          string `json:"csr"`     // PEM-encoded PKCS#10 CSR
	Profile      string `json:"profile"` // profile name; empty = default
	ValidityDays int    `json:"validity_days,omitempty"`
	// MustStaple optionally overrides the profile's RFC 7633 OCSP Must-Staple
	// default for this certificate (true stamps id-pe-tlsfeature: status_request;
	// false suppresses it). Honored only when the profile sets
	// allow_must_staple_override; omitted (null) uses the profile default.
	MustStaple *bool `json:"must_staple,omitempty"`
}

// PreviewCertRequest asks a CA to validate a would-be issuance through the full
// pre-issuance gate stack WITHOUT signing, persisting, or consuming a serial
// (Task 113): POST /api/ca/{id}/certificates:preview. Supply either a CSR (its
// subject/public key/SANs are previewed exactly as issuance would take them) or
// the explicit identity fields (common_name + SANs), in which case a throwaway
// subject key is synthesized only to resolve the extension layout.
type PreviewCertRequest struct {
	CSR          string `json:"csr,omitempty"`     // PEM PKCS#10 CSR (optional)
	Profile      string `json:"profile,omitempty"` // profile name; empty = default
	ValidityDays int    `json:"validity_days,omitempty"`
	// MustStaple optionally overrides the profile's RFC 7633 default, honored only
	// where the profile permits per-request overrides.
	MustStaple *bool `json:"must_staple,omitempty"`
	// The explicit-identity fields are used only when CSR is empty.
	CommonName     string   `json:"common_name,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

// IssueCertResponse returns a freshly issued end-entity certificate.
type IssueCertResponse struct {
	Certificate string `json:"certificate"` // PEM leaf certificate
	Chain       string `json:"chain,omitempty"`
	Serial      string `json:"serial"`
	Profile     string `json:"profile"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	// CT reports Certificate Transparency handling for this issuance. Present only
	// when the profile requested CT.
	CT *CTResponse `json:"ct,omitempty"`
}

// CTResponse conveys the Certificate Transparency outcome of an issuance to API
// clients and the admin console.
type CTResponse struct {
	Enabled  bool           `json:"enabled"`
	Embedded bool           `json:"embedded"`
	SCTCount int            `json:"sct_count"`
	Status   CTStatus       `json:"status"`
	Logs     []CTLogOutcome `json:"logs,omitempty"`
}

// CTLogOutcome is the per-log result of a precertificate submission.
type CTLogOutcome struct {
	Log   string `json:"log"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ExportPKCS12Request asks a CA to generate a subject keypair server-side, issue
// a leaf under the named profile, and return a password-protected PKCS#12
// (.p12/.pfx) bundle containing the subject key, the leaf, and the full issuer
// chain. The CA signing key never leaves the HSM — only the freshly-generated
// subject key is bundled. This is the key-delivery path for S/MIME and device
// enrollment, where the subscriber legitimately needs its own private key.
type ExportPKCS12Request struct {
	// Subject distinguished-name fields. A common name or at least one SAN is
	// required.
	CommonName         string `json:"common_name,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	// Subject Alternative Names. The profile still governs which are permitted.
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	URIs        []string `json:"uris,omitempty"`
	// Profile is the certificate profile name (empty = default).
	Profile string `json:"profile,omitempty"`
	// KeyType is "ecdsa" (default) or "rsa"; KeyBits sizes it (RSA bits, or ECDSA
	// curve 256/384/521). Zero selects the type default.
	KeyType string `json:"key_type,omitempty"`
	KeyBits int    `json:"key_bits,omitempty"`
	// ValidityDays overrides the profile default (0 = default), clamped to the
	// profile maximum and any deployment cap.
	ValidityDays int `json:"validity_days,omitempty"`
	// Password protects the PKCS#12 bundle. Required; short passwords are refused.
	Password string `json:"password"`
	// Encoder selects the PKCS#12 encoding: "modern" (default; PBES2/AES-256),
	// "legacy" (3DES, broad compatibility), or "legacyrc2" (oldest software).
	Encoder string `json:"encoder,omitempty"`
	// Escrow, when true, additionally escrows the freshly-generated subject
	// private key under the configured M-of-N recovery policy (Task 33), returning
	// the escrow envelope for the operator to store for break-glass recovery. It
	// requires the secret KEK and secret.escrow to be configured.
	Escrow bool `json:"escrow,omitempty"`
}

// ExportPKCS12Response returns the produced PKCS#12 bundle (base64-encoded DER)
// and issuance metadata. The private key is delivered only inside the
// password-protected bundle; it is never returned in the clear.
type ExportPKCS12Response struct {
	Serial   string `json:"serial"`
	Profile  string `json:"profile"`
	NotAfter string `json:"not_after"`
	// PKCS12 is the base64-encoded DER PKCS#12 bundle.
	PKCS12 string `json:"pkcs12"`
	// Chain is the PEM certificate chain (leaf + issuers), for display/verification.
	Chain string `json:"chain,omitempty"`
	// KeyType is the resolved subject key description (e.g. "ecdsa-p256").
	KeyType string `json:"key_type"`
	// Encoder is the resolved PKCS#12 encoder name used.
	Encoder string `json:"encoder"`
	// Escrow, present only when escrow was requested, carries the escrow envelope
	// and the recovery context needed for a later break-glass ceremony.
	Escrow *PKCS12EscrowInfo `json:"escrow,omitempty"`
	// CT reports Certificate Transparency handling; present only when the profile
	// requested CT.
	CT *CTResponse `json:"ct,omitempty"`
}

// PKCS12EscrowInfo describes the escrow of a PKCS#12 subject key and carries the
// envelope the operator must retain for recovery.
type PKCS12EscrowInfo struct {
	Threshold int `json:"threshold"`
	Agents    int `json:"agents"`
	// Context is the encryption context bound into the escrow envelope; the same
	// value must be supplied at recovery time (`secsy-secret recover -context`).
	Context string `json:"context"`
	// Envelope is the escrow envelope JSON to store for break-glass recovery.
	Envelope json.RawMessage `json:"envelope"`
}

// IssueSVIDRequest asks a CA to mint a SPIFFE X.509-SVID. The workload supplies
// a CSR for its freshly generated key; only the public key is used. The identity
// is the SPIFFE ID, given either as a full spiffe:// URI (SpiffeID) or as a
// trust domain plus workload path — never derived from the CSR's own subject or
// SANs. The trust domain must be permitted by the SVID trust-domain allowlist.
type IssueSVIDRequest struct {
	CSR string `json:"csr"` // PEM-encoded PKCS#10 CSR (public key source)
	// SpiffeID is the full spiffe:// URI. When set it takes precedence over
	// TrustDomain/Path.
	SpiffeID string `json:"spiffe_id,omitempty"`
	// TrustDomain and Path build the SPIFFE ID when SpiffeID is not given.
	TrustDomain string `json:"trust_domain,omitempty"`
	Path        string `json:"path,omitempty"`
	// Profile overrides the default SVID profile (empty = server default).
	Profile string `json:"profile,omitempty"`
	// TTLSeconds overrides the profile's default validity (clamped to its max).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// DNSNames are optional additional SANs (discouraged by the SVID spec).
	DNSNames []string `json:"dns_names,omitempty"`
}

// IssueSVIDResponse returns a freshly minted SPIFFE X.509-SVID.
type IssueSVIDResponse struct {
	SpiffeID    string `json:"spiffe_id"`
	TrustDomain string `json:"trust_domain"`
	Certificate string `json:"certificate"`     // PEM leaf SVID
	Chain       string `json:"chain,omitempty"` // leaf + issuer chain (PEM)
	Bundle      string `json:"bundle,omitempty"`
	Serial      string `json:"serial"`
	Profile     string `json:"profile"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

// IssueJWTSVIDRequest asks a CA to mint a SPIFFE JWT-SVID: a short-lived signed
// JWS bearer token whose subject is the SPIFFE ID. The identity is given either
// as a full spiffe:// URI (SpiffeID) or as trust domain plus workload path, and
// the trust domain must be permitted by the SVID trust-domain allowlist. Unlike
// an X.509-SVID there is no CSR — the token carries no workload key.
type IssueJWTSVIDRequest struct {
	// SpiffeID is the full spiffe:// URI. When set it takes precedence over
	// TrustDomain/Path.
	SpiffeID string `json:"spiffe_id,omitempty"`
	// TrustDomain and Path build the SPIFFE ID when SpiffeID is not given.
	TrustDomain string `json:"trust_domain,omitempty"`
	Path        string `json:"path,omitempty"`
	// Audience is the token's intended audience set ("aud"). At least one value is
	// required unless the server configures a default audience.
	Audience []string `json:"audience,omitempty"`
	// TTLSeconds overrides the default token lifetime (clamped to the server max).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// IssueJWTSVIDResponse returns a freshly minted SPIFFE JWT-SVID.
type IssueJWTSVIDResponse struct {
	Token       string   `json:"token"` // compact-serialized signed JWT-SVID
	SpiffeID    string   `json:"spiffe_id"`
	TrustDomain string   `json:"trust_domain"`
	Audience    []string `json:"audience"`
	KeyID       string   `json:"kid"` // token kid; resolves to a jwt-svid key in the bundle
	Algorithm   string   `json:"alg"` // JWS signature algorithm (e.g. ES256)
	IssuedAt    string   `json:"issued_at"`
	ExpiresAt   string   `json:"expires_at"`
	// Bundle is the SPIFFE trust bundle (JWKS) with the JWT verification keys, so a
	// relying party can validate the token from a single call. Best-effort.
	Bundle string `json:"bundle,omitempty"`
}

// RenewCertRequest renews a previously issued certificate identified by serial
// (or by supplying a fresh CSR for the same subject). A new serial and validity
// window are produced; the original is left untouched (and may be revoked
// separately).
type RenewCertRequest struct {
	Serial       string `json:"serial"`
	CSR          string `json:"csr,omitempty"` // optional: rekey with a new CSR
	ValidityDays int    `json:"validity_days,omitempty"`
}

// RevokeCertRequest revokes a certificate by serial number.
type RevokeCertRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason,omitempty"` // RFC 5280 reason name; default "unspecified"
}

// BulkRevokeFilterRequest narrows a bulk revocation (Task 70). All set fields
// AND together; a zero filter selects every not-yet-revoked, unexpired
// certificate of the CA.
type BulkRevokeFilterRequest struct {
	// Profile restricts to certificates issued under this profile.
	Profile string `json:"profile,omitempty"`
	// Pattern is a case-insensitive glob matched against the CN and every SAN.
	Pattern string `json:"pattern,omitempty"`
	// IssuedAfter / IssuedBefore bound the certificate NotBefore (inclusive).
	IssuedAfter  *time.Time `json:"issued_after,omitempty"`
	IssuedBefore *time.Time `json:"issued_before,omitempty"`
	// Serials restricts the operation to these serials (decimal strings).
	// Serials unknown to the inventory are still revoked as bare CRL entries.
	Serials []string `json:"serials,omitempty"`
	// IncludeExpired also revokes certificates past their NotAfter.
	IncludeExpired bool `json:"include_expired,omitempty"`
}

// BulkRevokeRequest is the body of POST /api/ca/{id}/revocations:bulk. A
// dry-run returns the plan (counts + sample) without changing anything; an
// execution must echo the dry-run total in confirm_count and is refused with
// 409 when the live selection has drifted from it.
type BulkRevokeRequest struct {
	DryRun bool                    `json:"dry_run,omitempty"`
	Reason string                  `json:"reason,omitempty"` // RFC 5280 reason name; default "unspecified"
	Filter BulkRevokeFilterRequest `json:"filter,omitempty"`
	// ConfirmCount is the operator-confirmed certificate count (required
	// unless dry_run). It must match the recomputed selection exactly.
	ConfirmCount *int `json:"confirm_count,omitempty"`
	// OperationID correlates audit events across a resumed operation
	// (optional; generated when empty).
	OperationID string `json:"operation_id,omitempty"`
	// BatchSize overrides the per-transaction batch size (bounded server-side).
	BatchSize int `json:"batch_size,omitempty"`
}

// BulkIssueItemRequest is one certificate request in a batch-issuance body
// (Task 101). The subject and SANs are taken from the CSR, exactly as in single
// issuance; ref is an opaque client correlation tag echoed back in the result.
type BulkIssueItemRequest struct {
	// Ref is an opaque client-supplied reference echoed back in the item's
	// result so the caller can match results to requests regardless of ordering.
	// Empty defaults to the item's zero-based index.
	Ref string `json:"ref,omitempty"`
	// CSR is a PEM-encoded PKCS#10 certificate signing request (required).
	CSR string `json:"csr"`
	// Profile is the certificate profile name (empty = default profile).
	Profile string `json:"profile,omitempty"`
	// ValidityDays overrides the profile default validity (0 = profile default).
	ValidityDays int `json:"validity_days,omitempty"`
}

// BulkIssueRequest is the body of POST /api/ca/{id}/certificates:bulk. Every
// item is issued independently through the full per-issuance gate stack; a
// per-item failure never aborts the batch, and an item whose profile requires
// manual approval is parked (reported "pending") rather than failing. The
// confirm_count guard against accidental mass issuance must equal the number of
// items unless dry_run.
type BulkIssueRequest struct {
	// DryRun validates each item (CSR + profile) and reports what would happen
	// without issuing or parking anything.
	DryRun bool `json:"dry_run,omitempty"`
	// Items are the certificate requests. At least one is required; the count is
	// bounded server-side (ca.MaxBulkIssueItems).
	Items []BulkIssueItemRequest `json:"items"`
	// ConfirmCount is the operator-confirmed item count (required unless
	// dry_run). It must equal len(items) exactly (409 otherwise).
	ConfirmCount *int `json:"confirm_count,omitempty"`
	// OperationID correlates the per-item audit events with the summary event
	// (optional; generated when empty).
	OperationID string `json:"operation_id,omitempty"`
	// Concurrency overrides how many items are issued in parallel (bounded
	// server-side; 0 = default).
	Concurrency int `json:"concurrency,omitempty"`
}

type Group struct {
	ID string `json:"id" db:"id"`
	// TenantID scopes the group to a tenant so a group name may be reused across
	// tenants and membership never leaks across the isolation boundary.
	TenantID string `json:"tenant_id" db:"tenant_id"`
	Name     string `json:"name" db:"name"`
}

type GroupMember struct {
	GroupID string `json:"group_id" db:"group_id"`
	UserSub string `json:"user_sub" db:"user_sub"`
}

type PermissionEntry struct {
	ID                   string     `json:"id" db:"id"`
	CAID                 string     `json:"ca_id" db:"ca_id"`
	EntityType           string     `json:"entity_type" db:"entity_type"` // "user" or "group"
	EntityID             string     `json:"entity_id" db:"entity_id"`
	Permission           Permission `json:"permission" db:"permission"`
	SSHRestrictionSetID  *string    `json:"ssh_restriction_set_id,omitempty" db:"ssh_restriction_set_id"`
	X509RestrictionSetID *string    `json:"x509_restriction_set_id,omitempty" db:"x509_restriction_set_id"`
}

// RestrictionSetType distinguishes between SSH and X.509 restriction sets.
type RestrictionSetType string

const (
	RestrictionSetSSH  RestrictionSetType = "ssh"
	RestrictionSetX509 RestrictionSetType = "x509"
)

// RestrictionSet defines constraints on certificate signing parameters.
type RestrictionSet struct {
	ID string `json:"id"`
	// TenantID scopes the restriction set (issuance profile) to a tenant. A CA
	// may only reference restriction sets belonging to its own tenant.
	TenantID        string             `json:"tenant_id,omitempty" db:"tenant_id"`
	CAID            string             `json:"ca_id,omitempty"`
	Name            string             `json:"name"`
	Type            RestrictionSetType `json:"type"` // "ssh" or "x509"
	MaxValiditySecs *int64             `json:"max_validity_secs,omitempty"`

	DenyAll bool `json:"deny_all"`

	// SSH-specific restrictions
	AllowedPrincipals   []string `json:"allowed_principals,omitempty"`
	AllowedCertTypes    []string `json:"allowed_cert_types,omitempty"` // ["user"], ["host"], ["user","host"]
	ForceKeyIDEmail     bool     `json:"force_key_id_email"`
	RequireReason       bool     `json:"require_reason"`
	AllowedExtensions   []string `json:"allowed_extensions,omitempty"`
	DenyExtensions      bool     `json:"deny_extensions"`
	DenyCriticalOptions bool     `json:"deny_critical_options"`
	MaxValidAfterOffset *int64   `json:"max_valid_after_offset,omitempty"`

	// X.509-specific restrictions
	AllowedKeyUsages     []string `json:"allowed_key_usages,omitempty"`     // e.g. ["digitalSignature", "keyEncipherment"]
	AllowedExtKeyUsages  []string `json:"allowed_ext_key_usages,omitempty"` // e.g. ["serverAuth", "clientAuth"]
	AllowedSANTypes      []string `json:"allowed_san_types,omitempty"`      // e.g. ["dns", "ip", "email"]
	AllowedSANPatterns   []string `json:"allowed_san_patterns,omitempty"`   // e.g. ["*.example.com", "10.0.0.0/8"]
	AllowedSubjectFields []string `json:"allowed_subject_fields,omitempty"` // e.g. ["CN", "O", "OU"]
	MaxPathLength        *int     `json:"max_path_length,omitempty"`        // -1 = no CA, 0+ = CA with path length
	DenyCA               bool     `json:"deny_ca"`                          // if true, cannot issue CA certificates
}

// X509SignRequest is the request to sign an X.509 certificate.
// All certificate parameters are taken from the CSR; only validity can be overridden.
type X509SignRequest struct {
	CAID        string `json:"ca_id"`
	CSR         string `json:"csr"` // PEM-encoded PKCS#10 CSR
	ValidBefore string `json:"valid_before,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// X509SignResponse is the response containing the signed X.509 certificate.
type X509SignResponse struct {
	Certificate string `json:"certificate"` // PEM-encoded X.509 certificate
	Serial      string `json:"serial"`
}

type SignRequest struct {
	CAID            string            `json:"ca_id"`
	PublicKey       string            `json:"public_key"`
	Principals      []string          `json:"principals"`
	CertType        string            `json:"cert_type"` // "user" or "host"
	KeyID           string            `json:"key_id"`
	Reason          string            `json:"reason,omitempty"` // used when force_key_id_email_reason is true
	ValidAfter      string            `json:"valid_after,omitempty"`
	ValidBefore     string            `json:"valid_before,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
}

type SignResponse struct {
	Certificate string `json:"certificate"`
	KeyID       string `json:"key_id"`
}

type KeyGenRequest struct {
	KeyType string            `json:"key_type"` // rsa, ecdsa, ed25519
	Bits    int               `json:"bits"`     // key size for rsa/ecdsa
	Comment string            `json:"comment"`
	Options map[string]string `json:"options"` // additional ssh-keygen options
}

type KeyGenResponse struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type PermissionGrant struct {
	CAID                 string     `json:"ca_id"`
	EntityType           string     `json:"entity_type"` // "user" or "group"
	EntityID             string     `json:"entity_id"`
	Permission           Permission `json:"permission"`
	SSHRestrictionSetID  *string    `json:"ssh_restriction_set_id,omitempty"`
	X509RestrictionSetID *string    `json:"x509_restriction_set_id,omitempty"`
}

type AuditLogEntry struct {
	ID               string            `json:"id"`
	Timestamp        time.Time         `json:"timestamp"`
	UserSub          string            `json:"user_sub"`
	UserEmail        string            `json:"user_email,omitempty"`
	UserName         string            `json:"user_name,omitempty"`
	CAID             string            `json:"ca_id"`
	CALabel          string            `json:"ca_label"`
	CertFormat       string            `json:"cert_format"` // "ssh" or "x509"
	KeyID            string            `json:"key_id"`
	CertType         string            `json:"cert_type"`
	Principals       []string          `json:"principals"`
	ValidAfter       time.Time         `json:"valid_after"`
	ValidBefore      time.Time         `json:"valid_before"`
	Extensions       map[string]string `json:"extensions,omitempty"`
	CriticalOptions  map[string]string `json:"critical_options,omitempty"`
	PublicKey        string            `json:"public_key"`
	Certificate      string            `json:"certificate,omitempty"`
	RestrictionSetID *string           `json:"restriction_set_id,omitempty"`
	Serial           string            `json:"serial"`
}

type HSMAuditEntry struct {
	Number      uint16  `json:"number"`
	Command     uint8   `json:"command"`
	Length      uint16  `json:"length"`
	SessionKey  uint16  `json:"session_key"`
	TargetKey   uint16  `json:"target_key"`
	SecondKey   uint16  `json:"second_key"`
	Result      uint8   `json:"result"`
	Tick        uint32  `json:"tick"`
	Hash        string  `json:"hash"`
	SignAuditID *string `json:"sign_audit_id,omitempty"`
}

type CombinedAuditExport struct {
	DeviceSerial    string            `json:"device_serial,omitempty"`
	HSMEntries      []HSMAuditEntry   `json:"hsm_entries"`
	SignOps         []AuditLogEntry   `json:"sign_operations"`
	KeyAttestations map[string]string `json:"key_attestations,omitempty"` // PKCS11 key label -> attestation cert PEM
}

type AccessLogEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	UserSub   string    `json:"user_sub"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	IP        string    `json:"ip"`
	// RequestID correlates this access-log row with the structured request log
	// line and the tamper-evident audit event(s) emitted while serving the same
	// HTTP request.
	RequestID string `json:"request_id,omitempty"`
}

type UserInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	// EmailVerified is the IdP's email_verified claim. RBAC assignments keyed by
	// email are only applied when this is true.
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	IsRoot        bool   `json:"is_root"`
	// Roles are the organization-wide RBAC roles (admin/issuer/auditor) the
	// authenticated subject holds, resolved at authentication time from central
	// configuration plus group membership. The built-in root user carries no
	// roles here; it is always treated as a superuser regardless.
	//
	// Roles listed here are PLATFORM-WIDE (cross-tenant): a principal holding them
	// exercises the capability in every tenant. They are reserved for platform
	// operators. Tenant-scoped roles live in TenantRoles.
	Roles []string `json:"roles,omitempty"`
	// TenantRoles maps a tenant ID to the roles the subject holds WITHIN that
	// tenant. A principal may only act on a tenant's resources when it is root,
	// holds a platform role, or holds a role for that specific tenant here — the
	// mechanism that forbids cross-tenant access.
	TenantRoles map[string][]string `json:"tenant_roles,omitempty"`
}

// TenantsWithRoles returns the set of tenant IDs the subject holds at least one
// role in. It does not include platform-wide access; callers combine it with
// IsRoot / platform Roles when deciding cross-tenant visibility.
func (u *UserInfo) TenantsWithRoles() []string {
	if u == nil || len(u.TenantRoles) == 0 {
		return nil
	}
	out := make([]string, 0, len(u.TenantRoles))
	for t := range u.TenantRoles {
		out = append(out, t)
	}
	return out
}

// WebAuthnCredential is a registered passkey used for operator step-up
// authentication (Task 50). The private key never leaves the authenticator; the
// server stores only the credential id, the public key (DER SubjectPublicKeyInfo),
// and the authenticator's signature counter for clone detection.
type WebAuthnCredential struct {
	// ID is the base64url credential id assigned by the authenticator; it is the
	// primary key and what the browser echoes in an assertion.
	ID string `json:"id"`
	// Subject is the owning principal (OIDC subject or "root").
	Subject string `json:"subject"`
	// Name is an operator-supplied label (e.g. "YubiKey 5C", "Laptop Touch ID").
	Name string `json:"name"`
	// PublicKeyDER is the credential public key marshaled as PKIX/SPKI DER.
	PublicKeyDER []byte `json:"-"`
	// SignCount is the last-seen authenticator signature counter. A non-increasing
	// counter on a subsequent assertion signals a cloned authenticator.
	SignCount uint32    `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

// Token scope values (Task 86). A tenant-scoped token exercises its roles only
// within its owning tenant; a platform-scoped token holds them across all
// tenants and may only be minted by a platform administrator.
const (
	TokenScopeTenant   = "tenant"
	TokenScopePlatform = "platform"
)

// APIToken is a native, revocable, scoped long-lived credential for
// machine-to-machine callers — a service account (Task 86). The opaque secret
// (secsy_pat_<random>) is shown to the operator exactly once at creation and is
// NEVER persisted; only its one-way hash (TokenHash) is stored, so a database
// disclosure cannot reveal a usable credential. A token is bound to a set of
// RBAC roles and a tenant scope, with an optional expiry and best-effort
// last-used tracking, and is verified in the same Authenticate/AuthenticateRPC
// paths as the other credential types.
type APIToken struct {
	// ID is the token's stable identifier (a UUID), used as the audit target and
	// as the principal subject ("token:<id>") of requests it authenticates.
	ID string `json:"id"`
	// TenantID is the token's owning/home tenant. For a tenant-scoped token it is
	// the single tenant its roles apply within; for a platform-scoped token it is
	// informational (the roles span all tenants).
	TenantID string `json:"tenant_id"`
	// Name is an operator-supplied label (e.g. "ci-cert-issuer", "backup-agent").
	Name string `json:"name"`
	// Description is optional free-form context for the credential.
	Description string `json:"description,omitempty"`
	// Prefix is the non-secret leading fragment of the token (secsy_pat_XXXX…),
	// retained for display so an operator can recognize a listed token without
	// ever seeing the full secret again.
	Prefix string `json:"prefix"`
	// TokenHash is the at-rest one-way hash of the full secret (hex SHA-256). It
	// is the lookup key on the verify path and is never serialized to clients.
	TokenHash string `json:"-"`
	// Roles are the RBAC roles the token grants. For a tenant-scoped token they
	// are exercised within TenantID; for a platform-scoped token, platform-wide.
	Roles []string `json:"roles"`
	// Scope is TokenScopeTenant or TokenScopePlatform.
	Scope string `json:"scope"`
	// CreatedBy / CreatedByName identify the principal that minted the token.
	CreatedBy     string `json:"created_by,omitempty"`
	CreatedByName string `json:"created_by_name,omitempty"`
	// CreatedAt is when the token was minted (UTC).
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt bounds the token's validity; nil means it never expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// LastUsedAt / LastUsedIP record the most recent successful verification,
	// updated best-effort (and throttled) so listing a token shows recent use
	// without a write on every request.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	// RevokedAt / RevokedBy record an explicit revocation. A revoked token fails
	// closed on every subsequent verification.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
}

// IsPlatform reports whether the token's roles span all tenants.
func (t *APIToken) IsPlatform() bool { return t.Scope == TokenScopePlatform }

// Durable outbound webhook subscriptions and their delivery queue (Task 116).
//
// A subscription binds an external HTTP endpoint to a set of certificate
// lifecycle event types and a tenant scope. When a matching event is durably
// committed to the audit log, the leader-elected delivery worker enqueues a
// WebhookDelivery per matching subscription and POSTs the signed payload with
// at-least-once semantics: exponential-backoff retries, dead-lettering after a
// bounded number of attempts, and an HMAC-SHA256 signature (over timestamp+body)
// the receiver verifies to authenticate the sender and blunt replay.

// Webhook scope values mirror the token scopes. A tenant-scoped subscription
// receives only its owning tenant's lifecycle events; a platform-scoped
// subscription receives every tenant's events and may only be created by a
// platform administrator.
const (
	WebhookScopeTenant   = "tenant"
	WebhookScopePlatform = "platform"
)

// Webhook delivery lifecycle states. A delivery starts pending, becomes
// delivered on a 2xx response, or is dead-lettered once its retry budget is
// exhausted. A delivery whose subscription is deleted or disabled mid-flight is
// canceled (a terminal, non-alerting state distinct from a genuine failure).
const (
	WebhookDeliveryPending   = "pending"
	WebhookDeliveryDelivered = "delivered"
	WebhookDeliveryDead      = "dead"
	WebhookDeliveryCanceled  = "canceled"
)

// WebhookSubscription is a durable, tenant-scoped registration of an external
// endpoint that receives certificate lifecycle events. The Secret is the HMAC
// key used to sign deliveries; it is required to compute the signature, so it is
// stored (like the monitor webhook's headers) rather than one-way hashed, and is
// never serialized to clients after creation (json:"-").
type WebhookSubscription struct {
	// ID is the subscription's stable identifier (a UUID) and the audit target.
	ID string `json:"id"`
	// TenantID is the owning tenant. For a tenant-scoped subscription it bounds
	// which events are delivered; for a platform-scoped one it is informational.
	TenantID string `json:"tenant_id"`
	// Scope is WebhookScopeTenant or WebhookScopePlatform.
	Scope string `json:"scope"`
	// URL is the HTTPS endpoint each matching event is POSTed to.
	URL string `json:"url"`
	// Secret is the HMAC-SHA256 signing key. Never serialized to clients; the
	// create response returns it exactly once through a dedicated wrapper.
	Secret string `json:"-"`
	// EventTypes filters which lifecycle events are delivered (e.g. "cert.issue",
	// "cert.revoke"). An empty list subscribes to every supported lifecycle event.
	EventTypes []string `json:"event_types"`
	// Enabled gates delivery: a disabled subscription still exists (and can be
	// re-enabled) but produces no new deliveries.
	Enabled bool `json:"enabled"`
	// Description is optional free-form context.
	Description string `json:"description,omitempty"`
	// CreatedBy identifies the principal that created the subscription.
	CreatedBy string `json:"created_by,omitempty"`
	// CreatedAt / UpdatedAt track the subscription's lifecycle (UTC).
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsPlatform reports whether the subscription receives every tenant's events.
func (s *WebhookSubscription) IsPlatform() bool { return s.Scope == WebhookScopePlatform }

// WebhookDelivery is one durable unit of work in the outbound delivery queue: a
// single event bound for a single subscription, tracked through its retry
// lifecycle. It survives restarts and leadership handovers, so delivery is
// at-least-once: a redelivery of the last unacknowledged attempt is possible and
// receivers must be idempotent on EventID.
type WebhookDelivery struct {
	// ID is the delivery's stable identifier (a UUID) and appears in the
	// X-Secsy-Delivery header so a receiver can correlate retries.
	ID string `json:"id"`
	// SubscriptionID is the owning subscription.
	SubscriptionID string `json:"subscription_id"`
	// TenantID is denormalized from the subscription for scoped read queries.
	TenantID string `json:"tenant_id"`
	// EventID is the source audit event's id — the idempotency key a receiver
	// should deduplicate on.
	EventID string `json:"event_id"`
	// EventSeq is the source audit event's monotonic sequence number. Together
	// with SubscriptionID it forms the fan-out idempotency key (each event is
	// enqueued at most once per subscription). Synthetic test deliveries use a
	// negative sentinel so they never collide with real events.
	EventSeq int64 `json:"event_seq"`
	// EventType is the lifecycle event (audit action) that produced the delivery.
	EventType string `json:"event_type"`
	// Payload is the exact JSON body POSTed to the endpoint (and signed).
	Payload string `json:"payload,omitempty"`
	// Status is the delivery lifecycle state (see the Webhook* constants above).
	Status string `json:"status"`
	// Attempts counts delivery attempts made so far; MaxAttempts snapshots the
	// configured retry budget at enqueue time so a later config change does not
	// retroactively re-open a dead-lettered delivery.
	Attempts    int `json:"attempts"`
	MaxAttempts int `json:"max_attempts"`
	// NextAttemptAt is when a pending delivery becomes due (now for the first
	// attempt, backed off after each failure).
	NextAttemptAt time.Time `json:"next_attempt_at"`
	// LastAttemptAt / LastStatusCode / LastError capture the most recent attempt's
	// outcome for operator visibility.
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	LastStatusCode int        `json:"last_status_code,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	// CreatedAt is when the delivery was enqueued; DeliveredAt when it terminally
	// succeeded (nil otherwise).
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

// Revoked reports whether the token has been explicitly revoked.
func (t *APIToken) Revoked() bool { return t != nil && t.RevokedAt != nil }

// Active reports whether the token may authenticate at the given instant: not
// revoked and not past its expiry.
func (t *APIToken) Active(now time.Time) bool {
	if t == nil || t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// Status renders a human-facing lifecycle state for listings.
func (t *APIToken) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.ExpiresAt != nil && !t.ExpiresAt.After(now):
		return "expired"
	default:
		return "active"
	}
}

// Principal builds the request principal a verified token authenticates as. A
// tenant-scoped token carries its roles under TenantRoles[tenant] (so the same
// cross-tenant isolation checks that confine an OIDC operator apply); a
// platform-scoped token carries them as platform-wide Roles. The token is never
// the built-in root superuser.
func (t *APIToken) Principal() *UserInfo {
	info := &UserInfo{
		Subject: "token:" + t.ID,
		Name:    t.Name,
		IsRoot:  false,
	}
	roles := append([]string(nil), t.Roles...)
	if t.IsPlatform() {
		info.Roles = roles
	} else {
		tenant := t.TenantID
		if tenant == "" {
			tenant = DefaultTenantID
		}
		info.TenantRoles = map[string][]string{tenant: roles}
	}
	return info
}

// ---------------------------------------------------------------------------
// ACME (RFC 8555) persistence records.
//
// These are the database-facing representations of the ACME protocol objects.
// The acme package maps them to and from the RFC 8555 wire JSON. Keeping the
// storage structs in models (rather than the acme package) lets the database
// layer read and write them without importing acme, avoiding an import cycle.
// ---------------------------------------------------------------------------

// ACME object statuses (RFC 8555 §7.1.6). Stored as plain strings.
const (
	ACMEAccountStatusValid       = "valid"
	ACMEAccountStatusDeactivated = "deactivated"
	ACMEAccountStatusRevoked     = "revoked"

	ACMEOrderStatusPending    = "pending"
	ACMEOrderStatusReady      = "ready"
	ACMEOrderStatusProcessing = "processing"
	ACMEOrderStatusValid      = "valid"
	ACMEOrderStatusInvalid    = "invalid"

	ACMEAuthzStatusPending     = "pending"
	ACMEAuthzStatusValid       = "valid"
	ACMEAuthzStatusInvalid     = "invalid"
	ACMEAuthzStatusDeactivated = "deactivated"
	ACMEAuthzStatusExpired     = "expired"
	ACMEAuthzStatusRevoked     = "revoked"

	ACMEChallengeStatusPending    = "pending"
	ACMEChallengeStatusProcessing = "processing"
	ACMEChallengeStatusValid      = "valid"
	ACMEChallengeStatusInvalid    = "invalid"
)

// ACME challenge type identifiers.
const (
	ACMEChallengeHTTP01 = "http-01"
	ACMEChallengeDNS01  = "dns-01"
	// ACMEChallengeTLSALPN01 is the tls-alpn-01 challenge (RFC 8737): the client
	// proves control of an identifier by presenting, over a TLS handshake on the
	// ACME TLS ALPN port that negotiates the "acme-tls/1" protocol, a self-signed
	// certificate carrying the critical id-pe-acmeIdentifier extension whose value
	// is SHA-256(keyAuthorization).
	ACMEChallengeTLSALPN01 = "tls-alpn-01"
	// ACMEChallengeDeviceAttest01 is the device-attest-01 challenge
	// (draft-ietf-acme-device-attest): the client proves control of a
	// hardware-resident key by returning a WebAuthn attestation object
	// (Apple/TPM) committing to the challenge's key authorization.
	ACMEChallengeDeviceAttest01 = "device-attest-01"
	// ACMEChallengeEmailReply00 is the email-reply-00 challenge (RFC 8823) for
	// "email"-type identifiers (S/MIME). The server mails a signed challenge to
	// the mailbox carrying token-part-1 in the Subject; the mailbox owner replies
	// with base64url(SHA-256(keyAuthorization)) computed over the full token
	// (token-part-1 ‖ token-part-2), which the server matches from its inbound
	// (IMAP) mailbox. Only offered when an inbound-mail poller is configured.
	ACMEChallengeEmailReply00 = "email-reply-00"
)

// ACMEIdentifier is a subject the client wishes to certify (RFC 8555 §7.1.4).
type ACMEIdentifier struct {
	Type  string `json:"type"`  // "dns" or "ip"
	Value string `json:"value"` // the domain name or IP literal
}

// ACMEAccount is a registered ACME account, keyed by its public account key.
type ACMEAccount struct {
	ID string `json:"id"`
	// Status is one of the ACMEAccountStatus* values.
	Status string `json:"status"`
	// Contacts are the "mailto:" (or other) contact URLs supplied by the client.
	Contacts []string `json:"contacts,omitempty"`
	// JWK is the account's public key, stored as a serialized JSON Web Key.
	JWK string `json:"-"`
	// Thumbprint is the base64url(SHA-256) JWK thumbprint (RFC 7638), used to
	// look an account up by its key on newAccount.
	Thumbprint string `json:"-"`
	// EABKid records the External Account Binding key id the account bound with,
	// when EAB is required. Empty otherwise.
	EABKid           string    `json:"-"`
	TermsOfServiceOK bool      `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
}

// ACMEOrder is a request to issue a certificate for a set of identifiers.
type ACMEOrder struct {
	ID          string           `json:"id"`
	AccountID   string           `json:"-"`
	Status      string           `json:"status"`
	Identifiers []ACMEIdentifier `json:"identifiers"`
	NotBefore   *time.Time       `json:"not_before,omitempty"`
	NotAfter    *time.Time       `json:"not_after,omitempty"`
	Expires     time.Time        `json:"expires"`
	// Error holds a serialized ACME problem document if the order failed.
	Error string `json:"-"`
	// CAID and Serial identify the issued certificate once the order is valid.
	CAID   string `json:"-"`
	Serial string `json:"-"`
	// Certificate is the issued PEM chain (leaf first), populated on finalize.
	Certificate string     `json:"-"`
	FinalizedAt *time.Time `json:"-"`
	// Replaces is the ARI CertID (draft-ietf-acme-ari §5) of the certificate this
	// order renews, when the client set the newOrder "replaces" field. It links a
	// renewal order back to its predecessor for renewal accounting.
	Replaces string `json:"replaces,omitempty"`
	// Profile is the internal ca issuance profile id selected for this order via
	// the ACME Profiles extension (RFC 9773). It is resolved from the client's
	// newOrder "profile" field against the server's configured allowlist at order
	// creation and threaded into issuance at finalize, so every pre-issuance gate
	// uses the chosen profile. Empty on legacy orders predating the extension,
	// where finalize falls back to the server's default profile. Surfaced (when
	// set) on the operator inventory endpoint GET /api/acme/orders for visibility
	// into the profile each order issued under.
	Profile   string    `json:"profile,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ACMEAuthorization is the authorization for a single identifier within an order.
type ACMEAuthorization struct {
	ID              string    `json:"id"`
	OrderID         string    `json:"-"`
	AccountID       string    `json:"-"`
	IdentifierType  string    `json:"-"`
	IdentifierValue string    `json:"-"`
	Status          string    `json:"status"`
	Expires         time.Time `json:"expires"`
	Wildcard        bool      `json:"wildcard,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// ACMEChallenge is one validation method offered for an authorization.
type ACMEChallenge struct {
	ID      string `json:"id"`
	AuthzID string `json:"-"`
	Type    string `json:"type"`
	// Token is the challenge token exposed over HTTPS. For email-reply-00 (RFC
	// 8823) it is token-part-2; for every other challenge type it is the whole
	// token.
	Token     string     `json:"token"`
	Status    string     `json:"status"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     string     `json:"-"`
	// EmailToken1 is token-part-1 of an email-reply-00 challenge (RFC 8823 §3):
	// the high-entropy half delivered to the mailbox in the challenge email's
	// Subject, never exposed over HTTPS. Empty for all other challenge types.
	EmailToken1 string `json:"-"`
	// EmailMessageID is the Message-ID of the challenge email once it has been
	// sent, used to match the mailbox owner's reply (via In-Reply-To/References)
	// back to this challenge. Empty until the email has been dispatched.
	EmailMessageID string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
}

// KEK (key-encryption-key) rotation states for the secret envelope layer
// (Task 63). A KEK family — named by its base label, e.g. the configured
// secret.kek_label or a tenant's kek_label — is a lineage of versioned HSM
// keys. Exactly one version is active (seals new envelopes); previous versions
// stay retiring (still able to open their envelopes) until every secret has
// been re-wrapped, and are then retired, after which decryption under them is
// refused fail-closed.
const (
	// KEKStatusActive marks the family's current wrapping key: new envelopes
	// are sealed under it, and it can open envelopes it wrapped.
	KEKStatusActive = "active"
	// KEKStatusRetiring marks a superseded version inside the dual-KEK decrypt
	// window: it no longer seals new envelopes but still opens existing ones,
	// so reads keep working while secrets are re-wrapped.
	KEKStatusRetiring = "retiring"
	// KEKStatusRetired marks a version withdrawn from service: decryption under
	// it is refused. Retire a version only once nothing is wrapped under it.
	KEKStatusRetired = "retired"
)

// KEKVersion is one versioned key-encryption key in a family's rotation
// lineage. Version 1 is the family's initial key whose HSM label is the family
// name itself; version N>1 lives under the label "<family>-vN", keeping every
// CKA_LABEL unique (generating a second key under an in-use label makes lookup
// ambiguous on PKCS#11 tokens).
type KEKVersion struct {
	Family  string `json:"family" db:"family"`
	Version int    `json:"version" db:"version"`
	Label   string `json:"label" db:"label"`
	Status  string `json:"status" db:"status"` // active | retiring | retired
	// CreatedAt is when the version was generated (or first registered, for a
	// backfilled version-1 row).
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// RotatedAt is when the version stopped being active (nil while active).
	RotatedAt *time.Time `json:"rotated_at,omitempty" db:"rotated_at"`
	// RetiredAt is when decryption under the version was withdrawn.
	RetiredAt *time.Time `json:"retired_at,omitempty" db:"retired_at"`
}

// StoredSecret is a server-held envelope-encrypted secret: the ciphertext
// envelope plus the bookkeeping that makes fleet-wide KEK rotation possible
// (which KEK family/label/version currently wraps its data key). The plaintext
// is never stored; the envelope is exactly what /api/secret/encrypt returns
// and decrypting it still requires the HSM-held KEK. KEKLabel/KEKVersion are
// denormalized from the envelope header so "which secrets still sit on an old
// KEK" is a cheap query for re-wrap batches and the on-old-KEK gauge.
type StoredSecret struct {
	ID       string `json:"id" db:"id"`
	TenantID string `json:"tenant_id" db:"tenant_id"`
	// Name is the caller-chosen identifier, unique within the tenant.
	Name string `json:"name" db:"name"`
	// Envelope is the serialized JSON envelope (see secret.Envelope). Omitted
	// from list responses; fetched individually.
	Envelope string `json:"envelope,omitempty" db:"envelope"`
	// KEKFamily is the rotation family that seals this secret (the deployment
	// or tenant KEK base label at encryption time).
	KEKFamily string `json:"kek_family" db:"kek_family"`
	// KEKLabel / KEKVersion mirror the envelope's current wrap header.
	KEKLabel   string `json:"kek_label" db:"kek_label"`
	KEKVersion int    `json:"kek_version" db:"kek_version"`
	// ContextBound records that decryption requires the caller-supplied
	// encryption context (which is deliberately not stored).
	ContextBound bool `json:"context_bound,omitempty" db:"context_bound"`
	// Escrowed records that the envelope carries an M-of-N recovery block.
	Escrowed bool `json:"escrowed,omitempty" db:"escrowed"`
	// CurrentVersion is the value-history version the envelope corresponds to
	// (Task 73). Every put advances it by one; a rollback appends a new version
	// whose envelope is copied from an older one.
	CurrentVersion int `json:"current_version" db:"current_version"`
	// ExpiresAt is the secret's optional TTL deadline. Past it the secret is
	// reported as expired by the lifecycle monitor; decryption still works
	// (expiry is an operational reminder, not a cryptographic revocation).
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	// RotateEveryDays is the optional rotation-reminder period: the lifecycle
	// monitor flags the secret once more than this many days have passed since
	// its value last changed. Zero disables the reminder.
	RotateEveryDays int       `json:"rotate_every_days,omitempty" db:"rotate_every_days"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	// UpdatedAt advances on every envelope rewrite (each put and each re-wrap).
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	// ValueChangedAt advances only when the secret's VALUE changes (put or
	// rollback), not on re-wraps — it is the reference point for rotation
	// reminders, so a KEK migration never masks an overdue rotation.
	ValueChangedAt time.Time `json:"value_changed_at" db:"value_changed_at"`
}

// StoredSecretVersion is one immutable entry in a stored secret's value
// history (Task 73): the envelope that was current at that version, plus the
// wrap bookkeeping needed to keep historical versions decryptable across KEK
// rotations (re-wrap batches migrate historical envelopes too). Version
// numbers start at 1 and only grow; a rollback appends a new version rather
// than rewriting history.
type StoredSecretVersion struct {
	SecretID string `json:"secret_id" db:"secret_id"`
	Version  int    `json:"version" db:"version"`
	// Envelope is the version's ciphertext envelope. Omitted from list
	// responses; fetched per version.
	Envelope     string `json:"envelope,omitempty" db:"envelope"`
	KEKFamily    string `json:"kek_family" db:"kek_family"`
	KEKLabel     string `json:"kek_label" db:"kek_label"`
	KEKVersion   int    `json:"kek_version" db:"kek_version"`
	ContextBound bool   `json:"context_bound,omitempty" db:"context_bound"`
	Escrowed     bool   `json:"escrowed,omitempty" db:"escrowed"`
	// CreatedBy is the operator/API principal that wrote the version.
	CreatedBy string `json:"created_by,omitempty" db:"created_by"`
	// Comment is a free-form note ("initial", "rollback to version 2", ...).
	Comment   string    `json:"comment,omitempty" db:"comment"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// SecretVersionRef addresses one stored-secret history entry — the work-list
// unit for re-wrapping historical envelopes after a KEK rotation.
type SecretVersionRef struct {
	SecretID string `json:"secret_id"`
	Version  int    `json:"version"`
}

// KEKUsage summarizes how many stored secrets are wrapped under one KEK
// version, joined against the version's rotation status for the KEK status
// report and the secrets-on-old-KEK gauge.
type KEKUsage struct {
	Label   string `json:"label"`
	Version int    `json:"version"`
	Status  string `json:"status"`
	Secrets int64  `json:"secrets"`
}

// PendingApproval is one four-eyes / maker-checker approval request (Task 81):
// a high-risk administrative operation held at the gate until a configured
// number of DISTINCT approvers (none of them the requester) sign off. For most
// classes it stores only enough to identify the operation (class, ResourceKey,
// Fingerprint) and describe it to approvers (Summary, Details); the guarded
// operation re-runs after approval and the gate consumes the approved request
// (status -> executed). Classes that cannot be re-run by the requester — notably
// Task 84's cert.issue leaf issuance — additionally park the request inputs in
// Payload and the completed outcome in Result, so the certificate can be issued
// and delivered server-side after approval.
type PendingApproval struct {
	ID       string `json:"id" db:"id"`
	TenantID string `json:"tenant_id" db:"tenant_id"`
	// OperationClass names the guarded operation family (e.g. "ca.rotate").
	OperationClass string `json:"operation_class" db:"operation_class"`
	// ResourceKey is the stable, human-meaningful target id (e.g. "ca:<id>").
	ResourceKey string `json:"resource_key" db:"resource_key"`
	// ResourceName is an optional human label for the target (a CA label, etc.).
	ResourceName string `json:"resource_name,omitempty" db:"resource_name"`
	// Fingerprint pins the exact operation parameters so an approval cannot
	// authorize a different operation than the one requested.
	Fingerprint string `json:"fingerprint" db:"fingerprint"`
	// Summary is a one-line description shown to approvers; Details is optional
	// structured/long-form context.
	Summary string `json:"summary" db:"summary"`
	Details string `json:"details,omitempty" db:"details"`
	// RequestedBy is the principal that triggered the operation (the maker);
	// RequestedByName is their display name. A distinct approver is required.
	RequestedBy     string `json:"requested_by" db:"requested_by"`
	RequestedByName string `json:"requested_by_name,omitempty" db:"requested_by_name"`
	// RequiredApprovals is the distinct-approver threshold snapshotted from the
	// policy at request time, so tightening the policy later cannot retroactively
	// weaken an in-flight request.
	RequiredApprovals int `json:"required_approvals" db:"required_approvals"`
	// Status is pending | approved | rejected | executed | expired.
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// ExpiresAt bounds how long the request is actionable.
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	// DecidedAt is when the request reached a terminal approved/rejected/expired
	// state; ExecutedAt is when the gate consumed an approved request.
	DecidedAt  *time.Time `json:"decided_at,omitempty" db:"decided_at"`
	ExecutedAt *time.Time `json:"executed_at,omitempty" db:"executed_at"`
	// ApprovalsCount is the running number of DISTINCT approvers (populated on
	// read, not a stored column). Decisions carries the full decision log when a
	// single request is fetched.
	ApprovalsCount int                `json:"approvals_count" db:"-"`
	Decisions      []ApprovalDecision `json:"decisions,omitempty" db:"-"`
	// Payload optionally carries an opaque, class-specific serialization of the
	// parked operation so it can be completed after approval WITHOUT the requester
	// resubmitting it (Task 84's cert.issue class stores the CSR and issuance
	// parameters here). Admin-op classes that simply re-run after approval leave it
	// empty. It is never exposed in API responses (json:"-").
	Payload string `json:"-" db:"payload"`
	// Result optionally carries an opaque, class-specific serialization of the
	// completed operation's outcome (Task 84's cert.issue stores the issued serial
	// here), so the certificate can be delivered on a later fetch. Empty until the
	// approved request is consumed. It is never exposed in API responses.
	Result string `json:"-" db:"result"`
}

// Expired reports whether the request's actionable window has elapsed.
func (p *PendingApproval) Expired(now time.Time) bool {
	return !p.ExpiresAt.IsZero() && now.After(p.ExpiresAt)
}

// ApprovalDecision is one approver's vote on a PendingApproval. The store's
// UNIQUE(approval_id, approver) constraint makes "N distinct approvers"
// enforceable: a given approver contributes at most one decision, so the
// threshold cannot be met by one person voting repeatedly.
type ApprovalDecision struct {
	ID           int64  `json:"id" db:"id"`
	ApprovalID   string `json:"approval_id" db:"approval_id"`
	Approver     string `json:"approver" db:"approver"`
	ApproverName string `json:"approver_name,omitempty" db:"approver_name"`
	// Decision is "approve" or "reject".
	Decision  string    `json:"decision" db:"decision"`
	Comment   string    `json:"comment,omitempty" db:"comment"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
