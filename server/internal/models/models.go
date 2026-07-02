package models

import "time"

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
	ID                          string    `json:"id" db:"id"`
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
}

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
	Label        string    `json:"label"`
	KeyType      string    `json:"key_type"`
	Subject      CASubject `json:"subject"`
	ValidityDays int       `json:"validity_days"`
	MaxPathLen   *int      `json:"max_path_len,omitempty"` // nil = unconstrained
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
}

// CertStatus is the lifecycle status of an issued end-entity certificate.
type CertStatus string

const (
	CertStatusValid   CertStatus = "valid"
	CertStatusRevoked CertStatus = "revoked"
	CertStatusExpired CertStatus = "expired"
)

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

// IssueCertRequest asks a CA to sign a CSR into an end-entity certificate under
// a named profile. SANs and subject fields are taken from the CSR; the profile
// governs key usage, extended key usage, and validity bounds.
type IssueCertRequest struct {
	CSR          string `json:"csr"`     // PEM-encoded PKCS#10 CSR
	Profile      string `json:"profile"` // profile name; empty = default
	ValidityDays int    `json:"validity_days,omitempty"`
}

// IssueCertResponse returns a freshly issued end-entity certificate.
type IssueCertResponse struct {
	Certificate string `json:"certificate"` // PEM leaf certificate
	Chain       string `json:"chain,omitempty"`
	Serial      string `json:"serial"`
	Profile     string `json:"profile"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
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

type Group struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
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
	ID              string             `json:"id"`
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
	Roles []string `json:"roles,omitempty"`
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
	CreatedAt   time.Time  `json:"created_at"`
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
	ID        string     `json:"id"`
	AuthzID   string     `json:"-"`
	Type      string     `json:"type"`
	Token     string     `json:"token"`
	Status    string     `json:"status"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     string     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
}
