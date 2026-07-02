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
	Name    string `json:"name,omitempty"`
	IsRoot  bool   `json:"is_root"`
}
