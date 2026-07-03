package config

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Database    DatabaseConfig    `yaml:"database"`
	OIDC        OIDCConfig        `yaml:"oidc"`
	RootUser    RootUserConfig    `yaml:"root_user"`
	KeyProvider KeyProviderConfig `yaml:"key_provider"`
	PKCS11      PKCS11Config      `yaml:"pkcs11"`
	YubiHSM     YubiHSMConfig     `yaml:"yubihsm"`
	Secret      SecretConfig      `yaml:"secret"`
	// RBAC assigns organization-wide roles (admin/issuer/signer/auditor) to subjects
	// and groups; Policy holds issuance guardrails; Profiles defines custom
	// certificate profiles layered over the built-ins. Together these give a
	// single, centralized place to govern who may do what and under which rules.
	RBAC     RBACConfig      `yaml:"rbac"`
	Policy   PolicyConfig    `yaml:"policy"`
	Profiles []ProfileConfig `yaml:"profiles"`
	// Tenants declares the isolated organizations this deployment serves. The
	// built-in "default" tenant always exists implicitly; declaring tenants here
	// provisions additional ones and their per-tenant RBAC role assignments. See
	// TenantConfig.
	Tenants []TenantConfig `yaml:"tenants"`
	// ACME configures the RFC 8555 automated-issuance server. Disabled unless
	// acme.enabled is true.
	ACME ACMEConfig `yaml:"acme"`
	// SCEP / EST configure the device-enrollment protocols (RFC 8894 / RFC 7030).
	// Disabled unless their .enabled is true.
	SCEP SCEPConfig `yaml:"scep"`
	EST  ESTConfig  `yaml:"est"`
	// TSA configures the RFC 3161 Time-Stamp Authority. Disabled unless
	// tsa.enabled is true.
	TSA TSAConfig `yaml:"tsa"`
	// Signing configures the artifact code-signing service (/api/sign and
	// `secsy-ca sign`). Disabled unless signing.enabled is true.
	Signing SigningConfig `yaml:"signing"`
	// CMP configures the Lightweight CMP (RFC 9483) certificate-management server.
	// Disabled unless cmp.enabled is true.
	CMP CMPConfig `yaml:"cmp"`
	// Monitor configures the background certificate-expiry monitor and optional
	// auto-renewal workflow. Disabled unless monitor.enabled is true.
	Monitor MonitorConfig `yaml:"monitor"`
	// Canary configures the synthetic issuance canary (Task 71): an end-to-end
	// self-test loop that periodically issues, verifies, and revokes a
	// short-lived certificate per configured CA to prove the whole issuance/
	// revocation path (HSM signing, lint gate, OCSP, CRL) is healthy. Failures
	// are dispatched through the monitor's notification sinks. Disabled unless
	// canary.enabled is true.
	Canary CanaryConfig `yaml:"canary"`
	// Audit configures streaming export of the tamper-evident audit event log to
	// external SIEM systems (syslog/CEF/webhook). Disabled unless
	// audit.export.enabled is true.
	Audit AuditConfig `yaml:"audit"`
	// RateLimit configures request rate limiting, per-account/IP/global quotas,
	// and the bounded in-flight concurrency guard protecting the HSM on the
	// public endpoints (ACME, OCSP, CRL, SCEP/EST). Disabled unless
	// rate_limit.enabled is true.
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	// CertificateTransparency registers the RFC 6962 CT logs available to
	// issuance profiles. Profiles opt in per-profile via their `ct` block; a log
	// referenced by a profile must be registered here.
	CertificateTransparency CTConfig `yaml:"certificate_transparency"`
	// CAA configures DNS Certification Authority Authorization checking (RFC
	// 8659). It supplies this CA's own identifier and the DNS-answer cache TTL;
	// profiles opt in per-profile via their `caa` block.
	CAA CAAGlobalConfig `yaml:"caa"`
	// CRL configures delta CRLs and CRL partitioning/sharding (RFC 5280). It
	// controls how many shards a CA's revocation data is split across, the delta
	// regeneration interval, and the base URL used to build the distribution-point
	// URLs stamped into issued certificates and CRL extensions.
	CRL CRLConfig `yaml:"crl"`
	// SPIFFE configures SPIFFE X.509-SVID workload-identity issuance: the
	// trust-domain allowlist enforced before an SVID is minted, the issuance
	// profile and default CA, aggressive short-TTL auto-renewal, and the trust
	// bundle's refresh hint. Disabled unless spiffe.enabled is true.
	SPIFFE SPIFFEConfig `yaml:"spiffe"`
	// Tracing configures OpenTelemetry (OTLP) distributed tracing, complementing
	// the Prometheus metrics and structured request log. Disabled unless
	// tracing.enabled is true; when disabled a no-op tracer is installed and the
	// instrumentation throughout the codebase costs effectively nothing.
	Tracing TracingConfig `yaml:"tracing"`
	// Attestation configures hardware key-attestation verification on the
	// device-enrollment paths (EST/SCEP/ACME). It supplies the trusted
	// manufacturer roots and a default enforcement mode; profiles opt into a
	// stricter/looser mode via their `attestation` block. Inert unless a profile
	// (or the default) sets a non-"off" mode.
	Attestation AttestationConfig `yaml:"attestation"`
	// Auth configures strong operator authentication for the console/API (Task
	// 50): interactive OIDC/OAuth2 login with claim/group -> RBAC role mapping,
	// mutual-TLS client-certificate binding for machine callers, WebAuthn/passkey
	// step-up for high-risk operations, and the session/CSRF plumbing that ties
	// them together. Each sub-feature is inert unless its `enabled` is set; the
	// stateless basic-auth root and Bearer-token paths keep working regardless.
	Auth AuthConfig `yaml:"auth"`
	// Discovery configures the external certificate discovery scanner (Task 54):
	// the endpoints to probe, the "expiring soon" window, and whether results are
	// stored to the inventory and alerted through the expiry-monitor sinks. Inert
	// unless discovery.enabled is set; the `secsy-ca discover` CLI works regardless.
	Discovery DiscoveryConfig `yaml:"discovery"`
	// GRPC configures the gRPC API surface (Task 56), which exposes the core
	// issuance/revocation/status operations alongside the REST API. Disabled
	// unless grpc.enabled is true. It reuses the server's TLS certificate and, when
	// mTLS operator-auth is configured, the same client-CA pool.
	GRPC GRPCConfig `yaml:"grpc"`
	// SSH configures the HSM-backed SSH certificate authority (Task 57): custom
	// signing profiles layered over the built-in user-default/host-default
	// profiles, and the comment stamped into generated KRLs. The /api/ssh
	// endpoints and `secsy-ca ssh` commands work with the built-ins regardless.
	SSH SSHCAConfig `yaml:"ssh"`
	// Publish configures the static revocation-artifact publisher (Task 58):
	// CRLs, delta CRLs, partition shards, issuer chains, and pre-signed OCSP
	// responses written to a local directory or S3-compatible object store in a
	// layout a CDN can front. Disabled unless publish.enabled is true; the
	// `secsy-ca publish` command works from this block regardless.
	Publish PublishConfig `yaml:"publish"`
	// Security holds deployment-wide cryptographic policy switches, notably the
	// fail-closed FIPS 140-3 algorithm policy (security.fips). See SecurityConfig
	// and docs/fips.md.
	Security SecurityConfig `yaml:"security"`
	// Coordination configures multi-replica leader election (Task 68): with a
	// shared PostgreSQL store, exactly one replica at a time runs the singleton
	// background jobs (expiry monitor/auto-renewal, CA auto-rotation, OCSP
	// pre-signing, CRL regeneration/publishing, audit anchoring, SIEM export,
	// discovery scans). The zero value is mode "auto", which elects via a
	// PostgreSQL advisory lock when database.driver is postgres and holds
	// leadership statically on single-node SQLite — so replicas>1 needs no
	// explicit configuration beyond the shared database. See
	// docs/high-availability.md.
	Coordination CoordinationConfig `yaml:"coordination"`
}

// CoordinationConfig tunes the background-job leader election. All fields are
// optional; the defaults elect correctly for the configured database driver.
type CoordinationConfig struct {
	// Mode selects the election backend: "auto" (default — advisory-lock
	// election on postgres, static single-node leadership on sqlite),
	// "postgres" (require advisory-lock election; rejected on sqlite), or
	// "static" (this replica always runs the jobs; only safe with exactly one
	// replica).
	Mode string `yaml:"mode"`
	// LockName namespaces the advisory lock (hashed to the 64-bit key). Give
	// each deployment sharing a PostgreSQL database its own name; renaming it
	// during a rolling update briefly allows two leaders (old and new name), so
	// keep it stable. Default "secsy-pki/background-jobs".
	LockName string `yaml:"lock_name"`
	// RenewIntervalSeconds is how often the leader re-confirms its lease (and
	// steps down when it cannot). Default 5.
	RenewIntervalSeconds int `yaml:"renew_interval_seconds"`
	// RetryIntervalSeconds is how often a follower retries acquisition, which
	// bounds failover latency after the old leader's session ends. Default 5.
	RetryIntervalSeconds int `yaml:"retry_interval_seconds"`
}

// SecurityConfig holds deployment-wide cryptographic policy switches.
type SecurityConfig struct {
	// FIPS enables the fail-closed FIPS 140-3 crypto policy: configuration
	// referencing non-approved algorithms (SHA-1, Ed25519, RSA<2048, ML-DSA)
	// fails at load, key generation and certificate issuance reject
	// non-approved key types and keys, and the secret envelope layer refuses
	// the SoftHSM RSA-OAEP SHA-1 fallback. This is secsy-pki's algorithm
	// policy; running on the validated Go Cryptographic Module additionally
	// requires the FIPS build (`make build-fips`, GOFIPS140). `secsy-ca doctor`
	// reports both halves. See docs/fips.md.
	FIPS bool `yaml:"fips"`
}

// PublishConfig configures static artifact publishing for CDN offload.
type PublishConfig struct {
	// Enabled starts the background publish loop in the server.
	Enabled bool `yaml:"enabled"`
	// IntervalMinutes is how often the server republishes (default: the OCSP
	// presign refresh interval when pre-signing is enabled, else 60).
	IntervalMinutes int `yaml:"interval_minutes"`
	// CAs restricts publishing to these CA ids or labels; empty publishes every
	// unexpired X.509 CA.
	CAs []string `yaml:"cas"`
	// IncludeOCSP publishes the pre-signed OCSP responses alongside the CRLs
	// and chains. Nil defaults to enabled.
	IncludeOCSP *bool `yaml:"include_ocsp"`
	// Dir configures the local-directory backend. Used when s3.bucket is unset.
	Dir PublishDirConfig `yaml:"dir"`
	// S3 configures the S3-compatible backend; setting s3.bucket selects it.
	S3 PublishS3Config `yaml:"s3"`
}

// PublishDirConfig configures the local-directory publish backend.
type PublishDirConfig struct {
	// Path is the publish root. Artifacts are served from <path>/current, a
	// symlink flipped atomically over versioned snapshot directories.
	Path string `yaml:"path"`
	// KeepSnapshots is how many snapshots to retain (default 3).
	KeepSnapshots int `yaml:"keep_snapshots"`
}

// PublishS3Config configures the S3-compatible publish backend.
type PublishS3Config struct {
	// Endpoint is the base URL of an S3-compatible service (e.g.
	// http://minio:9000). Empty targets AWS S3 in Region.
	Endpoint string `yaml:"endpoint"`
	// Region is the SigV4 signing region (default us-east-1).
	Region string `yaml:"region"`
	// Bucket is the destination bucket; setting it selects the S3 backend.
	Bucket string `yaml:"bucket"`
	// Prefix is prepended to every object key.
	Prefix string `yaml:"prefix"`
	// AccessKeyID / SecretAccessKey / SessionToken are static credentials. When
	// access_key_id is empty the default AWS credential chain applies
	// (environment, shared config, IAM role).
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
	// ForcePathStyle addresses the bucket in the URL path. Applied
	// automatically when endpoint is set.
	ForcePathStyle bool `yaml:"force_path_style"`
	// Concurrency bounds parallel artifact uploads (default 8).
	Concurrency int `yaml:"concurrency"`
}

// Backend reports which publish backend the configuration selects.
func (c PublishConfig) Backend() string {
	if c.S3.Bucket != "" {
		return "s3"
	}
	return "dir"
}

// IncludeOCSPEnabled reports whether pre-signed OCSP responses are published.
func (c PublishConfig) IncludeOCSPEnabled() bool {
	return c.IncludeOCSP == nil || *c.IncludeOCSP
}

// Interval returns the effective publish interval given the presign settings.
func (c PublishConfig) Interval(presign OCSPPresignConfig) time.Duration {
	if c.IntervalMinutes > 0 {
		return time.Duration(c.IntervalMinutes) * time.Minute
	}
	if presign.Enabled {
		return presign.Refresh()
	}
	return time.Hour
}

// SSHCAConfig configures the SSH certificate authority (Task 57).
type SSHCAConfig struct {
	// KRLComment is an optional human-readable note stamped into the header of
	// every generated Key Revocation List.
	KRLComment string `yaml:"krl_comment"`
	// Profiles defines custom SSH signing profiles, overlaid by name over the
	// built-in user-default and host-default profiles.
	Profiles []SSHProfileConfig `yaml:"profiles"`
}

// SSHProfileConfig is one operator-defined SSH signing profile. Validity fields
// accept a Go duration ("12h") or a day/week suffix ("30d", "12w").
type SSHProfileConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// CertType is "user" or "host".
	CertType string `yaml:"cert_type"`
	// DefaultValidity applies when a request names none; MaxValidity clamps
	// longer requests.
	DefaultValidity string `yaml:"default_validity"`
	MaxValidity     string `yaml:"max_validity"`
	// AllowedPrincipals restricts principals to these glob patterns (empty =
	// any); AllowEmptyPrincipals permits certificates naming no principal at
	// all (valid for EVERY user/host — off by default for a reason).
	AllowedPrincipals    []string `yaml:"allowed_principals"`
	AllowEmptyPrincipals bool     `yaml:"allow_empty_principals"`
	MaxPrincipals        int      `yaml:"max_principals"`
	// DefaultExtensions/DefaultCriticalOptions apply when a request supplies
	// none; Allowed* additionally permit request-supplied keys. Host profiles
	// must leave all four empty.
	DefaultExtensions      map[string]string `yaml:"default_extensions"`
	AllowedExtensions      []string          `yaml:"allowed_extensions"`
	DefaultCriticalOptions map[string]string `yaml:"default_critical_options"`
	AllowedCriticalOptions []string          `yaml:"allowed_critical_options"`
}

// GRPCConfig configures the gRPC listener (Task 56). When enabled, the server
// exposes PKIService (issue/renew/revoke/status + CRL/OCSP metadata) over gRPC
// on a dedicated port, enforcing the same operator authentication, RBAC, tenant
// scoping, and audit as the REST API. Server reflection and a gRPC health
// service are always registered when enabled.
type GRPCConfig struct {
	Enabled bool `yaml:"enabled"`
	// Address is the listen address (host:port). Defaults to ":9443" when unset.
	// The server binds a separate port from the REST/HTTP listener.
	Address string `yaml:"address"`
	// TLSCert / TLSKey override the certificate served on the gRPC listener. When
	// empty they fall back to the server.tls_cert / server.tls_key used by the
	// REST listener, so a single certificate covers both protocols.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// MTLS requests a client certificate on the gRPC listener and binds a
	// presented, trusted certificate to an operator principal, exactly as the REST
	// listener does. It requires auth.mtls to be configured (that supplies the
	// client-CA pool and the cert->principal bindings). A presented cert is
	// verified-if-given, so Bearer/Basic callers still connect.
	MTLS bool `yaml:"mtls"`
}

// GRPCAddress returns the configured gRPC listen address, defaulting to ":9443".
func (c GRPCConfig) GRPCAddress() string {
	if c.Address == "" {
		return ":9443"
	}
	return c.Address
}

// DiscoveryConfig configures the external certificate discovery scanner. When
// enabled, a background scan periodically probes the configured TLS endpoints,
// records the served leaf certificates (with their security flags) to the
// inventory, and dispatches expiring/weak/rogue findings through the same
// notification sinks as the expiry monitor (monitor.notifications).
type DiscoveryConfig struct {
	Enabled bool `yaml:"enabled"`
	// IntervalHours is how often the background scan runs (default 24 when unset).
	IntervalHours int `yaml:"interval_hours"`
	// ExpiryDays is the "expiring soon" window in days (default 30 when unset).
	ExpiryDays int `yaml:"expiry_days"`
	// Targets are literal "host[:port][#sni]" endpoints to scan.
	Targets []string `yaml:"targets"`
	// HostsFile is an optional file of endpoints, one per line ('#' comments).
	HostsFile string `yaml:"hosts_file"`
	// CIDRs are optional network ranges; each host address becomes a target on the
	// default port.
	CIDRs []string `yaml:"cidrs"`
	// DefaultPort is applied to targets without an explicit port (default 443).
	DefaultPort int `yaml:"default_port"`
	// DialTimeoutSeconds bounds each endpoint's TCP+TLS handshake (default 8).
	DialTimeoutSeconds int `yaml:"dial_timeout_seconds"`
	// Concurrency bounds parallel endpoint dials (default 16).
	Concurrency int `yaml:"concurrency"`
	// Store persists findings to the discovered-certificates inventory.
	Store bool `yaml:"store"`
	// Notify dispatches flagged findings through the monitor.notifications sinks.
	Notify bool `yaml:"notify"`
}

// AuthConfig is the top-level operator-authentication block (Task 50).
type AuthConfig struct {
	// Session configures the console session cookie and lifetimes.
	Session SessionConfig `yaml:"session"`
	// OIDC configures interactive Authorization-Code login for the console. When
	// its fields are empty the login endpoints fall back to the top-level `oidc`
	// block's issuer/client for token verification (Bearer only), but interactive
	// login requires at least a redirect_url here.
	OIDC AuthOIDCConfig `yaml:"oidc"`
	// MTLS configures mutual-TLS client-certificate authentication.
	MTLS MTLSConfig `yaml:"mtls"`
	// WebAuthn configures passkey step-up for high-risk operations.
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
}

// SessionConfig configures console sessions.
type SessionConfig struct {
	// CookieName overrides the session cookie name (default "secsy_session").
	CookieName string `yaml:"cookie_name"`
	// TTLMinutes bounds a session's absolute lifetime (default 60).
	TTLMinutes int `yaml:"ttl_minutes"`
	// Insecure drops the Secure attribute on issued cookies. It exists only for
	// local/plaintext testing; production must leave it false so cookies are
	// HTTPS-only.
	Insecure bool `yaml:"insecure"`
}

// AuthOIDCConfig configures interactive OIDC login and the claim -> role mapping.
type AuthOIDCConfig struct {
	// Enabled turns on the interactive login endpoints (/auth/login, /auth/callback).
	Enabled bool `yaml:"enabled"`
	// IssuerURL / ClientID identify the IdP and client. When empty they inherit
	// the top-level `oidc` block, so a single IdP can serve both Bearer
	// verification and interactive login.
	IssuerURL string `yaml:"issuer_url"`
	ClientID  string `yaml:"client_id"`
	// ClientSecret authenticates a confidential client at the token endpoint. Omit
	// for a public (PKCE-only) client.
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL is this server's callback URL registered at the IdP, e.g.
	// https://pki.example.com/auth/callback. Required for interactive login.
	RedirectURL string `yaml:"redirect_url"`
	// Scopes requested at authorization (default openid, profile, email). Add the
	// IdP's groups scope here when using group-claim role mapping.
	Scopes []string `yaml:"scopes"`
	// GroupsClaim names the token claim carrying group memberships (default
	// "groups"). Its values feed both the rbac group assignments and the mappings
	// below.
	GroupsClaim string `yaml:"groups_claim"`
	// RoleMappings map IdP claim values to RBAC roles, optionally scoped to a
	// tenant. They compose with the top-level rbac subject/email/group assignments.
	RoleMappings []ClaimMappingConfig `yaml:"role_mappings"`
	// AllowZeroRole permits a successful login even when the operator resolves to
	// no RBAC role (a read-nothing principal). Defaults to false: an operator with
	// no role is denied at login rather than landing in an empty console.
	AllowZeroRole bool `yaml:"allow_zero_role"`
}

// ClaimMappingConfig maps one IdP claim value to RBAC roles.
type ClaimMappingConfig struct {
	// Claim is the token claim to inspect (default: the groups claim).
	Claim string `yaml:"claim"`
	// Value is the exact claim value that triggers the mapping.
	Value string `yaml:"value"`
	// Tenant scopes the granted roles to a tenant id; empty grants platform-wide.
	Tenant string `yaml:"tenant"`
	// Roles are the RBAC roles granted (admin|issuer|signer|auditor).
	Roles []string `yaml:"roles"`
}

// MTLSConfig configures mutual-TLS client-certificate authentication.
type MTLSConfig struct {
	// Enabled requests a client certificate in the TLS handshake and verifies it
	// against CAFile. A caller presenting a bound certificate is authenticated;
	// callers without one fall back to the other mechanisms.
	Enabled bool `yaml:"enabled"`
	// CAFile is a PEM bundle of the client-certificate CA(s) trusted to
	// authenticate machine callers. Required when enabled.
	CAFile string `yaml:"ca_file"`
	// Bindings map a verified client certificate to a principal and roles.
	Bindings []CertBindingConfig `yaml:"bindings"`
}

// CertBindingConfig binds a client certificate (matched by subject/SAN) to a
// principal.
type CertBindingConfig struct {
	// Selectors — every non-empty one must match the presented certificate.
	SubjectCN string `yaml:"subject_cn"`
	SubjectDN string `yaml:"subject_dn"`
	SANDNS    string `yaml:"san_dns"`
	SANURI    string `yaml:"san_uri"`
	SANEmail  string `yaml:"san_email"`
	// Principal — Subject is the identity recorded in audit; Roles are platform
	// roles; TenantRoles are tenant-scoped roles.
	Subject     string              `yaml:"subject"`
	Name        string              `yaml:"name"`
	Roles       []string            `yaml:"roles"`
	TenantRoles map[string][]string `yaml:"tenant_roles"`
}

// WebAuthnConfig configures passkey step-up.
type WebAuthnConfig struct {
	// Enabled turns on the WebAuthn registration and step-up endpoints and the
	// step-up gate on high-risk operations.
	Enabled bool `yaml:"enabled"`
	// RPID is the WebAuthn Relying Party ID: the console's registrable domain
	// (e.g. "pki.example.com"). Required when enabled.
	RPID string `yaml:"rp_id"`
	// RPName is the display name shown by the authenticator (default "Secsy PKI").
	RPName string `yaml:"rp_name"`
	// Origins are the acceptable browser origins (e.g. https://pki.example.com).
	// At least one is required when enabled.
	Origins []string `yaml:"origins"`
	// StepUpTTLMinutes is how long a step-up remains valid within a session
	// (default 5).
	StepUpTTLMinutes int `yaml:"step_up_ttl_minutes"`
	// StepUpOperations names the high-risk operations gated behind step-up.
	// Recognized: cert.revoke, ca.manage, ca.init_root, ca.issue_intermediate,
	// ca.cross_sign, hsm.factory_reset. Empty applies a safe default set.
	StepUpOperations []string `yaml:"step_up_operations"`
}

// AttestationConfig holds the deployment-wide settings for enrollment
// key-attestation verification (Task 49). Enforcement is turned on per issuance
// profile (ProfileAttestationConfig) or via DefaultMode; this block supplies the
// trusted manufacturer roots every attestation certificate chain must terminate
// at (YubiKey PIV roots, TPM manufacturer roots, Apple attestation roots).
type AttestationConfig struct {
	// DefaultMode is the attestation mode applied to any issuance profile that
	// does not set its own `attestation.mode`: "off" (default), "permissive", or
	// "require". A profile-level mode overrides this.
	DefaultMode string `yaml:"default_mode"`
	// TrustedRootFiles are paths to PEM files, each holding one or more trusted
	// manufacturer root (or intermediate) certificates. Roots and intermediates
	// may be mixed; self-signed certificates are treated as roots and the rest as
	// intermediates for chain building.
	TrustedRootFiles []string `yaml:"trusted_root_files"`
	// TrustedRootsPEM is inline PEM carrying trusted manufacturer certificates, an
	// alternative (or supplement) to TrustedRootFiles.
	TrustedRootsPEM string `yaml:"trusted_roots_pem"`
}

// ProfileAttestationConfig is a profile's enrollment key-attestation policy.
// When the effective mode is "require", an enrollment under the profile is
// rejected fail-closed unless it presents a valid hardware attestation bound to
// the enrolled key; under "permissive" the attestation is evaluated and audited
// but never blocks; "off" disables the gate for the profile.
type ProfileAttestationConfig struct {
	// Mode is "off" (inherit nothing / disabled), "permissive", or "require".
	// Empty falls back to the global attestation.default_mode.
	Mode string `yaml:"mode"`
}

// TracingConfig configures OpenTelemetry distributed tracing over the OTLP
// exporter. It maps onto tracing.Config in the internal/tracing package. Tracing
// is off by default: with Enabled=false the server installs a no-op tracer and
// starts no exporter.
type TracingConfig struct {
	// Enabled turns tracing on. Required to be true for any span to be exported.
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP collector endpoint in host:port form (no scheme), e.g.
	// "otel-collector:4317" for gRPC or "otel-collector:4318" for HTTP. Required
	// when enabled.
	Endpoint string `yaml:"endpoint"`
	// Protocol selects the OTLP transport: "grpc" (default) or "http".
	Protocol string `yaml:"protocol"`
	// Insecure disables transport TLS to the collector (plaintext gRPC / http://),
	// for an in-cluster collector reached over a trusted network.
	Insecure bool `yaml:"insecure"`
	// SampleRatio is the head-based, parent-respecting sample probability in
	// [0,1]. 0 (or unset) with tracing enabled samples everything; dial it down in
	// production. A sampled parent trace is always continued regardless.
	SampleRatio float64 `yaml:"sample_ratio"`
	// ServiceName is the service.name resource attribute (default "secsy-pki").
	ServiceName string `yaml:"service_name"`
	// ServiceVersion is the optional service.version resource attribute.
	ServiceVersion string `yaml:"service_version"`
	// Headers are optional static headers sent to the collector (e.g. an auth
	// token for a managed OTLP endpoint).
	Headers map[string]string `yaml:"headers"`
	// TimeoutSeconds bounds a single export attempt (default 10s). Non-positive
	// uses the default.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// SPIFFEConfig configures SPIFFE X.509-SVID issuance and the trust-bundle
// endpoint. When enabled, the /api/ca/{id}/svid endpoint mints short-lived
// X.509-SVIDs whose sole identity is a spiffe:// URI SAN, restricted to the
// configured trust-domain allowlist, and /api/ca/{id}/svid/bundle serves the
// trust domain's CA authorities as a JWKS-style SPIFFE trust bundle.
type SPIFFEConfig struct {
	// Enabled turns on the SVID endpoints and their monitor auto-renewal wiring.
	Enabled bool `yaml:"enabled"`
	// TrustDomains is the global allowlist of trust domains an authorized issuer
	// may mint SVIDs for. An SVID whose trust domain is not listed here (nor
	// granted to the requester via SubjectTrustDomains) is refused. Empty with no
	// per-subject grants means no SVID may be issued (fail-closed).
	TrustDomains []string `yaml:"trust_domains"`
	// SubjectTrustDomains grants additional trust domains to specific authenticated
	// subjects (OIDC subject or verified email), beyond the global allowlist.
	SubjectTrustDomains map[string][]string `yaml:"subject_trust_domains"`
	// Profile is the issuance profile used for SVIDs. Defaults to the built-in
	// "spiffe-svid". A custom profile may override validity/EKUs but must remain a
	// short-lived leaf profile (CA:false, digitalSignature) or the lint gate
	// rejects it.
	Profile string `yaml:"profile"`
	// DefaultCAID is the CA used when an SVID request or bundle fetch omits one.
	DefaultCAID string `yaml:"default_ca_id"`
	// RefreshHintSeconds is advertised in the trust bundle (spiffe_refresh_hint)
	// so consumers know how often to re-fetch it. Defaults to 300s when unset.
	RefreshHintSeconds int `yaml:"refresh_hint_seconds"`
	// RenewFraction is the fraction of an SVID's lifetime that must remain for the
	// expiry monitor to still consider it fresh; at or below it the SVID is
	// auto-renewed. Defaults to 0.5 (renew at the halfway point). Ignored unless
	// monitor.auto_renew is on.
	RenewFraction float64 `yaml:"renew_fraction"`
}

// SVIDProfileName returns the effective SVID issuance profile name.
func (c SPIFFEConfig) SVIDProfileName() string {
	if strings.TrimSpace(c.Profile) != "" {
		return c.Profile
	}
	return "spiffe-svid"
}

// RefreshHint returns the configured bundle refresh hint as a duration,
// defaulting to 5 minutes when unset.
func (c SPIFFEConfig) RefreshHint() time.Duration {
	if c.RefreshHintSeconds > 0 {
		return time.Duration(c.RefreshHintSeconds) * time.Second
	}
	return 5 * time.Minute
}

// CRLConfig configures delta CRL generation and CRL partitioning/sharding (RFC
// 5280). Zero-valued fields fall back to safe defaults: unsharded (a single
// complete CRL), a 7-day base validity, and a 1-hour delta validity — matching
// the pre-Task-36 behavior.
type CRLConfig struct {
	// Shards is the number of CRL partitions. 0 or 1 keeps a single complete CRL;
	// N >= 2 deterministically splits revocations across N shard CRLs (by hashing
	// the certificate serial) and stamps each issued certificate with the
	// CRLDistributionPoints URL of its shard.
	Shards int `yaml:"shards"`
	// BaseURL is the externally reachable origin (e.g. https://pki.example.com)
	// used to build absolute CRLDistributionPoints / IssuingDistributionPoint /
	// Freshest CRL URLs. When empty it falls back to acme.base_url; if neither is
	// set, certificates carry no CDP and CRLs carry no distribution-point
	// extensions (numbering and delta reconstruction still work).
	BaseURL string `yaml:"base_url"`
	// DeltaIntervalMinutes bounds how long a delta CRL is served before a fresh
	// one is signed (its NextUpdate window). Defaults to 60. Non-positive uses the
	// default.
	DeltaIntervalMinutes int `yaml:"delta_interval_minutes"`
	// BaseValidityHours bounds a base CRL's validity window. Defaults to 168 (7
	// days). Non-positive uses the default.
	BaseValidityHours int `yaml:"base_validity_hours"`
}

// CAAGlobalConfig holds the deployment-wide settings for the CAA pre-issuance
// gate. Enforcement is turned on per issuance profile (ProfileCAAConfig); this
// block supplies the shared CA identifier a profile inherits and the cache TTL.
type CAAGlobalConfig struct {
	// Identifier is this CA's CAA domain identifier — the value a domain owner
	// publishes in an `issue "ca.example.com"` record to authorize this CA to
	// issue for their names (RFC 8659 §4.2). It is the default for every profile
	// whose caa block does not set its own identifier; required for any profile
	// running in enforce mode.
	Identifier string `yaml:"identifier"`
	// CacheTTLSeconds bounds how long a resolved CAA/CNAME answer is reused across
	// requests. Zero uses the package default (5 minutes).
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
}

// CTConfig registers the Certificate Transparency logs that issuance profiles
// may submit precertificates to.
type CTConfig struct {
	// Logs is the set of known CT logs, keyed by name.
	Logs []CTLogConfig `yaml:"logs"`
}

// CTLogConfig configures a single CT log endpoint.
type CTLogConfig struct {
	// Name is the identifier profiles reference and audit records display.
	Name string `yaml:"name"`
	// URL is the log's base URL; the RFC 6962 add-pre-chain path is appended.
	URL string `yaml:"url"`
	// PublicKey is the log's public key as a PEM SubjectPublicKeyInfo block. When
	// set, returned SCT signatures are cryptographically verified against it (and
	// the SCT's log id must match). PublicKeyFile is an alternative source.
	PublicKey     string `yaml:"public_key"`
	PublicKeyFile string `yaml:"public_key_file"`
}

// ProfileCTConfig is a profile's per-issuance Certificate Transparency policy.
type ProfileCTConfig struct {
	Enabled bool `yaml:"enabled"`
	// Logs names the registered logs to submit to (empty = all registered logs).
	Logs []string `yaml:"logs"`
	// MinSCTs is the minimum SCT count the policy requires (0 defaults to 1).
	MinSCTs int `yaml:"min_scts"`
	// FailOpen selects fail-open (issue anyway) vs fail-closed (default: reject).
	FailOpen bool `yaml:"fail_open"`
	// TimeoutSeconds bounds each individual log attempt (0 uses a default).
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// Retries is the number of extra attempts per log after the first.
	Retries int `yaml:"retries"`
}

// RateLimitConfig configures abuse protection for the public-facing endpoints.
// When enabled, a token-bucket limiter meters requests across three independent
// tiers (global, per-IP, per-account) and a concurrency guard bounds how many
// signing/enrollment requests may hit the HSM session pool at once. Tiers with
// a non-positive rate or burst are inert.
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	// Global caps the aggregate request rate across all clients. PerIP and
	// PerAccount cap a single source IP and a single authenticated account
	// (ACME account, EST user) respectively.
	Global     RateConfig `yaml:"global"`
	PerIP      RateConfig `yaml:"per_ip"`
	PerAccount RateConfig `yaml:"per_account"`
	// PerTenant caps a single tenant's aggregate request rate across its public
	// enrollment endpoints (ACME/EST/SCEP/CMP), keyed by the tenant that owns
	// the protocol instance's CA (Task 61). This is the deployment-wide default;
	// a tenant's own rate_limit_per_second/rate_limit_burst quota fields
	// override it per tenant. OCSP/CRL are never metered per tenant, so relying
	// parties can always check revocation status.
	PerTenant RateConfig `yaml:"per_tenant"`
	// MaxKeys bounds the number of distinct per-IP / per-account buckets held in
	// memory before idle eviction. Defaults to 100000.
	MaxKeys int `yaml:"max_keys"`
	// IdleTTLSeconds is how long a fully-replenished bucket may sit unused before
	// eviction. Defaults to 600.
	IdleTTLSeconds int `yaml:"idle_ttl_seconds"`
	// Concurrency configures the in-flight guard in front of the HSM.
	Concurrency ConcurrencyConfig `yaml:"concurrency"`
}

// RateConfig is a single token-bucket tier: a sustained rate in requests per
// second and a burst (bucket capacity). A non-positive Rate disables the tier.
type RateConfig struct {
	Rate  float64 `yaml:"rate"`
	Burst float64 `yaml:"burst"`
}

// ConcurrencyConfig configures the bounded in-flight guard that caps how many
// HSM-bound (signing/enrollment) requests run concurrently against the PKCS#11
// session pool, shedding excess load fast under overload.
type ConcurrencyConfig struct {
	// Enabled turns the guard on. When rate_limit.enabled is true it defaults to
	// on; set to false to disable the guard while keeping rate limiting.
	Enabled *bool `yaml:"enabled"`
	// MaxInFlight is the concurrent HSM-bound request ceiling. When <= 0 it is
	// derived from the PKCS#11 session pool size (pkcs11.session_pool_size), so
	// the guard tracks the backend it protects.
	MaxInFlight int `yaml:"max_in_flight"`
	// MaxQueue bounds how many requests may wait for a slot before excess is
	// shed with 503. Defaults to 64.
	MaxQueue int `yaml:"max_queue"`
	// AcquireTimeoutMs bounds how long a queued request waits for a slot.
	// Defaults to 5000. Zero means wait until the request context is canceled.
	AcquireTimeoutMs int `yaml:"acquire_timeout_ms"`
}

// GuardEnabled reports whether the concurrency guard should run given the parent
// rate-limit enablement. It defaults to on when rate limiting is enabled.
func (c ConcurrencyConfig) GuardEnabled(parentEnabled bool) bool {
	if c.Enabled != nil {
		return *c.Enabled
	}
	return parentEnabled
}

// AuditConfig groups audit-log settings: the SIEM export pipeline and the
// audit-chain anchoring job.
type AuditConfig struct {
	Export ExportConfig `yaml:"export"`
	Anchor AnchorConfig `yaml:"anchor"`
}

// AnchorConfig configures periodic anchoring of the audit hash-chain head
// (Task 64). When enabled, a background job takes the event log's newest
// (seq, hash), obtains an RFC 3161 timestamp token over their canonical digest,
// and persists it in audit_anchors — making whole-chain truncation or rewrite
// after each anchor point detectable by `secsy-ca audit verify`.
type AnchorConfig struct {
	Enabled bool `yaml:"enabled"`
	// IntervalHours is the anchor cadence. Defaults to 24 when unset. Each
	// interval bounds the window of newest events an undetected truncation
	// could cover.
	IntervalHours int `yaml:"interval_hours"`
	// TSAURL, when set, obtains tokens from an external RFC 3161 TSA at this
	// http(s) URL instead of the in-process one — for deployments that want the
	// anchor authority independent of the PKI being anchored (an attacker who
	// owns this host and its HSM could otherwise re-anchor a rewritten log).
	// Empty uses the internal TSA, which then must be enabled (tsa.enabled).
	TSAURL string `yaml:"tsa_url"`
	// TimeoutSeconds bounds each external TSA request. Defaults to 30.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// ExportConfig configures the audit-log SIEM exporter. When enabled, a
// background worker per sink streams sealed audit events forward from a durable
// per-sink cursor with at-least-once delivery and bounded backpressure.
type ExportConfig struct {
	Enabled bool `yaml:"enabled"`
	// PollIntervalSeconds is how often a caught-up worker re-checks for new
	// events. Defaults to 5 when unset.
	PollIntervalSeconds int `yaml:"poll_interval_seconds"`
	// BatchSize bounds how many events each worker reads and delivers per
	// iteration — the primary backpressure knob. Defaults to 256 when unset.
	BatchSize int `yaml:"batch_size"`
	// RetryBackoffSeconds is the initial retry delay after a failed delivery; it
	// doubles up to MaxBackoffSeconds. Defaults to 1 / 30.
	RetryBackoffSeconds int `yaml:"retry_backoff_seconds"`
	MaxBackoffSeconds   int `yaml:"max_backoff_seconds"`
	// Sinks lists the export destinations. Each has its own cursor.
	Sinks []ExportSinkConfig `yaml:"sinks"`
}

// ExportSinkConfig configures a single SIEM export sink.
type ExportSinkConfig struct {
	// Name uniquely identifies the sink; it keys the durable cursor and metrics,
	// so it must be stable across restarts and unique among configured sinks.
	Name string `yaml:"name"`
	// Type is "syslog" or "webhook".
	Type string `yaml:"type"`
	// Format is "rfc5424", "cef", or "json". Defaults to rfc5424 for syslog and
	// json for webhook.
	Format string `yaml:"format"`
	// TimeoutSeconds bounds each delivery attempt. Defaults per sink type.
	TimeoutSeconds int `yaml:"timeout_seconds"`

	// Syslog transport (type == "syslog").
	Network string              `yaml:"network"` // "tcp" or "tls"
	Address string              `yaml:"address"` // host:port
	Framing string              `yaml:"framing"` // "octet-counting" (default) or "lf"
	TLS     ExportSinkTLSConfig `yaml:"tls"`

	// Webhook transport (type == "webhook").
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`

	// Formatter metadata (optional overrides).
	Hostname     string `yaml:"hostname"`
	AppName      string `yaml:"app_name"`
	EnterpriseID string `yaml:"enterprise_id"`
	Facility     int    `yaml:"facility"`
	CEFVendor    string `yaml:"cef_vendor"`
	CEFProduct   string `yaml:"cef_product"`
	CEFVersion   string `yaml:"cef_version"`
}

// ExportSinkTLSConfig configures TLS for a syslog sink.
type ExportSinkTLSConfig struct {
	CAFile             string `yaml:"ca_file"`
	ServerName         string `yaml:"server_name"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// MonitorConfig configures the certificate-expiry monitor. When enabled, a
// background goroutine periodically scans issued certificates, reports upcoming
// expirations through the configured notification sinks, and (optionally)
// auto-renews eligible leaf certificates ahead of expiry through the same
// HSM-backed issuance path used by the API and CLI.
type MonitorConfig struct {
	Enabled bool `yaml:"enabled"`
	// IntervalHours is how often the background scan runs. Defaults to 12 hours
	// when unset. Ignored for one-shot CLI/API scans.
	IntervalHours int `yaml:"interval_hours"`
	// WarningDays / CriticalDays classify a certificate's remaining validity.
	// A cert with <= CriticalDays left is "critical"; <= WarningDays is
	// "warning". Defaults: warning=30, critical=7. CriticalDays must be <=
	// WarningDays.
	WarningDays  int `yaml:"warning_days"`
	CriticalDays int `yaml:"critical_days"`
	// AutoRenew enables reissuing eligible leaf certificates before expiry.
	AutoRenew bool `yaml:"auto_renew"`
	// RenewBeforeDays is the remaining-validity threshold at or below which an
	// eligible certificate is auto-renewed. Defaults to CriticalDays when unset.
	RenewBeforeDays int `yaml:"renew_before_days"`
	// RenewProfiles optionally restricts auto-renewal to certificates issued
	// under these profile names. Empty means every profile is eligible.
	RenewProfiles []string `yaml:"renew_profiles"`
	// RotateIntermediates enables automatic HSM-backed key rotation of
	// intermediate CAs whose own certificate is nearing expiry. When enabled the
	// monitor generates a fresh keypair, cross-signs a new intermediate under the
	// parent, and enters a dual-chain overlap window (see the ca rotation
	// support). Retirement of the old key remains a manual, ceremony-style step.
	RotateIntermediates bool `yaml:"rotate_intermediates"`
	// RotateBeforeDays is the remaining-validity threshold at or below which an
	// active intermediate CA is auto-rotated. Defaults to WarningDays when unset.
	RotateBeforeDays int `yaml:"rotate_before_days"`
	// SecretRenotifyHours is how long a still-due secret TTL/rotation reminder
	// (Task 73) stays quiet after a notification before it is re-sent
	// (severity escalations and value changes always break through).
	// Defaults to 24 hours.
	SecretRenotifyHours int `yaml:"secret_renotify_hours"`
	// Notifications lists the sinks expiry warnings are dispatched to.
	Notifications []NotificationConfig `yaml:"notifications"`
}

// CanaryConfig configures the synthetic issuance canary (internal/canary).
// Each interval, the canary issues a short-lived certificate from the canary
// profile under every listed CA, verifies the full chain, checks OCSP answers
// "good" and the CRL is fresh, revokes it, and confirms "revoked" propagates —
// timing every stage. Probe certificates are stamped with the canary marker so
// the expiry monitor and inventory reports ignore them.
type CanaryConfig struct {
	Enabled bool `yaml:"enabled"`
	// IntervalMinutes is how often each configured CA is probed. Defaults to 15
	// minutes when unset. Every probe costs a handful of HSM signing operations
	// (leaf + OCSP responses + possibly a CRL), so very short intervals add
	// measurable HSM load.
	IntervalMinutes int `yaml:"interval_minutes"`
	// CAs lists the CAs to probe, each by id or label. Required when enabled.
	// Probes follow key-rotation lineage, so listing a rotated CA keeps probing
	// its active successor.
	CAs []string `yaml:"cas"`
	// Profile is the certificate profile probe certs are issued under. Defaults
	// to the built-in "canary" profile (short-lived, non-public, lint enforced).
	// A custom profile must be classical (not pqc/hybrid): the prober generates
	// an ECDSA key per probe.
	Profile string `yaml:"profile"`
	// TimeoutSeconds bounds one CA's full probe (all stages). Defaults to 60.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// Interval returns the resolved probe interval.
func (c CanaryConfig) Interval() time.Duration {
	if c.IntervalMinutes <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.IntervalMinutes) * time.Minute
}

// Timeout returns the resolved per-CA probe timeout.
func (c CanaryConfig) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// NotificationConfig configures a single notification sink for expiry warnings.
type NotificationConfig struct {
	// Type selects the sink implementation: "log" or "webhook".
	Type string `yaml:"type"`
	// MinSeverity filters which certificates trigger a notification on this sink:
	// "warning" (default) sends warning + critical + expired; "critical" sends
	// only critical + expired; "expired" sends only already-expired certs.
	MinSeverity string `yaml:"min_severity"`
	// URL is the webhook endpoint (required for type=webhook).
	URL string `yaml:"url"`
	// Headers are extra HTTP headers sent with each webhook POST (e.g. an
	// Authorization token). Optional.
	Headers map[string]string `yaml:"headers"`
	// TimeoutSeconds bounds each webhook request. Defaults to 10 when unset.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// ACMEConfig configures the ACME (RFC 8555) server. When enabled, an ACME
// directory is exposed and clients can obtain HSM-backed certificates from the
// configured CA/profile through account/order/challenge/finalize flows.
type ACMEConfig struct {
	Enabled bool `yaml:"enabled"`
	// BaseURL is the externally reachable origin (e.g. https://pki.example.com).
	// Leave empty to derive it from each request (honoring X-Forwarded-Proto/Host).
	BaseURL string `yaml:"base_url"`
	// DirectoryPath is the URL prefix ACME endpoints mount under (default /acme).
	DirectoryPath string `yaml:"directory_path"`
	// CAID / CALabel select the issuing CA. Exactly one should be set; CAID wins.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// Profile is the certificate profile applied to ACME-issued certs (default
	// "server").
	Profile string `yaml:"profile"`
	// TermsOfService, if set, is advertised in the directory and required on
	// account creation.
	TermsOfService string `yaml:"terms_of_service"`
	// HTTP01Port overrides the http-01 validation port (default 80; tests only).
	HTTP01Port int `yaml:"http01_port"`
	// ChallengeTypes limits the offered challenge types (default http-01, dns-01).
	ChallengeTypes []string `yaml:"challenge_types"`
	// RequireEAB requires External Account Binding; EABHMACKeys maps kid -> key.
	RequireEAB  bool              `yaml:"require_eab"`
	EABHMACKeys map[string]string `yaml:"eab_hmac_keys"`
	// AllowIPIdentifiers permits ip-type identifiers (RFC 8738).
	AllowIPIdentifiers bool `yaml:"allow_ip_identifiers"`
	// OrderValidityHours / AuthzValidityHours bound how long orders and
	// authorizations remain pending (default 168h / 7 days).
	OrderValidityHours int `yaml:"order_validity_hours"`
	AuthzValidityHours int `yaml:"authz_validity_hours"`

	// ---- ACME Renewal Information (ARI, draft-ietf-acme-ari) ----
	// RenewalWindowDays sets how many days before expiry the ARI suggested renewal
	// window begins. Zero falls back to the monitor's renew-before threshold, then
	// to a third of each certificate's lifetime.
	RenewalWindowDays int `yaml:"renewal_window_days"`
	// RenewalWindowWidthHours is the width of the ARI suggested window. Zero
	// derives it as half of the renewal-window span.
	RenewalWindowWidthHours int `yaml:"renewal_window_width_hours"`
	// RenewalPollHours is advertised in the renewalInfo Retry-After header
	// (default 6h).
	RenewalPollHours int `yaml:"renewal_poll_hours"`
	// RenewalExplanationURL is returned in every renewalInfo response, pointing at
	// a page explaining an active mass-renewal event.
	RenewalExplanationURL string `yaml:"renewal_explanation_url"`
}

// SCEPConfig configures the SCEP (RFC 8894) enrollment server. When enabled, a
// SCEP endpoint is exposed for device/MDM auto-enrollment. The issuing CA MUST
// be an RSA CA (SCEP wraps the request in a PKCS#7 EnvelopedData that uses RSA
// key transport to the CA certificate).
type SCEPConfig struct {
	Enabled bool `yaml:"enabled"`
	// DirectoryPath is the URL prefix the SCEP endpoint mounts under (default
	// /scep).
	DirectoryPath string `yaml:"directory_path"`
	// CAID / CALabel select the issuing (RSA) CA. Exactly one should be set.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// Profile is the default certificate profile (default "client").
	Profile string `yaml:"profile"`
	// Grants are the challenge-password enrollment credentials. Each grant is an
	// operator-provisioned secret that authorizes enrollment under a profile.
	Grants []SCEPGrantConfig `yaml:"grants"`
	// RequireChallenge rejects an initial enrollment without a matching challenge
	// password (default true). Setting it false enables open enrollment.
	RequireChallenge *bool `yaml:"require_challenge"`
	// AllowRenewal permits challenge-free renewal by a client signing with a
	// currently-valid certificate this CA previously issued.
	AllowRenewal bool `yaml:"allow_renewal"`
}

// SCEPGrantConfig is one challenge-password enrollment credential.
type SCEPGrantConfig struct {
	Name      string `yaml:"name"`
	Challenge string `yaml:"challenge"`
	Profile   string `yaml:"profile"`
}

// RequireChallengeEnabled reports whether a challenge password is required for
// initial SCEP enrollment. It defaults to true.
func (s SCEPConfig) RequireChallengeEnabled() bool {
	return s.RequireChallenge == nil || *s.RequireChallenge
}

// ESTConfig configures the EST (RFC 7030) enrollment server. When enabled, EST
// endpoints are exposed under /.well-known/est for device/MDM auto-enrollment
// over TLS with HTTP Basic or TLS-client-certificate authentication.
type ESTConfig struct {
	Enabled bool `yaml:"enabled"`
	// BasePath is the URL prefix (default /.well-known/est).
	BasePath string `yaml:"base_path"`
	// CAID / CALabel select the issuing CA. Exactly one should be set.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// Profile is the default certificate profile (default "client").
	Profile string `yaml:"profile"`
	// Users maps a Basic-auth username to its enrollment credential.
	Users map[string]ESTUserConfig `yaml:"users"`
	// AllowTLSClientReenroll permits (re)enrollment authorized by a TLS client
	// certificate this CA previously issued (RFC 7030 §3.3.2).
	AllowTLSClientReenroll bool `yaml:"allow_tls_client_reenroll"`
	// EnableServerKeygen enables /serverkeygen server-side key generation.
	EnableServerKeygen bool `yaml:"enable_server_keygen"`
	// ServerKeygenKeyType selects the generated key type (default rsa-2048).
	ServerKeygenKeyType string `yaml:"server_keygen_key_type"`
}

// ESTUserConfig is one EST Basic-auth credential.
type ESTUserConfig struct {
	Password string `yaml:"password"`
	Profile  string `yaml:"profile"`
}

// CMPConfig configures the Lightweight CMP (RFC 9483) server. When enabled a
// /cmp endpoint accepts PKIMessage flows (ir/cr/kur/rr) with shared-secret
// (PasswordBasedMac) or signature-based message protection.
type CMPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Path is the URL the endpoint mounts under (default /cmp).
	Path string `yaml:"path"`
	// CAID / CALabel select the issuing CA. Exactly one should be set.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// Profile is the default certificate profile (default "client").
	Profile string `yaml:"profile"`
	// Secrets are the shared secrets for MAC-protected requests, each identified
	// by a reference value the client presents as the senderKID.
	Secrets []CMPSecretConfig `yaml:"secrets"`
	// AllowSignatureProtection enables signature-protected flows (kur, and rr by a
	// certificate this CA previously issued). Defaults to true.
	AllowSignatureProtection *bool `yaml:"allow_signature_protection"`
}

// SignatureProtectionEnabled reports whether signature-protected flows are
// permitted. It defaults to true.
func (c CMPConfig) SignatureProtectionEnabled() bool {
	return c.AllowSignatureProtection == nil || *c.AllowSignatureProtection
}

// CMPSecretConfig is one shared-secret enrollment credential for CMP PBM.
type CMPSecretConfig struct {
	// Reference is the senderKID (reference value) identifying this secret.
	Reference string `yaml:"reference"`
	// Secret is the shared secret value used to key the PasswordBasedMac.
	Secret string `yaml:"secret"`
	// Profile constrains what this credential may enroll (empty = server default).
	Profile string `yaml:"profile"`
}

// TSAConfig configures the RFC 3161 Time-Stamp Authority. When enabled a public
// /tsa endpoint issues signed time-stamp tokens. The signing key and certificate
// are provisioned offline with `secsy-ca tsa-key`; the key MUST be RSA.
type TSAConfig struct {
	Enabled bool `yaml:"enabled"`
	// Path is the URL the TSA mounts under (default /tsa).
	Path string `yaml:"path"`
	// KeyLabel is the provider label of the (RSA) TSA signing key.
	KeyLabel string `yaml:"key_label"`
	// CertificateFile is the PEM file holding the TSA signing certificate written
	// by `secsy-ca tsa-key`. When it contains multiple certificates, the first is
	// the TSA certificate and the rest form the issuer chain embedded on certReq.
	CertificateFile string `yaml:"certificate_file"`
	// CAID / CALabel identify the CA that issued the TSA certificate; its chain is
	// appended after the TSA certificate when a request sets certReq. Optional when
	// CertificateFile already carries the full chain.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// PolicyOID is the dotted-decimal TSA policy OID asserted in every token.
	// Defaults to the built-in example policy when unset.
	PolicyOID string `yaml:"policy_oid"`
	// AccuracySeconds / AccuracyMillis / AccuracyMicros bound genTime's deviation
	// from real time. All zero (the default) omits the accuracy field.
	AccuracySeconds int `yaml:"accuracy_seconds"`
	AccuracyMillis  int `yaml:"accuracy_millis"`
	AccuracyMicros  int `yaml:"accuracy_micros"`
	// Ordering asserts strict time ordering of tokens sharing this policy.
	Ordering bool `yaml:"ordering"`
	// SignatureDigest is the CMS signature hash (sha256|sha384|sha512; default sha256).
	SignatureDigest string `yaml:"signature_digest"`
	// AcceptedHashes restricts message-imprint hash algorithms (default
	// sha256,sha384,sha512). SHA-1 must be listed explicitly to be accepted.
	AcceptedHashes []string `yaml:"accepted_hashes"`
	// IncludeTSAName embeds the signing certificate subject as the tsa GeneralName.
	IncludeTSAName bool `yaml:"include_tsa_name"`
}

// SigningConfig configures the artifact code-signing service (Task 60): CMS
// detached signatures over release artifacts with provider-held keys, exposed
// at /api/sign (RBAC role "signer") and through `secsy-ca sign`. Each signer's
// key and certificate are provisioned offline with `secsy-ca signing-key`,
// which issues the certificate under the lint-gated "code-signing" profile.
type SigningConfig struct {
	Enabled bool `yaml:"enabled"`
	// Signers are the signing identities available to callers.
	Signers []SigningSignerConfig `yaml:"signers"`
}

// SigningSignerConfig is one configured signing identity.
type SigningSignerConfig struct {
	// Name is the identity callers reference in sign requests. Required, unique.
	Name string `yaml:"name"`
	// KeyLabel is the provider label of the signing key (RSA or ECDSA), created
	// by `secsy-ca signing-key`.
	KeyLabel string `yaml:"key_label"`
	// CertificateFile is the PEM file written by `secsy-ca signing-key`. When it
	// contains multiple certificates the first is the signer certificate and the
	// rest form the issuer chain embedded in every signature.
	CertificateFile string `yaml:"certificate_file"`
	// CAID / CALabel identify the CA that issued the signer certificate; its
	// chain is appended after the signer certificate when CertificateFile holds
	// only the leaf. Optional when the file already carries the full chain.
	CAID    string `yaml:"ca_id"`
	CALabel string `yaml:"ca_label"`
	// Digest is the message-digest / signature hash (sha256|sha384|sha512,
	// default sha256).
	Digest string `yaml:"digest"`
	// Timestamp embeds an RFC 3161 countersignature from the local TSA on every
	// signature unless a request opts out. Requires tsa.enabled.
	Timestamp bool `yaml:"timestamp"`
	// Tenant scopes this signer to a tenant for RBAC and audit. Empty means the
	// default tenant.
	Tenant string `yaml:"tenant"`
}

// RBACConfig maps OIDC subjects and group IDs to role names. Recognized roles
// are "admin", "issuer", "signer", and "auditor"; unknown names are rejected at
// load so a typo cannot silently grant or deny access.
type RBACConfig struct {
	Subjects map[string][]string `yaml:"subjects"`
	Groups   map[string][]string `yaml:"groups"`
}

// TenantConfig declares an isolated organization served by this deployment.
// Each tenant owns its own CAs, restriction sets, revocation state, secret
// envelopes, and audit trail. RBAC assignments declared here are scoped to the
// tenant: a subject listed under a tenant holds its roles ONLY within that
// tenant. Platform-wide roles (which apply across all tenants) are configured in
// the top-level rbac block and reserved for platform operators.
type TenantConfig struct {
	// ID is the stable internal identifier persisted on every tenant-scoped row.
	// It must be unique and, once assigned, must never change.
	ID string `yaml:"id"`
	// Slug is the URL/CLI-friendly identifier used to resolve a tenant from a
	// request path segment. Defaults to ID when empty.
	Slug string `yaml:"slug"`
	// Name is the human-readable display name. Defaults to ID when empty.
	Name string `yaml:"name"`
	// KEKLabel optionally overrides the deployment-wide secret KEK for this
	// tenant, so its secret envelopes are sealed under a tenant-specific key.
	KEKLabel string `yaml:"kek_label"`
	// RBAC assigns tenant-scoped roles to subjects and groups.
	RBAC RBACConfig `yaml:"rbac"`
	// AllowedEmailDomains scopes S/MIME issuance for this tenant: certificates
	// minted by the tenant's CAs under an S/MIME profile may only certify
	// e-mail addresses in these domains ("example.com" exact, "*.example.com"
	// subdomains). Empty means the tenant imposes no restriction of its own;
	// profile-level allowed_domains still apply.
	AllowedEmailDomains []string `yaml:"allowed_email_domains"`
}

// PolicyConfig holds system-wide issuance policy. These are conservative
// guardrails enforced centrally regardless of per-CA restriction sets.
type PolicyConfig struct {
	// RequireReason forces every certificate-issuing request to carry a
	// non-empty reason, improving auditability.
	RequireReason bool `yaml:"require_reason"`
	// MaxCertValidityDays caps the validity of any issued end-entity certificate
	// (0 = no global cap; per-profile and per-CA limits still apply).
	MaxCertValidityDays int `yaml:"max_cert_validity_days"`
	// AllowRootBasicAuth enables the built-in root user (HTTP basic auth). Set to
	// false in production once OIDC + RBAC admins are configured, to remove the
	// shared-credential superuser.
	AllowRootBasicAuth *bool `yaml:"allow_root_basic_auth"`
}

// RootBasicAuthEnabled reports whether the built-in root user should be
// accepted. It defaults to true (backward compatible) unless explicitly
// disabled.
func (p PolicyConfig) RootBasicAuthEnabled() bool {
	return p.AllowRootBasicAuth == nil || *p.AllowRootBasicAuth
}

// ProfileConfig defines a custom certificate profile in configuration. It
// mirrors ca.Profile using day-based validities for human-friendly YAML.
type ProfileConfig struct {
	Name                string   `yaml:"name"`
	Description         string   `yaml:"description"`
	KeyUsages           []string `yaml:"key_usages"`
	ExtKeyUsages        []string `yaml:"ext_key_usages"`
	DefaultValidityDays int      `yaml:"default_validity_days"`
	MaxValidityDays     int      `yaml:"max_validity_days"`
	// CT is the profile's Certificate Transparency policy (disabled unless
	// ct.enabled is true).
	CT ProfileCTConfig `yaml:"ct"`
	// Lint is the profile's pre-issuance lint policy (CA/Browser Forum Baseline
	// Requirements gate). Linting is on by default; see ProfileLintConfig.
	Lint ProfileLintConfig `yaml:"lint"`
	// CAA is the profile's DNS Certification Authority Authorization policy (RFC
	// 8659). Disabled unless caa.mode is "enforce" or "permissive"; see
	// ProfileCAAConfig.
	CAA ProfileCAAConfig `yaml:"caa"`
	// Policies assigns RFC 5280 certificate-policy OIDs (2.5.29.32) to leaves
	// issued under the profile, optionally with a CPS URI and policy mappings.
	Policies ProfilePolicyConfig `yaml:"policies"`
	// Attestation is the profile's enrollment key-attestation policy (Task 49).
	// When mode is "require", EST/SCEP/ACME enrollments under the profile must
	// present a valid hardware attestation bound to the enrolled key. Empty mode
	// inherits attestation.default_mode.
	Attestation ProfileAttestationConfig `yaml:"attestation"`
	// SMIME marks the profile as an S/MIME (emailProtection) profile: rfc822Name
	// SANs are validated, normalized (punycode domains), and checked against the
	// domain allowlists before signing, and the CA/B Forum S/MIME Baseline
	// Requirements lint rules apply. See ProfileSMIMEConfig.
	SMIME ProfileSMIMEConfig `yaml:"smime"`
}

// ProfileSMIMEConfig is a profile's S/MIME issuance policy. Enabled switches
// the profile into S/MIME mode; the remaining fields refine it.
type ProfileSMIMEConfig struct {
	// Enabled turns the S/MIME gate and lint rules on for the profile.
	Enabled bool `yaml:"enabled"`
	// Variant declares the key-usage split: "sign", "encrypt", or "dual"
	// (default). It must agree with the profile's key_usages; the lint gate
	// verifies that.
	Variant string `yaml:"variant"`
	// BRProfile selects the S/MIME Baseline Requirements class: "legacy"
	// (1185-day validity cap), "multipurpose" (825 days; default), or "strict"
	// (825 days, no EKU besides emailProtection).
	BRProfile string `yaml:"br_profile"`
	// AllowedDomains restricts the e-mail domains the profile may certify.
	// "example.com" matches exactly; "*.example.com" matches subdomains. Empty
	// means unrestricted (tenant allowlists still apply).
	AllowedDomains []string `yaml:"allowed_domains"`
	// SubjectEmail mirrors the first rfc822Name SAN into the subject DN as a
	// PKCS#9 emailAddress attribute for legacy relying parties.
	SubjectEmail bool `yaml:"subject_email"`
}

// ProfilePolicyConfig is a profile's certificate-policy assignment. When oids is
// non-empty, every leaf issued under the profile carries a certificatePolicies
// extension listing those OIDs (each with the optional CPS URI qualifier).
type ProfilePolicyConfig struct {
	// OIDs are dotted policy identifiers (or the literal "anyPolicy").
	OIDs []string `yaml:"oids"`
	// CPS is an optional CPS-URI qualifier applied to every listed policy.
	CPS string `yaml:"cps"`
	// Critical marks the certificatePolicies extension critical (rarely needed).
	Critical bool `yaml:"critical"`
	// Mappings are "issuerOID:subjectOID" policy-mapping pairs.
	Mappings []string `yaml:"mappings"`
}

// ProfileCAAConfig is a profile's pre-issuance CAA policy (RFC 8659). When
// enabled, the CA resolves the Certification Authority Authorization RRset for
// each DNS-name SAN before signing and, under enforce mode, blocks issuance when
// the RRset does not authorize this CA (fail-closed).
type ProfileCAAConfig struct {
	// Mode is "off" (default, gate disabled), "permissive" (evaluate and audit but
	// never block), or "enforce" (block on a forbidding CAA set or an undetermined
	// lookup).
	Mode string `yaml:"mode"`
	// Identifier overrides the top-level caa.identifier for this profile. Empty
	// falls back to the global CA identifier.
	Identifier string `yaml:"identifier"`
	// TimeoutSeconds bounds all DNS lookups for one certificate's names (0 =
	// resolver default).
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// ProfileLintConfig is a profile's pre-issuance certificate-linting policy. The
// linter runs CA/Browser-Forum structural and policy checks on every
// to-be-signed certificate before it is signed and blocks issuance on an
// enforce-mode violation (fail-closed).
type ProfileLintConfig struct {
	// Disabled turns the lint gate off for the profile (discouraged).
	Disabled bool `yaml:"disabled"`
	// Mode is the default enforcement mode: "enforce" (default) or "warn".
	Mode string `yaml:"mode"`
	// Public applies public-trust rules (SAN required, CN in SAN, no internal
	// names / reserved IPs, 398-day TLS cap).
	Public bool `yaml:"public"`
	// Overrides sets the mode ("enforce"|"warn") for individual checks by code.
	Overrides map[string]string `yaml:"overrides"`
}

// SecretConfig configures the HSM-backed envelope-encryption feature. KEKLabel
// is the label of the RSA key-encryption key used to wrap data keys; it must
// exist in the configured key provider (create it with `secsy-secret init-kek`).
// When empty, the secret encrypt/decrypt API endpoints are disabled.
type SecretConfig struct {
	KEKLabel string `yaml:"kek_label"`
	// Escrow optionally configures M-of-N key escrow so data keys can be
	// recovered under dual control when the original requester loses access.
	Escrow EscrowConfig `yaml:"escrow"`
}

// EscrowConfig configures optional M-of-N key escrow for the envelope layer. At
// encryption time (when Enabled and the operator opts in) each data key is
// Shamir-split across the recovery agents so that any Threshold of them can
// reconstruct it during a dual-control recovery ceremony, while fewer than
// Threshold learn nothing.
type EscrowConfig struct {
	// Enabled turns the escrow feature on. When false the escrow policy is
	// ignored and no recovery shares are produced.
	Enabled bool `yaml:"enabled"`
	// Threshold is the quorum M of recovery agents required to reconstruct a data
	// key. It must be at least 2 (dual control) and at most len(Agents).
	Threshold int `yaml:"threshold"`
	// Agents is the set of N recovery agents. Each must resolve to an RSA public
	// key, either from the key provider (KeyLabel) or an inline/file PEM.
	Agents []RecoveryAgentConfig `yaml:"agents"`
}

// RecoveryAgentConfig describes one escrow recovery agent. Provide a KeyLabel to
// use an RSA key held by the key provider (recommended: its private half stays
// in the HSM and participates in recovery on-device), and/or a PublicKey /
// PublicKeyFile to wrap to an externally-held key.
type RecoveryAgentConfig struct {
	// ID is the stable, human-meaningful identifier of the recovery agent.
	ID string `yaml:"id"`
	// KeyLabel is the agent's key label in the key provider, required for the
	// agent to participate in a recovery ceremony through this provider.
	KeyLabel string `yaml:"key_label"`
	// PublicKey is an inline PEM-encoded RSA public key (SPKI or PKCS#1). When
	// set it overrides the provider lookup for the wrap step.
	PublicKey string `yaml:"public_key"`
	// PublicKeyFile is a path to a PEM-encoded RSA public key, an alternative to
	// PublicKey.
	PublicKeyFile string `yaml:"public_key_file"`
}

type ServerConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// OCSPCacheTTLSeconds bounds how long a signed OCSP response is reused from
	// the in-memory cache before being re-signed on the HSM. It must be well
	// under the response NextUpdate window. A negative value disables caching; 0
	// means "use the server default" (handlers.DefaultOCSPCacheTTL). Revocations
	// invalidate the affected entry immediately regardless of this value. See
	// docs/benchmarks.md.
	OCSPCacheTTLSeconds int `yaml:"ocsp_cache_ttl_seconds"`
	// OCSP holds responder-hardening options (nonce, delegated responder,
	// stapling). Zero-valued fields fall back to safe defaults.
	OCSP OCSPConfig `yaml:"ocsp"`
}

// OCSPConfig configures the hardened OCSP responder (RFC 6960 / RFC 8954).
type OCSPConfig struct {
	// NonceEnabled turns on echoing of the id-pkix-ocsp-nonce extension. A
	// nonce-bearing request always bypasses the response cache and is signed
	// freshly. When nil, nonce echoing defaults to enabled.
	NonceEnabled *bool `yaml:"nonce_enabled"`
	// NonceMaxAgeSeconds bounds the NextUpdate window of a nonce-bearing
	// response. Because such responses are freshly signed and not cached, this
	// is kept short (default 60s). Non-positive uses the default.
	NonceMaxAgeSeconds int `yaml:"nonce_max_age_seconds"`
	// Delegated enables signing responses with a short-lived, HSM-backed
	// delegated OCSP-signing certificate (id-kp-OCSPSigning + ocsp-nocheck)
	// rather than with the CA key directly.
	Delegated bool `yaml:"delegated"`
	// DelegatedValidityHours is the lifetime of the delegated responder
	// certificate (default 168h = 7 days). Non-positive uses the default.
	DelegatedValidityHours int `yaml:"delegated_validity_hours"`
	// DelegatedKeyType is the key type for the delegated responder key
	// (default ecdsa P-256). Must be an RSA or ECDSA type; OCSP does not
	// support Ed25519.
	DelegatedKeyType string `yaml:"delegated_key_type"`
	// StapleCAID, when set, is the CA that issued the server's own TLS
	// certificate. The server periodically produces an OCSP staple for its TLS
	// certificate under this CA and serves it in the TLS handshake.
	StapleCAID string `yaml:"staple_ca_id"`
	// Presign configures background OCSP response pre-signing (Task 58): every
	// known serial gets a batch-signed response placed in the response cache so
	// the public responder never touches the HSM on the hot path (nonce-bearing
	// requests still bypass per RFC 8954).
	Presign OCSPPresignConfig `yaml:"presign"`
}

// OCSPPresignConfig configures batch OCSP response pre-signing.
type OCSPPresignConfig struct {
	// Enabled turns background pre-signing on.
	Enabled bool `yaml:"enabled"`
	// ValidityMinutes is the NextUpdate window of pre-signed responses (default
	// 1440 = 24h). It bounds how long pre-signed responses keep being served
	// through an HSM outage, and how long a revocation may take to reach
	// consumers of pre-signed/published responses.
	ValidityMinutes int `yaml:"validity_minutes"`
	// RefreshMinutes is how often the pre-signing batch runs (default
	// validity/4). It must leave a comfortable margin under the validity window
	// so a missed batch or two never means serving expired responses.
	RefreshMinutes int `yaml:"refresh_minutes"`
	// RecentlyQueried also pre-signs serials recently asked about through the
	// online responder that are not in the store (answered "unknown"). Nil
	// defaults to enabled.
	RecentlyQueried *bool `yaml:"recently_queried"`
	// RecentCapacity bounds the recently-queried tracker (default 4096).
	RecentCapacity int `yaml:"recent_capacity"`
	// ExpiredGraceMinutes keeps pre-signing a serial for this long past its
	// certificate's expiry (default 1440 = 24h); -1 disables the grace.
	ExpiredGraceMinutes int `yaml:"expired_grace_minutes"`
}

// Validity returns the effective pre-signed response validity window.
func (c OCSPPresignConfig) Validity() time.Duration {
	if c.ValidityMinutes <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.ValidityMinutes) * time.Minute
}

// Refresh returns the effective batch interval: the configured one, or a
// quarter of the validity window, floored at one minute.
func (c OCSPPresignConfig) Refresh() time.Duration {
	if c.RefreshMinutes > 0 {
		return time.Duration(c.RefreshMinutes) * time.Minute
	}
	r := c.Validity() / 4
	if r < time.Minute {
		r = time.Minute
	}
	return r
}

// ExpiredGrace returns the effective post-expiry grace window (-1 minute
// disables it; the ca package maps negatives to zero).
func (c OCSPPresignConfig) ExpiredGrace() time.Duration {
	if c.ExpiredGraceMinutes == 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.ExpiredGraceMinutes) * time.Minute
}

// TrackRecentlyQueried reports whether recently-queried serials join batches.
func (c OCSPPresignConfig) TrackRecentlyQueried() bool {
	return c.RecentlyQueried == nil || *c.RecentlyQueried
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`

	// Connection-pool tuning for networked backends (PostgreSQL). These are
	// ignored for the embedded SQLite driver, which is pinned to one connection.
	// Zero values select conservative built-in defaults (see
	// database.NewWithOptions). Durations are expressed in seconds.
	MaxOpenConns        int `yaml:"max_open_conns"`
	MaxIdleConns        int `yaml:"max_idle_conns"`
	ConnMaxLifetimeSecs int `yaml:"conn_max_lifetime_seconds"`
	ConnMaxIdleTimeSecs int `yaml:"conn_max_idle_time_seconds"`
}

type OIDCConfig struct {
	IssuerURL   string `yaml:"issuer_url"`
	ClientID    string `yaml:"client_id"`
	RedirectURL string `yaml:"redirect_url"`
}

type RootUserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// KeyProviderConfig selects which key backend the server uses to generate and
// sign with CA keys. Type is one of "pkcs11" (HSM-backed, the default when a
// PKCS#11 module is configured), "software" (on-disk keystore), or "kms" (a cloud
// KMS: AWS KMS or Azure Key Vault).
//
// Roles optionally overrides the backend for individual signing roles so, for
// example, the CA key can live on a PKCS#11 HSM while the TSA key lives in AWS
// KMS. An unset role falls back to Type. OCSP responder keys are provisioned and
// used by the CA manager, so they follow the CA role.
type KeyProviderConfig struct {
	Type     string                 `yaml:"type"`
	Software SoftwareProviderConfig `yaml:"software"`
	KMS      KMSProviderConfig      `yaml:"kms"`
	Roles    KeyProviderRoles       `yaml:"roles"`
}

type SoftwareProviderConfig struct {
	KeystoreDir string `yaml:"keystore_dir"`
}

// KMSProviderConfig configures the cloud-KMS backend. Backend selects the cloud
// service ("aws" or "azure"; "fake" is an in-memory emulation used only by
// tests). See docs/cloud-kms.md for IAM/permissions requirements.
type KMSProviderConfig struct {
	// Backend is "aws", "azure", or "fake".
	Backend string `yaml:"backend"`
	// Region is the AWS region (AWS backend). When empty the AWS SDK default
	// resolution (AWS_REGION / shared config) applies.
	Region string `yaml:"region"`
	// KeyPrefix namespaces this deployment's keys within the account/vault. It is
	// prepended to the key label to form the AWS alias / Azure key name.
	KeyPrefix string `yaml:"key_prefix"`
	// VaultURL is the Azure Key Vault base URL (Azure backend), e.g.
	// "https://my-vault.vault.azure.net/".
	VaultURL string `yaml:"vault_url"`
}

// KeyProviderRoles overrides the backend type per signing role. Each value, when
// set, must be a valid provider type ("pkcs11", "software", or "kms") whose
// backend block is itself configured.
type KeyProviderRoles struct {
	// CA is the backend for the CA signing key (and, by extension, OCSP responder
	// keys the CA manager provisions). Defaults to KeyProviderConfig.Type.
	CA string `yaml:"ca"`
	// TSA is the backend for the RFC 3161 timestamp-authority signing key.
	// Defaults to KeyProviderConfig.Type.
	TSA string `yaml:"tsa"`
	// Signing is the backend for artifact code-signing keys (the signing:
	// service). Defaults to KeyProviderConfig.Type.
	Signing string `yaml:"signing"`
}

type PKCS11Config struct {
	ModulePath        string `yaml:"module_path"`
	Pin               string `yaml:"pin"`
	TokenLabel        string `yaml:"token_label"`
	TokenSerial       string `yaml:"token_serial"`
	TokenManufacturer string `yaml:"token_manufacturer"`
	// SessionPoolSize bounds the number of concurrent PKCS#11 sessions the key
	// provider keeps open, and therefore how many signing/decryption operations
	// may hit the token at once. Requests beyond it queue (bounded backpressure).
	// When <= 0 the provider uses keyprovider.DefaultSessionPoolSize. This is the
	// primary HSM throughput tuning knob; see docs/benchmarks.md.
	SessionPoolSize int `yaml:"session_pool_size"`

	// Tokens, when non-empty, enables multi-token high availability: the pkcs11
	// backend spans these tokens/slots (each holding a replica of the signing
	// key(s) under the same label) behind health-tracked failover. When empty the
	// backend addresses the single token named by token_label/token_serial above.
	// See docs/hsm-ha.md.
	Tokens []PKCS11TokenConfig `yaml:"tokens"`
	// SelectionPolicy chooses how a healthy token is picked: "primary-backup"
	// (default) prefers the first healthy token, using backups only on failover;
	// "round-robin" spreads load across healthy tokens. Ignored unless tokens set.
	SelectionPolicy string `yaml:"selection_policy"`
	// FailureThreshold is the number of consecutive failures on a token before it
	// is marked unhealthy and taken out of rotation. <= 0 uses the provider
	// default. Ignored unless tokens set.
	FailureThreshold int `yaml:"failure_threshold"`
	// ProbeIntervalSeconds is how often the background prober re-checks tokens so a
	// recovered token returns to rotation. <= 0 uses the provider default. Ignored
	// unless tokens set.
	ProbeIntervalSeconds int `yaml:"probe_interval_seconds"`
}

// PKCS11TokenConfig identifies one token/slot within a high-availability set. All
// tokens share the module path and session-pool size from the enclosing
// PKCS11Config; each addresses a distinct token and may carry its own PIN.
type PKCS11TokenConfig struct {
	// Name is a stable identifier used in per-token health and failover metrics
	// and in logs. Defaults to token_label when empty.
	Name string `yaml:"name"`
	// TokenLabel / TokenSerial / TokenManufacturer address the token.
	TokenLabel        string `yaml:"token_label"`
	TokenSerial       string `yaml:"token_serial"`
	TokenManufacturer string `yaml:"token_manufacturer"`
	// Pin is this token's user PIN; when empty the shared pkcs11.pin is used.
	Pin string `yaml:"pin"`
}

type YubiHSMConfig struct {
	ConnectorURL         string `yaml:"connector_url"`
	AuthKeyID            int    `yaml:"auth_key_id"`
	Password             string `yaml:"password"`
	SuppressAuditWarning bool   `yaml:"suppress_audit_warning"`
}

// UnknownKeys re-decodes raw config YAML in strict mode and returns one
// human-readable finding per key that does not correspond to any known config
// field (e.g. "line 12: field pkcs1 not found in type config.Config" — usually
// a typo that would otherwise be silently ignored). Malformed YAML returns an
// error instead; callers are expected to have surfaced parse failures via Load
// already. It is used by `secsy-ca doctor` for preflight config linting.
func UnknownKeys(data []byte) ([]string, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	err := dec.Decode(&c)
	if err == nil || errors.Is(err, io.EOF) {
		return nil, nil
	}
	var te *yaml.TypeError
	if errors.As(err, &te) {
		var unknown []string
		for _, msg := range te.Errors {
			// A strict decode also reports genuine type mismatches; those already
			// fail the non-strict Load and are reported there. Only the
			// unknown-field findings are new information here.
			if strings.Contains(msg, "not found in type") {
				unknown = append(unknown, msg)
			}
		}
		return unknown, nil
	}
	return nil, err
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8443,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "secsy-pki.db",
		},
		RootUser: RootUserConfig{
			Username: "root",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyEnvOverrides(cfg)
	cfg.defaultKeyProvider()

	if cfg.RootUser.Password == "" {
		return nil, fmt.Errorf("root_user.password is required")
	}

	if err := cfg.validateKeyProvider(); err != nil {
		return nil, err
	}

	if err := cfg.validateRBAC(); err != nil {
		return nil, err
	}

	if err := cfg.validateACME(); err != nil {
		return nil, err
	}

	if err := cfg.validateMonitor(); err != nil {
		return nil, err
	}

	if err := cfg.validateCanary(); err != nil {
		return nil, err
	}

	if err := cfg.validateEnrollment(); err != nil {
		return nil, err
	}

	if err := cfg.validateAuditExport(); err != nil {
		return nil, err
	}

	if err := cfg.validateAuditAnchor(); err != nil {
		return nil, err
	}

	if err := cfg.validateCoordination(); err != nil {
		return nil, err
	}

	if err := cfg.validateRateLimit(); err != nil {
		return nil, err
	}

	if err := cfg.validateSPIFFE(); err != nil {
		return nil, err
	}

	if err := cfg.validateTracing(); err != nil {
		return nil, err
	}

	if err := cfg.validateAuth(); err != nil {
		return nil, err
	}

	if err := cfg.validatePresignPublish(); err != nil {
		return nil, err
	}

	if err := cfg.validateSigning(); err != nil {
		return nil, err
	}

	if err := cfg.validateFIPS(); err != nil {
		return nil, err
	}
	// Mirror the validated policy switch into the process-global enforcement
	// flag. Load is the single path configuration enters a process through, so
	// this is where key generation, issuance, and the secret layer pick the
	// policy up (see internal/fips).
	fips.SetPolicy(cfg.Security.FIPS)

	return cfg, nil
}

// validateFIPS rejects configuration that names non-approved algorithms when
// the fail-closed FIPS 140-3 policy (security.fips) is enabled. Every
// violation is reported in one pass so an operator fixes the config once, and
// each message names the offending key so `secsy-ca doctor` surfaces it
// verbatim in its config.parse finding.
func (c *Config) validateFIPS() error {
	if !c.Security.FIPS {
		return nil
	}
	var violations []string
	for _, h := range c.TSA.AcceptedHashes {
		if err := fips.ApprovedHashName(h); err != nil {
			violations = append(violations, fmt.Sprintf("tsa.accepted_hashes: %v", err))
		}
	}
	if d := c.TSA.SignatureDigest; d != "" {
		if err := fips.ApprovedHashName(d); err != nil {
			violations = append(violations, fmt.Sprintf("tsa.signature_digest: %v", err))
		}
	}
	for i, sg := range c.Signing.Signers {
		if sg.Digest == "" {
			continue
		}
		if err := fips.ApprovedHashName(sg.Digest); err != nil {
			violations = append(violations, fmt.Sprintf("signing.signers[%d] (%s): digest: %v", i, sg.Name, err))
		}
	}
	if kt := c.EST.ServerKeygenKeyType; kt != "" {
		if err := fips.ApprovedKeyType(kt); err != nil {
			violations = append(violations, fmt.Sprintf("est.server_keygen_key_type: %v", err))
		}
	}
	if kt := c.Server.OCSP.DelegatedKeyType; kt != "" {
		if err := fips.ApprovedKeyType(kt); err != nil {
			violations = append(violations, fmt.Sprintf("server.ocsp.delegated_key_type: %v", err))
		}
	}
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("security.fips is enabled but the configuration uses non-approved algorithms (fix these or disable security.fips):\n  - %s",
		strings.Join(violations, "\n  - "))
}

// validateSigning sanity-checks the artifact-signing block so a misconfigured
// signer fails at load rather than at the first sign request.
func (c *Config) validateSigning() error {
	s := c.Signing
	if !s.Enabled {
		return nil
	}
	if len(s.Signers) == 0 {
		return fmt.Errorf("signing.enabled requires at least one entry under signing.signers")
	}
	seen := map[string]bool{}
	for i, sg := range s.Signers {
		where := fmt.Sprintf("signing.signers[%d]", i)
		if sg.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		if seen[sg.Name] {
			return fmt.Errorf("%s: duplicate signer name %q", where, sg.Name)
		}
		seen[sg.Name] = true
		if sg.KeyLabel == "" {
			return fmt.Errorf("%s (%s): key_label is required", where, sg.Name)
		}
		if sg.CertificateFile == "" {
			return fmt.Errorf("%s (%s): certificate_file is required (write it with `secsy-ca signing-key`)", where, sg.Name)
		}
		switch sg.Digest {
		case "", "sha256", "sha384", "sha512":
		default:
			return fmt.Errorf("%s (%s): digest must be sha256, sha384, or sha512 (got %q)", where, sg.Name, sg.Digest)
		}
		if sg.Timestamp && !c.TSA.Enabled {
			return fmt.Errorf("%s (%s): timestamp: true requires tsa.enabled", where, sg.Name)
		}
	}
	return nil
}

// validatePresignPublish sanity-checks the OCSP pre-signing and static
// publishing blocks so a misconfiguration fails at load rather than silently
// serving stale or no revocation data.
func (c *Config) validatePresignPublish() error {
	p := c.Server.OCSP.Presign
	if p.Enabled {
		if c.Server.OCSPCacheTTLSeconds < 0 {
			return fmt.Errorf("server.ocsp.presign.enabled requires the OCSP response cache, but server.ocsp_cache_ttl_seconds disables it")
		}
		if p.RefreshMinutes > 0 && p.ValidityMinutes > 0 && p.RefreshMinutes*2 > p.ValidityMinutes {
			return fmt.Errorf("server.ocsp.presign.refresh_minutes (%d) must be at most half of validity_minutes (%d) so responses are always refreshed well before they expire",
				p.RefreshMinutes, p.ValidityMinutes)
		}
	}

	pub := c.Publish
	if !pub.Enabled {
		return nil
	}
	switch pub.Backend() {
	case "s3":
		if pub.S3.Endpoint != "" && !strings.Contains(pub.S3.Endpoint, "://") {
			return fmt.Errorf("publish.s3.endpoint must be a URL (e.g. https://minio.internal:9000)")
		}
	default:
		if pub.Dir.Path == "" {
			return fmt.Errorf("publish.enabled requires publish.dir.path or publish.s3.bucket")
		}
	}
	if pub.IncludeOCSPEnabled() && !p.Enabled {
		// Publishing OCSP without the presign loop still works (the publisher
		// pre-signs on demand), but the cache then never serves those responses.
		// Require the explicit opt-out rather than guessing.
		return fmt.Errorf("publish.enabled with OCSP artifacts requires server.ocsp.presign.enabled (or set publish.include_ocsp: false)")
	}
	return nil
}

// validateAuth sanity-checks the operator-authentication block when its
// sub-features are enabled, failing loudly at load so a half-configured login,
// mTLS, or WebAuthn setup cannot silently disable a protection an operator meant
// to turn on. Role names in mappings/bindings are checked against the known set.
func (c *Config) validateAuth() error {
	a := &c.Auth
	validRole := func(where, r string) error {
		switch r {
		case "admin", "issuer", "signer", "auditor":
			return nil
		}
		return fmt.Errorf("auth.%s: unknown role %q (want admin, issuer, signer, or auditor)", where, r)
	}

	if a.OIDC.Enabled {
		issuer := a.OIDC.IssuerURL
		if issuer == "" {
			issuer = c.OIDC.IssuerURL
		}
		if issuer == "" {
			return fmt.Errorf("auth.oidc.enabled is true but no issuer_url is set (here or in the top-level oidc block)")
		}
		if strings.TrimSpace(a.OIDC.RedirectURL) == "" {
			return fmt.Errorf("auth.oidc.enabled is true but auth.oidc.redirect_url is required for interactive login")
		}
		for i, m := range a.OIDC.RoleMappings {
			if strings.TrimSpace(m.Value) == "" {
				return fmt.Errorf("auth.oidc.role_mappings[%d]: value is required", i)
			}
			if len(m.Roles) == 0 {
				return fmt.Errorf("auth.oidc.role_mappings[%d]: at least one role is required", i)
			}
			for _, r := range m.Roles {
				if err := validRole(fmt.Sprintf("oidc.role_mappings[%d]", i), r); err != nil {
					return err
				}
			}
		}
	}

	if a.MTLS.Enabled {
		if strings.TrimSpace(a.MTLS.CAFile) == "" {
			return fmt.Errorf("auth.mtls.enabled is true but auth.mtls.ca_file is required to verify client certificates")
		}
		if len(a.MTLS.Bindings) == 0 {
			return fmt.Errorf("auth.mtls.enabled is true but no bindings are configured (every client cert would be rejected)")
		}
		for i, b := range a.MTLS.Bindings {
			if b.SubjectCN == "" && b.SubjectDN == "" && b.SANDNS == "" && b.SANURI == "" && b.SANEmail == "" {
				return fmt.Errorf("auth.mtls.bindings[%d]: at least one selector (subject_cn/subject_dn/san_*) is required", i)
			}
			for _, r := range b.Roles {
				if err := validRole(fmt.Sprintf("mtls.bindings[%d]", i), r); err != nil {
					return err
				}
			}
			for tid, roles := range b.TenantRoles {
				for _, r := range roles {
					if err := validRole(fmt.Sprintf("mtls.bindings[%d].tenant_roles[%q]", i, tid), r); err != nil {
						return err
					}
				}
			}
		}
	}

	if a.WebAuthn.Enabled {
		if strings.TrimSpace(a.WebAuthn.RPID) == "" {
			return fmt.Errorf("auth.webauthn.enabled is true but auth.webauthn.rp_id is required")
		}
		if len(a.WebAuthn.Origins) == 0 {
			return fmt.Errorf("auth.webauthn.enabled is true but auth.webauthn.origins is required (e.g. https://pki.example.com)")
		}
	}
	return nil
}

// validateTracing sanity-checks the OpenTelemetry tracing configuration when it
// is enabled: an endpoint is required, the protocol (if given) must be known,
// and the sample ratio must be a probability. Fail loudly at load so a
// misconfiguration does not silently disable tracing an operator turned on.
func (c *Config) validateTracing() error {
	t := &c.Tracing
	if !t.Enabled {
		return nil
	}
	if strings.TrimSpace(t.Endpoint) == "" {
		return fmt.Errorf("tracing.endpoint is required when tracing.enabled is true (e.g. otel-collector:4317)")
	}
	switch strings.ToLower(strings.TrimSpace(t.Protocol)) {
	case "", "grpc", "http":
	default:
		return fmt.Errorf("tracing.protocol %q is invalid (want grpc or http)", t.Protocol)
	}
	if t.SampleRatio < 0 || t.SampleRatio > 1 {
		return fmt.Errorf("tracing.sample_ratio must be in [0,1], got %v", t.SampleRatio)
	}
	return nil
}

// validateSPIFFE sanity-checks the SPIFFE SVID configuration when enabled: the
// renew fraction must be a sensible fraction, and each configured trust domain
// must be syntactically valid so a typo cannot silently widen (or dead-end) the
// allowlist. It never mutates cross-package state; canonicalization happens in
// spiffe.NewPolicy.
func (c *Config) validateSPIFFE() error {
	s := &c.SPIFFE
	if !s.Enabled {
		return nil
	}
	if s.RenewFraction != 0 && (s.RenewFraction <= 0 || s.RenewFraction >= 1) {
		return fmt.Errorf("spiffe.renew_fraction must be in (0,1), got %v", s.RenewFraction)
	}
	check := func(td string) error {
		td = strings.ToLower(strings.TrimSpace(td))
		if td == "" {
			return fmt.Errorf("spiffe: empty trust domain in allowlist")
		}
		if strings.Contains(td, "/") || strings.Contains(td, "spiffe:") {
			return fmt.Errorf("spiffe: trust domain %q must be a bare domain (no scheme or path)", td)
		}
		return nil
	}
	for _, td := range s.TrustDomains {
		if err := check(td); err != nil {
			return err
		}
	}
	for subject, tds := range s.SubjectTrustDomains {
		for _, td := range tds {
			if err := check(td); err != nil {
				return fmt.Errorf("spiffe.subject_trust_domains[%q]: %w", subject, err)
			}
		}
	}
	return nil
}

// validateRateLimit sanity-checks the rate-limit configuration when enabled so
// a misconfiguration (e.g. a positive rate with a zero burst that can never
// admit a request) fails loudly at startup rather than silently blackholing
// legitimate traffic.
func (c *Config) validateRateLimit() error {
	rl := &c.RateLimit
	if !rl.Enabled {
		return nil
	}
	tiers := []struct {
		name string
		r    RateConfig
	}{
		{"global", rl.Global},
		{"per_ip", rl.PerIP},
		{"per_account", rl.PerAccount},
		{"per_tenant", rl.PerTenant},
	}
	anyTier := false
	for _, t := range tiers {
		if t.r.Rate < 0 || t.r.Burst < 0 {
			return fmt.Errorf("rate_limit.%s: rate and burst must be non-negative", t.name)
		}
		if t.r.Rate > 0 && t.r.Burst <= 0 {
			return fmt.Errorf("rate_limit.%s: burst must be positive when rate is set (a zero-burst bucket never admits)", t.name)
		}
		if t.r.enabled() {
			anyTier = true
		}
	}
	guardOn := rl.Concurrency.GuardEnabled(true)
	if !anyTier && !guardOn {
		return fmt.Errorf("rate_limit.enabled is true but no tier has a positive rate/burst and the concurrency guard is disabled")
	}
	if rl.MaxKeys < 0 || rl.IdleTTLSeconds < 0 {
		return fmt.Errorf("rate_limit: max_keys and idle_ttl_seconds must be non-negative")
	}
	if rl.Concurrency.MaxQueue < 0 || rl.Concurrency.AcquireTimeoutMs < 0 {
		return fmt.Errorf("rate_limit.concurrency: max_queue and acquire_timeout_ms must be non-negative")
	}
	return nil
}

// enabled reports whether a tier is effective (positive rate and burst).
func (r RateConfig) enabled() bool { return r.Rate > 0 && r.Burst > 0 }

// validateAuditExport sanity-checks the SIEM export configuration when it is
// enabled, so a misconfiguration fails loudly at startup rather than silently
// dropping audit events downstream.
func (c *Config) validateAuditExport() error {
	e := &c.Audit.Export
	if !e.Enabled {
		return nil
	}
	if len(e.Sinks) == 0 {
		return fmt.Errorf("audit.export.enabled is true but no audit.export.sinks are configured")
	}
	if e.PollIntervalSeconds < 0 || e.RetryBackoffSeconds < 0 || e.MaxBackoffSeconds < 0 {
		return fmt.Errorf("audit.export: interval/backoff seconds must be non-negative")
	}
	if e.BatchSize < 0 {
		return fmt.Errorf("audit.export.batch_size must be non-negative")
	}
	names := make(map[string]bool, len(e.Sinks))
	for i, s := range e.Sinks {
		if s.Name == "" {
			return fmt.Errorf("audit.export.sinks[%d]: name is required", i)
		}
		if names[s.Name] {
			return fmt.Errorf("audit.export.sinks[%d]: duplicate sink name %q", i, s.Name)
		}
		names[s.Name] = true

		switch s.Format {
		case "", "rfc5424", "cef", "json":
		default:
			return fmt.Errorf("audit.export.sinks[%q]: unknown format %q (valid: rfc5424, cef, json)", s.Name, s.Format)
		}

		switch s.Type {
		case "syslog":
			if s.Address == "" {
				return fmt.Errorf("audit.export.sinks[%q]: syslog sink requires an address", s.Name)
			}
			switch s.Network {
			case "", "tcp", "tls":
			default:
				return fmt.Errorf("audit.export.sinks[%q]: unknown network %q (valid: tcp, tls)", s.Name, s.Network)
			}
			switch s.Framing {
			case "", "octet-counting", "lf":
			default:
				return fmt.Errorf("audit.export.sinks[%q]: unknown framing %q (valid: octet-counting, lf)", s.Name, s.Framing)
			}
			if (s.TLS.ClientCertFile == "") != (s.TLS.ClientKeyFile == "") {
				return fmt.Errorf("audit.export.sinks[%q]: tls.client_cert_file and tls.client_key_file must both be set for mutual TLS", s.Name)
			}
			if s.Format == "json" {
				return fmt.Errorf("audit.export.sinks[%q]: format json is not valid for a syslog sink (use rfc5424 or cef)", s.Name)
			}
		case "webhook":
			if s.URL == "" {
				return fmt.Errorf("audit.export.sinks[%q]: webhook sink requires a url", s.Name)
			}
		default:
			return fmt.Errorf("audit.export.sinks[%q]: unknown type %q (valid: syslog, webhook)", s.Name, s.Type)
		}
	}
	return nil
}

// validateAuditAnchor sanity-checks the audit-chain anchoring configuration
// when it is enabled, so a token source that cannot exist fails at load rather
// than on the first anchor tick.
// validateCoordination sanity-checks the multi-replica leader-election block.
// The mode strings mirror internal/leader (which re-validates at construction);
// checking here surfaces a misconfiguration as a config.Load error with the
// yaml key, before any component starts.
func (c *Config) validateCoordination() error {
	co := &c.Coordination
	switch co.Mode {
	case "", "auto", "postgres", "static":
	default:
		return fmt.Errorf("coordination.mode %q is not valid (valid: auto, postgres, static)", co.Mode)
	}
	isPostgres := c.Database.Driver == "postgres" || c.Database.Driver == "postgresql"
	if co.Mode == "postgres" && !isPostgres {
		return fmt.Errorf("coordination.mode \"postgres\" requires database.driver postgres (got %q)", c.Database.Driver)
	}
	if co.RenewIntervalSeconds < 0 {
		return fmt.Errorf("coordination.renew_interval_seconds must not be negative")
	}
	if co.RetryIntervalSeconds < 0 {
		return fmt.Errorf("coordination.retry_interval_seconds must not be negative")
	}
	return nil
}

func (c *Config) validateAuditAnchor() error {
	a := &c.Audit.Anchor
	if !a.Enabled {
		return nil
	}
	if a.IntervalHours < 0 {
		return fmt.Errorf("audit.anchor.interval_hours must not be negative")
	}
	if a.TimeoutSeconds < 0 {
		return fmt.Errorf("audit.anchor.timeout_seconds must not be negative")
	}
	if a.TSAURL != "" {
		if !strings.HasPrefix(a.TSAURL, "http://") && !strings.HasPrefix(a.TSAURL, "https://") {
			return fmt.Errorf("audit.anchor.tsa_url %q must be an http(s) URL", a.TSAURL)
		}
		return nil
	}
	if !c.TSA.Enabled {
		return fmt.Errorf("audit.anchor.enabled requires the internal TSA (tsa.enabled: true) or an external audit.anchor.tsa_url")
	}
	return nil
}

// validateEnrollment sanity-checks the SCEP and EST configuration when enabled.
func (c *Config) validateEnrollment() error {
	if c.SCEP.Enabled {
		if c.SCEP.CAID == "" && c.SCEP.CALabel == "" {
			return fmt.Errorf("scep.enabled is true but neither scep.ca_id nor scep.ca_label is set")
		}
		if c.SCEP.RequireChallengeEnabled() && len(c.SCEP.Grants) == 0 {
			return fmt.Errorf("scep.require_challenge is true but no scep.grants are configured")
		}
		for i, g := range c.SCEP.Grants {
			if g.Challenge == "" {
				return fmt.Errorf("scep.grants[%d]: challenge must not be empty", i)
			}
		}
	}
	if c.EST.Enabled {
		if c.EST.CAID == "" && c.EST.CALabel == "" {
			return fmt.Errorf("est.enabled is true but neither est.ca_id nor est.ca_label is set")
		}
		if len(c.EST.Users) == 0 && !c.EST.AllowTLSClientReenroll {
			return fmt.Errorf("est.enabled is true but no est.users and no est.allow_tls_client_reenroll are configured")
		}
	}
	if c.TSA.Enabled {
		if c.TSA.KeyLabel == "" {
			return fmt.Errorf("tsa.enabled is true but tsa.key_label is not set")
		}
		if c.TSA.CertificateFile == "" {
			return fmt.Errorf("tsa.enabled is true but tsa.certificate_file is not set (run: secsy-ca tsa-key)")
		}
		if c.TSA.PolicyOID != "" {
			if _, err := parseOID(c.TSA.PolicyOID); err != nil {
				return fmt.Errorf("tsa.policy_oid %q: %w", c.TSA.PolicyOID, err)
			}
		}
		switch c.TSA.SignatureDigest {
		case "", "sha256", "sha384", "sha512":
		default:
			return fmt.Errorf("tsa.signature_digest %q is invalid (want sha256, sha384, or sha512)", c.TSA.SignatureDigest)
		}
		for _, h := range c.TSA.AcceptedHashes {
			switch h {
			case "sha1", "sha256", "sha384", "sha512":
			default:
				return fmt.Errorf("tsa.accepted_hashes: %q is invalid (want sha1, sha256, sha384, or sha512)", h)
			}
		}
	}
	if c.CMP.Enabled {
		if c.CMP.CAID == "" && c.CMP.CALabel == "" {
			return fmt.Errorf("cmp.enabled is true but neither cmp.ca_id nor cmp.ca_label is set")
		}
		// At least one authentication method must be usable: a shared secret for
		// MAC-protected ir/cr, or signature-based protection for kur/rr.
		if len(c.CMP.Secrets) == 0 && !c.CMP.SignatureProtectionEnabled() {
			return fmt.Errorf("cmp.enabled is true but no cmp.secrets are configured and cmp.allow_signature_protection is false")
		}
		for i, s := range c.CMP.Secrets {
			if s.Reference == "" {
				return fmt.Errorf("cmp.secrets[%d]: reference must not be empty", i)
			}
			if s.Secret == "" {
				return fmt.Errorf("cmp.secrets[%d]: secret must not be empty", i)
			}
		}
	}
	if err := c.Secret.Escrow.validate(); err != nil {
		return err
	}
	return nil
}

// validate checks an escrow configuration for internal consistency. It enforces
// dual control (threshold >= 2), a threshold no greater than the number of
// agents, unique agent IDs and key labels, and that every agent resolves to a
// public-key source.
func (e *EscrowConfig) validate() error {
	if !e.Enabled {
		return nil
	}
	if e.Threshold < 2 {
		return fmt.Errorf("secret.escrow.threshold must be at least 2 for dual control (got %d)", e.Threshold)
	}
	if len(e.Agents) < e.Threshold {
		return fmt.Errorf("secret.escrow: %d recovery agent(s) configured but threshold is %d", len(e.Agents), e.Threshold)
	}
	seenID := make(map[string]bool, len(e.Agents))
	seenLabel := make(map[string]bool, len(e.Agents))
	for i, a := range e.Agents {
		if a.ID == "" {
			return fmt.Errorf("secret.escrow.agents[%d]: id must not be empty", i)
		}
		if seenID[a.ID] {
			return fmt.Errorf("secret.escrow.agents: duplicate id %q", a.ID)
		}
		seenID[a.ID] = true
		if a.KeyLabel == "" && a.PublicKey == "" && a.PublicKeyFile == "" {
			return fmt.Errorf("secret.escrow.agents[%q]: set key_label, public_key, or public_key_file", a.ID)
		}
		if a.KeyLabel != "" {
			if seenLabel[a.KeyLabel] {
				return fmt.Errorf("secret.escrow.agents: duplicate key_label %q", a.KeyLabel)
			}
			seenLabel[a.KeyLabel] = true
		}
	}
	return nil
}

// parseOID parses a dotted-decimal OID string into an asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("an OID needs at least two arcs")
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid arc %q", p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

// validateMonitor applies defaults and sanity-checks the expiry-monitor config
// when it is enabled, so a misconfiguration fails loudly at startup.
func (c *Config) validateMonitor() error {
	m := &c.Monitor
	if m.WarningDays == 0 {
		m.WarningDays = 30
	}
	if m.CriticalDays == 0 {
		m.CriticalDays = 7
	}
	if m.IntervalHours == 0 {
		m.IntervalHours = 12
	}
	if m.RenewBeforeDays == 0 {
		m.RenewBeforeDays = m.CriticalDays
	}
	if m.RotateBeforeDays == 0 {
		// Intermediate keys are long-lived; rotate well ahead of expiry, defaulting
		// to the (typically larger) warning window rather than the leaf threshold.
		m.RotateBeforeDays = m.WarningDays
	}
	if !m.Enabled {
		return nil
	}
	if m.WarningDays < 0 || m.CriticalDays < 0 || m.RenewBeforeDays < 0 || m.RotateBeforeDays < 0 {
		return fmt.Errorf("monitor: day thresholds must be non-negative")
	}
	if m.CriticalDays > m.WarningDays {
		return fmt.Errorf("monitor.critical_days (%d) must not exceed monitor.warning_days (%d)", m.CriticalDays, m.WarningDays)
	}
	if m.IntervalHours <= 0 {
		return fmt.Errorf("monitor.interval_hours must be positive")
	}
	for i, n := range m.Notifications {
		switch n.Type {
		case "log":
		case "webhook":
			if n.URL == "" {
				return fmt.Errorf("monitor.notifications[%d]: webhook sink requires a url", i)
			}
		default:
			return fmt.Errorf("monitor.notifications[%d]: unknown type %q (valid: log, webhook)", i, n.Type)
		}
		switch n.MinSeverity {
		case "", "warning", "critical", "expired":
		default:
			return fmt.Errorf("monitor.notifications[%d]: invalid min_severity %q (valid: warning, critical, expired)", i, n.MinSeverity)
		}
	}
	return nil
}

// validateCanary sanity-checks the synthetic issuance-canary configuration
// when it is enabled. The probed CAs must be listed explicitly: the canary
// issues (and revokes) real certificates and consumes tenant quota, so opting
// a CA in is a deliberate choice.
func (c *Config) validateCanary() error {
	cn := &c.Canary
	if !cn.Enabled {
		return nil
	}
	if len(cn.CAs) == 0 {
		return fmt.Errorf("canary.enabled is true but canary.cas is empty; list the CAs to probe by id or label")
	}
	for i, ref := range cn.CAs {
		if strings.TrimSpace(ref) == "" {
			return fmt.Errorf("canary.cas[%d] is empty", i)
		}
	}
	if cn.IntervalMinutes < 0 {
		return fmt.Errorf("canary.interval_minutes must be positive")
	}
	if cn.TimeoutSeconds < 0 {
		return fmt.Errorf("canary.timeout_seconds must be positive")
	}
	if cn.Timeout() >= cn.Interval() {
		return fmt.Errorf("canary.timeout_seconds (%s) must be shorter than canary.interval_minutes (%s)", cn.Timeout(), cn.Interval())
	}
	return nil
}

// validateACME sanity-checks the ACME configuration when it is enabled.
func (c *Config) validateACME() error {
	if !c.ACME.Enabled {
		return nil
	}
	if c.ACME.CAID == "" && c.ACME.CALabel == "" {
		return fmt.Errorf("acme.enabled is true but neither acme.ca_id nor acme.ca_label is set")
	}
	for _, ct := range c.ACME.ChallengeTypes {
		if ct != "http-01" && ct != "dns-01" {
			return fmt.Errorf("acme.challenge_types: unsupported challenge type %q (valid: http-01, dns-01)", ct)
		}
	}
	if c.ACME.RequireEAB && len(c.ACME.EABHMACKeys) == 0 {
		return fmt.Errorf("acme.require_eab is true but no acme.eab_hmac_keys are configured")
	}
	return nil
}

// validRoleNames are the role identifiers accepted in the rbac config. Kept in
// sync with the rbac package (duplicated here to avoid an import cycle risk and
// to keep config self-contained).
var validRoleNames = map[string]bool{"admin": true, "issuer": true, "signer": true, "auditor": true}

// validateRBAC rejects unknown role names so a misconfiguration fails loudly at
// startup rather than silently dropping an intended grant.
func (c *Config) validateRBAC() error {
	check := func(kind string, m map[string][]string) error {
		for key, roles := range m {
			for _, r := range roles {
				if !validRoleNames[r] {
					return fmt.Errorf("rbac.%s[%q]: unknown role %q (valid: admin, issuer, signer, auditor)", kind, key, r)
				}
			}
		}
		return nil
	}
	if err := check("subjects", c.RBAC.Subjects); err != nil {
		return err
	}
	if err := check("groups", c.RBAC.Groups); err != nil {
		return err
	}
	return c.validateTenants(check)
}

// validateTenants rejects duplicate/reserved tenant identifiers and unknown
// role names in per-tenant RBAC assignments, so a misconfigured tenant fails
// loudly at startup.
func (c *Config) validateTenants(checkRoles func(string, map[string][]string) error) error {
	seenID := map[string]bool{}
	seenSlug := map[string]bool{}
	for i, t := range c.Tenants {
		if t.ID == "" {
			return fmt.Errorf("tenants[%d]: id is required", i)
		}
		slug := t.Slug
		if slug == "" {
			slug = t.ID
		}
		if seenID[t.ID] {
			return fmt.Errorf("tenants[%d]: duplicate tenant id %q", i, t.ID)
		}
		if seenSlug[slug] {
			return fmt.Errorf("tenants[%d]: duplicate tenant slug %q", i, slug)
		}
		seenID[t.ID] = true
		seenSlug[slug] = true
		if err := checkRoles(fmt.Sprintf("tenants[%q].rbac.subjects", t.ID), t.RBAC.Subjects); err != nil {
			return err
		}
		if err := checkRoles(fmt.Sprintf("tenants[%q].rbac.groups", t.ID), t.RBAC.Groups); err != nil {
			return err
		}
	}
	return nil
}

// applyEnvOverrides lets environment variables override file settings. The
// SECSY_* names match those emitted by scripts/setup-softhsm.sh --export-env,
// so a developer can point the server at a SoftHSM token without editing YAML.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SECSY_KEY_PROVIDER"); v != "" {
		cfg.KeyProvider.Type = v
	}
	if v := os.Getenv("SECSY_PKCS11_MODULE"); v != "" {
		cfg.PKCS11.ModulePath = v
	}
	if v := os.Getenv("SECSY_TOKEN_LABEL"); v != "" {
		cfg.PKCS11.TokenLabel = v
	}
	if v := os.Getenv("SECSY_USER_PIN"); v != "" {
		cfg.PKCS11.Pin = v
	}
	// Cloud-KMS backend selection. The vault URL and region are non-secret and may
	// come from the environment; credentials are never taken from config and are
	// resolved by the cloud SDK's default chain (env, workload identity, etc.).
	if v := os.Getenv("SECSY_KMS_BACKEND"); v != "" {
		cfg.KeyProvider.KMS.Backend = v
	}
	if v := os.Getenv("SECSY_KMS_REGION"); v != "" {
		cfg.KeyProvider.KMS.Region = v
	}
	if v := os.Getenv("SECSY_KMS_KEY_PREFIX"); v != "" {
		cfg.KeyProvider.KMS.KeyPrefix = v
	}
	if v := os.Getenv("SECSY_KMS_VAULT_URL"); v != "" {
		cfg.KeyProvider.KMS.VaultURL = v
	}
	if v := os.Getenv("SECSY_KEY_PROVIDER_CA"); v != "" {
		cfg.KeyProvider.Roles.CA = v
	}
	if v := os.Getenv("SECSY_KEY_PROVIDER_TSA"); v != "" {
		cfg.KeyProvider.Roles.TSA = v
	}
	if v := os.Getenv("SECSY_KEY_PROVIDER_SIGNING"); v != "" {
		cfg.KeyProvider.Roles.Signing = v
	}
	// The built-in root password is a credential and must not live in a config
	// file or ConfigMap. Allow it to be injected from the environment (e.g. a
	// Kubernetes Secret) so deployments can keep it out of version control.
	if v := os.Getenv("SECSY_ROOT_PASSWORD"); v != "" {
		cfg.RootUser.Password = v
	}
	// Database selection and — importantly — the DSN can be injected from the
	// environment. For an external PostgreSQL the DSN embeds credentials, so it is
	// sourced from a Secret via SECSY_DATABASE_DSN rather than the ConfigMap. The
	// pool knobs are also overridable so operators can size the pool per replica
	// count without re-rendering config.
	if v := os.Getenv("SECSY_DATABASE_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("SECSY_DATABASE_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("SECSY_DATABASE_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Database.MaxOpenConns = n
		}
	}
	if v := os.Getenv("SECSY_DATABASE_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Database.MaxIdleConns = n
		}
	}
	if v := os.Getenv("SECSY_TOKEN_SERIAL"); v != "" {
		cfg.PKCS11.TokenSerial = v
	}
	if v := os.Getenv("SECSY_PKCS11_SESSION_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PKCS11.SessionPoolSize = n
		}
	}
	// Multi-token HA tuning. The token list itself is file-only (it is a list),
	// but the selection policy and failover threshold are overridable so operators
	// can retune per environment without re-rendering the token block.
	if v := os.Getenv("SECSY_PKCS11_SELECTION_POLICY"); v != "" {
		cfg.PKCS11.SelectionPolicy = v
	}
	if v := os.Getenv("SECSY_PKCS11_FAILURE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PKCS11.FailureThreshold = n
		}
	}
	if v := os.Getenv("SECSY_SOFTWARE_KEYSTORE_DIR"); v != "" {
		cfg.KeyProvider.Software.KeystoreDir = v
	}
	if v := os.Getenv("SECSY_SECRET_KEK_LABEL"); v != "" {
		cfg.Secret.KEKLabel = v
	}
	// ACME overrides — convenient for the SoftHSM integration harness, which
	// enables ACME against a freshly created CA and validates on a high port.
	if v := os.Getenv("SECSY_ACME_ENABLED"); v == "1" || v == "true" {
		cfg.ACME.Enabled = true
	}
	if v := os.Getenv("SECSY_ACME_CA_LABEL"); v != "" {
		cfg.ACME.CALabel = v
	}
	if v := os.Getenv("SECSY_ACME_BASE_URL"); v != "" {
		cfg.ACME.BaseURL = v
	}
	if v := os.Getenv("SECSY_ACME_HTTP01_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ACME.HTTP01Port = n
		}
	}
	// Monitor overrides — let the SoftHSM integration harness enable the
	// expiry monitor and auto-renewal without editing YAML.
	if v := os.Getenv("SECSY_MONITOR_ENABLED"); v == "1" || v == "true" {
		cfg.Monitor.Enabled = true
	}
	if v := os.Getenv("SECSY_MONITOR_AUTO_RENEW"); v == "1" || v == "true" {
		cfg.Monitor.AutoRenew = true
	}
	if v := os.Getenv("SECSY_MONITOR_ROTATE_INTERMEDIATES"); v == "1" || v == "true" {
		cfg.Monitor.RotateIntermediates = true
	}
}

// defaultKeyProvider fills in a sensible provider type and software defaults
// when none are configured, preserving the historical HSM-backed behavior.
func (c *Config) defaultKeyProvider() {
	if c.KeyProvider.Type == "" {
		switch {
		case c.PKCS11.ModulePath != "":
			c.KeyProvider.Type = "pkcs11"
		case c.KeyProvider.KMS.Backend != "":
			c.KeyProvider.Type = "kms"
		default:
			c.KeyProvider.Type = "software"
		}
	}
	if c.KeyProvider.Type == "software" && c.KeyProvider.Software.KeystoreDir == "" {
		c.KeyProvider.Software.KeystoreDir = "keystore"
	}
}

// validateKeyProvider ensures the selected provider — and every configured
// per-role override — has the settings it needs.
func (c *Config) validateKeyProvider() error {
	if err := c.validateProviderType(c.KeyProvider.Type, "key_provider.type"); err != nil {
		return err
	}
	if role := c.KeyProvider.Roles.CA; role != "" {
		if err := c.validateProviderType(role, "key_provider.roles.ca"); err != nil {
			return err
		}
	}
	if role := c.KeyProvider.Roles.TSA; role != "" {
		if err := c.validateProviderType(role, "key_provider.roles.tsa"); err != nil {
			return err
		}
	}
	if role := c.KeyProvider.Roles.Signing; role != "" {
		if err := c.validateProviderType(role, "key_provider.roles.signing"); err != nil {
			return err
		}
	}
	return nil
}

// validateProviderType checks that a provider type is valid and its backend block
// is configured. field names the config path for error messages.
func (c *Config) validateProviderType(providerType, field string) error {
	switch providerType {
	case "software":
		if c.KeyProvider.Software.KeystoreDir == "" {
			return fmt.Errorf("key_provider.software.keystore_dir is required for the software provider")
		}
	case "pkcs11":
		if c.PKCS11.ModulePath == "" {
			return fmt.Errorf("pkcs11.module_path is required for the pkcs11 provider")
		}
		if err := c.validatePKCS11HA(); err != nil {
			return err
		}
	case "kms":
		switch c.KeyProvider.KMS.Backend {
		case "aws", "fake":
			// AWS region is resolved by the SDK when unset; nothing else required.
		case "azure":
			if c.KeyProvider.KMS.VaultURL == "" {
				return fmt.Errorf("key_provider.kms.vault_url is required for the azure kms backend")
			}
		case "":
			return fmt.Errorf("key_provider.kms.backend is required for the kms provider (aws, azure, or fake)")
		default:
			return fmt.Errorf("key_provider.kms.backend %q is invalid (must be \"aws\", \"azure\", or \"fake\")", c.KeyProvider.KMS.Backend)
		}
	default:
		return fmt.Errorf("%s %q is invalid (must be \"pkcs11\", \"software\", or \"kms\")", field, providerType)
	}
	return nil
}

// validatePKCS11HA checks the optional multi-token high-availability settings.
// It is a no-op when no tokens are configured (single-token mode).
func (c *Config) validatePKCS11HA() error {
	if len(c.PKCS11.Tokens) == 0 {
		return nil
	}
	switch c.PKCS11.SelectionPolicy {
	case "", "primary-backup", "round-robin":
		// ok
	default:
		return fmt.Errorf("pkcs11.selection_policy %q is invalid (must be \"primary-backup\" or \"round-robin\")",
			c.PKCS11.SelectionPolicy)
	}
	names := make(map[string]bool, len(c.PKCS11.Tokens))
	for i, tok := range c.PKCS11.Tokens {
		if tok.TokenLabel == "" && tok.TokenSerial == "" {
			return fmt.Errorf("pkcs11.tokens[%d] requires a token_label or token_serial", i)
		}
		name := tok.Name
		if name == "" {
			name = tok.TokenLabel
		}
		if name != "" {
			if names[name] {
				return fmt.Errorf("pkcs11.tokens has a duplicate token name %q", name)
			}
			names[name] = true
		}
	}
	return nil
}

// KeyProviderTypeForRole returns the resolved backend type for a signing role
// ("ca", "tsa", or "signing"), applying the per-role override when set and
// otherwise falling back to the global key_provider.type.
func (c *Config) KeyProviderTypeForRole(role string) string {
	switch role {
	case "ca":
		if c.KeyProvider.Roles.CA != "" {
			return c.KeyProvider.Roles.CA
		}
	case "tsa":
		if c.KeyProvider.Roles.TSA != "" {
			return c.KeyProvider.Roles.TSA
		}
	case "signing":
		if c.KeyProvider.Roles.Signing != "" {
			return c.KeyProvider.Roles.Signing
		}
	}
	return c.KeyProvider.Type
}
