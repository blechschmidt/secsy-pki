package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
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
	// RBAC assigns organization-wide roles (admin/issuer/auditor) to subjects
	// and groups; Policy holds issuance guardrails; Profiles defines custom
	// certificate profiles layered over the built-ins. Together these give a
	// single, centralized place to govern who may do what and under which rules.
	RBAC     RBACConfig      `yaml:"rbac"`
	Policy   PolicyConfig    `yaml:"policy"`
	Profiles []ProfileConfig `yaml:"profiles"`
	// ACME configures the RFC 8555 automated-issuance server. Disabled unless
	// acme.enabled is true.
	ACME ACMEConfig `yaml:"acme"`
	// SCEP / EST configure the device-enrollment protocols (RFC 8894 / RFC 7030).
	// Disabled unless their .enabled is true.
	SCEP SCEPConfig `yaml:"scep"`
	EST  ESTConfig  `yaml:"est"`
	// Monitor configures the background certificate-expiry monitor and optional
	// auto-renewal workflow. Disabled unless monitor.enabled is true.
	Monitor MonitorConfig `yaml:"monitor"`
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

// AuditConfig groups audit-log settings; currently the SIEM export pipeline.
type AuditConfig struct {
	Export ExportConfig `yaml:"export"`
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
	// Notifications lists the sinks expiry warnings are dispatched to.
	Notifications []NotificationConfig `yaml:"notifications"`
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

// RBACConfig maps OIDC subjects and group IDs to role names. Recognized roles
// are "admin", "issuer", and "auditor"; unknown names are rejected at load so a
// typo cannot silently grant or deny access.
type RBACConfig struct {
	Subjects map[string][]string `yaml:"subjects"`
	Groups   map[string][]string `yaml:"groups"`
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
}

// SecretConfig configures the HSM-backed envelope-encryption feature. KEKLabel
// is the label of the RSA key-encryption key used to wrap data keys; it must
// exist in the configured key provider (create it with `secsy-secret init-kek`).
// When empty, the secret encrypt/decrypt API endpoints are disabled.
type SecretConfig struct {
	KEKLabel string `yaml:"kek_label"`
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
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
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
// PKCS#11 module is configured) or "software" (on-disk keystore).
type KeyProviderConfig struct {
	Type     string                 `yaml:"type"`
	Software SoftwareProviderConfig `yaml:"software"`
}

type SoftwareProviderConfig struct {
	KeystoreDir string `yaml:"keystore_dir"`
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
}

type YubiHSMConfig struct {
	ConnectorURL         string `yaml:"connector_url"`
	AuthKeyID            int    `yaml:"auth_key_id"`
	Password             string `yaml:"password"`
	SuppressAuditWarning bool   `yaml:"suppress_audit_warning"`
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

	if err := cfg.validateEnrollment(); err != nil {
		return nil, err
	}

	if err := cfg.validateAuditExport(); err != nil {
		return nil, err
	}

	if err := cfg.validateRateLimit(); err != nil {
		return nil, err
	}

	return cfg, nil
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
	return nil
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
var validRoleNames = map[string]bool{"admin": true, "issuer": true, "auditor": true}

// validateRBAC rejects unknown role names so a misconfiguration fails loudly at
// startup rather than silently dropping an intended grant.
func (c *Config) validateRBAC() error {
	check := func(kind string, m map[string][]string) error {
		for key, roles := range m {
			for _, r := range roles {
				if !validRoleNames[r] {
					return fmt.Errorf("rbac.%s[%q]: unknown role %q (valid: admin, issuer, auditor)", kind, key, r)
				}
			}
		}
		return nil
	}
	if err := check("subjects", c.RBAC.Subjects); err != nil {
		return err
	}
	return check("groups", c.RBAC.Groups)
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
	// The built-in root password is a credential and must not live in a config
	// file or ConfigMap. Allow it to be injected from the environment (e.g. a
	// Kubernetes Secret) so deployments can keep it out of version control.
	if v := os.Getenv("SECSY_ROOT_PASSWORD"); v != "" {
		cfg.RootUser.Password = v
	}
	if v := os.Getenv("SECSY_TOKEN_SERIAL"); v != "" {
		cfg.PKCS11.TokenSerial = v
	}
	if v := os.Getenv("SECSY_PKCS11_SESSION_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PKCS11.SessionPoolSize = n
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
		if c.PKCS11.ModulePath != "" {
			c.KeyProvider.Type = "pkcs11"
		} else {
			c.KeyProvider.Type = "software"
		}
	}
	if c.KeyProvider.Type == "software" && c.KeyProvider.Software.KeystoreDir == "" {
		c.KeyProvider.Software.KeystoreDir = "keystore"
	}
}

// validateKeyProvider ensures the selected provider has the settings it needs.
func (c *Config) validateKeyProvider() error {
	switch c.KeyProvider.Type {
	case "software":
		if c.KeyProvider.Software.KeystoreDir == "" {
			return fmt.Errorf("key_provider.software.keystore_dir is required for the software provider")
		}
	case "pkcs11":
		if c.PKCS11.ModulePath == "" {
			return fmt.Errorf("pkcs11.module_path is required for the pkcs11 provider")
		}
	default:
		return fmt.Errorf("key_provider.type %q is invalid (must be \"pkcs11\" or \"software\")", c.KeyProvider.Type)
	}
	return nil
}
