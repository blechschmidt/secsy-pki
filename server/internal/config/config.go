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

	return cfg, nil
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
