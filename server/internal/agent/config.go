// Package agent implements the secsy-agent host auto-enrollment client: a
// lightweight daemon that keeps host/service certificates fresh by enrolling
// against a secsy-pki server's EST or ACME endpoints. Private keys are
// generated locally and never leave the host; renewal timing is driven by ACME
// Renewal Information (ARI) when available and otherwise by a
// fraction-of-lifetime rule with deterministic per-certificate jitter, matching
// the server-side monitor's storm-prevention philosophy. New material is
// installed atomically (temp file + rename) only after the chain verifies
// against the configured trust bundle, and a post-renew reload hook tells the
// consuming service to pick it up, rolling the files back if the hook fails.
package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from YAML strings like "12h" or
// "90s" (yaml.v3 has no native duration support).
type Duration time.Duration

// UnmarshalYAML parses a Go duration string (or a bare integer, taken as
// seconds for convenience).
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw == "" {
		*d = 0
		return nil
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		*d = Duration(time.Duration(secs) * time.Second)
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML renders the duration back as a Go duration string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// FileMode is an octal permission string such as "0600".
type FileMode fs.FileMode

// UnmarshalYAML parses an octal mode string ("0600", "600", "0o644").
func (m *FileMode) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0o"), "0O")
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid file mode %q (want octal like \"0600\"): %w", raw, err)
	}
	if v&^uint64(fs.ModePerm) != 0 {
		return fmt.Errorf("invalid file mode %q: only permission bits are allowed", raw)
	}
	*m = FileMode(v)
	return nil
}

// Config is the declarative secsy-agent configuration, normally loaded from
// /etc/secsy/agent.yaml. Unknown keys are rejected so a typo cannot silently
// disable a renewal.
type Config struct {
	// StateDir holds agent state: state.json (renewal bookkeeping) and the ACME
	// account key. Created 0700 on first use.
	StateDir string `yaml:"state_dir"`

	Server  ServerConfig  `yaml:"server"`
	Trust   TrustConfig   `yaml:"trust"`
	ACME    ACMEConfig    `yaml:"acme"`
	EST     ESTConfig     `yaml:"est"`
	Renewal RenewalConfig `yaml:"renewal"`
	Metrics MetricsConfig `yaml:"metrics"`

	Certificates []*CertSpec `yaml:"certificates"`
}

// ServerConfig controls how the agent talks to the PKI server itself.
type ServerConfig struct {
	// TLSCAFile adds PEM roots trusted for the *server's* TLS certificate (on
	// top of the system pool). This is transport trust, distinct from the trust
	// bundle used to verify issued chains.
	TLSCAFile string `yaml:"tls_ca_file"`
	// InsecureSkipVerify disables TLS verification of the server. Lab use only.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// Timeout bounds each HTTP request to the server (default 30s).
	Timeout Duration `yaml:"timeout"`
}

// TrustConfig locates the trust anchors used to verify newly issued chains
// before they are installed. Exactly one source is required: a pre-provisioned
// PEM file, an explicit URL, or (implicitly) the EST cacerts endpoint when EST
// is configured.
type TrustConfig struct {
	// BundleFile is a PEM file of trust anchors.
	BundleFile string `yaml:"bundle_file"`
	// BundleURL is fetched from the server; the body may be PEM or an EST-style
	// base64 certs-only PKCS#7. Defaults to <est.url>/cacerts when EST is
	// configured and no other source is given.
	BundleURL string `yaml:"bundle_url"`
	// RefreshInterval is how often a fetched bundle is re-fetched in daemon mode
	// (default 24h; file bundles are re-read every pass).
	RefreshInterval Duration `yaml:"refresh_interval"`
}

// ACMEConfig configures enrollment through the server's RFC 8555 endpoint.
type ACMEConfig struct {
	// Directory is the ACME directory URL, e.g.
	// https://pki.example.com/acme/directory.
	Directory string `yaml:"directory"`
	// Contact is the account contact list (e.g. ["mailto:ops@example.com"]).
	Contact []string `yaml:"contact"`
	// EABKid / EABHMACKey present External Account Binding credentials during
	// account registration (required when the server sets acme.require_eab).
	// The key is base64url (padded or raw; standard base64 is also accepted).
	EABKid     string `yaml:"eab_kid"`
	EABHMACKey string `yaml:"eab_hmac_key"`
	// EABHMACKeyFile reads the HMAC key from a file instead (trailing
	// whitespace trimmed), keeping the secret out of the config file.
	EABHMACKeyFile string       `yaml:"eab_hmac_key_file"`
	HTTP01         HTTP01Config `yaml:"http01"`
}

// HTTP01Config selects how the agent answers http-01 challenges. Exactly one
// mode is used: a built-in listener (default ":80") or a webroot directory
// served by an existing web server.
type HTTP01Config struct {
	// Listen is the address the built-in solver binds while a challenge is
	// active (default ":80"; port 80 is what the server dials per RFC 8555).
	Listen string `yaml:"listen"`
	// Webroot, when set, writes key authorizations under
	// <webroot>/.well-known/acme-challenge/ instead of listening.
	Webroot string `yaml:"webroot"`
}

// ESTConfig configures enrollment through the server's RFC 7030 endpoint.
type ESTConfig struct {
	// URL is the EST base, e.g. https://pki.example.com/.well-known/est
	// (include any CA label segment the server mounts).
	URL string `yaml:"url"`
	// Username/Password are the operator-provisioned Basic-auth bootstrap
	// credentials.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PasswordFile reads the password from a file (trailing whitespace
	// trimmed), keeping the secret out of the config file.
	PasswordFile string `yaml:"password_file"`
}

// RenewalConfig tunes when certificates are renewed and how often the daemon
// re-evaluates. Per-certificate overrides live on CertSpec.
type RenewalConfig struct {
	// Fraction of the certificate lifetime after which renewal is due when ARI
	// is unavailable (default 2/3, the classic renew-at-two-thirds rule).
	Fraction float64 `yaml:"fraction"`
	// Jitter widens the renewal point by up to this extra fraction of the
	// lifetime. The offset is derived deterministically from the certificate
	// serial, so a fleet issued in one batch spreads its renewals without the
	// schedule moving between agent restarts (default 0.04).
	Jitter float64 `yaml:"jitter"`
	// CheckInterval is the daemon's evaluation cadence (default 5m).
	CheckInterval Duration `yaml:"check_interval"`
	// DisableARI turns off ACME Renewal Information scheduling, forcing the
	// fraction-of-lifetime rule even for ACME certificates.
	DisableARI bool `yaml:"disable_ari"`
}

// MetricsConfig exposes agent metrics for Prometheus.
type MetricsConfig struct {
	// Textfile, when set, atomically (re)writes a node_exporter
	// textfile-collector .prom file after every pass.
	Textfile string `yaml:"textfile"`
	// Listen, when set, serves /metrics on this address in daemon mode
	// (e.g. "127.0.0.1:9930").
	Listen string `yaml:"listen"`
}

// CertSpec declares one certificate the agent keeps fresh.
type CertSpec struct {
	// Name identifies the spec in state, logs, and metric labels.
	Name string `yaml:"name"`
	// Enroll selects the enrollment protocol: "acme" or "est".
	Enroll string `yaml:"enroll"`
	// CommonName defaults to the first DNS name.
	CommonName string `yaml:"common_name"`
	// DNSNames / IPAddresses are the requested SANs. At least one is required.
	DNSNames    []string `yaml:"dns_names"`
	IPAddresses []string `yaml:"ip_addresses"`
	// KeyType of the locally generated key: ecdsa-p256 (default), ecdsa-p384,
	// rsa-2048, rsa-3072, or rsa-4096. "auto" defers the choice to the EST
	// server's /csrattrs advertisement (RFC 7030 §4.5), falling back to
	// ecdsa-p256 when none is advertised.
	KeyType string `yaml:"key_type"`
	// Validity, when set, is requested as the ACME order's notAfter. The server
	// profile may cap it. EST ignores it (the server profile decides).
	Validity Duration `yaml:"validity"`

	// Output paths. KeyFile and CertFile (leaf only) are required. ChainFile
	// receives the issuer chain without the leaf; FullchainFile the leaf plus
	// issuers (nginx-style).
	KeyFile       string `yaml:"key_file"`
	CertFile      string `yaml:"cert_file"`
	ChainFile     string `yaml:"chain_file"`
	FullchainFile string `yaml:"fullchain_file"`

	// Owner is "user:group" applied to every written file (requires privilege;
	// empty leaves the agent's default ownership).
	Owner string `yaml:"owner"`
	// KeyMode/CertMode are the file modes (defaults 0600 / 0644). Chain and
	// fullchain files use CertMode.
	KeyMode  FileMode `yaml:"key_mode"`
	CertMode FileMode `yaml:"cert_mode"`

	// Renewal overrides the global fraction/jitter for this certificate.
	Renewal *RenewalOverride `yaml:"renewal"`
	// Reload is run after a successful install so the consuming service picks
	// up the new material.
	Reload *ReloadConfig `yaml:"reload"`
}

// RenewalOverride carries per-certificate renewal tuning; zero fields inherit
// the global values.
type RenewalOverride struct {
	Fraction float64 `yaml:"fraction"`
	Jitter   float64 `yaml:"jitter"`
}

// ReloadConfig describes the post-renew hook: either a command or a signal to
// a pid-file process.
type ReloadConfig struct {
	// Command is executed after install. A YAML list is exec'd directly; a
	// plain string runs under "sh -c".
	Command CommandLine `yaml:"command"`
	// Signal ("HUP", "SIGUSR1", ...) is sent to the process whose PID is in
	// PIDFile. Mutually exclusive with Command.
	Signal  string `yaml:"signal"`
	PIDFile string `yaml:"pid_file"`
	// Timeout bounds hook execution (default 30s). A hook that exceeds it is
	// killed and treated as failed.
	Timeout Duration `yaml:"timeout"`
}

// CommandLine accepts either a YAML sequence (argv, exec'd directly) or a
// scalar string (run via "sh -c").
type CommandLine []string

// UnmarshalYAML implements the dual string/list form.
func (c *CommandLine) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var argv []string
		if err := node.Decode(&argv); err != nil {
			return err
		}
		*c = argv
		return nil
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			*c = nil
			return nil
		}
		*c = []string{"sh", "-c", s}
		return nil
	default:
		return fmt.Errorf("reload command must be a string or a list of arguments")
	}
}

// Enrollment protocol names accepted in CertSpec.Enroll.
const (
	EnrollACME = "acme"
	EnrollEST  = "est"
)

// Defaults applied by LoadConfig.
const (
	defaultFraction      = 2.0 / 3.0
	defaultJitter        = 0.04
	defaultCheckInterval = 5 * time.Minute
	defaultTrustRefresh  = 24 * time.Hour
	defaultHTTPTimeout   = 30 * time.Second
	defaultHookTimeout   = 30 * time.Second
	defaultKeyMode       = FileMode(0o600)
	defaultCertMode      = FileMode(0o644)
	defaultKeyType       = "ecdsa-p256"
)

// LoadConfig reads, strictly decodes, defaults, and validates an agent
// configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig decodes and validates a configuration from raw YAML.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Timeout <= 0 {
		c.Server.Timeout = Duration(defaultHTTPTimeout)
	}
	if c.Trust.RefreshInterval <= 0 {
		c.Trust.RefreshInterval = Duration(defaultTrustRefresh)
	}
	if c.Trust.BundleFile == "" && c.Trust.BundleURL == "" && c.EST.URL != "" {
		c.Trust.BundleURL = strings.TrimRight(c.EST.URL, "/") + "/cacerts"
	}
	if c.Renewal.Fraction == 0 {
		c.Renewal.Fraction = defaultFraction
	}
	if c.Renewal.Jitter == 0 {
		c.Renewal.Jitter = defaultJitter
	}
	if c.Renewal.CheckInterval <= 0 {
		c.Renewal.CheckInterval = Duration(defaultCheckInterval)
	}
	if c.ACME.HTTP01.Listen == "" && c.ACME.HTTP01.Webroot == "" {
		c.ACME.HTTP01.Listen = ":80"
	}
	for _, spec := range c.Certificates {
		if spec == nil {
			continue
		}
		if spec.KeyType == "" {
			spec.KeyType = defaultKeyType
		}
		if spec.CommonName == "" && len(spec.DNSNames) > 0 {
			spec.CommonName = spec.DNSNames[0]
		}
		if spec.KeyMode == 0 {
			spec.KeyMode = defaultKeyMode
		}
		if spec.CertMode == 0 {
			spec.CertMode = defaultCertMode
		}
		if spec.Reload != nil && spec.Reload.Timeout <= 0 {
			spec.Reload.Timeout = Duration(defaultHookTimeout)
		}
	}
}

// fraction and jitter return the effective renewal tuning for a spec.
func (c *Config) fraction(spec *CertSpec) float64 {
	if spec.Renewal != nil && spec.Renewal.Fraction > 0 {
		return spec.Renewal.Fraction
	}
	return c.Renewal.Fraction
}

func (c *Config) jitter(spec *CertSpec) float64 {
	if spec.Renewal != nil && spec.Renewal.Jitter > 0 {
		return spec.Renewal.Jitter
	}
	return c.Renewal.Jitter
}

func (c *Config) validate() error {
	if c.StateDir == "" {
		return fmt.Errorf("state_dir is required")
	}
	if len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate must be configured")
	}
	if f := c.Renewal.Fraction; f <= 0 || f >= 1 {
		return fmt.Errorf("renewal.fraction must be in (0, 1), got %v", f)
	}
	if j := c.Renewal.Jitter; j < 0 || j > 0.5 {
		return fmt.Errorf("renewal.jitter must be in [0, 0.5], got %v", j)
	}
	if c.ACME.EABHMACKey != "" && c.ACME.EABHMACKeyFile != "" {
		return fmt.Errorf("acme: eab_hmac_key and eab_hmac_key_file are mutually exclusive")
	}
	if c.EST.Password != "" && c.EST.PasswordFile != "" {
		return fmt.Errorf("est: password and password_file are mutually exclusive")
	}
	if c.Trust.BundleFile == "" && c.Trust.BundleURL == "" {
		return fmt.Errorf("trust: a bundle_file or bundle_url is required (issued chains are verified before install)")
	}

	seenNames := make(map[string]bool)
	seenPaths := make(map[string]string)
	for i, spec := range c.Certificates {
		if spec == nil {
			return fmt.Errorf("certificates[%d] is empty", i)
		}
		if err := c.validateSpec(spec); err != nil {
			return fmt.Errorf("certificate %q: %w", spec.Name, err)
		}
		if seenNames[spec.Name] {
			return fmt.Errorf("certificate name %q is used twice", spec.Name)
		}
		seenNames[spec.Name] = true
		for _, p := range spec.outputPaths() {
			clean := filepath.Clean(p)
			if owner, dup := seenPaths[clean]; dup {
				return fmt.Errorf("certificates %q and %q both write %s", owner, spec.Name, clean)
			}
			seenPaths[clean] = spec.Name
		}
	}
	return nil
}

func (c *Config) validateSpec(spec *CertSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("name is required")
	}
	if strings.ContainsAny(spec.Name, "/\\ \t\n\"") {
		return fmt.Errorf("name must not contain path separators, whitespace, or quotes")
	}
	switch spec.Enroll {
	case EnrollACME:
		if c.ACME.Directory == "" {
			return fmt.Errorf("enroll is acme but acme.directory is not configured")
		}
		for _, d := range spec.DNSNames {
			if strings.Contains(d, "*") {
				return fmt.Errorf("wildcard name %q cannot be enrolled via ACME http-01", d)
			}
		}
	case EnrollEST:
		if c.EST.URL == "" {
			return fmt.Errorf("enroll is est but est.url is not configured")
		}
	default:
		return fmt.Errorf("enroll must be %q or %q, got %q", EnrollACME, EnrollEST, spec.Enroll)
	}
	if len(spec.DNSNames) == 0 && len(spec.IPAddresses) == 0 {
		return fmt.Errorf("at least one of dns_names or ip_addresses is required")
	}
	if !isAutoKeyType(spec.KeyType) {
		if _, err := parseKeyType(spec.KeyType); err != nil {
			return err
		}
	}
	if spec.KeyFile == "" || spec.CertFile == "" {
		return fmt.Errorf("key_file and cert_file are required")
	}
	paths := spec.outputPaths()
	unique := make(map[string]bool, len(paths))
	for _, p := range paths {
		clean := filepath.Clean(p)
		if unique[clean] {
			return fmt.Errorf("output path %s is used twice", clean)
		}
		unique[clean] = true
	}
	if spec.Owner != "" {
		if _, _, err := parseOwner(spec.Owner); err != nil {
			return err
		}
	}
	if o := spec.Renewal; o != nil {
		if o.Fraction < 0 || o.Fraction >= 1 {
			return fmt.Errorf("renewal.fraction override must be in (0, 1), got %v", o.Fraction)
		}
		if o.Jitter < 0 || o.Jitter > 0.5 {
			return fmt.Errorf("renewal.jitter override must be in [0, 0.5], got %v", o.Jitter)
		}
	}
	if r := spec.Reload; r != nil {
		if len(r.Command) > 0 && r.Signal != "" {
			return fmt.Errorf("reload: command and signal are mutually exclusive")
		}
		if r.Signal != "" && r.PIDFile == "" {
			return fmt.Errorf("reload: signal requires pid_file")
		}
		if r.Signal == "" && r.PIDFile != "" {
			return fmt.Errorf("reload: pid_file requires signal")
		}
		if r.Signal != "" {
			if _, err := parseSignal(r.Signal); err != nil {
				return err
			}
		}
	}
	return nil
}

// outputPaths lists every file the spec writes, in install order.
func (s *CertSpec) outputPaths() []string {
	paths := []string{s.KeyFile, s.CertFile}
	if s.ChainFile != "" {
		paths = append(paths, s.ChainFile)
	}
	if s.FullchainFile != "" {
		paths = append(paths, s.FullchainFile)
	}
	return paths
}
