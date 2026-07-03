// Package sshca implements an HSM-backed OpenSSH certificate authority (Task
// 57) on the keyprovider abstraction: it signs OpenSSH user and host
// certificates with CA private keys that never leave the configured backend
// (PKCS#11 HSM, cloud KMS, or the software keystore), allocates serials from
// the store's per-CA monotonic counter, and publishes revocations as OpenSSH
// Key Revocation Lists (KRLs).
package sshca

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Certificate types, mirroring ssh.UserCert / ssh.HostCert as strings for
// profiles, requests, and stored records.
const (
	CertTypeUser = "user"
	CertTypeHost = "host"
)

// Profile is a named signing template constraining the SSH certificates a CA
// may mint: the certificate type, how long they are valid, which principals
// they may name, and which extensions and critical options they carry. Profiles
// let an operator offer distinct, auditable certificate shapes (interactive
// user, CI automation, host) without callers hand-crafting permissions per
// request.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// CertType is "user" or "host"; a request signed under this profile must ask
	// for the same type.
	CertType string `json:"cert_type"`
	// DefaultValidity is applied when a request does not specify one.
	DefaultValidity time.Duration `json:"-"`
	// MaxValidity caps the validity a request may ask for; longer requests are
	// clamped (matching the X.509 profile convention). Zero means uncapped.
	MaxValidity time.Duration `json:"-"`
	// DefaultValiditySecs / MaxValiditySecs mirror the durations for JSON.
	DefaultValiditySecs int64 `json:"default_validity_secs"`
	MaxValiditySecs     int64 `json:"max_validity_secs"`
	// AllowedPrincipals restricts the principals a certificate may name, as
	// glob patterns (path.Match syntax: "deploy-*", "*.internal.example.com").
	// Empty permits any principal.
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	// AllowEmptyPrincipals permits signing a certificate that names no
	// principals. OpenSSH treats such a certificate as valid for EVERY user or
	// host, so this is off by default and must be a deliberate choice.
	AllowEmptyPrincipals bool `json:"allow_empty_principals,omitempty"`
	// MaxPrincipals caps how many principals one certificate may name. Zero
	// means uncapped.
	MaxPrincipals int `json:"max_principals,omitempty"`
	// DefaultExtensions are applied when a request specifies none. For user
	// certificates this is typically the standard permit-* set; host
	// certificates carry no extensions.
	DefaultExtensions map[string]string `json:"default_extensions,omitempty"`
	// AllowedExtensions is the allowlist for request-supplied extensions, in
	// addition to the keys of DefaultExtensions (which are always permitted).
	// A request asking for an extension outside the allowlist is refused.
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	// DefaultCriticalOptions are applied when a request specifies none (e.g. a
	// profile may pin force-command for automation certificates).
	DefaultCriticalOptions map[string]string `json:"default_critical_options,omitempty"`
	// AllowedCriticalOptions is the allowlist for request-supplied critical
	// options, in addition to the keys of DefaultCriticalOptions.
	AllowedCriticalOptions []string `json:"allowed_critical_options,omitempty"`
}

// standardUserExtensions is the ssh-keygen default extension set for user
// certificates, granting an interactive session with forwarding.
func standardUserExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}

// builtinProfiles are the SSH signing profiles available out of the box, keyed
// by (lowercase) name.
var builtinProfiles = map[string]Profile{
	"user-default": {
		Name:              "user-default",
		Description:       "Interactive user certificate (standard permit-* extensions)",
		CertType:          CertTypeUser,
		DefaultValidity:   12 * time.Hour,
		MaxValidity:       30 * 24 * time.Hour,
		DefaultExtensions: standardUserExtensions(),
		AllowedCriticalOptions: []string{
			"source-address", "force-command", "verify-required",
		},
	},
	"host-default": {
		Name:            "host-default",
		Description:     "Host certificate (no extensions or critical options)",
		CertType:        CertTypeHost,
		DefaultValidity: 90 * 24 * time.Hour,
		MaxValidity:     366 * 24 * time.Hour,
	},
}

// customProfiles holds operator-defined profiles installed from central
// configuration (ssh.profiles). They overlay the built-ins by name.
var customProfiles = map[string]Profile{}

// SetCustomProfiles validates and installs operator-defined SSH profiles,
// replacing any previously installed set. A profile whose name matches a
// built-in overrides it.
func SetCustomProfiles(profiles []Profile) error {
	next := make(map[string]Profile, len(profiles))
	for _, p := range profiles {
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if key == "" {
			return fmt.Errorf("ssh profile with empty name")
		}
		if _, dup := next[key]; dup {
			return fmt.Errorf("duplicate ssh profile name %q", key)
		}
		p.Name = key
		if err := p.validate(); err != nil {
			return err
		}
		next[key] = p
	}
	customProfiles = next
	return nil
}

func (p Profile) validate() error {
	switch p.CertType {
	case CertTypeUser:
		// Any extension/critical-option shape is meaningful for user certs.
	case CertTypeHost:
		// OpenSSH ignores extensions and refuses critical options on host
		// certificates; a profile carrying them is a configuration error.
		if len(p.DefaultExtensions) > 0 || len(p.AllowedExtensions) > 0 {
			return fmt.Errorf("ssh profile %q: host certificates cannot carry extensions", p.Name)
		}
		if len(p.DefaultCriticalOptions) > 0 || len(p.AllowedCriticalOptions) > 0 {
			return fmt.Errorf("ssh profile %q: host certificates cannot carry critical options", p.Name)
		}
	default:
		return fmt.Errorf("ssh profile %q: cert_type must be %q or %q, got %q",
			p.Name, CertTypeUser, CertTypeHost, p.CertType)
	}
	if p.DefaultValidity <= 0 {
		return fmt.Errorf("ssh profile %q: default_validity is required", p.Name)
	}
	if p.MaxValidity > 0 && p.DefaultValidity > p.MaxValidity {
		return fmt.Errorf("ssh profile %q: default_validity exceeds max_validity", p.Name)
	}
	if p.MaxPrincipals < 0 {
		return fmt.Errorf("ssh profile %q: max_principals cannot be negative", p.Name)
	}
	for _, pattern := range p.AllowedPrincipals {
		if _, err := path.Match(pattern, "probe"); err != nil {
			return fmt.Errorf("ssh profile %q: invalid principal pattern %q: %v", p.Name, pattern, err)
		}
	}
	return nil
}

// LookupProfile resolves a profile by name (case-insensitive), custom profiles
// taking precedence over built-ins.
func LookupProfile(name string) (Profile, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if p, ok := customProfiles[key]; ok {
		p.fillValiditySecs()
		return p, nil
	}
	if p, ok := builtinProfiles[key]; ok {
		p.fillValiditySecs()
		return p, nil
	}
	return Profile{}, fmt.Errorf("unknown ssh profile %q (available: %s)",
		name, strings.Join(ProfileNames(), ", "))
}

// DefaultProfileName returns the built-in default profile name for a
// certificate type.
func DefaultProfileName(certType string) string {
	if certType == CertTypeHost {
		return "host-default"
	}
	return "user-default"
}

// Profiles returns every effective profile (built-in + custom), sorted by name.
func Profiles() []Profile {
	merged := make(map[string]Profile, len(builtinProfiles)+len(customProfiles))
	for k, v := range builtinProfiles {
		merged[k] = v
	}
	for k, v := range customProfiles {
		merged[k] = v
	}
	out := make([]Profile, 0, len(merged))
	for _, p := range merged {
		p.fillValiditySecs()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProfileNames returns the sorted list of effective profile names.
func ProfileNames() []string {
	names := make([]string, 0, len(builtinProfiles)+len(customProfiles))
	seen := map[string]bool{}
	for name := range builtinProfiles {
		seen[name] = true
		names = append(names, name)
	}
	for name := range customProfiles {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// fillValiditySecs populates the *Secs JSON fields from the durations.
func (p *Profile) fillValiditySecs() {
	p.DefaultValiditySecs = int64(p.DefaultValidity / time.Second)
	p.MaxValiditySecs = int64(p.MaxValidity / time.Second)
}

// resolveValidity clamps a requested validity to the profile's bounds. A
// non-positive request falls back to the profile default.
func (p Profile) resolveValidity(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = p.DefaultValidity
	}
	if p.MaxValidity > 0 && requested > p.MaxValidity {
		requested = p.MaxValidity
	}
	return requested
}

// checkPrincipals enforces the profile's principal policy on a request.
func (p Profile) checkPrincipals(principals []string) error {
	if len(principals) == 0 {
		if p.AllowEmptyPrincipals {
			return nil
		}
		return fmt.Errorf("profile %q requires at least one principal (a certificate without principals is valid for every %s)",
			p.Name, p.CertType)
	}
	if p.MaxPrincipals > 0 && len(principals) > p.MaxPrincipals {
		return fmt.Errorf("profile %q permits at most %d principals, got %d",
			p.Name, p.MaxPrincipals, len(principals))
	}
	for _, principal := range principals {
		if strings.TrimSpace(principal) == "" {
			return fmt.Errorf("empty principal")
		}
		if len(p.AllowedPrincipals) == 0 {
			continue
		}
		allowed := false
		for _, pattern := range p.AllowedPrincipals {
			if ok, _ := path.Match(pattern, principal); ok || pattern == principal {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("principal %q is not permitted by profile %q (allowed: %s)",
				principal, p.Name, strings.Join(p.AllowedPrincipals, ", "))
		}
	}
	return nil
}

// resolvePermissions merges the request's extensions and critical options with
// the profile's defaults and allowlists. Nil/empty request maps take the
// profile defaults; a non-empty request map replaces the defaults entirely but
// every key must be permitted (a default key or in the allowlist).
func (p Profile) resolvePermissions(reqExtensions, reqCriticalOptions map[string]string) (extensions, criticalOptions map[string]string, err error) {
	extensions, err = p.resolvePermissionMap("extension", reqExtensions, p.DefaultExtensions, p.AllowedExtensions)
	if err != nil {
		return nil, nil, err
	}
	criticalOptions, err = p.resolvePermissionMap("critical option", reqCriticalOptions, p.DefaultCriticalOptions, p.AllowedCriticalOptions)
	if err != nil {
		return nil, nil, err
	}
	return extensions, criticalOptions, nil
}

func (p Profile) resolvePermissionMap(kind string, requested, defaults map[string]string, allowlist []string) (map[string]string, error) {
	if len(requested) == 0 {
		if len(defaults) == 0 {
			return nil, nil
		}
		out := make(map[string]string, len(defaults))
		for k, v := range defaults {
			out[k] = v
		}
		return out, nil
	}
	permitted := make(map[string]bool, len(defaults)+len(allowlist))
	for k := range defaults {
		permitted[k] = true
	}
	for _, k := range allowlist {
		permitted[k] = true
	}
	out := make(map[string]string, len(requested))
	for k, v := range requested {
		if !permitted[k] {
			return nil, fmt.Errorf("%s %q is not permitted by profile %q", kind, k, p.Name)
		}
		out[k] = v
	}
	return out, nil
}

// ParseValidity parses a human-friendly validity: a Go duration ("36h",
// "90m"), or a value with a day ("30d") or week ("12w") suffix.
func ParseValidity(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n := len(s); n > 1 {
		if unit := s[n-1]; unit == 'd' || unit == 'w' {
			v, err := strconv.ParseInt(s[:n-1], 10, 64)
			if err == nil && v > 0 {
				if unit == 'd' {
					return time.Duration(v) * 24 * time.Hour, nil
				}
				return time.Duration(v) * 7 * 24 * time.Hour, nil
			}
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid validity %q (use a Go duration like 12h, or 30d / 12w)", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("validity must be positive, got %q", s)
	}
	return d, nil
}
