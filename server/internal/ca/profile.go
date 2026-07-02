package ca

import (
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Profile is a named issuance template constraining the certificates a CA may
// mint: which key usages and extended key usages they carry, how long they are
// valid, and whether they may themselves be CAs. Profiles let an operator offer
// distinct, auditable certificate shapes (TLS server, TLS client, code signing,
// …) without callers hand-crafting extensions per request.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// KeyUsages / ExtKeyUsages are the string identifiers understood by
	// pki.X509KeyUsageFromString / pki.X509ExtKeyUsageFromString.
	KeyUsages    []string `json:"key_usages"`
	ExtKeyUsages []string `json:"ext_key_usages"`
	// DefaultValidity is applied when a request does not specify one.
	DefaultValidity time.Duration `json:"-"`
	// MaxValidity caps the validity a request may ask for. Zero means uncapped.
	MaxValidity time.Duration `json:"-"`
	// DefaultValidityDays / MaxValidityDays mirror the durations above for JSON.
	DefaultValidityDays int `json:"default_validity_days"`
	MaxValidityDays     int `json:"max_validity_days"`
	// IsCA mints a subordinate CA certificate rather than a leaf. Reserved for
	// specialized profiles; ordinary leaf profiles leave it false.
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
	// CT is the profile's Certificate Transparency policy. Nil (or disabled)
	// means precertificate submission and SCT embedding are skipped.
	CT *CTConfig `json:"ct,omitempty"`
	// Lint is the profile's pre-issuance lint policy. Nil applies the default
	// gate (enforce mode, internal-name rules); see LintConfig.
	Lint *LintConfig `json:"lint,omitempty"`
}

// day is a convenience unit for profile validity periods.
const day = 24 * time.Hour

// builtinProfiles are the certificate profiles available out of the box. They
// are keyed by (lowercase) name.
var builtinProfiles = map[string]Profile{
	"server": {
		Name:            "server",
		Description:     "TLS server certificate (serverAuth)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 397 * day, // CA/Browser Forum maximum for TLS leaves
		MaxValidity:     397 * day,
	},
	"client": {
		Name:            "client",
		Description:     "TLS client / mTLS certificate (clientAuth)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"clientAuth"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
	},
	"server-client": {
		Name:            "server-client",
		Description:     "Dual-purpose TLS certificate (serverAuth + clientAuth)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth", "clientAuth"},
		DefaultValidity: 397 * day,
		MaxValidity:     397 * day,
	},
	"code-signing": {
		Name:            "code-signing",
		Description:     "Code-signing certificate (codeSigning)",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"codeSigning"},
		DefaultValidity: 3 * 365 * day,
		MaxValidity:     3 * 365 * day,
	},
	"email": {
		Name:            "email",
		Description:     "S/MIME e-mail protection certificate (emailProtection)",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"emailProtection"},
		DefaultValidity: 365 * day,
		MaxValidity:     2 * 365 * day,
	},
}

// defaultProfileName is used when a request omits the profile.
const defaultProfileName = "server"

// customProfiles holds operator-defined profiles installed from central
// configuration via SetCustomProfiles. They layer over the built-ins: a custom
// profile with the same (lowercase) name as a built-in overrides it. This lets
// deployments add issuance shapes or tighten validity without a code change.
// Set once at startup before serving, so no locking is required for reads.
var customProfiles = map[string]Profile{}

// SetCustomProfiles validates and installs operator-defined profiles. Each
// profile must have a name and reference only known key usages / extended key
// usages. It is intended to be called once during initialization; calling it
// again replaces the previous custom set.
func SetCustomProfiles(profiles []Profile) error {
	next := make(map[string]Profile, len(profiles))
	for _, p := range profiles {
		if p.Name == "" {
			return fmt.Errorf("custom profile: name is required")
		}
		key := normalizeProfileName(p.Name)
		if _, dup := next[key]; dup {
			return fmt.Errorf("custom profile %q: duplicate name", p.Name)
		}
		// Fold day-based validity (from config) into durations if the caller only
		// supplied days, then validate the usage identifiers eagerly.
		if p.DefaultValidity == 0 && p.DefaultValidityDays > 0 {
			p.DefaultValidity = time.Duration(p.DefaultValidityDays) * day
		}
		if p.MaxValidity == 0 && p.MaxValidityDays > 0 {
			p.MaxValidity = time.Duration(p.MaxValidityDays) * day
		}
		if _, err := p.keyUsage(); err != nil {
			return err
		}
		if _, err := p.extKeyUsage(); err != nil {
			return err
		}
		next[key] = p
	}
	customProfiles = next
	return nil
}

// LookupProfile resolves a profile by name (case-insensitive), preferring a
// custom profile over a built-in of the same name. When name is empty the
// default profile is returned.
func LookupProfile(name string) (Profile, error) {
	if name == "" {
		name = defaultProfileName
	}
	key := normalizeProfileName(name)
	if p, ok := customProfiles[key]; ok {
		p.fillValidityDays()
		return p, nil
	}
	p, ok := builtinProfiles[key]
	if !ok {
		return Profile{}, fmt.Errorf("unknown certificate profile %q (available: %v)", name, ProfileNames())
	}
	p.fillValidityDays()
	return p, nil
}

// mergedProfiles returns the effective profile set: built-ins overlaid with any
// custom profiles.
func mergedProfiles() map[string]Profile {
	out := make(map[string]Profile, len(builtinProfiles)+len(customProfiles))
	for k, v := range builtinProfiles {
		out[k] = v
	}
	for k, v := range customProfiles {
		out[k] = v
	}
	return out
}

// Profiles returns every effective profile (built-in + custom), sorted by name.
func Profiles() []Profile {
	merged := mergedProfiles()
	out := make([]Profile, 0, len(merged))
	for _, p := range merged {
		p.fillValidityDays()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProfileNames returns the sorted list of effective profile names.
func ProfileNames() []string {
	merged := mergedProfiles()
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func normalizeProfileName(name string) string {
	return name // names are already stored lowercase; kept for a single choke point
}

// fillValidityDays populates the *Days JSON fields from the durations.
func (p *Profile) fillValidityDays() {
	p.DefaultValidityDays = int(p.DefaultValidity / day)
	p.MaxValidityDays = int(p.MaxValidity / day)
}

// keyUsage resolves the profile's string key usages to an x509 bitmask.
func (p Profile) keyUsage() (x509.KeyUsage, error) {
	var ku x509.KeyUsage
	for _, s := range p.KeyUsages {
		v, ok := pki.X509KeyUsageFromString[s]
		if !ok {
			return 0, fmt.Errorf("profile %q references unknown key usage %q", p.Name, s)
		}
		ku |= v
	}
	return ku, nil
}

// extKeyUsage resolves the profile's string extended key usages.
func (p Profile) extKeyUsage() ([]x509.ExtKeyUsage, error) {
	out := make([]x509.ExtKeyUsage, 0, len(p.ExtKeyUsages))
	for _, s := range p.ExtKeyUsages {
		v, ok := pki.X509ExtKeyUsageFromString[s]
		if !ok {
			return nil, fmt.Errorf("profile %q references unknown extended key usage %q", p.Name, s)
		}
		out = append(out, v)
	}
	return out, nil
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
