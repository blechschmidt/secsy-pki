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

// LookupProfile resolves a built-in profile by name (case-insensitive). When
// name is empty the default profile is returned.
func LookupProfile(name string) (Profile, error) {
	if name == "" {
		name = defaultProfileName
	}
	p, ok := builtinProfiles[normalizeProfileName(name)]
	if !ok {
		return Profile{}, fmt.Errorf("unknown certificate profile %q (available: %v)", name, ProfileNames())
	}
	p.fillValidityDays()
	return p, nil
}

// Profiles returns every built-in profile, sorted by name.
func Profiles() []Profile {
	out := make([]Profile, 0, len(builtinProfiles))
	for _, p := range builtinProfiles {
		p.fillValidityDays()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProfileNames returns the sorted list of built-in profile names.
func ProfileNames() []string {
	names := make([]string, 0, len(builtinProfiles))
	for name := range builtinProfiles {
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
