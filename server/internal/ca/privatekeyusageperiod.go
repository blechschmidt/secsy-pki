package ca

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// PrivateKeyUsagePeriodConfig is a profile's RFC 5280 §4.2.1 private-key usage
// period policy: the window during which the certified private key may be used to
// *produce* signatures, stamped in the non-critical id-ce-privateKeyUsagePeriod
// extension (OID 2.5.29.16) on every leaf issued under the profile. The window
// can be narrower than the certificate's own validity — a signing key can be
// retired before the certificate expires while signatures it already made remain
// verifiable — which is expected on some eIDAS / qualified signing certificates
// and legacy deployments.
//
// Exactly one of the three mutually-exclusive forms configures the default
// window (all relative to the certificate's own validity [certNotBefore,
// certNotAfter]):
//
//   - Duration: [certNotBefore, certNotBefore+Duration]. A flexible duration
//     string ("365d", "52w", "8760h", "1y"): the key may sign for that long from
//     issuance.
//   - Fraction: [certNotBefore, certNotBefore + Fraction*validity]. A value in
//     (0,1]: the key may sign for that fraction of the certificate's lifetime.
//   - NotBefore / NotAfter: explicit absolute RFC 3339 instants (either or both).
//
// A block that sets none of the three but has AllowOverride=true is an
// override-only policy: it carries no default window, but a request may supply
// one. The resolved window is always clamped to the certificate's validity (the
// key can never sign before the certificate is valid or after it expires).
type PrivateKeyUsagePeriodConfig struct {
	// Duration is the usage-period length from the certificate notBefore, as a
	// flexible duration string (e.g. "365d", "8760h"). Mutually exclusive with
	// Fraction and the explicit NotBefore/NotAfter.
	Duration string `json:"duration,omitempty"`
	// Fraction is the usage-period length as a fraction (0,1] of the certificate's
	// validity. Mutually exclusive with Duration and explicit NotBefore/NotAfter.
	Fraction float64 `json:"fraction,omitempty"`
	// NotBefore / NotAfter are explicit absolute RFC 3339 instants. Either or both
	// may be set; mutually exclusive with Duration and Fraction.
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	// AllowOverride lets a REST/gRPC/CLI issue request supply or replace the
	// usage-period window per certificate. When false, a per-request override is
	// rejected and the profile default (if any) is authoritative.
	AllowOverride bool `json:"allow_override,omitempty"`
}

// hasDefault reports whether the block configures a default window (any of the
// three forms), as opposed to being override-only.
func (c *PrivateKeyUsagePeriodConfig) hasDefault() bool {
	return c != nil && (strings.TrimSpace(c.Duration) != "" || c.Fraction != 0 ||
		strings.TrimSpace(c.NotBefore) != "" || strings.TrimSpace(c.NotAfter) != "")
}

// validate checks the block sets at most one default form and would produce a
// usable window, so a misconfiguration surfaces at profile-install time rather
// than at the first issuance.
func (c *PrivateKeyUsagePeriodConfig) validate(profileName string) error {
	if c == nil {
		return nil
	}
	modes := 0
	if strings.TrimSpace(c.Duration) != "" {
		modes++
	}
	if c.Fraction != 0 {
		modes++
	}
	if strings.TrimSpace(c.NotBefore) != "" || strings.TrimSpace(c.NotAfter) != "" {
		modes++
	}
	if modes > 1 {
		return fmt.Errorf("profile %q private_key_usage_period: set only one of duration, fraction, or explicit not_before/not_after", profileName)
	}
	if modes == 0 && !c.AllowOverride {
		return fmt.Errorf("profile %q private_key_usage_period: configures no window "+
			"(set duration, fraction, explicit not_before/not_after, or allow_override)", profileName)
	}
	// Window-independent field validation (the concrete window and the clamp to the
	// certificate validity are resolved per issuance).
	if err := c.validateFields(); err != nil {
		return fmt.Errorf("profile %q private_key_usage_period: %w", profileName, err)
	}
	return nil
}

// validateFields checks the field-level validity of whichever default form is
// set, independent of any certificate validity window: a parseable, positive
// duration; a fraction in (0,1]; or parseable explicit RFC 3339 instants with
// not_before not after not_after.
func (c *PrivateKeyUsagePeriodConfig) validateFields() error {
	if d := strings.TrimSpace(c.Duration); d != "" {
		dur, err := parseFlexibleDuration(d)
		if err != nil {
			return fmt.Errorf("duration: %w", err)
		}
		if dur <= 0 {
			return fmt.Errorf("duration must be positive, got %q", d)
		}
	}
	if c.Fraction != 0 && (c.Fraction <= 0 || c.Fraction > 1) {
		return fmt.Errorf("fraction must be in (0,1], got %g", c.Fraction)
	}
	var nb, na time.Time
	if s := strings.TrimSpace(c.NotBefore); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("not_before: %w", err)
		}
		nb = t
	}
	if s := strings.TrimSpace(c.NotAfter); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("not_after: %w", err)
		}
		na = t
	}
	if !nb.IsZero() && !na.IsZero() && na.Before(nb) {
		return fmt.Errorf("not_after (%s) precedes not_before (%s)", c.NotAfter, c.NotBefore)
	}
	return nil
}

// resolveDefault computes the profile-default usage-period window for a
// certificate whose validity is [certNotBefore, certNotAfter], returning
// present=false when the block sets no default (override-only).
func (c *PrivateKeyUsagePeriodConfig) resolveDefault(certNotBefore, certNotAfter time.Time) (pki.PrivateKeyUsagePeriod, bool, error) {
	if !c.hasDefault() {
		return pki.PrivateKeyUsagePeriod{}, false, nil
	}
	return resolvePKUPWindow(c.Duration, c.Fraction, c.NotBefore, c.NotAfter, certNotBefore, certNotAfter)
}

// resolvePKUPWindow turns one of the three usage-period forms into a concrete
// window, clamped to the certificate's validity. It is shared by the profile
// default and the per-request override so both resolve and validate identically
// (the override never sets fraction). It returns present=false when every input
// is empty.
func resolvePKUPWindow(duration string, fraction float64, notBefore, notAfter string, certNotBefore, certNotAfter time.Time) (pki.PrivateKeyUsagePeriod, bool, error) {
	duration = strings.TrimSpace(duration)
	notBefore = strings.TrimSpace(notBefore)
	notAfter = strings.TrimSpace(notAfter)

	forms := 0
	if duration != "" {
		forms++
	}
	if fraction != 0 {
		forms++
	}
	if notBefore != "" || notAfter != "" {
		forms++
	}
	switch {
	case forms == 0:
		return pki.PrivateKeyUsagePeriod{}, false, nil
	case forms > 1:
		return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("set only one of duration, fraction, or explicit not_before/not_after")
	}

	var p pki.PrivateKeyUsagePeriod
	switch {
	case duration != "":
		d, err := parseFlexibleDuration(duration)
		if err != nil {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("duration: %w", err)
		}
		if d <= 0 {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("duration must be positive, got %q", duration)
		}
		p = pki.PrivateKeyUsagePeriod{NotBefore: certNotBefore, NotAfter: certNotBefore.Add(d)}
	case fraction != 0:
		if fraction <= 0 || fraction > 1 {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("fraction must be in (0,1], got %g", fraction)
		}
		span := certNotAfter.Sub(certNotBefore)
		p = pki.PrivateKeyUsagePeriod{NotBefore: certNotBefore, NotAfter: certNotBefore.Add(time.Duration(float64(span) * fraction))}
	default: // explicit not_before / not_after
		if notBefore != "" {
			t, err := time.Parse(time.RFC3339, notBefore)
			if err != nil {
				return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("not_before: %w", err)
			}
			p.NotBefore = t.UTC()
		}
		if notAfter != "" {
			t, err := time.Parse(time.RFC3339, notAfter)
			if err != nil {
				return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("not_after: %w", err)
			}
			p.NotAfter = t.UTC()
		}
	}
	return clampPKUPToValidity(p, certNotBefore, certNotAfter)
}

// clampPKUPToValidity constrains a usage-period window to the certificate's own
// validity — the private key can never be used before the certificate is valid or
// after it expires — and validates the resulting ordering. It returns
// present=false only when the input was empty (never after a non-empty resolve).
func clampPKUPToValidity(p pki.PrivateKeyUsagePeriod, certNotBefore, certNotAfter time.Time) (pki.PrivateKeyUsagePeriod, bool, error) {
	if p.IsZero() {
		return pki.PrivateKeyUsagePeriod{}, false, nil
	}
	if !p.NotBefore.IsZero() && p.NotBefore.Before(certNotBefore) {
		p.NotBefore = certNotBefore
	}
	if !p.NotAfter.IsZero() && p.NotAfter.After(certNotAfter) {
		p.NotAfter = certNotAfter
	}
	if !p.NotBefore.IsZero() && !p.NotAfter.IsZero() && p.NotAfter.Before(p.NotBefore) {
		return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf(
			"resolved usage-period notAfter (%s) precedes notBefore (%s)",
			p.NotAfter.UTC().Format(time.RFC3339), p.NotBefore.UTC().Format(time.RFC3339))
	}
	return p, true, nil
}

// parseFlexibleDuration parses a duration that may use the day ("d"), week ("w"),
// or year ("y") units time.ParseDuration lacks, in addition to the units it
// supports (h/m/s/…). The extended units apply to a single leading number
// ("365d", "52w", "0.5y"); anything else is delegated to time.ParseDuration
// ("8760h", "24h30m"). A bare number with no unit is rejected.
func parseFlexibleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	switch last := s[len(s)-1]; last {
	case 'd', 'D', 'w', 'W', 'y', 'Y':
		n, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		var unit time.Duration
		switch last {
		case 'd', 'D':
			unit = 24 * time.Hour
		case 'w', 'W':
			unit = 7 * 24 * time.Hour
		case 'y', 'Y':
			unit = 365 * 24 * time.Hour
		}
		return time.Duration(n * float64(unit)), nil
	default:
		return time.ParseDuration(s)
	}
}

// pkupOverridePresent reports whether a per-request usage-period override carries
// any content (so an empty struct from a decoded JSON body is treated as absent).
func pkupOverridePresent(o *models.PrivateKeyUsagePeriod) bool {
	return o != nil && (strings.TrimSpace(o.Duration) != "" ||
		strings.TrimSpace(o.NotBefore) != "" || strings.TrimSpace(o.NotAfter) != "")
}

// privateKeyUsagePeriod resolves the effective RFC 5280 private-key usage period
// for one issuance against the certificate's validity window: the profile's
// configured default, with the window replaced by a per-request override when one
// is supplied and the profile permits it (allow_override). It returns
// present=false (and no error) when the profile has no policy and no override was
// requested. A per-request override against a profile that has no
// private_key_usage_period policy, or that forbids overrides, is a hard error — a
// request must never fabricate a usage-period constraint the profile did not
// grant.
func (p Profile) privateKeyUsagePeriod(override *models.PrivateKeyUsagePeriod, certNotBefore, certNotAfter time.Time) (pki.PrivateKeyUsagePeriod, bool, error) {
	hasOverride := pkupOverridePresent(override)
	cfg := p.PrivateKeyUsagePeriod
	if cfg == nil {
		if hasOverride {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf(
				"profile %q does not enable a private-key usage period; a per-request override is not permitted", p.Name)
		}
		return pki.PrivateKeyUsagePeriod{}, false, nil
	}
	if hasOverride {
		if !cfg.AllowOverride {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf(
				"profile %q does not allow per-request private-key usage period overrides (set private_key_usage_period.allow_override)", p.Name)
		}
		resolved, present, err := resolvePKUPWindow(override.Duration, 0, override.NotBefore, override.NotAfter, certNotBefore, certNotAfter)
		if err != nil {
			return pki.PrivateKeyUsagePeriod{}, false, fmt.Errorf("profile %q private-key usage period override: %w", p.Name, err)
		}
		if present {
			return resolved, true, nil
		}
		// An override present-but-empty falls back to the profile default.
	}
	return cfg.resolveDefault(certNotBefore, certNotAfter)
}

// applyPrivateKeyUsagePeriod appends the RFC 5280 id-ce-privateKeyUsagePeriod
// extension to a leaf request when the profile configures one, merging any
// per-request override, resolved against the request's validity window
// (base.NotBefore / base.NotAfter). It never mutates the caller's extension
// slice. Shared by the classical, PQC, hybrid, and preview issuance paths so the
// extension is stamped identically; it is appended before linting and before the
// CT poison/SCT split so the lint gate sees it and the precertificate and final
// certificate carry it identically.
func applyPrivateKeyUsagePeriod(base pki.LeafCertRequest, profile Profile, override *models.PrivateKeyUsagePeriod) (pki.LeafCertRequest, error) {
	pkup, present, err := profile.privateKeyUsagePeriod(override, base.NotBefore, base.NotAfter)
	if err != nil {
		return base, err
	}
	if !present {
		return base, nil
	}
	ext, err := pkup.Extension()
	if err != nil {
		return base, fmt.Errorf("profile %q private_key_usage_period: %w", profile.Name, err)
	}
	base.ExtraExtensions = appendExt(base.ExtraExtensions, ext)
	return base, nil
}

// describePrivateKeyUsagePeriod renders a short human-readable summary of the
// usage-period window a PKUP-enabled issuance would stamp, for the preview/dry-run
// gate verdict.
func describePrivateKeyUsagePeriod(p pki.PrivateKeyUsagePeriod) string {
	var parts []string
	if !p.NotBefore.IsZero() {
		parts = append(parts, "notBefore="+p.NotBefore.UTC().Format(time.RFC3339))
	}
	if !p.NotAfter.IsZero() {
		parts = append(parts, "notAfter="+p.NotAfter.UTC().Format(time.RFC3339))
	}
	return "id-ce-privateKeyUsagePeriod would be stamped: " + strings.Join(parts, ", ")
}
