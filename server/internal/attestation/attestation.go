// Package attestation verifies hardware key-attestation evidence presented on
// the device-enrollment paths (EST, SCEP, ACME) so the CA can prove that an
// enrolled private key is non-exportable and hardware-resident before it signs
// a certificate for the corresponding public key.
//
// Three evidence forms are supported:
//
//   - ACME device-attest-01 (draft-ietf-acme-device-attest): a WebAuthn-style
//     CBOR attestation object whose statement is an Apple anonymous attestation
//     or a TPM 2.0 attestation. See acme.go.
//   - EST/SCEP PKCS#10 attestation: an accompanying attestation-certificate
//     chain carried in a CSR extension (a certs-only CMS). The attestation
//     leaf's subject public key is the enrolled key — the YubiKey PIV model —
//     and is bound to the CSR key. See pkcs10.go.
//   - Manufacturer certificate-chain validation: YubiKey PIV attestation certs
//     and TPM EK/AK certificates chained to a configurable set of trusted
//     manufacturer roots. See device.go and chain.go.
//
// Enforcement is per issuance profile via a Mode (off / permissive / require).
// Under "require" a missing or invalid attestation fails the enrollment closed;
// under "permissive" it is evaluated and audited but never blocks. The package
// itself is transport-agnostic and side-effect free: callers (the EST/SCEP/ACME
// servers) own audit-event emission and metrics, keyed off the returned Result.
package attestation

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Mode is the per-profile enforcement mode for enrollment attestation.
type Mode string

const (
	// ModeOff disables attestation checking for the profile. Enrollment proceeds
	// exactly as before this feature existed.
	ModeOff Mode = "off"
	// ModePermissive evaluates any attestation that is presented and records the
	// outcome, but never blocks enrollment — including when no attestation is
	// presented at all. Useful for staging a policy or gaining fleet visibility.
	ModePermissive Mode = "permissive"
	// ModeRequire fails enrollment closed unless a valid, trusted attestation is
	// presented and bound to the enrolled key.
	ModeRequire Mode = "require"
)

// ParseMode validates and normalizes a configured mode string. An empty string
// maps to ModeOff so an unconfigured profile is inert.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeOff:
		return ModeOff, nil
	case ModePermissive:
		return ModePermissive, nil
	case ModeRequire:
		return ModeRequire, nil
	default:
		return "", fmt.Errorf("attestation: invalid mode %q (want off|permissive|require)", s)
	}
}

// Attestation format labels, surfaced in the Result and in audit/metric labels.
const (
	FormatYubiKeyPIV = "yubikey-piv"
	FormatTPM        = "tpm"
	FormatApple      = "apple"
	// FormatCertChain is a generic manufacturer attestation-certificate chain
	// (EST/SCEP CSR bundle) that is not recognized as a more specific format.
	FormatCertChain = "cert-chain"
)

// Result is the outcome of verifying an attestation. It is returned even on
// failure (with Verified false and Reason set) so callers can audit denials.
type Result struct {
	// Verified is true only when the evidence validated end to end: the
	// attestation chained to a trusted manufacturer root and (where applicable)
	// the attested key was bound to the enrolled key.
	Verified bool
	// Format is one of the Format* constants describing the evidence recognized.
	Format string
	// Manufacturer is a human label for the attesting hardware vendor when it can
	// be derived (e.g. "YubiKey", "TPM:<vendor>", "Apple").
	Manufacturer string
	// Serial is the device/hardware serial when the attestation carries one
	// (YubiKey PIV serial extension, TPM EK serial), else "".
	Serial string
	// HardwareResident reports that the attested private key is generated in and
	// confined to a hardware security element (true whenever Verified).
	HardwareResident bool
	// NonExportable reports that the attested key cannot be exported in the clear
	// (true whenever Verified — the whole point of the attestation).
	NonExportable bool
	// AttestedKey is the public key the attestation vouches for, when recovered.
	AttestedKey crypto.PublicKey
	// Reason is a short human explanation, populated on failure and often on
	// success (for the audit detail).
	Reason string
}

// ErrNoAttestation indicates that the enrollment presented no attestation
// evidence at all. Callers distinguish this from an invalid attestation: under
// ModePermissive a missing attestation is tolerated, whereas a present-but-bad
// one is still recorded as a failure.
var ErrNoAttestation = errors.New("attestation: no attestation evidence presented")

// Options configures a Verifier.
type Options struct {
	// Roots is the set of trusted manufacturer root certificates. An attestation
	// certificate chain must terminate at one of these to be trusted. Required
	// for any profile in ModeRequire.
	Roots *x509.CertPool
	// Intermediates are additional (non-root) manufacturer CA certificates made
	// available for chain building, supplementing any intermediates carried in
	// the attestation evidence itself.
	Intermediates []*x509.Certificate
	// DefaultMode is the mode applied to any profile not named in ProfileModes.
	DefaultMode Mode
	// ProfileModes maps an issuance profile name to its attestation mode,
	// overriding DefaultMode.
	ProfileModes map[string]Mode
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
}

// Verifier evaluates attestation evidence against a fixed set of trusted
// manufacturer roots and a per-profile policy. It is safe for concurrent use.
type Verifier struct {
	roots         *x509.CertPool
	intermediates []*x509.Certificate
	defaultMode   Mode
	profileModes  map[string]Mode
	now           func() time.Time
}

// NewVerifier constructs a Verifier from Options, validating the configuration.
// It returns an error when a profile (or the default) is set to require
// attestation but no trusted roots were supplied, since such a policy could
// never be satisfied and would silently fail every enrollment closed.
func NewVerifier(opts Options) (*Verifier, error) {
	defMode, err := ParseMode(string(opts.DefaultMode))
	if err != nil {
		return nil, err
	}
	profileModes := make(map[string]Mode, len(opts.ProfileModes))
	requiresRoots := defMode == ModeRequire
	for name, m := range opts.ProfileModes {
		pm, err := ParseMode(string(m))
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		profileModes[name] = pm
		if pm == ModeRequire {
			requiresRoots = true
		}
	}

	rootsEmpty := opts.Roots == nil || len(opts.Roots.Subjects()) == 0 //nolint:staticcheck // Subjects() is fine for emptiness
	if requiresRoots && rootsEmpty {
		return nil, errors.New("attestation: a profile requires attestation but no trusted manufacturer roots are configured")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	inter := make([]*x509.Certificate, 0, len(opts.Intermediates))
	for _, c := range opts.Intermediates {
		if c != nil {
			inter = append(inter, c)
		}
	}
	return &Verifier{
		roots:         opts.Roots,
		intermediates: inter,
		defaultMode:   defMode,
		profileModes:  profileModes,
		now:           now,
	}, nil
}

// Mode returns the effective attestation mode for an issuance profile.
func (v *Verifier) Mode(profile string) Mode {
	if v == nil {
		return ModeOff
	}
	if m, ok := v.profileModes[profile]; ok {
		return m
	}
	return v.defaultMode
}

// AnyEnforcing reports whether any configured profile (or the default) enforces
// or permissively evaluates attestation, i.e. the feature is active at all.
func (v *Verifier) AnyEnforcing() bool {
	if v == nil {
		return false
	}
	if v.defaultMode != ModeOff {
		return true
	}
	for _, m := range v.profileModes {
		if m != ModeOff {
			return true
		}
	}
	return false
}

// Decision is the enforcement outcome for one enrollment, computed from a
// profile's mode and a verification Result (or the absence of evidence).
type Decision struct {
	// Allow reports whether enrollment may proceed.
	Allow bool
	// Result is the verification result (nil when no evidence was presented).
	Result *Result
	// Mode is the profile mode that produced this decision.
	Mode Mode
	// Missing is true when no attestation evidence was presented.
	Missing bool
	// Detail is a human-readable summary suitable for an audit event.
	Detail string
}

// decide applies a profile's mode to a verification result, centralizing the
// fail-open (permissive) vs fail-closed (require) policy so every enrollment
// path behaves identically.
//
// verifyErr is the error from attempting verification (ErrNoAttestation when no
// evidence was presented, another error when evidence was present but invalid,
// nil on success).
func (v *Verifier) decide(profile string, res *Result, verifyErr error) Decision {
	mode := v.Mode(profile)
	d := Decision{Mode: mode, Result: res, Missing: errors.Is(verifyErr, ErrNoAttestation)}

	switch mode {
	case ModeOff:
		d.Allow = true
		d.Detail = "attestation disabled for profile"
		return d
	case ModePermissive:
		// Never blocks. Report what happened for the audit trail.
		d.Allow = true
		switch {
		case d.Missing:
			d.Detail = "permissive: no attestation presented"
		case verifyErr != nil:
			d.Detail = "permissive: attestation invalid: " + verifyErr.Error()
		default:
			d.Detail = "permissive: " + resultDetail(res)
		}
		return d
	case ModeRequire:
		switch {
		case d.Missing:
			d.Allow = false
			d.Detail = "attestation required but none presented"
		case verifyErr != nil:
			d.Allow = false
			d.Detail = "attestation required and invalid: " + verifyErr.Error()
		case res == nil || !res.Verified:
			d.Allow = false
			d.Detail = "attestation required but not verified"
		default:
			d.Allow = true
			d.Detail = resultDetail(res)
		}
		return d
	default:
		// Unreachable given ParseMode, but fail closed if it ever happens.
		d.Allow = false
		d.Detail = "unknown attestation mode"
		return d
	}
}

func resultDetail(res *Result) string {
	if res == nil {
		return "no result"
	}
	parts := []string{"format=" + res.Format}
	if res.Manufacturer != "" {
		parts = append(parts, "mfr="+res.Manufacturer)
	}
	if res.Serial != "" {
		parts = append(parts, "serial="+res.Serial)
	}
	parts = append(parts, fmt.Sprintf("hw_resident=%v non_exportable=%v", res.HardwareResident, res.NonExportable))
	if res.Reason != "" {
		parts = append(parts, res.Reason)
	}
	return strings.Join(parts, " ")
}
