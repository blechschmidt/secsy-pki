package hsmattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
)

// Check is one itemized verification step, so a report says which assertion
// failed rather than only that something did.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Result is the verdict on one key attestation.
type Result struct {
	// Verified is the bottom line: every required check passed. It is false
	// whenever any Problem is recorded.
	Verified bool `json:"verified"`

	// --- device assertions about the key ---

	// NonExportable reports that the key holds no capability permitting export,
	// so its private material cannot leave the HSM. This is the headline claim.
	NonExportable bool `json:"non_exportable"`
	// GeneratedOnDevice reports that the key was created inside the HSM and so
	// never existed anywhere else. Without it, non-exportability only says a
	// copy cannot leave *now* — not that one was never made before import.
	GeneratedOnDevice bool `json:"generated_on_device"`
	// CanSign reports whether the key holds any signing capability.
	CanSign bool `json:"can_sign"`
	// Origin renders the origin bits in Yubico's vocabulary.
	Origin string `json:"origin,omitempty"`
	// Capabilities lists the key's capabilities by canonical name.
	Capabilities []string `json:"capabilities,omitempty"`
	// Domains lists the YubiHSM domains the key belongs to.
	Domains []int `json:"domains,omitempty"`
	// KeyLabel, ObjectID identify the key on the device. ObjectID is also the
	// PKCS#11 CKA_ID and the target_key of the device audit log.
	KeyLabel string `json:"key_label,omitempty"`
	ObjectID uint16 `json:"object_id"`
	// DeviceSerial and FirmwareVersion identify the attesting device.
	DeviceSerial    string `json:"device_serial,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`

	// --- the attested key itself ---

	// PublicKeyAlgorithm and PublicKeyDetail describe the attested key.
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	PublicKeyDetail    string `json:"public_key_detail,omitempty"`
	// SPKIFingerprint is the attested key's SubjectPublicKeyInfo fingerprint in
	// the same "SHA256:<base64>" form the certificate inventory stores, so it
	// can be compared directly against an issued CA certificate.
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`

	// --- trust in the attestation itself ---

	// DeviceBound reports that the attestation certificate's signature was
	// verified against the device attestation certificate — i.e. this device
	// really made these assertions.
	DeviceBound bool `json:"device_bound"`
	// ChainAnchored reports that the device attestation certificate chains to a
	// configured trust anchor, i.e. the attesting device is a genuine YubiHSM
	// rather than something impersonating one.
	ChainAnchored bool `json:"chain_anchored"`
	// TrustAnchor names the root the chain reached, when anchored.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	// KeyMatched reports whether the attested key equals the expected key, when
	// one was supplied. Nil means the caller supplied none, so the attestation
	// stands on its own and is not tied to any particular CA.
	KeyMatched *bool `json:"key_matched,omitempty"`

	// --- reporting ---

	// Checks itemizes every step that was evaluated.
	Checks []Check `json:"checks,omitempty"`
	// Problems are the failures that made Verified false.
	Problems []string `json:"problems,omitempty"`
	// Warnings are findings that did not fail the configured policy but that an
	// operator should see.
	Warnings []string `json:"warnings,omitempty"`
	// Summary is a one-line human verdict.
	Summary string `json:"summary"`
}

// The Is* accessors let a Result satisfy metrics.KeyAttestationResult without
// internal/metrics having to import this package.

func (r *Result) IsVerified() bool          { return r != nil && r.Verified }
func (r *Result) IsNonExportable() bool     { return r != nil && r.NonExportable }
func (r *Result) IsGeneratedOnDevice() bool { return r != nil && r.GeneratedOnDevice }
func (r *Result) IsDeviceBound() bool       { return r != nil && r.DeviceBound }
func (r *Result) IsChainAnchored() bool     { return r != nil && r.ChainAnchored }

// Policy configures what an attestation must show to be considered verified.
//
// The two defaults that matter are on by default because they are the whole
// point: an attestation that is allowed to show an exportable, imported key is
// not evidence of anything. Callers wanting to inspect rather than enforce set
// them false and read the fields.
type Policy struct {
	// RequireNonExportable fails a key that holds exportable-under-wrap.
	RequireNonExportable bool
	// RequireGeneratedOnDevice fails a key that was imported rather than
	// generated inside the HSM.
	RequireGeneratedOnDevice bool
	// RequireDeviceBinding fails an attestation whose signature could not be
	// checked against the device attestation certificate.
	RequireDeviceBinding bool
	// RequireAnchoredChain fails an attestation whose device certificate does
	// not chain to a configured root.
	//
	// On by default. Without it an attestation shows a key's properties as
	// asserted by *a* device, and any attacker can mint a self-signed
	// "attestation" saying whatever they like; the anchor is what makes the
	// asserting device provably a genuine YubiHSM. Yubico publishes both the
	// root and the issuing sub-CA (see roots.go), and both ship embedded, so
	// stock hardware satisfies this with no configuration.
	//
	// Turn it off only for a device whose factory attestation key has been
	// replaced with an owner-generated one, where there is no Yubico chain to
	// anchor to by construction.
	RequireAnchoredChain bool

	// ForbiddenCapabilities names capabilities the key must not hold, beyond
	// the exportability check.
	ForbiddenCapabilities []string

	// ExpectedLabel, ExpectedSerial and ExpectedObjectID, when set, must match
	// the device's assertions.
	ExpectedLabel    string
	ExpectedSerial   string
	ExpectedObjectID *uint16

	// ExpectedPublicKey, when set, must equal the attested key. This is what
	// binds an attestation to a specific CA: without it, an attestation proves
	// that *some* key on the device is non-exportable, which is not the claim
	// anyone cares about.
	ExpectedPublicKey crypto.PublicKey

	// Roots and Intermediates anchor the device attestation certificate. When
	// Roots is nil the embedded Yubico attestation roots are used.
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate

	// Now overrides the clock for chain validation (tests).
	Now func() time.Time
}

// DefaultPolicy is the policy a CA signing key is expected to satisfy.
func DefaultPolicy() Policy {
	return Policy{
		RequireNonExportable:     true,
		RequireGeneratedOnDevice: true,
		RequireDeviceBinding:     true,
		RequireAnchoredChain:     true,
	}
}

// Verify checks an attestation against a policy and returns a full report.
//
// It never returns an error: a malformed or fraudulent attestation is a
// verdict, not an exception, and the caller wants the reason. Result.Verified
// is the only thing to branch on.
func Verify(att *Attestation, pol Policy) *Result {
	res := &Result{}
	fail := func(format string, args ...any) {
		res.Problems = append(res.Problems, fmt.Sprintf(format, args...))
	}
	check := func(name string, passed bool, detail string) bool {
		res.Checks = append(res.Checks, Check{Name: name, Passed: passed, Detail: detail})
		return passed
	}

	cert, err := att.Certificate()
	if err != nil {
		check("attestation-certificate", false, err.Error())
		fail("%v", err)
		return finish(res)
	}
	claims, err := ParseClaims(cert)
	if err != nil {
		check("attestation-claims", false, err.Error())
		fail("%v", err)
		return finish(res)
	}
	check("attestation-claims", true, "YubiHSM attestation extensions decoded")

	res.KeyLabel = claims.Label
	res.ObjectID = claims.ObjectID
	res.DeviceSerial = claims.DeviceSerial
	res.FirmwareVersion = claims.FirmwareVersion
	res.Origin = claims.OriginString()
	res.Capabilities = claims.CapabilityNames
	res.Domains = claims.Domains
	res.CanSign = claims.Capabilities.CanSign()

	// A YubiHSM emits every attestation extension. A certificate missing some
	// is not older firmware being lenient; it is a certificate that declines to
	// make exactly the assertions being checked, which is what a forgery
	// stripped of the inconvenient fields looks like.
	if len(claims.Missing) > 0 {
		detail := "absent: " + strings.Join(claims.Missing, ", ")
		check("attestation-completeness", false, detail)
		fail("attestation certificate omits YubiHSM extension(s) that every genuine attestation carries (%s)", detail)
	} else {
		check("attestation-completeness", true, "all seven YubiHSM attestation extensions present")
	}

	// --- exportability: the headline claim ---
	res.NonExportable = !claims.Exportable()
	if claims.Exportable() {
		check("non-exportable", false, "key holds exportable-under-wrap")
		if pol.RequireNonExportable {
			fail("key holds the exportable-under-wrap capability: its private material can be exported from the HSM under a wrap key, so confinement to hardware is only as strong as that wrap key")
		} else {
			res.Warnings = append(res.Warnings, "key holds exportable-under-wrap and can be exported from the device under a wrap key")
		}
	} else {
		check("non-exportable", true, "key does not hold exportable-under-wrap; private material cannot leave the device")
	}

	// --- origin ---
	res.GeneratedOnDevice = claims.GeneratedOnDevice()
	if !claims.GeneratedOnDevice() {
		detail := "origin=" + claims.OriginString()
		check("generated-on-device", false, detail)
		msg := fmt.Sprintf("key was not generated inside the HSM (%s): the private material existed outside the device before import, so non-exportability does not establish that no copy exists elsewhere", detail)
		if pol.RequireGeneratedOnDevice {
			fail("%s", msg)
		} else {
			res.Warnings = append(res.Warnings, msg)
		}
	} else {
		check("generated-on-device", true, "origin=generated; private material was created inside the HSM and never existed outside it")
	}

	// --- other forbidden capabilities ---
	if len(pol.ForbiddenCapabilities) > 0 {
		forbidden, err := ParseCapabilityNames(pol.ForbiddenCapabilities)
		if err != nil {
			check("forbidden-capabilities", false, err.Error())
			fail("%v", err)
		} else if held := claims.Capabilities & forbidden; held != 0 {
			names := strings.Join(held.Names(), ", ")
			check("forbidden-capabilities", false, "held: "+names)
			fail("key holds capabilities the policy forbids: %s", names)
		} else {
			check("forbidden-capabilities", true, "none of the forbidden capabilities are held")
		}
	}

	// An unnamed capability is one this build cannot reason about, so it cannot
	// be shown not to permit export. Surface it instead of implying the
	// capability list was fully understood.
	if unknown := claims.Capabilities.Unknown(); len(unknown) > 0 {
		bits := make([]string, 0, len(unknown))
		for _, b := range unknown {
			bits = append(bits, fmt.Sprintf("%d", b))
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"key holds capability bit(s) %s that this build has no name for; they may have been introduced by newer firmware and cannot be shown not to permit export",
			strings.Join(bits, ", ")))
	}

	if !res.CanSign {
		res.Warnings = append(res.Warnings, "key holds no signing capability; this attestation says nothing about certificate issuance")
	}

	// --- the attested key ---
	describePublicKey(cert.PublicKey, res)
	if fp, err := keycheck.Fingerprint(cert.PublicKey); err == nil {
		res.SPKIFingerprint = fp
	}

	if pol.ExpectedPublicKey != nil {
		matched := publicKeysEqual(cert.PublicKey, pol.ExpectedPublicKey)
		res.KeyMatched = &matched
		if matched {
			check("expected-key", true, "attested key equals the expected key")
		} else {
			check("expected-key", false, "attested key differs from the expected key")
			fail("the attested key is not the expected key: this attestation describes a different object on the device and says nothing about the key in question")
		}
	}

	// --- identity expectations ---
	if pol.ExpectedLabel != "" && claims.Label != pol.ExpectedLabel {
		check("expected-label", false, fmt.Sprintf("attested %q, expected %q", claims.Label, pol.ExpectedLabel))
		fail("attested key label %q does not match the expected label %q", claims.Label, pol.ExpectedLabel)
	}
	if pol.ExpectedSerial != "" && claims.DeviceSerial != pol.ExpectedSerial {
		check("expected-serial", false, fmt.Sprintf("attested %q, expected %q", claims.DeviceSerial, pol.ExpectedSerial))
		fail("attesting device serial %q does not match the expected serial %q", claims.DeviceSerial, pol.ExpectedSerial)
	}
	if pol.ExpectedObjectID != nil && claims.ObjectID != *pol.ExpectedObjectID {
		check("expected-object-id", false, fmt.Sprintf("attested 0x%04x, expected 0x%04x", claims.ObjectID, *pol.ExpectedObjectID))
		fail("attested object ID 0x%04x does not match the expected 0x%04x", claims.ObjectID, *pol.ExpectedObjectID)
	}

	verifyTrust(att, cert, claims, pol, res, check, fail)

	return finish(res)
}

// verifyTrust establishes that the assertions came from a real YubiHSM, in two
// independent steps that are reported separately because they can be
// established independently.
func verifyTrust(att *Attestation, cert *x509.Certificate, claims *Claims, pol Policy, res *Result,
	check func(string, bool, string) bool, fail func(string, ...any)) {

	deviceCert, err := att.DeviceCertificate()
	if err != nil {
		check("device-binding", false, err.Error())
		if pol.RequireDeviceBinding {
			fail("%v", err)
		}
		return
	}
	if deviceCert == nil {
		const detail = "attestation carries no device attestation certificate"
		check("device-binding", false, detail)
		msg := "attestation carries no device attestation certificate, so its signature cannot be checked and the device's assertions are unauthenticated"
		if pol.RequireDeviceBinding {
			fail("%s", msg)
		} else {
			res.Warnings = append(res.Warnings, msg)
		}
		return
	}

	// Step 1: the per-key certificate was signed by this device's attestation
	// key. Signature only — the fixed 2017..2071 validity a clockless YubiHSM
	// stamps into these certificates makes time checks meaningless here.
	if err := cert.CheckSignatureFrom(deviceCert); err != nil {
		check("device-binding", false, err.Error())
		fail("attestation certificate is not signed by the accompanying device attestation certificate (%v): the two do not belong together", err)
		return
	}
	res.DeviceBound = true
	check("device-binding", true, fmt.Sprintf("signed by device attestation certificate %q", deviceCert.Subject.CommonName))

	// The device certificate names the device it belongs to; if that disagrees
	// with the serial the key attestation asserts, the two were combined after
	// the fact.
	if claims.DeviceSerial != "" && !strings.Contains(deviceCert.Subject.CommonName, claims.DeviceSerial) {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"device attestation certificate subject %q does not mention the attested device serial %s",
			deviceCert.Subject.CommonName, claims.DeviceSerial))
	}

	// Step 2: the device certificate chains to a trusted root.
	roots := pol.Roots
	intermediates := pol.Intermediates
	if roots == nil {
		roots = EmbeddedRoots()
		if len(intermediates) == 0 {
			intermediates = EmbeddedIntermediates()
		}
	}
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	now := time.Now
	if pol.Now != nil {
		now = pol.Now
	}
	chains, err := deviceCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		check("chain-anchored", false, err.Error())
		msg := fmt.Sprintf("device attestation certificate %q does not chain to a trusted attestation root (%v); the assertions are self-consistent but nothing proves the attesting device is a genuine YubiHSM",
			deviceCert.Subject.CommonName, err)
		// Almost always a sub-CA published after this binary was built rather
		// than a fraudulent device, and the fix is one file, so say which one.
		if u := YubicoIntermediateURL(deviceCert); u != "" {
			msg += fmt.Sprintf("; if this is genuine hardware its issuing sub-CA %q is published at %s — fetch it and add it to the configured attestation anchors",
				deviceCert.Issuer.CommonName, u)
		}
		if pol.RequireAnchoredChain {
			fail("%s", msg)
		} else {
			res.Warnings = append(res.Warnings, msg)
		}
		return
	}
	res.ChainAnchored = true
	root := chains[0][len(chains[0])-1]
	res.TrustAnchor = root.Subject.CommonName
	check("chain-anchored", true, "chains to "+res.TrustAnchor)
}

// finish computes the bottom line and the one-line summary.
func finish(res *Result) *Result {
	res.Verified = len(res.Problems) == 0
	sort.Strings(res.Warnings)

	switch {
	case !res.Verified:
		res.Summary = fmt.Sprintf("NOT VERIFIED: %s", res.Problems[0])
	case res.NonExportable && res.GeneratedOnDevice:
		res.Summary = fmt.Sprintf("verified: key %q (object 0x%04x) was generated inside YubiHSM %s and cannot be exported from it",
			res.KeyLabel, res.ObjectID, res.DeviceSerial)
	case res.NonExportable:
		res.Summary = fmt.Sprintf("verified: key %q (object 0x%04x) cannot be exported from YubiHSM %s, but was imported rather than generated on it",
			res.KeyLabel, res.ObjectID, res.DeviceSerial)
	default:
		res.Summary = fmt.Sprintf("verified with findings: key %q (object 0x%04x) on YubiHSM %s is exportable under wrap",
			res.KeyLabel, res.ObjectID, res.DeviceSerial)
	}
	if res.Verified && !res.ChainAnchored {
		res.Summary += " (device certificate not anchored to a trusted attestation root)"
	}
	return res
}

// describePublicKey fills in the attested key's algorithm description.
func describePublicKey(pub crypto.PublicKey, res *Result) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		res.PublicKeyAlgorithm = "ECDSA"
		res.PublicKeyDetail = k.Curve.Params().Name
	case *rsa.PublicKey:
		res.PublicKeyAlgorithm = "RSA"
		res.PublicKeyDetail = fmt.Sprintf("%d bits", k.N.BitLen())
	case ed25519.PublicKey:
		res.PublicKeyAlgorithm = "Ed25519"
	default:
		res.PublicKeyAlgorithm = "unknown"
	}
}

// publicKeysEqual compares two public keys structurally.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b)
	}
	return false
}
