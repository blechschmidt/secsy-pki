package hsmattest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Device authenticity attestation (Task 189).
//
// The rest of this package attests *keys*: the device asserts what an object it
// holds is, and the assertions are trustworthy because a Yubico-rooted key
// signed them. That argument takes the device for granted. This file establishes
// the device itself — that the hardware on the other end of the USB cable is a
// genuine YubiHSM with the serial number it claims, as certified by Yubico's
// published attestation CA rather than by the operator.
//
// # Two links, and why one is not enough
//
// A YubiHSM ships with an attestation key whose certificate sits in opaque
// object 0. That certificate is signed by a Yubico sub-CA, chains to Yubico's
// published root, and carries the device's serial number in a Yubico-signed
// extension — so simply reading it and verifying the chain already proves that
// *a* genuine YubiHSM with that serial exists.
//
// It does not prove that the device answering right now is that one. The
// certificate is public: it is not secret, it is handed out on request, and it
// appears in every attestation the device has ever produced. Anything that can
// replay bytes can serve a copy. Chain verification alone therefore authenticates
// a certificate, not a device — the same reason a TLS server has to prove
// possession of its private key rather than merely presenting a certificate.
//
// So authenticity here is a challenge-response. The verifier picks a nonce, the
// device is made to sign a certificate over it with the attestation key, and the
// result is checked against the device certificate. Only a device holding that
// private key can answer, and a recorded answer to one nonce says nothing about
// the next.
//
// # Getting a nonce into a signature
//
// The YubiHSM will not sign a caller-supplied blob with the attestation key: the
// factory key holds sign-attestation-certificate and nothing else. The one
// channel from host to attestation signature is the label of an attested object,
// which is host-supplied at key generation. Device authentication therefore
// generates a throwaway key whose label encodes the nonce, attests it, deletes
// it, and keeps the certificate — the same primitive the audit subsystem uses to
// bind a log head to a serial number (hsm.AttestLabelledKey), read in the other
// direction: there the label is the payload and the serial is the evidence; here
// the nonce is the evidence and the serial is the payload.
//
// The cost is three audited device-log entries and a transient object in a
// reserved slot. `-no-challenge` skips it for callers that only want the
// certificate chain checked, and VerifyDevice says plainly which of the two
// claims it established.

// The challenge label is fixed by arithmetic rather than taste, for the reason
// spelled out in internal/hsmaudit/commitment.go: a YubiHSM object label is
// exactly 40 bytes, the device NUL-pads shorter ones and strips the padding on
// the way back out, and a full-width label never enters that round trip. Four
// bytes of prefix leave thirty-six, which is exactly what 27 bytes encode to in
// unpadded base64url.
//
// The nonce is hashed into that field rather than placed in it so that a
// challenge can be any string an auditor cares to choose — a word, a UUID, the
// digest of a document — without a length rule they have to know about.
const (
	// DeviceChallengeLabelPrefix marks a device label as an authenticity
	// challenge, and is what makes a leftover object safe to clean up.
	DeviceChallengeLabelPrefix = "da1:"
	// DeviceChallengeDigestBytes is how much of the challenge digest the label
	// carries. 216 bits is far past what a second preimage needs; the point of
	// spending the whole field is that there is nothing else to spend it on.
	DeviceChallengeDigestBytes = 27
	// DeviceChallengeLabelLen is the resulting label width, which is also the
	// device's label field width.
	DeviceChallengeLabelLen = 40
)

// The challenge key lives in its own reserved object-id range, distinct from the
// audit subsystem's (0xfb00..0xfbff), so that the device log tells the two
// schemes apart and neither can clean up after the other.
const (
	// DeviceChallengeKeyIDMin and DeviceChallengeKeyIDMax bound the range.
	DeviceChallengeKeyIDMin uint16 = 0xfa00
	DeviceChallengeKeyIDMax uint16 = 0xfaff
	// DefaultDeviceChallengeKeyID is the slot used unless a caller picks another
	// within the range.
	DefaultDeviceChallengeKeyID uint16 = 0xfa00
)

// DeviceAttestationKind identifies a device attestation bundle in JSON, so a
// verifier handed a file can tell it apart from a key attestation instead of
// guessing from which fields happen to be populated.
const DeviceAttestationKind = "yubihsm-device-attestation"

// DeviceChallengeLabel renders the on-device label that carries challenge.
func DeviceChallengeLabel(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return DeviceChallengeLabelPrefix + base64.RawURLEncoding.EncodeToString(sum[:DeviceChallengeDigestBytes])
}

// NewChallenge returns a fresh random challenge.
//
// 128 bits, hex-encoded so that it survives being copied between a terminal, a
// ticket and a config file — the challenge only has to be unpredictable to the
// party being audited, and it is echoed back in the bundle for them to check.
func NewChallenge() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("hsmattest: generating a device challenge: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// DeviceAttestation is a self-contained claim that a particular YubiHSM is
// genuine hardware.
//
// Like Attestation it carries certificates rather than conclusions: everything
// VerifyDevice reports is re-derived from these bytes, so an auditor who was
// never near the device can check the same things the operator did.
type DeviceAttestation struct {
	// Kind identifies this as a device attestation bundle.
	Kind string `json:"kind"`
	// DeviceCertificatePEM is the device's factory attestation certificate, read
	// from opaque object 0x0000. It is the object under examination: its chain
	// says the device is genuine and its Yubico-signed extension says which one.
	DeviceCertificatePEM string `json:"device_certificate_pem"`
	// Challenge is the nonce this attestation answers, empty when none was put.
	// It is echoed rather than trusted: verification recomputes the label from it
	// and compares against what the device signed.
	Challenge string `json:"challenge,omitempty"`
	// ChallengeCertificatePEM is the attestation certificate the device signed
	// over a throwaway key labelled with the challenge. This is the proof of
	// possession — the part that says the device answering held the attestation
	// private key, rather than that someone held a copy of its certificate.
	ChallengeCertificatePEM string `json:"challenge_certificate_pem,omitempty"`
	// ChallengeObjectID is the reserved handle the throwaway key occupied.
	// Informational: the certificate asserts it too, and that is the copy
	// verification reads.
	ChallengeObjectID uint16 `json:"challenge_object_id,omitempty"`
	// ReportedSerial is the serial the device gave over the authenticated
	// session. It is a claim by the device, not evidence — it is here so that
	// verification can report when the hardware being talked to and the
	// certificate it served disagree.
	ReportedSerial string `json:"reported_serial,omitempty"`
	// ProducedAt is the CA host's clock when the attestation was taken.
	// Informational; nothing in verification trusts it.
	ProducedAt time.Time `json:"produced_at"`
}

// DeviceCertificate parses the device attestation certificate.
func (d *DeviceAttestation) DeviceCertificate() (*x509.Certificate, error) {
	if d == nil || strings.TrimSpace(d.DeviceCertificatePEM) == "" {
		return nil, fmt.Errorf("hsmattest: device attestation carries no device certificate")
	}
	return parseCertPEM(d.DeviceCertificatePEM, "device attestation certificate")
}

// ChallengeCertificate parses the challenge attestation certificate, returning
// nil when the attestation carries none.
func (d *DeviceAttestation) ChallengeCertificate() (*x509.Certificate, error) {
	if d == nil || strings.TrimSpace(d.ChallengeCertificatePEM) == "" {
		return nil, nil
	}
	return parseCertPEM(d.ChallengeCertificatePEM, "challenge attestation certificate")
}

// DevicePolicy configures what a device attestation must show.
type DevicePolicy struct {
	// RequireProofOfPossession fails an attestation that carries no answered
	// challenge. On by default: without one the bundle establishes that a genuine
	// YubiHSM with this serial exists somewhere, not that it is the device that
	// produced this bundle.
	RequireProofOfPossession bool
	// RequireAnchoredChain fails a device certificate that does not chain to a
	// configured trust anchor. On by default, and it is the whole claim: an
	// unanchored device certificate is one anybody can mint.
	RequireAnchoredChain bool

	// ExpectedChallenge, when set, must equal the challenge the bundle answers.
	// An auditor who chose the nonce sets this; without it a bundle proves
	// possession at some unknown time rather than in answer to their request.
	ExpectedChallenge string
	// ExpectedSerial, when set, must equal the verified device serial.
	ExpectedSerial string

	// Roots and Intermediates anchor the device certificate. When Roots is nil
	// the embedded Yubico attestation anchors are used.
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate

	// Now overrides the clock for chain validation (tests).
	Now func() time.Time
}

// DefaultDevicePolicy is what an operator asking "is this a real YubiHSM"
// means.
func DefaultDevicePolicy() DevicePolicy {
	return DevicePolicy{
		RequireProofOfPossession: true,
		RequireAnchoredChain:     true,
	}
}

// DeviceResult is the verdict on one device attestation.
type DeviceResult struct {
	// Verified is the bottom line: every required check passed.
	Verified bool `json:"verified"`

	// Serial is the device serial number as asserted by the Yubico-signed device
	// attestation certificate — the answer to "which device is this", and the
	// only serial here that is evidence rather than a claim.
	Serial string `json:"serial,omitempty"`
	// FirmwareVersion is the firmware the device reported when it answered the
	// challenge. Empty for an attestation with no challenge: the device
	// certificate's own firmware extension records what was running when the
	// certificate was issued at the factory, which a firmware update makes stale,
	// so it is deliberately not reported as the device's version.
	FirmwareVersion string `json:"firmware_version,omitempty"`
	// FactoryFirmwareVersion is that manufacturing-time value, reported
	// separately because it identifies the certificate rather than the device.
	FactoryFirmwareVersion string `json:"factory_firmware_version,omitempty"`
	// SubjectCommonName is the device certificate's subject.
	SubjectCommonName string `json:"subject_common_name,omitempty"`

	// ChainAnchored reports that the device certificate chains to a trusted
	// attestation root, i.e. Yubico certified this device.
	ChainAnchored bool `json:"chain_anchored"`
	// TrustAnchor names the root the chain reached, and IssuingCA the sub-CA
	// directly above the device.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	IssuingCA   string `json:"issuing_ca,omitempty"`

	// ProofOfPossession reports that a certificate signed by this device's
	// attestation key was produced in answer to the challenge — the difference
	// between authenticating a device and authenticating a certificate.
	ProofOfPossession bool `json:"proof_of_possession"`
	// Challenge is the nonce that was answered.
	Challenge string `json:"challenge,omitempty"`
	// ChallengeObjectID is the handle the device asserts the challenge key had.
	ChallengeObjectID uint16 `json:"challenge_object_id,omitempty"`

	// ReportedSerial is what the device said over its authenticated session, and
	// ReportedSerialMatched whether that agreed with the certified serial. Nil
	// when the bundle carries no reported serial.
	ReportedSerial        string `json:"reported_serial,omitempty"`
	ReportedSerialMatched *bool  `json:"reported_serial_matched,omitempty"`

	// Checks itemizes every step that was evaluated.
	Checks []Check `json:"checks,omitempty"`
	// Problems are the failures that made Verified false.
	Problems []string `json:"problems,omitempty"`
	// Warnings are findings that did not fail the policy but that an operator
	// should see.
	Warnings []string `json:"warnings,omitempty"`
	// Summary is a one-line human verdict.
	Summary string `json:"summary"`
}

// VerifyDevice checks a device attestation against a policy.
//
// Like Verify it never returns an error: a bundle that fails to establish
// anything is a verdict, and the caller wants the reason.
func VerifyDevice(att *DeviceAttestation, pol DevicePolicy) *DeviceResult {
	if att == nil {
		att = &DeviceAttestation{}
	}
	res := &DeviceResult{Challenge: att.Challenge}
	fail := func(format string, args ...any) {
		res.Problems = append(res.Problems, fmt.Sprintf(format, args...))
	}
	check := func(name string, passed bool, detail string) {
		res.Checks = append(res.Checks, Check{Name: name, Passed: passed, Detail: detail})
	}

	deviceCert, err := att.DeviceCertificate()
	if err != nil {
		check("device-certificate", false, err.Error())
		fail("%v", err)
		return finishDevice(res)
	}
	res.SubjectCommonName = deviceCert.Subject.CommonName
	check("device-certificate", true, fmt.Sprintf("subject %q", deviceCert.Subject.CommonName))

	// The serial is read from the Yubico-signed extension rather than from the
	// subject, because the extension is what Yubico's signature commits to in a
	// machine-readable form. The subject is checked against it below: they always
	// agree on genuine hardware, and disagreement is the shape a hand-edited
	// certificate has.
	claims, err := ParseClaims(deviceCert)
	if err != nil {
		check("device-claims", false, err.Error())
		fail("device attestation certificate: %v", err)
		return finishDevice(res)
	}
	if claims.DeviceSerial == "" {
		check("device-claims", false, "no device-serial extension")
		fail("device attestation certificate carries no device-serial extension (%s): it names no device, so it cannot authenticate one",
			oidDeviceSerial)
		return finishDevice(res)
	}
	res.Serial = claims.DeviceSerial
	res.FactoryFirmwareVersion = claims.FirmwareVersion
	check("device-claims", true, "device-serial "+claims.DeviceSerial+" asserted by the certificate")

	if cn := serialFromSubject(deviceCert.Subject.CommonName); cn != "" && cn != claims.DeviceSerial {
		check("subject-serial", false, fmt.Sprintf("subject names %s, extension asserts %s", cn, claims.DeviceSerial))
		fail("device attestation certificate names serial %s in its subject but asserts %s in its device-serial extension; the two halves of one certificate disagree",
			cn, claims.DeviceSerial)
	} else if cn == "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"device attestation certificate subject %q does not name a serial number, so only the device-serial extension identifies this device",
			deviceCert.Subject.CommonName))
	} else {
		check("subject-serial", true, "subject and device-serial extension agree")
	}

	verifyDeviceChain(deviceCert, pol, res, check, fail)
	verifyDevicePossession(att, deviceCert, claims, pol, res, check, fail)

	// What the device said about itself over the authenticated session, against
	// what Yubico certified. On genuine hardware these are the same number; a
	// difference means the certificate in opaque object 0 was not issued to the
	// device serving it.
	if att.ReportedSerial != "" {
		res.ReportedSerial = att.ReportedSerial
		matched := att.ReportedSerial == res.Serial
		res.ReportedSerialMatched = &matched
		if matched {
			check("reported-serial", true, "the device reports the serial its certificate asserts")
		} else {
			check("reported-serial", false, fmt.Sprintf("device reports %s, certificate asserts %s", att.ReportedSerial, res.Serial))
			fail("the device reports serial %s but the attestation certificate it served asserts %s: the certificate was not issued to this device",
				att.ReportedSerial, res.Serial)
		}
	}

	if pol.ExpectedSerial != "" && pol.ExpectedSerial != res.Serial {
		check("expected-serial", false, fmt.Sprintf("attested %s, expected %s", res.Serial, pol.ExpectedSerial))
		fail("this is YubiHSM %s, not the expected %s", res.Serial, pol.ExpectedSerial)
	} else if pol.ExpectedSerial != "" {
		check("expected-serial", true, "device is the expected serial "+res.Serial)
	}

	return finishDevice(res)
}

// verifyDeviceChain establishes that Yubico certified this device.
func verifyDeviceChain(deviceCert *x509.Certificate, pol DevicePolicy, res *DeviceResult,
	check func(string, bool, string), fail func(string, ...any)) {

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
		msg := fmt.Sprintf("device attestation certificate %q does not chain to a trusted attestation root (%v); nothing here says the device is genuine Yubico hardware rather than something impersonating it",
			deviceCert.Subject.CommonName, err)
		// Almost always a sub-CA published after this binary was built rather
		// than a fraudulent device, and the fix is one file, so say which one.
		if u := YubicoIntermediateURL(deviceCert); u != "" {
			msg += fmt.Sprintf("; if this is genuine hardware its issuing sub-CA %q is published at %s — fetch it and pass it with -roots",
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
	chain := chains[0]
	res.TrustAnchor = chain[len(chain)-1].Subject.CommonName
	if len(chain) > 1 {
		res.IssuingCA = chain[1].Subject.CommonName
	}
	check("chain-anchored", true, "chains to "+res.TrustAnchor)
}

// verifyDevicePossession establishes that the device answering held the
// attestation private key, rather than a copy of a genuine device's certificate.
func verifyDevicePossession(att *DeviceAttestation, deviceCert *x509.Certificate, deviceClaims *Claims,
	pol DevicePolicy, res *DeviceResult, check func(string, bool, string), fail func(string, ...any)) {

	challengeCert, err := att.ChallengeCertificate()
	if err != nil {
		check("proof-of-possession", false, err.Error())
		fail("%v", err)
		return
	}
	if challengeCert == nil {
		const detail = "no challenge was answered"
		check("proof-of-possession", false, detail)
		msg := "this attestation carries no answered challenge: it shows that a genuine YubiHSM with this serial exists, not that the device it was taken from is that one — the device attestation certificate is public and anything able to replay bytes can serve a copy"
		if pol.RequireProofOfPossession {
			fail("%s", msg)
		} else {
			res.Warnings = append(res.Warnings, msg)
		}
		return
	}
	if att.Challenge == "" {
		check("proof-of-possession", false, "challenge certificate present but the challenge itself is missing")
		fail("the attestation carries a challenge certificate but not the challenge it answers, so there is nothing to check it against")
		return
	}

	// Signature only. The fixed 2017..2071 validity a clockless YubiHSM stamps
	// into these certificates makes time checks meaningless, as in Verify.
	if err := challengeCert.CheckSignatureFrom(deviceCert); err != nil {
		check("proof-of-possession", false, err.Error())
		fail("the challenge certificate is not signed by the device attestation certificate (%v): whatever answered does not hold that key", err)
		return
	}

	claims, err := ParseClaims(challengeCert)
	if err != nil {
		check("challenge-claims", false, err.Error())
		fail("challenge certificate: %v", err)
		return
	}
	if len(claims.Missing) > 0 {
		detail := "absent: " + strings.Join(claims.Missing, ", ")
		check("challenge-claims", false, detail)
		fail("challenge certificate omits YubiHSM extension(s) that every genuine attestation carries (%s)", detail)
		return
	}

	// The nonce is what makes this an authentication rather than a recording. A
	// label that does not encode the challenge means the certificate answers some
	// other question — very possibly one asked long ago.
	want := DeviceChallengeLabel(att.Challenge)
	if claims.Label != want {
		check("challenge-freshness", false, fmt.Sprintf("label %q, expected %q", claims.Label, want))
		fail("the challenge certificate attests an object labelled %q, but challenge %q encodes to %q: this certificate does not answer that challenge",
			claims.Label, att.Challenge, want)
		return
	}
	check("challenge-freshness", true, "the attested label encodes the challenge")

	if claims.DeviceSerial != deviceClaims.DeviceSerial {
		check("challenge-serial", false, fmt.Sprintf("challenge asserts %s, device certificate asserts %s", claims.DeviceSerial, deviceClaims.DeviceSerial))
		fail("the challenge was answered by device %s but the accompanying certificate belongs to device %s",
			claims.DeviceSerial, deviceClaims.DeviceSerial)
		return
	}
	check("challenge-serial", true, "the answering device asserts the certified serial")

	res.ProofOfPossession = true
	res.ChallengeObjectID = claims.ObjectID
	res.FirmwareVersion = claims.FirmwareVersion
	check("proof-of-possession", true, "the device signed a certificate over the challenge with its attestation key")

	if pol.ExpectedChallenge != "" && pol.ExpectedChallenge != att.Challenge {
		check("expected-challenge", false, fmt.Sprintf("answered %q, expected %q", att.Challenge, pol.ExpectedChallenge))
		fail("the attestation answers challenge %q, not the expected %q: it proves possession at some other time, not in answer to this request",
			att.Challenge, pol.ExpectedChallenge)
		return
	}
	if pol.ExpectedChallenge != "" {
		check("expected-challenge", true, "answers the expected challenge")
	}

	// Firmware moves; the certificate does not. Reporting both keeps an operator
	// from reading a legitimate update as a discrepancy.
	if deviceClaims.FirmwareVersion != "" && claims.FirmwareVersion != "" &&
		deviceClaims.FirmwareVersion != claims.FirmwareVersion {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the device runs firmware %s but its attestation certificate was issued under %s; this is what a firmware update looks like and is not by itself a problem",
			claims.FirmwareVersion, deviceClaims.FirmwareVersion))
	}

	// The challenge key should have been created in the reserved range. Outside
	// it, the answer is still a valid proof of possession, but the operations it
	// left in the device log are attributed to a handle that may hold something
	// else — which is exactly the ambiguity the reserved range exists to avoid.
	if claims.ObjectID < DeviceChallengeKeyIDMin || claims.ObjectID > DeviceChallengeKeyIDMax {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the challenge key was object 0x%04x, outside the range 0x%04x..0x%04x reserved for device challenges; its device-log entries are indistinguishable from work done with a production key at that handle",
			claims.ObjectID, DeviceChallengeKeyIDMin, DeviceChallengeKeyIDMax))
	}
	if claims.Capabilities != 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the challenge key held capabilities (%s); a challenge key exists only to carry a label and should hold none",
			strings.Join(claims.CapabilityNames, ", ")))
	}
}

// finishDevice computes the bottom line and the one-line summary.
func finishDevice(res *DeviceResult) *DeviceResult {
	res.Verified = len(res.Problems) == 0
	sort.Strings(res.Warnings)

	switch {
	case !res.Verified:
		res.Summary = "NOT VERIFIED: " + res.Problems[0]
	case res.ProofOfPossession && res.ChainAnchored:
		res.Summary = fmt.Sprintf("verified: this is YubiHSM serial %s — its attestation key answered the challenge and its certificate chains to %q",
			res.Serial, res.TrustAnchor)
	case res.ProofOfPossession:
		res.Summary = fmt.Sprintf("verified with findings: the device holding the certificate for serial %s answered the challenge, but that certificate chains to no trusted attestation root, so nothing establishes it as Yubico hardware",
			res.Serial)
	case res.ChainAnchored:
		res.Summary = fmt.Sprintf("verified with findings: a genuine YubiHSM with serial %s was certified by %q, but no challenge was answered, so this does not establish that the device examined is that one",
			res.Serial, res.TrustAnchor)
	default:
		res.Summary = fmt.Sprintf("verified with findings: a certificate claiming YubiHSM serial %s, anchored to nothing and answering nothing", res.Serial)
	}
	return res
}

// serialFromSubject extracts the serial a YubiHSM device attestation
// certificate names in its subject, which reads "YubiHSM Attestation
// (31650425)". It returns "" for any other shape rather than guessing, so an
// unrecognised subject is reported as unrecognised instead of as a mismatch.
func serialFromSubject(cn string) string {
	m := subjectSerialRE.FindStringSubmatch(cn)
	if m == nil {
		return ""
	}
	return m[1]
}

var subjectSerialRE = regexp.MustCompile(`\((\d+)\)`)

// DeviceAuthenticator produces device attestations from an attached YubiHSM.
type DeviceAuthenticator struct {
	Cfg hsm.Config
	// AttestKeyID selects the attesting key; 0 (the default) selects the
	// factory-provisioned one, which is the only one Yubico's PKI covers.
	AttestKeyID uint16
	// ChallengeObjectID is the reserved slot the throwaway challenge key
	// occupies; 0 selects DefaultDeviceChallengeKeyID.
	ChallengeObjectID uint16

	// Device-facing operations, as fields so that the surrounding logic is
	// testable without hardware. Nil means the real device.
	attestLabelled func(ctx context.Context, req hsm.LabelledKeyRequest) (certPEM, deviceCertPEM string, err error)
	deviceCert     func(ctx context.Context) ([]byte, error)
	deviceSerial   func(ctx context.Context) (string, error)
}

// NewDeviceAuthenticator returns an authenticator backed by the native YubiHSM
// driver.
func NewDeviceAuthenticator(cfg hsm.Config) *DeviceAuthenticator {
	return &DeviceAuthenticator{Cfg: cfg}
}

// Attest takes a device attestation, answering challenge.
//
// An empty challenge takes the passive form: the device certificate is read and
// nothing is created on the device. That is a weaker claim — see VerifyDevice —
// but it is also read-only, which is the right default for a caller that must
// not write to the device.
func (a *DeviceAuthenticator) Attest(ctx context.Context, challenge string) (*DeviceAttestation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	att := &DeviceAttestation{
		Kind:       DeviceAttestationKind,
		Challenge:  challenge,
		ProducedAt: time.Now().UTC(),
	}

	if challenge != "" {
		slot := a.ChallengeObjectID
		if slot == 0 {
			slot = DefaultDeviceChallengeKeyID
		}
		if slot < DeviceChallengeKeyIDMin || slot > DeviceChallengeKeyIDMax {
			return nil, fmt.Errorf("hsmattest: challenge object id 0x%04x is outside the reserved range 0x%04x..0x%04x",
				slot, DeviceChallengeKeyIDMin, DeviceChallengeKeyIDMax)
		}
		certPEM, deviceCertPEM, err := a.attest(ctx, hsm.LabelledKeyRequest{
			ObjectID:       slot,
			Label:          DeviceChallengeLabel(challenge),
			ReservedPrefix: DeviceChallengeLabelPrefix,
			AttestKeyID:    a.AttestKeyID,
		})
		if err != nil {
			return nil, fmt.Errorf("hsmattest: answering the device challenge: %w", err)
		}
		att.ChallengeCertificatePEM = certPEM
		att.DeviceCertificatePEM = deviceCertPEM
		att.ChallengeObjectID = slot
	} else {
		der, err := a.readDeviceCert(ctx)
		if err != nil {
			return nil, err
		}
		if len(der) == 0 {
			return nil, fmt.Errorf("hsmattest: the device returned an empty attestation certificate")
		}
		att.DeviceCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	// The serial the device reports is a cross-check, not the answer, so a
	// failure to read it degrades the bundle rather than failing the attestation:
	// the certified serial is already in hand.
	if serial, err := a.readSerial(ctx); err == nil {
		att.ReportedSerial = serial
	}
	return att, nil
}

func (a *DeviceAuthenticator) attest(ctx context.Context, req hsm.LabelledKeyRequest) (string, string, error) {
	if a.attestLabelled != nil {
		return a.attestLabelled(ctx, req)
	}
	return hsm.AttestLabelledKey(ctx, a.Cfg, req)
}

func (a *DeviceAuthenticator) readDeviceCert(ctx context.Context) ([]byte, error) {
	if a.deviceCert != nil {
		return a.deviceCert(ctx)
	}
	return hsm.GetDeviceAttestation(ctx, a.Cfg)
}

func (a *DeviceAuthenticator) readSerial(ctx context.Context) (string, error) {
	if a.deviceSerial != nil {
		return a.deviceSerial(ctx)
	}
	return hsm.GetDeviceSerial(ctx, a.Cfg)
}
