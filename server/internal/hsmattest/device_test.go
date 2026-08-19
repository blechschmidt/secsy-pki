package hsmattest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Tests for device authenticity attestation (Task 189).
//
// The property under test is not "does the parser agree with itself" but "can a
// party who does not hold the device produce a bundle that verifies". Most of
// what follows is therefore an attacker: a replayed certificate, a foreign
// signature, an impostor's self-signed device certificate, a bundle whose two
// halves name different devices. Each one has to be refused for a *specific*
// reason, so the tests assert on which check failed rather than only on the
// verdict — a bundle refused for the wrong reason is a bundle the next change
// might accept.
//
// The synthetic PKI below stands in for Yubico's. TestVerifyDeviceRealHardware
// keeps it honest by running the same verification over the device certificate
// captured from an actual YubiHSM against the actual embedded Yubico roots.

// --- a synthetic YubiHSM attestation PKI ---

// testPKI is root -> sub-CA -> device, plus whatever the device signs.
type testPKI struct {
	rootCert   *x509.Certificate
	subCert    *x509.Certificate
	deviceCert *x509.Certificate
	deviceKey  crypto.Signer
	serial     string
	firmware   [3]byte
}

func newTestPKI(t *testing.T, serial string) *testPKI {
	t.Helper()
	p := &testPKI{serial: serial, firmware: [3]byte{2, 4, 0}}

	rootKey := testKey(t)
	p.rootCert = issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("Test YubiHSM Root CA"),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, nil, rootKey, rootKey.Public())

	subKey := testKey(t)
	p.subCert = issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkixName("Test YubiHSM 6742036 Sub-CA"),
		IsCA:                  true,
		MaxPathLen:            0,
		BasicConstraintsValid: true,
	}, p.rootCert, rootKey, subKey.Public())

	p.deviceKey = testKey(t)
	p.deviceCert = issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkixName(fmt.Sprintf("YubiHSM Attestation (%s)", serial)),
		IsCA:                  true,
		MaxPathLen:            0,
		BasicConstraintsValid: true,
		ExtraExtensions:       deviceExtensions(t, p.firmware, serial),
	}, p.subCert, subKey, p.deviceKey.Public())

	return p
}

// roots returns the anchors a verifier of this PKI would be configured with.
func (p *testPKI) roots() (*x509.CertPool, []*x509.Certificate) {
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	return pool, []*x509.Certificate{p.subCert}
}

// policy is the default policy pointed at this PKI's anchors.
func (p *testPKI) policy() DevicePolicy {
	pol := DefaultDevicePolicy()
	pol.Roots, pol.Intermediates = p.roots()
	return pol
}

// challengeCert produces what the device signs when it answers a challenge:
// an attestation over a throwaway key labelled with the challenge digest.
func (p *testPKI) challengeCert(t *testing.T, challenge string, opts ...func(*attestationSpec)) *x509.Certificate {
	t.Helper()
	spec := attestationSpec{
		label:    DeviceChallengeLabel(challenge),
		objectID: DefaultDeviceChallengeKeyID,
		serial:   p.serial,
		firmware: p.firmware,
		origin:   OriginGenerated,
		domains:  1,
	}
	for _, o := range opts {
		o(&spec)
	}
	return issue(t, &x509.Certificate{
		SerialNumber:    big.NewInt(4),
		Subject:         pkixName(fmt.Sprintf("YubiHSM Attestation id:0x%04x", spec.objectID)),
		ExtraExtensions: attestationExtensions(t, spec),
	}, p.deviceCert, p.deviceKey, testKey(t).Public())
}

// bundle assembles what the CLI would hand an auditor.
func (p *testPKI) bundle(t *testing.T, challenge string, opts ...func(*attestationSpec)) *DeviceAttestation {
	t.Helper()
	att := &DeviceAttestation{
		Kind:                 DeviceAttestationKind,
		DeviceCertificatePEM: certPEM(p.deviceCert),
		ReportedSerial:       p.serial,
		ProducedAt:           time.Now().UTC(),
	}
	if challenge != "" {
		att.Challenge = challenge
		att.ChallengeCertificatePEM = certPEM(p.challengeCert(t, challenge, opts...))
		att.ChallengeObjectID = DefaultDeviceChallengeKeyID
	}
	return att
}

// attestationSpec is the set of assertions a synthetic attestation carries.
type attestationSpec struct {
	label        string
	objectID     uint16
	serial       string
	firmware     [3]byte
	origin       uint8
	domains      uint16
	capabilities uint64
	drop         []asn1.ObjectIdentifier
}

func deviceExtensions(t *testing.T, firmware [3]byte, serial string) []pkix.Extension {
	t.Helper()
	// A device attestation certificate carries exactly two of the Yubico
	// extensions: the rest describe an attested object, and this certificate
	// attests none.
	return []pkix.Extension{
		{Id: oidFirmwareVersion, Value: mustMarshal(t, firmware[:])},
		{Id: oidDeviceSerial, Value: mustMarshal(t, serialInt(t, serial))},
	}
}

func attestationExtensions(t *testing.T, s attestationSpec) []pkix.Extension {
	t.Helper()
	exts := []pkix.Extension{
		{Id: oidFirmwareVersion, Value: mustMarshal(t, s.firmware[:])},
		{Id: oidDeviceSerial, Value: mustMarshal(t, serialInt(t, s.serial))},
		{Id: oidOrigin, Value: mustMarshal(t, bitString([]byte{s.origin}))},
		{Id: oidDomains, Value: mustMarshal(t, bitString([]byte{byte(s.domains >> 8), byte(s.domains)}))},
		{Id: oidCapabilities, Value: mustMarshal(t, bitString(be64(s.capabilities)))},
		{Id: oidObjectID, Value: mustMarshal(t, big.NewInt(int64(s.objectID)))},
		{Id: oidLabel, Value: mustMarshalUTF8(t, s.label)},
	}
	if len(s.drop) == 0 {
		return exts
	}
	out := exts[:0]
	for _, e := range exts {
		keep := true
		for _, oid := range s.drop {
			if e.Id.Equal(oid) {
				keep = false
			}
		}
		if keep {
			out = append(out, e)
		}
	}
	return out
}

// --- the happy path ---

func TestVerifyDeviceAuthenticatesTheHardware(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	challenge := "0123456789abcdef0123456789abcdef"
	att := pki.bundle(t, challenge)

	pol := pki.policy()
	pol.ExpectedChallenge = challenge
	pol.ExpectedSerial = "31650425"
	res := VerifyDevice(att, pol)

	if !res.Verified {
		t.Fatalf("Verified = false: %v", res.Problems)
	}
	if got, want := res.Serial, "31650425"; got != want {
		t.Errorf("Serial = %q, want %q", got, want)
	}
	if !res.ProofOfPossession {
		t.Error("ProofOfPossession = false for a bundle whose challenge the device answered")
	}
	if !res.ChainAnchored {
		t.Error("ChainAnchored = false for a device certificate that reaches the configured root")
	}
	if got, want := res.TrustAnchor, "Test YubiHSM Root CA"; got != want {
		t.Errorf("TrustAnchor = %q, want %q", got, want)
	}
	if got, want := res.IssuingCA, "Test YubiHSM 6742036 Sub-CA"; got != want {
		t.Errorf("IssuingCA = %q, want %q", got, want)
	}
	if got, want := res.FirmwareVersion, "2.4.0"; got != want {
		t.Errorf("FirmwareVersion = %q, want %q", got, want)
	}
	if res.ReportedSerialMatched == nil || !*res.ReportedSerialMatched {
		t.Error("ReportedSerialMatched is not true for a device reporting the serial it is certified under")
	}
	if len(res.Warnings) > 0 {
		t.Errorf("unexpected warnings on a clean bundle: %v", res.Warnings)
	}
	// The serial is the answer to the question this command exists to ask, so it
	// belongs in the one line an operator reads.
	if !strings.Contains(res.Summary, "31650425") {
		t.Errorf("Summary = %q, want it to name the verified serial", res.Summary)
	}
	for _, name := range []string{"device-certificate", "device-claims", "subject-serial", "chain-anchored",
		"proof-of-possession", "challenge-freshness", "challenge-serial", "reported-serial", "expected-serial"} {
		if !checkPassed(res.Checks, name) {
			t.Errorf("check %q did not pass (or was not run): %+v", name, res.Checks)
		}
	}
}

// --- replay: the reason a challenge exists at all ---

// A recorded answer to yesterday's challenge must not authenticate a device
// today. This is the whole difference between attesting a device and attesting
// a certificate, so it is checked from both ends: the bundle that admits which
// challenge it answers, and the one that lies about it.
func TestVerifyDeviceRejectsAReplayedChallengeAnswer(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	recorded := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fresh := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	t.Run("answers an older challenge", func(t *testing.T) {
		att := pki.bundle(t, recorded)
		pol := pki.policy()
		pol.ExpectedChallenge = fresh

		res := VerifyDevice(att, pol)
		if res.Verified {
			t.Fatal("a bundle answering a different challenge verified")
		}
		if checkPassed(res.Checks, "expected-challenge") || !checkRan(res.Checks, "expected-challenge") {
			t.Errorf("expected the expected-challenge check to run and fail: %+v", res.Checks)
		}
	})

	t.Run("claims to answer the fresh one", func(t *testing.T) {
		// The attacker holds a certificate over the old label and relabels the
		// envelope. The device's signature covers the label, so the substitution
		// is visible.
		att := pki.bundle(t, recorded)
		att.Challenge = fresh

		pol := pki.policy()
		pol.ExpectedChallenge = fresh
		res := VerifyDevice(att, pol)
		if res.Verified {
			t.Fatal("a relabelled replay verified")
		}
		if checkPassed(res.Checks, "challenge-freshness") {
			t.Error("challenge-freshness passed for a certificate attesting a different label")
		}
		if !containsSubstr(res.Problems, "does not answer that challenge") {
			t.Errorf("Problems = %v, want the freshness failure named", res.Problems)
		}
	})
}

// A device certificate is public. Serving a genuine one alongside a challenge
// answered by some other key is the cheapest impersonation there is.
func TestVerifyDeviceRejectsAChallengeAnsweredByAnotherKey(t *testing.T) {
	genuine := newTestPKI(t, "31650425")
	impostor := newTestPKI(t, "31650425")
	challenge := "cafebabecafebabecafebabecafebabe"

	att := genuine.bundle(t, challenge)
	att.ChallengeCertificatePEM = certPEM(impostor.challengeCert(t, challenge))

	pol := genuine.policy()
	pol.ExpectedChallenge = challenge
	res := VerifyDevice(att, pol)

	if res.Verified {
		t.Fatal("a challenge answered by a foreign key verified")
	}
	if res.ProofOfPossession {
		t.Error("ProofOfPossession = true for a signature the device certificate does not verify")
	}
	if !containsSubstr(res.Problems, "does not hold that key") {
		t.Errorf("Problems = %v, want the possession failure named", res.Problems)
	}
}

// The passive form is honest about being weaker rather than being refused
// outright — but only when the caller asked for it.
func TestVerifyDeviceRequiresProofOfPossession(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	att := pki.bundle(t, "")

	res := VerifyDevice(att, pki.policy())
	if res.Verified {
		t.Fatal("a bundle with no answered challenge verified under the default policy")
	}
	if !containsSubstr(res.Problems, "no answered challenge") {
		t.Errorf("Problems = %v, want the missing challenge named", res.Problems)
	}

	pol := pki.policy()
	pol.RequireProofOfPossession = false
	res = VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false with proof of possession waived: %v", res.Problems)
	}
	if res.ProofOfPossession {
		t.Error("ProofOfPossession = true for a bundle that answered nothing")
	}
	if !containsSubstr(res.Warnings, "not that the device it was taken from is that one") {
		t.Errorf("Warnings = %v, want the weaker claim spelled out", res.Warnings)
	}
	if !strings.Contains(res.Summary, "no challenge was answered") {
		t.Errorf("Summary = %q, want it to say the claim is the weaker one", res.Summary)
	}
}

// A bundle carrying an answer but not the question cannot be checked at all.
func TestVerifyDeviceRejectsAChallengeCertificateWithoutItsChallenge(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	att := pki.bundle(t, "deadbeefdeadbeefdeadbeefdeadbeef")
	att.Challenge = ""

	res := VerifyDevice(att, pki.policy())
	if res.Verified {
		t.Fatal("a bundle with an uncheckable challenge certificate verified")
	}
	if !containsSubstr(res.Problems, "not the challenge it answers") {
		t.Errorf("Problems = %v, want the missing challenge named", res.Problems)
	}
}

// --- anchoring: the other half of the claim ---

// Anyone can mint a certificate saying "YubiHSM Attestation (31650425)" and
// answer challenges with it. Only the chain to Yubico says it is hardware.
func TestVerifyDeviceRejectsAnUnanchoredDeviceCertificate(t *testing.T) {
	impostor := newTestPKI(t, "31650425")
	challenge := "f00df00df00df00df00df00df00df00d"
	att := impostor.bundle(t, challenge)

	// Verified against the embedded Yubico anchors, as a third party would.
	pol := DefaultDevicePolicy()
	pol.ExpectedChallenge = challenge
	res := VerifyDevice(att, pol)

	if res.Verified {
		t.Fatal("a self-signed impostor chain verified against Yubico's roots")
	}
	if res.ChainAnchored {
		t.Error("ChainAnchored = true for a certificate no configured root covers")
	}
	if !containsSubstr(res.Problems, "genuine Yubico hardware") {
		t.Errorf("Problems = %v, want the anchoring failure named", res.Problems)
	}
	// Proof of possession still holds — the impostor does own its own key. The
	// report has to keep the two apart or an operator cannot tell which half of
	// the claim failed.
	if !res.ProofOfPossession {
		t.Error("ProofOfPossession = false; possession and anchoring are independent")
	}

	pol.RequireAnchoredChain = false
	res = VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false with anchoring waived: %v", res.Problems)
	}
	if !strings.Contains(res.Summary, "chains to no trusted attestation root") {
		t.Errorf("Summary = %q, want the unanchored caveat", res.Summary)
	}
}

// An unanchored chain is usually a sub-CA published after this binary was
// built, so the report has to say where to get it.
func TestVerifyDeviceNamesThePublishedIntermediate(t *testing.T) {
	att := &DeviceAttestation{Kind: DeviceAttestationKind, DeviceCertificatePEM: realDeviceCertPEM}
	pol := DefaultDevicePolicy()
	pol.RequireProofOfPossession = false
	pol.Roots = x509.NewCertPool() // no anchors at all
	res := VerifyDevice(att, pol)

	if res.Verified {
		t.Fatal("a device certificate verified against an empty root pool")
	}
	if !containsSubstr(res.Problems, "https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem") {
		t.Errorf("Problems = %v, want the published sub-CA URL", res.Problems)
	}
}

// --- identity: which device is this ---

func TestVerifyDeviceRejectsSerialDisagreements(t *testing.T) {
	challenge := "1111111111111111aaaaaaaaaaaaaaaa"

	t.Run("the device reports a different serial than its certificate", func(t *testing.T) {
		pki := newTestPKI(t, "31650425")
		att := pki.bundle(t, challenge)
		att.ReportedSerial = "99999999"

		res := VerifyDevice(att, pki.policy())
		if res.Verified {
			t.Fatal("a device serving another device's certificate verified")
		}
		if res.ReportedSerialMatched == nil || *res.ReportedSerialMatched {
			t.Error("ReportedSerialMatched should be false")
		}
		if !containsSubstr(res.Problems, "was not issued to this device") {
			t.Errorf("Problems = %v, want the mismatch named", res.Problems)
		}
	})

	t.Run("the answering device is not the certified one", func(t *testing.T) {
		pki := newTestPKI(t, "31650425")
		att := pki.bundle(t, challenge, func(s *attestationSpec) { s.serial = "12345678" })

		res := VerifyDevice(att, pki.policy())
		if res.Verified {
			t.Fatal("a challenge asserting another serial verified")
		}
		if !containsSubstr(res.Problems, "belongs to device") {
			t.Errorf("Problems = %v, want the serial split named", res.Problems)
		}
	})

	t.Run("not the device the operator expected", func(t *testing.T) {
		pki := newTestPKI(t, "31650425")
		att := pki.bundle(t, challenge)
		pol := pki.policy()
		pol.ExpectedSerial = "11111111"

		res := VerifyDevice(att, pol)
		if res.Verified {
			t.Fatal("the wrong device satisfied -expect-serial")
		}
		if !containsSubstr(res.Problems, "not the expected 11111111") {
			t.Errorf("Problems = %v, want the expectation named", res.Problems)
		}
	})
}

// A certificate whose subject and extension name different devices was edited
// after issuance, or was never issued by a device at all.
func TestVerifyDeviceRejectsSubjectAndExtensionDisagreement(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	// Re-issue the device certificate with a subject naming another device.
	subKey := testKey(t)
	root := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkixName("Test Root"), IsCA: true, BasicConstraintsValid: true,
	}, nil, subKey, subKey.Public())
	devKey := testKey(t)
	dev := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkixName("YubiHSM Attestation (11112222)"),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtraExtensions:       deviceExtensions(t, pki.firmware, "31650425"),
	}, root, subKey, devKey.Public())

	pool := x509.NewCertPool()
	pool.AddCert(root)
	pol := DefaultDevicePolicy()
	pol.Roots = pool
	pol.RequireProofOfPossession = false

	res := VerifyDevice(&DeviceAttestation{Kind: DeviceAttestationKind, DeviceCertificatePEM: certPEM(dev)}, pol)
	if res.Verified {
		t.Fatal("a certificate naming two different devices verified")
	}
	if !containsSubstr(res.Problems, "the two halves of one certificate disagree") {
		t.Errorf("Problems = %v, want the internal disagreement named", res.Problems)
	}
}

func TestVerifyDeviceRejectsACertificateThatNamesNoDevice(t *testing.T) {
	pol := DefaultDevicePolicy()
	pol.RequireProofOfPossession = false

	t.Run("no attestation extensions at all", func(t *testing.T) {
		res := VerifyDevice(&DeviceAttestation{DeviceCertificatePEM: selfSignedPEM(t)}, pol)
		if res.Verified {
			t.Fatal("an ordinary certificate verified as a device attestation")
		}
	})

	t.Run("firmware but no serial", func(t *testing.T) {
		key := testKey(t)
		cert := issue(t, &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			Subject:         pkixName("YubiHSM Attestation (31650425)"),
			ExtraExtensions: []pkix.Extension{{Id: oidFirmwareVersion, Value: mustMarshal(t, []byte{2, 4, 0})}},
		}, nil, key, key.Public())

		res := VerifyDevice(&DeviceAttestation{DeviceCertificatePEM: certPEM(cert)}, pol)
		if res.Verified {
			t.Fatal("a certificate with no device-serial extension verified")
		}
		if !containsSubstr(res.Problems, "carries no device-serial extension") {
			t.Errorf("Problems = %v, want the missing serial named", res.Problems)
		}
	})

	t.Run("not PEM at all", func(t *testing.T) {
		res := VerifyDevice(&DeviceAttestation{DeviceCertificatePEM: "not a certificate"}, pol)
		if res.Verified {
			t.Fatal("garbage verified")
		}
	})

	t.Run("nothing at all", func(t *testing.T) {
		res := VerifyDevice(nil, pol)
		if res.Verified {
			t.Fatal("a nil attestation verified")
		}
	})
}

// A genuine attestation carries all seven extensions; one stripped of the
// inconvenient ones is what a forgery looks like.
func TestVerifyDeviceRejectsStrippedChallengeExtensions(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	challenge := "2222222222222222bbbbbbbbbbbbbbbb"
	att := pki.bundle(t, challenge, func(s *attestationSpec) { s.drop = []asn1.ObjectIdentifier{oidObjectID} })

	res := VerifyDevice(att, pki.policy())
	if res.Verified {
		t.Fatal("a challenge certificate missing an extension verified")
	}
	if !containsSubstr(res.Problems, "omits YubiHSM extension(s)") {
		t.Errorf("Problems = %v, want the missing extension named", res.Problems)
	}
}

// --- findings that are worth saying but do not fail the claim ---

func TestVerifyDeviceWarnsAboutAnIrregularChallengeKey(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	challenge := "3333333333333333cccccccccccccccc"
	att := pki.bundle(t, challenge, func(s *attestationSpec) {
		s.objectID = 0x0100                          // outside the reserved range
		s.capabilities = 1 << CapExportableUnderWrap // and able to leave the device
	})

	res := VerifyDevice(att, pki.policy())
	if !res.Verified {
		t.Fatalf("Verified = false; an irregular challenge key is a finding, not a forgery: %v", res.Problems)
	}
	if !containsSubstr(res.Warnings, "reserved for device challenges") {
		t.Errorf("Warnings = %v, want the reserved-range finding", res.Warnings)
	}
	if !containsSubstr(res.Warnings, "should hold none") {
		t.Errorf("Warnings = %v, want the capability finding", res.Warnings)
	}
}

// A firmware update makes the certificate's manufacturing-time version stale.
// Reporting that as a discrepancy would train operators to ignore the report.
func TestVerifyDeviceTreatsAFirmwareUpdateAsAFinding(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	challenge := "4444444444444444dddddddddddddddd"
	att := pki.bundle(t, challenge, func(s *attestationSpec) { s.firmware = [3]byte{2, 4, 2} })

	res := VerifyDevice(att, pki.policy())
	if !res.Verified {
		t.Fatalf("Verified = false for an updated device: %v", res.Problems)
	}
	if got, want := res.FirmwareVersion, "2.4.2"; got != want {
		t.Errorf("FirmwareVersion = %q, want the running version %q", got, want)
	}
	if got, want := res.FactoryFirmwareVersion, "2.4.0"; got != want {
		t.Errorf("FactoryFirmwareVersion = %q, want %q", got, want)
	}
	if !containsSubstr(res.Warnings, "firmware update") {
		t.Errorf("Warnings = %v, want the update explained", res.Warnings)
	}
}

// --- real hardware bytes, real Yubico roots, no device ---

// The device certificate captured from the attached YubiHSM must authenticate
// against the anchors this binary embeds. It is the one test that exercises the
// actual published-CA path — synthetic PKIs prove the logic, this proves the
// logic is pointed at the right certificates.
func TestVerifyDeviceRealHardwareCertificateAnchorsToYubico(t *testing.T) {
	att := &DeviceAttestation{
		Kind:                 DeviceAttestationKind,
		DeviceCertificatePEM: realDeviceCertPEM,
		ReportedSerial:       "31650425",
	}
	pol := DefaultDevicePolicy()
	pol.RequireProofOfPossession = false // the fixture predates challenges

	res := VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false for real hardware against the embedded Yubico roots: %v", res.Problems)
	}
	if got, want := res.Serial, "31650425"; got != want {
		t.Errorf("Serial = %q, want %q", got, want)
	}
	if got, want := res.TrustAnchor, "Yubico YubiHSM Root CA"; got != want {
		t.Errorf("TrustAnchor = %q, want %q", got, want)
	}
	if got, want := res.IssuingCA, "Yubico YubiHSM 6742036 Sub-CA"; got != want {
		t.Errorf("IssuingCA = %q, want %q", got, want)
	}
	if got, want := res.SubjectCommonName, "YubiHSM Attestation (31650425)"; got != want {
		t.Errorf("SubjectCommonName = %q, want %q", got, want)
	}
}

// The per-key attestation captured from the same device is signed by that
// device certificate, which is the signature check the challenge relies on.
// Running it here means a regression in the possession check surfaces even
// without hardware — only the freshness half needs a live device.
func TestVerifyDeviceRealHardwareAttestationIsDeviceSigned(t *testing.T) {
	att := &DeviceAttestation{
		Kind:                    DeviceAttestationKind,
		DeviceCertificatePEM:    realDeviceCertPEM,
		Challenge:               "not the challenge this certificate answers",
		ChallengeCertificatePEM: realAttestationPEM,
	}
	res := VerifyDevice(att, DefaultDevicePolicy())

	// It must fail — the fixture answers no challenge — but on freshness, having
	// got past the signature check.
	if res.Verified {
		t.Fatal("a certificate answering no challenge verified")
	}
	if !checkPassed(res.Checks, "chain-anchored") {
		t.Error("the real device certificate did not anchor")
	}
	if checkRan(res.Checks, "challenge-freshness") && checkPassed(res.Checks, "challenge-freshness") {
		t.Error("challenge-freshness passed for a label that is not a challenge digest")
	}
	if !containsSubstr(res.Problems, "does not answer that challenge") {
		t.Errorf("Problems = %v; expected to fail on freshness, i.e. after the device signature verified", res.Problems)
	}
}

// --- the challenge encoding ---

// The label field is exactly 40 bytes on the device and the encoding has to fill
// it exactly: a shorter label is NUL-padded on the way in and stripped on the
// way out, which is a round trip a comparison should never depend on.
func TestDeviceChallengeLabelFillsTheDeviceField(t *testing.T) {
	for _, challenge := range []string{"", "x", strings.Repeat("long", 500), "0123456789abcdef"} {
		label := DeviceChallengeLabel(challenge)
		if len(label) != DeviceChallengeLabelLen {
			t.Errorf("label for %d-byte challenge is %d bytes, want %d", len(challenge), len(label), DeviceChallengeLabelLen)
		}
		if !strings.HasPrefix(label, DeviceChallengeLabelPrefix) {
			t.Errorf("label %q does not carry the reserved prefix", label)
		}
	}
	if DeviceChallengeLabel("a") == DeviceChallengeLabel("b") {
		t.Error("distinct challenges encode to the same label")
	}
	// Determinism is what lets a verifier recompute the label from the challenge
	// instead of trusting the one the bundle reports.
	first, again := DeviceChallengeLabel("a"), DeviceChallengeLabel(strings.Repeat("a", 1))
	if first != again {
		t.Errorf("the encoding is not deterministic: %q then %q", first, again)
	}
}

func TestNewChallengeIsFreshAndPrintable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		c, err := NewChallenge()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hex.DecodeString(c); err != nil {
			t.Fatalf("challenge %q is not hex: %v", c, err)
		}
		if len(c) != 32 {
			t.Fatalf("challenge %q is %d chars, want 32 (128 bits)", c, len(c))
		}
		if seen[c] {
			t.Fatalf("challenge %q repeated", c)
		}
		seen[c] = true
	}
}

// --- the device-facing half ---

// Attest has to ask the device for exactly the right thing: the challenge in the
// label, the reserved prefix so a leftover can be cleaned up, and the reserved
// slot so the log entries are attributable.
func TestDeviceAuthenticatorAsksForTheRightAttestation(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	challenge := "5555555555555555eeeeeeeeeeeeeeee"

	var got hsm.LabelledKeyRequest
	auth := &DeviceAuthenticator{
		attestLabelled: func(_ context.Context, req hsm.LabelledKeyRequest) (string, string, error) {
			got = req
			return certPEM(pki.challengeCert(t, challenge)), certPEM(pki.deviceCert), nil
		},
		deviceSerial: func(context.Context) (string, error) { return "31650425", nil },
		deviceCert: func(context.Context) ([]byte, error) {
			t.Error("the device certificate was read separately although the challenge path returns it")
			return nil, nil
		},
	}

	att, err := auth.Attest(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != DeviceChallengeLabel(challenge) {
		t.Errorf("attested label = %q, want the challenge digest %q", got.Label, DeviceChallengeLabel(challenge))
	}
	if got.ReservedPrefix != DeviceChallengeLabelPrefix {
		t.Errorf("ReservedPrefix = %q, want %q; without it a leftover key cannot be cleaned up",
			got.ReservedPrefix, DeviceChallengeLabelPrefix)
	}
	if got.ObjectID != DefaultDeviceChallengeKeyID {
		t.Errorf("ObjectID = 0x%04x, want the reserved 0x%04x", got.ObjectID, DefaultDeviceChallengeKeyID)
	}
	if got.Capabilities != 0 {
		t.Errorf("Capabilities = 0x%x, want none: a challenge key must not be usable for anything", got.Capabilities)
	}
	if att.Kind != DeviceAttestationKind {
		t.Errorf("Kind = %q, want %q", att.Kind, DeviceAttestationKind)
	}
	if att.ReportedSerial != "31650425" {
		t.Errorf("ReportedSerial = %q", att.ReportedSerial)
	}

	pol := pki.policy()
	pol.ExpectedChallenge = challenge
	if res := VerifyDevice(att, pol); !res.Verified {
		t.Fatalf("the bundle Attest produced does not verify: %v", res.Problems)
	}
}

// The passive form must not write to the device. A caller that chose it did so
// because writing was unacceptable, so reaching for key generation anyway would
// be worse than failing.
func TestDeviceAuthenticatorPassiveFormOnlyReads(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	auth := &DeviceAuthenticator{
		attestLabelled: func(context.Context, hsm.LabelledKeyRequest) (string, string, error) {
			t.Error("the passive form generated a key on the device")
			return "", "", nil
		},
		deviceCert:   func(context.Context) ([]byte, error) { return pki.deviceCert.Raw, nil },
		deviceSerial: func(context.Context) (string, error) { return "31650425", nil },
	}

	att, err := auth.Attest(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if att.ChallengeCertificatePEM != "" {
		t.Error("the passive form produced a challenge certificate")
	}
	pol := pki.policy()
	pol.RequireProofOfPossession = false
	if res := VerifyDevice(att, pol); !res.Verified {
		t.Fatalf("the passive bundle does not verify: %v", res.Problems)
	}
}

// A slot outside the reserved range is refused before the device is touched:
// the alternative is a throwaway key at a handle that may already hold
// something, and a delete that follows.
func TestDeviceAuthenticatorRefusesAnUnreservedSlot(t *testing.T) {
	auth := &DeviceAuthenticator{
		ChallengeObjectID: 0x0100,
		attestLabelled: func(context.Context, hsm.LabelledKeyRequest) (string, string, error) {
			t.Error("the device was touched despite an unreserved slot")
			return "", "", nil
		},
	}
	if _, err := auth.Attest(context.Background(), "abcd"); err == nil {
		t.Fatal("an unreserved challenge slot was accepted")
	} else if !strings.Contains(err.Error(), "reserved range") {
		t.Fatalf("error = %v, want it to name the reserved range", err)
	}
}

// Reading the serial is a cross-check, not the answer. Losing it must not cost
// the attestation, which already carries a Yubico-signed serial.
func TestDeviceAuthenticatorToleratesAnUnreadableSerial(t *testing.T) {
	pki := newTestPKI(t, "31650425")
	auth := &DeviceAuthenticator{
		deviceCert:   func(context.Context) ([]byte, error) { return pki.deviceCert.Raw, nil },
		deviceSerial: func(context.Context) (string, error) { return "", fmt.Errorf("device info unavailable") },
	}
	att, err := auth.Attest(context.Background(), "")
	if err != nil {
		t.Fatalf("a failed serial read cost the whole attestation: %v", err)
	}
	if att.ReportedSerial != "" {
		t.Errorf("ReportedSerial = %q, want it empty", att.ReportedSerial)
	}
	pol := pki.policy()
	pol.RequireProofOfPossession = false
	res := VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false: %v", res.Problems)
	}
	if res.ReportedSerialMatched != nil {
		t.Error("ReportedSerialMatched should be nil when nothing was reported")
	}
}

// --- helpers ---

func testKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issue signs tmpl under parent, or self-signs it when parent is nil.
func issue(t *testing.T, tmpl, parent *x509.Certificate, signer crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustMarshalUTF8(t *testing.T, s string) []byte {
	t.Helper()
	der, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func serialInt(t *testing.T, serial string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		t.Fatalf("serial %q is not a number", serial)
	}
	return n
}

// bitString encodes bytes the way the device does: whole bytes, no unused bits.
func bitString(b []byte) asn1.BitString {
	return asn1.BitString{Bytes: b, BitLength: len(b) * 8}
}

func be64(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func checkRan(checks []Check, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return true
		}
	}
	return false
}

func checkPassed(checks []Check, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return c.Passed
		}
	}
	return false
}
