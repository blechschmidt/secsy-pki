package yubihsmtest

// Tier 3: per-key attestation.
//
// Attestation is the only mechanism by which an auditor who does not hold the
// device can learn anything true about a key on it. Every claim above this tier
// — "the CA key is non-exportable", "this public key lives in that HSM" —
// reduces to a signature over a certificate carrying the device's assertions,
// so the questions here are: does the device really sign it, do the assertions
// decode to what is actually configured, and do the negative cases fail.
//
// The negative cases are the reason this tier cannot be replaced by fixtures.
// An exportable key and an imported key have to be created on real hardware to
// know what those bits look like; a fixture captured from a well-behaved key
// only proves the parser agrees with itself.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// attestScratch generates a key with the given capabilities and attests it
// through the production attester, returning the attestation.
//
// The session is opened and closed around the key creation because the attester
// opens its own: on direct USB only one session exists at a time.
func attestScratch(t *testing.T, id uint16, name string, caps ...string) *hsmattest.Attestation {
	t.Helper()
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		deleteScratch(ctx, c, id)
		if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
			ID: id, Label: label(name), Domains: 1,
			Capabilities: capabilities(t, caps...), Algorithm: algECP256,
		}); err != nil {
			t.Fatalf("generating the %s key: %v", name, err)
		}
	})
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) { deleteScratch(ctx, c, id) })
	})

	ctx := testContext(t)
	att, err := hsmattest.NewDeviceAttester(hsmConfig()).AttestObject(ctx, id)
	if err != nil {
		t.Fatalf("attesting the %s key: %v", name, err)
	}
	return att
}

// TestAttestGeneratedKey is the headline claim: a key generated inside the HSM
// with no export capability attests as non-exportable and device-generated, and
// the attestation is signed by the device.
func TestAttestGeneratedKey(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	id := scratchID(11)
	att := attestScratch(t, id, "attest-good", "sign-ecdsa")

	res := hsmattest.Verify(att, hsmattest.DefaultPolicy())
	if !res.Verified {
		t.Fatalf("a device-generated non-exportable key failed verification: %v", res.Problems)
	}
	if !res.NonExportable {
		t.Error("the key was reported exportable; it holds no export capability")
	}
	if !res.GeneratedOnDevice {
		t.Errorf("the key was reported as origin %q; it was generated on the device", res.Origin)
	}
	if !res.DeviceBound {
		t.Error("the attestation was not bound to the device certificate, so nothing signed these assertions")
	}
	if !res.CanSign {
		t.Error("a key with sign-ecdsa was reported as unable to sign")
	}
	if res.ObjectID != id {
		t.Errorf("attested object id = 0x%04x, want 0x%04x", res.ObjectID, id)
	}
	if res.DeviceSerial == "" {
		t.Error("the attestation names no device serial, so it cannot be tied to a device")
	}
	if res.SPKIFingerprint == "" {
		t.Error("the attestation carries no SPKI fingerprint, so it cannot be matched to an issued certificate")
	}
	t.Logf("verdict: %s", res.Summary)
	t.Logf("serial %s firmware %s, capabilities %v, domains %v",
		res.DeviceSerial, res.FirmwareVersion, res.Capabilities, res.Domains)
}

// TestAttestExportableKeyFails is the negative case that gives the positive one
// its meaning. A key carrying exportable-under-wrap can have its private half
// leave the device, so it must fail the default policy — and the capability has
// to be reported by name, not merely counted, or an operator reading the report
// cannot tell which capability was the problem.
func TestAttestExportableKeyFails(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	att := attestScratch(t, scratchID(12), "attest-exportable", "sign-ecdsa", "exportable-under-wrap")

	res := hsmattest.Verify(att, hsmattest.DefaultPolicy())
	if res.Verified {
		t.Fatal("an exportable key passed verification")
	}
	if res.NonExportable {
		t.Error("a key holding exportable-under-wrap was reported as non-exportable")
	}
	if !res.GeneratedOnDevice {
		t.Error("the key was still generated on the device; exportability is a separate bit from origin")
	}
	var named bool
	for _, c := range res.Capabilities {
		if c == "exportable-under-wrap" {
			named = true
		}
	}
	if !named {
		t.Errorf("the report does not name exportable-under-wrap among %v", res.Capabilities)
	}
	t.Logf("rejected as expected: %v", res.Problems)
}

// TestAttestImportedKeyFails covers the other half of the claim. A key imported
// from a host existed outside the HSM before it arrived, so non-exportability
// alone says only that no copy can leave *now*. The origin bit is what
// distinguishes the two, and it has to be independent of the capability mask.
func TestAttestImportedKeyFails(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key on the host: %v", err)
	}
	id := scratchID(13)
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		deleteScratch(ctx, c, id)
		if _, err := c.PutAsymmetricKey(ctx, yubihsm.KeySpec{
			ID: id, Label: label("attest-imported"), Domains: 1,
			Capabilities: capabilities(t, "sign-ecdsa"), Algorithm: algECP256,
		}, host.D.FillBytes(make([]byte, 32))); err != nil {
			t.Fatalf("importing the host key: %v", err)
		}
	})
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) { deleteScratch(ctx, c, id) })
	})

	att, err := hsmattest.NewDeviceAttester(hsmConfig()).AttestObject(testContext(t), id)
	if err != nil {
		t.Fatalf("attesting the imported key: %v", err)
	}
	res := hsmattest.Verify(att, hsmattest.DefaultPolicy())
	if res.Verified {
		t.Fatal("an imported key passed the default policy, which requires device generation")
	}
	if res.GeneratedOnDevice {
		t.Error("an imported key was reported as generated on the device")
	}
	// Exportability is a different bit: this key is imported and still cannot
	// be exported. Conflating the two would make the report wrong in both
	// directions.
	if !res.NonExportable {
		t.Error("an imported key with no export capability was reported as exportable")
	}
	t.Logf("rejected as expected: origin %q, %v", res.Origin, res.Problems)
}

// TestAttestationBindsToTheExpectedPublicKey is what makes an attestation about
// a specific key rather than about the device in general.
//
// Without ExpectedPublicKey, a passing attestation says only that *some* key on
// the device is non-exportable — which is not a claim anyone needs. The
// interesting assertion is the negative one: an attestation for key A must not
// verify when the caller expected key B.
func TestAttestationBindsToTheExpectedPublicKey(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 10)

	idA, idB := scratchID(14), scratchID(15)
	attA := attestScratch(t, idA, "attest-bind-a", "sign-ecdsa")
	attB := attestScratch(t, idB, "attest-bind-b", "sign-ecdsa")

	certA, err := attA.Certificate()
	if err != nil {
		t.Fatalf("parsing attestation A: %v", err)
	}
	certB, err := attB.Certificate()
	if err != nil {
		t.Fatalf("parsing attestation B: %v", err)
	}

	pol := hsmattest.DefaultPolicy()
	pol.ExpectedPublicKey = certA.PublicKey
	res := hsmattest.Verify(attA, pol)
	if !res.Verified {
		t.Fatalf("attestation A did not verify against its own public key: %v", res.Problems)
	}
	if res.KeyMatched == nil || !*res.KeyMatched {
		t.Error("attestation A did not report a key match against its own public key")
	}

	// The same policy against the other key's attestation must fail.
	pol.ExpectedPublicKey = certB.PublicKey
	res = hsmattest.Verify(attA, pol)
	if res.Verified {
		t.Fatal("attestation A verified while the caller expected key B")
	}
	if res.KeyMatched == nil || *res.KeyMatched {
		t.Error("the mismatch was not reported as a key mismatch")
	}
	t.Logf("mismatch rejected as expected: %v", res.Problems)
}

// TestAttestationIsTamperEvident edits a byte of the signed certificate and
// checks the device binding breaks.
//
// The whole tier rests on the device's signature over the assertions. If the
// assertions could be changed without invalidating it, an attacker could take a
// genuine attestation for an exportable key and present it as non-exportable.
func TestAttestationIsTamperEvident(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	att := attestScratch(t, scratchID(16), "attest-tamper", "sign-ecdsa")
	if res := hsmattest.Verify(att, hsmattest.DefaultPolicy()); !res.Verified {
		t.Fatalf("the untampered attestation does not verify: %v", res.Problems)
	}

	cert, err := att.Certificate()
	if err != nil {
		t.Fatalf("parsing the attestation: %v", err)
	}
	// Flip a bit inside the signature and re-encode. Verification must fail.
	forged := *att
	tampered := make([]byte, len(cert.Raw))
	copy(tampered, cert.Raw)
	tampered[len(tampered)-1] ^= 0x01
	forged.CertificatePEM = pemCertificate(tampered)

	res := hsmattest.Verify(&forged, hsmattest.DefaultPolicy())
	if res.Verified {
		t.Fatal("an attestation with a flipped signature bit still verified")
	}
	if res.DeviceBound {
		t.Fatal("a tampered attestation was still reported as bound to the device")
	}
	t.Logf("tampering detected as expected: %v", res.Problems)
}

func pemCertificate(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestAttestationChainToYubico requires that the device in front of the
// operator is provably a genuine YubiHSM.
//
// This is the check that separates "a device asserts this key is
// non-exportable" from "a YubiHSM asserts it". Yubico publishes the YubiHSM 2
// attestation root and the sub-CA that issues device certificates, and both
// ship embedded, so stock hardware anchors with no configuration.
//
// A failure here has exactly two causes worth distinguishing, and the test says
// which: a device whose sub-CA Yubico published after this binary was built —
// fetch the one file the verdict names — or hardware that is not what it claims
// to be.
func TestAttestationChainToYubico(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	att := attestScratch(t, scratchID(17), "attest-chain", "sign-ecdsa")

	devCert, err := att.DeviceCertificate()
	if err != nil {
		t.Fatalf("parsing the device attestation certificate: %v", err)
	}
	t.Logf("device certificate: subject %q issuer %q", devCert.Subject, devCert.Issuer)

	res := hsmattest.Verify(att, hsmattest.DefaultPolicy())

	if !res.ChainAnchored {
		t.Errorf("the device certificate does not chain to an embedded Yubico attestation root: %v", res.Problems)
		t.Errorf("if this device is genuine, its issuing sub-CA %q is published at %s — add it to the embedded bundle",
			devCert.Issuer.CommonName, hsmattest.YubicoIntermediateURL(devCert))
		return
	}
	t.Logf("the device certificate chains to the embedded trust anchor %q", res.TrustAnchor)
	if !res.Verified {
		t.Errorf("the chain anchored but verification still failed: %v", res.Problems)
	}
}

// TestAttestByLabelResolvesExactly checks that label lookup is exact.
//
// Labels are how the product names keys, and the device permits one label to be
// a prefix of another. A resolver that matched on prefix would attest — and
// therefore make claims about — a key other than the one named, which is the
// worst possible failure for an attestation subsystem.
func TestAttestByLabelResolvesExactly(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 8)

	shortLabel := label("exact")
	longLabel := shortLabel + "-longer"
	idShort, idLong := scratchID(18), scratchID(19)

	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		for _, k := range []struct {
			id  uint16
			lbl string
		}{{idShort, shortLabel}, {idLong, longLabel}} {
			deleteScratch(ctx, c, k.id)
			if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
				ID: k.id, Label: k.lbl, Domains: 1,
				Capabilities: capabilities(t, "sign-ecdsa"), Algorithm: algECP256,
			}); err != nil {
				t.Fatalf("generating %q: %v", k.lbl, err)
			}
		}
	})
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) {
			deleteScratch(ctx, c, idShort)
			deleteScratch(ctx, c, idLong)
		})
	})

	attester := hsmattest.NewDeviceAttester(hsmConfig())
	ctx := testContext(t)

	att, err := attester.AttestKey(ctx, shortLabel)
	if err != nil {
		t.Fatalf("attesting %q: %v", shortLabel, err)
	}
	if att.Claims.ObjectID != idShort {
		t.Errorf("label %q resolved to 0x%04x, want 0x%04x (the longer label's key was picked)",
			shortLabel, att.Claims.ObjectID, idShort)
	}

	att, err = attester.AttestKey(ctx, longLabel)
	if err != nil {
		t.Fatalf("attesting %q: %v", longLabel, err)
	}
	if att.Claims.ObjectID != idLong {
		t.Errorf("label %q resolved to 0x%04x, want 0x%04x", longLabel, att.Claims.ObjectID, idLong)
	}

	if _, err := attester.AttestKey(ctx, shortLabel+"-nonexistent"); err == nil {
		t.Error("attesting a label that does not exist reported success")
	}
}
