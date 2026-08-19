package yubihsmtest

// Tier 3b: device authenticity (Task 189).
//
// The rest of tier 3 attests keys, which takes the device for granted: an
// attestation is trustworthy because a Yubico-rooted key signed it, and nothing
// so far has checked that the key doing the signing belongs to real hardware.
// This file is that check, and it is where the chain to Yubico's published
// attestation CA is exercised against a device rather than against a fixture.
//
// Two properties matter and only hardware can show both:
//
//   - the certificate in opaque object 0 chains to Yubico's published root, and
//     the serial it asserts is the serial the device reports over its own
//     authenticated session;
//   - the device answers a nonce it has never seen, which is what separates
//     authenticating a device from replaying a certificate anyone can obtain.
//
// Answering costs a generate/attest/delete triple in the reserved challenge
// slot 0xfa00 — outside the suite's own 0x7f00–0x7f1f scratch range, because
// the range is fixed by the production code that a deployment also uses.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// clearChallengeSlot removes anything a previous interrupted run left in the
// reserved challenge slot. The production path clears its own leftovers, so
// doing it here keeps that recovery path from being what these tests exercise
// by accident.
//
// It deletes only an object whose label carries the challenge prefix — the same
// rule the production code applies, and for the same reason: 0xfa00 is outside
// the suite's own scratch range (deleteScratch refuses it, correctly), so
// anything else sitting there was put there by an operator and is not this
// suite's to destroy.
func clearChallengeSlot(t *testing.T) {
	t.Helper()
	const slot = hsmattest.DefaultDeviceChallengeKeyID
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		info, err := c.GetObjectInfo(ctx, slot, yubihsm.ObjectTypeAsymmetricKey)
		if err != nil {
			return // the usual case: the slot is free
		}
		if !strings.HasPrefix(info.Label, hsmattest.DeviceChallengeLabelPrefix) {
			t.Fatalf("object 0x%04x is labelled %q and is not a leftover device challenge; "+
				"refusing to delete it", slot, info.Label)
		}
		if err := c.DeleteObject(ctx, slot, yubihsm.ObjectTypeAsymmetricKey); err != nil {
			t.Fatalf("deleting the leftover challenge key at 0x%04x: %v", slot, err)
		}
		t.Logf("removed a leftover challenge key from 0x%04x", slot)
	})
}

// TestDeviceAuthenticityAgainstYubicosPublishedCA is the headline claim of the
// `secsy-ca hsm-attest device` command: this is a genuine YubiHSM, it has this
// serial number, and Yubico says so.
func TestDeviceAuthenticityAgainstYubicosPublishedCA(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)
	clearChallengeSlot(t)
	t.Cleanup(func() { clearChallengeSlot(t) })

	challenge, err := hsmattest.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t)
	att, err := hsmattest.NewDeviceAuthenticator(hsmConfig()).Attest(ctx, challenge)
	if err != nil {
		t.Fatalf("attesting the device: %v", err)
	}

	// Verified with the anchors this binary embeds — no -roots, no network, and
	// no configuration, which is the property a third party depends on.
	pol := hsmattest.DefaultDevicePolicy()
	pol.ExpectedChallenge = challenge
	res := hsmattest.VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("the attached device did not authenticate: %v", res.Problems)
	}
	if res.Serial == "" {
		t.Fatal("no serial number was established; that is the answer this command exists to produce")
	}
	if !res.ChainAnchored {
		t.Error("the device certificate did not chain to Yubico's published attestation root")
	}
	if !res.ProofOfPossession {
		t.Error("the device did not prove possession of its attestation key")
	}
	if res.ReportedSerialMatched == nil || !*res.ReportedSerialMatched {
		t.Errorf("the device reports serial %q but its certificate asserts %q", res.ReportedSerial, res.Serial)
	}
	if !strings.Contains(res.TrustAnchor, "Yubico") {
		t.Errorf("TrustAnchor = %q, want a Yubico root", res.TrustAnchor)
	}
	t.Logf("verified YubiHSM serial %s, firmware %s: %q -> %q",
		res.Serial, res.FirmwareVersion, res.IssuingCA, res.TrustAnchor)

	// The device's own assertion of its serial has to agree with what the driver
	// reads out of GET DEVICE INFO; a disagreement would mean one of the two is
	// not describing the attached hardware.
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			t.Fatalf("reading device info: %v", err)
		}
		if info.Serial != res.Serial {
			t.Errorf("GET DEVICE INFO reports serial %s, the attestation certificate asserts %s", info.Serial, res.Serial)
		}
	})
}

// Every challenge must produce a different answer. A device that returned the
// same certificate twice would make a recording as good as the device.
func TestDeviceChallengeAnswersAreDistinct(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 10)
	clearChallengeSlot(t)
	t.Cleanup(func() { clearChallengeSlot(t) })

	auth := hsmattest.NewDeviceAuthenticator(hsmConfig())
	ctx := testContext(t)

	first, err := hsmattest.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	second, err := hsmattest.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}

	a, err := auth.Attest(ctx, first)
	if err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	b, err := auth.Attest(ctx, second)
	if err != nil {
		t.Fatalf("second challenge: %v", err)
	}
	if a.ChallengeCertificatePEM == b.ChallengeCertificatePEM {
		t.Fatal("two different challenges produced the same certificate")
	}
	if a.DeviceCertificatePEM != b.DeviceCertificatePEM {
		t.Error("the device certificate changed between challenges")
	}

	// The recorded answer to the first challenge must not satisfy the second.
	// This is the replay case, run against real signatures.
	replayed := &hsmattest.DeviceAttestation{
		Kind:                    hsmattest.DeviceAttestationKind,
		DeviceCertificatePEM:    b.DeviceCertificatePEM,
		Challenge:               second,
		ChallengeCertificatePEM: a.ChallengeCertificatePEM,
		ReportedSerial:          b.ReportedSerial,
	}
	pol := hsmattest.DefaultDevicePolicy()
	pol.ExpectedChallenge = second
	if res := hsmattest.VerifyDevice(replayed, pol); res.Verified {
		t.Fatal("an answer to an earlier challenge satisfied a later one")
	}

	// Each genuine answer verifies against its own challenge.
	for _, tc := range []struct {
		att       *hsmattest.DeviceAttestation
		challenge string
	}{{a, first}, {b, second}} {
		p := hsmattest.DefaultDevicePolicy()
		p.ExpectedChallenge = tc.challenge
		if res := hsmattest.VerifyDevice(tc.att, p); !res.Verified {
			t.Errorf("the answer to challenge %s did not verify: %v", tc.challenge, res.Problems)
		}
	}
}

// The challenge key must be gone when the command returns. It exists only to
// carry a label into a certificate, and one left behind occupies a reserved
// handle and shows up in the device inventory as an unexplained key.
func TestDeviceChallengeLeavesNoKeyBehind(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)
	clearChallengeSlot(t)

	challenge, err := hsmattest.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hsmattest.NewDeviceAuthenticator(hsmConfig()).Attest(testContext(t), challenge); err != nil {
		t.Fatalf("attesting the device: %v", err)
	}

	var survivor string
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		if info, err := c.GetObjectInfo(ctx, hsmattest.DefaultDeviceChallengeKeyID, yubihsm.ObjectTypeAsymmetricKey); err == nil {
			survivor = info.Label
		}
	})
	if survivor != "" {
		clearChallengeSlot(t)
		t.Fatalf("the challenge key survived at 0x%04x (label %q)",
			hsmattest.DefaultDeviceChallengeKeyID, survivor)
	}
}

// The read-only form has to work on a device the caller may not write to, and
// has to say plainly that it establishes less.
func TestDeviceAttestationWithoutAChallenge(t *testing.T) {
	requireDevice(t)

	att, err := hsmattest.NewDeviceAuthenticator(hsmConfig()).Attest(testContext(t), "")
	if err != nil {
		t.Fatalf("reading the device certificate: %v", err)
	}
	if att.ChallengeCertificatePEM != "" {
		t.Error("the passive form produced a challenge certificate")
	}

	if res := hsmattest.VerifyDevice(att, hsmattest.DefaultDevicePolicy()); res.Verified {
		t.Error("a bundle with no answered challenge verified under the default policy")
	}
	pol := hsmattest.DefaultDevicePolicy()
	pol.RequireProofOfPossession = false
	res := hsmattest.VerifyDevice(att, pol)
	if !res.Verified {
		t.Fatalf("the passive bundle did not verify with possession waived: %v", res.Problems)
	}
	if !res.ChainAnchored || res.Serial == "" {
		t.Errorf("ChainAnchored = %v, Serial = %q; the certificate alone should still establish both",
			res.ChainAnchored, res.Serial)
	}
}

// Attesting the wrong device is the failure an operator most needs the command
// to catch: the right hardware, in the wrong slot of a rack.
func TestDeviceAttestationRejectsAnUnexpectedSerial(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)
	clearChallengeSlot(t)
	t.Cleanup(func() { clearChallengeSlot(t) })

	challenge, err := hsmattest.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	att, err := hsmattest.NewDeviceAuthenticator(hsmConfig()).Attest(testContext(t), challenge)
	if err != nil {
		t.Fatal(err)
	}

	pol := hsmattest.DefaultDevicePolicy()
	pol.ExpectedChallenge = challenge
	pol.ExpectedSerial = "00000001"
	res := hsmattest.VerifyDevice(att, pol)
	if res.Verified {
		t.Fatal("a device with a different serial satisfied the expectation")
	}
	if !strings.Contains(res.Problems[0], "not the expected 00000001") {
		t.Errorf("Problems = %v, want the expected serial named", res.Problems)
	}
}
