package hsmaudit

// These tests are the written-down form of the evaluation in genesis.go: they
// pin the two measurements it rests on and demonstrate the argument that makes
// the measurements beside the point. The hardware half — that the sentinel's
// bytes really are constant across factory resets and its digest really is not
// — lives in internal/yubihsmtest/genesis_test.go, which needs a device.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// TestSentinelPreimageIsAPublicConstant is the first half of why the anchor
// cannot be made self-verifying: the bytes a sentinel contributes to the chain
// are fixed, so any hash of them is the same on every YubiHSM ever made.
func TestSentinelPreimageIsAPublicConstant(t *testing.T) {
	got := hex.EncodeToString(SentinelPreimage())
	if got != SentinelPreimageHex {
		t.Fatalf("sentinel preimage is %s, want %s", got, SentinelPreimageHex)
	}
	if !hsm.IsBootSentinel(Sentinel()) {
		t.Fatal("Sentinel() is not recognised as a device-init sentinel")
	}

	// Spelled out rather than asserted through a helper, because the shape is
	// the claim: a two-byte entry number of 1, then nothing but 0xff.
	want := append([]byte{0x00, 0x01}, repeat(0xff, 14)...)
	if !bytes.Equal(SentinelPreimage(), want) {
		t.Fatalf("sentinel preimage %x is not 0x0001 followed by fourteen 0xff bytes", SentinelPreimage())
	}

	// The consequence: hashing it yields a value that identifies nothing. Two
	// unrelated devices would publish the same "anchor", so it could not
	// distinguish their histories.
	deviceA := hsm.ComputeEntryHash(Sentinel(), nil)
	deviceB := hsm.ComputeEntryHash(Sentinel(), nil)
	if deviceA != deviceB {
		t.Fatal("hashing a constant produced two values, which cannot happen")
	}
}

// TestSentinelDigestIsNotDerivable pins the candidate seeds that were ruled out
// against hardware. A firmware that started deriving the genesis digest from any
// of them would make this test fail, which is the notification we want: the
// anchor would then be a universal constant and pinning it would prove nothing.
//
// The observations are the seven factory resets of YubiHSM 2 serial 31650425
// (firmware 2.4.0) recorded in genesis.go.
func TestSentinelDigestIsNotDerivable(t *testing.T) {
	observed := []string{
		"27caf4edc279c4b514bfc61fc6638677",
		"bf22cc13167d6d976defa49648a7f0a3",
		"ef6067b14aae540ed1cf74669abe7b37",
		"fe6bd9680b4df143948cb3e2d3d7230f",
		"9267e0f9f2a2884922bb9b2eedfe58bc",
		"207006239e4d4373e05d876ba9a46647",
		"7ba868938a7a16ef60702d947dc57815",
	}

	// Seven resets of the same device, seven different digests for byte-identical
	// records. That alone settles it: a function of the record could not do that.
	seen := map[string]bool{}
	for _, d := range observed {
		if seen[d] {
			t.Fatalf("digest %s appears twice in the recorded observations", d)
		}
		seen[d] = true
	}

	for name, seed := range CandidateSeeds("31650425") {
		derived := hsm.ComputeEntryHash(Sentinel(), seed)
		for i, want := range observed {
			if strings.EqualFold(derived, want) {
				t.Errorf("reset %d's digest %s is reproducible with the %q seed: the anchor would be "+
					"a public constant and pinning it would prove nothing", i, want, name)
			}
		}
	}
}

// TestDerivableAnchorIsReportedAsWorthless: if a firmware ever seeded the chain
// with a guessable value, the anchor would be a universal constant and pinning
// it would prove nothing. Verification must say so rather than reporting a
// confident "anchor matches" over a value every observer can compute.
func TestDerivableAnchorIsReportedAsWorthless(t *testing.T) {
	// The digest a device would report if it seeded from an all-zero block.
	derivable := hsm.ComputeEntryHash(Sentinel(), repeat(0x00, DigestLen))
	if name := DerivableAnchor(derivable, "31650425"); name != "all-zero (16)" {
		t.Fatalf("DerivableAnchor = %q, want the all-zero seed", name)
	}
	// A real observation must not be flagged.
	if name := DerivableAnchor("27caf4edc279c4b514bfc61fc6638677", "31650425"); name != "" {
		t.Fatalf("a real device anchor was reported derivable under %q", name)
	}

	entries := chain(derivable, signEntry(attestedKeyID))
	res := VerifyBundle(&Bundle{
		Version:    BundleVersion,
		Anchor:     derivable,
		LogEntries: entries,
		Device:     DeviceInfo{Serial: "31650425"},
	}, VerifyOptions{
		// Pinned to the very same value, so every other anchor check passes.
		ExpectedAnchor:      derivable,
		SkipFreshness:       true,
		AllowUnattestedKeys: true,
	})
	if res.OK {
		t.Fatal("a bundle whose anchor is a public constant passed verification")
	}
	if !strings.Contains(strings.Join(res.Findings, "; "), "derivable from public data") {
		t.Fatalf("rejection did not name the derivable anchor: %v", res.Findings)
	}
}

// TestForgedHistoryPassesInternalConsistency is the argument that survives any
// firmware change: the chain rule is unkeyed, so anyone can pick an anchor and
// hash a flawless history forward from it — including one that hides a rogue
// signature. Only comparing the anchor against a value obtained outside the
// system catches it.
//
// This is why "let the verifier recompute the anchor" cannot work. A check the
// verifier can perform is a check the forger performs first, on the way to
// choosing an anchor that satisfies it.
func TestForgedHistoryPassesInternalConsistency(t *testing.T) {
	// A forger with no device at all. The anchor is simply invented; nothing
	// about it can be distinguished from a device-chosen one, because a device
	// chooses it the same way.
	// chain() hashes each entry forward from the one before, exactly as a device
	// does — which is the point: nothing about it needs a device.
	forged := chain("00112233445566778899aabbccddeeff",
		signEntry(attestedKeyID), signEntry(attestedKeyID), signEntry(attestedKeyID))

	if seg := VerifyChainFromGenesis(forged, Unlogged{}); !seg.OK {
		t.Fatalf("a wholly invented history failed internal verification, so this test proves nothing: %v", seg.Err())
	}

	// And with a real anchor pinned, the same forgery is rejected — which is the
	// entire security value of the pin.
	b := &Bundle{
		Version:    BundleVersion,
		Anchor:     forged[0].Hash,
		LogEntries: forged,
		Device:     DeviceInfo{Serial: "31650425"},
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor:      "27caf4edc279c4b514bfc61fc6638677",
		SkipFreshness:       true,
		AllowUnattestedKeys: true,
	})
	if res.OK {
		t.Fatal("a bundle built on an invented anchor passed against a pinned one")
	}
	if !strings.Contains(strings.Join(res.Findings, "; "), "does not match the pinned anchor") {
		t.Fatalf("rejection did not name the anchor mismatch: %v", res.Findings)
	}
}

// TestProvisionRecordsTheAnchorInTheAuditLog covers the half of the problem that
// is actually solvable. The anchor cannot be shown to have come from a genuine
// reset, but it can be shown to have existed at commissioning time — which is
// what stops one being invented after the abuse it is meant to hide.
func TestProvisionRecordsTheAnchorInTheAuditLog(t *testing.T) {
	entries := chain(testAnchor)
	dev := newFake(entries)
	auditor := &MemAuditor{}
	svc := NewService(dev, NewMemStore())
	svc.SetAuditor(auditor)

	res, err := svc.Provision(context.Background())
	if err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if !strings.EqualFold(res.Anchor, testAnchor) {
		t.Fatalf("pinned anchor %s, want %s", res.Anchor, testAnchor)
	}

	events := auditor.Events()
	if len(events) != 1 {
		t.Fatalf("provisioning wrote %d audit event(s), want 1", len(events))
	}
	e := events[0]
	if e.Action != audit.ActionHSMProvisionAudit {
		t.Errorf("action %q, want %q", e.Action, audit.ActionHSMProvisionAudit)
	}
	if e.Result != audit.ResultSuccess {
		t.Errorf("result %q, want %q", e.Result, audit.ResultSuccess)
	}
	if e.Target != dev.info.Serial {
		t.Errorf("target %q, want the device serial %q", e.Target, dev.info.Serial)
	}
	// The anchor itself must be in the record. An event that merely says
	// "provisioned" dates nothing.
	if !strings.Contains(strings.ToLower(e.Detail), strings.ToLower(testAnchor)) {
		t.Errorf("audit detail does not carry the anchor: %q", e.Detail)
	}
	if !strings.Contains(e.Detail, SentinelPreimageHex) {
		t.Errorf("audit detail does not name the sentinel preimage: %q", e.Detail)
	}
	if e.Hash == "" {
		t.Error("the event was not sealed into the hash chain")
	}
}

// TestProvisionRefusesWithoutAnAuditLog: an anchor nothing witnessed is one an
// operator could have chosen at any later date, so provisioning stops rather
// than producing a force-audited device whose origin is undatable.
func TestProvisionRefusesWithoutAnAuditLog(t *testing.T) {
	dev := newFake(chain(testAnchor))
	svc := NewService(dev, NewMemStore())

	if _, err := svc.Provision(context.Background()); err == nil {
		t.Fatal("provisioning pinned an anchor with no audit log to record it in")
	} else if !strings.Contains(err.Error(), "no audit log configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestProvisionAbortsWhenTheAnchorCannotBeRecorded is the fail-closed half: a
// store that refuses the event must stop provisioning before the device is
// changed irreversibly, not carry on with an unwitnessed anchor.
func TestProvisionAbortsWhenTheAnchorCannotBeRecorded(t *testing.T) {
	dev := newFake(chain(testAnchor))
	svc := NewService(dev, NewMemStore())
	svc.SetAuditor(&MemAuditor{Fail: errors.New("event log is read-only")})

	_, err := svc.Provision(context.Background())
	if err == nil {
		t.Fatal("provisioning continued after failing to record the anchor")
	}
	if !strings.Contains(err.Error(), "recording the chain anchor") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Nothing irreversible may have happened on the device.
	if dev.consumed != 0 {
		t.Errorf("the device log was acknowledged (up to %d) despite the abort", dev.consumed)
	}
}

// --- helpers --------------------------------------------------------------

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
