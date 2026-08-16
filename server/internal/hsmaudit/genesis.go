package hsmaudit

// Why the chain anchor cannot be made self-verifying.
//
// The anchor is the one value in this subsystem an auditor has to be handed out
// of band, and that is an awkward requirement: everything else in a bundle is
// checkable from the bundle, while the anchor is a bare 16-byte hex string the
// auditor must simply have. A recurring and entirely reasonable idea is to
// remove that requirement by making the anchor *derivable* — publish the
// device-init sentinel record itself, which is famously almost all 0xff bytes,
// let the verifier hash it, and thereby establish that the pinned value really
// did come from a factory reset rather than being invented.
//
// It does not work, and the reason is worth stating precisely because the idea
// keeps coming back.
//
// # The preimage is a public constant
//
// The bytes a sentinel contributes to the chain are SentinelPreimage: 0x0001
// followed by fourteen 0xff bytes. Every field except the entry number is
// saturated, and the entry number is always 1 because a factory reset restarts
// the counter. This was confirmed on hardware across seven factory resets of a
// YubiHSM 2 (serial 31650425, firmware 2.4.0), in two sittings: the sixteen
// hashed bytes were byte-identical every time.
//
// A constant is the same on every YubiHSM 2 ever manufactured. Any hash of it is
// therefore also a universal constant, which identifies no device and no
// history. Pinning it would prove precisely one thing — that the log came from
// some YubiHSM — which the bundle already says on its own.
//
// # The digest is not a function of the preimage
//
// The device does not seed its chain with a public value. Those same seven
// factory resets produced seven *different* digests for the byte-identical
// sentinel:
//
//	27caf4edc279c4b514bfc61fc6638677
//	bf22cc13167d6d976defa49648a7f0a3
//	ef6067b14aae540ed1cf74669abe7b37
//	fe6bd9680b4df143948cb3e2d3d7230f
//	9267e0f9f2a2884922bb9b2eedfe58bc
//	207006239e4d4373e05d876ba9a46647
//	7ba868938a7a16ef60702d947dc57815
//
// So digest = trunc16(SHA-256(SentinelPreimage || seed)) for a seed the device
// chooses at reset and never discloses. No obvious candidate reproduces it —
// not an absent seed, not all-zero, not all-ones, not the preimage itself, not
// the serial number (TestSentinelDigestIsNotDerivable pins that list). A
// verifier holding the sentinel therefore cannot recompute the anchor, which is
// exactly the operation the idea requires.
//
// # And if it could, it would be worthless
//
// This is the part that survives any firmware change, so it matters more than
// the two measurements above.
//
// Let P be any predicate over a candidate anchor that a *verifier* can evaluate
// from public information — the sentinel's bytes, the device serial, the
// firmware version, anything printed in a datasheet. Whatever P is, a forger can
// evaluate it too. They pick a value satisfying P, call it the anchor, and hash a
// perfectly consistent history forward from it: the chain rule is unkeyed, so
// producing a 62-entry log that verifies end to end takes a few lines of code
// (TestForgedHistoryPassesInternalConsistency does exactly that). P rejects
// nothing.
//
// Self-verifiability and evidentiary value are mutually exclusive here. The
// anchor is useful *because* it is unpredictable and was recorded before the
// history it anchors — it is a trust-on-first-use pin, not a proof of a
// property. Making it recomputable would not add a check; it would delete the
// only thing the anchor does.
//
// # What the bundle already does
//
// The half of the idea that is achievable is already implemented, and has been
// since the subsystem was written: a bundle carries the sentinel record in full,
// VerifySegment requires it to have the sentinel's shape (hsm.IsBootSentinel:
// every field 0xff, number 1), and VerifyBundle requires the pinned anchor to
// equal that entry's reported digest. So the preimage *is* published and *is*
// checked. What is missing is not the preimage — it is the seed, and the device
// offers no way to learn it and no signature over its log that would stand in
// for one.
//
// # What actually closes the gap
//
// Two things, neither of which is a property of the sentinel:
//
//   - Time. Provision records the anchor into the hash-chained event log, which
//     internal/anchor periodically timestamps with an RFC 3161 authority. An
//     operator who later fabricates a history has to produce an anchor that a
//     third party already witnessed before the signatures in question — which is
//     not something they can do after the fact. See Service.SetAuditor.
//   - Identity. The device's factory attestation key signs statements that name
//     the device serial and chain to a Yubico root, which binds a commitment to
//     a specific piece of hardware rather than to an unattributed hash.
//
// Both are external witnesses. That is the general shape of the answer: the
// sentinel cannot vouch for itself, so something outside it has to.

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// SentinelPreimageHex is the hex form of SentinelPreimage, pinned as a literal
// so a change to the field layout in hsm.EntryData shows up as a test failure
// here rather than as a silently different constant.
const SentinelPreimageHex = "0001ffffffffffffffffffffffffffff"

// Sentinel returns the device-init entry a YubiHSM 2 factory reset writes: entry
// number 1, every other field saturated. The Hash field is left empty because
// that is precisely the value that cannot be derived — see the file comment.
func Sentinel() hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Number:     1,
		Command:    0xff,
		Length:     0xffff,
		SessionKey: 0xffff,
		TargetKey:  0xffff,
		SecondKey:  0xffff,
		Result:     0xff,
		Tick:       0xffffffff,
	}
}

// SentinelPreimage returns the sixteen bytes a device-init sentinel contributes
// to the device chain digest. It is a constant: identical on every YubiHSM 2 and
// after every factory reset.
func SentinelPreimage() []byte {
	return hsm.EntryData(Sentinel())
}

// CandidateSeeds are the predecessor digests a device could plausibly seed its
// chain with that anyone could guess: nothing at all, a saturated or zeroed
// block, the sentinel's own bytes, the device serial.
//
// None of them is what a YubiHSM 2 actually uses — seven factory resets produced
// seven unrelated digests — and that is the outcome to want. A device that
// seeded from any of these would publish an anchor every observer could compute,
// which is to say an anchor that identifies no history and distinguishes no
// device. See DerivableAnchor.
//
// serial is the device serial as reported by the device, used for the one
// candidate that depends on it; an empty string skips that candidate.
func CandidateSeeds(serial string) map[string][]byte {
	saturated := func(b byte, n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = b
		}
		return out
	}
	preimage := SentinelPreimage()
	sum := sha256.Sum256(preimage)
	out := map[string][]byte{
		"absent":                             nil,
		"all-zero (16)":                      saturated(0x00, 16),
		"all-ones (16)":                      saturated(0xff, 16),
		"all-zero (32)":                      saturated(0x00, 32),
		"all-ones (32)":                      saturated(0xff, 32),
		"the sentinel preimage":              preimage,
		"sha-256 of the preimage":            sum[:],
		"sha-256 of the preimage, truncated": sum[:DigestLen],
	}
	if n := parseSerial(serial); n != 0 {
		be := make([]byte, 8)
		binary.BigEndian.PutUint64(be, n)
		out["device serial (big-endian)"] = be
		out["device serial (32-bit big-endian)"] = be[4:]
	}
	return out
}

// DerivableAnchor reports the name of a publicly guessable seed under which
// digest is the chain digest of a device-init sentinel, or "" when none is.
//
// A non-empty result is a finding, not a reassurance. It would mean the anchor
// is a value any observer can compute from public information, so pinning it
// proves nothing about which device or which reset a log came from — and a
// forger could hash a consistent history forward from the same value. Nothing
// in this codebase can make such an anchor useful, so verification reports it
// rather than quietly treating a matched anchor as evidence.
func DerivableAnchor(digest, serial string) string {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if digest == "" {
		return ""
	}
	seeds := CandidateSeeds(serial)
	names := make([]string, 0, len(seeds))
	for name := range seeds {
		names = append(names, name)
	}
	// Sorted so the reported name is stable across runs rather than whichever
	// map key the runtime happened to visit first.
	sort.Strings(names)
	for _, name := range names {
		if strings.EqualFold(hsm.ComputeEntryHash(Sentinel(), seeds[name]), digest) {
			return name
		}
	}
	return ""
}

// parseSerial reads a decimal device serial, returning 0 for anything it cannot
// parse — the serial only feeds a guessed-seed candidate, so a device that
// reports one in an unexpected form loses a candidate rather than failing.
func parseSerial(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + uint64(r-'0')
	}
	return n
}
