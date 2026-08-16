// Package hsmaudit turns the YubiHSM's on-device audit log into a remotely
// verifiable proof that the HSM has not been used to produce any signature
// beyond the ones the CA published.
//
// The guarantee is assembled from four independent facts, each of which must
// hold or verification fails closed:
//
//  1. Completeness at the source. The device is provisioned with force-audit
//     and per-command audit level 0x02 ("forced") on every signing command, so
//     the HSM physically refuses to sign once the log is full. A signature that
//     does not appear in the log therefore cannot exist. See Options.
//
//  2. Completeness of the collected copy. The device log is a 62-entry ring
//     buffer that the collector drains continuously. Each drained segment must
//     start exactly where the previous one stopped — same successor entry
//     number, and a device chain digest that hashes forward from the previously
//     stored digest. A dropped, reordered, or silently re-fetched segment
//     breaks one of the two. See VerifySegment.
//
//  3. A trustworthy origin for the chain. The very first collected entry must
//     be the device-init sentinel a factory reset writes, so the history starts
//     on a device with no prior use. The sentinel's own digest is the chain
//     anchor; it is recorded when the device is provisioned and pinned on every
//     later verification, closing the "export starts at an arbitrary point"
//     hole. See VerifyChainFromGenesis.
//
//     The anchor has to be pinned rather than recomputed, and no amount of
//     publishing the sentinel changes that: the sixteen bytes a sentinel
//     contributes to the chain are a public constant (0x0001 then fourteen
//     0xff), while the digest the device reports for them differs after every
//     factory reset. genesis.go carries the measurements and the argument for
//     why a self-verifying anchor is not merely unavailable but undesirable.
//     So an unpinned chain proves only internal consistency: an attacker could
//     invent a sentinel, pick any anchor digest, and compute a perfectly
//     consistent forged history from it. Service.Provision records the anchor
//     into the hash-chained event log — which internal/anchor timestamps with
//     an RFC 3161 authority — so it at least cannot be introduced after the
//     fact; recording it out of band is what gives an auditor a copy the CA
//     cannot revise.
//
//  4. Reconciliation against what was published. Every SIGN entry in the log is
//     matched against the signature ledger the CA writes at the key-provider
//     chokepoint, and every ledger row is matched against a published artifact.
//     A surplus of device signatures over published ones is key abuse. See
//     Reconcile.
//
// The device digest is the HSM's own commitment: each entry's 16-byte digest is
// SHA-256(entry_fields_BE || previous_digest) truncated to 16 bytes, so the
// newest digest transitively commits to every entry since the reset. Nothing in
// this package trusts the database — a verifier re-derives every digest from the
// entry fields alone.
package hsmaudit

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// DigestLen is the length in bytes of a device log entry's chain digest. The
// YubiHSM truncates the SHA-256 to 16 bytes.
const DigestLen = 16

// MaxLogEntries is the depth of the YubiHSM 2 on-device log ring buffer. Once
// this many entries accumulate unconsumed the device (in force-audit mode)
// refuses every auditable command, which is what makes the log complete rather
// than merely informative.
const MaxLogEntries = 62

// Tail is the position a previous collection stopped at: the entry number and
// device chain digest of the last entry durably stored. A new segment must
// continue from exactly this point.
type Tail struct {
	Number uint16 `json:"number"`
	Digest string `json:"digest"` // lowercase hex, DigestLen bytes
}

// nextNumber returns the entry number that must follow n.
//
// The device counter is a uint16 that wraps. Entry number 0 is never emitted
// (the log index is 1-based and "set log index 0" is the reset-to-beginning
// command), so the successor of 0xffff is 1, not 0. Reaching the wrap requires
// 65535 audited operations between two collections, which the collector's
// drain cadence makes unreachable in practice; it is handled so that a
// long-lived device does not trip a false alarm.
func nextNumber(n uint16) uint16 {
	if n == 0xffff {
		return 1
	}
	return n + 1
}

// EntryDigest recomputes the device chain digest for one entry given the
// previous entry's digest. It is the verifier's independent re-derivation of
// hsm.ComputeEntryHash and returns lowercase hex.
func EntryDigest(e hsm.AuditLogEntry, prevDigest []byte) string {
	return hsm.ComputeEntryHash(e, prevDigest)
}

// Problem is one specific way a log segment failed verification. Problems are
// collected rather than returned as a single error so an operator sees every
// break at once instead of only the first.
type Problem struct {
	// Number is the device entry number the problem was found at, or 0 when the
	// problem is about the segment as a whole.
	Number uint16 `json:"number,omitempty"`
	// Kind is a stable machine-readable classifier; see the Problem* constants.
	Kind string `json:"kind"`
	// Detail is the human-readable explanation.
	Detail string `json:"detail"`
}

// Problem kinds. These are stable strings: alerting rules and the offline
// verifier match on them.
const (
	// ProblemGap means entry numbers skipped — entries exist that were never
	// collected. On a force-audited device those entries may include signatures.
	ProblemGap = "gap"
	// ProblemDigest means an entry's chain digest does not match the digest
	// recomputed from its fields and its predecessor: the record was altered.
	ProblemDigest = "digest_mismatch"
	// ProblemRewind means the segment restarts at or before the stored tail,
	// i.e. entries were replayed or the device was reset behind our back.
	ProblemRewind = "rewind"
	// ProblemGenesis means the chain does not start at a factory-reset
	// device-init sentinel, so operations may predate the audited history.
	ProblemGenesis = "genesis"
	// ProblemUnknownCommand means an entry carries a command byte this build
	// does not know. An unknown command may be a signing operation, so it is
	// treated as a failure rather than ignored.
	ProblemUnknownCommand = "unknown_command"
	// ProblemUnloggedOps means the device reported boots or authentications
	// that happened while the log was full and were therefore never recorded.
	// This is the device telling us its own log is incomplete.
	ProblemUnloggedOps = "unlogged_operations"
)

// SegmentResult is the verdict on one collected segment of device log entries.
type SegmentResult struct {
	// OK is true only when the segment continues the chain with no gap, every
	// digest re-derives, and no unknown command or unlogged-operation counter
	// was seen. Callers must fail closed on false.
	OK bool `json:"ok"`
	// Count is the number of entries in the segment.
	Count int `json:"count"`
	// First and Last are the entry numbers bounding the segment (0 when empty).
	First uint16 `json:"first,omitempty"`
	Last  uint16 `json:"last,omitempty"`
	// Tail is the position a subsequent segment must continue from. It is set
	// even when OK is false so an operator can see where collection stopped.
	Tail Tail `json:"tail"`
	// Problems lists every fault found, in entry order.
	Problems []Problem `json:"problems,omitempty"`
}

// Err renders the result as an error when verification failed, and nil when it
// passed, so callers can fail closed with a single check.
func (r *SegmentResult) Err() error {
	if r.OK {
		return nil
	}
	parts := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		if p.Number != 0 {
			parts = append(parts, fmt.Sprintf("entry %d: %s (%s)", p.Number, p.Detail, p.Kind))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", p.Detail, p.Kind))
	}
	if len(parts) == 0 {
		return fmt.Errorf("hsm audit segment verification failed")
	}
	return fmt.Errorf("hsm audit segment verification failed: %s", strings.Join(parts, "; "))
}

// VerifySegment checks that entries continue the device log from prev.
//
// prev is nil only for the very first segment ever collected from a device; in
// that case the segment must begin at the factory-reset device-init sentinel.
// Otherwise entries[0] must carry the successor entry number of prev.Number and
// a digest that hashes forward from prev.Digest. Because the digest of every
// entry folds in its predecessor, a single verified link is enough to bind the
// whole new segment to everything collected before it — which is precisely the
// property that lets a remote auditor conclude that no signature was performed
// in the interval between two exports.
//
// unlogged is the device's report of boots and authentications that were not
// recorded because the log was full; any non-zero value means the device log
// itself has holes and the segment fails.
func VerifySegment(entries []hsm.AuditLogEntry, prev *Tail, unlogged Unlogged) *SegmentResult {
	res := &SegmentResult{OK: true, Count: len(entries)}
	if prev != nil {
		res.Tail = *prev
	}

	if n := unlogged.Boots + unlogged.Authentications; n > 0 {
		res.OK = false
		res.Problems = append(res.Problems, Problem{
			Kind: ProblemUnloggedOps,
			Detail: fmt.Sprintf("device reports %d unlogged boot(s) and %d unlogged authentication(s): "+
				"the log overflowed and operations went unrecorded",
				unlogged.Boots, unlogged.Authentications),
		})
	}

	if len(entries) == 0 {
		return res
	}
	res.First = entries[0].Number
	res.Last = entries[len(entries)-1].Number

	// Establish the digest the first entry must chain from, and the entry
	// number it must carry.
	var prevDigest []byte
	var wantNumber uint16
	if prev == nil {
		// The sentinel is the chain anchor. Its digest cannot be re-derived
		// (see the package comment), so it is taken as given here and pinned
		// separately by VerifyChainFromGenesis. What is checked is its shape:
		// only a factory reset produces an all-ones entry at number 1.
		wantNumber = entries[0].Number
		prevDigest = nil
		if !hsm.IsBootSentinel(entries[0]) {
			res.OK = false
			res.Problems = append(res.Problems, Problem{
				Number: entries[0].Number,
				Kind:   ProblemGenesis,
				Detail: "first collected entry is not a factory-reset device-init sentinel; " +
					"the device may have performed operations before auditing began",
			})
		}
	} else {
		d, err := decodeDigest(prev.Digest)
		if err != nil {
			res.OK = false
			res.Problems = append(res.Problems, Problem{
				Kind:   ProblemDigest,
				Detail: fmt.Sprintf("stored tail digest is unusable: %v", err),
			})
			return res
		}
		prevDigest = d
		wantNumber = nextNumber(prev.Number)
	}

	for i, e := range entries {
		if i > 0 {
			wantNumber = nextNumber(entries[i-1].Number)
		}

		// Numbering: any skip means entries exist that we never saw. On a
		// force-audited device those may be signatures, so this is fatal.
		if e.Number != wantNumber {
			res.OK = false
			kind := ProblemGap
			detail := fmt.Sprintf("expected entry number %d, got %d: %d entr(ies) were never collected",
				wantNumber, e.Number, gapSize(wantNumber, e.Number))
			if !isForward(wantNumber, e.Number) {
				kind = ProblemRewind
				detail = fmt.Sprintf("expected entry number %d, got %d: the log went backwards "+
					"(replayed segment, or the device was reset)", wantNumber, e.Number)
			}
			res.Problems = append(res.Problems, Problem{Number: e.Number, Kind: kind, Detail: detail})
			// The chain digest cannot be re-derived across a gap; stop digest
			// checking but keep reporting structural problems for the rest.
			prevDigest = nil
		}

		// Digest: re-derive from the entry fields plus the predecessor digest.
		if prevDigest != nil {
			want := EntryDigest(e, prevDigest)
			if !strings.EqualFold(want, e.Hash) {
				res.OK = false
				res.Problems = append(res.Problems, Problem{
					Number: e.Number,
					Kind:   ProblemDigest,
					Detail: fmt.Sprintf("chain digest %s does not match %s recomputed from the entry fields: record altered",
						strings.ToLower(e.Hash), want),
				})
			}
		}

		if _, known := hsm.AllCommands[e.Command]; !known {
			res.OK = false
			res.Problems = append(res.Problems, Problem{
				Number: e.Number,
				Kind:   ProblemUnknownCommand,
				Detail: fmt.Sprintf("unknown command 0x%02x: cannot rule out that it produced a signature", e.Command),
			})
		}

		d, err := decodeDigest(e.Hash)
		if err != nil {
			res.OK = false
			res.Problems = append(res.Problems, Problem{
				Number: e.Number,
				Kind:   ProblemDigest,
				Detail: fmt.Sprintf("unusable digest: %v", err),
			})
			prevDigest = nil
			continue
		}
		prevDigest = d
	}

	last := entries[len(entries)-1]
	res.Tail = Tail{Number: last.Number, Digest: strings.ToLower(last.Hash)}
	return res
}

// VerifyChainFromGenesis verifies a complete device log — every entry since the
// factory reset — in one pass. It is what the offline verifier runs against an
// exported bundle: the chain must begin at the device-init sentinel and remain
// gap-free to the end, with every digest after the first re-derived from its
// predecessor.
//
// The sentinel's own digest is taken as given, not re-derived. There is no
// genesis value to hash forward from — the device seeds the chain with
// something it never discloses, so entry 1's digest is unverifiable by
// construction and is instead pinned by VerifyBundle against the anchor the
// auditor holds. A chain that verifies here but carries an unpinned anchor is
// self-consistent and worthless; see genesis.go.
//
// A caller holding only a suffix of the log cannot use this; that is the point.
// Any export claiming to prove "the HSM signed nothing else" must carry the
// whole history, because a suffix says nothing about what happened before it.
func VerifyChainFromGenesis(entries []hsm.AuditLogEntry, unlogged Unlogged) *SegmentResult {
	return VerifySegment(entries, nil, unlogged)
}

// isForward reports whether got is at or ahead of want in uint16 counter space,
// tolerating the wrap. Half the counter space is treated as "ahead" and the
// other half as "behind", the standard serial-number comparison.
func isForward(want, got uint16) bool {
	return got-want < 0x8000
}

// gapSize returns how many entry numbers were skipped between want and got.
func gapSize(want, got uint16) uint16 {
	return got - want
}

// decodeDigest parses a device chain digest and enforces its length, so a
// truncated or padded value is rejected rather than silently mis-hashed.
func decodeDigest(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != DigestLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", DigestLen, len(b))
	}
	return b, nil
}
