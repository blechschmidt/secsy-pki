package hsmaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// The export bundle is the artifact a remote auditor receives. It has to stand
// on its own: the auditor has no access to the HSM, no access to the CA's
// database, and no reason to trust either. Everything in it is therefore either
// re-derivable (the device chain digests, the ledger chain hashes) or pinned
// from an earlier, independently retained bundle (the genesis anchor).
//
// What the auditor learns from a single bundle:
//
//	the device performed exactly N signatures with key K since the factory reset,
//	and the CA accounts for all N of them, with a digest for each.
//
// What the auditor learns by comparing two bundles taken at different times:
//
//	between export A and export B the device performed exactly the signatures
//	listed in B-minus-A, and no others.
//
// The second is the property the task is about, and it is why the bundle
// carries the whole history rather than a window: a suffix cannot prove that
// nothing happened before it started.

// BundleVersion is the schema version of an export bundle. A verifier refuses
// versions it does not know rather than silently skipping checks it cannot
// perform.
const BundleVersion = 1

// Bundle is a self-contained, remotely verifiable export of the HSM audit
// state.
type Bundle struct {
	Version int `json:"version"`
	// ExportedAt is when the bundle was produced. It is metadata only — no
	// verification step trusts it, because the exporting side controls it.
	ExportedAt time.Time `json:"exported_at"`

	// Device identifies the HSM and reports its audit configuration. Options is
	// what backs the completeness claim: without force-audit fixed the device
	// would overwrite log entries rather than refuse to operate, and the "a
	// signature that is not in the log cannot exist" argument collapses.
	Device  DeviceInfo `json:"device"`
	Options *Options   `json:"options"`

	// Anchor is the pinned device chain digest of the device-init sentinel. The
	// auditor must compare it against the value they recorded when the device
	// was commissioned; a bundle whose anchor differs describes a different
	// history, however internally consistent it looks.
	Anchor string `json:"anchor"`

	// LogEntries is the complete device log since the factory reset, in
	// ascending entry-number order.
	LogEntries []hsm.AuditLogEntry `json:"log_entries"`
	// Unlogged is the device's report of operations it could not record. Any
	// non-zero value means the log has holes.
	Unlogged Unlogged `json:"unlogged"`

	// Ledger is the CA's hash-chained record of every signature it requested,
	// carrying the digest of each signed input.
	Ledger []LedgerEntry `json:"ledger"`

	// Freshness holds the RFC 3161 attestations that pin this history to real
	// time. Without them a bundle proves the device signed only what was
	// published *as of some unknown moment*, and an operator could answer an
	// audit with a pristine snapshot taken before the abuse. See VerifyFreshness.
	Freshness []FreshnessProof `json:"freshness,omitempty"`
}

// Fingerprint returns the SHA-256 of the bundle's canonical JSON encoding.
//
// It gives the auditor a short value to retain, to timestamp via the RFC 3161
// TSA, or to publish, so that a later bundle claiming to extend this one can be
// checked against the exact bytes that were seen rather than a re-serialization
// the exporting side might have adjusted.
func (b *Bundle) Fingerprint() (string, error) {
	// json.Marshal orders struct fields by declaration and map keys by sort
	// order, so the encoding is deterministic for a given value.
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("canonicalizing bundle: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// BundleResult is the verdict on a bundle.
type BundleResult struct {
	// OK is true only when every check passed. A verifier must treat false as
	// "this HSM may have signed things that were never published".
	OK bool `json:"ok"`

	// Device, Segment, LedgerChain, Reconciliation, and Published are the
	// individual verdicts, retained so an operator sees which specific property
	// failed rather than a single opaque boolean.
	DeviceOptionsErr string             `json:"device_options_error,omitempty"`
	AnchorErr        string             `json:"anchor_error,omitempty"`
	Chain            *SegmentResult     `json:"chain"`
	LedgerChain      LedgerVerifyResult `json:"ledger_chain"`
	Reconciliation   *ReconcileResult   `json:"reconciliation"`
	Published        *PublishedResult   `json:"published,omitempty"`
	Freshness        *FreshnessResult   `json:"freshness,omitempty"`

	// Summary is a one-line operator-readable conclusion.
	Summary string `json:"summary"`
	// Findings lists every problem found, in the order the checks ran.
	Findings []string `json:"findings,omitempty"`
}

// Err renders a failed verification as an error, nil when it passed.
func (r *BundleResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm audit bundle verification failed")
	}
	return fmt.Errorf("hsm audit bundle verification failed: %s", strings.Join(r.Findings, "; "))
}

// VerifyOptions parameterizes bundle verification.
type VerifyOptions struct {
	// ExpectedAnchor is the genesis anchor the auditor recorded out of band when
	// the device was commissioned. When empty the anchor is not checked and the
	// result says so — the bundle then proves only internal consistency, which
	// is strictly weaker. Auditors doing this for real must supply it.
	ExpectedAnchor string
	// ExpectedSerial is the device serial the auditor expects, checked for the
	// same reason.
	ExpectedSerial string
	// PublishedDigests is the multiset of SHA-256 digests over the signed bytes
	// of every artifact the auditor obtained independently of the CA. When nil
	// the published-artifact match is skipped and the bundle proves only that
	// the device signed exactly what the CA's ledger claims — not that the
	// ledger corresponds to anything real.
	PublishedDigests []string
	// Freshness parameterizes the RFC 3161 staleness check. Its zero value
	// applies DefaultMaxAge with no TSA trust anchors.
	Freshness FreshnessOptions
	// SkipFreshness suppresses the staleness check entirely. It exists for the
	// deployment that has not configured a TSA yet and wants the rest of the
	// verdict; it must not be used in a real audit, because a bundle whose age
	// is unknown cannot bound what the HSM has signed lately.
	SkipFreshness bool
}

// VerifyBundle checks a bundle end to end and reports what it does and does not
// prove.
//
// The checks run in dependency order, and all of them run even after one fails,
// so an operator sees the whole picture rather than the first symptom:
//
//  1. The device is configured so that no signature can escape the log.
//  2. The bundle's anchor is the one the auditor pinned.
//  3. The device log chain re-derives from the sentinel, gap-free.
//  4. The CA's signature ledger chain re-derives.
//  5. Device signature counts equal ledger counts, per key.
//  6. Every ledger digest corresponds to an independently obtained artifact.
//  7. A trusted timestamp authority has attested to this history recently
//     enough that it is not simply an outdated snapshot.
//
// Steps 1-5 need nothing but the bundle. Step 6 needs the auditor to have
// collected the published artifacts themselves, which is the only part of the
// argument that cannot be delegated to the party being audited. Step 7 needs
// the CA to have been obtaining timestamps all along — which is why it is a
// background job, not something an export can retrofit.
func VerifyBundle(b *Bundle, opts VerifyOptions) *BundleResult {
	res := &BundleResult{OK: true}
	fail := func(format string, args ...any) {
		res.OK = false
		res.Findings = append(res.Findings, fmt.Sprintf(format, args...))
	}

	if b == nil {
		res.OK = false
		res.Summary = "no bundle supplied"
		res.Findings = []string{"no bundle supplied"}
		return res
	}
	if b.Version != BundleVersion {
		fail("unsupported bundle version %d (this verifier understands %d); refusing to report a verdict it cannot compute",
			b.Version, BundleVersion)
		res.Summary = "unsupported bundle version"
		return res
	}

	// 1. Device configuration.
	if err := b.Options.Verify(); err != nil {
		res.DeviceOptionsErr = err.Error()
		fail("%v", err)
	}

	// 2. Identity and anchor pinning.
	if opts.ExpectedSerial != "" && !strings.EqualFold(strings.TrimSpace(opts.ExpectedSerial), strings.TrimSpace(b.Device.Serial)) {
		fail("bundle is from device %q, expected %q: this is a different HSM",
			b.Device.Serial, opts.ExpectedSerial)
	}
	switch {
	case opts.ExpectedAnchor == "":
		res.AnchorErr = "no expected anchor supplied: the chain was checked for internal consistency only, " +
			"which cannot distinguish a genuine history from a forged one built on an invented anchor"
	case !strings.EqualFold(strings.TrimSpace(opts.ExpectedAnchor), strings.TrimSpace(b.Anchor)):
		res.AnchorErr = fmt.Sprintf("bundle anchor %s does not match the pinned anchor %s",
			strings.ToLower(b.Anchor), strings.ToLower(opts.ExpectedAnchor))
		fail("%s: the bundle describes a different device history (the device was reset, or the log was fabricated)", res.AnchorErr)
	}

	// The pinned anchor must also actually be the digest of the sentinel the
	// bundle carries, otherwise a matching anchor field would be decoration.
	if len(b.LogEntries) > 0 && b.Anchor != "" && !strings.EqualFold(b.Anchor, b.LogEntries[0].Hash) {
		fail("bundle anchor %s is not the digest of the first log entry (%s): the anchor does not bind this chain",
			strings.ToLower(b.Anchor), strings.ToLower(b.LogEntries[0].Hash))
	}

	// 3. Device log chain.
	res.Chain = VerifyChainFromGenesis(b.LogEntries, b.Unlogged)
	if err := res.Chain.Err(); err != nil {
		fail("%v", err)
	}

	// 4. Ledger chain.
	res.LedgerChain = VerifyLedger(b.Ledger)
	if !res.LedgerChain.Valid {
		fail("signature ledger chain broken at seq %d: %s", res.LedgerChain.BrokenAtSeq, res.LedgerChain.Reason)
	}

	// 5. Device-vs-ledger reconciliation.
	res.Reconciliation = Reconcile(b.LogEntries, b.Ledger)
	if err := res.Reconciliation.Err(); err != nil {
		fail("%v", err)
	}

	// 6. Ledger-vs-published match.
	if opts.PublishedDigests != nil {
		res.Published = MatchPublished(b.Ledger, opts.PublishedDigests)
		if err := res.Published.Err(); err != nil {
			fail("%v", err)
		}
	}

	// 7. Freshness. This runs last because it is the only check whose subject is
	// the bundle as a whole rather than its contents: everything above says what
	// the history contains, and this says whether that history is current.
	if !opts.SkipFreshness {
		res.Freshness = VerifyFreshness(b, opts.Freshness)
		if err := res.Freshness.Err(); err != nil {
			fail("%v", err)
		}
	}

	res.Summary = summarize(res, b, opts)
	return res
}

func summarize(res *BundleResult, b *Bundle, opts VerifyOptions) string {
	total := 0
	if res.Reconciliation != nil {
		total = res.Reconciliation.TotalDeviceSignatures
	}
	if !res.OK {
		return fmt.Sprintf("VERIFICATION FAILED: cannot conclude that device %s signed only what was published (%d finding(s))",
			b.Device.Serial, len(res.Findings))
	}
	scope := "the CA's signature ledger"
	if opts.PublishedDigests != nil {
		scope = "the published artifacts"
	}
	// The "as of" clause is the honest bound. Without a trusted timestamp the
	// verdict holds only as of an unknown moment, and saying so plainly is the
	// difference between a real audit result and a reassuring one.
	asOf := "as of an unverified point in time (no freshness proof was checked)"
	if f := res.Freshness; f != nil && f.OK {
		asOf = fmt.Sprintf("current as of %s (%s ago, attested by a timestamp authority)",
			f.NewestGenTime.Format(time.RFC3339), roundDuration(f.Age))
	}
	return fmt.Sprintf("OK: device %s performed %d signature(s) since the factory reset, all accounted for by %s; "+
		"no key abuse detected, %s",
		b.Device.Serial, total, scope, asOf)
}

// ContinuationResult is the verdict on whether one bundle genuinely extends
// another.
type ContinuationResult struct {
	// OK is true when next is a faithful extension of prev.
	OK bool `json:"ok"`
	// NewSignatures is how many signatures the device performed in the interval
	// between the two exports.
	NewSignatures int `json:"new_signatures"`
	// NewEntries is how many device log entries were added.
	NewEntries int `json:"new_entries"`
	// Interval states the window the two exports bracket in trusted-clock terms,
	// or why it cannot be stated. See describeInterval.
	Interval string `json:"interval,omitempty"`
	// Findings lists every problem found.
	Findings []string `json:"findings,omitempty"`
}

// Err renders a failed continuation check as an error, nil when it passed.
func (r *ContinuationResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm audit bundle is not a continuation of the previous export")
	}
	return fmt.Errorf("hsm audit bundle is not a continuation of the previous export: %s", strings.Join(r.Findings, "; "))
}

// VerifyContinuation checks that next extends prev without rewriting history.
//
// This is what answers "has any key abuse taken place *since* the last export".
// A single bundle proves the device signed only what the CA published up to the
// moment it was taken. Chaining bundles extends that guarantee forward: because
// prev's entries must reappear in next byte-for-byte, and next's chain digests
// fold in their predecessors, the CA cannot quietly drop or rewrite an entry
// that a previously exported bundle already committed to. An auditor who
// retained prev (or merely its fingerprint plus tail) can therefore bound
// exactly what happened in the interval.
func VerifyContinuation(prev, next *Bundle) *ContinuationResult {
	res := &ContinuationResult{OK: true}
	fail := func(format string, args ...any) {
		res.OK = false
		res.Findings = append(res.Findings, fmt.Sprintf(format, args...))
	}
	if prev == nil || next == nil {
		fail("both a previous and a current bundle are required")
		return res
	}

	if !strings.EqualFold(prev.Device.Serial, next.Device.Serial) {
		fail("device serial changed from %q to %q: these are different HSMs", prev.Device.Serial, next.Device.Serial)
	}
	if !strings.EqualFold(prev.Anchor, next.Anchor) {
		fail("genesis anchor changed from %s to %s: the device was factory reset between exports, "+
			"so the earlier history cannot be continued (a reset is itself a way to erase evidence)",
			strings.ToLower(prev.Anchor), strings.ToLower(next.Anchor))
		return res
	}

	// The earlier log must be a prefix of the later one, entry for entry. A
	// changed field in an already-exported entry is a rewrite of committed
	// history.
	if len(next.LogEntries) < len(prev.LogEntries) {
		fail("current export has %d device log entries, fewer than the %d already exported: entries were deleted",
			len(next.LogEntries), len(prev.LogEntries))
	}
	n := min(len(prev.LogEntries), len(next.LogEntries))
	for i := 0; i < n; i++ {
		if prev.LogEntries[i] != next.LogEntries[i] {
			fail("device log entry %d differs from the previously exported copy: history was rewritten",
				prev.LogEntries[i].Number)
			break
		}
	}
	res.NewEntries = len(next.LogEntries) - n

	// Same for the ledger.
	if len(next.Ledger) < len(prev.Ledger) {
		fail("current export has %d ledger entries, fewer than the %d already exported: rows were deleted",
			len(next.Ledger), len(prev.Ledger))
	}
	m := min(len(prev.Ledger), len(next.Ledger))
	for i := 0; i < m; i++ {
		if prev.Ledger[i].Hash != next.Ledger[i].Hash {
			fail("ledger entry seq %d differs from the previously exported copy: history was rewritten",
				prev.Ledger[i].Seq)
			break
		}
	}

	// And for the freshness proofs. Dropping a previously exported attestation
	// would let the CA disown a moment it had already committed to — the one
	// move that could make a rewritten interval look like it was never attested.
	if len(next.Freshness) < len(prev.Freshness) {
		fail("current export has %d freshness proof(s), fewer than the %d already exported: attestations were deleted",
			len(next.Freshness), len(prev.Freshness))
	}
	f := min(len(prev.Freshness), len(next.Freshness))
	for i := 0; i < f; i++ {
		if prev.Freshness[i].HeadDigest != next.Freshness[i].HeadDigest ||
			!prev.Freshness[i].GenTime.Equal(next.Freshness[i].GenTime) {
			fail("freshness proof %d differs from the previously exported copy: an attestation was replaced",
				prev.Freshness[i].Seq)
			break
		}
	}

	res.NewSignatures = countSignatures(next.LogEntries) - countSignatures(prev.LogEntries)
	res.Interval = describeInterval(prev, next)
	return res
}

// describeInterval states, in trusted-clock terms, the window the two bundles
// bracket.
//
// This is what a chained pair of exports buys over a single one: the newest
// attestation in prev and the newest in next are both signed by a TSA, so the
// signatures that appeared between the exports are pinned between two instants
// neither the CA nor an auditor had to be trusted to report. Without
// attestations on both sides the interval is bounded only by the CA's own
// claims about when it produced each file.
func describeInterval(prev, next *Bundle) string {
	from, okFrom := newestGenTime(prev)
	to, okTo := newestGenTime(next)
	if !okFrom || !okTo {
		return "the interval between these exports is not bounded by trusted time: " +
			"one of them carries no freshness proof, so only the CA's own account places them in time"
	}
	return fmt.Sprintf("attested interval %s .. %s (%s)",
		from.Format(time.RFC3339), to.Format(time.RFC3339), roundDuration(to.Sub(from)))
}

// newestGenTime returns the latest TSA-asserted time in a bundle.
func newestGenTime(b *Bundle) (time.Time, bool) {
	var newest time.Time
	for _, p := range b.Freshness {
		if p.GenTime.After(newest) {
			newest = p.GenTime
		}
	}
	return newest.UTC(), !newest.IsZero()
}

// countSignatures counts successful signing operations in a device log.
func countSignatures(entries []hsm.AuditLogEntry) int {
	n := 0
	for _, e := range entries {
		if _, isSign := hsm.SignCommands[e.Command]; isSign && signSucceeded(e) {
			n++
		}
	}
	return n
}

// LedgerDigests returns the digests recorded in a ledger, sorted. It is a
// convenience for auditors assembling the published-artifact comparison.
func LedgerDigests(ledger []LedgerEntry) []string {
	out := make([]string, 0, len(ledger))
	for _, l := range ledger {
		out = append(out, strings.ToLower(l.Digest))
	}
	sort.Strings(out)
	return out
}
