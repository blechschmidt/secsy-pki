package hsmaudit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Reconciliation answers the question the whole subsystem exists for: has this
// HSM produced more signatures than the CA published?
//
// The device log gives the numerator — how many times each key actually signed,
// counted from records the device wrote itself and that no one can forge without
// breaking the chain digest. The signature ledger gives the denominator — how
// many signatures the CA asked for and can account for. A numerator larger than
// the denominator is, by construction, a signature that exists in the world and
// that the CA cannot explain. That is key abuse, and it is detectable even
// against an operator who holds the HSM authentication key, because that
// operator can no more suppress a device log entry than forge one.

// entrySucceeded reports whether a device log entry records a completed
// operation.
//
// The YubiHSM stores the response command byte in the entry's result field.
// A successful response is the request command with the high bit set; a failure
// carries the device's error code instead. Both observed on a real device: a
// SIGN PKCS1 request (cmd 0x47) that succeeded carries result 0xc7, and a
// DELETE OBJECT (cmd 0x58) naming an object that does not exist carries 0x0b
// (OBJECT NOT FOUND). Error codes are all below 0x80, so the test below cannot
// mistake a failure for a success.
//
// The distinction matters because a rejected signing attempt produces no
// signature and so must not be counted against published artifacts — but it is
// still reported, since a burst of failures is itself worth an operator's
// attention.
func entrySucceeded(e hsm.AuditLogEntry) bool {
	return e.Result == e.Command|0x80
}

// KeyReconciliation is the per-key result of matching device signatures against
// ledger rows.
type KeyReconciliation struct {
	// KeyID is the on-device object ID both sides are joined on.
	KeyID uint16 `json:"key_id"`
	// KeyLabel is the human-readable label, taken from the ledger (the device
	// log records only the object ID).
	KeyLabel string `json:"key_label,omitempty"`
	// DeviceSignatures is the number of successful signing operations the
	// device recorded for this key.
	DeviceSignatures int `json:"device_signatures"`
	// DeviceFailures is the number of signing attempts the device rejected.
	// These produced no signature and are excluded from the balance.
	DeviceFailures int `json:"device_failures"`
	// LedgerSignatures is the number of signatures the CA recorded requesting.
	LedgerSignatures int `json:"ledger_signatures"`
	// Surplus is DeviceSignatures - LedgerSignatures. A positive value is key
	// abuse: the HSM signed something the CA never asked for. A negative value
	// means device log entries are missing, which is equally fatal to the proof
	// because the missing entries could have been anything.
	Surplus int `json:"surplus"`
	// Balanced is true only when Surplus is zero.
	Balanced bool `json:"balanced"`
	// Commands counts the device sign entries by command name, so an operator
	// can see whether a surplus was ECDSA, EdDSA, RSA, and so on.
	Commands map[string]int `json:"commands,omitempty"`
}

// ReconcileResult is the overall verdict.
type ReconcileResult struct {
	// OK is true only when every key balances and no unattributed signature was
	// seen. Callers must fail closed on false.
	OK bool `json:"ok"`
	// Keys holds the per-key results, ordered by key ID.
	Keys []KeyReconciliation `json:"keys"`
	// TotalDeviceSignatures and TotalLedgerSignatures are the sums across keys.
	TotalDeviceSignatures int `json:"total_device_signatures"`
	TotalLedgerSignatures int `json:"total_ledger_signatures"`
	// Findings describes every imbalance in operator-readable form.
	Findings []string `json:"findings,omitempty"`
}

// Err renders a failed reconciliation as an error, nil when it passed.
func (r *ReconcileResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm signature reconciliation failed")
	}
	return fmt.Errorf("hsm signature reconciliation failed: %s", strings.Join(r.Findings, "; "))
}

// Reconcile matches the successful signing operations recorded in the device
// log against the CA's signature ledger, per key.
//
// entries must already have passed VerifyChainFromGenesis and ledger must have
// passed VerifyLedger; reconciling unverified inputs is meaningless, because
// either side could then simply have been edited to agree with the other.
func Reconcile(entries []hsm.AuditLogEntry, ledger []LedgerEntry) *ReconcileResult {
	type counters struct {
		device   int
		failures int
		ledger   int
		label    string
		commands map[string]int
	}
	byKey := map[uint16]*counters{}
	get := func(id uint16) *counters {
		c, ok := byKey[id]
		if !ok {
			c = &counters{commands: map[string]int{}}
			byKey[id] = c
		}
		return c
	}

	for _, e := range entries {
		name, isSign := hsm.SignCommands[e.Command]
		if !isSign {
			continue
		}
		c := get(e.TargetKey)
		if !entrySucceeded(e) {
			c.failures++
			continue
		}
		c.device++
		c.commands[name]++
	}
	for _, l := range ledger {
		c := get(l.KeyID)
		c.ledger++
		if c.label == "" {
			c.label = l.KeyLabel
		}
	}

	res := &ReconcileResult{OK: true}
	ids := make([]uint16, 0, len(byKey))
	for id := range byKey {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		c := byKey[id]
		kr := KeyReconciliation{
			KeyID:            id,
			KeyLabel:         c.label,
			DeviceSignatures: c.device,
			DeviceFailures:   c.failures,
			LedgerSignatures: c.ledger,
			Surplus:          c.device - c.ledger,
			Commands:         c.commands,
		}
		kr.Balanced = kr.Surplus == 0
		if !kr.Balanced {
			res.OK = false
			switch {
			case kr.Surplus > 0:
				res.Findings = append(res.Findings, fmt.Sprintf(
					"key 0x%04x%s: KEY ABUSE — the device performed %d signature(s) but the CA accounts for only %d; "+
						"%d signature(s) exist that were never published",
					id, labelSuffix(c.label), kr.DeviceSignatures, kr.LedgerSignatures, kr.Surplus))
			default:
				res.Findings = append(res.Findings, fmt.Sprintf(
					"key 0x%04x%s: the CA recorded %d signature(s) but the device log shows only %d; "+
						"%d device log entr(ies) are missing, so the log cannot bound what this key signed",
					id, labelSuffix(c.label), kr.LedgerSignatures, kr.DeviceSignatures, -kr.Surplus))
			}
		}
		res.TotalDeviceSignatures += kr.DeviceSignatures
		res.TotalLedgerSignatures += kr.LedgerSignatures
		res.Keys = append(res.Keys, kr)
	}
	return res
}

func labelSuffix(label string) string {
	if label == "" {
		return ""
	}
	return " (" + label + ")"
}

// PublishedResult is the verdict on matching ledger rows to published
// artifacts.
type PublishedResult struct {
	// OK is true when every ledger row corresponds to a published artifact.
	OK bool `json:"ok"`
	// Matched is the number of ledger rows accounted for by a published
	// artifact digest.
	Matched int `json:"matched"`
	// Unpublished lists ledger rows with no matching published artifact: the CA
	// signed something it never published. Each entry is "seq/digest".
	Unpublished []string `json:"unpublished,omitempty"`
	// Unmatched lists published artifact digests with no ledger row. These are
	// artifacts signed outside the ledger's view — either by a different key or
	// before the ledger existed.
	Unmatched []string `json:"unmatched,omitempty"`
}

// Err renders a failed published-artifact match as an error, nil when it passed.
func (r *PublishedResult) Err() error {
	if r.OK {
		return nil
	}
	var parts []string
	if n := len(r.Unpublished); n > 0 {
		parts = append(parts, fmt.Sprintf("%d ledger signature(s) have no published artifact: %s",
			n, strings.Join(truncateList(r.Unpublished, 5), ", ")))
	}
	if n := len(r.Unmatched); n > 0 {
		parts = append(parts, fmt.Sprintf("%d published artifact(s) have no ledger entry: %s",
			n, strings.Join(truncateList(r.Unmatched, 5), ", ")))
	}
	return fmt.Errorf("published-artifact reconciliation failed: %s", strings.Join(parts, "; "))
}

// MatchPublished checks that every ledger row's digest is the digest of some
// published artifact, and vice versa.
//
// This is the half of the argument the device log cannot supply. Signature
// counts alone would still balance if the CA had signed a rogue certificate and
// dutifully recorded it in its own ledger; requiring each ledger digest to
// appear among the artifacts the CA actually published is what turns "the HSM
// signed N times" into "the HSM signed exactly these N things".
//
// publishedDigests is the multiset of hex SHA-256 digests over the signed bytes
// of every artifact the auditor obtained independently — from the published
// inventory, a CRL distribution point, or a Certificate Transparency log.
func MatchPublished(ledger []LedgerEntry, publishedDigests []string) *PublishedResult {
	remaining := map[string]int{}
	for _, d := range publishedDigests {
		remaining[strings.ToLower(strings.TrimSpace(d))]++
	}

	res := &PublishedResult{OK: true}
	for _, l := range ledger {
		d := strings.ToLower(l.Digest)
		if remaining[d] > 0 {
			remaining[d]--
			res.Matched++
			continue
		}
		res.OK = false
		res.Unpublished = append(res.Unpublished, fmt.Sprintf("%d/%s", l.Seq, d))
	}
	for d, n := range remaining {
		for i := 0; i < n; i++ {
			res.OK = false
			res.Unmatched = append(res.Unmatched, d)
		}
	}
	sort.Strings(res.Unmatched)
	return res
}

func truncateList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string(nil), items[:max]...)
	return append(out, fmt.Sprintf("and %d more", len(items)-max))
}
