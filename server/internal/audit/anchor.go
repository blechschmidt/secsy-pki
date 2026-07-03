package audit

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Anchor is one persisted anchoring of the hash chain's head: at CreatedAt the
// log's newest entry was (Seq, HeadHash), and Token is a DER-encoded RFC 3161
// TimeStampToken whose message imprint covers AnchorMessage(Seq, HeadHash).
//
// The hash chain alone proves internal consistency, but a party who can rewrite
// the whole store can re-seal every entry (or simply drop the newest ones) and
// present a shorter, internally consistent log. An anchor defeats that: the
// timestamp token is signed by a TSA key the store writer does not control, so
// after each anchor point the existence and exact head hash of the log at that
// moment is independently attested. Truncating or rewriting history behind an
// anchor makes verification fail (see CheckAnchorAgainstChain).
type Anchor struct {
	ID       string `json:"id"`
	Seq      int64  `json:"seq"`
	HeadHash string `json:"head_hash"`
	// Token is the DER TimeStampToken (a CMS SignedData). It is emitted as
	// base64 in JSON so auditors can archive or re-verify it externally
	// (e.g. openssl ts -verify against the TSA certificate).
	Token []byte `json:"token,omitempty"`
	// TSASource records where the token came from: empty for the deployment's
	// internal TSA, or the external TSA URL.
	TSASource string    `json:"tsa_source,omitempty"`
	GenTime   time.Time `json:"gen_time"`
	CreatedAt time.Time `json:"created_at"`
}

// anchorMessagePrefix domain-separates anchor imprints from any other data this
// PKI ever timestamps, and versions the canonical layout.
const anchorMessagePrefix = "secsy-pki-audit-anchor-v1"

// AnchorMessage returns the canonical bytes an anchor's timestamp token covers.
// The layout is fixed and versioned so a token minted today remains verifiable
// against a log examined years later. The hash is lowercased: chain hashes are
// hex and must compare case-insensitively.
func AnchorMessage(seq int64, headHash string) []byte {
	return []byte(fmt.Sprintf("%s\nseq=%d\nhead=%s\n", anchorMessagePrefix, seq, strings.ToLower(headHash)))
}

// AnchorDigest is the SHA-256 message imprint submitted to the TSA for an
// anchor over (seq, headHash).
func AnchorDigest(seq int64, headHash string) []byte {
	sum := sha256.Sum256(AnchorMessage(seq, headHash))
	return sum[:]
}

// CheckAnchorAgainstChain confirms the log still contains the exact history the
// anchor attested: the anchored sequence number must be present and its chain
// hash must equal the anchored head hash. events must be the full log ordered
// by ascending Seq (as ListAllEventsAsc returns it) and should already have
// passed VerifyFullChain — this check adds the external-anchor guarantee the
// chain alone cannot provide (see the note on VerifyFullChain).
//
// It does NOT validate the timestamp token's signature; that requires CMS/X.509
// machinery outside this package (see internal/anchor.VerifyAnchors).
func CheckAnchorAgainstChain(events []Event, a Anchor) error {
	if a.Seq <= 0 {
		return fmt.Errorf("anchor carries invalid sequence number %d", a.Seq)
	}
	if len(events) == 0 {
		return fmt.Errorf("log is empty but an anchor attests a head at seq %d: the log was truncated or replaced", a.Seq)
	}
	if tail := events[len(events)-1].Seq; tail < a.Seq {
		return fmt.Errorf("log was truncated: anchored head seq %d is beyond the current tail seq %d", a.Seq, tail)
	}
	i := sort.Search(len(events), func(i int) bool { return events[i].Seq >= a.Seq })
	if i >= len(events) || events[i].Seq != a.Seq {
		return fmt.Errorf("anchored seq %d is missing from the log", a.Seq)
	}
	if !strings.EqualFold(events[i].Hash, a.HeadHash) {
		return fmt.Errorf("chain hash at seq %d does not match the anchored head hash (history was rewritten after anchoring)", a.Seq)
	}
	return nil
}
