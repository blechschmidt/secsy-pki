package hsmaudit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// The signature ledger is the CA's own record of every signature it asked the
// HSM to produce. It exists because the device log alone cannot answer the
// question this package is about.
//
// The device log says "key 0x1939 performed 412 ECDSA signatures". It does not
// say what was signed — the entries carry no digest of the input. So the device
// log by itself can never distinguish 412 legitimate certificate signatures
// from 411 legitimate ones plus one forged certificate for a domain the CA
// never issued.
//
// The ledger closes that gap from the other side. Written at the key-provider
// chokepoint every signature passes through, it records the digest of each
// to-be-signed input. Reconciliation then checks two directions:
//
//	device sign count == ledger row count      (the HSM signed nothing extra)
//	every ledger digest == a published artifact (the CA published everything it signed)
//
// Together those give the property the audit log is supposed to prove. The
// ledger is hash-chained for the same reason the event log is: an operator who
// signs a rogue certificate and then deletes its ledger row would otherwise
// turn a detectable surplus into a clean reconciliation.

// LedgerEntry is one recorded HSM signing operation.
type LedgerEntry struct {
	// Seq is a gap-free monotonic counter assigned by the store. It is part of
	// the hashed content, so deleting a row breaks the chain rather than just
	// shortening it.
	Seq int64 `json:"seq"`
	// Timestamp is when the signature was requested.
	Timestamp time.Time `json:"timestamp"`
	// KeyLabel is the PKCS#11 CKA_LABEL of the signing key.
	KeyLabel string `json:"key_label"`
	// KeyID is the on-device object ID of the signing key, matching the
	// target_key field of the device log entry. Reconciliation joins on it.
	KeyID uint16 `json:"key_id"`
	// Digest is the hex-encoded digest handed to the signer: the hash of the
	// TBSCertificate for a certificate, of the TBSCertList for a CRL, and so
	// on. This is what binds a ledger row to a published artifact — an auditor
	// recomputes it from the published bytes, hashing with Algorithm, and
	// checks that the result appears here.
	Digest string `json:"digest"`
	// Algorithm is the digest algorithm the signer was called with, e.g.
	// "SHA-256". It tells an auditor which hash to recompute over a published
	// artifact; without it a digest is not reproducible.
	Algorithm string `json:"algorithm"`
	// Purpose classifies the artifact being signed (see the Purpose* constants).
	// It is descriptive only; reconciliation never trusts it.
	Purpose string `json:"purpose"`
	// PrevHash and Hash chain the ledger.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Purposes recorded on ledger entries. These describe which subsystem asked for
// the signature so an auditor investigating a surplus knows where to look.
const (
	PurposeCertificate = "certificate"
	PurposeCRL         = "crl"
	PurposeOCSP        = "ocsp"
	PurposeTimestamp   = "timestamp"
	PurposeSSH         = "ssh"
	PurposeArtifact    = "artifact"
	PurposeSVID        = "svid"
	PurposeAttestation = "attestation"
	PurposeOther       = "other"
)

// LedgerGenesisHash is the PrevHash of the first ledger entry.
const LedgerGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// canonicalBytes renders the entry as a deterministic, length-prefixed byte
// string for hashing. Length prefixes keep field boundaries unambiguous, so no
// combination of field values can be rearranged into a different entry with the
// same encoding.
func (e *LedgerEntry) canonicalBytes() []byte {
	var buf []byte
	appendUint64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		buf = append(buf, b[:]...)
	}
	appendString := func(s string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(s)))
		buf = append(buf, b[:]...)
		buf = append(buf, s...)
	}
	appendUint64(uint64(e.Seq))
	appendUint64(uint64(e.Timestamp.UTC().UnixNano()))
	appendString(e.KeyLabel)
	appendUint64(uint64(e.KeyID))
	appendString(strings.ToLower(e.Digest))
	appendString(e.Algorithm)
	appendString(e.Purpose)
	appendString(strings.ToLower(e.PrevHash))
	return buf
}

// ComputeHash returns the entry's chain hash.
func (e *LedgerEntry) ComputeHash() string {
	sum := sha256.Sum256(e.canonicalBytes())
	return hex.EncodeToString(sum[:])
}

// Seal assigns the sequence number and previous hash, then computes the entry's
// own hash. The store calls it inside the transaction that appends the row.
func (e *LedgerEntry) Seal(seq int64, prevHash string) {
	e.Seq = seq
	e.PrevHash = strings.ToLower(prevHash)
	e.Digest = strings.ToLower(e.Digest)
	e.Timestamp = e.Timestamp.UTC().Truncate(time.Microsecond)
	e.Hash = e.ComputeHash()
}

// LedgerVerifyResult is the verdict on a ledger chain walk.
type LedgerVerifyResult struct {
	Valid bool `json:"valid"`
	// Count is how many entries verified before any break.
	Count int `json:"count"`
	// BrokenAtSeq is the sequence number of the first bad entry, 0 when valid.
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// VerifyLedger walks the ledger chain in ascending sequence order and reports
// the first break. It enforces the same three properties the event log does:
// the chain starts at the genesis hash, sequence numbers are contiguous (so a
// deleted row is visible as a gap rather than a shorter list), and every hash
// re-derives from its own fields plus its predecessor.
func VerifyLedger(entries []LedgerEntry) LedgerVerifyResult {
	if len(entries) == 0 {
		return LedgerVerifyResult{Valid: true}
	}
	if entries[0].Seq != 1 {
		return LedgerVerifyResult{
			BrokenAtSeq: entries[0].Seq,
			Reason:      fmt.Sprintf("ledger starts at seq %d, expected 1: earlier signatures were removed", entries[0].Seq),
		}
	}
	if !strings.EqualFold(entries[0].PrevHash, LedgerGenesisHash) {
		return LedgerVerifyResult{
			BrokenAtSeq: entries[0].Seq,
			Reason:      "first ledger entry does not chain from the genesis hash",
		}
	}

	prevHash := LedgerGenesisHash
	prevSeq := int64(0)
	for i := range entries {
		e := entries[i]
		if prevSeq != 0 && e.Seq != prevSeq+1 {
			return LedgerVerifyResult{
				Count:       i,
				BrokenAtSeq: e.Seq,
				Reason: fmt.Sprintf("sequence jumps from %d to %d: %d ledger entr(ies) were deleted",
					prevSeq, e.Seq, e.Seq-prevSeq-1),
			}
		}
		if !strings.EqualFold(e.PrevHash, prevHash) {
			return LedgerVerifyResult{
				Count:       i,
				BrokenAtSeq: e.Seq,
				Reason:      "entry does not chain from the previous entry's hash",
			}
		}
		if want := e.ComputeHash(); !strings.EqualFold(want, e.Hash) {
			return LedgerVerifyResult{
				Count:       i,
				BrokenAtSeq: e.Seq,
				Reason:      "entry hash does not match its contents: the row was altered",
			}
		}
		prevHash = e.Hash
		prevSeq = e.Seq
	}
	return LedgerVerifyResult{Valid: true, Count: len(entries)}
}
