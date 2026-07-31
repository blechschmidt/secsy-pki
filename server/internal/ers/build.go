package ers

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// EvidenceRecord is a parsed RFC 4998 Evidence Record. It wraps the ASN.1 wire
// structure and offers generation, renewal, inspection, and DER (Marshal)
// output. Values are immutable: renewal returns a new EvidenceRecord.
type EvidenceRecord struct {
	wire evidenceRecord
}

// Parse decodes a DER EvidenceRecord.
func Parse(der []byte) (*EvidenceRecord, error) {
	w, err := parseEvidenceRecord(der)
	if err != nil {
		return nil, err
	}
	return &EvidenceRecord{wire: *w}, nil
}

// GenerateOptions parameterizes Generate.
type GenerateOptions struct {
	// Objects are the protected data objects, forming one RFC 4998 data group.
	Objects []DataObject
	// Hash is the hash algorithm of the initial ArchiveTimeStampChain (default
	// SHA-256). It must be linked into the binary.
	Hash crypto.Hash
}

// Generate builds an EvidenceRecord over a set of protected data objects: it
// hashes each object into a leaf, forms the data-group root, obtains an
// ArchiveTimeStamp over the root from the Timestamper, and assembles the initial
// ArchiveTimeStampChain / ArchiveTimeStampSequence.
func Generate(ctx context.Context, ts Timestamper, opts GenerateOptions) (*EvidenceRecord, error) {
	if len(opts.Objects) == 0 {
		return nil, ErrEmpty
	}
	hash := opts.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}
	if !hash.Available() {
		return nil, &UnsupportedHashError{Hash: hash}
	}

	leaves := make([][]byte, len(opts.Objects))
	for i, o := range opts.Objects {
		leaves[i] = leafHash(hash, o.Bytes)
	}
	root := groupRoot(hash, leaves)

	token, _, err := ts.Timestamp(ctx, hash, root)
	if err != nil {
		return nil, err
	}
	ats, err := newArchiveTimeStamp(hash, groupReducedTree(leaves), token)
	if err != nil {
		return nil, err
	}

	seq := []archiveTimeStampChain{{ats}}
	algs, err := digestAlgorithms(seq)
	if err != nil {
		return nil, err
	}
	return &EvidenceRecord{wire: evidenceRecord{
		Version:                  Version,
		DigestAlgorithms:         algs,
		ArchiveTimeStampSequence: seq,
	}}, nil
}

// RenewTimestamp appends a time-stamp renewal (RFC 4998 §5.2) to the current
// ArchiveTimeStampChain: it hashes the newest timestamp token with the chain's
// existing hash algorithm and obtains a fresh ArchiveTimeStamp over that value,
// re-attesting the record before the current TSA certificate expires. The hash
// algorithm is unchanged (same chain). It returns a new EvidenceRecord.
func (er *EvidenceRecord) RenewTimestamp(ctx context.Context, ts Timestamper) (*EvidenceRecord, error) {
	seq := er.copySequence()
	if len(seq) == 0 {
		return nil, ErrNoTimestamp
	}
	ci := len(seq) - 1
	chain := seq[ci]
	if len(chain) == 0 {
		return nil, ErrNoTimestamp
	}
	hash, err := chainHashAlg(chain)
	if err != nil {
		return nil, err
	}
	prevToken := chain[len(chain)-1].TimeStamp.FullBytes
	if len(prevToken) == 0 {
		return nil, ErrNoTimestamp
	}
	// The renewal's first (and only) reduced-hash-tree list holds H(previous
	// timestamp token); its root is H over that, which the new token covers. This
	// is the linkage §5.3 checks between consecutive ArchiveTimeStamps.
	prevHash := leafHash(hash, prevToken)
	reduced := groupReducedTree([][]byte{prevHash})
	root := groupRoot(hash, [][]byte{prevHash})

	token, _, err := ts.Timestamp(ctx, hash, root)
	if err != nil {
		return nil, err
	}
	ats, err := newArchiveTimeStamp(hash, reduced, token)
	if err != nil {
		return nil, err
	}
	seq[ci] = append(chain, ats)

	algs, err := digestAlgorithms(seq)
	if err != nil {
		return nil, err
	}
	return &EvidenceRecord{wire: evidenceRecord{Version: Version, DigestAlgorithms: algs, ArchiveTimeStampSequence: seq}}, nil
}

// RenewHashTree appends a hash-tree renewal (RFC 4998 §5.2) as a new
// ArchiveTimeStampChain: under the stronger newHash, each protected object is
// re-hashed and bound to the hash of the entire prior ArchiveTimeStampSequence
// (h(i)' = H_new(H_new(d(i)) || H_new(atsc))), a fresh data-group root over the
// new leaves is timestamped, and the new chain is appended to the sequence. This
// preserves the existence proof across obsolescence of the previous algorithm.
// objects MUST be the same protected data objects the record was generated over.
func (er *EvidenceRecord) RenewHashTree(ctx context.Context, ts Timestamper, objects []DataObject, newHash crypto.Hash) (*EvidenceRecord, error) {
	if len(objects) == 0 {
		return nil, ErrEmpty
	}
	if newHash == 0 || !newHash.Available() {
		return nil, &UnsupportedHashError{Hash: newHash}
	}
	seq := er.copySequence()
	if len(seq) == 0 {
		return nil, ErrNoTimestamp
	}

	prevSeqBytes, err := previousSequenceBytes(seq)
	if err != nil {
		return nil, err
	}
	ha := leafHash(newHash, prevSeqBytes) // H_new(atsc) — binds the new chain to all prior chains

	newLeaves := make([][]byte, len(objects))
	for i, o := range objects {
		hi := leafHash(newHash, o.Bytes)
		newLeaves[i] = leafHash(newHash, append(append([]byte{}, hi...), ha...))
	}
	root := groupRoot(newHash, newLeaves)

	token, _, err := ts.Timestamp(ctx, newHash, root)
	if err != nil {
		return nil, err
	}
	ats, err := newArchiveTimeStamp(newHash, groupReducedTree(newLeaves), token)
	if err != nil {
		return nil, err
	}
	seq = append(seq, archiveTimeStampChain{ats})

	algs, err := digestAlgorithms(seq)
	if err != nil {
		return nil, err
	}
	return &EvidenceRecord{wire: evidenceRecord{Version: Version, DigestAlgorithms: algs, ArchiveTimeStampSequence: seq}}, nil
}

// newArchiveTimeStamp assembles an ArchiveTimeStamp with an explicit digest
// algorithm, an optional reduced hash tree, and the embedded RFC 3161 token.
func newArchiveTimeStamp(hash crypto.Hash, reduced []partialHashtree, token []byte) (archiveTimeStamp, error) {
	algID, err := algorithmIdentifier(hash)
	if err != nil {
		return archiveTimeStamp{}, err
	}
	ats := archiveTimeStamp{
		DigestAlgorithm: algID,
		TimeStamp:       asn1.RawValue{FullBytes: token},
	}
	if len(reduced) > 0 {
		ats.ReducedHashtree = reduced
	}
	return ats, nil
}

// copySequence returns a shallow-per-element copy of the sequence deep enough
// that appending a chain or an ArchiveTimeStamp does not alias the receiver's
// slices. The ArchiveTimeStamp values themselves are treated as immutable.
func (er *EvidenceRecord) copySequence() []archiveTimeStampChain {
	out := make([]archiveTimeStampChain, len(er.wire.ArchiveTimeStampSequence))
	for i, c := range er.wire.ArchiveTimeStampSequence {
		nc := make(archiveTimeStampChain, len(c))
		copy(nc, c)
		out[i] = nc
	}
	return out
}

// chainHashAlg reports the hash algorithm of an ArchiveTimeStampChain: the
// digestAlgorithm of its first ArchiveTimeStamp, or, when that optional field is
// absent, the message-imprint hash of the first token (RFC 4998 §4.1).
func chainHashAlg(chain archiveTimeStampChain) (crypto.Hash, error) {
	if len(chain) == 0 {
		return 0, ErrNoTimestamp
	}
	ats := chain[0]
	if len(ats.DigestAlgorithm.Algorithm) > 0 {
		if h, ok := digestForOID(ats.DigestAlgorithm.Algorithm); ok {
			return h, nil
		}
		return 0, fmt.Errorf("ers: unsupported reduced-hash-tree algorithm %v", ats.DigestAlgorithm.Algorithm)
	}
	info, err := tsa.ParseTokenInfo(ats.TimeStamp.FullBytes)
	if err != nil {
		return 0, err
	}
	return info.Hash, nil
}

// digestAlgorithms returns the union of chain hash algorithms as the
// EvidenceRecord digestAlgorithms field (order not significant, RFC 4998 §3.1).
func digestAlgorithms(seq []archiveTimeStampChain) ([]pkix.AlgorithmIdentifier, error) {
	seen := map[string]bool{}
	var out []pkix.AlgorithmIdentifier
	for _, c := range seq {
		h, err := chainHashAlg(c)
		if err != nil {
			return nil, err
		}
		algID, err := algorithmIdentifier(h)
		if err != nil {
			return nil, err
		}
		key := algID.Algorithm.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, algID)
		}
	}
	return out, nil
}
