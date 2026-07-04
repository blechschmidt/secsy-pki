package ct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// RFC 6962 endpoints used by the inclusion monitor, relative to a log's base URL.
const (
	getSTHPath         = "ct/v1/get-sth"
	getProofByHashPath = "ct/v1/get-proof-by-hash"
)

// signatureTypeTreeHash is the RFC 6962 SignatureType covering a Signed Tree
// Head (as opposed to signatureTypeCertificateTimestamp for an SCT).
const signatureTypeTreeHash = 1

// Merkle hash prefixes distinguish leaf and interior node hashing so a proof
// cannot present an interior node as a leaf (RFC 6962 §2.1).
const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// maxProofResponseBytes bounds a get-sth / get-proof-by-hash response body.
const maxProofResponseBytes = 1 << 20 // 1 MiB

// ErrProofNotFound reports that a log has no inclusion proof for the queried
// leaf hash at the requested tree size (the get-proof-by-hash endpoint answered
// 404). Once the log's Maximum Merge Delay has elapsed this is the concrete
// mis-issuance / log-misbehavior signal: the log issued an SCT promising to log
// the entry but never did.
var ErrProofNotFound = errors.New("ct: log has no inclusion proof for the entry")

// SignedTreeHead is a decoded, optionally signature-verified RFC 6962 Signed
// Tree Head (§4.3): the log's commitment to the contents of its Merkle tree at
// a point in time.
type SignedTreeHead struct {
	// TreeSize is the number of entries in the tree the head commits to.
	TreeSize uint64
	// Timestamp is the head's assertion time in milliseconds since the Unix epoch.
	Timestamp uint64
	// SHA256RootHash is the Merkle Tree Hash of the tree at TreeSize.
	SHA256RootHash [32]byte
	// Signature is the raw TLS digitally-signed structure over the tree head.
	Signature []byte
}

// InclusionProof is a decoded get-proof-by-hash response (RFC 6962 §4.5): the
// position of a leaf in the tree and the Merkle audit path proving it.
type InclusionProof struct {
	// LeafIndex is the 0-based index of the leaf in the log.
	LeafIndex uint64
	// AuditPath is the list of sibling node hashes from the leaf to the root.
	AuditPath [][]byte
}

// getSTHResponse is the JSON body of get-sth (RFC 6962 §4.3).
type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`
	Timestamp         uint64 `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

// getProofResponse is the JSON body of get-proof-by-hash (RFC 6962 §4.5).
type getProofResponse struct {
	LeafIndex uint64   `json:"leaf_index"`
	AuditPath []string `json:"audit_path"`
}

// GetSTH fetches the log's current Signed Tree Head. When the log's public key
// is configured the tree-head signature is verified before the STH is returned,
// so a caller can trust SHA256RootHash as the log's signed commitment.
func (l *Log) GetSTH(ctx context.Context) (*SignedTreeHead, error) {
	body, err := l.getJSON(ctx, l.rootURL+"/"+getSTHPath)
	if err != nil {
		return nil, err
	}
	var r getSTHResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decoding get-sth response from log %q: %w", l.Name, err)
	}
	root, err := base64.StdEncoding.DecodeString(r.SHA256RootHash)
	if err != nil {
		return nil, fmt.Errorf("decoding sha256_root_hash from log %q: %w", l.Name, err)
	}
	if len(root) != sha256.Size {
		return nil, fmt.Errorf("log %q returned a %d-byte root hash, want %d", l.Name, len(root), sha256.Size)
	}
	sig, err := base64.StdEncoding.DecodeString(r.TreeHeadSignature)
	if err != nil {
		return nil, fmt.Errorf("decoding tree_head_signature from log %q: %w", l.Name, err)
	}
	sth := &SignedTreeHead{TreeSize: r.TreeSize, Timestamp: r.Timestamp, Signature: sig}
	copy(sth.SHA256RootHash[:], root)

	if l.hasKey {
		if err := sth.verify(l.PublicKey); err != nil {
			return nil, fmt.Errorf("log %q: %w", l.Name, err)
		}
	}
	return sth, nil
}

// GetProofByHash fetches the inclusion proof for the given Merkle leaf hash at
// the given tree size. It returns ErrProofNotFound when the log reports no such
// leaf (HTTP 404), which — after the log's MMD — is the misbehavior signal.
func (l *Log) GetProofByHash(ctx context.Context, leafHash []byte, treeSize uint64) (*InclusionProof, error) {
	q := url.Values{}
	q.Set("hash", base64.StdEncoding.EncodeToString(leafHash))
	q.Set("tree_size", strconv.FormatUint(treeSize, 10))
	body, err := l.getJSON(ctx, l.rootURL+"/"+getProofByHashPath+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var r getProofResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decoding get-proof-by-hash response from log %q: %w", l.Name, err)
	}
	proof := &InclusionProof{LeafIndex: r.LeafIndex, AuditPath: make([][]byte, len(r.AuditPath))}
	for i, node := range r.AuditPath {
		nb, err := base64.StdEncoding.DecodeString(node)
		if err != nil {
			return nil, fmt.Errorf("decoding audit path node %d from log %q: %w", i, l.Name, err)
		}
		proof.AuditPath[i] = nb
	}
	return proof, nil
}

// getJSON performs a bounded GET against the log and returns the body, mapping a
// 404 to ErrProofNotFound so callers can distinguish "not present" from a
// transient failure.
func (l *Log) getJSON(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for log %q: %w", l.Name, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("querying log %q: %w", l.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProofResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading log %q response: %w", l.Name, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrProofNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log %q returned HTTP %d: %s", l.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// treeHeadSignatureInput reconstructs the TreeHeadSignature structure a log
// signs over (RFC 6962 §3.5).
func (s *SignedTreeHead) treeHeadSignatureInput() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(0) // Version.v1
	b.AddUint8(signatureTypeTreeHash)
	b.AddUint64(s.Timestamp)
	b.AddUint64(s.TreeSize)
	b.AddBytes(s.SHA256RootHash[:])
	return b.Bytes()
}

// verify checks the STH's tree-head signature against the log's public key.
func (s *SignedTreeHead) verify(pub interface{}) error {
	input, err := s.treeHeadSignatureInput()
	if err != nil {
		return err
	}
	if err := verifyDigitallySigned(pub, s.Signature, input); err != nil {
		return fmt.Errorf("signed tree head %w", err)
	}
	return nil
}

// PrecertLeafHash returns the RFC 6962 Merkle tree leaf hash of the
// precertificate entry the given SCT attests: SHA-256(0x00 || MerkleTreeLeaf).
// tbs is the precertificate's TBSCertificate with the poison extension removed
// (equivalently, the final certificate's TBS with the SCT list removed — obtain
// it with TBSWithoutExtension), and issuer is the issuing CA certificate.
//
// The MerkleTreeLeaf bytes for a v1 timestamped precert entry are byte-for-byte
// identical to the SCT's own signature input (both are
// version||0||timestamp||precert_entry||PreCert||extensions, since
// timestamped_entry and certificate_timestamp are both enum value 0), so the
// leaf is derived from the same reconstruction the SCT signature is checked
// against — the hash the log must be able to prove is in its tree.
func PrecertLeafHash(sct *SCT, issuer *x509.Certificate, tbs []byte) ([32]byte, error) {
	leaf, err := sct.signatureInput(issuerKeyHash(issuer), tbs)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(leaf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifyInclusionProof checks a Merkle audit path: it recomputes the tree's
// root hash from leafHash at leafIndex in a tree of treeSize entries using
// auditPath, and confirms it equals rootHash (the SHA256RootHash of a
// signature-verified STH). A nil return means the leaf is provably included in
// the tree the STH commits to. It implements the RFC 6962 §2.1.1 audit-path
// algorithm via the split-at-the-tree-border decomposition (bit indexing on the
// leaf index), which is simpler to get right than the shift-based pseudocode.
func VerifyInclusionProof(leafIndex, treeSize uint64, auditPath [][]byte, rootHash, leafHash []byte) error {
	if treeSize == 0 {
		return fmt.Errorf("empty tree cannot include any leaf")
	}
	if leafIndex >= treeSize {
		return fmt.Errorf("leaf index %d is out of range for a tree of size %d", leafIndex, treeSize)
	}
	if len(leafHash) != sha256.Size {
		return fmt.Errorf("leaf hash has length %d, want %d", len(leafHash), sha256.Size)
	}
	if len(rootHash) != sha256.Size {
		return fmt.Errorf("root hash has length %d, want %d", len(rootHash), sha256.Size)
	}
	for i, n := range auditPath {
		if len(n) != sha256.Size {
			return fmt.Errorf("audit path node %d has length %d, want %d", i, len(n), sha256.Size)
		}
	}

	inner := innerProofSize(leafIndex, treeSize)
	border := bits.OnesCount64(leafIndex >> inner)
	if want := int(inner) + border; len(auditPath) != want {
		return fmt.Errorf("inclusion proof has %d nodes, want %d for leaf %d in a tree of size %d",
			len(auditPath), want, leafIndex, treeSize)
	}

	res := chainInner(leafHash, auditPath[:inner], leafIndex)
	res = chainBorderRight(res, auditPath[inner:])
	if !bytes.Equal(res, rootHash) {
		return fmt.Errorf("computed Merkle root %x does not match the signed tree head root %x", res, rootHash)
	}
	return nil
}

// innerProofSize is the number of proof nodes that sit below the tree's rightmost
// border for a leaf at index in a tree of the given size: the bit length of
// index XOR (size-1).
func innerProofSize(index, size uint64) uint {
	return uint(bits.Len64(index ^ (size - 1)))
}

// chainInner folds the "inner" proof nodes (those strictly below the tree
// border) into the running hash, choosing left/right by the corresponding bit
// of the leaf index.
func chainInner(seed []byte, proof [][]byte, index uint64) []byte {
	for i, p := range proof {
		if (index>>uint(i))&1 == 0 {
			seed = hashChildren(seed, p)
		} else {
			seed = hashChildren(p, seed)
		}
	}
	return seed
}

// chainBorderRight folds the remaining "border" proof nodes, each of which is a
// left sibling, into the running hash up to the root.
func chainBorderRight(seed []byte, proof [][]byte) []byte {
	for _, p := range proof {
		seed = hashChildren(p, seed)
	}
	return seed
}

// hashChildren computes the interior Merkle node hash SHA-256(0x01 || left || right).
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MMDElapsed reports whether the log's Maximum Merge Delay has passed for an SCT
// issued at sctTimestamp (milliseconds since the Unix epoch) as of now, i.e.
// whether the log is now obliged to have merged the entry and a missing proof is
// evidence of misbehavior rather than of a pending merge.
func (l *Log) MMDElapsed(sctTimestampMS uint64, now time.Time) bool {
	issued := time.UnixMilli(int64(sctTimestampMS))
	return now.After(issued.Add(l.mmd))
}
