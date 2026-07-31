package ers

import (
	"bytes"
	"crypto"
	"sort"
)

// DataObject is one protected data object: a stable identifier and the exact
// bytes whose existence the Evidence Record attests. The identifier is used only
// for diagnostics and lookup (it is never hashed), so the same bytes always map
// to the same leaf regardless of ID.
type DataObject struct {
	ID    string
	Bytes []byte
}

// The protected objects of one Evidence Record form a single RFC 4998 "data
// object group" (§4.1): each object is hashed into a leaf, the leaves are the
// first (and only) PartialHashtree list, and the group's root — H over the
// binary-ascending-sorted concatenation of the leaves — is what an
// ArchiveTimeStamp covers. This proves every group member with one timestamp and
// keeps renewal to one timestamp per record. recomputeRoot below implements the
// full, general RFC 4998 §4.3 reduction, so it also verifies the single-element
// reduced hash trees that time-stamp renewal produces.

// leafHash computes the leaf digest H(data) of a data object.
func leafHash(h crypto.Hash, data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

// hashNode computes an inner (parent/root) node digest H(data). It is separate
// from leafHash only for readability; both are a single application of H.
func hashNode(h crypto.Hash, data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

// sortHashes returns a copy of hs sorted in binary ascending order — the whole
// output of the hash algorithm compared most-significant-byte first, with
// leading zeros retained (RFC 4998 §4.2). Every node concatenation applies this
// ordering so the tree is independent of input order.
func sortHashes(hs [][]byte) [][]byte {
	out := make([][]byte, len(hs))
	copy(out, hs)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// concat joins the byte slices in order.
func concat(hs [][]byte) []byte {
	var buf []byte
	for _, h := range hs {
		buf = append(buf, h...)
	}
	return buf
}

// sortConcatHash sorts the hashes binary-ascending, concatenates them, and
// applies H — the canonical way RFC 4998 forms a parent node from its children.
func sortConcatHash(h crypto.Hash, hs [][]byte) []byte {
	return hashNode(h, concat(sortHashes(hs)))
}

// groupReducedTree builds the reduced hash tree for a data group: a single
// PartialHashtree holding every member leaf hash, binary-ascending sorted. Any
// member is proven present by its membership in this list.
func groupReducedTree(leaves [][]byte) []partialHashtree {
	return []partialHashtree{sortHashes(leaves)}
}

// groupRoot computes the data-group root that an ArchiveTimeStamp covers: H over
// the sorted concatenation of the member leaf hashes.
func groupRoot(h crypto.Hash, leaves [][]byte) []byte {
	return sortConcatHash(h, leaves)
}

// recomputeRoot reconstructs the root from a leaf hash and a reduced hash tree,
// following RFC 4998 §4.3: verify the leaf is a member of the first
// partial-hashtree list, hash that list to its parent, then at each higher level
// insert the running parent into the stored sibling list, sort, concatenate, and
// hash. With no partials the leaf is itself the root. It errors only when the
// leaf is absent from the first list (which no valid reduced tree can omit).
func recomputeRoot(h crypto.Hash, leaf []byte, partials []partialHashtree) ([]byte, error) {
	if len(partials) == 0 {
		return leaf, nil
	}
	if !containsHash(partials[0], leaf) {
		return nil, verifyErr(-1, "", "leaf hash not present in the first partial hash tree", nil)
	}
	running := sortConcatHash(h, partials[0])
	for k := 1; k < len(partials); k++ {
		combined := append([][]byte{}, partials[k]...)
		combined = append(combined, running)
		running = sortConcatHash(h, combined)
	}
	return running, nil
}

// containsHash reports whether target appears in the list.
func containsHash(list [][]byte, target []byte) bool {
	for _, h := range list {
		if bytes.Equal(h, target) {
			return true
		}
	}
	return false
}
