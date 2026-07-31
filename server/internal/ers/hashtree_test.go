package ers

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"testing"
)

// --- a binary Merkle oracle, used only by tests to exercise recomputeRoot's
// general multi-level RFC 4998 §4.3 reduction (production uses the shallow
// data-group reduced tree, whose paths are single-list). If recomputeRoot ever
// stops reproducing arbitrary tree paths, these tests catch it.

func oracleLevels(h crypto.Hash, leaves [][]byte) [][][]byte {
	levels := [][][]byte{leaves}
	cur := leaves
	for len(cur) > 1 {
		next := make([][]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 < len(cur) {
				next = append(next, sortConcatHash(h, [][]byte{cur[i], cur[i+1]}))
			} else {
				next = append(next, hashNode(h, cur[i]))
			}
		}
		levels = append(levels, next)
		cur = next
	}
	return levels
}

// oracleReducedTree builds a genuine multi-level authentication path for one
// leaf, matching the recomputeRoot reduction rules.
func oracleReducedTree(levels [][][]byte, idx int) []partialHashtree {
	var partials []partialHashtree
	node := idx
	for L := 0; L < len(levels)-1; L++ {
		lvl := levels[L]
		base := (node / 2) * 2
		if L == 0 {
			grp := [][]byte{lvl[base]}
			if base+1 < len(lvl) {
				grp = append(grp, lvl[base+1])
			}
			partials = append(partials, sortHashes(grp))
		} else {
			var grp [][]byte
			for j := base; j < base+2 && j < len(lvl); j++ {
				if j != node {
					grp = append(grp, lvl[j])
				}
			}
			partials = append(partials, sortHashes(grp))
		}
		node /= 2
	}
	return partials
}

// TestRecomputeRootMultiLevel drives recomputeRoot against a real binary Merkle
// tree of every size, proving the general §4.3 reduction (including the
// multi-list loop) recovers the root for each leaf.
func TestRecomputeRootMultiLevel(t *testing.T) {
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA512} {
		for n := 1; n <= 33; n++ {
			leaves := make([][]byte, n)
			for i := 0; i < n; i++ {
				leaves[i] = leafHash(hash, []byte(fmt.Sprintf("obj-%d-%s", i, HashName(hash))))
			}
			sorted := sortHashes(leaves)
			levels := oracleLevels(hash, sorted)
			root := levels[len(levels)-1][0]
			for idx := 0; idx < n; idx++ {
				partials := oracleReducedTree(levels, idx)
				got, err := recomputeRoot(hash, sorted[idx], partials)
				if err != nil {
					t.Fatalf("n=%d hash=%v leaf=%d: %v", n, hash, idx, err)
				}
				if !equalHash(got, root) {
					t.Fatalf("n=%d hash=%v leaf=%d: root mismatch\n got=%x\nwant=%x", n, hash, idx, got, root)
				}
			}
		}
	}
}

// TestGroupReducedTreeRoundTrip checks the production data-group reduction: every
// member of a group recomputes the same group root.
func TestGroupReducedTreeRoundTrip(t *testing.T) {
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for n := 1; n <= 20; n++ {
			leaves := make([][]byte, n)
			for i := 0; i < n; i++ {
				leaves[i] = leafHash(hash, []byte(fmt.Sprintf("member-%d", i)))
			}
			root := groupRoot(hash, leaves)
			partials := groupReducedTree(leaves)
			for i := 0; i < n; i++ {
				got, err := recomputeRoot(hash, leaves[i], partials)
				if err != nil {
					t.Fatalf("n=%d hash=%v member=%d: %v", n, hash, i, err)
				}
				if !equalHash(got, root) {
					t.Fatalf("n=%d hash=%v member=%d: group root mismatch", n, hash, i)
				}
			}
			// A non-member must be rejected by the membership check.
			outsider := leafHash(hash, []byte("outsider"))
			if _, err := recomputeRoot(hash, outsider, partials); err == nil {
				t.Fatalf("n=%d hash=%v: outsider must not verify", n, hash)
			}
		}
	}
}

// TestGroupRootKnownAnswer pins the data-group root of a fixed three-member
// SHA-256 group, so a change to the leaf hash, binary-ascending sort,
// concatenation, or the single application of H is caught.
func TestGroupRootKnownAnswer(t *testing.T) {
	members := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	leaves := make([][]byte, len(members))
	for i, m := range members {
		leaves[i] = leafHash(crypto.SHA256, m)
	}
	const wantRoot = "1aced86c3b7644b93974a6d04ea9fcf20e01a6120a5315af13687f0456fadeff"
	got := hex.EncodeToString(groupRoot(crypto.SHA256, leaves))
	if got != wantRoot {
		t.Fatalf("group-root drift:\n got=%s\nwant=%s", got, wantRoot)
	}
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
