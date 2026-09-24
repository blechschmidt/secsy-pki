package ers

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// The oracles below recompute the RFC 4998 §4.2 data-group root with
// crypto/sha256 / crypto/sha512 directly rather than through the package's own
// hashNode/sortConcatHash, so a change to the production construction cannot
// silently move the expectation with it.

// oracleSortedConcat returns the binary-ascending sorted concatenation of hs —
// whole hash values compared most-significant-byte first, leading zeros kept.
func oracleSortedConcat(hs [][]byte) []byte {
	cp := make([][]byte, len(hs))
	for i, h := range hs {
		cp[i] = append([]byte(nil), h...)
	}
	sort.Slice(cp, func(i, j int) bool { return bytes.Compare(cp[i], cp[j]) < 0 })
	var buf []byte
	for _, h := range cp {
		buf = append(buf, h...)
	}
	return buf
}

func oracleGroupRoot256(leaves [][]byte) []byte {
	sum := sha256.Sum256(oracleSortedConcat(leaves))
	return sum[:]
}

func oracleGroupRoot512(leaves [][]byte) []byte {
	sum := sha512.Sum512(oracleSortedConcat(leaves))
	return sum[:]
}

// TestGroupRootMatchesIndependentOracle pins the group root for every leaf count
// that matters — zero, one, two, an odd count, and exact powers of two — against
// an oracle built straight on crypto/sha256 and crypto/sha512.
func TestGroupRootMatchesIndependentOracle(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 7, 8, 16, 17} {
		leaves256 := make([][]byte, n)
		leaves512 := make([][]byte, n)
		for i := 0; i < n; i++ {
			leaves256[i] = leafHash(crypto.SHA256, []byte(fmt.Sprintf("leaf-%d", i)))
			leaves512[i] = leafHash(crypto.SHA512, []byte(fmt.Sprintf("leaf-%d", i)))
		}
		if got, want := groupRoot(crypto.SHA256, leaves256), oracleGroupRoot256(leaves256); !bytes.Equal(got, want) {
			t.Fatalf("n=%d SHA-256 group root\n got=%x\nwant=%x", n, got, want)
		}
		if got, want := groupRoot(crypto.SHA512, leaves512), oracleGroupRoot512(leaves512); !bytes.Equal(got, want) {
			t.Fatalf("n=%d SHA-512 group root\n got=%x\nwant=%x", n, got, want)
		}
	}
}

// TestGroupRootEmptyAndSingleLeaf spells out the two degenerate cases with
// hardcoded expectations, so neither can drift into "the same as the other".
func TestGroupRootEmptyAndSingleLeaf(t *testing.T) {
	// Zero leaves: H over the empty concatenation.
	emptySum := sha256.Sum256(nil)
	if got := groupRoot(crypto.SHA256, nil); !bytes.Equal(got, emptySum[:]) {
		t.Fatalf("zero-leaf root = %x, want H(\"\") = %x", got, emptySum)
	}
	if got := groupRoot(crypto.SHA256, [][]byte{}); !bytes.Equal(got, emptySum[:]) {
		t.Fatal("zero-leaf root must not depend on nil vs empty slice")
	}

	// Exactly one leaf: H(leaf), which must differ from the leaf itself (a single
	// further application of H is what binds the group).
	leaf := leafHash(crypto.SHA256, []byte("solo"))
	want := sha256.Sum256(leaf)
	got := groupRoot(crypto.SHA256, [][]byte{leaf})
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("single-leaf root = %x, want H(leaf) = %x", got, want)
	}
	if bytes.Equal(got, leaf) {
		t.Fatal("single-leaf root must not be the bare leaf hash")
	}
	if bytes.Equal(got, emptySum[:]) {
		t.Fatal("a one-leaf group must not collide with the empty group")
	}
}

// TestGroupRootTwoLeavesUsesBinaryAscendingOrder checks the two-leaf case against
// both possible concatenations explicitly: only the smaller-first one may match.
func TestGroupRootTwoLeavesUsesBinaryAscendingOrder(t *testing.T) {
	a := leafHash(crypto.SHA256, []byte("alpha"))
	b := leafHash(crypto.SHA256, []byte("bravo"))
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	wantSorted := sha256.Sum256(append(append([]byte{}, lo...), hi...))
	wantReversed := sha256.Sum256(append(append([]byte{}, hi...), lo...))
	if bytes.Equal(wantSorted[:], wantReversed[:]) {
		t.Fatal("test setup: the two concatenations must differ")
	}

	for _, order := range [][][]byte{{a, b}, {b, a}} {
		got := groupRoot(crypto.SHA256, order)
		if !bytes.Equal(got, wantSorted[:]) {
			t.Fatalf("group root = %x, want the binary-ascending concatenation %x", got, wantSorted)
		}
	}
}

// TestGroupRootDeterministicAcrossShuffles builds the same group hundreds of
// times from shuffled input orders: the root bytes must be byte-identical every
// time. Any residual dependence on input or map iteration order would silently
// invalidate every previously stored proof.
func TestGroupRootDeterministicAcrossShuffles(t *testing.T) {
	const n = 12
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = leafHash(crypto.SHA384, []byte(fmt.Sprintf("member-%02d", i)))
	}
	want := hex.EncodeToString(groupRoot(crypto.SHA384, leaves))

	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 200; iter++ {
		shuffled := make([][]byte, n)
		copy(shuffled, leaves)
		rng.Shuffle(n, func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := hex.EncodeToString(groupRoot(crypto.SHA384, shuffled)); got != want {
			t.Fatalf("iteration %d: group root changed with input order\n got=%s\nwant=%s", iter, got, want)
		}
		// The stored reduced tree must be canonical too: same bytes, same order.
		tree := groupReducedTree(shuffled)
		if len(tree) != 1 || len(tree[0]) != n {
			t.Fatalf("iteration %d: reduced tree shape = %d lists", iter, len(tree))
		}
		for i := 1; i < n; i++ {
			if bytes.Compare(tree[0][i-1], tree[0][i]) > 0 {
				t.Fatalf("iteration %d: reduced tree is not binary-ascending at %d", iter, i)
			}
		}
	}
}

// TestGroupReducedTreeDoesNotAliasInput guards against the reduced tree sharing
// backing storage with the caller's slice: a later mutation of the caller's
// leaves must not rewrite a stored proof.
func TestGroupReducedTreeDoesNotAliasInput(t *testing.T) {
	leaves := [][]byte{
		leafHash(crypto.SHA256, []byte("x")),
		leafHash(crypto.SHA256, []byte("y")),
		leafHash(crypto.SHA256, []byte("z")),
	}
	tree := groupReducedTree(leaves)
	before := append([][]byte(nil), tree[0]...)
	leaves[0], leaves[2] = leaves[2], leaves[0]
	for i := range tree[0] {
		if !bytes.Equal(tree[0][i], before[i]) {
			t.Fatalf("reduced tree entry %d changed when the caller reordered its own slice", i)
		}
	}
}

// TestSortHashesKeepsLeadingZeros pins the RFC 4998 §4.2 ordering rule: the whole
// hash output is compared most-significant-byte first with leading zeros retained.
// Stripping them (or comparing as big integers of differing width) would reorder
// these values and change every root.
func TestSortHashesKeepsLeadingZeros(t *testing.T) {
	in := [][]byte{
		{0x01, 0x00, 0x00},
		{0x00, 0xff, 0xff},
		{0x00, 0x00, 0x01},
		{0xff},
	}
	got := sortHashes(in)
	want := [][]byte{
		{0x00, 0x00, 0x01},
		{0x00, 0xff, 0xff},
		{0x01, 0x00, 0x00},
		{0xff},
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("sortHashes[%d] = %x, want %x (full ordering: %x)", i, got[i], want[i], got)
		}
	}
	// sortHashes must copy, not sort in place.
	if !bytes.Equal(in[0], []byte{0x01, 0x00, 0x00}) {
		t.Fatalf("sortHashes mutated its input: %x", in)
	}
}

// TestRecomputeRootNoPartialsReturnsLeaf covers the degenerate reduction: with no
// partial hash trees the leaf is itself the root (RFC 4998 §4.3).
func TestRecomputeRootNoPartialsReturnsLeaf(t *testing.T) {
	leaf := leafHash(crypto.SHA256, []byte("only"))
	got, err := recomputeRoot(crypto.SHA256, leaf, nil)
	if err != nil {
		t.Fatalf("recomputeRoot: %v", err)
	}
	if !bytes.Equal(got, leaf) {
		t.Fatalf("root = %x, want the leaf %x", got, leaf)
	}
	if _, err := recomputeRoot(crypto.SHA256, leaf, []partialHashtree{}); err != nil {
		t.Fatalf("empty (non-nil) partial list: %v", err)
	}
}

// TestRecomputeRootRejectsTamperedPath is the core negative test for the
// reduction: a genuine multi-level authentication path is mutated one way at a
// time and the recomputed root must stop matching (or the walk must error).
// Without these, a verifier that accepted everything would still pass every
// happy-path test in this package.
func TestRecomputeRootRejectsTamperedPath(t *testing.T) {
	const hash = crypto.SHA256
	const n = 9 // odd, so the reduction exercises the promoted-node level too
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = leafHash(hash, []byte(fmt.Sprintf("obj-%d", i)))
	}
	sorted := sortHashes(leaves)
	levels := oracleLevels(hash, sorted)
	root := levels[len(levels)-1][0]
	const idx = 3
	leaf := sorted[idx]
	base := oracleReducedTree(levels, idx)

	// Sanity: the untouched path must reproduce the root, else the mutations below
	// would prove nothing.
	if got, err := recomputeRoot(hash, leaf, clonePartials(base)); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("baseline path must verify: err=%v got=%x want=%x", err, got, root)
	}
	if len(base) < 3 {
		t.Fatalf("test setup: expected a multi-level path, got %d levels", len(base))
	}

	tests := []struct {
		name   string
		leaf   []byte
		mutate func(p []partialHashtree) []partialHashtree
	}{
		{
			name: "one byte flipped in the leaf's own list",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				p[0][0] = flipByte(p[0][0], 0)
				return p
			},
		},
		{
			name: "one byte flipped in a higher-level sibling",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				p[len(p)-1][0] = flipByte(p[len(p)-1][0], 5)
				return p
			},
		},
		{
			name: "last byte flipped in a mid-level sibling",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				h := p[1][0]
				p[1][0] = flipByte(h, len(h)-1)
				return p
			},
		},
		{
			name:   "path truncated by one level",
			leaf:   leaf,
			mutate: func(p []partialHashtree) []partialHashtree { return p[:len(p)-1] },
		},
		{
			name:   "path truncated to the leaf list only",
			leaf:   leaf,
			mutate: func(p []partialHashtree) []partialHashtree { return p[:1] },
		},
		{
			name: "extra level appended to the path",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				return append(p, partialHashtree{leafHash(hash, []byte("bogus-level"))})
			},
		},
		{
			name: "extra sibling injected into the leaf list",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				p[0] = append(p[0], leafHash(hash, []byte("injected")))
				return p
			},
		},
		{
			name: "sibling removed from the leaf list",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				for i, h := range p[0] {
					if !bytes.Equal(h, leaf) {
						p[0] = append(p[0][:i], p[0][i+1:]...)
						break
					}
				}
				return p
			},
		},
		{
			name: "two path levels transposed",
			leaf: leaf,
			mutate: func(p []partialHashtree) []partialHashtree {
				p[1], p[2] = p[2], p[1]
				return p
			},
		},
		{
			name:   "leaf that is not in the tree at all",
			leaf:   leafHash(hash, []byte("outsider")),
			mutate: func(p []partialHashtree) []partialHashtree { return p },
		},
		{
			name:   "leaf from the tree but not from this path",
			leaf:   sorted[(idx+4)%n],
			mutate: func(p []partialHashtree) []partialHashtree { return p },
		},
		{
			name:   "empty leaf",
			leaf:   nil,
			mutate: func(p []partialHashtree) []partialHashtree { return p },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := recomputeRoot(hash, tc.leaf, tc.mutate(clonePartials(base)))
			if err != nil {
				return // rejected outright, which is what we want
			}
			if bytes.Equal(got, root) {
				t.Fatalf("mutated path still recomputed the real root %x", root)
			}
		})
	}
}

// TestRecomputeRootIgnoresStoredSiblingOrder is the flip side of the tamper
// table: because every node concatenation is re-sorted binary-ascending, the
// order siblings happen to be stored in carries no meaning. Swapping a sibling
// pair inside one partial list must therefore leave the root unchanged — while
// swapping the *levels* of the path (asserted above) must not.
func TestRecomputeRootIgnoresStoredSiblingOrder(t *testing.T) {
	const hash = crypto.SHA512
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = leafHash(hash, []byte(fmt.Sprintf("s-%d", i)))
	}
	sorted := sortHashes(leaves)
	levels := oracleLevels(hash, sorted)
	root := levels[len(levels)-1][0]
	path := oracleReducedTree(levels, 2)

	reversed := clonePartials(path)
	for _, list := range reversed {
		for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
			list[i], list[j] = list[j], list[i]
		}
	}
	got, err := recomputeRoot(hash, sorted[2], reversed)
	if err != nil {
		t.Fatalf("recomputeRoot with reversed sibling order: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatalf("canonical sorting broken: reversing stored sibling order changed the root\n got=%x\nwant=%x", got, root)
	}
}

// TestRecomputeRootDistinguishesDuplicateLastNode is the classic odd-leaf-count
// ambiguity: a tree over [a,b,c] must not produce the same root as a tree over
// [a,b,c,c]. If the promoted odd node were duplicated instead of re-hashed the
// two would collide, letting one proof stand in for a different data set.
func TestRecomputeRootDistinguishesDuplicateLastNode(t *testing.T) {
	const hash = crypto.SHA256
	a := leafHash(hash, []byte("a"))
	b := leafHash(hash, []byte("b"))
	c := leafHash(hash, []byte("c"))

	odd := sortHashes([][]byte{a, b, c})
	dup := sortHashes([][]byte{a, b, c, c})
	oddLevels := oracleLevels(hash, odd)
	dupLevels := oracleLevels(hash, dup)
	oddRoot := oddLevels[len(oddLevels)-1][0]
	dupRoot := dupLevels[len(dupLevels)-1][0]
	if bytes.Equal(oddRoot, dupRoot) {
		t.Fatal("three-leaf and duplicate-last four-leaf trees must not share a root")
	}

	// A proof from the three-leaf tree must not recompute the four-leaf root.
	for idx := range odd {
		got, err := recomputeRoot(hash, odd[idx], oracleReducedTree(oddLevels, idx))
		if err != nil {
			t.Fatalf("leaf %d: %v", idx, err)
		}
		if !bytes.Equal(got, oddRoot) {
			t.Fatalf("leaf %d: proof did not recompute its own root", idx)
		}
		if bytes.Equal(got, dupRoot) {
			t.Fatalf("leaf %d: three-leaf proof recomputed the duplicate-last root", idx)
		}
	}

	// The same holds for the flat data-group tree the package actually emits.
	if bytes.Equal(groupRoot(hash, [][]byte{a, b, c}), groupRoot(hash, [][]byte{a, b, c, c})) {
		t.Fatal("group root must distinguish a duplicated member")
	}
}

// TestGroupRootBindsMemberCount catches a length-extension style confusion: a
// group of two 32-byte leaves hashes the same bytes as a one-element list holding
// their 64-byte concatenation. The roots therefore coincide — so membership must
// be decided by the exact leaf, never by "the root reduces", and checkReduction
// must reject a list that merely concatenates the members away.
func TestGroupRootBindsMemberCount(t *testing.T) {
	const hash = crypto.SHA256
	a := leafHash(hash, []byte("first"))
	b := leafHash(hash, []byte("second"))
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	glued := append(append([]byte{}, lo...), hi...)

	root := groupRoot(hash, [][]byte{a, b})
	if !bytes.Equal(groupRoot(hash, [][]byte{glued}), root) {
		t.Skip("construction is not ambiguous under this hash; nothing to guard")
	}
	// The ambiguity exists, so the membership check is what carries the weight:
	// a reduced tree holding only the glued value must not prove either member.
	forged := []partialHashtree{{glued}}
	if err := checkReduction(hash, forged, [][]byte{a}, root); err == nil {
		t.Fatal("checkReduction accepted a reduced tree that concatenated the members away")
	}
	if err := checkReduction(hash, forged, [][]byte{a, b}, root); err == nil {
		t.Fatal("checkReduction accepted a glued reduced tree for both members")
	}
	// The honest tree still proves both.
	honest := groupReducedTree([][]byte{a, b})
	if err := checkReduction(hash, honest, [][]byte{a, b}, root); err != nil {
		t.Fatalf("honest reduced tree must verify: %v", err)
	}
}

func clonePartials(in []partialHashtree) []partialHashtree {
	out := make([]partialHashtree, len(in))
	for i, list := range in {
		cp := make(partialHashtree, len(list))
		for j, h := range list {
			cp[j] = append([]byte(nil), h...)
		}
		out[i] = cp
	}
	return out
}

func flipByte(h []byte, i int) []byte {
	cp := append([]byte(nil), h...)
	cp[i] ^= 0xff
	return cp
}
