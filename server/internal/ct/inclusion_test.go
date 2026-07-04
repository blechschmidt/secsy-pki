package ct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// --- reference RFC 6962 Merkle tree, used only to generate correct proofs the
// implementation under test must accept (and, when tampered, reject). ----------

// refLeafHash is MTH({input}) = SHA-256(0x00 || input).
func refLeafHash(input []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(input)
	return h.Sum(nil)
}

// refNodeHash is SHA-256(0x01 || left || right).
func refNodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// largestPow2LessThan returns the largest power of two strictly less than n (n>=2).
func largestPow2LessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// refRoot computes the Merkle Tree Hash over already-leaf-hashed nodes.
func refRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := largestPow2LessThan(len(leaves))
	return refNodeHash(refRoot(leaves[:k]), refRoot(leaves[k:]))
}

// refAuditPath computes the audit path for leaf m over already-leaf-hashed nodes.
func refAuditPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPow2LessThan(len(leaves))
	if m < k {
		return append(refAuditPath(m, leaves[:k]), refRoot(leaves[k:]))
	}
	return append(refAuditPath(m-k, leaves[k:]), refRoot(leaves[:k]))
}

// TestVerifyInclusionProof exercises the audit-path verifier across a range of
// tree sizes and every leaf position, and confirms a corrupted root or a
// swapped sibling is rejected.
func TestVerifyInclusionProof(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 16, 100} {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = refLeafHash([]byte(fmt.Sprintf("entry-%d-of-%d", i, n)))
		}
		root := refRoot(leaves)
		for m := 0; m < n; m++ {
			path := refAuditPath(m, leaves)
			if err := VerifyInclusionProof(uint64(m), uint64(n), path, root, leaves[m]); err != nil {
				t.Fatalf("n=%d leaf=%d: valid proof rejected: %v", n, m, err)
			}
			// A flipped root must fail.
			badRoot := append([]byte(nil), root...)
			badRoot[0] ^= 0xff
			if err := VerifyInclusionProof(uint64(m), uint64(n), path, badRoot, leaves[m]); err == nil {
				t.Fatalf("n=%d leaf=%d: proof accepted against a tampered root", n, m)
			}
			// A flipped sibling (when there is one) must fail.
			if len(path) > 0 {
				badPath := make([][]byte, len(path))
				copy(badPath, path)
				sib := append([]byte(nil), path[0]...)
				sib[0] ^= 0xff
				badPath[0] = sib
				if err := VerifyInclusionProof(uint64(m), uint64(n), badPath, root, leaves[m]); err == nil {
					t.Fatalf("n=%d leaf=%d: proof accepted with a tampered sibling", n, m)
				}
			}
		}
	}
}

// TestVerifyInclusionProofRejectsBadShape checks the guard rails: out-of-range
// index, empty tree, wrong-length nodes, and a proof of the wrong size.
func TestVerifyInclusionProofRejectsBadShape(t *testing.T) {
	leaves := [][]byte{refLeafHash([]byte("a")), refLeafHash([]byte("b"))}
	root := refRoot(leaves)
	path := refAuditPath(0, leaves)

	if err := VerifyInclusionProof(2, 2, path, root, leaves[0]); err == nil {
		t.Error("out-of-range leaf index accepted")
	}
	if err := VerifyInclusionProof(0, 0, nil, root, leaves[0]); err == nil {
		t.Error("empty tree accepted")
	}
	// Wrong proof length for the tree.
	if err := VerifyInclusionProof(0, 2, append(append([][]byte{}, path...), root), root, leaves[0]); err == nil {
		t.Error("oversized proof accepted")
	}
	// Wrong-length audit node.
	if err := VerifyInclusionProof(0, 2, [][]byte{{0x01, 0x02}}, root, leaves[0]); err == nil {
		t.Error("short audit node accepted")
	}
}

// TestPrecertLeafHashMatchesLogLeaf proves the leaf hash the monitor computes
// for an SCT equals the leaf the log built its Merkle entry from: it derives the
// same MerkleTreeLeaf bytes and hashes them with the 0x00 leaf prefix. The
// "want" side is rebuilt independently (not via signatureInput) so the test
// pins the wire layout rather than tautologically re-deriving it.
func TestPrecertLeafHashMatchesLogLeaf(t *testing.T) {
	caCert, caKey := testCA(t)
	m := newMockLog(t, caCert)
	srv := httptest.NewServer(m)
	defer srv.Close()

	sub, err := NewSubmitter([]LogConfig{{Name: "log", URL: srv.URL, PublicKeyPEM: m.publicKeyPEM(t)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := newLeafKey(t)
	precertDER := buildLeaf(t, caCert, caKey, leafKey.Public(), big.NewInt(0xABCDEF), PoisonExtension())
	res, err := sub.Submit(context.Background(), SubmitRequest{
		PrecertDER: precertDER, Issuer: caCert, IssuerChainDER: [][]byte{caCert.Raw}, Timeout: 5 * time.Second,
	})
	if err != nil || len(res.SCTs) != 1 {
		t.Fatalf("submit: err=%v scts=%d", err, len(res.SCTs))
	}
	tbs, err := TBSWithoutExtension(precertDER, OIDPoison)
	if err != nil {
		t.Fatal(err)
	}
	sct := res.SCTs[0]

	got, err := PrecertLeafHash(sct, caCert, tbs)
	if err != nil {
		t.Fatal(err)
	}

	// Independently rebuild the MerkleTreeLeaf the log hashes for a v1
	// timestamped precert entry, then leaf-hash it.
	ikh := sha256.Sum256(caCert.RawSubjectPublicKeyInfo)
	var b cryptobyte.Builder
	b.AddUint8(0) // version v1
	b.AddUint8(0) // leaf_type = timestamped_entry
	b.AddUint64(sct.Timestamp)
	b.AddUint16(1) // entry_type = precert_entry
	b.AddBytes(ikh[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sct.Extensions) })
	leaf, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte{merkleLeafPrefix}, leaf...))
	if got != want {
		t.Fatalf("PrecertLeafHash = %x, want %x", got, want)
	}
}

// TestGetSTHVerifiesSignature confirms GetSTH accepts a correctly signed tree
// head and rejects one signed by the wrong key.
func TestGetSTHVerifiesSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const treeSize = 42
	root := sha256.Sum256([]byte("root-hash"))
	timestamp := uint64(1_700_000_000_000)
	sth := signSTH(t, key, treeSize, timestamp, root)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sth)
	}))
	defer srv.Close()

	good, err := NewLog(LogConfig{Name: "log", URL: srv.URL, PublicKeyPEM: spkiPEM(t, key)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := good.GetSTH(context.Background())
	if err != nil {
		t.Fatalf("GetSTH with correct key: %v", err)
	}
	if out.TreeSize != treeSize || out.SHA256RootHash != root {
		t.Fatalf("STH mismatch: size=%d root=%x", out.TreeSize, out.SHA256RootHash)
	}

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad, err := NewLog(LogConfig{Name: "log", URL: srv.URL, PublicKeyPEM: spkiPEM(t, wrongKey)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.GetSTH(context.Background()); err == nil {
		t.Fatal("GetSTH accepted an STH signed by the wrong key")
	}
}

// TestGetProofByHashNotFound maps a 404 to ErrProofNotFound.
func TestGetProofByHashNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	l, err := NewLog(LogConfig{Name: "log", URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256([]byte("leaf"))
	if _, err := l.GetProofByHash(context.Background(), leafHash[:], 10); err != ErrProofNotFound {
		t.Fatalf("GetProofByHash 404 = %v, want ErrProofNotFound", err)
	}
}

// signSTH builds a getSTHResponse with a valid tree-head signature over the
// given fields, signed by key.
func signSTH(t *testing.T, key *ecdsa.PrivateKey, treeSize, timestamp uint64, root [32]byte) getSTHResponse {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(0) // version v1
	b.AddUint8(signatureTypeTreeHash)
	b.AddUint64(timestamp)
	b.AddUint64(treeSize)
	b.AddBytes(root[:])
	input, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var sb cryptobyte.Builder
	sb.AddUint8(hashAlgSHA256)
	sb.AddUint8(sigAlgECDSA)
	sb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	ds, err := sb.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return getSTHResponse{
		TreeSize:          treeSize,
		Timestamp:         timestamp,
		SHA256RootHash:    base64.StdEncoding.EncodeToString(root[:]),
		TreeHeadSignature: base64.StdEncoding.EncodeToString(ds),
	}
}

// spkiPEM returns the PEM SubjectPublicKeyInfo of key's public half.
func spkiPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
}
