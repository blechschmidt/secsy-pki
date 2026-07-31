package timesource

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// roughtimeResponder is a minimal, correct Roughtime server used to test the
// client verifier end to end: it holds a long-term key and a delegated key,
// certifies the delegated key, and signs an SREP committing to the client's
// nonce via a Merkle tree.
type roughtimeResponder struct {
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	delePub   ed25519.PublicKey
	delePriv  ed25519.PrivateKey
	minMicros uint64
	maxMicros uint64
}

func newRoughtimeResponder(t *testing.T, minMicros, maxMicros uint64) *roughtimeResponder {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delePub, delePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &roughtimeResponder{
		rootPub: rootPub, rootPriv: rootPriv,
		delePub: delePub, delePriv: delePriv,
		minMicros: minMicros, maxMicros: maxMicros,
	}
}

// respond builds a signed response committing to nonce, with the given midpoint
// and radius, and optional additional leaves to force a non-trivial Merkle path.
func (r *roughtimeResponder) respond(nonce []byte, midMicros uint64, radius uint32, extraLeaf []byte) []byte {
	// DELE certifies the delegated public key over a validity window.
	dele := encodeRoughtimeMessage(map[uint32][]byte{
		tagPUBK: r.delePub,
		tagMINT: le64(r.minMicros),
		tagMAXT: le64(r.maxMicros),
	})
	certSig := ed25519.Sign(r.rootPriv, append([]byte(roughtimeCertContext), dele...))
	cert := encodeRoughtimeMessage(map[uint32][]byte{
		tagDELE: dele,
		tagSIG:  certSig,
	})

	// Merkle tree: leaf 0 is the client's nonce. With an extra leaf, the client's
	// PATH is the sibling and index 0.
	var root, path []byte
	index := uint32(0)
	if extraLeaf == nil {
		root = hashLeaf(nonce)
	} else {
		sibling := hashLeaf(extraLeaf)
		root = hashNode(hashLeaf(nonce), sibling)
		path = sibling
	}

	srep := encodeRoughtimeMessage(map[uint32][]byte{
		tagROOT: root,
		tagMIDP: le64(midMicros),
		tagRADI: le32(radius),
	})
	sig := ed25519.Sign(r.delePriv, append([]byte(roughtimeResponseContext), srep...))

	return encodeRoughtimeMessage(map[uint32][]byte{
		tagSIG:  sig,
		tagPATH: path,
		tagSREP: srep,
		tagCERT: cert,
		tagINDX: le32(index),
		tagNONC: nonce,
	})
}

func TestRoughtimeVerifyHappyPath(t *testing.T) {
	mid := uint64(1_700_000_000_000_000) // 2023-11-14T22:13:20Z in microseconds
	r := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	nonce := randomNonce(t)

	resp := r.respond(nonce, mid, 1000, nil)
	got, radius, err := verifyRoughtimeResponse(resp, nonce, r.rootPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := microsToTime(mid)
	if !got.Equal(want) {
		t.Fatalf("midpoint = %v, want %v", got, want)
	}
	if radius != time.Millisecond {
		t.Fatalf("radius = %v, want 1ms", radius)
	}
}

func TestRoughtimeVerifyMerklePath(t *testing.T) {
	mid := uint64(1_700_000_000_000_000)
	r := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	nonce := randomNonce(t)
	other := randomNonce(t)

	resp := r.respond(nonce, mid, 0, other)
	if _, _, err := verifyRoughtimeResponse(resp, nonce, r.rootPub); err != nil {
		t.Fatalf("verify with non-empty Merkle path: %v", err)
	}
}

func TestRoughtimeRejectsWrongNonce(t *testing.T) {
	mid := uint64(1_700_000_000_000_000)
	r := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	nonce := randomNonce(t)
	resp := r.respond(nonce, mid, 0, nil)

	if _, _, err := verifyRoughtimeResponse(resp, randomNonce(t), r.rootPub); err == nil {
		t.Fatal("verify accepted a response for a different nonce")
	}
}

func TestRoughtimeRejectsWrongLongTermKey(t *testing.T) {
	mid := uint64(1_700_000_000_000_000)
	r := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	nonce := randomNonce(t)
	resp := r.respond(nonce, mid, 0, nil)

	attackerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := verifyRoughtimeResponse(resp, nonce, attackerPub); err == nil {
		t.Fatal("verify accepted a response under the wrong long-term key")
	}
}

func TestRoughtimeRejectsTamperedMidpoint(t *testing.T) {
	mid := uint64(1_700_000_000_000_000)
	r := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	nonce := randomNonce(t)
	resp := r.respond(nonce, mid, 0, nil)

	// Flip a byte somewhere in the response: the Ed25519 signatures cover the
	// SREP/CERT bytes, so any mutation must be rejected.
	tampered := append([]byte(nil), resp...)
	tampered[len(tampered)/2] ^= 0x01
	if _, _, err := verifyRoughtimeResponse(tampered, nonce, r.rootPub); err == nil {
		t.Fatal("verify accepted a tampered response")
	}
}

func TestRoughtimeRejectsMidpointOutsideDelegation(t *testing.T) {
	mid := uint64(1_700_000_000_000_000)
	// Delegation window ends before the midpoint: the delegated key was not valid
	// at the claimed time, so the response must be rejected.
	r := newRoughtimeResponder(t, mid-2_000_000, mid-1_000_000)
	nonce := randomNonce(t)
	resp := r.respond(nonce, mid, 0, nil)

	if _, _, err := verifyRoughtimeResponse(resp, nonce, r.rootPub); err == nil {
		t.Fatal("verify accepted a midpoint outside the delegation validity window")
	}
}

func TestRoughtimeMessageRoundTrip(t *testing.T) {
	in := map[uint32][]byte{
		tagNONC: []byte("0123456789abcdef0123456789abcdef"),
		tagMIDP: le64(42),
		tagSIG:  make([]byte, ed25519.SignatureSize),
	}
	encoded := encodeRoughtimeMessage(in)
	out, err := decodeRoughtimeMessage(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for tag, want := range in {
		if got, ok := out[tag]; !ok || string(got) != string(want) {
			t.Fatalf("tag %#x round-trip mismatch: got %x ok=%v", tag, got, ok)
		}
	}
}

func TestDecodeEd25519PublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// base64 std, base64 raw, and hex must all decode to the same key.
	for _, enc := range []string{
		b64Std(pub), b64Raw(pub), hexStr(pub),
	} {
		got, err := decodeEd25519PublicKey(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if string(got) != string(pub) {
			t.Fatalf("decoded key mismatch for %q", enc)
		}
	}
	if _, err := decodeEd25519PublicKey("not-a-key"); err == nil {
		t.Fatal("expected error decoding garbage")
	}
	if _, err := decodeEd25519PublicKey(hexStr([]byte{1, 2, 3})); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, roughtimeNonceLen)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	return n
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func b64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64Raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func hexStr(b []byte) string { return hex.EncodeToString(b) }
