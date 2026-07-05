package secret

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, MACSeedBytes)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return seed
}

// TestDeriveMACKeyDeterministicAndSeparated: derivation is a pure function of
// (seed, family, version) — stable across calls, but a different family or
// version yields an independent key so a tag can never cross-verify.
func TestDeriveMACKeyDeterministicAndSeparated(t *testing.T) {
	seed := testSeed(t)

	k1, err := DeriveMACKey(seed, "fam", 1)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(k1) != macKeyBytes {
		t.Fatalf("derived key length = %d, want %d", len(k1), macKeyBytes)
	}
	k1again, _ := DeriveMACKey(seed, "fam", 1)
	if !bytes.Equal(k1, k1again) {
		t.Error("derivation not deterministic for identical inputs")
	}

	kv2, _ := DeriveMACKey(seed, "fam", 2)
	if bytes.Equal(k1, kv2) {
		t.Error("different version produced the same key")
	}
	kOther, _ := DeriveMACKey(seed, "other", 1)
	if bytes.Equal(k1, kOther) {
		t.Error("different family produced the same key")
	}
}

// TestDeriveMACKeyValidation rejects malformed inputs.
func TestDeriveMACKeyValidation(t *testing.T) {
	if _, err := DeriveMACKey(make([]byte, 8), "fam", 1); err == nil {
		t.Error("short seed accepted")
	}
	if _, err := DeriveMACKey(testSeed(t), "fam", 0); err == nil {
		t.Error("non-positive version accepted")
	}
}

// TestComputeVerifyHMAC: VerifyHMAC accepts the matching tag and rejects any
// change to the data or the tag.
func TestComputeVerifyHMAC(t *testing.T) {
	key, _ := DeriveMACKey(testSeed(t), "fam", 1)
	data := []byte("the quick brown fox")

	mac := ComputeHMAC(key, data)
	if !VerifyHMAC(key, data, mac) {
		t.Fatal("matching tag did not verify")
	}
	if VerifyHMAC(key, []byte("the quick brown FOX"), mac) {
		t.Error("tag verified over altered data")
	}
	bad := append([]byte(nil), mac...)
	bad[0] ^= 0x01
	if VerifyHMAC(key, data, bad) {
		t.Error("altered tag verified")
	}
	// A key derived for a different version must not verify the tag.
	otherKey, _ := DeriveMACKey(testSeed(t), "fam", 1)
	if VerifyHMAC(otherKey, data, mac) {
		t.Error("tag verified under an unrelated key")
	}
}
