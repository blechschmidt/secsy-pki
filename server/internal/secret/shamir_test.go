package secret

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func cryptoRand(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// TestShamirRoundTripAllQuorums checks that every combination of exactly the
// threshold number of shares reconstructs the secret, for a range of (n, k).
func TestShamirRoundTripAllQuorums(t *testing.T) {
	secret := bytes.Repeat([]byte{0}, dekSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ n, k int }{{2, 2}, {3, 2}, {5, 3}, {7, 4}, {10, 6}} {
		shares, err := shamirSplit(secret, tc.n, tc.k, cryptoRand)
		if err != nil {
			t.Fatalf("split n=%d k=%d: %v", tc.n, tc.k, err)
		}
		if len(shares) != tc.n {
			t.Fatalf("got %d shares, want %d", len(shares), tc.n)
		}
		// Every k-subset (using the first k as a representative plus a rotated set)
		// must reconstruct.
		for start := 0; start <= tc.n-tc.k; start++ {
			subset := shares[start : start+tc.k]
			got, err := shamirCombine(subset)
			if err != nil {
				t.Fatalf("combine n=%d k=%d start=%d: %v", tc.n, tc.k, start, err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("n=%d k=%d start=%d: reconstructed mismatch", tc.n, tc.k, start)
			}
		}
	}
}

// TestShamirSubQuorumWrong verifies that combining fewer than threshold shares
// does not reproduce the secret. (It returns some value, but must not equal the
// real secret except with negligible probability.)
func TestShamirSubQuorumWrong(t *testing.T) {
	secret := []byte("a-256-bit-data-encryption-key!!!")
	if len(secret) != dekSize {
		t.Fatalf("test secret must be %d bytes", dekSize)
	}
	shares, err := shamirSplit(secret, 5, 3, cryptoRand)
	if err != nil {
		t.Fatal(err)
	}
	// Two of three required shares.
	got, err := shamirCombine(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("a sub-quorum (2 of 3) reconstructed the secret; Shamir security violated")
	}
}

// TestShamirDeterministicShares ensures shares interpolate to the same secret
// regardless of which quorum members are chosen, including non-contiguous sets.
func TestShamirNonContiguousQuorum(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, dekSize)
	shares, err := shamirSplit(secret, 6, 3, cryptoRand)
	if err != nil {
		t.Fatal(err)
	}
	pick := []shamirShare{shares[0], shares[3], shares[5]}
	got, err := shamirCombine(pick)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("non-contiguous quorum failed to reconstruct")
	}
}

func TestShamirRejectsBadParams(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, dekSize)
	if _, err := shamirSplit(secret, 3, 1, cryptoRand); err == nil {
		t.Error("threshold 1 must be rejected (no dual control)")
	}
	if _, err := shamirSplit(secret, 2, 3, cryptoRand); err == nil {
		t.Error("parts < threshold must be rejected")
	}
	if _, err := shamirSplit(nil, 3, 2, cryptoRand); err == nil {
		t.Error("empty secret must be rejected")
	}
}

func TestShamirCombineRejectsDuplicateAndZeroX(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, dekSize)
	shares, err := shamirSplit(secret, 3, 2, cryptoRand)
	if err != nil {
		t.Fatal(err)
	}
	dup := []shamirShare{shares[0], shares[0]}
	if _, err := shamirCombine(dup); err == nil {
		t.Error("duplicate x-coordinate must be rejected")
	}
	zeroX := []shamirShare{{X: 0, Y: shares[0].Y}, shares[1]}
	if _, err := shamirCombine(zeroX); err == nil {
		t.Error("zero x-coordinate must be rejected")
	}
}

// TestGFFieldArithmetic sanity-checks the field: a*inv(a)=1 for all non-zero a.
func TestGFFieldArithmetic(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := gfMul(byte(a), gfInv(byte(a))); got != 1 {
			t.Fatalf("a=%d: a*inv(a)=%d, want 1", a, got)
		}
	}
}
