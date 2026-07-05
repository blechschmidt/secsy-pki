package fpe

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST FF1 sample vectors, from the NIST "FF1samples.pdf" example set that
// accompanies SP 800-38G. Each vector fixes the AES key, radix, tweak, and a
// numeral string, with the expected ciphertext numerals. These are the
// authoritative known-answer tests: a correct FF1 must reproduce them exactly.
var ff1Vectors = []struct {
	name   string
	keyHex string
	radix  int
	tweak  string // hex
	pt     []uint16
	ctNum  []uint16
}{
	{
		name:   "NIST-1/AES-128/radix10/no-tweak",
		keyHex: "2b7e151628aed2a6abf7158809cf4f3c",
		radix:  10,
		tweak:  "",
		pt:     []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		ctNum:  []uint16{2, 4, 3, 3, 4, 7, 7, 4, 8, 4},
	},
	{
		name:   "NIST-2/AES-128/radix10/tweak",
		keyHex: "2b7e151628aed2a6abf7158809cf4f3c",
		radix:  10,
		tweak:  "39383736353433323130",
		pt:     []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		ctNum:  []uint16{6, 1, 2, 4, 2, 0, 0, 7, 7, 3},
	},
	{
		name:   "NIST-3/AES-128/radix36/tweak",
		keyHex: "2b7e151628aed2a6abf7158809cf4f3c",
		radix:  36,
		tweak:  "3737373770717273373737",
		// "0123456789abcdefghi" in base-36 (0-9 then a=10..i=18)
		pt: []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
		// "a9tv40mll9kdu509eum"
		ctNum: []uint16{10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22},
	},
	{
		name:   "NIST-7/AES-256/radix10/no-tweak",
		keyHex: "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94",
		radix:  10,
		tweak:  "",
		pt:     []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		ctNum:  []uint16{6, 6, 5, 7, 6, 6, 7, 0, 0, 9},
	},
	{
		name:   "NIST-8/AES-256/radix10/tweak",
		keyHex: "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94",
		radix:  10,
		tweak:  "39383736353433323130",
		pt:     []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		ctNum:  []uint16{1, 0, 0, 1, 6, 2, 3, 4, 6, 3},
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func numEq(a, b []uint16) bool {
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

// TestFF1NISTVectors checks encryption AND decryption against the published NIST
// sample vectors: FF1.Encrypt must produce the exact ciphertext and FF1.Decrypt
// must recover the exact plaintext.
func TestFF1NISTVectors(t *testing.T) {
	for _, v := range ff1Vectors {
		t.Run(v.name, func(t *testing.T) {
			f, err := NewFF1(mustHex(t, v.keyHex), v.radix)
			if err != nil {
				t.Fatalf("NewFF1: %v", err)
			}
			tweak := mustHex(t, v.tweak)
			got, err := f.Encrypt(tweak, v.pt)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !numEq(got, v.ctNum) {
				t.Fatalf("ciphertext mismatch\n got %v\nwant %v", got, v.ctNum)
			}
			back, err := f.Decrypt(tweak, v.ctNum)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !numEq(back, v.pt) {
				t.Fatalf("decrypt mismatch\n got %v\nwant %v", back, v.pt)
			}
		})
	}
}

// TestFF1AlphabetVectors re-runs the alphanumeric-lower vector through the codec
// so the symbol<->numeral mapping is exercised end-to-end at string level.
func TestFF1AlphabetVectors(t *testing.T) {
	a, err := ResolveAlphabet("alphanumeric-lower")
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFF1(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"), a.Radix())
	if err != nil {
		t.Fatal(err)
	}
	tweak := mustHex(t, "3737373770717273373737")
	nums, err := a.ToNumerals("0123456789abcdefghi")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := f.Encrypt(tweak, nums)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.FromNumerals(ct); got != "a9tv40mll9kdu509eum" {
		t.Fatalf("alphabet ciphertext = %q, want a9tv40mll9kdu509eum", got)
	}
}

// TestFF1RoundTripAlphabets round-trips a fixed plaintext through every named
// alphabet at a length above its FF1 minimum, confirming Decrypt inverts Encrypt
// and that the ciphertext stays within the alphabet.
func TestFF1RoundTripAlphabets(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f")
	tweak := []byte("ctx-42")
	for _, name := range NamedAlphabets() {
		t.Run(name, func(t *testing.T) {
			a, err := ResolveAlphabet(name)
			if err != nil {
				t.Fatal(err)
			}
			f, err := NewFF1(key, a.Radix())
			if err != nil {
				t.Fatal(err)
			}
			// Build a plaintext of MinLen numerals from the alphabet's symbols.
			n := MinLen(a.Radix())
			pt := make([]uint16, n)
			for i := range pt {
				pt[i] = uint16(i % a.Radix())
			}
			ct, err := f.Encrypt(tweak, pt)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(ct) != len(pt) {
				t.Fatalf("length not preserved: got %d want %d", len(ct), len(pt))
			}
			for _, d := range ct {
				if int(d) >= a.Radix() {
					t.Fatalf("ciphertext numeral %d out of radix %d", d, a.Radix())
				}
			}
			back, err := f.Decrypt(tweak, ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !numEq(back, pt) {
				t.Fatalf("round-trip mismatch: got %v want %v", back, pt)
			}
		})
	}
}

// TestFF1Deterministic confirms the cipher is a pure function of (key, tweak,
// plaintext): repeated encryption yields identical ciphertext (the property that
// makes convergent tokenization possible), while a different tweak diverges.
func TestFF1Deterministic(t *testing.T) {
	f, _ := NewFF1(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"), 10)
	pt := []uint16{4, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3}
	a, _ := f.Encrypt(nil, pt)
	b, _ := f.Encrypt(nil, pt)
	if !numEq(a, b) {
		t.Fatal("empty-tweak encryption is not deterministic")
	}
	c, _ := f.Encrypt([]byte("other"), pt)
	if numEq(a, c) {
		t.Fatal("different tweak produced identical ciphertext")
	}
}

// TestFF1DomainEnforced rejects inputs shorter than the SP 800-38G minimum.
func TestFF1DomainEnforced(t *testing.T) {
	f, _ := NewFF1(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"), 10)
	// radix 10 needs 6 numerals (10^6 == 1,000,000).
	if MinLen(10) != 6 {
		t.Fatalf("MinLen(10) = %d, want 6", MinLen(10))
	}
	if _, err := f.Encrypt(nil, []uint16{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("expected rejection of 5-numeral radix-10 input")
	}
	if _, err := f.Encrypt(nil, []uint16{1, 2, 3, 4, 5, 6}); err != nil {
		t.Fatalf("6-numeral input should be accepted: %v", err)
	}
}

// TestFF1RejectsBadNumeral rejects a numeral at or above the radix.
func TestFF1RejectsBadNumeral(t *testing.T) {
	f, _ := NewFF1(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"), 10)
	if _, err := f.Encrypt(nil, []uint16{0, 1, 2, 3, 4, 10}); err == nil {
		t.Fatal("expected rejection of numeral 10 for radix 10")
	}
}

// TestPRFMatchesKnownCBCMAC sanity-checks the PRF against a hand-computed
// AES-CBC-MAC of two zero blocks under the AES-128 test key, guarding the core
// primitive independently of the full Feistel network.
func TestPRFMatchesKnownCBCMAC(t *testing.T) {
	f, _ := NewFF1(mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c"), 10)
	// CBC-MAC(0^32) = AES(AES(0^16)) with a zero IV.
	zero := make([]byte, 16)
	got := f.prf(zero, zero)
	first := make([]byte, 16)
	f.block.Encrypt(first, zero)
	want := make([]byte, 16)
	f.block.Encrypt(want, first)
	if !bytes.Equal(got, want) {
		t.Fatalf("prf = %x, want %x", got, want)
	}
}
