package fpe

import (
	"crypto/sha256"
	"testing"
)

// FuzzFF1RoundTrip fuzzes FF1 over several alphabets and tweaks: for any input
// that Encrypt accepts, Decrypt must recover it exactly and the ciphertext must
// preserve length and stay within the alphabet. The fuzzer drives the codec so
// arbitrary bytes are mapped into valid numeral strings first.
func FuzzFF1RoundTrip(f *testing.F) {
	// A deterministic 32-byte key derived from a label keeps runs reproducible.
	key := sha256.Sum256([]byte("fpe-fuzz-key"))

	f.Add("digits", "4111111111111111", "")
	f.Add("alphanumeric", "abc123XYZ789", "record-7")
	f.Add("hex-lower", "deadbeefcafef00d", "")
	f.Add("chars:ACGT", "ACGTACGTACGTAC", "seq")

	f.Fuzz(func(t *testing.T, alphabetSpec, raw, tweak string) {
		a, err := ResolveAlphabet(alphabetSpec)
		if err != nil {
			return // not a valid alphabet spec; nothing to test
		}
		f1, err := NewFF1(key[:], a.Radix())
		if err != nil {
			return
		}
		// Fold arbitrary input onto the alphabet so we always have a valid numeral
		// string, then require enough numerals to satisfy the FF1 domain minimum.
		runes := []rune(raw)
		n := len(runes)
		if n < MinLen(a.Radix()) {
			return
		}
		if n > 512 {
			runes = runes[:512] // keep the fuzz iteration bounded
		}
		nums := make([]uint16, len(runes))
		for i, r := range runes {
			nums[i] = uint16(uint32(r) % uint32(a.Radix()))
		}

		ct, err := f1.Encrypt([]byte(tweak), nums)
		if err != nil {
			t.Fatalf("Encrypt(len=%d radix=%d): %v", len(nums), a.Radix(), err)
		}
		if len(ct) != len(nums) {
			t.Fatalf("length changed: %d -> %d", len(nums), len(ct))
		}
		for _, d := range ct {
			if int(d) >= a.Radix() {
				t.Fatalf("ciphertext numeral %d escaped radix %d", d, a.Radix())
			}
		}
		back, err := f1.Decrypt([]byte(tweak), ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		for i := range nums {
			if back[i] != nums[i] {
				t.Fatalf("round-trip mismatch at %d: %d != %d", i, back[i], nums[i])
			}
		}
	})
}
