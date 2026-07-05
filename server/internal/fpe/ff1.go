// Package fpe implements NIST SP 800-38G format-preserving encryption (FF1)
// over configurable alphabets, plus the symbol<->numeral codec that adapts real
// data (digits, alphanumerics, custom character sets) to the numeral strings
// FF1 operates on.
//
// FF1 is a 10-round, AES-based Feistel network that enciphers a string of
// numerals into another string of the SAME length over the SAME radix, so a
// 16-digit card number encrypts to 16 digits and a legacy system that validates
// format keeps working. It is deterministic in (key, tweak, plaintext): the same
// inputs always yield the same output, which is what makes convergent
// tokenization (equality search / de-duplication on protected fields) possible.
//
// This package is deliberately self-contained and side-effect free — it holds no
// keys at rest and performs no I/O — so it can be validated directly against the
// published NIST FF1 sample vectors (see ff1_test.go). The HSM/KEK-derived key
// material and the request-time policy live one layer up in internal/secret.
package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	// MinRadix and MaxRadix bound the alphabet size FF1 supports (SP 800-38G
	// §5.2: 2 <= radix < 2^16).
	MinRadix = 2
	MaxRadix = 1 << 16

	// feistelRounds is fixed at 10 by the FF1 standard.
	feistelRounds = 10

	// minDomain is the minimum domain size radix^len required by SP 800-38G
	// (§5.2, and the corrected security bound): radix^minlen must be at least
	// 1,000,000 so the message space is large enough for the cipher to be secure.
	minDomain = 1_000_000
)

// FF1 is a configured FF1 cipher: an AES block cipher keyed once and a radix. It
// is safe for concurrent use — every operation keeps its Feistel state on the
// stack and the AES cipher.Block is stateless across Encrypt calls.
type FF1 struct {
	block cipher.Block
	radix int
}

// NewFF1 constructs an FF1 cipher over radix using the AES key (16, 24, or 32
// bytes selecting AES-128/192/256). The radix must be in [MinRadix, MaxRadix].
func NewFF1(key []byte, radix int) (*FF1, error) {
	if radix < MinRadix || radix > MaxRadix {
		return nil, fmt.Errorf("fpe: radix %d out of range [%d,%d]", radix, MinRadix, MaxRadix)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fpe: invalid AES key: %w", err)
	}
	return &FF1{block: block, radix: radix}, nil
}

// Radix returns the cipher's radix.
func (f *FF1) Radix() int { return f.radix }

// MinLen returns the smallest numeral-string length whose domain radix^len meets
// the SP 800-38G minimum of 1,000,000, but never less than 2 (FF1 requires at
// least two numerals so the Feistel split is non-trivial).
func MinLen(radix int) int {
	n := 2
	dom := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(n)), nil)
	min := big.NewInt(minDomain)
	step := big.NewInt(int64(radix))
	for dom.Cmp(min) < 0 {
		n++
		dom.Mul(dom, step)
	}
	return n
}

// Encrypt enciphers the numeral string x (each numeral in [0,radix)) under tweak,
// returning a numeral string of the same length. It fails if the length is below
// the SP 800-38G minimum for the radix or a numeral is out of range.
func (f *FF1) Encrypt(tweak []byte, x []uint16) ([]uint16, error) {
	return f.feistel(tweak, x, true)
}

// Decrypt is the inverse of Encrypt for the same key and tweak.
func (f *FF1) Decrypt(tweak []byte, x []uint16) ([]uint16, error) {
	return f.feistel(tweak, x, false)
}

// feistel runs the FF1 Feistel network (SP 800-38G Algorithms 7 & 8). encrypt
// selects the round ordering and the add/subtract direction; the two directions
// are otherwise identical, so sharing the body keeps them provably inverse.
func (f *FF1) feistel(tweak []byte, input []uint16, encrypt bool) ([]uint16, error) {
	radix := f.radix
	n := len(input)
	if err := f.validateLen(n); err != nil {
		return nil, err
	}
	for _, d := range input {
		if int(d) >= radix {
			return nil, fmt.Errorf("fpe: numeral %d out of range for radix %d", d, radix)
		}
	}

	t := len(tweak)
	u := n / 2
	v := n - u
	// A and B are the two halves; copy so the caller's slice is untouched.
	A := append([]uint16(nil), input[:u]...)
	B := append([]uint16(nil), input[u:]...)

	radixBig := big.NewInt(int64(radix))

	// b = ceil(ceil(v*log2(radix))/8). ceil(v*log2(radix)) is the bit length of
	// radix^v, computed exactly via big integers (bitLen(radix^v - 1)) to avoid
	// floating-point rounding at the boundaries.
	powV := new(big.Int).Exp(radixBig, big.NewInt(int64(v)), nil)
	minBits := new(big.Int).Sub(powV, big.NewInt(1)).BitLen()
	b := (minBits + 7) / 8
	// d = 4*ceil(b/4) + 4.
	d := 4*((b+3)/4) + 4

	// P is the fixed 16-byte prefix block (SP 800-38G step 5).
	P := make([]byte, 16)
	P[0], P[1], P[2] = 1, 2, 1
	P[3] = byte(radix >> 16)
	P[4] = byte(radix >> 8)
	P[5] = byte(radix)
	P[6] = 10
	P[7] = byte(u) // u mod 256
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	// padLen zero-pads Q so that len(T || pad || [i] || [NUM(...)]_b) is a
	// multiple of 16 (P is already one block); ((-t-b-1) mod 16), non-negative.
	padLen := ((-t-b-1)%16 + 16) % 16

	for round := 0; round < feistelRounds; round++ {
		i := round
		if !encrypt {
			i = feistelRounds - 1 - round
		}

		// Encrypt folds NUM(B) into A; decrypt folds NUM(A) into B (the inverse).
		src, dst := B, A
		if !encrypt {
			src, dst = A, B
		}

		// Q = T || [0]^padLen || [i] || [NUM_radix(src)]^b, then R = PRF(P||Q).
		q := make([]byte, 0, t+padLen+1+b)
		q = append(q, tweak...)
		q = append(q, make([]byte, padLen)...)
		q = append(q, byte(i))
		q = appendUintBytes(q, numeralValue(src, radixBig), b)
		R := f.prf(P, q)

		// S = first d bytes of R || CIPH(R^1) || CIPH(R^2) || ...; y = NUM(S).
		y := new(big.Int).SetBytes(f.generateS(R, d))

		m := u
		if i%2 != 0 {
			m = v
		}
		modulus := new(big.Int).Exp(radixBig, big.NewInt(int64(m)), nil)

		c := numeralValue(dst, radixBig)
		if encrypt {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}
		c.Mod(c, modulus)
		C := numeralString(c, radix, m)

		// Rotate the halves. Encrypt: A=B, B=C. Decrypt: B=A, A=C.
		if encrypt {
			A, B = B, C
		} else {
			A, B = C, A
		}
	}

	out := make([]uint16, 0, n)
	out = append(out, A...)
	out = append(out, B...)
	return out, nil
}

// validateLen enforces the FF1 domain requirement for the cipher's radix.
func (f *FF1) validateLen(n int) error {
	if n < 2 {
		return errors.New("fpe: input must have at least 2 numerals")
	}
	if uint64(n) > uint64(^uint32(0)) {
		return fmt.Errorf("fpe: input length %d exceeds the FF1 maximum", n)
	}
	if minLen := MinLen(f.radix); n < minLen {
		return fmt.Errorf("fpe: input length %d is below the minimum %d for radix %d (domain radix^len must be >= %d)", n, minLen, f.radix, minDomain)
	}
	return nil
}

// prf is the FF1 pseudorandom function: CBC-MAC over P||Q (a multiple of 16
// bytes) under the AES key with a zero IV, returning the final 16-byte block.
func (f *FF1) prf(p, q []byte) []byte {
	y := make([]byte, 16)
	blk := make([]byte, 16)
	feed := func(chunk []byte) {
		for off := 0; off < len(chunk); off += 16 {
			for j := 0; j < 16; j++ {
				blk[j] = y[j] ^ chunk[off+j]
			}
			f.block.Encrypt(y, blk)
		}
	}
	feed(p)
	feed(q)
	return y
}

// generateS derives the d-byte value string S from R by encrypting R XORed with
// an incrementing 16-byte counter, per SP 800-38G: S is the first d bytes of
// R || CIPH(R^[1]) || CIPH(R^[2]) || ...
func (f *FF1) generateS(R []byte, d int) []byte {
	s := make([]byte, 0, ((d+15)/16)*16)
	s = append(s, R...)
	var ctr, blk [16]byte
	for j := uint32(1); len(s) < d; j++ {
		binary.BigEndian.PutUint32(ctr[12:16], j)
		for k := 0; k < 16; k++ {
			blk[k] = R[k] ^ ctr[k]
		}
		enc := make([]byte, 16)
		f.block.Encrypt(enc, blk[:])
		s = append(s, enc...)
	}
	return s[:d]
}

// numeralValue returns NUM_radix(x): the integer a big-endian numeral string
// represents in base radix (x[0] is the most significant numeral).
func numeralValue(x []uint16, radix *big.Int) *big.Int {
	acc := new(big.Int)
	for _, d := range x {
		acc.Mul(acc, radix)
		acc.Add(acc, big.NewInt(int64(d)))
	}
	return acc
}

// numeralString returns STR_m_radix(v): the m-numeral big-endian representation
// of v in base radix (index 0 most significant). v must be in [0, radix^m).
func numeralString(v *big.Int, radix, m int) []uint16 {
	out := make([]uint16, m)
	r := big.NewInt(int64(radix))
	tmp := new(big.Int).Set(v)
	rem := new(big.Int)
	for j := m - 1; j >= 0; j-- {
		tmp.DivMod(tmp, r, rem)
		out[j] = uint16(rem.Int64())
	}
	return out
}

// appendUintBytes appends v as a big-endian byte string left-padded (or, only in
// pathological cases, truncated) to exactly width bytes.
func appendUintBytes(dst []byte, v *big.Int, width int) []byte {
	raw := v.Bytes()
	if len(raw) > width {
		raw = raw[len(raw)-width:]
	}
	dst = append(dst, make([]byte, width-len(raw))...)
	return append(dst, raw...)
}
