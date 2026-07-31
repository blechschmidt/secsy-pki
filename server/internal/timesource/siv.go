package timesource

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// AES-SIV (RFC 5297) with AES-CMAC (RFC 4493) is the mandatory-to-implement AEAD
// for NTS (RFC 8915 §5.1, AEAD_AES_SIV_CMAC_256). Go's standard library has
// neither CMAC nor SIV, so both are implemented here. The primitive is a
// deterministic, nonce-misuse-resistant AEAD: it authenticates a vector of
// associated-data strings (in NTS: the NTP packet header/extension fields plus a
// per-message nonce) alongside the ciphertext.
//
// This file is self-tested against the RFC 5297 Appendix A.1 test vector
// (siv_test.go), which exercises CMAC, S2V dbl/xor, and CTR end to end.

// rb is the CMAC/SIV doubling constant for a 128-bit block (RFC 4493 §2.3).
const rb = 0x87

// aesSIV is an AES-SIV AEAD instance. The key is split in half: the first half
// keys S2V (CMAC), the second half keys CTR. For AEAD_AES_SIV_CMAC_256 the key
// is 32 bytes and each half is an AES-128 key.
type aesSIV struct {
	macBlock cipher.Block // S2V / CMAC key (K1)
	ctrBlock cipher.Block // CTR key (K2)
}

// newAESSIV constructs an AES-SIV instance. The key must be 32 bytes
// (AEAD_AES_SIV_CMAC_256) or 64 bytes (AEAD_AES_SIV_CMAC_512).
func newAESSIV(key []byte) (*aesSIV, error) {
	if len(key) != 32 && len(key) != 64 {
		return nil, fmt.Errorf("aes-siv: key must be 32 or 64 bytes, got %d", len(key))
	}
	half := len(key) / 2
	macBlock, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, err
	}
	ctrBlock, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, err
	}
	return &aesSIV{macBlock: macBlock, ctrBlock: ctrBlock}, nil
}

// Overhead is the SIV tag size prepended to every ciphertext.
const sivTagSize = aes.BlockSize

// Seal encrypts plaintext and authenticates it together with the associated-data
// strings, returning V||ciphertext where V is the 16-byte synthetic IV/tag. The
// associated-data vector is processed in order (RFC 5297 §2.6).
func (s *aesSIV) Seal(plaintext []byte, associatedData ...[]byte) ([]byte, error) {
	v := s.s2v(associatedData, plaintext)
	out := make([]byte, len(v)+len(plaintext))
	copy(out, v)
	s.ctr(v, plaintext, out[len(v):])
	return out, nil
}

// Open authenticates and decrypts a V||ciphertext blob against the associated-
// data strings, returning the plaintext. It fails when the recomputed synthetic
// IV does not match, in constant time.
func (s *aesSIV) Open(sealed []byte, associatedData ...[]byte) ([]byte, error) {
	if len(sealed) < sivTagSize {
		return nil, errors.New("aes-siv: ciphertext too short")
	}
	v := sealed[:sivTagSize]
	ciphertext := sealed[sivTagSize:]
	plaintext := make([]byte, len(ciphertext))
	s.ctr(v, ciphertext, plaintext)

	expected := s.s2v(associatedData, plaintext)
	if subtle.ConstantTimeCompare(expected, v) != 1 {
		return nil, errors.New("aes-siv: authentication failed")
	}
	return plaintext, nil
}

// ctr runs AES-CTR keyed by ctrBlock with the SIV-derived counter: V with the
// two "reserved" bits (bit 31 and 63 from the right) cleared (RFC 5297 §2.6).
func (s *aesSIV) ctr(v, in, out []byte) {
	var iv [aes.BlockSize]byte
	copy(iv[:], v)
	iv[8] &= 0x7f
	iv[12] &= 0x7f
	cipher.NewCTR(s.ctrBlock, iv[:]).XORKeyStream(out, in)
}

// s2v implements S2V (RFC 5297 §2.4): it folds the associated-data vector and
// the plaintext into a single 16-byte synthetic value via CMAC and doubling.
func (s *aesSIV) s2v(ad [][]byte, plaintext []byte) []byte {
	// With no associated data and empty plaintext, S2V(<>) = CMAC(1).
	if len(ad) == 0 && len(plaintext) == 0 {
		one := make([]byte, aes.BlockSize)
		one[len(one)-1] = 1
		return s.cmac(one)
	}

	zero := make([]byte, aes.BlockSize)
	d := s.cmac(zero)
	for _, a := range ad {
		d = xor(dbl(d), s.cmac(a))
	}

	var t []byte
	if len(plaintext) >= aes.BlockSize {
		// T = plaintext with D xored into its final block ("xorend").
		t = make([]byte, len(plaintext))
		copy(t, plaintext)
		off := len(t) - aes.BlockSize
		for i := 0; i < aes.BlockSize; i++ {
			t[off+i] ^= d[i]
		}
	} else {
		t = xor(dbl(d), pad(plaintext))
	}
	return s.cmac(t)
}

// cmac computes AES-CMAC (RFC 4493) over msg with the MAC key.
func (s *aesSIV) cmac(msg []byte) []byte {
	k1, k2 := s.cmacSubkeys()

	n := (len(msg) + aes.BlockSize - 1) / aes.BlockSize
	lastComplete := false
	if n == 0 {
		n = 1
	} else {
		lastComplete = len(msg)%aes.BlockSize == 0
	}

	var lastBlock [aes.BlockSize]byte
	if lastComplete {
		copy(lastBlock[:], msg[(n-1)*aes.BlockSize:])
		for i := range lastBlock {
			lastBlock[i] ^= k1[i]
		}
	} else {
		padded := pad(msg[(n-1)*aes.BlockSize:])
		for i := range lastBlock {
			lastBlock[i] = padded[i] ^ k2[i]
		}
	}

	var x [aes.BlockSize]byte
	var y [aes.BlockSize]byte
	for i := 0; i < n-1; i++ {
		block := msg[i*aes.BlockSize : (i+1)*aes.BlockSize]
		for j := range y {
			y[j] = x[j] ^ block[j]
		}
		s.macBlock.Encrypt(x[:], y[:])
	}
	for j := range y {
		y[j] = x[j] ^ lastBlock[j]
	}
	s.macBlock.Encrypt(x[:], y[:])
	out := make([]byte, aes.BlockSize)
	copy(out, x[:])
	return out
}

// cmacSubkeys derives the CMAC subkeys K1/K2 from L = AES(0) (RFC 4493 §2.3).
func (s *aesSIV) cmacSubkeys() (k1, k2 []byte) {
	l := make([]byte, aes.BlockSize)
	s.macBlock.Encrypt(l, l)
	k1 = dbl(l)
	k2 = dbl(k1)
	return k1, k2
}

// dbl doubles a 128-bit big-endian value in GF(2^128) (RFC 5297 §2.3).
func dbl(b []byte) []byte {
	out := make([]byte, len(b))
	var carry byte
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if carry != 0 || b[0]&0x80 != 0 {
		out[len(out)-1] ^= rb
	}
	return out
}

// xor returns a XOR b, truncated to the shorter length.
func xor(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// pad applies the 10* padding to a sub-block-sized string (RFC 4493 §2.4).
func pad(b []byte) []byte {
	out := make([]byte, aes.BlockSize)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

// be64 is a small helper used by the NTS timestamp math to read NTP timestamps.
func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }
