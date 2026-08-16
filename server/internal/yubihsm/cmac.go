package yubihsm

import (
	"crypto/cipher"
	"crypto/subtle"
)

// AES-CMAC (RFC 4493 / NIST SP 800-38B).
//
// SCP03 uses CMAC for three separate jobs — session-key derivation, command
// authentication, and response authentication — so the secure channel cannot be
// built without it, and neither the standard library nor golang.org/x/crypto
// ships one. It is implemented here rather than pulled in as a dependency, in
// keeping with the other small primitives this codebase hand-rolls (AES-SIV for
// the NTS time source, FF1 for tokenization). The construction is short enough
// to state in full and is pinned by the RFC 4493 test vectors in cmac_test.go.

// cmacSubkeys derives the two CMAC subkeys K1 and K2 from the block cipher, per
// RFC 4493 section 2.3.
func cmacSubkeys(b cipher.Block) (k1, k2 []byte) {
	n := b.BlockSize()
	l := make([]byte, n)
	b.Encrypt(l, make([]byte, n))
	k1 = shiftLeftXorRb(l)
	k2 = shiftLeftXorRb(k1)
	return k1, k2
}

// rb is the constant from RFC 4493 for a 128-bit block: the low byte of the
// irreducible polynomial x^128 + x^7 + x^2 + x + 1.
const rb = 0x87

// shiftLeftXorRb returns (in << 1), XORed with Rb when the shift overflowed.
func shiftLeftXorRb(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	// Constant-time conditional XOR: the branch would otherwise depend on a bit
	// of a value derived from the key.
	out[len(out)-1] ^= byte(subtle.ConstantTimeSelect(int(carry), rb, 0))
	return out
}

// cmacSum returns the full CMAC tag (one block wide) over msg.
func cmacSum(b cipher.Block, msg []byte) []byte {
	n := b.BlockSize()
	k1, k2 := cmacSubkeys(b)

	// Split off the final block, applying the appropriate subkey. An empty
	// message is treated as a single padded block, which is why the complete-block
	// case additionally requires a non-empty message.
	var last []byte
	var head []byte
	if len(msg) > 0 && len(msg)%n == 0 {
		head = msg[:len(msg)-n]
		last = xorBytes(msg[len(msg)-n:], k1)
	} else {
		head = msg[:len(msg)-len(msg)%n]
		tail := msg[len(head):]
		padded := make([]byte, n)
		copy(padded, tail)
		padded[len(tail)] = 0x80
		last = xorBytes(padded, k2)
	}

	x := make([]byte, n)
	block := make([]byte, n)
	for off := 0; off < len(head); off += n {
		copy(block, xorBytes(x, head[off:off+n]))
		b.Encrypt(x, block)
	}
	b.Encrypt(x, xorBytes(x, last))
	return x
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
