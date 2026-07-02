package secret

// Shamir's Secret Sharing over GF(2^8) (the AES field, reduction polynomial
// x^8 + x^4 + x^3 + x + 1 = 0x11b). A secret is split byte-wise into N shares
// such that any K of them reconstruct it and any K-1 reveal nothing (in the
// information-theoretic sense). This is the mathematical core of the M-of-N key
// escrow: the 256-bit data-encryption key is split into N shares, one handed to
// each recovery agent (wrapped to that agent's key), and a quorum of K agents
// is required to reconstruct it.
//
// The implementation is deliberately small and dependency-free. Field
// multiplication uses the classic "Russian peasant" carry-less multiply with
// reduction; inversion uses precomputed exp/log tables. None of these operations
// are secret-dependent in their control flow.

// gfMul multiplies two GF(2^8) elements.
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // reduction by the low bits of 0x11b
		}
		b >>= 1
	}
	return p
}

// gfExp and gfLog are the exponential/logarithm tables for the field, built from
// the primitive element 0x03. gfExp[i] = 0x03^i; gfLog is its inverse. They are
// used only for inversion (and thus division); multiplication uses gfMul.
var (
	gfExp [256]byte
	gfLog [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		x = gfMul(x, 0x03)
	}
	// gfExp[255] duplicates gfExp[0]; the (mod 255) index arithmetic never reads
	// it, but set it for completeness.
	gfExp[255] = gfExp[0]
}

// gfInv returns the multiplicative inverse of a non-zero field element. gfInv(0)
// is defined as 0 (0 has no inverse; callers never divide by a zero denominator
// because share x-coordinates are distinct and non-zero).
func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// gfDiv returns a / b in the field. b must be non-zero.
func gfDiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// shamirShare is one share of a split secret: an x-coordinate (1..255, distinct
// and non-zero) and the polynomial evaluations at that x for each secret byte.
type shamirShare struct {
	X byte
	Y []byte
}

// bytes serializes a share as X followed by its Y values, the form that is
// wrapped to a recovery agent's key.
func (s shamirShare) bytes() []byte {
	out := make([]byte, 0, len(s.Y)+1)
	out = append(out, s.X)
	out = append(out, s.Y...)
	return out
}

// parseShamirShare reverses shamirShare.bytes. It rejects a zero x-coordinate
// (f(0) is the secret itself) and an empty share.
func parseShamirShare(b []byte) (shamirShare, error) {
	if len(b) < 2 {
		return shamirShare{}, errShareMalformed
	}
	if b[0] == 0 {
		return shamirShare{}, errShareZeroX
	}
	y := make([]byte, len(b)-1)
	copy(y, b[1:])
	return shamirShare{X: b[0], Y: y}, nil
}

// shamirSplit splits secret into parts shares with the given reconstruction
// threshold. randRead supplies the random polynomial coefficients (crypto/rand
// in production; a deterministic reader in tests). It requires
// 2 <= threshold <= parts <= 255.
func shamirSplit(secret []byte, parts, threshold int, randRead func([]byte) error) ([]shamirShare, error) {
	if threshold < 2 {
		return nil, errThresholdTooLow
	}
	if parts < threshold {
		return nil, errPartsBelowThreshold
	}
	if parts > 255 {
		return nil, errTooManyParts
	}
	if len(secret) == 0 {
		return nil, errEmptySecret
	}

	// Distinct, non-zero x-coordinates 1..parts.
	shares := make([]shamirShare, parts)
	for i := range shares {
		shares[i] = shamirShare{X: byte(i + 1), Y: make([]byte, len(secret))}
	}

	// For each secret byte, pick a random degree-(threshold-1) polynomial whose
	// constant term is that byte, then evaluate it at every share's x.
	coeffs := make([]byte, threshold)
	for b := 0; b < len(secret); b++ {
		coeffs[0] = secret[b]
		if err := randRead(coeffs[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			shares[i].Y[b] = gfEval(coeffs, shares[i].X)
		}
	}
	return shares, nil
}

// gfEval evaluates the polynomial with the given coefficients (coeffs[0] is the
// constant term) at x, using Horner's method in the field.
func gfEval(coeffs []byte, x byte) byte {
	var out byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		out = gfMul(out, x) ^ coeffs[i]
	}
	return out
}

// shamirCombine reconstructs the secret from a set of shares via Lagrange
// interpolation at x = 0. It requires at least two shares with distinct
// x-coordinates and equal Y lengths; supplying fewer than the original
// threshold yields a wrong (but structurally valid) result, so callers must
// enforce the quorum before trusting the output.
func shamirCombine(shares []shamirShare) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errTooFewShares
	}
	secretLen := len(shares[0].Y)
	if secretLen == 0 {
		return nil, errShareMalformed
	}
	seenX := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if s.X == 0 {
			return nil, errShareZeroX
		}
		if len(s.Y) != secretLen {
			return nil, errShareLengthMismatch
		}
		if seenX[s.X] {
			return nil, errShareDuplicateX
		}
		seenX[s.X] = true
	}

	secret := make([]byte, secretLen)
	for b := 0; b < secretLen; b++ {
		var acc byte
		for i := range shares {
			// Lagrange basis at x=0: prod_{j!=i} x_j / (x_i XOR x_j).
			num := byte(1)
			den := byte(1)
			for j := range shares {
				if i == j {
					continue
				}
				num = gfMul(num, shares[j].X)
				den = gfMul(den, shares[i].X^shares[j].X)
			}
			acc ^= gfMul(shares[i].Y[b], gfDiv(num, den))
		}
		secret[b] = acc
	}
	return secret, nil
}
