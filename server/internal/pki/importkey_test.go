package pki

// Key-type derivation for imported key material (Task 196).
//
// These run without a token because the property under test is a host-side one:
// what this PKI is willing to *call* a key, before any module sees it.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
)

// TestPrivateKeyTypeMatchesRSASizesExactly guards against rounding a modulus up
// to the next name.
//
// An earlier version reported any size in 2049..3072 as "rsa-3072" and anything
// larger as "rsa-4096". That string is not cosmetic: it is persisted on the CA
// record and reproduced in inventory listings and compliance exports, so a
// 2560-bit key described as "rsa-3072" overstates the modulus in every report
// derived from it — permanently, and with no later step positioned to notice.
//
// Rounding also bought nothing, because no backend here can hold the key: a
// YubiHSM has exactly three RSA algorithms, and the PKI has exactly three RSA
// key-type names. The only thing the rounding changed was *where* the operator
// found out, turning a sentence into CKR_ATTRIBUTE_VALUE_INVALID from the far
// side of a USB cable.
func TestPrivateKeyTypeMatchesRSASizesExactly(t *testing.T) {
	for _, bits := range SupportedRSABits {
		key := rsaKeyOfSize(t, bits)
		got, err := PrivateKeyType(key)
		if err != nil {
			t.Fatalf("RSA-%d: %v", bits, err)
		}
		if want := "rsa-" + itoa(bits); got != want {
			t.Errorf("RSA-%d reports %q, want %q", bits, got, want)
		}
	}

	// Sizes between and above the supported ones must be refused, and the
	// refusal has to name the actual size and the supported set — an operator
	// holding a key file needs to know which of the two to fix.
	for _, bits := range []int{2056, 2560, 3073, 8192} {
		key := rsaKeyOfSize(t, bits)
		_, err := PrivateKeyType(key)
		if err == nil {
			t.Errorf("RSA-%d was accepted; only %v are supported", bits, SupportedRSABits)
			continue
		}
		if !strings.Contains(err.Error(), itoa(bits)) {
			t.Errorf("RSA-%d rejection does not name the key's size: %v", bits, err)
		}
		if !strings.Contains(err.Error(), "2048, 3072, or 4096") {
			t.Errorf("RSA-%d rejection does not name the supported sizes: %v", bits, err)
		}
	}

	// Below the floor the message is about the floor, not about the named set:
	// a 1024-bit key is not "an unusual size", it is too weak to certify.
	if _, err := PrivateKeyType(rsaKeyOfSize(t, 1024)); err == nil {
		t.Error("a 1024-bit RSA key was accepted")
	} else if !strings.Contains(err.Error(), "minimum is 2048") {
		t.Errorf("a 1024-bit key should be rejected for weakness, got: %v", err)
	}
}

// TestPrivateKeyTypeNonRSA covers the other algorithms, which have no size
// vocabulary problem: the curve is the name.
func TestPrivateKeyTypeNonRSA(t *testing.T) {
	cases := []struct {
		key  interface{}
		want string
	}{
		{importTestECDSA(t, elliptic.P256()), "ecdsa-sha2-nistp256"},
		{importTestECDSA(t, elliptic.P384()), "ecdsa-sha2-nistp384"},
		{importTestECDSA(t, elliptic.P521()), "ecdsa-sha2-nistp521"},
		{importTestEd25519(t), "ed25519"},
	}
	for _, tc := range cases {
		got, err := PrivateKeyType(tc.key)
		if err != nil {
			t.Errorf("%s: %v", tc.want, err)
			continue
		}
		if got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func importTestECDSA(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func importTestEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rsaKeyOfSize builds a key whose modulus is exactly the requested bit length.
// PrivateKeyType reads nothing but N, so the modulus is constructed rather than
// factored: generating a real 8192-bit key would dominate this package's test
// time and cover nothing extra.
func rsaKeyOfSize(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1)) // odd, and exactly `bits` long
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}}
}

func itoa(n int) string {
	return strings.TrimSpace(joinBits([]int{n}))
}
