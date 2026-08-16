package yubihsm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// RFC 4493 section 4 test vectors for AES-128-CMAC. The whole secure channel
// rests on this primitive — session keys, command MACs and response MACs are all
// CMAC outputs — so it is pinned to the standard's own vectors rather than to
// whatever the implementation happens to produce.
func TestCMACRFC4493Vectors(t *testing.T) {
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		msg  string
		want string
	}{
		{"empty", "", "bb1d6929e95937287fa37d129b756746"},
		{"one block", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{
			"partial block",
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			"dfa66747de9ae63030ca32611497c827",
		},
		{
			"four blocks",
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
				"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			"51f0bebf7e3b9d92fc49741779363cfe",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := hex.DecodeString(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if got := cmacSum(block, msg); !bytes.Equal(got, want) {
				t.Fatalf("cmacSum = %x, want %x", got, want)
			}
		})
	}
}

// The subkey derivation conditionally XORs in Rb depending on a bit of a
// key-derived value, so it is written branch-free; this pins the values the RFC
// gives for the same key.
func TestCMACSubkeys(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := cmacSubkeys(block)
	wantK1, _ := hex.DecodeString("fbeed618357133667c85e08f7236a8de")
	wantK2, _ := hex.DecodeString("f7ddac306ae266ccf90bc11ee46d513b")
	if !bytes.Equal(k1, wantK1) {
		t.Errorf("K1 = %x, want %x", k1, wantK1)
	}
	if !bytes.Equal(k2, wantK2) {
		t.Errorf("K2 = %x, want %x", k2, wantK2)
	}
}

// Yubico documents the keys the factory password derives to, so the PBKDF2
// parameters — salt "Yubico", 10000 iterations, SHA-256, 32 bytes split in two —
// can be pinned to a published value rather than to whatever this code happens
// to compute. Getting them wrong would show up only as an unexplained
// authentication failure against a device.
func TestDeriveAuthenticationKeysDefaultPassword(t *testing.T) {
	enc, mac, err := DeriveAuthenticationKeys("password")
	if err != nil {
		t.Fatal(err)
	}
	const wantEnc = "090b47dbed595654901dee1cc655e420"
	const wantMAC = "592fd483f759e29909a04c4505d2ce0a"
	if hex.EncodeToString(enc) != wantEnc {
		t.Errorf("ENC key = %x, want %s", enc, wantEnc)
	}
	if hex.EncodeToString(mac) != wantMAC {
		t.Errorf("MAC key = %x, want %s", mac, wantMAC)
	}
}
