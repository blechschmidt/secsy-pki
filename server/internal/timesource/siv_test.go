package timesource

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAESSIVVectorRFC5297 verifies the AES-SIV (AEAD_AES_SIV_CMAC_256)
// implementation against the deterministic-authenticated-encryption test vector
// in RFC 5297 Appendix A.1. Passing it exercises CMAC subkey derivation, the S2V
// dbl/xorend construction, and the CTR step end to end — so NTS authenticators
// built and verified with this primitive are correct.
func TestAESSIVVectorRFC5297(t *testing.T) {
	key := mustHex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := mustHex(t, "101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext := mustHex(t, "112233445566778899aabbccddee")
	want := mustHex(t, "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")

	siv, err := newAESSIV(key)
	if err != nil {
		t.Fatalf("newAESSIV: %v", err)
	}

	got, err := siv.Seal(plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Seal mismatch:\n got %x\nwant %x", got, want)
	}

	// Open must recover the plaintext and authenticate.
	back, err := siv.Open(got, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("Open mismatch: got %x want %x", back, plaintext)
	}

	// A single flipped bit in the sealed blob must fail authentication.
	tampered := append([]byte(nil), got...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := siv.Open(tampered, ad); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
	}
	// A changed associated-data string must also fail authentication.
	badAD := append([]byte(nil), ad...)
	badAD[0] ^= 0x01
	if _, err := siv.Open(got, badAD); err == nil {
		t.Fatal("Open accepted mismatched associated data")
	}
}

// TestAESSIVEmptyPlaintext covers the NTS request/response shape: an empty
// plaintext with the packet bytes and a nonce as the associated-data vector. The
// sealed output is exactly the 16-byte synthetic tag, and it round-trips.
func TestAESSIVEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	siv, err := newAESSIV(key)
	if err != nil {
		t.Fatalf("newAESSIV: %v", err)
	}
	packet := []byte("an NTP packet prefix of arbitrary length")
	nonce := bytes.Repeat([]byte{0xa5}, 16)

	sealed, err := siv.Seal(nil, packet, nonce)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != sivTagSize {
		t.Fatalf("empty-plaintext seal should be %d bytes (tag only), got %d", sivTagSize, len(sealed))
	}
	if _, err := siv.Open(sealed, packet, nonce); err != nil {
		t.Fatalf("Open of empty-plaintext seal: %v", err)
	}
	if _, err := siv.Open(sealed, packet[:len(packet)-1], nonce); err == nil {
		t.Fatal("Open accepted a different associated-data prefix")
	}
}

// TestCMACVectorRFC4493 checks AES-CMAC against the RFC 4493 example (empty and
// 16-byte messages under the standard example key), independent of SIV, so a
// CMAC regression is localized.
func TestCMACVectorRFC4493(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	// A 32-byte SIV key that reuses this key for the MAC half; the CTR half is
	// irrelevant to cmac().
	siv, err := newAESSIV(append(append([]byte(nil), key...), make([]byte, 16)...))
	if err != nil {
		t.Fatalf("newAESSIV: %v", err)
	}
	cases := []struct {
		msgHex string
		want   string
	}{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
	}
	for _, c := range cases {
		got := siv.cmac(mustHex(t, c.msgHex))
		if hex.EncodeToString(got) != c.want {
			t.Fatalf("cmac(%q) = %x, want %s", c.msgHex, got, c.want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}
