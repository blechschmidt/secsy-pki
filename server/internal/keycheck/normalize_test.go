package keycheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNormalizeFingerprint_Accepts(t *testing.T) {
	// A known 32-byte digest and its two canonical encodings.
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	canonical := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	hexLower := hex.EncodeToString(digest[:])

	// openssl-style colon-grouped hex of the same digest.
	var groups []string
	for i := 0; i < len(digest); i++ {
		groups = append(groups, hex.EncodeToString(digest[i:i+1]))
	}
	hexColons := strings.ToUpper(strings.Join(groups, ":"))

	cases := []struct {
		name  string
		input string
	}{
		{"canonical", canonical},
		{"canonical-with-padding", "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])},
		{"canonical-lowercase-scheme", "sha256:" + base64.RawStdEncoding.EncodeToString(digest[:])},
		{"canonical-surrounding-space", "  " + canonical + "  "},
		{"hex-lower", hexLower},
		{"hex-upper", strings.ToUpper(hexLower)},
		{"hex-colon-grouped", hexColons},
		{"hex-with-space", strings.ToUpper(hexLower[:32]) + " " + hexLower[32:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeFingerprint(tc.input)
			if err != nil {
				t.Fatalf("NormalizeFingerprint(%q) errored: %v", tc.input, err)
			}
			if got != canonical {
				t.Fatalf("NormalizeFingerprint(%q) = %q, want %q", tc.input, got, canonical)
			}
		})
	}
}

func TestNormalizeFingerprint_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace-only", "   "},
		{"short-hex", "abcdef"},
		{"odd-hex", "abc"},
		{"non-hex", "zz" + strings.Repeat("a", 62)},
		{"sha256-not-32-bytes", "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short"))},
		{"sha256-bad-base64", "SHA256:!!!not-base64!!!"},
		{"sha512-hex-length", strings.Repeat("a", 128)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NormalizeFingerprint(tc.input); err == nil {
				t.Fatalf("NormalizeFingerprint(%q) = %q, want error", tc.input, got)
			}
		})
	}
}

// TestNormalizeFingerprint_MatchesFingerprint ties the hex input form to the
// canonical value the inventory stores: the hex SHA-256 of a key's SPKI must
// normalize to exactly what Fingerprint emits for that key, so an operator can
// search by either form.
func TestNormalizeFingerprint_MatchesFingerprint(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Fingerprint(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	hexForm := hex.EncodeToString(sum[:])

	got, err := NormalizeFingerprint(hexForm)
	if err != nil {
		t.Fatalf("NormalizeFingerprint(hex): %v", err)
	}
	if got != canonical {
		t.Fatalf("hex form normalized to %q, want %q", got, canonical)
	}
	// And the canonical form is idempotent under normalization.
	if again, err := NormalizeFingerprint(canonical); err != nil || again != canonical {
		t.Fatalf("NormalizeFingerprint(canonical) = %q, %v; want %q, nil", again, err, canonical)
	}
}
