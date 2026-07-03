package pkcs12

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

func TestEncoderFor(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"", EncoderModern, false},
		{"modern", EncoderModern, false},
		{"modern2023", EncoderModern, false},
		{"legacy", EncoderLegacyDES, false},
		{"legacydes", EncoderLegacyDES, false},
		{"legacyrc2", EncoderLegacyRC2, false},
		{"rc2", EncoderLegacyRC2, false},
		{"bogus", "", true},
	}
	for _, tc := range cases {
		enc, name, err := EncoderFor(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("EncoderFor(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("EncoderFor(%q): %v", tc.in, err)
			continue
		}
		if name != tc.want {
			t.Errorf("EncoderFor(%q) name = %q, want %q", tc.in, name, tc.want)
		}
		if enc == nil {
			t.Errorf("EncoderFor(%q): nil encoder", tc.in)
		}
	}
}

// TestEncoderForFIPS confirms the legacy encoders (3DES/RC2 + SHA-1) are refused
// when the FIPS policy is enforced, while the modern PBES2/AES-256 encoder is
// still allowed.
func TestEncoderForFIPS(t *testing.T) {
	prev := fips.PolicyEnforced()
	fips.SetPolicy(true)
	t.Cleanup(func() { fips.SetPolicy(prev) })

	if _, _, err := EncoderFor(EncoderModern); err != nil {
		t.Errorf("modern encoder rejected under FIPS: %v", err)
	}
	for _, name := range []string{EncoderLegacyDES, EncoderLegacyRC2} {
		if _, _, err := EncoderFor(name); err == nil {
			t.Errorf("legacy encoder %q accepted under FIPS policy; want rejection", name)
		}
	}
}

func TestGenerateSubjectKey(t *testing.T) {
	// Defaults.
	key, desc, err := generateSubjectKey(KeySpec{})
	if err != nil {
		t.Fatalf("default key: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("default key type = %T, want *ecdsa.PrivateKey", key)
	}
	if desc != "ecdsa-p256" {
		t.Errorf("default key desc = %q, want ecdsa-p256", desc)
	}

	// RSA default and explicit sizes.
	key, desc, err = generateSubjectKey(KeySpec{Type: "rsa"})
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("rsa key type = %T, want *rsa.PrivateKey", key)
	}
	if desc != "rsa-3072" {
		t.Errorf("rsa default desc = %q, want rsa-3072", desc)
	}

	// Rejections.
	for _, spec := range []KeySpec{
		{Type: "ed25519"},          // unsupported for PKCS#12 interop
		{Type: "rsa", Bits: 1024},  // below the 2048 floor
		{Type: "ecdsa", Bits: 200}, // not a valid curve
	} {
		if _, _, err := generateSubjectKey(spec); err == nil {
			t.Errorf("generateSubjectKey(%+v): expected error", spec)
		}
	}
}

func TestEscrowContext(t *testing.T) {
	if got := EscrowContext("42"); got != "pkcs12/42" {
		t.Errorf("EscrowContext = %q, want pkcs12/42", got)
	}
}
