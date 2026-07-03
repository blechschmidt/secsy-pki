package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testCAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %v", err)
	}
	return sshPub
}

// TestKRLRoundTrip proves the writer and parser agree: serial and key-ID
// revocations bound to a CA key survive a marshal/parse cycle and the revocation
// predicates answer correctly for both revoked and non-revoked targets.
func TestKRLRoundTrip(t *testing.T) {
	caKey := testCAKey(t)
	otherCA := testCAKey(t)
	generated := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

	blob, err := MarshalKRL(&KRLContent{
		Version:     7,
		GeneratedAt: generated,
		Comment:     "secsy-pki test",
		CAKey:       caKey,
		Serials:     []uint64{42, 3, 42, 100000}, // unordered + duplicate on purpose
		KeyIDs:      []string{"carol@corp", "bob@corp"},
	})
	if err != nil {
		t.Fatalf("MarshalKRL: %v", err)
	}

	parsed, err := ParseKRL(blob)
	if err != nil {
		t.Fatalf("ParseKRL: %v", err)
	}
	if parsed.Version != 7 {
		t.Errorf("Version = %d, want 7", parsed.Version)
	}
	if !parsed.GeneratedAt.Equal(generated) {
		t.Errorf("GeneratedAt = %v, want %v", parsed.GeneratedAt, generated)
	}
	if parsed.Comment != "secsy-pki test" {
		t.Errorf("Comment = %q", parsed.Comment)
	}
	if len(parsed.Certificates) != 1 {
		t.Fatalf("certificate sections = %d, want 1", len(parsed.Certificates))
	}
	sect := parsed.Certificates[0]
	if sect.CAKey == nil || string(sect.CAKey.Marshal()) != string(caKey.Marshal()) {
		t.Error("section CA key does not round-trip")
	}
	// Duplicates collapse, order is ascending.
	wantSerials := []uint64{3, 42, 100000}
	if len(sect.Serials) != len(wantSerials) {
		t.Fatalf("serials = %v, want %v", sect.Serials, wantSerials)
	}
	for i, s := range wantSerials {
		if sect.Serials[i] != s {
			t.Fatalf("serials = %v, want %v", sect.Serials, wantSerials)
		}
	}

	for _, serial := range wantSerials {
		if !parsed.IsSerialRevoked(caKey, serial) {
			t.Errorf("serial %d should be revoked", serial)
		}
	}
	if parsed.IsSerialRevoked(caKey, 4) {
		t.Error("serial 4 should not be revoked")
	}
	if parsed.IsSerialRevoked(otherCA, 42) {
		t.Error("serial 42 should not be revoked under a different CA")
	}
	if !parsed.IsKeyIDRevoked(caKey, "carol@corp") || !parsed.IsKeyIDRevoked(caKey, "bob@corp") {
		t.Error("key IDs should be revoked")
	}
	if parsed.IsKeyIDRevoked(caKey, "alice@corp") {
		t.Error("alice@corp should not be revoked")
	}
}

// TestKRLEmpty proves a KRL with no revocations is a valid header-only blob.
func TestKRLEmpty(t *testing.T) {
	blob, err := MarshalKRL(&KRLContent{
		Version:     0,
		GeneratedAt: time.Now(),
		CAKey:       testCAKey(t),
	})
	if err != nil {
		t.Fatalf("MarshalKRL: %v", err)
	}
	parsed, err := ParseKRL(blob)
	if err != nil {
		t.Fatalf("ParseKRL: %v", err)
	}
	if len(parsed.Certificates) != 0 {
		t.Errorf("empty KRL has %d certificate sections", len(parsed.Certificates))
	}
	if parsed.IsSerialRevoked(nil, 1) {
		t.Error("empty KRL revokes serial 1")
	}
}

// TestKRLRejectsGarbage proves the parser fails cleanly on non-KRL input and
// truncation rather than mis-reading it.
func TestKRLRejectsGarbage(t *testing.T) {
	if _, err := ParseKRL([]byte("not a krl")); err == nil {
		t.Error("garbage accepted")
	}
	blob, err := MarshalKRL(&KRLContent{
		Version: 1, GeneratedAt: time.Now(), CAKey: testCAKey(t), Serials: []uint64{7},
	})
	if err != nil {
		t.Fatalf("MarshalKRL: %v", err)
	}
	for _, cut := range []int{1, 9, len(blob) / 2, len(blob) - 1} {
		if _, err := ParseKRL(blob[:cut]); err == nil {
			t.Errorf("truncation at %d accepted", cut)
		}
	}
}

func TestParseValidity(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"12h", 12 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"12w", 12 * 7 * 24 * time.Hour, false},
		{"bogus", 0, true},
		{"-4h", 0, true},
		{"0", 0, true},
	}
	for _, c := range cases {
		got, err := ParseValidity(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseValidity(%q) accepted, want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseValidity(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseValidity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestProfileValidation exercises SetCustomProfiles' guard rails.
func TestProfileValidation(t *testing.T) {
	t.Cleanup(func() { SetCustomProfiles(nil) })

	bad := []Profile{
		{Name: "", CertType: CertTypeUser, DefaultValidity: time.Hour},
		{Name: "x", CertType: "server", DefaultValidity: time.Hour},
		{Name: "x", CertType: CertTypeUser}, // no default validity
		{Name: "x", CertType: CertTypeUser, DefaultValidity: 2 * time.Hour, MaxValidity: time.Hour},
		{Name: "x", CertType: CertTypeHost, DefaultValidity: time.Hour,
			DefaultExtensions: map[string]string{"permit-pty": ""}},
		{Name: "x", CertType: CertTypeHost, DefaultValidity: time.Hour,
			AllowedCriticalOptions: []string{"force-command"}},
		{Name: "x", CertType: CertTypeUser, DefaultValidity: time.Hour,
			AllowedPrincipals: []string{"[bad-pattern"}},
	}
	for i, p := range bad {
		if err := SetCustomProfiles([]Profile{p}); err == nil {
			t.Errorf("case %d: invalid profile %+v accepted", i, p)
		}
	}

	// A valid custom profile overrides a built-in by name and is listed.
	err := SetCustomProfiles([]Profile{{
		Name:            "User-Default", // case-insensitive override
		CertType:        CertTypeUser,
		DefaultValidity: time.Hour,
		MaxValidity:     2 * time.Hour,
	}})
	if err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	p, err := LookupProfile("user-default")
	if err != nil {
		t.Fatalf("LookupProfile: %v", err)
	}
	if p.DefaultValidity != time.Hour {
		t.Errorf("custom profile did not override built-in (default validity %v)", p.DefaultValidity)
	}
}
