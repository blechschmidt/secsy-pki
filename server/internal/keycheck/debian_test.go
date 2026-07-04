package keycheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // fingerprint basis under test.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// spkiHashes returns the lowercase hex SHA-256 and SHA-1 of a key's DER SPKI —
// the basis the Debian blocklist matches on.
func spkiHashes(t *testing.T, pub interface{}) (sha256hex, sha1hex string) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling SPKI: %v", err)
	}
	s256 := sha256.Sum256(spki)
	s1 := sha1.Sum(spki) //nolint:gosec // fingerprint basis under test.
	return hex.EncodeToString(s256[:]), hex.EncodeToString(s1[:])
}

func TestBlocklist_MatchesDebianWeakKey(t *testing.T) {
	// Stand in for "a published Debian weak key": a concrete RSA key whose SPKI
	// fingerprint an operator has placed on the blocklist. The gate must reject any
	// certificate request bearing exactly this public key.
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sha256hex, _ := spkiHashes(t, &weak.PublicKey)

	dir := t.TempDir()
	file := filepath.Join(dir, "blacklist.RSA-2048")
	content := "# Debian OpenSSL predictable keys (CVE-2008-0166) — SHA-256 of DER SPKI\n" +
		sha256hex + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	bl, err := LoadBlocklist(file)
	if err != nil {
		t.Fatalf("loading blocklist: %v", err)
	}
	if bl.Empty() {
		t.Fatal("blocklist loaded empty")
	}
	if !bl.Contains(&weak.PublicKey) {
		t.Fatal("blocklisted weak key was NOT matched")
	}

	// A different key is not on the list.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if bl.Contains(&other.PublicKey) {
		t.Fatal("non-blocklisted key falsely matched")
	}

	// The blocklist drives Inspect's debian_weak_key finding.
	res := Inspect(&weak.PublicKey, DefaultPolicy(bl))
	if !hasCode(res, CodeDebianWeakKey) {
		t.Fatalf("expected debian_weak_key finding, got %v", res.Codes())
	}
	if res := Inspect(&other.PublicKey, DefaultPolicy(bl)); hasCode(res, CodeDebianWeakKey) {
		t.Fatalf("clean key falsely produced debian_weak_key finding: %v", res.Codes())
	}
}

func TestBlocklist_MatchesSHA1AndPrefixedForms(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, sha1hex := spkiHashes(t, &k.PublicKey)
	fp, _ := Fingerprint(&k.PublicKey) // "SHA256:<base64>"

	dir := t.TempDir()
	// One file uses the SHA-1 hex form (with a 0x prefix and a trailing comment),
	// another uses the "SHA256:<base64>" form exported from our own tooling.
	if err := os.WriteFile(filepath.Join(dir, "sha1.txt"), []byte("0x"+sha1hex+"  # weak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prefixed.txt"), []byte(fp+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load the whole directory.
	bl, err := LoadBlocklist(dir)
	if err != nil {
		t.Fatalf("loading dir: %v", err)
	}
	if bl.Len() < 2 {
		t.Fatalf("expected >= 2 entries from the directory, got %d", bl.Len())
	}
	if !bl.Contains(&k.PublicKey) {
		t.Fatal("key not matched via SHA-1 / prefixed forms")
	}
}

func TestLoadBlocklist_NoPaths(t *testing.T) {
	bl, err := LoadBlocklist()
	if err != nil {
		t.Fatalf("no paths should not error: %v", err)
	}
	if bl != nil {
		t.Fatalf("no paths should yield nil blocklist, got len=%d", bl.Len())
	}
	// A nil blocklist is safe to consult.
	if bl.Contains(nil) {
		t.Fatal("nil blocklist matched")
	}
}

func TestLoadBlocklist_MissingPathFailsClosed(t *testing.T) {
	if _, err := LoadBlocklist(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("a missing blocklist path must be a hard error (fail closed), got nil")
	}
}
