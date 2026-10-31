//go:build sqlite

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// sshCLIEnv builds the store + software key provider the `secsy-ca ssh`
// subcommands run against, so the CLI surface is exercised exactly as a
// operator invokes it (cmdSSH dispatch included).
func sshCLIEnv(t *testing.T) (*database.DB, keyprovider.Provider) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { prov.Close() })
	return db, prov
}

// writeSSHPub writes a fresh Ed25519 public key as an authorized_keys file and
// returns its path.
func writeSSHPub(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}
	return path
}

// signedCertLifetime signs a user certificate through the CLI and returns the
// lifetime of the certificate it wrote.
func signedCertLifetime(t *testing.T, db *database.DB, prov keyprovider.Provider, caLabel, validity string) time.Duration {
	t.Helper()
	out := filepath.Join(t.TempDir(), "id_ed25519-cert.pub")
	args := []string{"sign-user", "-ca", caLabel, "-pub", writeSSHPub(t), "-principals", "alice", "-out", out}
	if validity != "" {
		args = append(args, "-validity", validity)
	}
	if err := cmdSSH(db, prov, args); err != nil {
		t.Fatalf("ssh sign-user: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("CLI wrote %T, want an ssh certificate", pub)
	}
	return time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
}

// TestCLISSHCAMaxValidity drives the whole CLI story for Task 217: create a CA
// with a ceiling, read it back, change it, sign against it, and clear it.
func TestCLISSHCAMaxValidity(t *testing.T) {
	db, prov := sshCLIEnv(t)

	// ca-init -max-validity accepts the day/week suffixes ParseValidity does.
	if err := cmdSSH(db, prov, []string{"ca-init", "-label", "cli-cap-ca", "-max-validity", "2d"}); err != nil {
		t.Fatalf("ssh ca-init: %v", err)
	}
	ca, err := db.GetCAByLabel("cli-cap-ca")
	if err != nil || ca == nil {
		t.Fatalf("GetCAByLabel: %v (ca=%v)", err, ca)
	}
	if want := int64((48 * time.Hour).Seconds()); ca.MaxSSHValiditySecs != want {
		t.Fatalf("ceiling after ca-init = %d, want %d", ca.MaxSSHValiditySecs, want)
	}

	// A request past the ceiling is clamped (user-default would permit 30d).
	if got := signedCertLifetime(t, db, prov, "cli-cap-ca", "30d"); got > 48*time.Hour+10*time.Minute {
		t.Errorf("lifetime = %s, want clamped to ~48h", got)
	}

	// ca-max-validity without -set is the read path; it must not change anything.
	if err := cmdSSH(db, prov, []string{"ca-max-validity", "-ca", "cli-cap-ca"}); err != nil {
		t.Fatalf("ssh ca-max-validity (show): %v", err)
	}
	if ca, _ = db.GetCAByLabel("cli-cap-ca"); ca.MaxSSHValiditySecs != int64((48 * time.Hour).Seconds()) {
		t.Errorf("read path changed the ceiling to %d", ca.MaxSSHValiditySecs)
	}

	// Tighten it to 30 minutes, addressing the CA by label.
	if err := cmdSSH(db, prov, []string{"ca-max-validity", "-ca", "cli-cap-ca", "-set", "30m"}); err != nil {
		t.Fatalf("ssh ca-max-validity -set: %v", err)
	}
	if ca, _ = db.GetCAByLabel("cli-cap-ca"); ca.MaxSSHValiditySecs != 1800 {
		t.Fatalf("ceiling after -set 30m = %d, want 1800", ca.MaxSSHValiditySecs)
	}
	if got := signedCertLifetime(t, db, prov, "cli-cap-ca", "12h"); got > 35*time.Minute {
		t.Errorf("lifetime after tightening = %s, want clamped to ~30m", got)
	}
	// The profile default (12h) is clamped too.
	if got := signedCertLifetime(t, db, prov, "cli-cap-ca", ""); got > 35*time.Minute {
		t.Errorf("profile-default lifetime = %s, want clamped to ~30m", got)
	}

	// -set none clears it, and the profile bounds take over again.
	if err := cmdSSH(db, prov, []string{"ca-max-validity", "-ca", "cli-cap-ca", "-set", "none"}); err != nil {
		t.Fatalf("ssh ca-max-validity -set none: %v", err)
	}
	if ca, _ = db.GetCAByLabel("cli-cap-ca"); ca.MaxSSHValiditySecs != 0 {
		t.Fatalf("ceiling after -set none = %d, want 0", ca.MaxSSHValiditySecs)
	}
	if got := signedCertLifetime(t, db, prov, "cli-cap-ca", "7d"); got < 7*24*time.Hour {
		t.Errorf("lifetime after clearing = %s, want the full 7d request", got)
	}
}

// TestCLISSHCAMaxValidityErrors pins the CLI's refusals: a missing -ca, an
// unparseable duration (on both commands), and an unknown CA.
func TestCLISSHCAMaxValidityErrors(t *testing.T) {
	db, prov := sshCLIEnv(t)
	if err := cmdSSH(db, prov, []string{"ca-init", "-label", "cli-cap-err-ca"}); err != nil {
		t.Fatalf("ssh ca-init: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no -ca", []string{"ca-max-validity"}},
		{"bad duration", []string{"ca-max-validity", "-ca", "cli-cap-err-ca", "-set", "forever"}},
		{"unknown CA", []string{"ca-max-validity", "-ca", "nope", "-set", "1h"}},
		{"bad duration at ca-init", []string{"ca-init", "-label", "cli-cap-err2-ca", "-max-validity", "forever"}},
	} {
		if err := cmdSSH(db, prov, tc.args); err == nil {
			t.Errorf("%s: accepted, want an error", tc.name)
		}
	}

	// The failed ca-init must not have left a CA behind.
	if ca, _ := db.GetCAByLabel("cli-cap-err2-ca"); ca != nil {
		t.Error("ca-init with a bad -max-validity created a CA anyway")
	}
	// …and the valid CA is still uncapped.
	if ca, _ := db.GetCAByLabel("cli-cap-err-ca"); ca == nil || ca.MaxSSHValiditySecs != 0 {
		t.Errorf("CA ceiling = %v, want 0 after only failed attempts", ca)
	}
}
