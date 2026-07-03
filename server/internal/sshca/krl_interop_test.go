package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestKRLSSHKeygenInterop proves OpenSSH itself accepts the KRLs this package
// generates: `ssh-keygen -Q -f <krl>` must flag a certificate revoked by
// serial and one revoked by key ID, and pass an unrevoked certificate. This is
// the same code path sshd's RevokedKeys option uses, so it is the
// authoritative interop check. Skipped when ssh-keygen is not installed.
func TestKRLSSHKeygenInterop(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found on PATH; skipping KRL interop test")
	}

	// Software CA key (the KRL format is independent of where the key lives).
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("wrapping CA key: %v", err)
	}

	mkCert := func(serial uint64, keyID string) *ssh.Certificate {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating subject key: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("converting subject key: %v", err)
		}
		cert := &ssh.Certificate{
			Key:             sshPub,
			Serial:          serial,
			CertType:        ssh.UserCert,
			KeyId:           keyID,
			ValidPrincipals: []string{"alice"},
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatalf("signing certificate: %v", err)
		}
		return cert
	}

	bySerial := mkCert(42, "by-serial@corp")
	byKeyID := mkCert(43, "by-key-id@corp")
	unrevoked := mkCert(44, "fine@corp")

	krl, err := MarshalKRL(&KRLContent{
		Version:     1,
		GeneratedAt: time.Now(),
		Comment:     "secsy-pki interop test",
		CAKey:       caSigner.PublicKey(),
		Serials:     []uint64{42},
		KeyIDs:      []string{"by-key-id@corp"},
	})
	if err != nil {
		t.Fatalf("MarshalKRL: %v", err)
	}

	dir := t.TempDir()
	krlPath := filepath.Join(dir, "test.krl")
	if err := os.WriteFile(krlPath, krl, 0o644); err != nil {
		t.Fatalf("writing KRL: %v", err)
	}
	write := func(name string, cert *ssh.Certificate) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return p
	}
	bySerialPath := write("by-serial-cert.pub", bySerial)
	byKeyIDPath := write("by-key-id-cert.pub", byKeyID)
	unrevokedPath := write("unrevoked-cert.pub", unrevoked)

	// ssh-keygen -Q prints "<file>:<line>: <status>" per key and exits non-zero
	// when any tested key is revoked.
	check := func(certPath string) (revoked bool, out string) {
		t.Helper()
		cmd := exec.Command(keygen, "-Q", "-f", krlPath, certPath)
		outB, err := cmd.CombinedOutput()
		out = string(outB)
		if err != nil {
			if _, isExit := err.(*exec.ExitError); !isExit {
				t.Fatalf("running ssh-keygen -Q: %v\n%s", err, out)
			}
			return true, out
		}
		return false, out
	}

	if revoked, out := check(bySerialPath); !revoked || !strings.Contains(out, "REVOKED") {
		t.Errorf("ssh-keygen does not consider the serial-revoked certificate revoked:\n%s", out)
	}
	if revoked, out := check(byKeyIDPath); !revoked || !strings.Contains(out, "REVOKED") {
		t.Errorf("ssh-keygen does not consider the key-ID-revoked certificate revoked:\n%s", out)
	}
	if revoked, out := check(unrevokedPath); revoked {
		t.Errorf("ssh-keygen considers the unrevoked certificate revoked:\n%s", out)
	}
}
