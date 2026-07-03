//go:build sqlite

package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestSoftHSMSSHCAEndToEnd is the Task 57 acceptance test against a real
// PKCS#11 token: for each supported CA key type it initializes an SSH CA whose
// key lives on the HSM, signs user and host certificates (every signature
// produced by the token via crypto.Signer), verifies them, checks ssh-keygen
// parses the certificates (-L) and honors the generated KRL (-Q), and proves
// expired and revoked certificates are rejected. Skipped unless the SoftHSM
// environment is exported (run: eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMSSHCAEndToEnd(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}

	provider, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	for _, keyType := range []string{
		keyprovider.KeyTypeEd25519,
		keyprovider.KeyTypeECDSAP256,
		keyprovider.KeyTypeRSA2048,
	} {
		keyType := keyType
		t.Run(keyType, func(t *testing.T) {
			db, err := database.New("sqlite", ":memory:")
			if err != nil {
				t.Fatalf("database.New: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			authority := NewAuthority(db, provider)
			ctx := context.Background()

			// Unique per-run label: the SoftHSM store persists across runs and
			// duplicate CKA_LABELs cause intermittent verify failures.
			label := fmt.Sprintf("ssh-ca-%s-%s-%s", keyType, time.Now().Format("150405"), randSuffix(t))
			ca, err := authority.InitCA(ctx, CASpec{Label: label, KeyType: keyType})
			if err != nil {
				t.Fatalf("InitCA(%s): %v", keyType, err)
			}

			userCert := signAndVerify(t, authority, ca.ID, CertTypeUser, "alice", "alice@corp")
			hostCert := signAndVerify(t, authority, ca.ID, CertTypeHost, "web1.example.com", "web1.example.com")

			// Expired certificates are rejected at their evaluation time.
			if _, err := authority.VerifyCertificate(ctx, ca.ID, userCert, "alice", time.Now().Add(31*24*time.Hour)); err == nil {
				t.Error("expired certificate verified")
			}

			// Revoke the user certificate and prove verification now fails while
			// the host certificate still passes.
			parsed := mustParseCert(t, userCert)
			_, _, err = authority.Revoke(ctx, RevokeRequest{
				CAID: ca.ID, Serial: fmt.Sprintf("%d", parsed.Serial), Reason: "test", RevokedBy: "test",
			})
			if err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if _, err := authority.VerifyCertificate(ctx, ca.ID, userCert, "alice", time.Now()); err == nil {
				t.Error("revoked certificate verified")
			}
			if _, err := authority.VerifyCertificate(ctx, ca.ID, hostCert, "web1.example.com", time.Now()); err != nil {
				t.Errorf("unrevoked host certificate rejected: %v", err)
			}

			krl, err := authority.BuildKRL(ctx, ca.ID, "softhsm test")
			if err != nil {
				t.Fatalf("BuildKRL: %v", err)
			}
			sshKeygenInterop(t, userCert, hostCert, krl, parsed)
		})
	}
}

// signAndVerify signs one certificate on the HSM and verifies it in-process,
// returning the authorized_keys encoding.
func signAndVerify(t *testing.T, authority *Authority, caID, certType, principal, keyID string) []byte {
	t.Helper()
	ctx := context.Background()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating subject key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting subject key: %v", err)
	}

	result, err := authority.Sign(ctx, SignRequest{
		CAID:        caID,
		CertType:    certType,
		PublicKey:   string(ssh.MarshalAuthorizedKey(sshPub)),
		Principals:  []string{principal},
		KeyID:       keyID,
		RequestedBy: "softhsm-test",
	})
	if err != nil {
		t.Fatalf("Sign(%s): %v", certType, err)
	}
	if _, err := authority.VerifyCertificate(ctx, caID, result.AuthorizedKey, principal, time.Now()); err != nil {
		t.Fatalf("%s certificate does not verify: %v", certType, err)
	}
	return result.AuthorizedKey
}

func mustParseCert(t *testing.T, authorizedKey []byte) *ssh.Certificate {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	return cert
}

// sshKeygenInterop runs the OpenSSH tooling against the HSM-signed artifacts:
// `ssh-keygen -L` must parse both certificates (type, key ID, principal,
// serial), and `ssh-keygen -Q` must report the revoked certificate REVOKED and
// pass the unrevoked one against the generated KRL. Logged-and-skipped when
// ssh-keygen is unavailable, like the openssl interop checks.
func sshKeygenInterop(t *testing.T, revokedCert, okCert, krl []byte, revoked *ssh.Certificate) {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Log("ssh-keygen not found; skipping OpenSSH interop verification")
		return
	}

	dir := t.TempDir()
	revokedPath := filepath.Join(dir, "revoked-cert.pub")
	okPath := filepath.Join(dir, "ok-cert.pub")
	krlPath := filepath.Join(dir, "ca.krl")
	for _, f := range []struct {
		path string
		data []byte
	}{{revokedPath, revokedCert}, {okPath, okCert}, {krlPath, krl}} {
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			t.Fatalf("writing %s: %v", f.path, err)
		}
	}

	// -L: certificate parsing. The output must reflect what we signed.
	list, err := exec.Command(keygen, "-L", "-f", revokedPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L failed: %v\n%s", err, list)
	}
	out := string(list)
	for _, want := range []string{
		"user certificate",
		fmt.Sprintf("Serial: %d", revoked.Serial),
		revoked.KeyId,
		revoked.ValidPrincipals[0],
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-keygen -L output missing %q:\n%s", want, out)
		}
	}
	hostList, err := exec.Command(keygen, "-L", "-f", okPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L (host) failed: %v\n%s", err, hostList)
	}
	if !strings.Contains(string(hostList), "host certificate") {
		t.Errorf("ssh-keygen -L does not report a host certificate:\n%s", hostList)
	}

	// -Q: KRL checking — the exact path sshd's RevokedKeys uses.
	qRevoked, err := exec.Command(keygen, "-Q", "-f", krlPath, revokedPath).CombinedOutput()
	if err == nil || !strings.Contains(string(qRevoked), "REVOKED") {
		t.Errorf("ssh-keygen -Q does not flag the revoked certificate (err=%v):\n%s", err, qRevoked)
	}
	if qOK, err := exec.Command(keygen, "-Q", "-f", krlPath, okPath).CombinedOutput(); err != nil {
		t.Errorf("ssh-keygen -Q rejects the unrevoked certificate: %v\n%s", err, qOK)
	}
}

func randSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}
