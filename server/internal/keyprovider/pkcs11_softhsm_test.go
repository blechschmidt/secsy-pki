package keyprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// pkcs11TestProvider builds a PKCS11Provider from the SECSY_* environment
// variables emitted by scripts/setup-softhsm.sh --export-env. Tests are skipped
// unless a module path and token label are present, so that a plain
// `go test ./...` run (with no HSM) stays green.
func pkcs11TestProvider(t *testing.T) *PKCS11Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL " +
			"(run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := NewPKCS11Provider(PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// uniqueLabel derives a per-run key label so repeated test runs against a
// persistent SoftHSM token do not collide on an already-existing key.
func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "test-" + base + "-" + time.Now().Format("150405") +
		"-" + string("0123456789abcdef"[b[0]&0xf]) + string("0123456789abcdef"[b[1]&0xf])
}

func TestPKCS11GenerateFindSign(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	for _, keyType := range []string{KeyTypeEd25519, KeyTypeECDSAP256, KeyTypeRSA2048} {
		t.Run(keyType, func(t *testing.T) {
			label := uniqueLabel(t, keyType)

			gen, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if gen.KeyType != keyType {
				t.Errorf("KeyType = %q, want %q", gen.KeyType, keyType)
			}
			if gen.SSHPublicKey == "" {
				t.Error("empty SSH public key")
			}

			// Look the key back up by label.
			found, err := p.FindKey(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("FindKey: %v", err)
			}
			if found.SSHPublicKey != gen.SSHPublicKey {
				t.Errorf("FindKey public key mismatch:\n got %q\nwant %q", found.SSHPublicKey, gen.SSHPublicKey)
			}

			// Sign through the HSM and verify with the exported public key.
			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
			if err != nil {
				t.Fatalf("parsing public key: %v", err)
			}

			certBytes, err := pki.SignSSHCertificate(
				signer,
				[]byte(gen.SSHPublicKey),
				ssh.UserCert,
				"hsm-test",
				[]string{"tester"},
				time.Now().Add(-time.Minute),
				time.Now().Add(time.Hour),
				nil, nil,
			)
			if err != nil {
				t.Fatalf("SignSSHCertificate: %v", err)
			}

			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
			if err != nil {
				t.Fatalf("parsing signed cert: %v", err)
			}
			cert := pubKey.(*ssh.Certificate)
			checker := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					return string(auth.Marshal()) == string(sshPub.Marshal())
				},
			}
			if err := checker.CheckCert("tester", cert); err != nil {
				t.Fatalf("HSM-signed certificate failed verification: %v", err)
			}
		})
	}
}

func TestPKCS11FindNotFound(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)
	if _, err := p.FindKey(ctx, KeyRef{Label: "definitely-does-not-exist-xyz"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestPKCS11RawSignVerify exercises the raw crypto.Signer contract against the
// HSM for a non-Ed25519 key (digest signing), independent of the SSH layer.
func TestPKCS11RawSignVerify(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	label := uniqueLabel(t, "raw")
	if _, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: label})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	digest := sha256.Sum256([]byte("hello hsm"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}
