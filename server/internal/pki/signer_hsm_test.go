//go:build yubihsm

package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var hsmCfg PKCS11Config

func TestMain(m *testing.M) {
	// Write yubihsm_pkcs11.conf so the PKCS#11 module knows how to reach the device.
	confDir, err := os.MkdirTemp("", "yubihsm-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(confDir)

	confPath := filepath.Join(confDir, "yubihsm_pkcs11.conf")
	confContent := "connector = yhusb://\n"
	if err := os.WriteFile(confPath, []byte(confContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write conf: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("YUBIHSM_PKCS11_CONF", confPath)

	hsmCfg = PKCS11Config{
		ModulePath: "/usr/lib/pkcs11/yubihsm_pkcs11.so",
		Pin:        "0001password",
		TokenLabel: "YubiHSM",
	}

	os.Exit(m.Run())
}

// testRunID is a unique suffix for this test run to avoid label collisions
// with keys left over from previous runs.
var testRunID string

func init() {
	b := make([]byte, 4)
	rand.Read(b)
	testRunID = fmt.Sprintf("%x", b)
}

// safeLabel creates a PKCS#11-safe label with a unique run suffix.
// YubiHSM labels are max 40 bytes. We use a short suffix to ensure
// the unique testRunID is always included.
func safeLabel(_ *testing.T, suffix string) string {
	label := fmt.Sprintf("t_%s_%s", testRunID, suffix)
	if len(label) > 40 {
		label = label[:40]
	}
	return label
}

// generateKeyRetry wraps GenerateKeyOnHSM with retries to handle
// transient USB contention with the YubiHSM. The PKCS#11 module
// sometimes needs a moment after being loaded or after Finalize/Destroy.
func generateKeyRetry(t *testing.T, label, keyType string) *GeneratedHSMKey {
	t.Helper()
	var gen *GeneratedHSMKey
	var err error
	for i := 0; i < 5; i++ {
		gen, err = GenerateKeyOnHSM(hsmCfg, label, keyType)
		if err == nil {
			return gen
		}
		if !strings.Contains(err.Error(), "no token found") {
			t.Fatalf("GenerateKeyOnHSM %s: %v", keyType, err)
		}
		t.Logf("retry %d: %v", i+1, err)
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}
	t.Fatalf("GenerateKeyOnHSM %s failed after retries: %v", keyType, err)
	return nil
}

// newSignerRetry wraps NewPKCS11Signer with retries.
func newSignerRetry(t *testing.T, label string) *PKCS11Signer {
	t.Helper()
	var signer *PKCS11Signer
	var err error
	for i := 0; i < 5; i++ {
		signer, err = NewPKCS11Signer(hsmCfg, label)
		if err == nil {
			return signer
		}
		if !strings.Contains(err.Error(), "no token found") {
			t.Fatalf("NewPKCS11Signer: %v", err)
		}
		t.Logf("retry %d: %v", i+1, err)
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}
	t.Fatalf("NewPKCS11Signer failed after retries: %v", err)
	return nil
}

// ---------------------------------------------------------------------------
// TestHSM_Ed25519 tests GenerateKeyOnHSM, NewPKCS11Signer, Sign, SSHPublicKey
// ---------------------------------------------------------------------------

func TestHSM_Ed25519(t *testing.T) {
	label := safeLabel(t, "ed25519")

	gen := generateKeyRetry(t, label, "ed25519")
	t.Logf("generated key: URI=%s KeyType=%s", gen.PKCS11URI, gen.KeyType)

	if gen.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want ed25519", gen.KeyType)
	}

	// Verify SSH public key format parses
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
	if err != nil {
		t.Fatalf("SSH public key does not parse: %v", err)
	}

	// Open signer for the generated key
	signer := newSignerRetry(t, label)
	defer signer.Close()

	// Verify Public() and KeyType()
	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("Public() type = %T, want ed25519.PublicKey", pub)
	}
	if signer.KeyType() != "ssh-ed25519" {
		t.Errorf("KeyType() = %q, want ssh-ed25519", signer.KeyType())
	}

	// SSHPublicKey round-trip
	sshPub, err := signer.SSHPublicKey()
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if sshPub.Type() != "ssh-ed25519" {
		t.Errorf("SSH key type = %q", sshPub.Type())
	}

	// Sign and verify (Ed25519 signs the raw message)
	message := []byte("test message for ed25519 signing")
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}

	edPub := pub.(ed25519.PublicKey)
	if !ed25519.Verify(edPub, message, sig) {
		t.Error("ed25519.Verify failed")
	}

	// Verify SSHPublicKey matches GenerateKeyOnHSM output
	genKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
	if genKey != nil && !bytes.Equal(genKey.Marshal(), sshPub.Marshal()) {
		t.Error("SSHPublicKey from signer does not match GenerateKeyOnHSM output")
	}
}

// ---------------------------------------------------------------------------
// TestHSM_ECDSA_P256
// ---------------------------------------------------------------------------

func TestHSM_ECDSA_P256(t *testing.T) {
	label := safeLabel(t, "p256")

	gen := generateKeyRetry(t, label, "ecdsa-sha2-nistp256")
	t.Logf("generated key: URI=%s KeyType=%s", gen.PKCS11URI, gen.KeyType)

	if gen.KeyType != "ecdsa-sha2-nistp256" {
		t.Errorf("KeyType = %q", gen.KeyType)
	}

	// Verify SSH public key format
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
	if err != nil {
		t.Fatalf("SSH public key does not parse: %v", err)
	}

	signer := newSignerRetry(t, label)
	defer signer.Close()

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() type = %T, want *ecdsa.PublicKey", pub)
	}
	if signer.KeyType() != "ecdsa-sha2-nistp256" {
		t.Errorf("KeyType() = %q", signer.KeyType())
	}

	// SSHPublicKey
	sshPub, err := signer.SSHPublicKey()
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if sshPub.Type() != "ecdsa-sha2-nistp256" {
		t.Errorf("SSH key type = %q", sshPub.Type())
	}

	// Sign with SHA-256 digest and verify
	message := []byte("test message for ECDSA P-256 signing")
	digest := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !ecdsa.VerifyASN1(ecPub, digest[:], sig) {
		t.Error("ecdsa.VerifyASN1 failed")
	}
}

// ---------------------------------------------------------------------------
// TestHSM_RSA2048
// ---------------------------------------------------------------------------

func TestHSM_RSA2048(t *testing.T) {
	label := safeLabel(t, "rsa2048")

	gen := generateKeyRetry(t, label, "rsa-2048")
	t.Logf("generated key: URI=%s KeyType=%s", gen.PKCS11URI, gen.KeyType)

	if gen.KeyType != "rsa-2048" {
		t.Errorf("KeyType = %q", gen.KeyType)
	}

	// Verify SSH public key format
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
	if err != nil {
		t.Fatalf("SSH public key does not parse: %v", err)
	}

	signer := newSignerRetry(t, label)
	defer signer.Close()

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() type = %T, want *rsa.PublicKey", pub)
	}
	if signer.KeyType() != "ssh-rsa" {
		t.Errorf("KeyType() = %q", signer.KeyType())
	}

	// SSHPublicKey
	sshPub, err := signer.SSHPublicKey()
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if sshPub.Type() != "ssh-rsa" {
		t.Errorf("SSH key type = %q", sshPub.Type())
	}

	// Sign with SHA-256 digest and verify
	message := []byte("test message for RSA-2048 signing")
	digest := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15 failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestHSM_FindToken
// ---------------------------------------------------------------------------

func TestHSM_FindToken(t *testing.T) {
	label := safeLabel(t, "findtoken")
	generateKeyRetry(t, label, "ed25519")

	signer := newSignerRetry(t, label)
	signer.Close()
}

// ---------------------------------------------------------------------------
// TestHSM_SSHPublicKey_RoundTrip
// ---------------------------------------------------------------------------

func TestHSM_SSHPublicKey_RoundTrip(t *testing.T) {
	types := []struct {
		keyType   string
		sshPrefix string
	}{
		{"ed25519", "ssh-ed25519"},
		{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"},
		{"rsa-2048", "ssh-rsa"},
	}

	for _, tc := range types {
		tc := tc
		t.Run(tc.keyType, func(t *testing.T) {
			// Use key-type-specific suffix to avoid label collisions
			// across subtests (they share the same testRunID).
			shortType := strings.ReplaceAll(tc.keyType, "-sha2-nistp", "")
			label := safeLabel(t, "rt-"+shortType)
			gen := generateKeyRetry(t, label, tc.keyType)

			// Parse the SSH public key string from GenerateKeyOnHSM
			parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(gen.SSHPublicKey))
			if err != nil {
				t.Fatalf("ParseAuthorizedKey: %v", err)
			}

			if parsedKey.Type() != tc.sshPrefix {
				t.Errorf("parsed key type = %q, want %q", parsedKey.Type(), tc.sshPrefix)
			}

			// Also verify via the signer's SSHPublicKey method
			signer := newSignerRetry(t, label)
			defer signer.Close()

			sshPub, err := signer.SSHPublicKey()
			if err != nil {
				t.Fatalf("SSHPublicKey: %v", err)
			}

			// The marshaled keys should match
			if !bytes.Equal(parsedKey.Marshal(), sshPub.Marshal()) {
				t.Error("SSH key from GenerateKeyOnHSM does not match key from NewPKCS11Signer")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestHSM_ZZ_Close runs last (alphabetically) to avoid disrupting other tests
// that need the PKCS#11 module.
// ---------------------------------------------------------------------------

func TestHSM_ZZ_Close(t *testing.T) {
	label := safeLabel(t, "close")
	generateKeyRetry(t, label, "ed25519")

	signer := newSignerRetry(t, label)

	// Close should not panic
	signer.Close()

	// After Close, opening a new signer should still work
	// (proves the module can be re-initialized)
	signer2 := newSignerRetry(t, label)
	signer2.Close()
}
