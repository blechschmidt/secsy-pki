package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// pkcs11Provider builds a PKCS11Provider from the SECSY_* environment variables
// emitted by scripts/setup-softhsm.sh --export-env. The test is skipped unless
// a module path and token label are present, so a plain `go test ./...` run with
// no HSM stays green — mirroring keyprovider's pkcs11_softhsm_test.go.
func pkcs11Provider(t *testing.T) *keyprovider.PKCS11Provider {
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
	p, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
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

func uniqueKEKLabel(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	const hex = "0123456789abcdef"
	return "test-kek-" + time.Now().Format("150405") +
		"-" + string(hex[b[0]&0xf]) + string(hex[b[1]&0xf]) + string(hex[b[2]&0xf])
}

// TestHSMEnvelopeRoundTrip provisions an RSA KEK on the token, then verifies
// that a secret sealed under it round-trips — with the DEK unwrapped on the
// HSM via C_Decrypt (the KEK private key never leaves the device).
func TestHSMEnvelopeRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)
	label := uniqueKEKLabel(t)

	svc, err := ProvisionKEK(ctx, p, label, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK on HSM: %v", err)
	}
	if info := svc.KEKInfo(); info.Provider != "pkcs11" || info.KeyBits != 2048 {
		t.Fatalf("unexpected KEK info: %+v", info)
	}

	secret := []byte("correct horse battery staple")
	blob, err := svc.EncryptToJSON(secret, nil)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	// Rebind a fresh Service to the same KEK to prove decryption depends only on
	// the token-resident key, not on in-memory state from provisioning.
	svc2, err := NewService(ctx, p, keyprovider.KeyRef{Label: label})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	got, err := svc2.DecryptJSON(blob, nil)
	if err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: got %q want %q", got, secret)
	}
}

// TestHSMEnvelopeContextAndTamper checks context binding and tamper detection
// against a real HSM-held KEK.
func TestHSMEnvelopeContextAndTamper(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)
	label := uniqueKEKLabel(t)

	svc, err := ProvisionKEK(ctx, p, label, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK on HSM: %v", err)
	}

	encCtx := []byte("service=payments")
	env, err := svc.Encrypt([]byte("bound"), encCtx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := svc.Decrypt(env, encCtx); err != nil {
		t.Fatalf("decrypt with correct context: %v", err)
	}
	if _, err := svc.Decrypt(env, []byte("service=other")); err == nil {
		t.Fatal("expected failure with wrong context")
	}

	bad := *env
	bad.Ciphertext = append([]byte(nil), env.Ciphertext...)
	bad.Ciphertext[len(bad.Ciphertext)-1] ^= 0x80
	if _, err := svc.Decrypt(&bad, encCtx); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext")
	}
}
