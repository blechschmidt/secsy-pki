package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
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

var errConcurrentVerify = errors.New("HSM signature failed verification")

// TestPKCS11ConcurrentSign exercises the session pool under concurrency: many
// goroutines sign through a single shared provider at once and every signature
// must verify against the key's public half. This is the regression guard for
// the pooled architecture — the previous open-per-operation design was unsafe
// under concurrency on SoftHSM (a per-application C_Logout/C_Finalize during one
// request's teardown corrupted another's in-flight session). Run under -race to
// also catch data races in the pool bookkeeping.
func TestPKCS11ConcurrentSign(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	label := uniqueLabel(t, "concurrent")
	gen, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, ok := gen.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", gen.PublicKey)
	}

	const goroutines = 32
	const perGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				errs <- err
				return
			}
			defer signer.Close()
			for i := 0; i < perGoroutine; i++ {
				digest := sha256.Sum256([]byte{seed, byte(i)})
				sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					errs <- errConcurrentVerify
					return
				}
			}
		}(byte(g))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent signing failed: %v", err)
	}
}

func TestPKCS11FindNotFound(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)
	if _, err := p.FindKey(ctx, KeyRef{Label: "definitely-does-not-exist-xyz"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestPKCS11Ping verifies the readiness connectivity probe succeeds against a
// reachable token, and that a wrong PIN is reported as an error (unready)
// without requiring any key to exist. It also confirms the probe survives the
// instrumented wrapper used in production.
func TestPKCS11Ping(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping against reachable token failed: %v", err)
	}

	// The instrumented wrapper must forward the probe.
	if prober, ok := Instrument(p).(Prober); !ok {
		t.Fatal("instrumented pkcs11 provider does not expose Prober")
	} else if err := prober.Ping(ctx); err != nil {
		t.Fatalf("instrumented Ping failed: %v", err)
	}

	// A bad PIN must surface as a probe failure, not a success. The pooled
	// provider validates the PIN when it builds its session pool (the login
	// round-trip). On SoftHSM the C_Login state is per-application, not
	// per-session: once any pool in the process is authenticated, a second
	// Login returns CKR_USER_ALREADY_LOGGED_IN regardless of the PIN supplied.
	// So we release the good provider's login first; otherwise the wrong PIN
	// would never reach a real login attempt. In production there is exactly
	// one provider per process, so its first login validates the PIN.
	if err := p.Close(); err != nil {
		t.Fatalf("closing good provider: %v", err)
	}
	bad, err := NewPKCS11Provider(PKCS11Settings{
		ModulePath: p.cfg.ModulePath,
		Pin:        "0000wrong",
		TokenLabel: p.cfg.TokenLabel,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	if err := bad.Ping(ctx); err == nil {
		t.Error("Ping with wrong PIN unexpectedly succeeded")
	}
}

// TestPKCS11GenerateDuplicateLabelRejected verifies the Provider contract that
// generating a second key with an existing label fails, rather than leaving the
// token with ambiguous duplicate-labeled objects (whose private/public halves
// can resolve to different key pairs and produce unverifiable signatures).
func TestPKCS11GenerateDuplicateLabelRejected(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	label := uniqueLabel(t, "dup")
	if _, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256}); err == nil {
		t.Fatal("expected duplicate-label GenerateKey to fail, got nil error")
	}
}

// TestPKCS11ListKeys verifies the KeyLister inventory: a freshly generated key
// appears in the listing with its label and canonical key type, and — crucially
// for the key non-extractability invariant — is reported as sensitive and
// non-extractable by the token. It also confirms the capability survives the
// instrumented wrapper used in production.
func TestPKCS11ListKeys(t *testing.T) {
	ctx := context.Background()
	p := pkcs11TestProvider(t)

	label := uniqueLabel(t, "inv")
	if _, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	var found *KeyDescriptor
	for i := range keys {
		if keys[i].Label == label {
			found = &keys[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("generated key %q not present in inventory of %d key(s)", label, len(keys))
	}
	if found.KeyType != KeyTypeECDSAP256 {
		t.Errorf("KeyType = %q, want %q", found.KeyType, KeyTypeECDSAP256)
	}
	if found.Extractable {
		t.Error("CA/KEK key must be non-extractable, but token reports it extractable")
	}
	if !found.Sensitive {
		t.Error("expected token to report the private key as sensitive")
	}

	if lister, ok := Instrument(p).(KeyLister); !ok {
		t.Fatal("instrumented pkcs11 provider does not expose KeyLister")
	} else if _, err := lister.ListKeys(ctx); err != nil {
		t.Fatalf("instrumented ListKeys: %v", err)
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
