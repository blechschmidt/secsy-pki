package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// softwareService provisions a software-backed KEK in a temp keystore and
// returns a Service bound to it. These tests need no HSM.
func softwareService(t *testing.T, keyType string) (*Service, keyprovider.Provider) {
	t.Helper()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	svc, err := ProvisionKEK(context.Background(), prov, "test-kek", keyType)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	return svc, prov
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)

	cases := [][]byte{
		[]byte("hunter2"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 4096),
		{0x00, 0xff, 0x10, 0x7f},
	}
	for _, pt := range cases {
		blob, err := svc.EncryptToJSON(pt, nil)
		if err != nil {
			t.Fatalf("EncryptToJSON: %v", err)
		}
		got, err := svc.DecryptJSON(blob, nil)
		if err != nil {
			t.Fatalf("DecryptJSON: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("round trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestCiphertextIsVersionedAndOpaque(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)
	secret := []byte("s3cr3t-password")

	blob, err := svc.EncryptToJSON(secret, nil)
	if err != nil {
		t.Fatalf("EncryptToJSON: %v", err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("plaintext leaked into ciphertext blob")
	}

	var env Envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Version != FormatVersion1 {
		t.Errorf("version = %d, want %d", env.Version, FormatVersion1)
	}
	if env.WrapAlg != AlgRSAOAEPSHA256 || env.DataAlg != AlgAES256GCM {
		t.Errorf("unexpected algs: wrap=%q data=%q", env.WrapAlg, env.DataAlg)
	}
	if env.KEKLabel != "test-kek" {
		t.Errorf("kek label = %q", env.KEKLabel)
	}
}

func TestNonceAndDEKAreFreshPerMessage(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)
	e1, _ := svc.Encrypt([]byte("same"), nil)
	e2, _ := svc.Encrypt([]byte("same"), nil)
	if bytes.Equal(e1.Nonce, e2.Nonce) {
		t.Error("nonce reused across messages")
	}
	if bytes.Equal(e1.WrappedDEK, e2.WrappedDEK) {
		t.Error("wrapped DEK identical across messages (DEK reuse or deterministic wrap)")
	}
	if bytes.Equal(e1.Ciphertext, e2.Ciphertext) {
		t.Error("ciphertext identical for same plaintext")
	}
}

func TestTamperDetection(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)
	env, err := svc.Encrypt([]byte("integrity matters"), nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flip ciphertext byte", func(t *testing.T) {
		bad := *env
		bad.Ciphertext = append([]byte(nil), env.Ciphertext...)
		bad.Ciphertext[0] ^= 0x01
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected auth failure on tampered ciphertext")
		}
	})

	t.Run("swap data algorithm", func(t *testing.T) {
		bad := *env
		bad.DataAlg = "AES-128-GCM"
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected failure when algorithm field is altered")
		}
	})

	t.Run("alter kek label bound in AAD", func(t *testing.T) {
		// Change the label but keep validate() happy by round-tripping; the AAD
		// mismatch must still cause a GCM failure.
		bad := *env
		bad.KEKLabel = "attacker-kek"
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected failure when KEK label is altered")
		}
	})
}

func TestEncryptionContextBinding(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)
	ctxData := []byte("tenant=acme;field=db_password")

	env, err := svc.Encrypt([]byte("bound secret"), ctxData)
	if err != nil {
		t.Fatal(err)
	}
	if !env.ContextBound {
		t.Fatal("ContextBound flag not set")
	}

	// Correct context succeeds.
	if _, err := svc.Decrypt(env, ctxData); err != nil {
		t.Fatalf("decrypt with correct context: %v", err)
	}
	// Wrong context fails.
	if _, err := svc.Decrypt(env, []byte("tenant=evil")); err == nil {
		t.Fatal("expected failure with wrong context")
	}
	// Missing context fails.
	if _, err := svc.Decrypt(env, nil); err == nil {
		t.Fatal("expected failure with missing context")
	}
}

func TestContextRejectedWhenNotBound(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA2048)
	env, _ := svc.Encrypt([]byte("no context"), nil)
	if _, err := svc.Decrypt(env, []byte("unexpected")); err == nil {
		t.Fatal("expected failure supplying context to a non-context ciphertext")
	}
}

func TestUnmarshalRejectsBadEnvelopes(t *testing.T) {
	cases := map[string]string{
		"bad version":    `{"version":99,"wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","kek_label":"k","wrapped_dek":"AA==","nonce":"AA==","ciphertext":"AA=="}`,
		"bad wrap alg":   `{"version":1,"wrap_alg":"RSA-PKCS1","data_alg":"AES-256-GCM","kek_label":"k","wrapped_dek":"AA==","nonce":"AA==","ciphertext":"AA=="}`,
		"missing label":  `{"version":1,"wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","wrapped_dek":"AA==","nonce":"AA==","ciphertext":"AA=="}`,
		"unknown field":  `{"version":1,"wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","kek_label":"k","wrapped_dek":"AA==","nonce":"AA==","ciphertext":"AA==","evil":1}`,
		"not json":       `not json at all`,
		"missing cipher": `{"version":1,"wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","kek_label":"k","nonce":"AA=="}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Unmarshal([]byte(in)); err == nil {
				t.Fatalf("expected Unmarshal to reject %s", name)
			}
		})
	}
}

func TestWrongKEKCannotDecrypt(t *testing.T) {
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	svcA, err := ProvisionKEK(context.Background(), prov, "kek-a", keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	svcB, err := ProvisionKEK(context.Background(), prov, "kek-b", keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatal(err)
	}

	env, err := svcA.Encrypt([]byte("only A can read"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svcB.Decrypt(env, nil); err == nil {
		t.Fatal("KEK B must not be able to decrypt KEK A's ciphertext")
	}
}

func TestProvisionKEKRejectsNonRSA(t *testing.T) {
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKEK(context.Background(), prov, "bad-kek", keyprovider.KeyTypeEd25519); err == nil {
		t.Fatal("expected ProvisionKEK to reject a non-RSA key type")
	}
}

func TestProvisionKEKDuplicateRejected(t *testing.T) {
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKEK(context.Background(), prov, "dup-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKEK(context.Background(), prov, "dup-kek", keyprovider.KeyTypeRSA2048); err == nil {
		t.Fatal("expected ProvisionKEK to refuse overwriting an existing KEK")
	}
}

func TestKEKInfo(t *testing.T) {
	svc, _ := softwareService(t, keyprovider.KeyTypeRSA4096)
	info := svc.KEKInfo()
	if info.Label != "test-kek" || info.KeyBits != 4096 || info.WrapAlg != AlgRSAOAEPSHA256 {
		t.Errorf("unexpected KEKInfo: %+v", info)
	}
}
