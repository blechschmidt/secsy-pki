package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// Task 194: importing an existing key. The software backend is the one that can
// be exercised without hardware, so the contract lives here; the SoftHSM tests
// (import_softhsm_test.go) prove a real token behaves the same.

func softwareTestProvider(t *testing.T) *SoftwareProvider {
	t.Helper()
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	return p
}

func TestSoftwareImportKeyRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		key     any
		keyType string
	}{
		{"rsa-2048", rsaKey, KeyTypeRSA2048},
		{"ecdsa-p384", ecKey, KeyTypeECDSAP384},
		{"ed25519", edKey, KeyTypeEd25519},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := softwareTestProvider(t)
			ctx := context.Background()

			info, err := ImportKey(ctx, p, ImportSpec{Label: "imported", PrivateKey: tc.key})
			if err != nil {
				t.Fatalf("ImportKey: %v", err)
			}
			if info.KeyType != tc.keyType {
				t.Errorf("KeyType = %q, want %q", info.KeyType, tc.keyType)
			}

			// The key must be findable and usable afterwards, exactly like a
			// generated one — that is the whole contract.
			found, err := p.FindKey(ctx, KeyRef{Label: "imported"})
			if err != nil {
				t.Fatalf("FindKey after import: %v", err)
			}
			expected := tc.key.(crypto.Signer).Public()
			if !publicKeysMatch(found.PublicKey, expected) {
				t.Error("the stored key is not the one that was imported")
			}
			if err := VerifyKeyUsable(ctx, p, KeyRef{Label: "imported"}, expected); err != nil {
				t.Errorf("VerifyKeyUsable: %v", err)
			}
		})
	}
}

func TestImportKeyRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		spec ImportSpec
	}{
		{"no label", ImportSpec{PrivateKey: rsaKey}},
		{"no key", ImportSpec{Label: "x"}},
		{"undersized rsa", ImportSpec{Label: "x", PrivateKey: small}},
		{"non-rsa kek", ImportSpec{Label: "x", Usage: KeyUsageDecrypt, PrivateKey: ecKey}},
		{"unknown usage", ImportSpec{Label: "x", Usage: "wrap", PrivateKey: rsaKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := softwareTestProvider(t)
			if _, err := ImportKey(context.Background(), p, tc.spec); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestImportKeyRefusesDuplicateLabel guards the invariant that makes key lookup
// well-defined: one label, one key. Silently overwriting the key a CA record
// points at would be catastrophic and irreversible.
func TestImportKeyRefusesDuplicateLabel(t *testing.T) {
	p := softwareTestProvider(t)
	ctx := context.Background()
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportKey(ctx, p, ImportSpec{Label: "dup", PrivateKey: first}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := ImportKey(ctx, p, ImportSpec{Label: "dup", PrivateKey: second}); err == nil {
		t.Fatal("expected the second import under the same label to fail")
	}
	// The original must still be the one on file.
	if err := VerifyKeyUsable(ctx, p, KeyRef{Label: "dup"}, first.Public()); err != nil {
		t.Errorf("the original key was disturbed by the refused import: %v", err)
	}

	// A generated key must equally block a later import onto its label.
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "gen", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := ImportKey(ctx, p, ImportSpec{Label: "gen", PrivateKey: first}); err == nil {
		t.Fatal("expected import onto a generated key's label to fail")
	}
}

// TestImportUnsupportedBackend proves a backend that cannot adopt foreign key
// material says so, rather than being silently skipped or panicking.
func TestImportUnsupportedBackend(t *testing.T) {
	p := newFakeKMSProvider(t)
	if CanImport(p) {
		t.Fatal("the KMS backend must not advertise the import capability")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ImportKey(context.Background(), p, ImportSpec{Label: "x", PrivateKey: key})
	if !errors.Is(err, ErrImportUnsupported) {
		t.Fatalf("err = %v, want ErrImportUnsupported", err)
	}
}

// TestVerifyKeyUsableDetectsMismatch proves the post-import self-check actually
// discriminates: a key that is present but is not the expected one fails.
func TestVerifyKeyUsableDetectsMismatch(t *testing.T) {
	p := softwareTestProvider(t)
	ctx := context.Background()
	real, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportKey(ctx, p, ImportSpec{Label: "k", PrivateKey: real}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyUsable(ctx, p, KeyRef{Label: "k"}, other.Public()); err == nil {
		t.Fatal("expected VerifyKeyUsable to reject a different public key")
	}
	if err := VerifyKeyUsable(ctx, p, KeyRef{Label: "missing"}, real.Public()); err == nil {
		t.Fatal("expected VerifyKeyUsable to fail for an absent key")
	}
}

// TestInstrumentedProviderForwardsImport proves the capability survives the
// wrappers the server puts around every provider — otherwise import would work
// from the CLI and vanish in the server process.
func TestInstrumentedProviderForwardsImport(t *testing.T) {
	base := softwareTestProvider(t)
	wrapped := Instrument(base)
	if !CanImport(wrapped) {
		t.Fatal("the instrumented wrapper hides the import capability")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := ImportKey(context.Background(), wrapped, ImportSpec{Label: "wrapped", PrivateKey: key})
	if err != nil {
		t.Fatalf("ImportKey through the instrumented wrapper: %v", err)
	}
	if !publicKeysMatch(info.PublicKey, key.Public()) {
		t.Error("the wrapper returned a different key")
	}
}
