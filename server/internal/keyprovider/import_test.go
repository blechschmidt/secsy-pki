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
	"math/big"
	"strings"
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

// TestImportKeyQualityGate covers the weak-key checks every import passes
// (Task 196).
//
// The CA-adoption path ran this gate from the start; `import-key` and the
// secret layer's signing-key import did not, so the single command whose
// purpose is to give a key a *more* trustworthy home would happily write a
// known-broken one onto a token. The gate now lives in the shared validation,
// so every caller and every backend inherits it.
//
// The exponent case is also a hardware-compatibility check in disguise: a
// YubiHSM 2 accepts e=65537 and nothing else, and its refusal is an
// undifferentiated CKR_ATTRIBUTE_VALUE_INVALID. Catching it here turns that
// into a sentence, before the device is touched.
func TestImportKeyQualityGate(t *testing.T) {
	weakExponent := rsaKeyWithExponent(t, 2048, 3)

	cases := []struct {
		name string
		key  crypto.PrivateKey
		want string
	}{
		{"exponent below 65537", weakExponent, "exponent 3"},
		{"even modulus", evenModulusKey(), "even"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := softwareTestProvider(t)
			_, err := ImportKey(context.Background(), p, ImportSpec{Label: "weak", PrivateKey: tc.key})
			if err == nil {
				t.Fatal("the key-quality gate accepted a key it must reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the rejection does not explain the defect (%q): %v", tc.want, err)
			}
		})
	}

	// A sound key must still pass: the gate has to be a filter, not a wall.
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := softwareTestProvider(t)
	if _, err := ImportKey(context.Background(), p, ImportSpec{Label: "good", PrivateKey: good}); err != nil {
		t.Fatalf("a sound RSA-2048 key was rejected: %v", err)
	}
}

// TestImportKeyRejectsUnnamedRSASize checks the size vocabulary at the provider
// boundary. The message has to reach the operator through the wrapping, which
// is the part a unit test on PrivateKeyType alone would not catch.
func TestImportKeyRejectsUnnamedRSASize(t *testing.T) {
	p := softwareTestProvider(t)
	odd := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: oddModulus(2560), E: 65537}}
	_, err := ImportKey(context.Background(), p, ImportSpec{Label: "odd", PrivateKey: odd})
	if err == nil {
		t.Fatal("a 2560-bit RSA key was accepted")
	}
	for _, want := range []string{"2560 bits", "2048, 3072, or 4096"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q: %v", want, err)
		}
	}
}

func oddModulus(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.Add(n, big.NewInt(1))
}

// evenModulusKey is structurally impossible for a real RSA key (a product of
// two odd primes is odd) and stands in for malformed or crafted key material.
func evenModulusKey() *rsa.PrivateKey {
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: oddModulus(2048).Add(oddModulus(2048), big.NewInt(1)), E: 65537}}
}

// rsaKeyWithExponent builds a valid RSA key with a chosen public exponent,
// which crypto/rsa will not do: GenerateKey fixes e at 65537.
func rsaKeyWithExponent(t *testing.T, bits, e int) *rsa.PrivateKey {
	t.Helper()
	one := big.NewInt(1)
	E := big.NewInt(int64(e))
	for attempt := 0; attempt < 400; attempt++ {
		half := bits / 2
		p, err := rand.Prime(rand.Reader, half)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, bits-half)
		if err != nil {
			t.Fatal(err)
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		if new(big.Int).GCD(nil, nil, phi, E).Cmp(one) != 0 {
			continue
		}
		d := new(big.Int).ModInverse(E, phi)
		if d == nil {
			continue
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: e}, D: d, Primes: []*big.Int{p, q}}
		k.Precompute()
		if k.Validate() != nil {
			continue
		}
		return k
	}
	t.Fatalf("could not build a %d-bit RSA key with exponent %d", bits, e)
	return nil
}
