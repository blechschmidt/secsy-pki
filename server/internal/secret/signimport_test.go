package secret

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 194: adopting an application's existing signing key. The property that
// matters is continuity — signatures made by the imported key must still verify
// against the public half the application's clients already have.

func TestImportSigningKeyPreservesVerifiability(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		key     crypto.Signer
		alg     SigningAlgorithm
		wantAlg SigningAlgorithm
	}{
		{"ecdsa-derived", ecKey, "", AlgECDSAP384},
		{"ed25519-derived", edKey, "", AlgEd25519},
		{"rsa-pss-explicit", rsaKey, AlgRSAPSS2048, AlgRSAPSS2048},
		{"rsa-pkcs1v15-explicit", rsaKey, AlgRSAPKCS1v152048, AlgRSAPKCS1v152048},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := newSoftwareProvider(t)
			store := newFakeSigningKeyStore()

			row, err := ImportSigningKey(ctx, provider, store, ImportSigningKeySpec{
				TenantID: "t", Name: "release-signing", PrivateKey: tc.key, Algorithm: tc.alg,
			})
			if err != nil {
				t.Fatalf("ImportSigningKey: %v", err)
			}
			if SigningAlgorithm(row.Algorithm) != tc.wantAlg {
				t.Errorf("algorithm = %q, want %q", row.Algorithm, tc.wantAlg)
			}

			// The registry's public key must be the one the application's
			// clients already trust.
			pub, err := PublicKey(row)
			if err != nil {
				t.Fatal(err)
			}
			type equaler interface{ Equal(crypto.PublicKey) bool }
			if !pub.(equaler).Equal(tc.key.Public()) {
				t.Fatal("the registered public key is not the imported key's public half")
			}

			// And a signature made through the service must verify against it.
			data := []byte("release manifest v1.2.3")
			res, err := Sign(ctx, provider, row, data, "", false)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			ok, err := Verify(row, data, res.Signature, "", false)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("a signature from the imported key does not verify")
			}
		})
	}
}

func TestImportSigningKeyRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		spec    ImportSigningKeySpec
		wantErr string
	}{
		{"no name", ImportSigningKeySpec{TenantID: "t", PrivateKey: ecKey}, "name is required"},
		{"no tenant", ImportSigningKeySpec{Name: "n", PrivateKey: ecKey}, "tenant is required"},
		{"no key", ImportSigningKeySpec{TenantID: "t", Name: "n"}, "no private key"},
		{
			// RSA is the one case the key does not determine the scheme, and
			// guessing would produce signatures existing verifiers reject.
			name:    "rsa without an algorithm",
			spec:    ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: rsaKey},
			wantErr: "explicit algorithm",
		},
		{
			name:    "algorithm contradicts the key",
			spec:    ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: ecKey, Algorithm: AlgECDSAP521},
			wantErr: "expects a",
		},
		{
			name:    "algorithm contradicts the rsa modulus",
			spec:    ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: rsaKey, Algorithm: AlgRSAPSS4096},
			wantErr: "expects a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ImportSigningKey(context.Background(), newSoftwareProvider(t), newFakeSigningKeyStore(), tc.spec)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestImportSigningKeyDuplicateName checks the name collision is caught before
// key material is written, so a repeated import leaves no orphan behind.
func TestImportSigningKeyDuplicateName(t *testing.T) {
	ctx := context.Background()
	provider := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSigningKey(ctx, provider, store, ImportSigningKeySpec{
		TenantID: "t", Name: "dup", PrivateKey: key,
	}); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ImportSigningKey(ctx, provider, store, ImportSigningKeySpec{
		TenantID: "t", Name: "dup", PrivateKey: other,
	})
	if !errors.Is(err, ErrSigningKeyNameTaken) {
		t.Fatalf("err = %v, want ErrSigningKeyNameTaken", err)
	}
	// Exactly one key may have been written to the provider: the refused import
	// must not strand material under a label no registry row points at.
	keys, err := provider.(keyprovider.KeyLister).ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("provider holds %d keys, want 1", len(keys))
	}
}

// insertFailingStore is a SigningKeyStore whose INSERT fails. That is the failure
// mode the classification below exists for: it happens AFTER the key has been
// written into the provider, non-extractably, under a label only the row that
// failed to commit would have pointed at.
type insertFailingStore struct{ *fakeSigningKeyStore }

func (insertFailingStore) InsertSigningKey(*models.SigningKey) error {
	return errors.New("storing the signing key: database is locked")
}

// TestImportSigningKeyErrorClassification pins which failures are the CALLER's.
//
// Only material/algorithm rejections carry ErrSigningKeyMaterial, and only the
// host-side provider gates carry keyprovider.ErrImportRejected. Everything else —
// notably the registry INSERT — must carry NEITHER, because an API that answers
// "bad request" there invites the operator to retry the same body, and every retry
// mints a fresh id, hence a fresh label, hence another stranded non-extractable
// key on a device nobody can delete from. The REST surface classifies on exactly
// these sentinels (handlers/secret_sign_import.go), so this is where the split is
// guaranteed rather than in a status-code assertion.
func TestImportSigningKeyErrorClassification(t *testing.T) {
	ctx := context.Background()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		store        SigningKeyStore
		spec         ImportSigningKeySpec
		wantMaterial bool
	}{
		// The caller's: decided entirely by what arrived in the request.
		{"no key material", newFakeSigningKeyStore(),
			ImportSigningKeySpec{TenantID: "t", Name: "n"}, true},
		{"rsa without an algorithm", newFakeSigningKeyStore(),
			ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: rsaKey}, true},
		{"algorithm contradicts the key", newFakeSigningKeyStore(),
			ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: ecKey, Algorithm: AlgECDSAP521}, true},
		{"unsupported algorithm", newFakeSigningKeyStore(),
			ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: ecKey, Algorithm: "rsa-1024"}, true},
		{"unsupported key type", newFakeSigningKeyStore(),
			ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: struct{}{}}, true},
		// Ours: the key is already in the provider by the time this fails.
		{"the registry insert fails", insertFailingStore{newFakeSigningKeyStore()},
			ImportSigningKeySpec{TenantID: "t", Name: "n", PrivateKey: ecKey}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ImportSigningKey(ctx, newSoftwareProvider(t), tc.store, tc.spec)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ErrSigningKeyMaterial); got != tc.wantMaterial {
				t.Errorf("errors.Is(err, ErrSigningKeyMaterial) = %v, want %v for %v",
					got, tc.wantMaterial, err)
			}
			if !tc.wantMaterial && errors.Is(err, keyprovider.ErrImportRejected) {
				t.Errorf("a service-side failure must not look like a provider rejection either: %v", err)
			}
		})
	}
}
