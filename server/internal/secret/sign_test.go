package secret

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeSigningKeyStore is an in-memory SigningKeyStore for the unit tests, so they
// exercise the orchestration without the database package.
type fakeSigningKeyStore struct {
	rows map[string]*models.SigningKey // keyed by tenant\x00name
}

func newFakeSigningKeyStore() *fakeSigningKeyStore {
	return &fakeSigningKeyStore{rows: map[string]*models.SigningKey{}}
}

func skKey(tenant, name string) string { return tenant + "\x00" + name }

func (s *fakeSigningKeyStore) GetSigningKey(tenant, name string) (*models.SigningKey, error) {
	return s.rows[skKey(tenant, name)], nil
}

func (s *fakeSigningKeyStore) InsertSigningKey(k *models.SigningKey) error {
	key := skKey(k.TenantID, k.Name)
	if _, ok := s.rows[key]; ok {
		return errors.New("duplicate")
	}
	s.rows[key] = k
	return nil
}

func (s *fakeSigningKeyStore) ListSigningKeys(tenant string) ([]*models.SigningKey, error) {
	var out []*models.SigningKey
	for _, r := range s.rows {
		if r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

func newSoftwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	return p
}

func TestNormalizeSigningAlgorithm(t *testing.T) {
	cases := map[string]SigningAlgorithm{
		"ecdsa-p256":          AlgECDSAP256,
		"P256":                AlgECDSAP256,
		"ecdsa-sha2-nistp384": AlgECDSAP384,
		"ecdsa-p521":          AlgECDSAP521,
		"es512":               AlgECDSAP521,
		"ed25519":             AlgEd25519,
		"EdDSA":               AlgEd25519,
		"rsa-pss-2048":        AlgRSAPSS2048,
		"rsa-pss-3072":        AlgRSAPSS3072,
		"RSA-PSS-4096":        AlgRSAPSS4096,
		"rsa-pkcs1v15-2048":   AlgRSAPKCS1v152048,
		"rsa-3072":            AlgRSAPKCS1v153072,
		"rsa-4096":            AlgRSAPKCS1v154096,
	}
	for in, want := range cases {
		got, err := NormalizeSigningAlgorithm(in)
		if err != nil {
			t.Errorf("NormalizeSigningAlgorithm(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeSigningAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeSigningAlgorithm("rsa-1024"); err == nil {
		t.Error("expected error for unsupported algorithm rsa-1024")
	}
}

func TestParseHash(t *testing.T) {
	for in, want := range map[string]crypto.Hash{
		"sha256": crypto.SHA256, "sha-384": crypto.SHA384, "sha512": crypto.SHA512,
	} {
		got, err := ParseHash(in)
		if err != nil || got != want {
			t.Errorf("ParseHash(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseHash("md5"); err == nil {
		t.Error("expected error for md5")
	}
}

// signableAlgorithms is the set exercised by the round-trip tests. ECDSA (all
// curves) and Ed25519 are cheap; the larger RSA keys (3072/4096) are slow to
// generate in software, so they are skipped under -short.
func signableAlgorithms(short bool) []SigningAlgorithm {
	algs := []SigningAlgorithm{
		AlgECDSAP256, AlgECDSAP384, AlgECDSAP521, AlgEd25519,
		AlgRSAPSS2048, AlgRSAPKCS1v152048,
	}
	if !short {
		algs = append(algs,
			AlgRSAPSS3072, AlgRSAPKCS1v153072,
			AlgRSAPSS4096, AlgRSAPKCS1v154096,
		)
	}
	return algs
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	msg := []byte("the quick brown fox jumps over the lazy dog")

	for _, alg := range signableAlgorithms(testing.Short()) {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
				TenantID: "default", Name: "k-" + string(alg), Algorithm: alg, CreatedBy: "test",
			})
			if err != nil {
				t.Fatalf("CreateSigningKey: %v", err)
			}
			if row.PublicKeyDER == "" || row.KeyRef == "" {
				t.Fatal("row missing public key or key ref")
			}

			res, err := Sign(ctx, prov, row, msg, "", false)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(res.Signature) == 0 {
				t.Fatal("empty signature")
			}

			// Correct signature verifies.
			ok, err := Verify(row, msg, res.Signature, "", false)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("valid signature failed to verify")
			}

			// Tampered message does not verify.
			bad := append([]byte{}, msg...)
			bad[0] ^= 0xff
			if ok, _ := Verify(row, bad, res.Signature, "", false); ok {
				t.Fatal("tampered message verified")
			}

			// Tampered signature does not verify.
			badSig := append([]byte{}, res.Signature...)
			badSig[len(badSig)-1] ^= 0xff
			if ok, _ := Verify(row, msg, badSig, "", false); ok {
				t.Fatal("tampered signature verified")
			}
		})
	}
}

func TestSignVerifyPreHashed(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	msg := []byte("pre-hash me")
	sum := sha256.Sum256(msg)

	row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
		TenantID: "default", Name: "k", Algorithm: AlgECDSAP256, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}

	// Signing the message vs. signing its digest (prehashed) both verify both ways:
	// the digest is the same, so the signatures are interchangeable for verify.
	resMsg, err := Sign(ctx, prov, row, msg, "sha256", false)
	if err != nil {
		t.Fatalf("Sign(message): %v", err)
	}
	resDigest, err := Sign(ctx, prov, row, sum[:], "sha256", true)
	if err != nil {
		t.Fatalf("Sign(prehashed): %v", err)
	}
	if ok, _ := Verify(row, sum[:], resMsg.Signature, "sha256", true); !ok {
		t.Error("message signature did not verify against the digest (prehashed)")
	}
	if ok, _ := Verify(row, msg, resDigest.Signature, "sha256", false); !ok {
		t.Error("prehashed signature did not verify against the message")
	}

	// A wrong-length pre-hash is a SignInputError.
	_, err = Sign(ctx, prov, row, []byte("short"), "sha256", true)
	var sie *SignInputError
	if !errors.As(err, &sie) {
		t.Errorf("expected SignInputError for wrong-length pre-hash, got %v", err)
	}
}

func TestEd25519RejectsHashAndPrehash(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	msg := []byte("ed25519 signs the message directly")

	row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
		TenantID: "default", Name: "ed", Algorithm: AlgEd25519, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}

	// A plain sign (no hash, no prehash) round-trips and reports "none" for hash.
	res, err := Sign(ctx, prov, row, msg, "", false)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if HashName(res.Hash) != "none" {
		t.Errorf("ed25519 hash = %q, want none", HashName(res.Hash))
	}
	if ok, err := Verify(row, msg, res.Signature, "", false); err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil)", ok, err)
	}

	// A caller-specified hash is a SignInputError (fail closed, not silently ignored).
	var sie *SignInputError
	if _, err := Sign(ctx, prov, row, msg, "sha256", false); !errors.As(err, &sie) {
		t.Errorf("Sign(ed25519, hash=sha256): got %v, want SignInputError", err)
	}
	// A pre-hashed request is likewise rejected.
	if _, err := Sign(ctx, prov, row, msg, "", true); !errors.As(err, &sie) {
		t.Errorf("Sign(ed25519, prehashed): got %v, want SignInputError", err)
	}
	if _, err := Verify(row, msg, res.Signature, "sha256", false); !errors.As(err, &sie) {
		t.Errorf("Verify(ed25519, hash=sha256): got %v, want SignInputError", err)
	}
}

func TestSignSelectableHashIsBound(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	msg := []byte("hash binding")

	row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
		TenantID: "default", Name: "k", Algorithm: AlgECDSAP256, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	res, err := Sign(ctx, prov, row, msg, "sha512", false)
	if err != nil {
		t.Fatalf("Sign(sha512): %v", err)
	}
	// Verifying with the same hash succeeds; with a different hash the digest
	// differs, so verification must fail.
	if ok, _ := Verify(row, msg, res.Signature, "sha512", false); !ok {
		t.Error("sha512 signature did not verify with sha512")
	}
	if ok, _ := Verify(row, msg, res.Signature, "sha256", false); ok {
		t.Error("sha512 signature verified under sha256 (hash not bound)")
	}
}

func TestVerifyWithSuppliedPublicKey(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	msg := []byte("verify me against a supplied public key")

	for _, alg := range []SigningAlgorithm{AlgECDSAP256, AlgEd25519, AlgRSAPSS2048} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
				TenantID: "default", Name: "sk-" + string(alg), Algorithm: alg, CreatedBy: "test",
			})
			if err != nil {
				t.Fatalf("CreateSigningKey: %v", err)
			}
			res, err := Sign(ctx, prov, row, msg, "", false)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// Verify against the exported public key (PEM), parsed the way an
			// external caller would supply it — no stored row.
			pemBytes, err := PublicKeyPEM(row)
			if err != nil {
				t.Fatalf("PublicKeyPEM: %v", err)
			}
			pub, err := ParsePublicKey(pemBytes)
			if err != nil {
				t.Fatalf("ParsePublicKey(PEM): %v", err)
			}
			ok, err := VerifyWithPublicKey(alg, pub, msg, res.Signature, "", false)
			if err != nil || !ok {
				t.Fatalf("VerifyWithPublicKey(PEM) = (%v, %v), want (true, nil)", ok, err)
			}

			// DER form parses too.
			der, err := PublicKeyDER(row)
			if err != nil {
				t.Fatalf("PublicKeyDER: %v", err)
			}
			if _, err := ParsePublicKey(der); err != nil {
				t.Fatalf("ParsePublicKey(DER): %v", err)
			}

			// Tampered message does not verify (and is not an error).
			bad := append([]byte{}, msg...)
			bad[0] ^= 0xff
			if ok, _ := VerifyWithPublicKey(alg, pub, bad, res.Signature, "", false); ok {
				t.Fatal("tampered message verified against supplied key")
			}
		})
	}

	// A public key that does not match the stated algorithm's family is a
	// SignInputError, not a silent false.
	ecRow, _ := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
		TenantID: "default", Name: "ec", Algorithm: AlgECDSAP256, CreatedBy: "test",
	})
	ecPub, _ := ParsePublicKey(mustPEM(t, ecRow))
	var sie *SignInputError
	if _, err := VerifyWithPublicKey(AlgRSAPSS2048, ecPub, msg, []byte("sig"), "", false); !errors.As(err, &sie) {
		t.Errorf("algorithm/key mismatch: got %v, want SignInputError", err)
	}
	// A garbage public key is a SignInputError from ParsePublicKey.
	if _, err := ParsePublicKey([]byte("not a key")); !errors.As(err, &sie) {
		t.Errorf("ParsePublicKey(garbage): got %v, want SignInputError", err)
	}
}

func mustPEM(t *testing.T, row *models.SigningKey) []byte {
	t.Helper()
	b, err := PublicKeyPEM(row)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	return b
}

func TestCreateSigningKeyDuplicateName(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	spec := CreateSigningKeySpec{TenantID: "default", Name: "dup", Algorithm: AlgECDSAP256, CreatedBy: "test"}
	if _, err := CreateSigningKey(ctx, prov, store, spec); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := CreateSigningKey(ctx, prov, store, spec); !errors.Is(err, ErrSigningKeyNameTaken) {
		t.Errorf("second create: got %v, want ErrSigningKeyNameTaken", err)
	}
}

func TestPublicKeyExportRoundTrips(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
		TenantID: "default", Name: "k", Algorithm: AlgECDSAP384, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	pemBytes, err := PublicKeyPEM(row)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	if len(pemBytes) == 0 || string(pemBytes[:11]) != "-----BEGIN " {
		t.Fatalf("unexpected PEM: %q", pemBytes)
	}
	if _, err := PublicKey(row); err != nil {
		t.Fatalf("PublicKey parse: %v", err)
	}
}
