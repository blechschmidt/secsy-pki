package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Task 194: importing an existing key onto a real PKCS#11 token. These tests
// need SoftHSM (see pkcs11TestProvider) and are the ones that matter: the
// C_CreateObject templates are where a subtly wrong encoding produces a key
// object that exists and signs garbage.

// TestPKCS11ImportKeyAllTypes imports each supported key type onto the token and
// proves the token now holds *that* key — not a lookalike — by signing with it
// and verifying against the public half of the original in-memory key.
func TestPKCS11ImportKeyAllTypes(t *testing.T) {
	p := pkcs11TestProvider(t)
	ctx := context.Background()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		key     crypto.Signer
		keyType string
	}{
		{"rsa2048", rsaKey, KeyTypeRSA2048},
		{"ecp256", ecKey, KeyTypeECDSAP256},
		{"ecp384", ec384, KeyTypeECDSAP384},
		{"ed25519", edKey, KeyTypeEd25519},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label := uniqueLabel(t, "import-"+tc.name)
			info, err := p.ImportKey(ctx, ImportSpec{Label: label, PrivateKey: tc.key})
			if err != nil {
				t.Fatalf("ImportKey: %v", err)
			}
			if info.KeyType != tc.keyType {
				t.Errorf("KeyType = %q, want %q", info.KeyType, tc.keyType)
			}
			if !publicKeysMatch(info.PublicKey, tc.key.Public()) {
				t.Fatal("the token returned a different public key than was imported")
			}

			// The decisive check: the token signs, and the signature verifies
			// under the original key's public half.
			if err := VerifyKeyUsable(ctx, p, KeyRef{Label: label}, tc.key.Public()); err != nil {
				t.Fatalf("the imported key does not sign correctly on the token: %v", err)
			}

			// Resolution by label must also work through the ordinary lookup
			// path, since every caller in the codebase addresses keys that way.
			found, err := p.FindKey(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("FindKey: %v", err)
			}
			if !publicKeysMatch(found.PublicKey, tc.key.Public()) {
				t.Error("FindKey resolved a different key")
			}
		})
	}
}

// TestPKCS11ImportKeyIsNonExtractable holds the line on the security invariant
// that makes an HSM worth having: once imported, the key must be no more
// extractable than a generated one. If this ever regresses, the migration story
// becomes "copy your root key into a box it can be copied out of".
func TestPKCS11ImportKeyIsNonExtractable(t *testing.T) {
	p := pkcs11TestProvider(t)
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	label := uniqueLabel(t, "import-attrs")
	if _, err := p.ImportKey(ctx, ImportSpec{Label: label, PrivateKey: key}); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	var found bool
	for _, k := range keys {
		if k.Label != label {
			continue
		}
		found = true
		if k.Extractable {
			t.Error("the imported key is CKA_EXTRACTABLE — it can be wrapped off the token")
		}
		if !k.Sensitive {
			t.Error("the imported key is not CKA_SENSITIVE — its value can be read via attributes")
		}
	}
	if !found {
		t.Fatalf("the imported key %q is not in the token inventory", label)
	}
}

// TestPKCS11ImportKeyRefusesDuplicateLabel proves the token path enforces the
// same one-label-one-key invariant as the software path. A duplicate CKA_LABEL
// makes lookups ambiguous, which historically produced signatures that failed
// to verify (see the note in GenerateKey).
func TestPKCS11ImportKeyRefusesDuplicateLabel(t *testing.T) {
	p := pkcs11TestProvider(t)
	ctx := context.Background()
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	label := uniqueLabel(t, "import-dup")
	if _, err := p.ImportKey(ctx, ImportSpec{Label: label, PrivateKey: first}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := p.ImportKey(ctx, ImportSpec{Label: label, PrivateKey: second}); err == nil {
		t.Fatal("expected a duplicate-label import to be refused")
	}
	if err := VerifyKeyUsable(ctx, p, KeyRef{Label: label}, first.Public()); err != nil {
		t.Errorf("the original key was disturbed by the refused import: %v", err)
	}
}

// TestPKCS11ImportedKeySignsCACertificate is the end-to-end proof of the
// migration story: a CA key that was generated outside the HSM is imported, and
// the token then signs a certificate that verifies under the CA's *existing*
// certificate — i.e. the adopted authority keeps working.
func TestPKCS11ImportedKeySignsCACertificate(t *testing.T) {
	p := pkcs11TestProvider(t)
	ctx := context.Background()

	// The legacy CA: key and self-signed certificate created in software, as
	// they would have been years ago.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	label := uniqueLabel(t, "import-ca")
	if _, err := p.ImportKey(ctx, ImportSpec{Label: label, PrivateKey: caKey}); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: label})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// The certificate is signed on the token, by the imported key.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("signing a leaf with the imported CA key: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	// It must verify under the CA's pre-existing certificate: the authority
	// survived the move intact.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("a certificate signed by the imported key does not chain to the legacy CA: %v", err)
	}
}

// TestPKCS11ImportRSAKEK covers the decrypt-usage template: an existing RSA
// key-encryption key imported for the envelope layer must unwrap on the token.
func TestPKCS11ImportRSAKEK(t *testing.T) {
	p := pkcs11TestProvider(t)
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	label := uniqueLabel(t, "import-kek")
	if _, err := p.ImportKey(ctx, ImportSpec{Label: label, Usage: KeyUsageDecrypt, PrivateKey: key}); err != nil {
		t.Fatalf("ImportKey(decrypt): %v", err)
	}

	dec, err := p.Decrypter(ctx, KeyRef{Label: label})
	if err != nil {
		t.Fatalf("Decrypter: %v", err)
	}
	defer dec.Close()

	// SoftHSM's RSA-OAEP is SHA-1 only, so the round trip uses SHA-1 here; the
	// envelope layer negotiates the hash the same way.
	secret := []byte("data encryption key")
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("unwrapping with the imported KEK: %v", err)
	}
	if string(pt) != string(secret) {
		t.Fatalf("unwrapped %q, want %q", pt, secret)
	}
	// A decrypt-only key must not have been given signing rights.
	if signer, err := p.Signer(ctx, KeyRef{Label: label}); err == nil {
		digest := sha256.Sum256([]byte("x"))
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
			t.Error("the imported key-encryption key was able to sign; CKA_SIGN should be false")
		}
		signer.Close()
	}
}
