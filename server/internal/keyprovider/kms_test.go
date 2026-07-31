package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// newFakeKMSProvider builds a KMSProvider over the in-memory fake backend, the
// same wiring keyprovider.New(cfg) produces for kms.backend=fake.
func newFakeKMSProvider(t *testing.T) *KMSProvider {
	t.Helper()
	p, err := NewKMSProvider(KMSSettings{Backend: KMSBackendFake, KeyPrefix: "secsy/"})
	if err != nil {
		t.Fatalf("NewKMSProvider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// TestKMSGenerateResolveSign exercises the full provider surface for every
// KMS-supported key type: generate, resolve by label, export the public key, and
// sign a digest that must verify against the exported public half.
func TestKMSGenerateResolveSign(t *testing.T) {
	ctx := context.Background()
	for _, keyType := range []string{
		KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521,
		KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096,
	} {
		t.Run(keyType, func(t *testing.T) {
			p := newFakeKMSProvider(t)
			label := "role-" + keyType

			gen, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if gen.KeyType != keyType {
				t.Errorf("KeyType = %q, want %q", gen.KeyType, keyType)
			}
			if gen.PublicKey == nil {
				t.Fatal("nil public key")
			}

			found, err := p.FindKey(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("FindKey: %v", err)
			}
			if found.URI != gen.URI {
				t.Errorf("FindKey URI = %q, want %q", found.URI, gen.URI)
			}

			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			digest := sha256.Sum256([]byte("hello kms"))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			verifyDigest(t, gen.PublicKey, digest[:], sig, false)
		})
	}
}

// TestKMSSignRSAPSS verifies RSA-PSS is selected when the caller passes
// *rsa.PSSOptions, exercising the pss branch of the signer.
func TestKMSSignRSAPSS(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "pss", KeyType: KeyTypeRSA2048}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "pss"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	digest := sha256.Sum256([]byte("pss message"))
	sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}
	verifyDigest(t, signer.Public(), digest[:], sig, true)
}

// TestKMSSignsX509Certificate is the end-to-end guarantee that matters for the
// CA/TSA/OCSP roles: a certificate signed through the KMS signer verifies against
// the KMS public key, using the real x509 signing path (not a hand-rolled digest).
func TestKMSSignsX509Certificate(t *testing.T) {
	ctx := context.Background()
	for _, keyType := range []string{KeyTypeECDSAP256, KeyTypeRSA2048} {
		t.Run(keyType, func(t *testing.T) {
			p := newFakeKMSProvider(t)
			if _, err := p.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: keyType}); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signer, err := p.Signer(ctx, KeyRef{Label: "ca"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "KMS Root CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
			if err != nil {
				t.Fatalf("CreateCertificate: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Fatalf("self-signature verification failed: %v", err)
			}
		})
	}
}

// TestKMSListKeys checks the inventory surface reports keys as non-extractable and
// sensitive — the cloud-KMS trust boundary.
func TestKMSListKeys(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	for _, l := range []string{"ca", "tsa", "ocsp"} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: l, KeyType: KeyTypeECDSAP256}); err != nil {
			t.Fatalf("GenerateKey %s: %v", l, err)
		}
	}
	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("ListKeys returned %d keys, want 3", len(keys))
	}
	for _, k := range keys {
		if k.Extractable {
			t.Errorf("key %q reported Extractable=true; cloud KMS keys must be non-extractable", k.Label)
		}
		if !k.Sensitive {
			t.Errorf("key %q reported Sensitive=false", k.Label)
		}
	}
}

// TestKMSPing confirms the provider satisfies Prober and the instrumented wrapper
// forwards the probe.
func TestKMSPing(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	prober, ok := Instrument(p).(Prober)
	if !ok {
		t.Fatal("instrumented KMS provider does not expose Prober")
	}
	if err := prober.Ping(ctx); err != nil {
		t.Fatalf("instrumented Ping: %v", err)
	}
}

// TestKMSDuplicateLabelRejected mirrors the PKCS#11/software contract: a second
// key with an existing label is an error.
func TestKMSDuplicateLabelRejected(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err == nil {
		t.Fatal("expected duplicate label to be rejected")
	}
}

// TestKMSRejectsUnsupportedKeyType confirms Ed25519 and PQC are rejected with a
// clear error, since no cloud KMS offers them for these signing roles.
func TestKMSRejectsUnsupportedKeyType(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	for _, kt := range []string{KeyTypeEd25519, KeyTypeMLDSA65} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: "x-" + kt, KeyType: kt}); err == nil {
			t.Errorf("GenerateKey(%s) unexpectedly succeeded", kt)
		}
	}
}

// TestKMSFindNotFound checks the ErrKeyNotFound contract.
func TestKMSFindNotFound(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	if _, err := p.FindKey(ctx, KeyRef{Label: "nope"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestKMSViaNewConfig verifies the public keyprovider.New entry point wires the
// KMS backend from Config, exactly as the server and secsy-ca do.
func TestKMSViaNewConfig(t *testing.T) {
	p, err := New(Config{Type: ProviderKMS, KMS: KMSSettings{Backend: KMSBackendFake}})
	if err != nil {
		t.Fatalf("New(kms): %v", err)
	}
	defer p.Close()
	if p.Name() != string(ProviderKMS) {
		t.Errorf("Name = %q, want %q", p.Name(), ProviderKMS)
	}
}

// verifyDigest verifies a signature over a precomputed SHA-256 digest against the
// given public key, dispatching by key family.
func verifyDigest(t *testing.T, pub crypto.PublicKey, digest, sig []byte, pss bool) {
	t.Helper()
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			t.Fatal("ECDSA signature failed verification")
		}
	case *rsa.PublicKey:
		if pss {
			if err := rsa.VerifyPSS(key, crypto.SHA256, digest, sig, nil); err != nil {
				t.Fatalf("RSA-PSS verification failed: %v", err)
			}
		} else if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig); err != nil {
			t.Fatalf("RSA PKCS1v15 verification failed: %v", err)
		}
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
}
