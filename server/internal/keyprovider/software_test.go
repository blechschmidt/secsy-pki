package keyprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func newTestSoftwareProvider(t *testing.T) *SoftwareProvider {
	t.Helper()
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	return p
}

func TestSoftwareGenerateAllKeyTypes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		keyType string
		check   func(t *testing.T, info *KeyInfo)
	}{
		{KeyTypeEd25519, func(t *testing.T, info *KeyInfo) {
			if _, ok := info.PublicKey.(ed25519.PublicKey); !ok {
				t.Fatalf("expected ed25519 public key, got %T", info.PublicKey)
			}
		}},
		{KeyTypeECDSAP256, func(t *testing.T, info *KeyInfo) {
			if _, ok := info.PublicKey.(*ecdsa.PublicKey); !ok {
				t.Fatalf("expected ecdsa public key, got %T", info.PublicKey)
			}
		}},
		{KeyTypeECDSAP384, nil},
		{KeyTypeRSA2048, func(t *testing.T, info *KeyInfo) {
			if _, ok := info.PublicKey.(*rsa.PublicKey); !ok {
				t.Fatalf("expected rsa public key, got %T", info.PublicKey)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.keyType, func(t *testing.T) {
			p := newTestSoftwareProvider(t)
			info, err := p.GenerateKey(ctx, KeySpec{Label: "k", KeyType: tc.keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if info.KeyType != tc.keyType {
				t.Errorf("KeyType = %q, want %q", info.KeyType, tc.keyType)
			}
			if info.URI != "software:k" {
				t.Errorf("URI = %q", info.URI)
			}
			if info.SSHPublicKey == "" {
				t.Error("SSHPublicKey is empty")
			}
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(info.SSHPublicKey)); err != nil {
				t.Errorf("SSHPublicKey does not parse: %v", err)
			}
			if tc.check != nil {
				tc.check(t, info)
			}
		})
	}
}

func TestSoftwareKeyTypeAliases(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	// "rsa" and "ecdsa" are aliases that should normalize.
	info, err := p.GenerateKey(ctx, KeySpec{Label: "aliased", KeyType: "ecdsa"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if info.KeyType != KeyTypeECDSAP256 {
		t.Errorf("KeyType = %q, want %q", info.KeyType, KeyTypeECDSAP256)
	}
}

func TestSoftwareGenerateDuplicate(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeEd25519}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeEd25519}); err == nil {
		t.Fatal("expected error generating duplicate key")
	}
}

func TestSoftwareFindAndPublicKey(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	gen, err := p.GenerateKey(ctx, KeySpec{Label: "findme", KeyType: KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	found, err := p.FindKey(ctx, KeyRef{Label: "findme"})
	if err != nil {
		t.Fatalf("FindKey: %v", err)
	}
	if found.SSHPublicKey != gen.SSHPublicKey {
		t.Errorf("FindKey public key mismatch:\n got %q\nwant %q", found.SSHPublicKey, gen.SSHPublicKey)
	}

	pub, err := p.PublicKey(ctx, KeyRef{Label: "findme"})
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}
}

func TestSoftwareListKeys(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)

	if keys, err := p.ListKeys(ctx); err != nil {
		t.Fatalf("ListKeys on empty keystore: %v", err)
	} else if len(keys) != 0 {
		t.Fatalf("expected empty inventory, got %d", len(keys))
	}

	for _, lbl := range []string{"alpha", "beta"} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: lbl, KeyType: KeyTypeECDSAP256}); err != nil {
			t.Fatalf("GenerateKey %q: %v", lbl, err)
		}
	}

	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	for _, k := range keys {
		if k.KeyType != KeyTypeECDSAP256 {
			t.Errorf("key %q type = %q, want %q", k.Label, k.KeyType, KeyTypeECDSAP256)
		}
		// The software backend stores keys as files — it must honestly report
		// them as extractable, which is why it is unfit for production CA keys.
		if !k.Extractable {
			t.Errorf("software key %q should report Extractable=true", k.Label)
		}
	}
}

func TestSoftwareFindNotFound(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	_, err := p.FindKey(ctx, KeyRef{Label: "ghost"})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareRefRequiresIdentifier(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	if _, err := p.Signer(ctx, KeyRef{}); err == nil {
		t.Fatal("expected error for empty key reference")
	}
}

func TestSoftwareLabelPathTraversal(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	for _, bad := range []string{"../escape", "sub/dir", ".."} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: bad, KeyType: KeyTypeEd25519}); err == nil {
			t.Errorf("expected error for label %q", bad)
		}
	}
}

func TestSoftwarePrivateKeyPermissions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "perm", KeyType: KeyTypeEd25519}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "perm.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 600", fi.Mode().Perm())
	}
	// Confirm the stored file is a PKCS#8 private key and not, e.g., a public key.
	data, _ := os.ReadFile(filepath.Join(dir, "perm.key"))
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY PEM, got %v", block)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("stored key is not valid PKCS#8: %v", err)
	}
}

// TestSoftwareSignerSignsSSHCertificate proves the provider's signer plugs into
// the existing SSH certificate signing path and produces a verifiable cert.
func TestSoftwareSignerSignsSSHCertificate(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	caInfo, err := p.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: KeyTypeEd25519})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if signer.KeyType() != KeyTypeEd25519 {
		t.Errorf("signer KeyType = %q", signer.KeyType())
	}

	// A user key to be certified.
	userInfo, err := p.GenerateKey(ctx, KeySpec{Label: "user", KeyType: KeyTypeECDSAP256})
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := pki.SignSSHCertificate(
		signer,
		[]byte(userInfo.SSHPublicKey),
		ssh.UserCert,
		"key-id",
		[]string{"alice"},
		time.Now().Add(-time.Minute),
		time.Now().Add(time.Hour),
		nil, nil,
	)
	if err != nil {
		t.Fatalf("SignSSHCertificate: %v", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("parsing signed cert: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected certificate, got %T", pub)
	}

	// Verify the certificate was signed by our CA key.
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caInfo.SSHPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caPub.Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("certificate failed verification: %v", err)
	}
}

// TestSoftwareSignerSignsX509 proves the provider's signer can issue an X.509
// certificate from a CSR through the existing signing path.
func TestSoftwareSignerSignsX509(t *testing.T) {
	ctx := context.Background()
	p := newTestSoftwareProvider(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "x509ca", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatal(err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "x509ca"})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()

	csrPEM := makeTestCSR(t)
	certPEM, serial, err := pki.SignX509Certificate(signer, csrPEM, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SignX509Certificate: %v", err)
	}
	if serial == "" {
		t.Error("empty serial")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("signed cert is not PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parsing signed cert: %v", err)
	}
}

func makeTestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}
