//go:build sqlite

package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func intPtr(v int) *int { return &v }

// newTestManager builds a Manager backed by a fresh sqlite database and the
// given provider.
func newTestManager(t *testing.T, provider keyprovider.Provider) *Manager {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "ca-test.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewManager(db, provider)
}

// softwareProvider returns a keystore-backed provider in a temp directory.
func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// pkcs11Provider returns a SoftHSM-backed provider, or skips if not configured.
func pkcs11Provider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: module,
			Pin:        pin,
			TokenLabel: token,
		},
	})
	if err != nil {
		t.Fatalf("pkcs11 provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// uniqueLabel avoids collisions across runs against a persistent SoftHSM token:
// a fresh random suffix is drawn per call so a re-run never reuses a CKA_LABEL.
func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "catest-" + base + "-" + hex.EncodeToString(b[:])
}

func TestCAHierarchy(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runCAHierarchy(t, mk(t), name)
		})
	}
}

func runCAHierarchy(t *testing.T, provider keyprovider.Provider, tag string) {
	ctx := context.Background()
	mgr := newTestManager(t, provider)

	keyType := keyprovider.KeyTypeECDSAP256
	rootLabel := uniqueLabel(t, tag+"-root")
	interLabel := uniqueLabel(t, tag+"-inter")

	root, err := mgr.InitRoot(ctx, RootSpec{
		Label:      rootLabel,
		KeyType:    keyType,
		Subject:    PKIXName(models.CASubject{CommonName: "Unit Root CA", Organization: "Secsy"}),
		Validity:   10 * 365 * 24 * time.Hour,
		MaxPathLen: nil,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	if root.Serial != "1" {
		t.Errorf("root serial = %q, want 1", root.Serial)
	}
	if root.ParentID != nil {
		t.Errorf("root should have no parent, got %v", *root.ParentID)
	}
	rootCert := mustParse(t, root.Certificate)
	if !rootCert.IsCA {
		t.Error("root cert is not a CA")
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("root is not properly self-signed: %v", err)
	}

	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:   root.ID,
		Label:      interLabel,
		KeyType:    keyType,
		Subject:    PKIXName(models.CASubject{CommonName: "Unit Intermediate CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	if inter.ParentID == nil || *inter.ParentID != root.ID {
		t.Errorf("intermediate parent = %v, want %s", inter.ParentID, root.ID)
	}
	if inter.Serial != "2" {
		t.Errorf("intermediate serial = %q, want 2 (from parent counter)", inter.Serial)
	}
	interCert := mustParse(t, inter.Certificate)

	// The HSM-signed intermediate must verify against the root.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if err := interCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("intermediate not signed by root: %v", err)
	}
	if _, err := interCert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("intermediate chain verification failed: %v", err)
	}

	// The intermediate has path length 0, so it cannot itself parent a CA.
	if _, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:   inter.ID,
		Label:      uniqueLabel(t, tag+"-grandchild"),
		KeyType:    keyType,
		Subject:    PKIXName(models.CASubject{CommonName: "Should Fail"}),
		Validity:   24 * time.Hour,
		MaxPathLen: nil,
	}); err == nil {
		t.Error("expected path-length constraint to reject grandchild CA")
	}

	// Duplicate label is rejected.
	if _, err := mgr.InitRoot(ctx, RootSpec{
		Label:    rootLabel,
		KeyType:  keyType,
		Subject:  PKIXName(models.CASubject{CommonName: "Dup"}),
		Validity: 24 * time.Hour,
	}); err == nil {
		t.Error("expected duplicate label to be rejected")
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))

	cases := []struct {
		name string
		spec RootSpec
	}{
		{"no label", RootSpec{KeyType: "ecdsa-p256", Subject: PKIXName(models.CASubject{CommonName: "x"}), Validity: 24 * time.Hour}},
		{"no cn", RootSpec{Label: "l", KeyType: "ecdsa-p256", Validity: 24 * time.Hour}},
		{"bad key type", RootSpec{Label: "l", KeyType: "nope", Subject: PKIXName(models.CASubject{CommonName: "x"}), Validity: 24 * time.Hour}},
		{"zero validity", RootSpec{Label: "l", KeyType: "ecdsa-p256", Subject: PKIXName(models.CASubject{CommonName: "x"})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mgr.InitRoot(ctx, tc.spec); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestIssueIntermediateUnknownParent(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	if _, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID: "does-not-exist",
		Label:    "x",
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "x"}),
		Validity: 24 * time.Hour,
	}); err == nil {
		t.Error("expected error for unknown parent")
	}
}

func mustParse(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	cert, err := pki.ParseCertificatePEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}
