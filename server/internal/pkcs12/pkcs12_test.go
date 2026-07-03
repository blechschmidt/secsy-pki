//go:build sqlite

package pkcs12

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	sslpkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestGenerateAndBundleRoundTrip is the Task 80 acceptance test. It stands up a
// three-level CA hierarchy (root -> intermediate -> leaf), generates a subject
// keypair server-side, issues a leaf, and packs the key + leaf + full chain into
// a PKCS#12 bundle. It then round-trips the bundle two ways:
//
//  1. Decode it with the go-pkcs12 library and verify the recovered private key,
//     leaf, and CA chain — building an x509 path from the bundled issuers up to
//     the root and calling Certificate.Verify.
//  2. Pipe it through `openssl pkcs12 -info` and confirm OpenSSL parses the
//     bundle, prints the subject key, and lists the full subject chain (leaf,
//     intermediate, root).
//
// It runs over the software key provider (always) and a SoftHSM token (when
// configured), matching the rest of the HSM-backed test suite. The CRITICAL
// invariant — that only the freshly-generated subject key is bundled, never the
// HSM-resident CA key — is exercised implicitly: the bundle decrypts to the
// subject key alone, and the CA keys are only ever used to sign.
func TestGenerateAndBundleRoundTrip(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runRoundTrip(t, mk(t), name)
		})
	}
}

func runRoundTrip(t *testing.T, provider keyprovider.Provider, tag string) {
	ctx := context.Background()
	mgr := newManager(t, provider)

	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, tag+"-root"),
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "P12 Test Root " + tag, Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID: root.ID,
		Label:    uniqueLabel(t, tag+"-inter"),
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "P12 Test Intermediate " + tag, Organization: "Secsy"}),
		Validity: 3 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	rootCert := mustParsePEM(t, root.Certificate)
	interCert := mustParsePEM(t, inter.Certificate)

	cases := []struct {
		keyType string
		encoder string
	}{
		{"ecdsa", EncoderModern},
		{"rsa", EncoderModern},
		{"ecdsa", EncoderLegacyDES},
		{"rsa", EncoderLegacyRC2},
	}
	for _, tc := range cases {
		t.Run(tc.keyType+"-"+tc.encoder, func(t *testing.T) {
			const password = "correct-horse-battery-staple"
			cn := "leaf-" + tc.keyType + ".example.com"
			res, err := GenerateAndBundle(ctx, mgr, BundleRequest{
				CAID:        inter.ID,
				Profile:     "server",
				Subject:     ca.PKIXName(models.CASubject{CommonName: cn, Organization: "Secsy"}),
				DNSNames:    []string{cn},
				Key:         KeySpec{Type: tc.keyType},
				Password:    password,
				Encoder:     tc.encoder,
				RequestedBy: "pkcs12-test",
			})
			if err != nil {
				t.Fatalf("GenerateAndBundle: %v", err)
			}

			// The bundled leaf must carry our subject key type.
			assertLeafKeyType(t, res.Leaf, tc.keyType)

			// The issuer chain must be [intermediate, root].
			if len(res.CACerts) != 2 {
				t.Fatalf("bundled CA certs = %d, want 2 (intermediate + root)", len(res.CACerts))
			}
			assertChainContains(t, res.CACerts, interCert, rootCert)

			// --- Round-trip 1: decode with go-pkcs12 and verify the chain. ------
			priv, leaf, caCerts, err := sslpkcs12.DecodeChain(res.PKCS12, password)
			if err != nil {
				t.Fatalf("DecodeChain: %v", err)
			}
			if priv == nil {
				t.Fatal("decoded PKCS#12 has no private key")
			}
			// The recovered key must be the freshly-generated subject key type
			// (never the CA key) and must match the leaf's public key.
			assertPrivKeyMatchesLeaf(t, priv, leaf)
			if !leaf.Equal(res.Leaf) {
				t.Fatal("decoded leaf does not match the issued leaf")
			}
			if len(caCerts) != 2 {
				t.Fatalf("decoded CA certs = %d, want 2", len(caCerts))
			}

			roots := x509.NewCertPool()
			roots.AddCert(rootCert)
			inters := x509.NewCertPool()
			for _, c := range caCerts {
				if !c.Equal(rootCert) {
					inters.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inters,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				t.Fatalf("chain verification of decoded bundle failed: %v", err)
			}

			// A wrong password must fail to decode (confidentiality holds).
			if _, _, _, err := sslpkcs12.DecodeChain(res.PKCS12, "wrong-password"); err == nil {
				t.Fatal("DecodeChain succeeded with a wrong password")
			}

			// --- Round-trip 2: openssl pkcs12 -info. ---------------------------
			// OpenSSL 3 reads the modern (PBES2/AES) and 3DES-legacy encoders out
			// of the box; RC2-legacy needs the legacy provider, so it is verified
			// only via the Go decoder above.
			if tc.encoder != EncoderLegacyRC2 {
				opensslInfoVerify(t, res.PKCS12, password, cn, interCert.Subject.CommonName, rootCert.Subject.CommonName)
			}
		})
	}
}

// opensslInfoVerify writes the bundle to a temp file and runs
// `openssl pkcs12 -info` over it, asserting OpenSSL parses it, decrypts the
// subject key, and lists every subject in the chain. Skips if openssl is absent.
func opensslInfoVerify(t *testing.T, pfx []byte, password string, wantSubjects ...string) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found on PATH; skipping openssl round-trip")
	}
	path := filepath.Join(t.TempDir(), "bundle.p12")
	if err := os.WriteFile(path, pfx, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	// -nodes so OpenSSL does not prompt for an output passphrase for the key;
	// -passin supplies the import password non-interactively; -info prints the
	// structure (MAC/PBE parameters) and, without -noout, the bags as PEM plus
	// their subject/issuer headers.
	cmd := exec.Command(openssl, "pkcs12", "-info", "-in", path, "-passin", "pass:"+password, "-nodes")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs12 -info failed: %v\n%s", err, out)
	}
	s := string(out)
	// The subject key and every certificate in the chain must be present.
	if !strings.Contains(s, "PRIVATE KEY") {
		t.Errorf("openssl output missing the subject private key\n%s", s)
	}
	if !strings.Contains(s, "BEGIN CERTIFICATE") {
		t.Errorf("openssl output missing certificates\n%s", s)
	}
	for _, subj := range wantSubjects {
		if subj != "" && !strings.Contains(s, subj) {
			t.Errorf("openssl output missing expected subject %q\n%s", subj, s)
		}
	}
}

// --- provider + manager helpers (mirrors the internal/ca test harness) -----

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

func newManager(t *testing.T, provider keyprovider.Provider) *ca.Manager {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "pkcs12-test.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return ca.NewManager(db, provider)
}

func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "p12test-" + base + "-" + hex.EncodeToString(b[:])
}

func mustParsePEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

func assertLeafKeyType(t *testing.T, leaf *x509.Certificate, keyType string) {
	t.Helper()
	switch keyType {
	case "ecdsa":
		if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Fatalf("leaf public key is %T, want ECDSA", leaf.PublicKey)
		}
	case "rsa":
		if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
			t.Fatalf("leaf public key is %T, want RSA", leaf.PublicKey)
		}
	}
}

func assertPrivKeyMatchesLeaf(t *testing.T, priv any, leaf *x509.Certificate) {
	t.Helper()
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !k.PublicKey.Equal(pub) {
			t.Fatal("recovered ECDSA key does not match the leaf public key")
		}
	case *rsa.PrivateKey:
		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok || !k.PublicKey.Equal(pub) {
			t.Fatal("recovered RSA key does not match the leaf public key")
		}
	default:
		t.Fatalf("recovered key has unexpected type %T", priv)
	}
}

func assertChainContains(t *testing.T, chain []*x509.Certificate, want ...*x509.Certificate) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, c := range chain {
			if c.Equal(w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bundled chain missing certificate %q", w.Subject.CommonName)
		}
	}
}
