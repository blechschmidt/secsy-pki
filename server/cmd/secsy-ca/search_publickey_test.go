//go:build sqlite

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
)

// TestResolveSearchFingerprint_PEM verifies that a --by-public-key @file value
// is fingerprinted locally to exactly the canonical value the inventory stores,
// for each artifact form an operator might hold: a bare public key, a
// certificate, and a CSR.
func TestResolveSearchFingerprint_PEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want, err := keycheck.Fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	// 1) Bare SubjectPublicKeyInfo (PEM).
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "key.pub.pem")
	writePEM(t, pubPath, "PUBLIC KEY", spki)

	// 2) A certificate carrying the same key (PEM).
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaked.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "leaked.crt.pem")
	writePEM(t, certPath, "CERTIFICATE", certDER)

	// 3) A PKCS#10 CSR carrying the same key (PEM).
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaked.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(dir, "leaked.csr.pem")
	writePEM(t, csrPath, "CERTIFICATE REQUEST", csrDER)

	for _, tc := range []struct{ name, path string }{
		{"public-key", pubPath},
		{"certificate", certPath},
		{"csr", csrPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSearchFingerprint("@" + tc.path)
			if err != nil {
				t.Fatalf("resolveSearchFingerprint(@%s): %v", tc.path, err)
			}
			if got != want {
				t.Fatalf("fingerprint = %q, want %q", got, want)
			}
		})
	}

	// A DER (non-PEM) certificate is also accepted.
	t.Run("der-certificate", func(t *testing.T) {
		derPath := filepath.Join(dir, "leaked.crt.der")
		if err := os.WriteFile(derPath, certDER, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveSearchFingerprint("@" + derPath)
		if err != nil {
			t.Fatalf("resolveSearchFingerprint(@der): %v", err)
		}
		if got != want {
			t.Fatalf("DER fingerprint = %q, want %q", got, want)
		}
	})
}

// TestResolveSearchFingerprint_Literal covers the non-@ forms: a hex SPKI digest
// and the canonical fingerprint both resolve, and garbage is rejected.
func TestResolveSearchFingerprint_Literal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := keycheck.Fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)

	for _, tc := range []struct{ name, input string }{
		{"hex", hex.EncodeToString(sum[:])},
		{"canonical", canonical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSearchFingerprint(tc.input)
			if err != nil {
				t.Fatalf("resolveSearchFingerprint(%q): %v", tc.input, err)
			}
			if got != canonical {
				t.Fatalf("= %q, want %q", got, canonical)
			}
		})
	}

	t.Run("garbage", func(t *testing.T) {
		if _, err := resolveSearchFingerprint("not-a-fingerprint"); err == nil {
			t.Fatal("want error for garbage input")
		}
	})
	t.Run("missing-file", func(t *testing.T) {
		if _, err := resolveSearchFingerprint("@/nonexistent/path.pem"); err == nil {
			t.Fatal("want error for missing @file")
		}
	})
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}
