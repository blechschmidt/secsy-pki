package cms

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenSSLInterop confirms the CMS structures this package emits are parsable
// by an independent implementation (OpenSSL), guarding against self-consistent
// but non-conformant ASN.1. It is skipped when the openssl binary is absent.
func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()

	leaf, key := testRSACert(t, "interop-leaf", 42)

	// 1) Degenerate certs-only PKCS#7 must be parsable by `openssl pkcs7`.
	p7, err := DegenerateCertsOnly([]*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("DegenerateCertsOnly: %v", err)
	}
	p7Path := filepath.Join(dir, "certs.p7")
	writeFile(t, p7Path, p7)
	out, err := exec.Command(openssl, "pkcs7", "-inform", "DER", "-in", p7Path, "-print_certs", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs7 failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "interop-leaf") {
		t.Fatalf("openssl did not list the embedded certificate:\n%s", out)
	}

	// 2) EnvelopedData must be decryptable by `openssl cms -decrypt`.
	plaintext := []byte("interop enveloped payload spanning multiple AES blocks 0123456789")
	env, err := BuildEnvelopedData(plaintext, leaf)
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	envPath := filepath.Join(dir, "env.p7")
	writeFile(t, envPath, env)

	certPath := filepath.Join(dir, "cert.pem")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	out, err = exec.Command(openssl, "cms", "-decrypt", "-inform", "DER", "-in", envPath,
		"-recip", certPath, "-inkey", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), string(plaintext)) {
		t.Fatalf("openssl decrypt output mismatch:\n%s", out)
	}

	// 3) A SignedData with authenticated attributes must verify under
	//    `openssl cms -verify` (the SCEP pkiMessage / CertRep signature format).
	signContent := []byte("signed-data interop content")
	signed, err := BuildSignedData(SignedDataOpts{
		Content:    signContent,
		SignerCert: leaf,
		Signer:     key,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	signedPath := filepath.Join(dir, "signed.p7")
	writeFile(t, signedPath, signed)
	// -noverify skips signer-chain trust (the SCEP signer is self-signed); the
	// signature over the authenticated attributes is still checked.
	out, err = exec.Command(openssl, "cms", "-verify", "-inform", "DER", "-in", signedPath,
		"-certfile", certPath, "-noverify").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), string(signContent)) {
		t.Fatalf("openssl verify output mismatch:\n%s", out)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
