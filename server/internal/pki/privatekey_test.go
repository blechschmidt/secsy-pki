package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Task 194: reading the private key files operators actually hold. The openssl
// cases matter more than the Go-generated ones: they are the encodings a real
// migration arrives in, and they are produced here by the same tool that
// produced them on the CA being migrated.

func TestParsePrivateKeyGoFormats(t *testing.T) {
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

	pkcs8 := func(k any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		data       []byte
		wantFormat KeyFileFormat
		wantPub    any
	}{
		{"pkcs8-rsa", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(rsaKey)}), FormatPKCS8, &rsaKey.PublicKey},
		{"pkcs8-ec", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(ecKey)}), FormatPKCS8, &ecKey.PublicKey},
		{"pkcs8-ed25519", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(edKey)}), FormatPKCS8, edKey.Public()},
		{"pkcs1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), FormatPKCS1, &rsaKey.PublicKey},
		{"sec1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), FormatSEC1, &ecKey.PublicKey},
		{"bare-der-pkcs8", pkcs8(ecKey), FormatDER, &ecKey.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tc.data, nil)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if got.Format != tc.wantFormat {
				t.Errorf("format = %q, want %q", got.Format, tc.wantFormat)
			}
			if got.Encrypted {
				t.Error("Encrypted = true for an unencrypted key")
			}
			signer, err := got.Signer()
			if err != nil {
				t.Fatal(err)
			}
			if !publicKeysEqual(signer.Public(), tc.wantPub) {
				t.Error("parsed key does not match the original")
			}
		})
	}
}

// TestParsePrivateKeyOpenSSH covers the format an SSH CA key arrives in, both
// plain and passphrase-protected.
func TestParsePrivateKeyOpenSSH(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ssh.MarshalPrivateKey(edKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKey(pem.EncodeToMemory(plain), nil)
	if err != nil {
		t.Fatalf("ParsePrivateKey(openssh): %v", err)
	}
	if parsed.Format != FormatOpenSSH {
		t.Errorf("format = %q, want %q", parsed.Format, FormatOpenSSH)
	}
	if _, ok := parsed.Key.(ed25519.PrivateKey); !ok {
		t.Fatalf("key type = %T, want ed25519.PrivateKey", parsed.Key)
	}

	enc, err := ssh.MarshalPrivateKeyWithPassphrase(edKey, "test", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(enc)
	if _, err := ParsePrivateKey(encPEM, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("no passphrase: err = %v, want ErrPassphraseRequired", err)
	}
	if _, err := ParsePrivateKey(encPEM, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: err = %v, want ErrWrongPassphrase", err)
	}
	parsed, err = ParsePrivateKey(encPEM, []byte("hunter2"))
	if err != nil {
		t.Fatalf("ParsePrivateKey(openssh, passphrase): %v", err)
	}
	if !parsed.Encrypted {
		t.Error("Encrypted = false for a passphrase-protected key")
	}
	if !publicKeysEqual(parsed.Key.(ed25519.PrivateKey).Public(), edKey.Public()) {
		t.Error("decrypted key does not match the original")
	}
}

func TestParsePrivateKeyRejects(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"garbage", []byte("this is not a key")},
		{"certificate-pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})},
		{"truncated-pkcs8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x01, 0x02}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tc.data, nil); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestParsePrivateKeyRejectsUnsupportedAlgorithm proves an undersized RSA key —
// structurally valid, so it parses — is refused by the key-type derivation the
// importer runs, rather than surfacing as an opaque token error later.
func TestParsePrivateKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// A 1024-bit RSA key parses (it is structurally valid) but must be refused
	// by the key-type derivation the importer runs.
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})
	parsed, err := ParsePrivateKey(data, nil)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, err := PrivateKeyType(parsed.Key); err == nil {
		t.Fatal("expected PrivateKeyType to reject a 1024-bit RSA key")
	}
}

// --- openssl interop -------------------------------------------------------

func opensslPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	return path
}

func runOpenSSL(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(opensslPath(t), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
}

// TestParsePrivateKeyOpenSSLFormats runs the actual openssl commands an
// operator would have used to create and protect a CA key, and reads the
// results back. Each case is one real-world migration input.
func TestParsePrivateKeyOpenSSLFormats(t *testing.T) {
	opensslPath(t)
	dir := t.TempDir()
	const pass = "correct horse battery staple"
	passArg := "pass:" + pass

	cases := []struct {
		name       string
		file       string
		gen        []string
		passphrase []byte
		// wantFormat lists the acceptable formats: `openssl genrsa` emits
		// PKCS#1 on OpenSSL 1.x and PKCS#8 on 3.x, and both must read back.
		wantFormat []KeyFileFormat
	}{
		{
			name:       "genrsa-plain",
			file:       "rsa.pem",
			gen:        []string{"genrsa", "-out", filepath.Join(dir, "rsa.pem"), "2048"},
			wantFormat: []KeyFileFormat{FormatPKCS1, FormatPKCS8},
		},
		{
			name:       "genpkey-ec-plain",
			file:       "ec.pem",
			gen:        []string{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", filepath.Join(dir, "ec.pem")},
			wantFormat: []KeyFileFormat{FormatPKCS8},
		},
		{
			name:       "genpkey-ed25519-plain",
			file:       "ed.pem",
			gen:        []string{"genpkey", "-algorithm", "ED25519", "-out", filepath.Join(dir, "ed.pem")},
			wantFormat: []KeyFileFormat{FormatPKCS8},
		},
		{
			name:       "genpkey-aes256-pbes2",
			file:       "rsa-aes256.pem",
			gen:        []string{"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-aes256", "-pass", passArg, "-out", filepath.Join(dir, "rsa-aes256.pem")},
			passphrase: []byte(pass),
			wantFormat: []KeyFileFormat{FormatPKCS8Encrypted},
		},
		{
			name:       "pkcs8-topk8-default",
			file:       "ec-pkcs8.pem",
			gen:        nil, // derived below
			passphrase: []byte(pass),
			wantFormat: []KeyFileFormat{FormatPKCS8Encrypted},
		},
		{
			name:       "pkcs8-topk8-3des",
			file:       "ec-3des.pem",
			gen:        nil, // derived below
			passphrase: []byte(pass),
			wantFormat: []KeyFileFormat{FormatPKCS8Encrypted},
		},
	}

	for _, tc := range cases {
		if tc.gen != nil {
			runOpenSSL(t, tc.gen...)
		}
	}
	// The two -topk8 cases re-encrypt the plain EC key with the default cipher
	// and with 3DES, covering both cipher families of PBES2.
	runOpenSSL(t, "pkcs8", "-topk8", "-in", filepath.Join(dir, "ec.pem"),
		"-out", filepath.Join(dir, "ec-pkcs8.pem"), "-passout", passArg)
	runOpenSSL(t, "pkcs8", "-topk8", "-v2", "des-ede3-cbc", "-in", filepath.Join(dir, "ec.pem"),
		"-out", filepath.Join(dir, "ec-3des.pem"), "-passout", passArg)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.passphrase) > 0 {
				if _, err := ParsePrivateKey(data, nil); !errors.Is(err, ErrPassphraseRequired) {
					t.Errorf("no passphrase: err = %v, want ErrPassphraseRequired", err)
				}
				if _, err := ParsePrivateKey(data, []byte("nope")); !errors.Is(err, ErrWrongPassphrase) {
					t.Errorf("wrong passphrase: err = %v, want ErrWrongPassphrase", err)
				}
			}
			parsed, err := ParsePrivateKey(data, tc.passphrase)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if !slices.Contains(tc.wantFormat, parsed.Format) {
				t.Errorf("format = %q, want one of %q", parsed.Format, tc.wantFormat)
			}
			if _, err := PrivateKeyType(parsed.Key); err != nil {
				t.Errorf("PrivateKeyType: %v", err)
			}
			// A key that parses must be usable: the whole point is to sign with it.
			if _, err := parsed.Signer(); err != nil {
				t.Errorf("Signer: %v", err)
			}
		})
	}
}

// TestParsePrivateKeyPKCS12 covers the container an operator exports from a
// Windows CA or a browser: key and certificate chain in one file.
func TestParsePrivateKeyPKCS12(t *testing.T) {
	opensslPath(t)
	dir := t.TempDir()
	const pass = "p12pass"
	key := filepath.Join(dir, "leaf.key")
	crt := filepath.Join(dir, "leaf.crt")
	p12 := filepath.Join(dir, "bundle.p12")

	runOpenSSL(t, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
		"-days", "30", "-nodes", "-subj", "/CN=p12 test")
	runOpenSSL(t, "pkcs12", "-export", "-inkey", key, "-in", crt, "-out", p12,
		"-passout", "pass:"+pass)

	data, err := os.ReadFile(p12)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(data, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: err = %v, want ErrWrongPassphrase", err)
	}
	parsed, err := ParsePrivateKey(data, []byte(pass))
	if err != nil {
		t.Fatalf("ParsePrivateKey(p12): %v", err)
	}
	if parsed.Format != FormatPKCS12 {
		t.Errorf("format = %q, want %q", parsed.Format, FormatPKCS12)
	}
	if parsed.Certificate == nil {
		t.Fatal("PKCS#12 container yielded no certificate")
	}
	signer, err := parsed.Signer()
	if err != nil {
		t.Fatal(err)
	}
	// The container's certificate must be the one certifying its key: that
	// pairing is what lets `ca import` accept a single .p12.
	if !publicKeysEqual(signer.Public(), parsed.Certificate.PublicKey) {
		t.Error("the container's certificate does not match its key")
	}
}

// TestParsePrivateKeyLegacyEncryptedPEM covers the pre-OpenSSL-3.0 in-place PEM
// encryption that still guards many long-lived root keys. OpenSSL 3 can still
// produce it with -traditional; when it cannot, the case is skipped rather than
// weakened.
func TestParsePrivateKeyLegacyEncryptedPEM(t *testing.T) {
	opensslPath(t)
	dir := t.TempDir()
	const pass = "legacy"
	out := filepath.Join(dir, "legacy.pem")
	cmd := exec.Command(opensslPath(t), "genrsa", "-aes256", "-traditional",
		"-passout", "pass:"+pass, "-out", out, "2048")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("this openssl cannot emit traditional encrypted PEM: %v\n%s", err, combined)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(data, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("no passphrase: err = %v, want ErrPassphraseRequired", err)
	}
	parsed, err := ParsePrivateKey(data, []byte(pass))
	if err != nil {
		t.Fatalf("ParsePrivateKey(legacy): %v", err)
	}
	if parsed.Format != FormatPEMEncrypted {
		t.Errorf("format = %q, want %q", parsed.Format, FormatPEMEncrypted)
	}
	if _, ok := parsed.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", parsed.Key)
	}
}
