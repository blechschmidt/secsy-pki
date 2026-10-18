package config

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestConfiguredKeyURIEndToEndSoftHSM closes the loop Task 206 is about: a
// config file that names its signing key with an RFC 7512 URI, loaded through
// the real loader, mapped through the real settings mapper, must produce a
// provider that signs with that key on that token.
//
// Every layer in between is exercised as the server uses it — Validate,
// KeyProviderConfigForRole, keyprovider.New, KeyRefFor — so a regression in
// any of them fails here rather than at someone's first issuance.
func TestConfiguredKeyURIEndToEndSoftHSM(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	if module == "" || os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SoftHSM not configured (run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found on PATH")
	}
	pin := envOrDefault("SECSY_USER_PIN", "1234")
	soPin := envOrDefault("SECSY_SO_PIN", "5678")

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hexString(b[:])
	tokenLabel := "cfge2e-" + suffix
	keyLabel := "cfge2e-key-" + suffix

	run(t, "softhsm2-util", "--init-token", "--free", "--label", tokenLabel,
		"--pin", pin, "--so-pin", soPin)
	t.Cleanup(func() { _ = exec.Command("softhsm2-util", "--delete-token", "--token", tokenLabel).Run() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// The token is addressed by a URI; the signing key is addressed by a second
	// URI that pins the same token by label. Neither the module path nor the
	// PIN appears in the key reference, which is exactly the split the loader
	// enforces.
	body := `root_user:
  username: root
  password: hunter2hunter2
key_provider:
  type: pkcs11
pkcs11:
  pin: "` + pin + `"
  uri: "pkcs11:token=` + tokenLabel + `?module-path=` + module + `"
tsa:
  enabled: true
  key_label: "pkcs11:object=` + keyLabel + `;token=` + tokenLabel + `;type=private"
  certificate_file: /dev/null
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The ambient SoftHSM environment exports SECSY_PKCS11_MODULE and
	// SECSY_TOKEN_LABEL, which the loader applies as overrides and which win
	// over the URI by design. Clear them so the module and the token genuinely
	// have to come out of the URI.
	t.Setenv("SECSY_PKCS11_MODULE", "")
	t.Setenv("SECSY_TOKEN_LABEL", "")
	t.Setenv("SECSY_PKCS11_TOKEN_SERIAL", "")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("config did not load: %v", err)
	}
	// The module came from the URI alone — module_path was never set.
	if cfg.PKCS11.ModulePath != "" {
		t.Fatalf("module_path = %q, expected it to be unset in the file", cfg.PKCS11.ModulePath)
	}
	if got, _ := cfg.PKCS11.EffectiveModulePath(); got != module {
		t.Fatalf("EffectiveModulePath = %q, want %q", got, module)
	}

	provider, err := keyprovider.New(cfg.KeyProviderConfigForRole("tsa"))
	if err != nil {
		t.Fatalf("building the tsa key provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	ctx := context.Background()
	// Provision through the same helper the CLI and the provisioning API use,
	// so the key is created at the address the config names.
	if _, err := provider.GenerateKey(ctx,
		keyprovider.KeySpecFor(cfg.TSA.KeyLabel, keyprovider.KeyTypeECDSAP256, keyprovider.KeyUsageSign)); err != nil {
		t.Fatalf("generating the configured key: %v", err)
	}

	signer, err := provider.Signer(ctx, keyprovider.KeyRefFor(cfg.TSA.KeyLabel))
	if err != nil {
		t.Fatalf("opening a signer for the configured key URI: %v", err)
	}
	defer signer.Close()

	digest := sha256.Sum256([]byte("task 206 end-to-end"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signer public key is %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature produced through the configured key URI failed verification")
	}

	// The key really is the one named: a plain-label lookup finds it, and the
	// URI reported back by the provider round-trips to the same reference.
	info, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: keyLabel})
	if err != nil {
		t.Fatalf("the configured key is not present under its plain label: %v", err)
	}
	if got := keyprovider.KeyLabelFor(info.URI); got != keyLabel {
		t.Errorf("provider-reported URI %q resolves to label %q, want %q", info.URI, got, keyLabel)
	}
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hexString(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexdigits[x>>4], hexdigits[x&0xf])
	}
	return string(out)
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
