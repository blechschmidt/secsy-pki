package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeURIConfig writes a minimal loadable config with extra appended, and
// returns its path.
func writeURIConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	base := `root_user:
  username: root
  password: hunter2hunter2
key_provider:
  type: software
  software:
    keystore_dir: ` + filepath.Join(dir, "keystore") + `
`
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(base+extra), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return p
}

func loadURIConfig(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	return Load(writeURIConfig(t, extra))
}

// writePKCS11Config writes a config whose key provider is pkcs11, so the module
// resolution path is exercised.
func writePKCS11Config(t *testing.T, pkcs11Block string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := `root_user:
  username: root
  password: hunter2hunter2
key_provider:
  type: pkcs11
` + pkcs11Block
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return p
}

func TestConfigAcceptsKeyURIs(t *testing.T) {
	cfg, err := loadURIConfig(t, `
tsa:
  enabled: true
  key_label: "pkcs11:object=tsa-key;id=%0a%0b;serial=0001234;type=private"
  certificate_file: /dev/null
signing:
  enabled: true
  signers:
    - name: release
      key_label: "pkcs11:id=%ff;type=private"
      certificate_file: /dev/null
secret:
  kek_label: "pkcs11:object=prod-kek"
  escrow:
    enabled: true
    threshold: 2
    agents:
      - id: a
        key_label: "pkcs11:object=agent-a;serial=0001234"
      - id: b
        key_label: agent-b
tenants:
  - id: acme
    kek_label: "pkcs11:object=acme-kek"
`)
	if err != nil {
		t.Fatalf("config with key URIs did not load: %v", err)
	}
	// Ordinary key references keep the full URI; they are resolved at use.
	if cfg.TSA.KeyLabel != "pkcs11:object=tsa-key;id=%0a%0b;serial=0001234;type=private" {
		t.Errorf("tsa.key_label was rewritten: %q", cfg.TSA.KeyLabel)
	}
	// KEK references are reduced to the family label, which is what the
	// database and every envelope's wrap header carry.
	if cfg.Secret.KEKLabel != "prod-kek" {
		t.Errorf("secret.kek_label = %q, want the normalized label prod-kek", cfg.Secret.KEKLabel)
	}
	if cfg.Tenants[0].KEKLabel != "acme-kek" {
		t.Errorf("tenants[0].kek_label = %q, want acme-kek", cfg.Tenants[0].KEKLabel)
	}
	if got := cfg.Secret.ResolvedKEKLabel(); got != "prod-kek" {
		t.Errorf("ResolvedKEKLabel = %q", got)
	}
}

func TestConfigRejectsUnusableKeyURIs(t *testing.T) {
	cases := []struct{ name, extra, want string }{
		{
			name:  "tsa key uri names no object",
			extra: "tsa:\n  enabled: true\n  key_label: \"pkcs11:serial=0001234\"\n  certificate_file: /dev/null\n",
			want:  "names a token but no key",
		},
		{
			name:  "tsa key uri addresses a certificate",
			extra: "tsa:\n  enabled: true\n  key_label: \"pkcs11:object=k;type=cert\"\n  certificate_file: /dev/null\n",
			want:  "not a key",
		},
		{
			name:  "key uri carries the module",
			extra: "tsa:\n  enabled: true\n  key_label: \"pkcs11:object=k?module-path=/x.so\"\n  certificate_file: /dev/null\n",
			want:  "module is deployment-wide",
		},
		{
			name:  "key uri carries a pin",
			extra: "tsa:\n  enabled: true\n  key_label: \"pkcs11:object=k?pin-value=1234\"\n  certificate_file: /dev/null\n",
			want:  "PIN is per-token",
		},
		{
			name:  "kek uri pins a token",
			extra: "secret:\n  kek_label: \"pkcs11:object=kek;serial=0001234\"\n",
			want:  "must not pin a token",
		},
		{
			name:  "kek uri pins a CKA_ID",
			extra: "secret:\n  kek_label: \"pkcs11:object=kek;id=%01\"\n",
			want:  "must not pin id=",
		},
		{
			name:  "token uri names an object",
			extra: "pkcs11:\n  uri: \"pkcs11:token=t;object=k?module-path=/x.so\"\n",
			want:  "addresses the token",
		},
		{
			name:  "token uri typo",
			extra: "pkcs11:\n  uri: \"pkcs11:tokn=t?module-path=/x.so\"\n",
			want:  "unrecognized attribute",
		},
		{
			name:  "malformed token uri",
			extra: "pkcs11:\n  uri: \"pkcs11:type=bogus\"\n",
			want:  "pkcs11.uri",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadURIConfig(t, tc.extra)
			if err == nil {
				t.Fatalf("config unexpectedly loaded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A plaintext pin-value embedded anywhere in the config must never survive a
// redacted dump — the dump is what goes into a support bundle.
func TestRedactedConfigMasksURIPIN(t *testing.T) {
	cfg, err := loadURIConfig(t, `
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  uri: "pkcs11:token=softtoken?pin-value=supersecret"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	red := cfg.Redacted()
	if strings.Contains(red.PKCS11.URI, "supersecret") {
		t.Fatalf("redacted config leaked the pin-value: %q", red.PKCS11.URI)
	}
}

func TestPKCS11SettingsCarryFullAddressing(t *testing.T) {
	slot := uint(3)
	p := PKCS11Config{
		ModulePath:       "/x.so",
		TokenLabel:       "tok",
		TokenSerial:      "ser",
		TokenModel:       "model",
		SlotID:           &slot,
		SlotDescription:  "desc",
		SlotManufacturer: "mfr",
		Tokens: []PKCS11TokenConfig{{
			Name: "a", TokenLabel: "tl", TokenModel: "tm", SlotID: &slot,
			SlotDescription: "sd", SlotManufacturer: "sm",
		}},
	}
	s := p.KeyProviderSettings()
	if s.TokenModel != "model" || s.SlotDescription != "desc" || s.SlotManufacturer != "mfr" {
		t.Errorf("set-level selectors lost: %+v", s)
	}
	if s.SlotID == nil || *s.SlotID != 3 {
		t.Errorf("set-level slot id lost: %v", s.SlotID)
	}
	if len(s.Tokens) != 1 {
		t.Fatalf("tokens = %d, want 1", len(s.Tokens))
	}
	tk := s.Tokens[0]
	if tk.TokenModel != "tm" || tk.SlotDescription != "sd" || tk.SlotManufacturer != "sm" {
		t.Errorf("per-token selectors lost: %+v", tk)
	}
	if tk.SlotID == nil || *tk.SlotID != 3 {
		t.Errorf("per-token slot id lost: %v", tk.SlotID)
	}
}

// The pkcs11 provider may be configured entirely through its URI: a config
// that names the module only there must load rather than demanding a
// module_path it already has.
func TestModulePathMayComeFromTheURI(t *testing.T) {
	// SECSY_PKCS11_MODULE is an override that wins over the URI by design, and
	// the ambient SoftHSM test environment exports it. Clear it so this test
	// measures URI resolution rather than the environment.
	t.Setenv("SECSY_PKCS11_MODULE", "")
	dir := t.TempDir()
	modulePath := filepath.Join(dir, "libsofthsm2.so")
	if err := os.WriteFile(modulePath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(writePKCS11Config(t, `pkcs11:
  uri: "pkcs11:token=softtoken?module-path=`+modulePath+`"
`))
	if err != nil {
		t.Fatalf("uri-only pkcs11 config did not load: %v", err)
	}
	got, err := cfg.PKCS11.EffectiveModulePath()
	if err != nil || got != modulePath {
		t.Errorf("EffectiveModulePath = (%q, %v), want %q", got, err, modulePath)
	}

	// And through module-name, resolved against the search path.
	t.Setenv("SECSY_PKCS11_MODULE_DIRS", dir)
	cfg, err = Load(writePKCS11Config(t, `pkcs11:
  uri: "pkcs11:token=softtoken?module-name=libsofthsm2"
`))
	if err != nil {
		t.Fatalf("module-name pkcs11 config did not load: %v", err)
	}
	if got, _ := cfg.PKCS11.EffectiveModulePath(); got != modulePath {
		t.Errorf("EffectiveModulePath via module-name = %q, want %q", got, modulePath)
	}

	// A module-name that resolves to nothing fails the load, naming the problem.
	_, err = Load(writePKCS11Config(t, `pkcs11:
  uri: "pkcs11:token=softtoken?module-name=definitely-not-installed"
`))
	if err == nil || !strings.Contains(err.Error(), "definitely-not-installed") {
		t.Errorf("unresolvable module-name error = %v, want it to name the module", err)
	}
}

// One PKCS#11 library drives every token in a set. A config naming two is
// expressing something the backend cannot do, and silently picking one would
// route half the operations to a device the operator did not mean.
func TestConfigRejectsDisagreeingModules(t *testing.T) {
	t.Setenv("SECSY_PKCS11_MODULE", "")
	_, err := Load(writePKCS11Config(t, `pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  tokens:
    - name: a
      uri: "pkcs11:serial=0001?module-path=/opt/yubihsm_pkcs11.so"
    - name: b
      uri: "pkcs11:serial=0002"
`))
	if err == nil {
		t.Fatal("a config naming two modules unexpectedly loaded")
	}
	for _, want := range []string{"different PKCS#11 modules", "libsofthsm2.so", "yubihsm_pkcs11.so"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// An HA member may be addressed entirely by its own URI — which is the natural
// form when replicas share a CKA_LABEL and differ only by serial.
func TestHATokensMayBeAddressedByURI(t *testing.T) {
	t.Setenv("SECSY_PKCS11_MODULE", "")
	cfg, err := Load(writePKCS11Config(t, `pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  tokens:
    - uri: "pkcs11:serial=0001234567"
    - uri: "pkcs11:slot-id=4"
`))
	if err != nil {
		t.Fatalf("URI-addressed HA members did not load: %v", err)
	}
	s := cfg.PKCS11.KeyProviderSettings()
	if len(s.Tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(s.Tokens))
	}
	// A member addressing nothing at all is still rejected: it would match
	// every token in the set, which is never what listing two replicas meant.
	if _, err := Load(writePKCS11Config(t, `pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  tokens:
    - name: nothing
`)); err == nil || !strings.Contains(err.Error(), "does not address a token") {
		t.Errorf("an unaddressed HA member error = %v, want it rejected", err)
	}
}

// A container is pointed at an HSM whose address the image could not know, so
// the whole token must be configurable from the environment.
func TestPKCS11EnvOverrides(t *testing.T) {
	t.Setenv("SECSY_PKCS11_MODULE", "")
	t.Setenv("SECSY_TOKEN_LABEL", "")
	t.Setenv("SECSY_PKCS11_URI", "pkcs11:token=from-env?module-path=/from/env.so")
	t.Setenv("SECSY_TOKEN_MODEL", "YubiHSMv2")
	t.Setenv("SECSY_PKCS11_SLOT_ID", "11")

	cfg, err := Load(writePKCS11Config(t, "pkcs11: {}\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.PKCS11.URI != "pkcs11:token=from-env?module-path=/from/env.so" {
		t.Errorf("uri = %q", cfg.PKCS11.URI)
	}
	if cfg.PKCS11.TokenModel != "YubiHSMv2" {
		t.Errorf("token_model = %q", cfg.PKCS11.TokenModel)
	}
	if cfg.PKCS11.SlotID == nil || *cfg.PKCS11.SlotID != 11 {
		t.Errorf("slot_id = %v, want 11", cfg.PKCS11.SlotID)
	}
	if got, _ := cfg.PKCS11.EffectiveModulePath(); got != "/from/env.so" {
		t.Errorf("EffectiveModulePath = %q", got)
	}

	// A file field still wins over the URI's corresponding attribute, and an
	// explicit env override still wins over the file.
	t.Setenv("SECSY_TOKEN_LABEL", "from-env-label")
	cfg, err = Load(writePKCS11Config(t, "pkcs11:\n  token_label: from-file\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.PKCS11.TokenLabel != "from-env-label" {
		t.Errorf("token_label = %q, want the env override to win", cfg.PKCS11.TokenLabel)
	}
}
