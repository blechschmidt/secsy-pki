package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
server:
  host: "0.0.0.0"
  port: 9999
database:
  driver: postgres
  dsn: "host=localhost"
root_user:
  username: admin
  password: secret
oidc:
  issuer_url: "https://example.com"
  client_id: "test"
pkcs11:
  module_path: "/usr/lib/test.so"
  pin: "1234"
  token_label: "test"
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 1
  password: "pass"
  suppress_audit_warning: true
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("host = %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("port = %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("driver = %q", cfg.Database.Driver)
	}
	if cfg.RootUser.Username != "admin" {
		t.Errorf("username = %q", cfg.RootUser.Username)
	}
	if cfg.OIDC.IssuerURL != "https://example.com" {
		t.Errorf("issuer = %q", cfg.OIDC.IssuerURL)
	}
	if cfg.YubiHSM.ConnectorURL != "yhusb://" {
		t.Errorf("connector = %q", cfg.YubiHSM.ConnectorURL)
	}
	if !cfg.YubiHSM.SuppressAuditWarning {
		t.Error("suppress_audit_warning should be true")
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
root_user:
  password: secret
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default host = %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 8443 {
		t.Errorf("default port = %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("default driver = %q", cfg.Database.Driver)
	}
	if cfg.RootUser.Username != "root" {
		t.Errorf("default username = %q", cfg.RootUser.Username)
	}
}

func TestKeyProviderDefaultsToPKCS11WhenModuleSet(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
pkcs11:
  module_path: "/usr/lib/test.so"
`)
	if cfg.KeyProvider.Type != "pkcs11" {
		t.Errorf("type = %q, want pkcs11", cfg.KeyProvider.Type)
	}
}

func TestKeyProviderDefaultsToSoftware(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if cfg.KeyProvider.Type != "software" {
		t.Errorf("type = %q, want software", cfg.KeyProvider.Type)
	}
	if cfg.KeyProvider.Software.KeystoreDir != "keystore" {
		t.Errorf("keystore_dir = %q, want default 'keystore'", cfg.KeyProvider.Software.KeystoreDir)
	}
}

func TestKeyProviderExplicitSoftware(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
key_provider:
  type: software
  software:
    keystore_dir: /var/lib/secsy/keys
`)
	if cfg.KeyProvider.Type != "software" {
		t.Errorf("type = %q", cfg.KeyProvider.Type)
	}
	if cfg.KeyProvider.Software.KeystoreDir != "/var/lib/secsy/keys" {
		t.Errorf("keystore_dir = %q", cfg.KeyProvider.Software.KeystoreDir)
	}
}

func TestKeyProviderInvalidType(t *testing.T) {
	clearProviderEnv(t)
	_, err := loadContent(t, `
root_user:
  password: secret
key_provider:
  type: bogus
`)
	if err == nil {
		t.Fatal("expected error for invalid provider type")
	}
}

func TestKeyProviderPKCS11RequiresModule(t *testing.T) {
	clearProviderEnv(t)
	_, err := loadContent(t, `
root_user:
  password: secret
key_provider:
  type: pkcs11
`)
	if err == nil {
		t.Fatal("expected error: pkcs11 provider without module_path")
	}
}

func TestKeyProviderKMSAWS(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
key_provider:
  type: kms
  kms:
    backend: aws
    region: eu-central-1
    key_prefix: secsy/
`)
	if cfg.KeyProvider.Type != "kms" {
		t.Errorf("type = %q, want kms", cfg.KeyProvider.Type)
	}
	if cfg.KeyProvider.KMS.Backend != "aws" || cfg.KeyProvider.KMS.Region != "eu-central-1" {
		t.Errorf("kms = %+v", cfg.KeyProvider.KMS)
	}
}

func TestKeyProviderKMSDefaultsFromBackend(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
key_provider:
  kms:
    backend: fake
`)
	if cfg.KeyProvider.Type != "kms" {
		t.Errorf("type = %q, want kms (inferred from kms.backend)", cfg.KeyProvider.Type)
	}
}

func TestKeyProviderKMSBackendRequired(t *testing.T) {
	clearProviderEnv(t)
	if _, err := loadContent(t, `
root_user:
  password: secret
key_provider:
  type: kms
`); err == nil {
		t.Fatal("expected error: kms provider without backend")
	}
}

func TestKeyProviderKMSAzureRequiresVaultURL(t *testing.T) {
	clearProviderEnv(t)
	if _, err := loadContent(t, `
root_user:
  password: secret
key_provider:
  type: kms
  kms:
    backend: azure
`); err == nil {
		t.Fatal("expected error: azure backend without vault_url")
	}
}

func TestKeyProviderPerRoleSelection(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
pkcs11:
  module_path: /usr/lib/test.so
key_provider:
  type: pkcs11
  kms:
    backend: aws
    region: us-east-1
  roles:
    tsa: kms
`)
	if got := cfg.KeyProviderTypeForRole("ca"); got != "pkcs11" {
		t.Errorf("ca role = %q, want pkcs11 (falls back to global type)", got)
	}
	if got := cfg.KeyProviderTypeForRole("tsa"); got != "kms" {
		t.Errorf("tsa role = %q, want kms (override)", got)
	}
}

func TestKeyProviderInvalidRoleType(t *testing.T) {
	clearProviderEnv(t)
	if _, err := loadContent(t, `
root_user:
  password: secret
key_provider:
  type: software
  roles:
    tsa: bogus
`); err == nil {
		t.Fatal("expected error: invalid per-role provider type")
	}
}

func TestKeyProviderEnvOverride(t *testing.T) {
	t.Setenv("SECSY_KEY_PROVIDER", "pkcs11")
	t.Setenv("SECSY_PKCS11_MODULE", "/env/module.so")
	t.Setenv("SECSY_TOKEN_LABEL", "env-token")
	t.Setenv("SECSY_USER_PIN", "9999")
	cfg := writeAndLoad(t, `
root_user:
  password: secret
key_provider:
  type: software
`)
	if cfg.KeyProvider.Type != "pkcs11" {
		t.Errorf("type = %q, want pkcs11 (env override)", cfg.KeyProvider.Type)
	}
	if cfg.PKCS11.ModulePath != "/env/module.so" {
		t.Errorf("module_path = %q", cfg.PKCS11.ModulePath)
	}
	if cfg.PKCS11.TokenLabel != "env-token" {
		t.Errorf("token_label = %q", cfg.PKCS11.TokenLabel)
	}
	if cfg.PKCS11.Pin != "9999" {
		t.Errorf("pin = %q", cfg.PKCS11.Pin)
	}
}

// clearProviderEnv neutralizes any ambient SECSY_* overrides (e.g. exported by
// scripts/setup-softhsm.sh) so a test observes only its file content. Setting a
// variable to "" makes applyEnvOverrides ignore it.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECSY_KEY_PROVIDER", "SECSY_PKCS11_MODULE", "SECSY_TOKEN_LABEL",
		"SECSY_USER_PIN", "SECSY_SOFTWARE_KEYSTORE_DIR",
		"SECSY_KMS_BACKEND", "SECSY_KMS_REGION", "SECSY_KMS_KEY_PREFIX",
		"SECSY_KMS_VAULT_URL", "SECSY_KEY_PROVIDER_CA", "SECSY_KEY_PROVIDER_TSA",
	} {
		t.Setenv(k, "")
	}
}

// writeAndLoad writes content to a temp config and loads it, failing the test
// on any load error.
func writeAndLoad(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := loadContent(t, content)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// loadContent writes content to a temp config and returns the load result.
func loadContent(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadMissingPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
root_user:
  username: admin
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`{{{invalid`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}
