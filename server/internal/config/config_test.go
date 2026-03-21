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
