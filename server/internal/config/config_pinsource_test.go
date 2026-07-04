package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPinSourceConfig proves the pkcs11.pin_source schema parses end-to-end
// through Load (including the inline Vault block and a per-token override) and is
// accepted by the strict unknown-key lint the doctor uses.
func TestLoadPinSourceConfig(t *testing.T) {
	raw := `
root_user:
  password: "x"
key_provider:
  type: "software"
  software:
    keystore_dir: "ks"
pkcs11:
  module_path: "/m.so"
  pin_source:
    type: "vault"
    vault:
      address: "https://vault.example:8200"
      auth_method: "approle"
      role_id: "r"
      secret_id: "s"
      mount: "kv"
      path: "hsm/prod"
      field: "userpin"
      kv_version: 2
  tokens:
    - name: "a"
      pin_source:
        type: "file"
        file:
          path: "/etc/secsy/pin"
          allow_insecure_perms: false
`
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ps := cfg.PKCS11.PinSource
	if ps.Type != "vault" {
		t.Errorf("pin_source.type = %q, want vault", ps.Type)
	}
	if ps.Vault.Address != "https://vault.example:8200" || ps.Vault.AuthMethod != "approle" ||
		ps.Vault.RoleID != "r" || ps.Vault.SecretID != "s" {
		t.Errorf("vault auth fields not parsed: %+v", ps.Vault)
	}
	if ps.Vault.Mount != "kv" || ps.Vault.Path != "hsm/prod" || ps.Vault.Field != "userpin" || ps.Vault.KVVersion != 2 {
		t.Errorf("vault kv fields not parsed: mount=%q path=%q field=%q ver=%d",
			ps.Vault.Mount, ps.Vault.Path, ps.Vault.Field, ps.Vault.KVVersion)
	}
	if len(cfg.PKCS11.Tokens) != 1 || cfg.PKCS11.Tokens[0].PinSource.Type != "file" ||
		cfg.PKCS11.Tokens[0].PinSource.File.Path != "/etc/secsy/pin" {
		t.Errorf("per-token pin_source not parsed: %+v", cfg.PKCS11.Tokens)
	}

	// The strict unknown-key lint (secsy-ca doctor config.unknown_keys) must not
	// flag any of the new pin_source keys.
	unknown, err := UnknownKeys([]byte(raw))
	if err != nil {
		t.Fatalf("UnknownKeys: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("unexpected unknown keys for pin_source config: %v", unknown)
	}
}
