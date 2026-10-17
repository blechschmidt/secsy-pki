package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The `yubihsm:` block is the one part of the configuration a container cannot
// reasonably bake into its mounted file: the password is a credential, the
// connector URL depends on whether a yubihsm-connector is in front of the
// device, and the audit-log destination is a mount point the orchestrator
// chooses. All four come from the environment.
func TestYubiHSMEnvOverrides(t *testing.T) {
	clearYubiHSMEnv(t)
	t.Setenv("SECSY_YUBIHSM_CONNECTOR_URL", "http://yubihsm-connector:12345")
	t.Setenv("SECSY_YUBIHSM_AUTH_KEY_ID", "3")
	t.Setenv("SECSY_YUBIHSM_PASSWORD", "from-the-environment")
	t.Setenv("SECSY_YUBIHSM_AUDIT_LOG_FILE", "/app/audit/device-log.jsonl")

	cfg := loadYubiHSMConfig(t, `
root_user:
  password: secret
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 1
  password: "from-the-file"
  audit_log_file: "/baked/into/the/image.jsonl"
`)
	if cfg.YubiHSM.ConnectorURL != "http://yubihsm-connector:12345" {
		t.Errorf("connector_url = %q", cfg.YubiHSM.ConnectorURL)
	}
	if cfg.YubiHSM.AuthKeyID != 3 {
		t.Errorf("auth_key_id = %d, want 3", cfg.YubiHSM.AuthKeyID)
	}
	if cfg.YubiHSM.Password != "from-the-environment" {
		t.Errorf("password = %q", cfg.YubiHSM.Password)
	}
	if cfg.YubiHSM.AuditLogFile != "/app/audit/device-log.jsonl" {
		t.Errorf("audit_log_file = %q", cfg.YubiHSM.AuditLogFile)
	}
}

// An unset variable must leave the file's value alone. This is the ordinary
// case — a deployment overrides the password and nothing else — and getting it
// wrong would blank the rest of the block.
func TestYubiHSMEnvOverridesLeaveUnsetValuesAlone(t *testing.T) {
	clearYubiHSMEnv(t)
	t.Setenv("SECSY_YUBIHSM_PASSWORD", "from-the-environment")

	cfg := loadYubiHSMConfig(t, `
root_user:
  password: secret
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 2
  password: "from-the-file"
  audit_log_file: "/var/log/secsy/device-log.jsonl"
`)
	if cfg.YubiHSM.ConnectorURL != "yhusb://" {
		t.Errorf("connector_url = %q, want the file's value", cfg.YubiHSM.ConnectorURL)
	}
	if cfg.YubiHSM.AuthKeyID != 2 {
		t.Errorf("auth_key_id = %d, want the file's 2", cfg.YubiHSM.AuthKeyID)
	}
	if cfg.YubiHSM.AuditLogFile != "/var/log/secsy/device-log.jsonl" {
		t.Errorf("audit_log_file = %q, want the file's value", cfg.YubiHSM.AuditLogFile)
	}
	if cfg.YubiHSM.Password != "from-the-environment" {
		t.Errorf("password = %q", cfg.YubiHSM.Password)
	}
}

// A non-numeric auth key id is ignored rather than fatal, matching every other
// integer override in applyEnvOverrides: the file's value stands, and the
// device rejects a wrong key id loudly enough on its own.
func TestYubiHSMEnvAuthKeyIDIgnoresGarbage(t *testing.T) {
	clearYubiHSMEnv(t)
	t.Setenv("SECSY_YUBIHSM_AUTH_KEY_ID", "0x01")

	cfg := loadYubiHSMConfig(t, `
root_user:
  password: secret
yubihsm:
  auth_key_id: 7
`)
	if cfg.YubiHSM.AuthKeyID != 7 {
		t.Errorf("auth_key_id = %d, want the file's 7", cfg.YubiHSM.AuthKeyID)
	}
}

// clearYubiHSMEnv neutralizes ambient overrides so a test sees only what it set.
func clearYubiHSMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECSY_YUBIHSM_CONNECTOR_URL", "SECSY_YUBIHSM_AUTH_KEY_ID",
		"SECSY_YUBIHSM_PASSWORD", "SECSY_YUBIHSM_AUDIT_LOG_FILE",
	} {
		t.Setenv(k, "")
	}
}

func loadYubiHSMConfig(t *testing.T, content string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}
