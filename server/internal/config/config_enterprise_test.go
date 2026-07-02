package config

import "testing"

func TestLoadRBACPolicyProfiles(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
rbac:
  subjects:
    "oidc-sub-1": [admin]
    "alice@example.com": [auditor]
  groups:
    "group-ops": [issuer, auditor]
policy:
  require_reason: true
  max_cert_validity_days: 90
  allow_root_basic_auth: false
profiles:
  - name: short-client
    description: "Ephemeral client cert"
    key_usages: [digitalSignature]
    ext_key_usages: [clientAuth]
    default_validity_days: 7
    max_validity_days: 30
`)

	if got := cfg.RBAC.Subjects["oidc-sub-1"]; len(got) != 1 || got[0] != "admin" {
		t.Errorf("subject roles = %v", got)
	}
	if got := cfg.RBAC.Groups["group-ops"]; len(got) != 2 {
		t.Errorf("group roles = %v", got)
	}
	if !cfg.Policy.RequireReason {
		t.Error("require_reason should be true")
	}
	if cfg.Policy.MaxCertValidityDays != 90 {
		t.Errorf("max_cert_validity_days = %d, want 90", cfg.Policy.MaxCertValidityDays)
	}
	if cfg.Policy.RootBasicAuthEnabled() {
		t.Error("root basic auth should be disabled")
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Name != "short-client" {
		t.Fatalf("profiles = %+v", cfg.Profiles)
	}
	if cfg.Profiles[0].MaxValidityDays != 30 {
		t.Errorf("profile max validity = %d, want 30", cfg.Profiles[0].MaxValidityDays)
	}
}

func TestRootBasicAuthDefaultsEnabled(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if !cfg.Policy.RootBasicAuthEnabled() {
		t.Error("root basic auth should default to enabled when unset")
	}
}

func TestRBACRejectsUnknownRole(t *testing.T) {
	clearProviderEnv(t)
	_, err := loadContent(t, `
root_user:
  password: secret
rbac:
  subjects:
    "bob": [superuser]
`)
	if err == nil {
		t.Fatal("expected error for unknown role name")
	}
}

func TestRBACRejectsUnknownGroupRole(t *testing.T) {
	clearProviderEnv(t)
	_, err := loadContent(t, `
root_user:
  password: secret
rbac:
  groups:
    "g1": [issuer, wizard]
`)
	if err == nil {
		t.Fatal("expected error for unknown group role name")
	}
}
