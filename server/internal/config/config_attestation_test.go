package config

import "testing"

func TestLoadAttestationConfig(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
attestation:
  default_mode: permissive
  trusted_roots_pem: |
    -----BEGIN CERTIFICATE-----
    MIIB
    -----END CERTIFICATE-----
profiles:
  - name: hw-client
    description: "Hardware-attested client cert"
    key_usages: [digitalSignature]
    ext_key_usages: [clientAuth]
    default_validity_days: 30
    attestation:
      mode: require
`)

	if cfg.Attestation.DefaultMode != "permissive" {
		t.Errorf("default_mode = %q, want permissive", cfg.Attestation.DefaultMode)
	}
	if cfg.Attestation.TrustedRootsPEM == "" {
		t.Error("trusted_roots_pem should be populated")
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Attestation.Mode != "require" {
		t.Errorf("profile attestation mode = %+v, want require", cfg.Profiles)
	}
}
