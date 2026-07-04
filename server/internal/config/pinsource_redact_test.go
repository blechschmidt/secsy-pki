package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestConfigRedactedMasksSecrets asserts that Config.Redacted masks every
// credential — including the new pkcs11 pin and pin_source Vault credentials —
// while preserving non-secret fields, and does not mutate the original config.
func TestConfigRedactedMasksSecrets(t *testing.T) {
	c := &Config{
		RootUser: RootUserConfig{Username: "root", Password: "rootpw"},
		YubiHSM:  YubiHSMConfig{Password: "yubipw"},
		PKCS11: PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			Pin:        "toppin",
			PinSource: PinSourceConfig{
				Type: "vault",
				Vault: VaultPinSourceConfig{
					VaultProviderConfig: VaultProviderConfig{
						Address:  "https://vault.example:8200",
						Token:    "vtoken",
						SecretID: "vsecret",
					},
					Path: "hsm/prod",
				},
			},
			Tokens: []PKCS11TokenConfig{{Name: "t1", Pin: "tokpin"}},
		},
		KeyProvider: KeyProviderConfig{
			KMS: KMSProviderConfig{Vault: VaultProviderConfig{Token: "kmsvtoken", SecretID: "kmsvsecret"}},
		},
	}

	red := c.Redacted()

	// The original must be untouched (Redacted returns a copy).
	if c.PKCS11.Pin != "toppin" || c.PKCS11.Tokens[0].Pin != "tokpin" ||
		c.PKCS11.PinSource.Vault.Token != "vtoken" || c.RootUser.Password != "rootpw" ||
		c.KeyProvider.KMS.Vault.SecretID != "kmsvsecret" {
		t.Fatal("Redacted mutated the original config")
	}

	// Every credential field is masked to the placeholder.
	for field, got := range map[string]string{
		"pkcs11.pin":                        red.PKCS11.Pin,
		"pkcs11.tokens[0].pin":              red.PKCS11.Tokens[0].Pin,
		"pkcs11.pin_source.vault.token":     red.PKCS11.PinSource.Vault.Token,
		"pkcs11.pin_source.vault.secret_id": red.PKCS11.PinSource.Vault.SecretID,
		"root_user.password":                red.RootUser.Password,
		"yubihsm.password":                  red.YubiHSM.Password,
		"key_provider.kms.vault.token":      red.KeyProvider.KMS.Vault.Token,
		"key_provider.kms.vault.secret_id":  red.KeyProvider.KMS.Vault.SecretID,
	} {
		if got != redactedSecret {
			t.Errorf("%s = %q, want %q", field, got, redactedSecret)
		}
	}

	// Non-secret fields survive redaction.
	if red.PKCS11.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" ||
		red.PKCS11.PinSource.Vault.Address != "https://vault.example:8200" ||
		red.PKCS11.PinSource.Vault.Path != "hsm/prod" ||
		red.PKCS11.Tokens[0].Name != "t1" {
		t.Errorf("redaction dropped a non-secret field: %+v", red.PKCS11)
	}

	// A dump of the (self-contained) pkcs11 subtree must not leak any secret.
	dump := marshalYAML(t, red.PKCS11)
	for _, secret := range []string{"toppin", "tokpin", "vtoken", "vsecret"} {
		if strings.Contains(dump, secret) {
			t.Errorf("redacted pkcs11 dump leaks secret %q:\n%s", secret, dump)
		}
	}
	if !strings.Contains(dump, redactedSecret) {
		t.Errorf("expected redaction placeholder in pkcs11 dump:\n%s", dump)
	}
}

func marshalYAML(t *testing.T, v any) string {
	t.Helper()
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

// TestRedactedNilSafe guards the nil receiver path.
func TestRedactedNilSafe(t *testing.T) {
	var c *Config
	if c.Redacted() != nil {
		t.Error("nil config should redact to nil")
	}
}
