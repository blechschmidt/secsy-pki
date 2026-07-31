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
				GCP: GCPPinSourceConfig{Project: "proj", Secret: "hsm-pin", CredentialsJSON: "pingcpjson"},
			},
			Tokens: []PKCS11TokenConfig{{Name: "t1", Pin: "tokpin"}},
		},
		KeyProvider: KeyProviderConfig{
			KMS: KMSProviderConfig{
				Vault: VaultProviderConfig{Token: "kmsvtoken", SecretID: "kmsvsecret"},
				GCP:   GCPProviderConfig{Project: "proj", CredentialsJSON: "kmsgcpjson"},
			},
		},
	}

	red := c.Redacted()

	// The original must be untouched (Redacted returns a copy).
	if c.PKCS11.Pin != "toppin" || c.PKCS11.Tokens[0].Pin != "tokpin" ||
		c.PKCS11.PinSource.Vault.Token != "vtoken" || c.RootUser.Password != "rootpw" ||
		c.KeyProvider.KMS.Vault.SecretID != "kmsvsecret" ||
		c.KeyProvider.KMS.GCP.CredentialsJSON != "kmsgcpjson" {
		t.Fatal("Redacted mutated the original config")
	}

	// Every credential field is masked to the placeholder.
	for field, got := range map[string]string{
		"pkcs11.pin":                             red.PKCS11.Pin,
		"pkcs11.tokens[0].pin":                   red.PKCS11.Tokens[0].Pin,
		"pkcs11.pin_source.vault.token":          red.PKCS11.PinSource.Vault.Token,
		"pkcs11.pin_source.vault.secret_id":      red.PKCS11.PinSource.Vault.SecretID,
		"root_user.password":                     red.RootUser.Password,
		"yubihsm.password":                       red.YubiHSM.Password,
		"key_provider.kms.vault.token":           red.KeyProvider.KMS.Vault.Token,
		"key_provider.kms.vault.secret_id":       red.KeyProvider.KMS.Vault.SecretID,
		"key_provider.kms.gcp.credentials_json":  red.KeyProvider.KMS.GCP.CredentialsJSON,
		"pkcs11.pin_source.gcp.credentials_json": red.PKCS11.PinSource.GCP.CredentialsJSON,
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
	for _, secret := range []string{"toppin", "tokpin", "vtoken", "vsecret", "pingcpjson"} {
		if strings.Contains(dump, secret) {
			t.Errorf("redacted pkcs11 dump leaks secret %q:\n%s", secret, dump)
		}
	}
	if !strings.Contains(dump, redactedSecret) {
		t.Errorf("expected redaction placeholder in pkcs11 dump:\n%s", dump)
	}
}

// TestRedactedMasksURIPinValue asserts that a pin-value embedded in an RFC 7512
// pkcs11: URI (top-level or per-token) is stripped from a redacted config, while
// the URI's non-secret attributes survive.
func TestRedactedMasksURIPinValue(t *testing.T) {
	c := &Config{
		PKCS11: PKCS11Config{
			URI: "pkcs11:token=softtoken?module-path=/lib/p11.so&pin-value=topsecret",
			Tokens: []PKCS11TokenConfig{
				{Name: "t1", URI: "pkcs11:serial=SER-1?pin-value=tokensecret"},
			},
		},
	}

	red := c.Redacted()

	// Original untouched.
	if !strings.Contains(c.PKCS11.URI, "topsecret") || !strings.Contains(c.PKCS11.Tokens[0].URI, "tokensecret") {
		t.Fatal("Redacted mutated the original URI")
	}

	dump := marshalYAML(t, red.PKCS11)
	for _, secret := range []string{"topsecret", "tokensecret"} {
		if strings.Contains(dump, secret) {
			t.Errorf("redacted pkcs11 dump leaks URI pin-value %q:\n%s", secret, dump)
		}
	}
	// Non-secret URI attributes survive.
	if !strings.Contains(red.PKCS11.URI, "softtoken") || !strings.Contains(red.PKCS11.URI, "/lib/p11.so") {
		t.Errorf("redaction dropped non-secret URI attributes: %q", red.PKCS11.URI)
	}
	if !strings.Contains(red.PKCS11.Tokens[0].URI, "SER-1") {
		t.Errorf("redaction dropped non-secret token URI attributes: %q", red.PKCS11.Tokens[0].URI)
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

// TestRedactedMasksAuthSecrets asserts that the operator-authentication secrets —
// the OIDC confidential-client secret and the LDAP bind-service-account password
// (inline and any credential-store token backing bind_password_source) — are
// masked, while non-secret directory settings survive.
func TestRedactedMasksAuthSecrets(t *testing.T) {
	c := &Config{
		Auth: AuthConfig{
			OIDC: AuthOIDCConfig{ClientSecret: "oidcsecret"},
			LDAP: AuthLDAPConfig{
				Enabled:      true,
				URL:          "ldaps://ad.example.com:636",
				BindDN:       "CN=svc,DC=example,DC=com",
				BindPassword: "bindpw",
				BindPasswordSource: PinSourceConfig{
					Type:  "vault",
					Vault: VaultPinSourceConfig{VaultProviderConfig: VaultProviderConfig{Token: "ldapvtoken"}},
				},
			},
		},
	}

	red := c.Redacted()

	// Original untouched.
	if c.Auth.LDAP.BindPassword != "bindpw" || c.Auth.OIDC.ClientSecret != "oidcsecret" ||
		c.Auth.LDAP.BindPasswordSource.Vault.Token != "ldapvtoken" {
		t.Fatal("Redacted mutated the original auth config")
	}

	for field, got := range map[string]string{
		"auth.oidc.client_secret":                    red.Auth.OIDC.ClientSecret,
		"auth.ldap.bind_password":                    red.Auth.LDAP.BindPassword,
		"auth.ldap.bind_password_source.vault.token": red.Auth.LDAP.BindPasswordSource.Vault.Token,
	} {
		if got != redactedSecret {
			t.Errorf("%s = %q, want %q", field, got, redactedSecret)
		}
	}

	// Non-secret directory settings survive.
	if red.Auth.LDAP.URL != "ldaps://ad.example.com:636" || red.Auth.LDAP.BindDN != "CN=svc,DC=example,DC=com" {
		t.Errorf("redaction dropped non-secret LDAP fields: %+v", red.Auth.LDAP)
	}

	dump := marshalYAML(t, red.Auth)
	for _, secret := range []string{"bindpw", "oidcsecret", "ldapvtoken"} {
		if strings.Contains(dump, secret) {
			t.Errorf("redacted auth dump leaks secret %q:\n%s", secret, dump)
		}
	}
}

// TestRedactedNilSafe guards the nil receiver path.
func TestRedactedNilSafe(t *testing.T) {
	var c *Config
	if c.Redacted() != nil {
		t.Error("nil config should redact to nil")
	}
}
