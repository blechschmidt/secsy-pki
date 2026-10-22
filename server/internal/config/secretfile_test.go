package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// clearCredentialEnv neutralizes every ambient credential variable so a test
// observes only what its config file says. scripts/setup-softhsm.sh exports
// SECSY_USER_PIN, and CI exports it for the whole job, so without this a test
// asserting on a file-sourced credential would be measuring the environment.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	clearProviderEnv(t)
	clearYubiHSMEnv(t)
	for _, k := range []string{
		"SECSY_ROOT_PASSWORD", "SECSY_ROOT_PASSWORD_FILE",
		"SECSY_USER_PIN_FILE", "SECSY_YUBIHSM_PASSWORD_FILE",
		"SECSY_DATABASE_DRIVER", "SECSY_DATABASE_DSN", "SECSY_DATABASE_DSN_FILE",
		"VAULT_TOKEN_FILE", "SECSY_VAULT_SECRET_ID_FILE",
	} {
		t.Setenv(k, "")
	}
}

// writeSecret writes a credential file with owner-only permissions (what a
// correctly-provisioned deployment looks like) and returns its path.
func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSecretFileResolvesPasswords proves the two credentials the feature exists
// for — the operator root password and the HSM password — can be named as files
// instead of written in the config, and that the resolved value is what the rest
// of the server sees.
func TestSecretFileResolvesPasswords(t *testing.T) {
	clearCredentialEnv(t)
	rootPW := writeSecret(t, "root.pw", "s3cr3t-root\n")
	hsmPW := writeSecret(t, "hsm.pw", "0001password\n")

	cfg := writeAndLoad(t, fmt.Sprintf(`
root_user:
  username: admin
  password_file: %q
yubihsm:
  connector_url: "http://127.0.0.1:12345"
  password_file: %q
`, rootPW, hsmPW))

	if cfg.RootUser.Password != "s3cr3t-root" {
		t.Errorf("root_user.password = %q, want the file's contents", cfg.RootUser.Password)
	}
	if cfg.YubiHSM.Password != "0001password" {
		t.Errorf("yubihsm.password = %q, want the file's contents", cfg.YubiHSM.Password)
	}
	// The path itself survives resolution: diagnostics should still be able to
	// say where a credential came from.
	if cfg.RootUser.PasswordFile != rootPW {
		t.Errorf("root_user.password_file = %q, want it preserved", cfg.RootUser.PasswordFile)
	}
}

// TestSecretFileMissingRootPasswordStillRequired proves a password_file that
// cannot be read is a load error naming the key, not a server that starts with
// an empty root password.
func TestSecretFileLoadErrors(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	good := writeSecret(t, "ok.pw", "pw\n")

	empty := filepath.Join(dir, "empty.pw")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose.pw")
	if err := os.WriteFile(loose, []byte("pw\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		yaml  string
		wants []string
	}{
		{
			name:  "missing file",
			yaml:  fmt.Sprintf("root_user:\n  password_file: %q\n", filepath.Join(dir, "nope.pw")),
			wants: []string{"root_user.password_file", "nope.pw"},
		},
		{
			name:  "directory",
			yaml:  fmt.Sprintf("root_user:\n  password_file: %q\n", dir),
			wants: []string{"root_user.password_file", "directory"},
		},
		{
			name:  "empty file",
			yaml:  fmt.Sprintf("root_user:\n  password_file: %q\n", empty),
			wants: []string{"root_user.password_file", "is empty"},
		},
		{
			name:  "group readable",
			yaml:  fmt.Sprintf("root_user:\n  password_file: %q\n", loose),
			wants: []string{"insecure permissions", "0644", "allow_insecure_secret_file_perms"},
		},
		{
			name:  "inline and file",
			yaml:  fmt.Sprintf("root_user:\n  password: inline\n  password_file: %q\n", good),
			wants: []string{"root_user.password", "root_user.password_file", "mutually exclusive"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, tc.yaml)
			if err == nil {
				t.Fatal("expected a load error")
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestSecretFileAllowInsecurePerms proves the deployment-wide escape hatch that
// exists for container runtimes, which project secrets 0644/0444.
func TestSecretFileAllowInsecurePerms(t *testing.T) {
	clearCredentialEnv(t)
	path := filepath.Join(t.TempDir(), "k8s.pw")
	if err := os.WriteFile(path, []byte("projected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := writeAndLoad(t, fmt.Sprintf(`
security:
  allow_insecure_secret_file_perms: true
root_user:
  password_file: %q
`, path))
	if cfg.RootUser.Password != "projected" {
		t.Errorf("root_user.password = %q", cfg.RootUser.Password)
	}
}

// TestSecretFileTrimming pins the trimming rule: one trailing line terminator
// and nothing else, so a password with meaningful whitespace survives a trip
// through a file.
func TestSecretFileTrimming(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"pw\n", "pw"},
		{"pw\r\n", "pw"},
		{"pw\r", "pw"},
		{"pw", "pw"},
		{"pw\n\n", "pw\n"},
		{" pw ", " pw "},
		{" pw \n", " pw "},
		{"pw with spaces\n", "pw with spaces"},
		{"\tpw\t\n", "\tpw\t"},
	}
	for _, tc := range cases {
		path := writeSecret(t, "pw", tc.raw)
		got, err := readSecretFile("root_user.password_file", path, false)
		if err != nil {
			t.Fatalf("readSecretFile(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("readSecretFile(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestPinFileExpandsToFilePinSource proves pkcs11.pin_file is the one-line
// spelling of a `file` pin_source: the PIN never enters the config struct, and
// the credential is read lazily by the Task 111 machinery.
func TestPinFileExpandsToFilePinSource(t *testing.T) {
	clearCredentialEnv(t)
	pin := writeSecret(t, "hsm.pin", "1234\n")
	cfg := writeAndLoad(t, fmt.Sprintf(`
root_user: {password: secret}
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: secsy
  pin_file: %q
`, pin))

	if cfg.PKCS11.PinSource.Type != "file" {
		t.Fatalf("pin_source.type = %q, want file", cfg.PKCS11.PinSource.Type)
	}
	if cfg.PKCS11.PinSource.File.Path != pin {
		t.Errorf("pin_source.file.path = %q, want %q", cfg.PKCS11.PinSource.File.Path, pin)
	}
	if cfg.PKCS11.Pin != "" {
		t.Errorf("pkcs11.pin = %q, want the PIN to stay out of the config struct", cfg.PKCS11.Pin)
	}
	// The expansion reaches the provider settings, which is what actually logs in.
	if got := cfg.PKCS11.KeyProviderSettings().PinSource; got.Type != "file" || got.File.Path != pin {
		t.Errorf("provider pin source = %+v, want file %q", got, pin)
	}
}

// TestPinFileConflicts proves the shorthand refuses to coexist with either form
// it is shorthand for, rather than silently picking one.
func TestPinFileConflicts(t *testing.T) {
	clearCredentialEnv(t)
	pin := writeSecret(t, "hsm.pin", "1234\n")
	base := "root_user: {password: secret}\npkcs11:\n  module_path: /usr/lib/softhsm/libsofthsm2.so\n"

	for _, tc := range []struct{ name, extra, want string }{
		{"inline pin", fmt.Sprintf("  pin: \"1234\"\n  pin_file: %q\n", pin), "pkcs11.pin and pkcs11.pin_file"},
		{"explicit source", fmt.Sprintf("  pin_file: %q\n  pin_source:\n    type: env\n", pin), "pkcs11.pin_source and pkcs11.pin_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, base+tc.extra)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// TestPinFilePrecedenceAgainstAmbientEnv pins the one place a credential's
// precedence deliberately differs from the rest: for the PIN, an explicitly
// configured external source wins over SECSY_USER_PIN — as pin_source always
// has — so pin_file, being only the shorthand for that source, is not quietly
// defeated by a variable left in the environment. scripts/setup-softhsm.sh
// exports SECSY_USER_PIN and CI exports it job-wide, so the alternative would be
// a production deployment reading the wrong PIN with nothing to see in its
// config.
func TestPinFilePrecedenceAgainstAmbientEnv(t *testing.T) {
	clearCredentialEnv(t)
	pin := writeSecret(t, "hsm.pin", "from-file\n")
	t.Setenv("SECSY_USER_PIN", "from-env")

	base := "root_user: {password: secret}\npkcs11:\n  module_path: /usr/lib/softhsm/libsofthsm2.so\n"
	cfg := writeAndLoad(t, base+fmt.Sprintf("  pin_file: %q\n", pin))
	if cfg.PKCS11.PinSource.Type != "file" || cfg.PKCS11.PinSource.File.Path != pin {
		t.Fatalf("pin_source = %+v, want the file the config named", cfg.PKCS11.PinSource)
	}
	if cfg.PKCS11.Pin != "" {
		t.Errorf("pkcs11.pin = %q — the ambient SECSY_USER_PIN was recorded anyway", cfg.PKCS11.Pin)
	}

	// The equivalence claim, asserted rather than asserted in prose: the
	// shorthand and the block it expands to must produce the same source under
	// the same environment.
	block := writeAndLoad(t, base+fmt.Sprintf("  pin_source:\n    type: file\n    file:\n      path: %q\n", pin))
	if block.PKCS11.PinSource != cfg.PKCS11.PinSource {
		t.Errorf("pin_file produced %+v but the pin_source block produced %+v", cfg.PKCS11.PinSource, block.PKCS11.PinSource)
	}

	// SECSY_USER_PIN_FILE names a source rather than carrying a value, so it does
	// replace a configured one.
	envPin := writeSecret(t, "env.pin", "from-env-file\n")
	t.Setenv("SECSY_USER_PIN_FILE", envPin)
	fromEnv := writeAndLoad(t, base+"  pin_source:\n    type: env\n    env:\n      var: SOMETHING_ELSE\n")
	if fromEnv.PKCS11.PinSource.Type != "file" || fromEnv.PKCS11.PinSource.File.Path != envPin {
		t.Errorf("pin_source = %+v, want the file SECSY_USER_PIN_FILE named", fromEnv.PKCS11.PinSource)
	}
}

// TestTokenPinFileExpandsPerToken proves each member of an HA token set takes
// its own PIN file, which is the shape of a real multi-HSM deployment.
func TestTokenPinFileExpandsPerToken(t *testing.T) {
	clearCredentialEnv(t)
	a := writeSecret(t, "a.pin", "aaaa\n")
	b := writeSecret(t, "b.pin", "bbbb\n")
	cfg := writeAndLoad(t, fmt.Sprintf(`
root_user: {password: secret}
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  tokens:
    - name: hsm-a
      token_label: a
      pin_file: %q
    - name: hsm-b
      token_label: b
      pin_file: %q
`, a, b))

	if len(cfg.PKCS11.Tokens) != 2 {
		t.Fatalf("tokens = %d", len(cfg.PKCS11.Tokens))
	}
	for i, want := range []string{a, b} {
		src := cfg.PKCS11.Tokens[i].PinSource
		if src.Type != "file" || src.File.Path != want {
			t.Errorf("token %d pin_source = %+v, want file %q", i, src, want)
		}
	}
}

// TestLDAPBindPasswordFileExpandsToSource covers the second shorthand that maps
// onto a credential source rather than a value.
func TestLDAPBindPasswordFileExpandsToSource(t *testing.T) {
	clearCredentialEnv(t)
	pw := writeSecret(t, "bind.pw", "bind-pw\n")
	cfg := writeAndLoad(t, fmt.Sprintf(`
root_user: {password: secret}
auth:
  ldap:
    enabled: true
    url: "ldaps://dc.example.com:636"
    bind_dn: "cn=svc,dc=example,dc=com"
    bind_password_file: %q
    user_base_dn: "ou=people,dc=example,dc=com"
    user_filter: "(uid=%%s)"
`, pw))

	src := cfg.Auth.LDAP.BindPasswordSource
	if src.Type != "file" || src.File.Path != pw {
		t.Fatalf("bind_password_source = %+v, want file %q", src, pw)
	}
	if cfg.Auth.LDAP.BindPassword != "" {
		t.Errorf("bind_password = %q, want empty", cfg.Auth.LDAP.BindPassword)
	}
}

// TestEABHMACKeysFile covers the one credential setting that is a mapping: the
// ACME External Account Binding keys, one shared secret per onboarded client.
func TestEABHMACKeysFile(t *testing.T) {
	clearCredentialEnv(t)
	t.Run("yaml mapping", func(t *testing.T) {
		keys := writeSecret(t, "eab.yaml", "kid-one: c2VjcmV0MQ\nkid-two: c2VjcmV0Mg\n")
		cfg := writeAndLoad(t, fmt.Sprintf(`
root_user: {password: secret}
acme:
  require_eab: true
  eab_hmac_keys_file: %q
`, keys))
		if got := cfg.ACME.EABHMACKeys["kid-one"]; got != "c2VjcmV0MQ" {
			t.Errorf("kid-one = %q", got)
		}
		if len(cfg.ACME.EABHMACKeys) != 2 {
			t.Errorf("keys = %d, want 2", len(cfg.ACME.EABHMACKeys))
		}
	})

	t.Run("json mapping", func(t *testing.T) {
		keys := writeSecret(t, "eab.json", `{"kid-one":"c2VjcmV0MQ"}`)
		cfg := writeAndLoad(t, fmt.Sprintf("root_user: {password: secret}\nacme:\n  eab_hmac_keys_file: %q\n", keys))
		if got := cfg.ACME.EABHMACKeys["kid-one"]; got != "c2VjcmV0MQ" {
			t.Errorf("kid-one = %q", got)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		keys := writeSecret(t, "eab.yaml", "kid: c2VjcmV0\n")
		_, err := loadContent(t, fmt.Sprintf(
			"root_user: {password: secret}\nacme:\n  eab_hmac_keys: {kid: c2VjcmV0}\n  eab_hmac_keys_file: %q\n", keys))
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("not a mapping", func(t *testing.T) {
		keys := writeSecret(t, "eab.yaml", "- just-a-list\n")
		_, err := loadContent(t, fmt.Sprintf("root_user: {password: secret}\nacme:\n  eab_hmac_keys_file: %q\n", keys))
		if err == nil || !strings.Contains(err.Error(), "mapping of kid -> key") {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestDatabaseDSNFile proves the DSN — which embeds the PostgreSQL password —
// can be named as a file despite the built-in SQLite default already occupying
// the inline field.
func TestDatabaseDSNFile(t *testing.T) {
	clearCredentialEnv(t)
	dsn := writeSecret(t, "dsn", "postgres://secsy:pgpw@db.example.com:5432/secsy_pki?sslmode=require\n")
	cfg := writeAndLoad(t, fmt.Sprintf(`
root_user: {password: secret}
database:
  driver: postgres
  dsn_file: %q
`, dsn))
	if !strings.Contains(cfg.Database.DSN, "pgpw@db.example.com") {
		t.Fatalf("database.dsn = %q, want the file's contents", cfg.Database.DSN)
	}

	// An explicitly configured DSN alongside dsn_file is still a conflict.
	_, err := loadContent(t, fmt.Sprintf(
		"root_user: {password: secret}\ndatabase:\n  driver: postgres\n  dsn: \"host=x\"\n  dsn_file: %q\n", dsn))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want a conflict", err)
	}
}

// TestSecretFileEnvOverrides proves the precedence rule: an environment variable
// supersedes a file named in the config, in both directions, with no ambiguity
// left over.
func TestSecretFileEnvOverrides(t *testing.T) {
	clearCredentialEnv(t)
	fileInConfig := writeSecret(t, "cfg.pw", "from-config-file\n")
	fileInEnv := writeSecret(t, "env.pw", "from-env-file\n")

	t.Run("env value beats config file", func(t *testing.T) {
		t.Setenv("SECSY_ROOT_PASSWORD", "from-env")
		cfg := writeAndLoad(t, fmt.Sprintf("root_user:\n  password_file: %q\n", fileInConfig))
		if cfg.RootUser.Password != "from-env" {
			t.Errorf("password = %q, want the environment's value", cfg.RootUser.Password)
		}
	})

	t.Run("env file beats config value", func(t *testing.T) {
		t.Setenv("SECSY_ROOT_PASSWORD_FILE", fileInEnv)
		cfg := writeAndLoad(t, "root_user:\n  password: from-config\n")
		if cfg.RootUser.Password != "from-env-file" {
			t.Errorf("password = %q, want the environment file's contents", cfg.RootUser.Password)
		}
	})

	t.Run("direct env wins over env file", func(t *testing.T) {
		t.Setenv("SECSY_ROOT_PASSWORD_FILE", fileInEnv)
		t.Setenv("SECSY_ROOT_PASSWORD", "direct")
		cfg := writeAndLoad(t, "root_user: {}\n")
		if cfg.RootUser.Password != "direct" {
			t.Errorf("password = %q, want the direct variable", cfg.RootUser.Password)
		}
	})

	t.Run("pin file from env", func(t *testing.T) {
		pin := writeSecret(t, "pin", "9999\n")
		t.Setenv("SECSY_USER_PIN_FILE", pin)
		cfg := writeAndLoad(t, "root_user: {password: secret}\npkcs11:\n  module_path: /usr/lib/softhsm/libsofthsm2.so\n")
		if cfg.PKCS11.PinSource.Type != "file" || cfg.PKCS11.PinSource.File.Path != pin {
			t.Errorf("pin_source = %+v, want file %q", cfg.PKCS11.PinSource, pin)
		}
	})

	t.Run("yubihsm password from env file", func(t *testing.T) {
		pw := writeSecret(t, "yhpw", "yh-secret\n")
		t.Setenv("SECSY_YUBIHSM_PASSWORD_FILE", pw)
		cfg := writeAndLoad(t, "root_user: {password: secret}\n")
		if cfg.YubiHSM.Password != "yh-secret" {
			t.Errorf("yubihsm.password = %q", cfg.YubiHSM.Password)
		}
	})

	t.Run("database dsn from env file", func(t *testing.T) {
		dsn := writeSecret(t, "dsn", "host=db user=secsy password=pgpw\n")
		t.Setenv("SECSY_DATABASE_DSN_FILE", dsn)
		cfg := writeAndLoad(t, "root_user: {password: secret}\n")
		if cfg.Database.DSN != "host=db user=secsy password=pgpw" {
			t.Errorf("database.dsn = %q", cfg.Database.DSN)
		}
	})
}

// everySecretFileKey builds a config that exercises every `*_file` key at once,
// returning the YAML plus the plaintext each file holds keyed by the field it is
// expected to land in. It is the completeness fixture: a credential field that
// gains a file form must be added here, and the assertions below then prove it
// resolves and is redacted.
func everySecretFileKey(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	secret := func(name, value string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	want := map[string]string{}
	p := func(name, value string) string {
		want[name] = value
		return secret(name, value)
	}

	yamlDoc := fmt.Sprintf(`
root_user:
  username: admin
  password_file: %q
database:
  driver: postgres
  dsn_file: %q
yubihsm:
  connector_url: "http://127.0.0.1:12345"
  password_file: %q
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: secsy
  pin_file: %q
  tokens:
    - name: hsm-b
      token_label: b
      pin_file: %q
    - name: hsm-c
      token_label: c
      pin_source:
        type: vault
        vault:
          address: "https://vault.example.com"
          path: hsm/prod
          token_file: %q
key_provider:
  type: pkcs11
  kms:
    vault:
      address: "https://vault.example.com"
      auth_method: approle
      role_id: r
      token_file: %q
      secret_id_file: %q
auth:
  oidc:
    enabled: true
    issuer_url: "https://idp.example.com"
    client_id: secsy
    redirect_url: "https://pki.example.com/auth/callback"
    client_secret_file: %q
  ldap:
    enabled: true
    url: "ldaps://dc.example.com:636"
    bind_dn: "cn=svc,dc=example,dc=com"
    bind_password_file: %q
    user_base_dn: "ou=people,dc=example,dc=com"
    user_filter: "(uid=%%s)"
acme:
  nonce_hmac_key_file: %q
  eab_hmac_keys_file: %q
  email:
    smtp:
      host: smtp.example.com
      username: acme
      password_file: %q
    imap:
      host: imap.example.com
      username: acme
      password_file: %q
publish:
  s3:
    bucket: pki-artifacts
    access_key_id: AKIAEXAMPLE
    secret_access_key_file: %q
    session_token_file: %q
backup:
  s3:
    bucket: pki-backups
    access_key_id: AKIAEXAMPLE
    secret_access_key_file: %q
    session_token_file: %q
scep:
  enabled: true
  ca_label: issuing-ca
  grants:
    - name: field-devices
      challenge_file: %q
est:
  enabled: true
  ca_label: issuing-ca
  users:
    device-01:
      password_file: %q
cmp:
  enabled: true
  ca_label: issuing-ca
  secrets:
    - reference: kid-1
      secret_file: %q
`,
		p("root.pw", "root-password"),
		p("database.dsn", "postgres://secsy:pgpw@db.example.com/secsy_pki"),
		p("yubihsm.pw", "yubihsm-password"),
		p("pkcs11.pin", "hsm-pin"),
		p("token-b.pin", "token-b-pin"),
		p("pinsource.vault.token", "pinsource-vault-token"),
		p("kms.vault.token", "kms-vault-token"),
		p("kms.vault.secret-id", "kms-vault-secret-id"),
		p("oidc.client-secret", "oidc-client-secret"),
		p("ldap.bind.pw", "ldap-bind-password"),
		p("acme.nonce", "YWNtZS1ub25jZS1obWFjLWtleQ"),
		secret("acme.eab", "kid-one: ZWFiLWhtYWMta2V5"),
		p("smtp.pw", "smtp-password"),
		p("imap.pw", "imap-password"),
		p("publish.s3.secret", "publish-s3-secret-key"),
		p("publish.s3.token", "publish-s3-session-token"),
		p("backup.s3.secret", "backup-s3-secret-key"),
		p("backup.s3.token", "backup-s3-session-token"),
		p("scep.field-devices.challenge", "scep-challenge-password"),
		p("est.device-01.pw", "est-device-password"),
		p("cmp.kid-1.secret", "cmp-shared-secret"),
	)
	want["acme.eab"] = "ZWFiLWhtYWMta2V5"
	return yamlDoc, want
}

// TestEverySecretFileKeyResolves proves every credential field that advertises a
// `*_file` form actually resolves from it — the completeness check that keeps a
// newly added file key from being inert.
func TestEverySecretFileKeyResolves(t *testing.T) {
	clearCredentialEnv(t)
	doc, want := everySecretFileKey(t)
	cfg := writeAndLoad(t, doc)

	got := map[string]string{
		"root.pw":                      cfg.RootUser.Password,
		"database.dsn":                 cfg.Database.DSN,
		"yubihsm.pw":                   cfg.YubiHSM.Password,
		"pinsource.vault.token":        cfg.PKCS11.Tokens[1].PinSource.Vault.Token,
		"kms.vault.token":              cfg.KeyProvider.KMS.Vault.Token,
		"kms.vault.secret-id":          cfg.KeyProvider.KMS.Vault.SecretID,
		"oidc.client-secret":           cfg.Auth.OIDC.ClientSecret,
		"acme.nonce":                   cfg.ACME.NonceHMACKey,
		"acme.eab":                     cfg.ACME.EABHMACKeys["kid-one"],
		"smtp.pw":                      cfg.ACME.Email.SMTP.Password,
		"imap.pw":                      cfg.ACME.Email.IMAP.Password,
		"publish.s3.secret":            cfg.Publish.S3.SecretAccessKey,
		"publish.s3.token":             cfg.Publish.S3.SessionToken,
		"backup.s3.secret":             cfg.Backup.S3.SecretAccessKey,
		"backup.s3.token":              cfg.Backup.S3.SessionToken,
		"scep.field-devices.challenge": cfg.SCEP.Grants[0].Challenge,
		"est.device-01.pw":             cfg.EST.Users["device-01"].Password,
		"cmp.kid-1.secret":             cfg.CMP.Secrets[0].Secret,
	}

	// Every file the fixture wrote must be accounted for above: a key present in
	// `want` but missing from `got` reads as "" and fails here, which is what
	// makes this the completeness check rather than a spot check.
	for key, wantValue := range want {
		if key == "pkcs11.pin" || key == "token-b.pin" || key == "ldap.bind.pw" {
			continue // lazily-resolved sources, asserted below
		}
		if got[key] != wantValue {
			t.Errorf("%s resolved to %q, want %q", key, got[key], wantValue)
		}
	}

	// The three shorthands that expand to a credential source keep the secret
	// out of the config entirely.
	if cfg.PKCS11.PinSource.Type != "file" || cfg.PKCS11.Pin != "" {
		t.Errorf("pkcs11 pin source = %+v, pin = %q", cfg.PKCS11.PinSource, cfg.PKCS11.Pin)
	}
	if cfg.PKCS11.Tokens[0].PinSource.Type != "file" {
		t.Errorf("token pin source = %+v", cfg.PKCS11.Tokens[0].PinSource)
	}
	if cfg.Auth.LDAP.BindPasswordSource.Type != "file" || cfg.Auth.LDAP.BindPassword != "" {
		t.Errorf("ldap bind source = %+v, password = %q", cfg.Auth.LDAP.BindPasswordSource, cfg.Auth.LDAP.BindPassword)
	}
}

// TestRedactedMasksFileSourcedCredentials proves the redaction API keeps pace
// with the file convention: a credential delivered as a file ends up in the same
// field an inline one would, so a dumped config must not leak it.
func TestRedactedMasksFileSourcedCredentials(t *testing.T) {
	clearCredentialEnv(t)
	doc, want := everySecretFileKey(t)
	cfg := writeAndLoad(t, doc)

	out, err := yaml.Marshal(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	dump := string(out)
	for key, plaintext := range want {
		if key == "pkcs11.pin" || key == "token-b.pin" || key == "ldap.bind.pw" {
			continue // never read into the config at all
		}
		if strings.Contains(dump, plaintext) {
			t.Errorf("redacted dump leaks %s (%q)", key, plaintext)
		}
	}
	// Redacting must not mutate the original — including the credentials held in
	// maps and slices, which a shallow struct copy would alias.
	for what, got := range map[string]string{
		"root_user.password":       cfg.RootUser.Password,
		"acme.eab_hmac_keys":       cfg.ACME.EABHMACKeys["kid-one"],
		"est.users[].password":     cfg.EST.Users["device-01"].Password,
		"cmp.secrets[].secret":     cfg.CMP.Secrets[0].Secret,
		"scep.grants[].challenge":  cfg.SCEP.Grants[0].Challenge,
		"publish.s3.secret":        cfg.Publish.S3.SecretAccessKey,
		"acme.email.smtp.password": cfg.ACME.Email.SMTP.Password,
	} {
		if got == redactedSecret || got == "" {
			t.Errorf("Redacted mutated the original config: %s = %q", what, got)
		}
	}
	// A path is not a secret: the dump should still say where each credential
	// came from, or it is useless for diagnosing a deployment.
	if !strings.Contains(dump, "password_file") {
		t.Error("redacted dump dropped the credential file paths")
	}
}

// TestRedactDSN proves the DSN is masked where it carries a password and left
// readable where it does not — a dumped DSN is how an operator confirms which
// database a replica is talking to.
func TestRedactDSN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"secsy-pki.db", "secsy-pki.db"},
		{"file:/var/lib/secsy/pki.db?_journal=WAL", "file:/var/lib/secsy/pki.db?_journal=WAL"},
		{"host=db user=secsy dbname=pki sslmode=require", "host=db user=secsy dbname=pki sslmode=require"},
		{
			"postgres://secsy:pgpw@db.example.com:5432/pki?sslmode=require",
			"postgres://secsy:" + redactedSecret + "@db.example.com:5432/pki?sslmode=require",
		},
		{"postgres://secsy@db.example.com/pki", "postgres://secsy@db.example.com/pki"},
		{
			"host=db user=secsy password=pgpw dbname=pki",
			"host=db user=secsy password=" + redactedSecret + " dbname=pki",
		},
		{
			"host=db password='pg pw with spaces' dbname=pki",
			"host=db password=" + redactedSecret + " dbname=pki",
		},
		{
			"host=db PASSWORD=pgpw dbname=pki",
			"host=db PASSWORD=" + redactedSecret + " dbname=pki",
		},
	}
	for _, tc := range cases {
		if got := redactDSN(tc.in); got != tc.want {
			t.Errorf("redactDSN(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.in != "" && strings.Contains(redactDSN(tc.in), "pgpw") {
			t.Errorf("redactDSN(%q) leaked the password", tc.in)
		}
	}
}

// TestSecretFileKeysAreKnownFields proves `secsy-ca doctor`'s strict re-decode
// recognizes every new key, so a correct config is not reported as a typo.
func TestSecretFileKeysAreKnownFields(t *testing.T) {
	clearCredentialEnv(t)
	doc, _ := everySecretFileKey(t)
	unknown, err := UnknownKeys([]byte(doc))
	if err != nil {
		t.Fatalf("UnknownKeys: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("strict decode rejected known keys: %v", unknown)
	}
}
