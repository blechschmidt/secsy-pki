package config

// This file implements the `*_file` credential convention: every password-shaped
// setting in config.yaml has a sibling key naming a *file* whose contents are the
// value, so a deployment can keep the credential out of the configuration
// altogether.
//
// The motivation is that a config file is the wrong place for a secret and is
// treated as such by everything around it. It is rendered by a templating tool
// into a Kubernetes ConfigMap, baked into a container image, committed to the
// repository that describes the environment, copied by an operator debugging a
// rollout, and printed wholesale in a bug report. Secret delivery, meanwhile, is
// already solved on every platform this runs on — and it is solved by presenting
// a file: Kubernetes projects a Secret volume, Docker and Swarm mount
// /run/secrets/*, systemd writes LoadCredential= into $CREDENTIALS_DIRECTORY,
// Vault Agent and the CSI driver template a file, and a bare host has
// root-owned 0600 under /etc. Naming that file is therefore the one form that
// needs no new machinery anywhere.
//
// Conventions, uniform across every field:
//
//   - `<key>_file` holds a path; `<key>` holds the literal value. Setting both is
//     an error rather than a precedence rule — a deployment that disagrees with
//     itself about where a CA's credential comes from should be told, not quietly
//     resolved in a direction the operator may not have intended.
//   - The file's contents are the credential verbatim, minus one trailing line
//     terminator (so `echo "pw" > file` works, and so does `printf %s`). No other
//     whitespace is stripped: a leading space or an interior tab may be part of
//     the password, and silently eating it would produce an authentication
//     failure no amount of staring at the file would explain. An empty file is an
//     error.
//   - The file must not be readable by group or other. A credential every local
//     account can read has not been externalized, only relocated. The invariant
//     is relaxed deployment-wide by security.allow_insecure_secret_file_perms,
//     which an orchestrated deployment needs: a projected Kubernetes Secret is a
//     root-owned per-pod tmpfs that a non-root container can only read through
//     the group bits, so the mode was never the boundary there. See that field's
//     documentation.
//   - Resolution happens once, at config load, after the environment overrides.
//     A path that does not exist, is a directory, or fails the permission check
//     is a load error — the server refuses to start rather than binding its
//     listener and failing every request that needs the credential.
//
// Two fields resolve to a lazily-read credential *source* instead of a value:
// pkcs11.pin_file and auth.ldap.bind_password_file expand to the equivalent
// `file` pin_source (Task 111), which keeps the PIN out of the Config struct
// entirely and inherits that machinery's startup preflight and `secsy-ca doctor`
// integration. Their file is still stat-checked here so the failure is reported
// at load time like every other one. Being a source rather than a value is also
// why the PIN's precedence against the environment differs — see the
// SECSY_USER_PIN handling in applyEnvOverrides.

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// secretFileRef binds one `*_file` setting to the inline setting it replaces.
// The installer is a closure rather than a *string so map values and slice
// elements bind the same way struct fields do.
type secretFileRef struct {
	// fileKey / inlineKey are the dotted config keys, used verbatim in errors so
	// an operator can grep for them in their own configuration.
	fileKey   string
	inlineKey string
	// path is the configured file, "" when the key is unset.
	path string
	// inline is the current literal value, "" when that key is unset.
	inline string
	// install stores the resolved credential.
	install func(string)
}

func strRef(fileKey, inlineKey, path string, inline *string) secretFileRef {
	return secretFileRef{
		fileKey:   fileKey,
		inlineKey: inlineKey,
		path:      path,
		inline:    *inline,
		install:   func(v string) { *inline = v },
	}
}

// vaultSecretFileRefs returns the credential bindings of one Vault connection
// block. The same struct backs the Transit key-provider backend and every
// `vault` pin_source, so each place it appears contributes these two.
func vaultSecretFileRefs(prefix string, v *VaultProviderConfig) []secretFileRef {
	return []secretFileRef{
		strRef(prefix+".token_file", prefix+".token", v.TokenFile, &v.Token),
		strRef(prefix+".secret_id_file", prefix+".secret_id", v.SecretIDFile, &v.SecretID),
	}
}

// pinSourceSecretFileRefs returns the credential bindings nested inside a
// pin_source block (its Vault token / AppRole secret-id).
func pinSourceSecretFileRefs(prefix string, p *PinSourceConfig) []secretFileRef {
	return vaultSecretFileRefs(prefix+".vault", &p.Vault.VaultProviderConfig)
}

// secretFileRefs enumerates every `*_file` credential binding in the
// configuration. It is the single list the resolver, the schema documentation,
// and the tests all work from, so a new credential field is wired up — and
// covered — by adding one line here.
func (c *Config) secretFileRefs() []secretFileRef {
	refs := []secretFileRef{
		strRef("root_user.password_file", "root_user.password", c.RootUser.PasswordFile, &c.RootUser.Password),
		strRef("yubihsm.password_file", "yubihsm.password", c.YubiHSM.PasswordFile, &c.YubiHSM.Password),
		strRef("auth.oidc.client_secret_file", "auth.oidc.client_secret", c.Auth.OIDC.ClientSecretFile, &c.Auth.OIDC.ClientSecret),
		strRef("acme.nonce_hmac_key_file", "acme.nonce_hmac_key", c.ACME.NonceHMACKeyFile, &c.ACME.NonceHMACKey),
		strRef("acme.email.smtp.password_file", "acme.email.smtp.password", c.ACME.Email.SMTP.PasswordFile, &c.ACME.Email.SMTP.Password),
		strRef("acme.email.imap.password_file", "acme.email.imap.password", c.ACME.Email.IMAP.PasswordFile, &c.ACME.Email.IMAP.Password),
		strRef("publish.s3.secret_access_key_file", "publish.s3.secret_access_key", c.Publish.S3.SecretAccessKeyFile, &c.Publish.S3.SecretAccessKey),
		strRef("publish.s3.session_token_file", "publish.s3.session_token", c.Publish.S3.SessionTokenFile, &c.Publish.S3.SessionToken),
		strRef("backup.s3.secret_access_key_file", "backup.s3.secret_access_key", c.Backup.S3.SecretAccessKeyFile, &c.Backup.S3.SecretAccessKey),
		strRef("backup.s3.session_token_file", "backup.s3.session_token", c.Backup.S3.SessionTokenFile, &c.Backup.S3.SessionToken),
	}

	// The DSN carries a default ("secsy-pki.db", installed before the file is
	// parsed), so an inline value that still equals it was never configured and
	// must not read as a conflict with dsn_file.
	dsn := strRef("database.dsn_file", "database.dsn", c.Database.DSNFile, &c.Database.DSN)
	if dsn.inline == defaultDatabaseDSN {
		dsn.inline = ""
	}
	refs = append(refs, dsn)

	refs = append(refs, vaultSecretFileRefs("key_provider.kms.vault", &c.KeyProvider.KMS.Vault)...)
	refs = append(refs, pinSourceSecretFileRefs("pkcs11.pin_source", &c.PKCS11.PinSource)...)
	refs = append(refs, pinSourceSecretFileRefs("auth.ldap.bind_password_source", &c.Auth.LDAP.BindPasswordSource)...)
	for i := range c.PKCS11.Tokens {
		refs = append(refs, pinSourceSecretFileRefs(fmt.Sprintf("pkcs11.tokens[%d].pin_source", i), &c.PKCS11.Tokens[i].PinSource)...)
	}

	// est.users is a map of value structs: a map entry is not addressable, so the
	// installer writes the whole entry back. Iterate in sorted order — two
	// misconfigured users would otherwise be reported in whichever order the map
	// happened to hash, and a load error an operator diffs should be stable.
	for _, name := range sortedUserNames(c.EST.Users) {
		name, u := name, c.EST.Users[name]
		if u.PasswordFile == "" && u.Password == "" {
			continue
		}
		refs = append(refs, secretFileRef{
			fileKey:   fmt.Sprintf("est.users[%q].password_file", name),
			inlineKey: fmt.Sprintf("est.users[%q].password", name),
			path:      u.PasswordFile,
			inline:    u.Password,
			install: func(v string) {
				e := c.EST.Users[name]
				e.Password = v
				c.EST.Users[name] = e
			},
		})
	}
	for i := range c.SCEP.Grants {
		g := &c.SCEP.Grants[i]
		refs = append(refs, strRef(
			fmt.Sprintf("scep.grants[%d].challenge_file", i),
			fmt.Sprintf("scep.grants[%d].challenge", i),
			g.ChallengeFile, &g.Challenge))
	}
	for i := range c.CMP.Secrets {
		s := &c.CMP.Secrets[i]
		refs = append(refs, strRef(
			fmt.Sprintf("cmp.secrets[%d].secret_file", i),
			fmt.Sprintf("cmp.secrets[%d].secret", i),
			s.SecretFile, &s.Secret))
	}
	return refs
}

// sortedUserNames returns the EST user names in a stable order.
func sortedUserNames(users map[string]ESTUserConfig) []string {
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resolveSecretFiles replaces every configured `*_file` path with the file's
// contents. It runs after applyEnvOverrides — an environment variable overrides
// a file source, as it overrides every other file setting — and before the
// required-field and semantic validation, so a credential delivered as a file
// satisfies those checks exactly as an inline one does.
func (c *Config) resolveSecretFiles() error {
	allowInsecure := c.Security.AllowInsecureSecretFilePerms
	// The shorthands run first: each replaces a whole pin_source block, so
	// resolving credentials *inside* those blocks beforehand would either be
	// discarded or read as a conflict with the block the shorthand replaces.
	if err := c.resolvePinFiles(); err != nil {
		return err
	}
	for _, r := range c.secretFileRefs() {
		if r.path == "" {
			continue
		}
		if r.inline != "" {
			return fmt.Errorf("%s and %s are mutually exclusive: set exactly one", r.inlineKey, r.fileKey)
		}
		v, err := readSecretFile(r.fileKey, r.path, allowInsecure)
		if err != nil {
			return err
		}
		r.install(v)
	}
	return c.resolveEABHMACKeysFile()
}

// resolvePinFiles expands the two `*_file` shorthands that denote a credential
// source rather than a value: pkcs11.pin_file (per set and per token) and
// auth.ldap.bind_password_file. Each becomes the `file` pin_source it is
// shorthand for, so the credential is read at login time by the Task 111
// machinery and never enters the Config struct.
func (c *Config) resolvePinFiles() error {
	allowInsecure := c.Security.AllowInsecureSecretFilePerms
	if f := c.PKCS11.PinFile; f != "" {
		src, err := fileCredentialSource("pkcs11.pin_file", f, "pkcs11.pin", c.PKCS11.Pin, "pkcs11.pin_source", c.PKCS11.PinSource, allowInsecure)
		if err != nil {
			return err
		}
		c.PKCS11.PinSource = src
	}
	for i := range c.PKCS11.Tokens {
		t := &c.PKCS11.Tokens[i]
		if t.PinFile == "" {
			continue
		}
		key := fmt.Sprintf("pkcs11.tokens[%d]", i)
		src, err := fileCredentialSource(key+".pin_file", t.PinFile, key+".pin", t.Pin, key+".pin_source", t.PinSource, allowInsecure)
		if err != nil {
			return err
		}
		t.PinSource = src
	}
	if f := c.Auth.LDAP.BindPasswordFile; f != "" {
		src, err := fileCredentialSource("auth.ldap.bind_password_file", f,
			"auth.ldap.bind_password", c.Auth.LDAP.BindPassword,
			"auth.ldap.bind_password_source", c.Auth.LDAP.BindPasswordSource, allowInsecure)
		if err != nil {
			return err
		}
		c.Auth.LDAP.BindPasswordSource = src
	}
	return nil
}

// fileCredentialSource validates one `*_file` shorthand against the inline value
// and explicit source block it replaces, preflights the path, and returns the
// equivalent `file` pin_source.
func fileCredentialSource(fileKey, path, inlineKey, inline, sourceKey string, source PinSourceConfig, allowInsecure bool) (PinSourceConfig, error) {
	if inline != "" {
		return PinSourceConfig{}, fmt.Errorf("%s and %s are mutually exclusive: set exactly one", inlineKey, fileKey)
	}
	// Any content in the block the shorthand expands to is a conflict, not just a
	// type: a configured-looking `pin_source` that pin_file would silently
	// replace is exactly the kind of disagreement an operator needs told about.
	if source != (PinSourceConfig{}) {
		return PinSourceConfig{}, fmt.Errorf("%s and %s are mutually exclusive: %s is the shorthand for %s.type: file",
			sourceKey, fileKey, fileKey, sourceKey)
	}
	// Preflight now so a path that cannot work is a startup error, not a runtime
	// one. The source re-checks and reads it at login time.
	if err := statSecretFile(fileKey, path, allowInsecure); err != nil {
		return PinSourceConfig{}, err
	}
	return PinSourceConfig{
		Type: "file",
		File: FilePinSourceConfig{Path: path, AllowInsecurePerms: allowInsecure},
	}, nil
}

// resolveEABHMACKeysFile loads acme.eab_hmac_keys_file, the one credential
// setting that is a mapping rather than a string: it holds one shared HMAC
// secret per ACME account key (kid -> base64url key), which belongs in a mounted
// secret because the set grows with every onboarded client.
func (c *Config) resolveEABHMACKeysFile() error {
	path := c.ACME.EABHMACKeysFile
	if path == "" {
		return nil
	}
	if len(c.ACME.EABHMACKeys) > 0 {
		return fmt.Errorf("acme.eab_hmac_keys and acme.eab_hmac_keys_file are mutually exclusive: set exactly one")
	}
	data, err := readSecretFileBytes("acme.eab_hmac_keys_file", path, c.Security.AllowInsecureSecretFilePerms)
	if err != nil {
		return err
	}
	keys := map[string]string{}
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("acme.eab_hmac_keys_file %s: expected a YAML/JSON mapping of kid -> key: %w", path, err)
	}
	for kid, key := range keys {
		if strings.TrimSpace(kid) == "" || strings.TrimSpace(key) == "" {
			return fmt.Errorf("acme.eab_hmac_keys_file %s: entry %q has an empty kid or key", path, kid)
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("acme.eab_hmac_keys_file %s contains no keys", path)
	}
	c.ACME.EABHMACKeys = keys
	return nil
}

// statSecretFile applies everything that can be decided about a credential file
// without reading it: that it exists, that it is a regular file, and that it is
// not readable by group or other. It mirrors the pin_source file check so both
// paths report the same invariant the same way.
func statSecretFile(key, path string, allowInsecurePerms bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", key, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %s: is a directory, not a file", key, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s: not a regular file", key, path)
	}
	if !allowInsecurePerms {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("%s %s has insecure permissions %#o: a credential file must not be readable by group or other "+
				"(chmod 600 %s), or set security.allow_insecure_secret_file_perms to override",
				key, path, perm, path)
		}
	}
	return nil
}

// readSecretFileBytes stats and reads a credential file without interpreting its
// contents, for the one setting whose file is a mapping.
func readSecretFileBytes(key, path string, allowInsecurePerms bool) ([]byte, error) {
	if err := statSecretFile(key, path, allowInsecurePerms); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", key, path, err)
	}
	return data, nil
}

// readSecretFile returns the credential held in path: the file's contents minus
// one trailing line terminator. Anything else is preserved — see the trimming
// rationale at the top of this file.
func readSecretFile(key, path string, allowInsecurePerms bool) (string, error) {
	data, err := readSecretFileBytes(key, path, allowInsecurePerms)
	if err != nil {
		return "", err
	}
	v := trimOneLineTerminator(string(data))
	if v == "" {
		return "", fmt.Errorf("%s %s is empty", key, path)
	}
	return v, nil
}

// trimOneLineTerminator removes a single trailing "\r\n", "\n", or "\r".
func trimOneLineTerminator(s string) string {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "\n"), strings.HasSuffix(s, "\r"):
		return s[:len(s)-1]
	}
	return s
}

// redactDSN masks the password embedded in a database DSN while preserving
// everything an operator reads a dumped DSN for — driver, host, database, and
// options. Both spellings PostgreSQL accepts are handled: the URL form
// (postgres://user:pw@host/db) and the keyword form (password=pw). A DSN that
// carries no password is returned unchanged, which is the SQLite case.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.User != nil {
		if _, ok := u.User.Password(); ok {
			masked := maskURLPassword(dsn)
			if masked == "" {
				// The DSN carries a password that the textual pass could not
				// locate. Mask the whole thing: a redaction that cannot find the
				// secret must not return the secret.
				return redactedSecret
			}
			return masked
		}
	}
	if !strings.Contains(strings.ToLower(dsn), "password=") {
		return dsn
	}
	// Keyword/value form: mask each password= value, leaving the rest readable.
	// A quoted value may contain spaces, so honour the quoting libpq defines.
	var out strings.Builder
	for i := 0; i < len(dsn); {
		if hasFoldedPrefix(dsn[i:], "password=") && (i == 0 || dsn[i-1] == ' ' || dsn[i-1] == '\t') {
			out.WriteString(dsn[i : i+len("password=")])
			out.WriteString(redactedSecret)
			i += len("password=")
			if i < len(dsn) && dsn[i] == '\'' {
				i++
				for i < len(dsn) && dsn[i] != '\'' {
					if dsn[i] == '\\' && i+1 < len(dsn) {
						i++
					}
					i++
				}
				if i < len(dsn) {
					i++
				}
				continue
			}
			for i < len(dsn) && dsn[i] != ' ' && dsn[i] != '\t' {
				i++
			}
			continue
		}
		out.WriteByte(dsn[i])
		i++
	}
	return out.String()
}

// maskURLPassword replaces the password inside a URL DSN's userinfo by textual
// surgery rather than re-serializing the parsed URL, which would percent-encode
// the redaction marker and normalize parts of the DSN an operator reads a dump
// to compare verbatim. It returns "" when the DSN has no userinfo password.
func maskURLPassword(dsn string) string {
	i := strings.Index(dsn, "://")
	if i < 0 {
		return ""
	}
	rest := dsn[i+3:]
	authority := rest
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		authority = rest[:j]
	}
	// url.Parse treats the last "@" in the authority as the userinfo delimiter.
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return ""
	}
	userinfo := authority[:at]
	colon := strings.Index(userinfo, ":")
	if colon < 0 {
		return ""
	}
	return dsn[:i+3] + userinfo[:colon+1] + redactedSecret + rest[at:]
}

func hasFoldedPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
