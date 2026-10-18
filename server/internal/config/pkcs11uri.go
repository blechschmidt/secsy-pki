package config

// RFC 7512 PKCS#11 URIs in the configuration.
//
// Two different things in this file are addressed by a URI, and they are not
// interchangeable:
//
//   - the *token* (and the module and PIN that reach it) — pkcs11.uri and
//     pkcs11.tokens[].uri. These may not name an object: the token block says
//     which device to talk to, not which key to use.
//   - a *key* — tsa.key_label, secret.kek_label, signing.signers[].key_label,
//     brski.registrar_key_label, brski.masa.key_label, the escrow agents, and
//     the serving-TLS key. These must name an object (object= and/or id=) and
//     may additionally pin the token the key lives on, but they may not carry
//     the module or the PIN, which are deployment-wide rather than per-key.
//
// Every one of these is checked when the config is loaded. A URI that cannot be
// honoured in full is rejected there, with the YAML path in the message, rather
// than being half-applied at first signature — "the config says serial 0001234
// and the signature came off a different device" is not a failure anyone wants
// to debug from an audit log.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// EffectiveModulePath returns the PKCS#11 module library this config loads:
// module_path when set, otherwise the module-path (or p11-kit module-name)
// carried by pkcs11.uri, otherwise the one carried by a per-token uri.
//
// The last case exists because a URI pasted out of `p11tool --list-tokens`
// names the module it came from, and refusing it there would be pedantry — an
// HA set drives all its tokens through one module, so any member naming it
// names it for the set. validateModuleAgreement rejects a set whose members
// disagree, which is the only way this could be ambiguous.
//
// It returns "" when nothing names a module.
func (p PKCS11Config) EffectiveModulePath() (string, error) {
	if p.ModulePath != "" {
		return p.ModulePath, nil
	}
	refs := []struct{ field, uri string }{{"pkcs11.uri", p.URI}}
	for i, t := range p.Tokens {
		refs = append(refs, struct{ field, uri string }{fmt.Sprintf("pkcs11.tokens[%d].uri", i), t.URI})
	}
	for _, ref := range refs {
		if ref.uri == "" {
			continue
		}
		u, err := pki.ParsePKCS11URI(ref.uri)
		if err != nil {
			return "", fmt.Errorf("%s: %w", ref.field, err)
		}
		path, err := u.ResolveModulePath()
		if err != nil {
			return "", fmt.Errorf("%s: %w", ref.field, err)
		}
		if path != "" {
			return path, nil
		}
	}
	return "", nil
}

// validateModuleAgreement rejects a set whose URIs name more than one module.
// One PKCS#11 library drives every token in a high-availability set; a config
// naming two is expressing something the backend cannot do, and picking one
// silently would route half the operations to a device the operator did not
// mean.
func (p PKCS11Config) validateModuleAgreement() error {
	seen := map[string]string{} // resolved path -> the field that named it
	note := func(field, uri string) error {
		if uri == "" {
			return nil
		}
		u, err := pki.ParsePKCS11URI(uri)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		path, err := u.ResolveModulePath()
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		if path == "" {
			return nil
		}
		if _, ok := seen[path]; !ok {
			// Keep the first field that named this module; the error below
			// reports one field per distinct module, which is enough to see
			// where the disagreement came from.
			seen[path] = field
		}
		return nil
	}
	if p.ModulePath != "" {
		seen[p.ModulePath] = "pkcs11.module_path"
	}
	if err := note("pkcs11.uri", p.URI); err != nil {
		return err
	}
	for i, t := range p.Tokens {
		if err := note(fmt.Sprintf("pkcs11.tokens[%d].uri", i), t.URI); err != nil {
			return err
		}
	}
	if len(seen) > 1 {
		var parts []string
		for path, field := range seen {
			parts = append(parts, fmt.Sprintf("%s=%s", field, path))
		}
		sortStrings(parts)
		return fmt.Errorf("pkcs11: the configuration names %d different PKCS#11 modules (%s) — "+
			"one module drives every token in a set", len(seen), strings.Join(parts, ", "))
	}
	return nil
}

// sortStrings orders a tiny slice so an error message is deterministic.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// validateTokenURI checks a URI that addresses a token rather than a key.
func validateTokenURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	if !keyprovider.IsPKCS11URI(raw) {
		return fmt.Errorf("%s: %q is not a pkcs11: URI", field, raw)
	}
	u, err := pki.ParsePKCS11URI(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if u.HasObjectSelector() {
		return fmt.Errorf("%s: pkcs11 uri names an object (object=/id=) but this setting addresses the token — "+
			"put the key reference in the field that names the key (for example tsa.key_label)", field)
	}
	if len(u.Unknown) > 0 {
		names := make([]string, 0, len(u.Unknown))
		for k := range u.Unknown {
			names = append(names, k)
		}
		return fmt.Errorf("%s: pkcs11 uri has unrecognized attribute(s) %v", field, names)
	}
	return nil
}

// validatePKCS11URIs checks the token-addressing URIs and the module they name.
func (c *Config) validatePKCS11URIs() error {
	if err := validateTokenURI("pkcs11.uri", c.PKCS11.URI); err != nil {
		return err
	}
	for i, t := range c.PKCS11.Tokens {
		if err := validateTokenURI(fmt.Sprintf("pkcs11.tokens[%d].uri", i), t.URI); err != nil {
			return err
		}
	}
	return c.PKCS11.validateModuleAgreement()
}

// keyRefField is one configured key reference to validate: its YAML path, its
// value, and whether the label also names a rotation family.
type keyRefField struct {
	field string
	value string
	kind  keyprovider.KeyRefKind
}

// keyReferenceFields enumerates every configured reference to a provider key.
// Adding a key-naming setting without adding it here means that setting
// silently stops accepting a URI, so it is deliberately exhaustive rather than
// reflective.
func (c *Config) keyReferenceFields() []keyRefField {
	fields := []keyRefField{
		{"tsa.key_label", c.TSA.KeyLabel, keyprovider.KeyRefKeyField},
		{"brski.registrar_key_label", c.BRSKI.RegistrarKeyLabel, keyprovider.KeyRefKeyField},
		{"brski.masa.key_label", c.BRSKI.MASA.KeyLabel, keyprovider.KeyRefKeyField},
		{"server.tls.self_issue.key_label", c.Server.TLS.SelfIssue.KeyLabel, keyprovider.KeyRefKeyField},
		{"secret.kek_label", c.Secret.KEKLabel, keyprovider.KeyRefFamilyField},
		{"backup.kek_label", c.Backup.KEKLabel, keyprovider.KeyRefFamilyField},
	}
	for i, s := range c.Signing.Signers {
		fields = append(fields, keyRefField{
			fmt.Sprintf("signing.signers[%d].key_label", i), s.KeyLabel, keyprovider.KeyRefKeyField,
		})
	}
	for i, a := range c.Secret.Escrow.Agents {
		fields = append(fields, keyRefField{
			fmt.Sprintf("secret.escrow.agents[%d].key_label", i), a.KeyLabel, keyprovider.KeyRefKeyField,
		})
	}
	for i, t := range c.Tenants {
		fields = append(fields, keyRefField{
			fmt.Sprintf("tenants[%d].kek_label", i), t.KEKLabel, keyprovider.KeyRefFamilyField,
		})
	}
	return fields
}

// validateKeyReferences checks every configured key reference at load time.
func (c *Config) validateKeyReferences() error {
	for _, f := range c.keyReferenceFields() {
		if err := keyprovider.ValidateKeyReference(f.field, f.value, f.kind); err != nil {
			return err
		}
	}
	return nil
}

// ResolvedKEKLabel returns the object label of the configured secret KEK. The
// label doubles as the KEK *family* name that rotation derives "<label>-v2"
// from, so a URI contributes only its object= here; its token pin still applies
// wherever the key itself is opened.
func (c SecretConfig) ResolvedKEKLabel() string {
	return keyprovider.KeyLabelFor(c.KEKLabel)
}

// ResolvedKEKLabel returns the object label of this tenant's KEK override.
func (t TenantConfig) ResolvedKEKLabel() string {
	return keyprovider.KeyLabelFor(t.KEKLabel)
}

// ResolvedKEKLabel returns the object label of the backup KEK, falling back to
// the deployment-wide secret KEK exactly as EffectiveKEKLabel does.
func (c BackupConfig) ResolvedKEKLabel(secretKEKLabel string) string {
	return keyprovider.KeyLabelFor(c.EffectiveKEKLabel(secretKEKLabel))
}

// addressesAToken reports whether this HA member names a token at all, through
// its fields or through its own URI. A member that addresses nothing would
// match every token in the set, which is never what an operator listing two
// replicas meant.
func (t PKCS11TokenConfig) addressesAToken() bool {
	if t.TokenLabel != "" || t.TokenSerial != "" || t.TokenManufacturer != "" ||
		t.TokenModel != "" || t.SlotID != nil || t.SlotDescription != "" || t.SlotManufacturer != "" {
		return true
	}
	if t.URI == "" {
		return false
	}
	u, err := pki.ParsePKCS11URI(t.URI)
	return err == nil && u.HasTokenSelector()
}
