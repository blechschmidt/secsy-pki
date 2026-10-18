package keyprovider

// Configured key references.
//
// Every place the configuration names a key — tsa.key_label, secret.kek_label,
// signing.signers[].key_label, brski.registrar_key_label, the escrow agents,
// the serving-TLS key — accepts the same three forms:
//
//	my-ca-key                                 a bare label (the historical form)
//	software:my-ca-key                        the software provider's URI
//	pkcs11:object=my-ca-key;type=private      a full RFC 7512 URI
//
// The URI form is what makes the configuration unambiguous on real hardware. A
// CKA_LABEL is not a key identity: HA replicas deliberately share one, a token
// can hold two objects with the same label, and a migrated key may have a label
// nobody chose. "pkcs11:id=%01%02;serial=0001234" names exactly one key on
// exactly one device, and that is the string an operator can copy out of
// `p11tool --list-all` or `pkcs11-tool -O` and paste into the config.
//
// This file is the single place that interpretation lives, so a URI means the
// same thing in every field rather than working in whichever ones happened to
// be converted.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// IsPKCS11URI reports whether ref is written as an RFC 7512 "pkcs11:" URI
// (scheme matched case-insensitively per RFC 3986). It does not validate the
// rest of the URI.
func IsPKCS11URI(ref string) bool {
	t := strings.TrimSpace(ref)
	return len(t) >= len("pkcs11:") && strings.EqualFold(t[:len("pkcs11:")], "pkcs11:")
}

// KeyLabelFor returns the object label a configured key reference names: the
// object= attribute of a pkcs11: URI, the label of a software: URI, or the
// reference itself when it is a bare label.
//
// Use it where the label is needed as a *name* rather than as an address — the
// KEK family name that version labels are derived from, a metrics dimension, a
// log line. Use KeyRefFor wherever the key is actually being located.
// A URI that names no object (or does not parse) yields "".
func KeyLabelFor(ref string) string {
	t := strings.TrimSpace(ref)
	if t == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(t, "software:"); ok {
		return rest
	}
	if !IsPKCS11URI(t) {
		return t
	}
	u, err := pki.ParsePKCS11URI(t)
	if err != nil {
		return ""
	}
	return u.Object
}

// KeySpecFor builds a KeySpec for generating a key under a configured
// reference. A bare label behaves exactly as before; a pkcs11: URI additionally
// carries its CKA_ID and its token pin into the spec, so the key is created
// with the identity the configuration asked for rather than with a label that
// merely happens to contain a URI.
func KeySpecFor(ref, keyType, usage string) KeySpec {
	r := KeyRefFor(ref)
	return KeySpec{Label: r.Label, ID: r.ID, KeyType: keyType, Usage: usage, Token: r.Token}
}

// KeyRefKind tells ValidateKeyReference what the field is for, because the two
// kinds tolerate different URIs.
type KeyRefKind int

const (
	// KeyRefKeyField is an ordinary reference to one key.
	KeyRefKeyField KeyRefKind = iota
	// KeyRefFamilyField is a reference whose label also names a *family* of
	// keys that later versions are derived from — the secret-layer KEK, whose
	// rotation creates "<label>-v2", "<label>-v3" and so on. A CKA_ID cannot be
	// carried across a derived label, so one may not be pinned here.
	KeyRefFamilyField
)

// ValidateKeyReference checks a configured key reference at load time rather
// than at first use. field is the YAML path, used verbatim in the error.
//
// It fails closed on anything it cannot honor. The alternative — accepting a
// URI and quietly ignoring the half of it that does not fit — is how a
// deployment ends up signing with the wrong key on the wrong token while its
// configuration says otherwise.
func ValidateKeyReference(field, ref string, kind KeyRefKind) error {
	t := strings.TrimSpace(ref)
	if t == "" {
		return nil // emptiness is the caller's own requiredness rule
	}
	if !IsPKCS11URI(t) {
		return nil // bare label or software: URI — nothing to check
	}
	u, err := pki.ParsePKCS11URI(t)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if !u.HasObjectSelector() {
		return fmt.Errorf("%s: pkcs11 uri %q names a token but no key (add object=<label> or id=<hex>)",
			field, u.RedactedString())
	}
	switch u.Type {
	case "", pki.PKCS11TypePrivate, pki.PKCS11TypePublic, pki.PKCS11TypeSecretKey:
		// A key object.
	default:
		return fmt.Errorf("%s: pkcs11 uri type=%s addresses a %s object, not a key (use type=private or omit it)",
			field, u.Type, u.Type)
	}
	if u.HasModuleSelector() {
		return fmt.Errorf("%s: pkcs11 uri must not carry module-path/module-name — the module is deployment-wide; "+
			"configure it under pkcs11.module_path or pkcs11.uri", field)
	}
	if u.HasPIN() {
		return fmt.Errorf("%s: pkcs11 uri must not carry pin-value/pin-source — the PIN is per-token, not per-key; "+
			"configure it under pkcs11.pin_source or pkcs11.uri", field)
	}
	if len(u.Unknown) > 0 {
		return fmt.Errorf("%s: pkcs11 uri has unrecognized attribute(s) %s", field, strings.Join(sortedAttrNames(u.Unknown), ", "))
	}
	if kind == KeyRefFamilyField {
		// A KEK label is not only an address. It is written into every envelope's
		// wrap header, it keys the rotation lineage in the database, and it is
		// what "<label>-v2" is derived from — so only the part of the URI that
		// survives into a derived label can be honoured, and the rest is
		// rejected rather than silently dropped.
		if u.Object == "" {
			return fmt.Errorf("%s: pkcs11 uri must set object=<label> — this setting names a KEK family, "+
				"which is identified by its label", field)
		}
		if len(u.ID) > 0 {
			return fmt.Errorf("%s: pkcs11 uri must not pin id=%s — this label also names the KEK family that "+
				"rotation derives \"<label>-v2\" from, and a derived key has its own CKA_ID; address it by object= instead",
				field, u.IDHex())
		}
		if u.HasTokenSelector() {
			return fmt.Errorf("%s: pkcs11 uri must not pin a token (%s) — a KEK family's versions are created "+
				"wherever its base key lives, and the family name is persisted in every envelope; "+
				"select the token under pkcs11.uri / pkcs11.token_* instead", field, u.String())
		}
	}
	return nil
}

// sortedAttrNames returns the keys of an attribute map in a stable order for
// error messages.
func sortedAttrNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// DescribeKeyReference renders a configured key reference for a log line or an
// error, with any embedded PIN redacted. A bare label is returned unchanged.
func DescribeKeyReference(ref string) string {
	t := strings.TrimSpace(ref)
	if !IsPKCS11URI(t) {
		return t
	}
	u, err := pki.ParsePKCS11URI(t)
	if err != nil {
		return t
	}
	return u.RedactedString()
}
