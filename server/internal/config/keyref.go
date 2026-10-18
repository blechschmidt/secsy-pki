package config

// Normalization of the KEK references after validation.
//
// A KEK label is not only an address: it is persisted into every envelope's
// wrap header, it is the key the rotation lineage is stored under in the
// database, and it is what "<label>-v2" is derived from when the key rotates.
// Roughly twenty call sites look a KEK family up in the database by that
// string.
//
// So a pkcs11: URI is accepted in these fields — an operator should not have to
// remember which fields take a URI and which do not — but it is reduced to its
// object label here, once, immediately after validation has confirmed that the
// label is all it carries. Nothing downstream ever sees a URI in a KEK field,
// and no database lookup can be handed one by accident.

import "github.com/blechschmidt/secsy-pki/server/internal/keyprovider"

// normalizeKeyReferences reduces every KEK reference to its object label.
// Ordinary key references (tsa.key_label and friends) are deliberately left
// alone: they are addresses, resolved through keyprovider.KeyRefFor at use, and
// keep the full RFC 7512 addressing the operator wrote.
func (c *Config) normalizeKeyReferences() {
	normalize := func(p *string) {
		if l := keyprovider.KeyLabelFor(*p); l != "" {
			*p = l
		}
	}
	normalize(&c.Secret.KEKLabel)
	normalize(&c.Backup.KEKLabel)
	for i := range c.Tenants {
		normalize(&c.Tenants[i].KEKLabel)
	}
}
