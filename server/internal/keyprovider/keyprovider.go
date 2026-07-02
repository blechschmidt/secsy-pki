// Package keyprovider defines a backend-agnostic abstraction over the storage,
// generation, and use of asymmetric signing keys.
//
// Two implementations are provided:
//
//   - SoftwareProvider keeps private keys in an on-disk keystore. It is the
//     zero-dependency default, useful for development and for deployments that
//     do not have a hardware security module.
//   - PKCS11Provider talks to a PKCS#11 token (an HSM such as YubiHSM, or
//     SoftHSM for testing) via a module path, token label, and user PIN. The
//     private key never leaves the token; all signing happens on the device.
//
// The abstraction lets the rest of the application (CA creation, certificate
// signing, public-key export) treat both backends uniformly. Which backend is
// used is chosen by configuration; see Config and New.
package keyprovider

import (
	"context"
	"crypto"
	"fmt"
	"strings"
)

// Canonical key-type identifiers accepted by GenerateKey. These match the
// strings already used elsewhere in the codebase (SSH key-type names for EC /
// Ed25519, and rsa-<bits> for RSA) so a KeyInfo.KeyType round-trips cleanly.
const (
	KeyTypeEd25519   = "ed25519"
	KeyTypeECDSAP256 = "ecdsa-sha2-nistp256"
	KeyTypeECDSAP384 = "ecdsa-sha2-nistp384"
	KeyTypeECDSAP521 = "ecdsa-sha2-nistp521"
	KeyTypeRSA2048   = "rsa-2048"
	KeyTypeRSA4096   = "rsa-4096"
)

// ProviderType selects which backend New constructs.
type ProviderType string

const (
	// ProviderSoftware stores keys in an on-disk keystore.
	ProviderSoftware ProviderType = "software"
	// ProviderPKCS11 stores and uses keys on a PKCS#11 token / HSM.
	ProviderPKCS11 ProviderType = "pkcs11"
)

// KeyRef identifies an existing key within a provider. A key is addressed
// primarily by its Label; ID is an optional secondary identifier (a hex CKA_ID
// for PKCS#11, or an alternate keystore name for the software provider). At
// least one of Label or ID must be set.
type KeyRef struct {
	Label string
	ID    string
}

// resolve returns the primary identifier for the reference, preferring Label.
func (r KeyRef) resolve() (string, error) {
	if r.Label != "" {
		return r.Label, nil
	}
	if r.ID != "" {
		return r.ID, nil
	}
	return "", fmt.Errorf("keyprovider: key reference has neither label nor ID")
}

// Key usage identifiers. A key is generated either for signing (the default,
// covering CA and end-entity certificate keys) or for decryption / key
// wrapping (a KEK used by the envelope-encryption feature). Keeping these
// separate lets the PKCS#11 backend generate keys with least-privilege usage
// attributes on the token.
const (
	KeyUsageSign    = "sign"
	KeyUsageDecrypt = "decrypt"
)

// KeySpec describes a key pair to generate.
type KeySpec struct {
	// Label is the human-readable identifier the key is stored under. Required.
	Label string
	// ID is an optional secondary identifier (hex CKA_ID for PKCS#11).
	ID string
	// KeyType is one of the KeyType* constants (aliases such as "rsa",
	// "ecdsa", or "rsa-2048" are normalized by NormalizeKeyType).
	KeyType string
	// Usage is KeyUsageSign (default) or KeyUsageDecrypt. A decryption key is
	// generated as an RSA key-encryption key (KEK) for envelope encryption; it
	// must therefore be an RSA key type.
	Usage string
}

// KeyInfo describes a key that exists within a provider.
type KeyInfo struct {
	// Label is the identifier the key is stored under.
	Label string
	// ID is the secondary identifier, if any.
	ID string
	// KeyType is one of the canonical KeyType* constants.
	KeyType string
	// PublicKey is the exported public key.
	PublicKey crypto.PublicKey
	// URI is a stable, provider-specific reference to the key. For PKCS#11 it
	// is an RFC 7512 pkcs11: URI; for the software provider it is a
	// software:<label> URI.
	URI string
	// SSHPublicKey is the OpenSSH authorized_keys representation of PublicKey.
	SSHPublicKey string
}

// Signer is a crypto.Signer bound to a specific provider key, plus a Close that
// releases any backend resources (PKCS#11 session, etc.).
type Signer interface {
	crypto.Signer
	// KeyType returns the canonical key-type identifier of the signing key.
	KeyType() string
	// Close releases resources held by the signer. It is safe to call more
	// than once.
	Close() error
}

// Provider is a backend for generating, locating, and using signing keys.
//
// Implementations must be safe for concurrent use by multiple goroutines:
// callers may request signers and generate keys concurrently.
type Provider interface {
	// Name returns the provider's ProviderType as a string.
	Name() string
	// GenerateKey creates a new key pair and returns its metadata. It fails if
	// a key with the same label already exists.
	GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error)
	// FindKey locates an existing key by reference. It returns an error that
	// unwraps to ErrKeyNotFound if no matching key exists.
	FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error)
	// Signer returns a crypto.Signer for the referenced key. The caller must
	// Close the returned Signer when done.
	Signer(ctx context.Context, ref KeyRef) (Signer, error)
	// PublicKey exports the public key of the referenced key.
	PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error)
	// Close releases any long-lived resources held by the provider.
	Close() error
}

// Prober is an optional capability implemented by providers that can perform a
// lightweight connectivity/health check without requiring a specific key to
// exist. Both the software and PKCS#11 backends implement it. The readiness
// endpoint type-asserts a Provider to this interface to probe the HSM.
type Prober interface {
	// Ping reports whether the backend is reachable and ready to service key
	// operations. It returns nil when healthy and a descriptive error otherwise.
	// Implementations must not create, mutate, or require any particular key.
	Ping(ctx context.Context) error
}

// Decrypter is a crypto.Decrypter bound to a specific provider key, plus a
// Close that releases backend resources (a PKCS#11 session, etc.). It is used
// to unwrap data-encryption keys during envelope decryption.
type Decrypter interface {
	crypto.Decrypter
	// Close releases resources held by the decrypter. It is safe to call more
	// than once.
	Close() error
}

// DecrypterProvider is an optional capability implemented by providers that can
// unwrap data-encryption keys with a KEK. Both the software and PKCS#11
// backends implement it. Callers type-assert a Provider to this interface.
type DecrypterProvider interface {
	// Decrypter returns a Decrypter for the referenced key. The caller must
	// Close the returned Decrypter when done. The referenced key must support
	// decryption (an RSA KEK generated with KeyUsageDecrypt).
	Decrypter(ctx context.Context, ref KeyRef) (Decrypter, error)
}

// ErrKeyNotFound is returned (wrapped) by FindKey / Signer / PublicKey when no
// key matches the supplied reference.
var ErrKeyNotFound = fmt.Errorf("keyprovider: key not found")

// ErrProbeUnsupported is returned by a wrapper's Ping when the wrapped provider
// does not implement Prober. Readiness checks treat it as "cannot probe" rather
// than "unhealthy".
var ErrProbeUnsupported = fmt.Errorf("keyprovider: connectivity probe not supported by this provider")

// PKCS11Settings configures the PKCS#11 backend. It mirrors the fields of
// pki.PKCS11Config; New maps it across so callers of this package need not
// import the pki package directly.
type PKCS11Settings struct {
	ModulePath        string
	Pin               string
	TokenLabel        string
	TokenSerial       string
	TokenManufacturer string
}

// SoftwareSettings configures the software backend.
type SoftwareSettings struct {
	// KeystoreDir is the directory in which private keys are stored. It is
	// created (0700) on first use if it does not exist.
	KeystoreDir string
}

// Config selects and configures a provider.
type Config struct {
	Type     ProviderType
	PKCS11   PKCS11Settings
	Software SoftwareSettings
}

// New constructs the provider selected by cfg.Type.
func New(cfg Config) (Provider, error) {
	switch cfg.Type {
	case ProviderSoftware:
		return NewSoftwareProvider(cfg.Software)
	case ProviderPKCS11:
		return NewPKCS11Provider(cfg.PKCS11)
	case "":
		return nil, fmt.Errorf("keyprovider: no provider type configured")
	default:
		return nil, fmt.Errorf("keyprovider: unknown provider type %q (supported: %s, %s)",
			cfg.Type, ProviderSoftware, ProviderPKCS11)
	}
}

// NormalizeKeyType maps user-supplied key-type strings (including common
// aliases) to one of the canonical KeyType* constants. It is used by both
// providers so they accept the same vocabulary.
func NormalizeKeyType(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ed25519", "ssh-ed25519":
		return KeyTypeEd25519, nil
	case "ecdsa", "ecdsa-p256", "p256", "ecdsa-sha2-nistp256", "nistp256":
		return KeyTypeECDSAP256, nil
	case "ecdsa-p384", "p384", "ecdsa-sha2-nistp384", "nistp384":
		return KeyTypeECDSAP384, nil
	case "ecdsa-p521", "p521", "ecdsa-sha2-nistp521", "nistp521":
		return KeyTypeECDSAP521, nil
	case "rsa", "rsa-2048", "rsa2048":
		return KeyTypeRSA2048, nil
	case "rsa-4096", "rsa4096":
		return KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("keyprovider: unsupported key type %q", s)
	}
}
