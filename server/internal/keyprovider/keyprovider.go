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
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
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
	KeyTypeRSA3072   = "rsa-3072"
	KeyTypeRSA4096   = "rsa-4096"

	// Post-quantum ML-DSA (FIPS 204) key types. These are only supported by the
	// software provider; see the pqc package and docs/pqc.md.
	KeyTypeMLDSA44 = pqc.KeyTypeMLDSA44
	KeyTypeMLDSA65 = pqc.KeyTypeMLDSA65
	KeyTypeMLDSA87 = pqc.KeyTypeMLDSA87
)

// ProviderType selects which backend New constructs.
type ProviderType string

const (
	// ProviderSoftware stores keys in an on-disk keystore.
	ProviderSoftware ProviderType = "software"
	// ProviderPKCS11 stores and uses keys on a PKCS#11 token / HSM.
	ProviderPKCS11 ProviderType = "pkcs11"
	// ProviderKMS stores and uses keys in a cloud KMS (AWS KMS / Azure Key
	// Vault). Defined in kms.go.
)

// KeyRef identifies an existing key within a provider. A key is addressed
// primarily by its Label; ID is an optional secondary identifier (a hex-encoded
// CKA_ID for PKCS#11, or an alternate keystore name for the software / KMS
// providers). At least one of Label or ID must be set.
//
// Token optionally pins a PKCS#11 operation to a specific token within a
// high-availability set, using RFC 7512 token/slot addressing (serial, slot-id,
// model, ...). It is populated by KeyRefFromURI from a pkcs11: URI's token path
// attributes and is ignored by the software and KMS backends.
type KeyRef struct {
	Label string
	ID    string
	Token TokenSelector
}

// TokenSelector pins a PKCS#11 key operation to a specific token within a
// high-availability set, using RFC 7512 token/slot path attributes. Every field
// is optional; each set field must match the token for it to be selected. It is
// advisory for the single-token backend (which has exactly one token) and
// authoritative for the HA backend, which routes only to member tokens matching
// every set field — the unambiguous way to address a specific replica when
// replicas deliberately share a CKA_LABEL.
type TokenSelector struct {
	Label        string // token= (CK_TOKEN_INFO.label)
	Serial       string // serial= (CK_TOKEN_INFO.serialNumber)
	Model        string // model= (CK_TOKEN_INFO.model)
	Manufacturer string // manufacturer= (CK_TOKEN_INFO.manufacturerID)
	SlotID       *uint  // slot-id= (CK_SLOT_ID)
}

// IsZero reports whether the selector pins nothing (matches any token).
func (s TokenSelector) IsZero() bool {
	return s.Label == "" && s.Serial == "" && s.Model == "" && s.Manufacturer == "" && s.SlotID == nil
}

// Describe renders the selector for error messages.
func (s TokenSelector) Describe() string {
	var parts []string
	if s.Label != "" {
		parts = append(parts, fmt.Sprintf("token=%q", s.Label))
	}
	if s.Serial != "" {
		parts = append(parts, fmt.Sprintf("serial=%q", s.Serial))
	}
	if s.Model != "" {
		parts = append(parts, fmt.Sprintf("model=%q", s.Model))
	}
	if s.Manufacturer != "" {
		parts = append(parts, fmt.Sprintf("manufacturer=%q", s.Manufacturer))
	}
	if s.SlotID != nil {
		parts = append(parts, fmt.Sprintf("slot-id=%d", *s.SlotID))
	}
	if len(parts) == 0 {
		return "(any token)"
	}
	return strings.Join(parts, " ")
}

// resolve returns the primary identifier for the reference, preferring Label. It
// is used by the software and KMS backends, whose ID is an alternate name rather
// than a binary CKA_ID. The PKCS#11 backend does not use it — it addresses keys
// by a pki.KeyLocator (label and/or CKA_ID) instead; see locatorFor.
func (r KeyRef) resolve() (string, error) {
	if r.Label != "" {
		return r.Label, nil
	}
	if r.ID != "" {
		return r.ID, nil
	}
	return "", fmt.Errorf("keyprovider: key reference has neither label nor ID")
}

// KeyRefFromURI builds a KeyRef from a stored key-reference string, accepting the
// three forms the codebase uses so callers no longer have to pull out only the
// CKA_LABEL:
//
//   - "pkcs11:…"          a full RFC 7512 URI. The object= / id= object selectors
//     become Label / ID (hex CKA_ID); the token / serial / model / manufacturer /
//     slot-id path attributes become the Token selector so the operation can be
//     pinned to a specific token in a high-availability set.
//   - "software:<label>"  the software provider's URI shorthand → Label.
//   - "<label>"           a bare label (historical shorthand) → Label.
//
// It returns an error only for a malformed pkcs11: URI. An empty string is
// rejected; a well-formed URI that names no object (neither object= nor id=)
// yields a KeyRef with an empty Label/ID that the caller may fall back from
// (e.g. to the CA label).
func KeyRefFromURI(ref string) (KeyRef, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return KeyRef{}, fmt.Errorf("keyprovider: empty key reference")
	}
	if rest, ok := strings.CutPrefix(trimmed, "software:"); ok {
		return KeyRef{Label: rest}, nil
	}
	if len(trimmed) >= len("pkcs11:") && strings.EqualFold(trimmed[:len("pkcs11:")], "pkcs11:") {
		u, err := pki.ParsePKCS11URI(trimmed)
		if err != nil {
			return KeyRef{}, err
		}
		return keyRefFromParsedURI(u), nil
	}
	// Bare-label shorthand.
	return KeyRef{Label: trimmed}, nil
}

// KeyRefFor builds a KeyRef from a configured key reference that may be a bare
// label (the common case), a "software:<label>" URI, or a full RFC 7512 pkcs11:
// URI. A bare label — or any value that does not resolve to an object selector —
// yields KeyRef{Label: ref} unchanged, so existing bare-label configuration keeps
// working; a pkcs11: URI additionally enables addressing the key by CKA_ID or by
// token serial/slot-id (e.g. pinning a TSA signing key to a specific replica in
// an HA set). It never errors: an unparseable value falls back to a bare label,
// matching how the CA path resolves its stored URI.
func KeyRefFor(ref string) KeyRef {
	r, err := KeyRefFromURI(ref)
	if err != nil || (r.Label == "" && r.ID == "") {
		return KeyRef{Label: ref}
	}
	return r
}

// keyRefFromParsedURI maps a parsed RFC 7512 URI onto a KeyRef.
func keyRefFromParsedURI(u *pki.PKCS11URI) KeyRef {
	ref := KeyRef{Label: u.Object, ID: u.IDHex()}
	ref.Token = TokenSelector{
		Label:        u.Token,
		Serial:       u.Serial,
		Model:        u.Model,
		Manufacturer: u.Manufacturer,
	}
	if u.SlotID != nil && *u.SlotID >= 0 {
		s := uint(*u.SlotID)
		ref.Token.SlotID = &s
	}
	return ref
}

// PinSourceFromURI maps the pin-value / pin-source query attributes of a parsed
// RFC 7512 pkcs11: URI onto the Task 111 external-PIN-sourcing settings, wiring a
// self-describing URI into the credential-store machinery. pin-value yields an
// inline PIN (a plaintext-at-rest credential); pin-source is treated as a file
// reference (p11-kit's convention — a bare path or a file: URI). It returns
// ok=false when the URI carries neither, so the caller keeps its existing PIN
// configuration.
func PinSourceFromURI(u *pki.PKCS11URI) (settings PinSourceSettings, inlinePIN string, ok bool, err error) {
	if u == nil {
		return PinSourceSettings{}, "", false, nil
	}
	if u.PinValue != "" {
		return PinSourceSettings{}, u.PinValue, true, nil
	}
	if u.PinSource == "" {
		return PinSourceSettings{}, "", false, nil
	}
	path, perr := pinSourceFilePath(u.PinSource)
	if perr != nil {
		return PinSourceSettings{}, "", false, perr
	}
	return PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: path}}, "", true, nil
}

// pinSourceFilePath extracts a filesystem path from an RFC 7512 pin-source value.
// It accepts a bare path and the "file:" / "file://" URI forms; anything else
// (e.g. an exec "|program" or an unsupported scheme) is rejected rather than
// silently mishandled.
func pinSourceFilePath(src string) (string, error) {
	s := strings.TrimSpace(src)
	switch {
	case strings.HasPrefix(s, "file://"):
		return strings.TrimPrefix(s, "file://"), nil
	case strings.HasPrefix(s, "file:"):
		return strings.TrimPrefix(s, "file:"), nil
	case strings.Contains(s, "://"):
		return "", fmt.Errorf("keyprovider: unsupported pin-source scheme in %q (only file: is supported)", src)
	case strings.HasPrefix(s, "|"):
		return "", fmt.Errorf("keyprovider: exec pin-source %q is not supported", src)
	default:
		return s, nil
	}
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

// KeyDescriptor is the non-sensitive inventory record for one key held by a
// provider. It deliberately carries no private key material — only the
// identifiers, type, and (for hardware tokens) the extractability/sensitivity
// policy flags that let an operator audit the key non-extractability invariant.
type KeyDescriptor struct {
	// Label is the identifier the key is stored under.
	Label string `json:"label"`
	// ID is the secondary identifier (hex CKA_ID for PKCS#11), if any.
	ID string `json:"id,omitempty"`
	// KeyType is a canonical key-type string where derivable.
	KeyType string `json:"key_type"`
	// URI is the provider-specific reference (pkcs11: or software: URI).
	URI string `json:"uri"`
	// Extractable reports whether the private key may be read off the backend.
	// For an HSM-backed CA/KEK key this must be false. The software backend
	// always reports true, since keys live as on-disk files.
	Extractable bool `json:"extractable"`
	// Sensitive reports whether the backend refuses to expose the private value
	// via attribute reads. Hardware tokens report true for protected keys.
	Sensitive bool `json:"sensitive"`
}

// KeyLister is an optional capability implemented by providers that can
// enumerate the keys they hold, for inventory and disaster-recovery
// verification. Both the software and PKCS#11 backends implement it. Callers
// type-assert a Provider to this interface.
type KeyLister interface {
	// ListKeys returns a descriptor for every key the provider holds. It reports
	// only non-sensitive metadata and never private key material.
	ListKeys(ctx context.Context) ([]KeyDescriptor, error)
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

// KeyWrapper is an optional capability implemented by providers whose keys can
// wrap and unwrap opaque data (a data-encryption key) with a key-encryption key
// that never leaves the backend — a symmetric KEK. It differs from
// DecrypterProvider: DecrypterProvider models an asymmetric RSA-OAEP KEK exposed
// as a crypto.Decrypter, whereas KeyWrapper models a backend-native symmetric
// wrap where the ciphertext is an opaque, backend-defined blob and only the same
// backend key can unwrap it. The Vault Transit backend implements it via the
// transit encrypt/decrypt endpoints. Callers type-assert a Provider to it.
type KeyWrapper interface {
	// WrapKey seals plaintext under the referenced KEK, returning an opaque
	// ciphertext. The KEK must have been generated with KeyUsageDecrypt.
	WrapKey(ctx context.Context, ref KeyRef, plaintext []byte) (ciphertext []byte, err error)
	// UnwrapKey opens a ciphertext produced by WrapKey under the same KEK.
	UnwrapKey(ctx context.Context, ref KeyRef, ciphertext []byte) (plaintext []byte, err error)
}

// RandomProvider is an optional capability implemented by providers that can
// source cryptographically-strong random bytes directly from their backend's
// hardware RNG — a PKCS#11 token's C_GenerateRandom (Task 138). Callers
// type-assert a Provider to it and fall back to crypto/rand when it is absent
// (the software and cloud-KMS backends do not implement it), so the random-bytes
// service degrades gracefully to the OS CSPRNG rather than failing when no HSM
// is present. Only the PKCS#11 backends implement it, so a successful call means
// the bytes came off the token.
type RandomProvider interface {
	// Random returns n cryptographically-strong random bytes drawn from the
	// backend RNG. It errors on a non-positive n or on a backend failure; the
	// caller is expected to fall back to crypto/rand on error only for
	// availability, never to weaken an explicit HSM-RNG requirement silently.
	Random(ctx context.Context, n int) ([]byte, error)
}

// ErrKeyNotFound is returned (wrapped) by FindKey / Signer / PublicKey when no
// key matches the supplied reference.
var ErrKeyNotFound = fmt.Errorf("keyprovider: key not found")

// ErrWrapUnsupported is returned by KeyWrapper methods when the underlying
// backend cannot wrap keys (every backend except Vault Transit).
var ErrWrapUnsupported = fmt.Errorf("keyprovider: key wrapping not supported by this backend")

// ErrProbeUnsupported is returned by a wrapper's Ping when the wrapped provider
// does not implement Prober. Readiness checks treat it as "cannot probe" rather
// than "unhealthy".
var ErrProbeUnsupported = fmt.Errorf("keyprovider: connectivity probe not supported by this provider")

// ErrRandomUnsupported is returned by the instrumented wrapper's Random when the
// wrapped provider does not implement RandomProvider (the software and cloud-KMS
// backends). The random-bytes service treats it as "no HSM RNG" and falls back
// to crypto/rand, so the presence of the always-on wrapper method never forces a
// caller to believe a hardware RNG exists.
var ErrRandomUnsupported = fmt.Errorf("keyprovider: hardware RNG not supported by this provider")

// PKCS11Settings configures the PKCS#11 backend. It mirrors the fields of
// pki.PKCS11Config; New maps it across so callers of this package need not
// import the pki package directly.
type PKCS11Settings struct {
	ModulePath string
	// URI, when set, is a self-describing RFC 7512 pkcs11: URI that backfills any
	// module/token/PIN field left unset above: its module-path fills ModulePath;
	// its token / serial / manufacturer fill the token selectors; and its
	// pin-value / pin-source fill the PIN (inline PIN or a file PinSource) when no
	// other PIN is configured. Explicit fields always win over the URI. It lets an
	// operator point at an HSM with a single string instead of a block of fields.
	URI string
	// Pin is the inline user PIN (config pkcs11.pin / SECSY_USER_PIN). It is used
	// only when PinSource selects the inline source (the default). Prefer an
	// external PinSource so the PIN is not stored in plaintext at rest.
	Pin string
	// PinSource, when its Type is set, resolves the user PIN lazily from an
	// external credential store (env/file/vault/aws/azure) at login time instead
	// of the inline Pin above. See pinsource.go and docs/hsm-configuration.md.
	PinSource         PinSourceSettings
	TokenLabel        string
	TokenSerial       string
	TokenManufacturer string
	// SessionPoolSize bounds the number of concurrent PKCS#11 sessions (and thus
	// concurrent on-device operations) the provider keeps open. When <= 0 the
	// provider uses DefaultSessionPoolSize. It is the primary HSM throughput
	// tuning knob; see docs/benchmarks.md.
	SessionPoolSize int

	// Tokens, when non-empty, turns the PKCS#11 backend into a high-availability
	// set spanning multiple tokens/slots behind health-tracked failover (see
	// PKCS11HAProvider and docs/hsm-ha.md). Each token holds a replica of the
	// signing key(s) under the same CKA_LABEL; operations are routed to a healthy
	// token and fail over on error. When empty, the backend is the single-token
	// PKCS11Provider addressed by TokenLabel/TokenSerial above.
	Tokens []TokenSettings
	// SelectionPolicy chooses how a healthy token is picked for each operation:
	// "primary-backup" (the default) always prefers the first healthy token in
	// configured order, using backups only on failover; "round-robin" spreads
	// operations across all healthy tokens. Ignored unless Tokens is set.
	SelectionPolicy string
	// FailureThreshold is the number of consecutive operation/probe failures on a
	// token before it is marked unhealthy and taken out of rotation. When <= 0 the
	// provider uses DefaultFailureThreshold. Ignored unless Tokens is set.
	FailureThreshold int
	// ProbeInterval is how often the background health prober re-checks tokens so
	// an unhealthy token is returned to rotation once it recovers. When <= 0 the
	// provider uses DefaultProbeInterval. Ignored unless Tokens is set.
	ProbeInterval time.Duration
}

// TokenSettings identifies one PKCS#11 token/slot within a high-availability
// set. All tokens in a set share the module path and session-pool size from the
// enclosing PKCS11Settings; each addresses a distinct token by label/serial and
// may carry its own PIN.
type TokenSettings struct {
	// Name is a stable logical identifier used in per-token health and failover
	// metrics and in logs. When empty it defaults to TokenLabel (then to a
	// positional token-N name).
	Name string
	// URI, when set, is a per-token RFC 7512 pkcs11: URI that backfills this
	// token's unset label/serial/manufacturer and PIN, exactly as PKCS11Settings.URI
	// does for the single-token backend. It is the natural way to address a
	// specific replica by serial in an HA set where replicas share a CKA_LABEL.
	URI string
	// TokenLabel / TokenSerial / TokenManufacturer address the token, exactly as
	// on the single-token PKCS11Settings.
	TokenLabel        string
	TokenSerial       string
	TokenManufacturer string
	// Pin is the inline user PIN for this token. When empty the shared
	// PKCS11Settings.Pin is used (common when every token shares a PIN policy).
	Pin string
	// PinSource overrides the set-level PKCS11Settings.PinSource for this token.
	// When its Type is empty the shared pin_source (then the inline Pin) is used.
	PinSource PinSourceSettings
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
	KMS      KMSSettings
}

// New constructs the provider selected by cfg.Type.
func New(cfg Config) (Provider, error) {
	switch cfg.Type {
	case ProviderSoftware:
		return NewSoftwareProvider(cfg.Software)
	case ProviderPKCS11:
		// Multiple tokens select the high-availability provider (health-tracked
		// failover across tokens); a single token uses the direct pooled provider.
		if len(cfg.PKCS11.Tokens) > 0 {
			return NewPKCS11HAProvider(cfg.PKCS11)
		}
		return NewPKCS11Provider(cfg.PKCS11)
	case ProviderKMS:
		return NewKMSProvider(cfg.KMS)
	case "":
		return nil, fmt.Errorf("keyprovider: no provider type configured")
	default:
		return nil, fmt.Errorf("keyprovider: unknown provider type %q (supported: %s, %s, %s)",
			cfg.Type, ProviderSoftware, ProviderPKCS11, ProviderKMS)
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
	case "rsa-3072", "rsa3072":
		return KeyTypeRSA3072, nil
	case "rsa-4096", "rsa4096":
		return KeyTypeRSA4096, nil
	default:
		// Fall back to the post-quantum normalizer (ml-dsa-44/65/87 and aliases).
		if kt, err := pqc.NormalizeKeyType(s); err == nil {
			return kt, nil
		}
		return "", fmt.Errorf("keyprovider: unsupported key type %q", s)
	}
}
