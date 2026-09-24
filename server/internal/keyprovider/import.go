package keyprovider

// Importing an existing private key into a provider (Task 194).
//
// Every other path in this package generates key material: a key is born inside
// the backend and its private half never exists anywhere else. That is the
// property the whole design defends, and import is the one operation that
// cannot offer it — the key already exists, in a file, on the operator's disk.
//
// It is nevertheless the operation that gets key material *out* of that file.
// An organization adopting this PKI typically already has a CA whose root is in
// trust stores it does not control; a CA whose key sits in a software keystore
// today. Refusing to import it does not make that key safer, it makes it stay
// where it is. So import is supported, and made honest about what it is:
//
//   - The imported key gets the same locked-down attributes a generated key
//     gets (non-extractable, sensitive, single-purpose), so from the moment it
//     lands it is as protected as any other key on the device.
//   - Provenance is not laundered. On a YubiHSM the device's own key
//     attestation records that the key was imported rather than generated, and
//     this PKI's attestation verifier reports it (see docs/hsm/key-attestation.md).
//     ImportKey does not, and cannot, change that — it is the correct answer.
//   - It is a distinct, optional capability rather than a Provider method, so a
//     backend that cannot accept foreign key material (every cloud KMS here)
//     says so instead of pretending.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
)

// ImportSpec describes an existing private key to place into a provider.
type ImportSpec struct {
	// Label is the identifier the key will be stored under. Required, and must
	// not already be in use: a duplicate label makes later lookups ambiguous.
	Label string
	// ID is an optional secondary identifier (a hex CKA_ID for PKCS#11).
	ID string
	// Usage is KeyUsageSign (default) or KeyUsageDecrypt, selecting the
	// least-privilege attribute set the key is stored with, exactly as for
	// GenerateKey. A decryption key must be RSA.
	Usage string
	// PrivateKey is the key material: *rsa.PrivateKey, *ecdsa.PrivateKey, or
	// ed25519.PrivateKey. Post-quantum keys cannot be imported (no backend here
	// accepts foreign ML-DSA material).
	PrivateKey crypto.PrivateKey
}

// KeyImporter is an optional capability implemented by providers that can adopt
// an existing private key. The software and PKCS#11 backends (including the
// high-availability multi-token backend) implement it; the cloud-KMS backends
// do not, because bringing your own key there is a service-specific wrapped-
// import ceremony rather than a key-material upload. Callers type-assert a
// Provider to this interface, or use the ImportKey helper.
type KeyImporter interface {
	// ImportKey stores an existing private key in the backend and returns its
	// metadata, exactly as GenerateKey would for a freshly generated one. It
	// fails if a key with the same label already exists.
	ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error)
}

// ErrImportUnsupported is returned when the configured backend cannot adopt an
// existing key.
var ErrImportUnsupported = errors.New("keyprovider: this backend cannot import an existing key")

// ErrImportRejected marks a HOST-SIDE rejection of an import: the request itself
// cannot be honored, whatever the backend's state. Missing label, unusable key
// material, a key type or exact RSA size the crypto policy forbids, a key that
// fails the key-quality gate, a label already in use.
//
// It exists so a caller can tell those apart from a BACKEND failure — an
// unreachable token, a refused C_CreateObject, a dead session — which carries no
// sentinel precisely because it is not the caller's mistake. An API that reports
// a dead HSM as "bad request" sends the operator auditing their key file; one
// that reports a ROCA-vulnerable key as a service outage sends them rebooting the
// token. Classify with errors.Is, never by matching message text.
var ErrImportRejected = errors.New("keyprovider: the key cannot be imported as specified")

// ImportKey imports spec into p when p supports it, and returns a wrapped
// ErrImportUnsupported naming the backend when it does not.
func ImportKey(ctx context.Context, p Provider, spec ImportSpec) (*KeyInfo, error) {
	imp, ok := p.(KeyImporter)
	if !ok {
		return nil, fmt.Errorf("%w (backend %q); generate the key instead, or import it with the backend's own tooling", ErrImportUnsupported, p.Name())
	}
	return imp.ImportKey(ctx, spec)
}

// CanImport reports whether p can adopt an existing key.
func CanImport(p Provider) bool {
	_, ok := p.(KeyImporter)
	return ok
}

// validateImportSpec applies the checks every backend shares: a label, usable
// key material, an algorithm the deployment's crypto policy permits, the
// key-quality gate, and the RSA-only rule for key-encryption keys. It returns
// the canonical key type.
//
// Every failure here is host-side — none of it touches the backend — so all of
// it is tagged ErrImportRejected: this is the single function every provider's
// ImportKey goes through, which makes it the one place the caller/backend split
// can be established for all of them at once.
func validateImportSpec(spec ImportSpec) (string, error) {
	if spec.Label == "" {
		return "", fmt.Errorf("%w: key label is required", ErrImportRejected)
	}
	if spec.PrivateKey == nil {
		return "", fmt.Errorf("%w: no private key supplied for import", ErrImportRejected)
	}
	keyType, err := pki.PrivateKeyType(spec.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrImportRejected, err)
	}
	if err := fips.CheckKeyType(keyType); err != nil {
		return "", fmt.Errorf("%w: %w", ErrImportRejected, err)
	}
	if err := checkImportKeyQuality(spec.PrivateKey); err != nil {
		return "", err // already tagged
	}
	switch spec.Usage {
	case "", KeyUsageSign:
	case KeyUsageDecrypt:
		if _, ok := spec.PrivateKey.(*rsa.PrivateKey); !ok {
			return "", fmt.Errorf("%w: a key-encryption key must be RSA, got %s", ErrImportRejected, keyType)
		}
	default:
		return "", fmt.Errorf("%w: unsupported key usage %q", ErrImportRejected, spec.Usage)
	}
	if _, ok := spec.PrivateKey.(crypto.Signer); !ok {
		return "", fmt.Errorf("%w: private key of type %T cannot be used", ErrImportRejected, spec.PrivateKey)
	}
	return keyType, nil
}

// checkImportKeyQuality runs the same structural weak-key gate that every
// subject public key passes before it is certified (CA/Browser Forum BR
// §6.1.1.3): ROCA, exponent policy, and modulus sanity.
//
// The CA-adoption path already ran this, but `import-key` and the secret layer's
// signing-key import did not — so a ROCA-vulnerable key, or one with e=3, could
// be written to a token by the one command whose whole purpose is to give a key
// a *more* trustworthy home. Checking here covers every caller and every backend
// at once, because this is the single function all of them go through.
//
// The gate is stateless: the persisted compromised-key blocklist lives in the ca
// package, which consults it on top of this for an adopted CA key. Only the
// structural checks belong here, where there is no database to consult.
//
// On a YubiHSM the exponent rule is doubly useful. The device accepts e=65537
// and nothing else, so a key with e=3 was going to fail there regardless — this
// turns "CKR_ATTRIBUTE_VALUE_INVALID" into a sentence naming the problem.
func checkImportKeyQuality(priv crypto.PrivateKey) error {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil // The type check in validateImportSpec reports this.
	}
	res := keycheck.Inspect(signer.Public(), keycheck.DefaultPolicy(nil))
	if res.OK() {
		return nil
	}
	details := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		details = append(details, f.Detail)
	}
	return fmt.Errorf("%w: it fails the key-quality gate and must not be imported: %s",
		ErrImportRejected, strings.Join(details, "; "))
}

// VerifyKeyUsable proves that the referenced key is present in the provider and
// really is the key the caller expects, by signing a random challenge with the
// backend and verifying the signature against the expected public key.
//
// This is the check that makes an import trustworthy end to end. Creating a key
// object can succeed while the material is subtly wrong — a truncated CRT
// coefficient, a scalar the module re-encoded, a public object that resolves to
// a *different* key that happens to share the label — and every one of those
// failures would otherwise surface much later, as a certificate nobody can
// verify. One signature settles it.
//
// It is only meaningful for signing keys; a decryption-only key cannot sign and
// is skipped by the caller.
func VerifyKeyUsable(ctx context.Context, p Provider, ref KeyRef, expected crypto.PublicKey) error {
	signer, err := p.Signer(ctx, ref)
	if err != nil {
		return fmt.Errorf("keyprovider: opening a signer for the key: %w", err)
	}
	defer signer.Close()

	if !publicKeysMatch(signer.Public(), expected) {
		return fmt.Errorf("keyprovider: the key in the backend does not match the expected public key")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("keyprovider: generating verification challenge: %w", err)
	}
	digest := sha256.Sum256(challenge)

	switch pub := expected.(type) {
	case ed25519.PublicKey:
		// Ed25519 signs the message itself, not a digest (crypto.Hash(0)).
		sig, err := signer.Sign(rand.Reader, challenge, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("keyprovider: test signature failed: %w", err)
		}
		if !ed25519.Verify(pub, challenge, sig) {
			return fmt.Errorf("keyprovider: the key produced a signature that does not verify against its own public key")
		}
	case *ecdsa.PublicKey:
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("keyprovider: test signature failed: %w", err)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("keyprovider: the key produced a signature that does not verify against its own public key")
		}
	case *rsa.PublicKey:
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("keyprovider: test signature failed: %w", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("keyprovider: the key produced a signature that does not verify against its own public key: %w", err)
		}
	default:
		return fmt.Errorf("keyprovider: cannot verify a key of type %T", expected)
	}
	return nil
}

// publicKeysMatch compares two public keys structurally.
func publicKeysMatch(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if a == nil || b == nil {
		return false
	}
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// ImportKey stores an existing private key in the software keystore. The key is
// written with the same 0600 permissions and atomic rename as a generated one.
//
// The software backend cannot make an imported key any less copyable than the
// file it came from — that is the honest difference between it and a token, and
// the reason the CLI says so when adopting a CA onto it.
func (p *SoftwareProvider) ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error) {
	keyType, err := validateImportSpec(spec)
	if err != nil {
		return nil, err
	}
	// Duplicate-label check up front, as the PKCS#11 backend does it: writeKeyFile
	// also refuses, but it is shared with GenerateKey and so cannot tag the failure
	// as an import rejection — and a label already in use is the caller's choice to
	// fix, not a backend that is down.
	if _, ferr := p.FindKey(ctx, KeyRef{Label: spec.Label}); ferr == nil {
		return nil, fmt.Errorf("%w: a key labeled %q already exists in the keystore", ErrImportRejected, spec.Label)
	} else if !errors.Is(ferr, ErrKeyNotFound) {
		return nil, fmt.Errorf("keyprovider: checking for existing key %q: %w", spec.Label, ferr)
	}
	signer := spec.PrivateKey.(crypto.Signer)

	der, err := marshalPKCS8(signer, keyType)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: marshaling private key: %w", err)
	}
	if err := p.writeKeyFile(spec.Label, der); err != nil {
		return nil, err
	}
	return p.keyInfo(spec.Label, spec.ID, keyType, signer.Public())
}

// ImportKey stores an existing private key on the PKCS#11 token.
func (p *PKCS11Provider) ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error) {
	keyType, err := validateImportSpec(spec)
	if err != nil {
		return nil, err
	}
	// Same duplicate-label invariant GenerateKey enforces: two objects sharing a
	// CKA_LABEL resolve ambiguously, and the private and public halves of a
	// signer can then come from different key pairs.
	if _, err := p.FindKey(ctx, KeyRef{Label: spec.Label}); err == nil {
		return nil, fmt.Errorf("%w: a key labeled %q already exists on the token", ErrImportRejected, spec.Label)
	} else if !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("keyprovider: checking for existing key %q: %w", spec.Label, err)
	}

	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	loc, err := locatorFor(KeyRef{Label: spec.Label, ID: spec.ID})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrImportRejected, err)
	}
	imported, err := pool.ImportKey(ctx, spec.Label, loc.ID, spec.PrivateKey, importUsage(spec.Usage))
	if err != nil {
		return nil, fmt.Errorf("keyprovider: importing key onto the HSM: %w", err)
	}
	pub, err := publicKeyFromSSH(imported.SSHPublicKey)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		Label:        spec.Label,
		ID:           spec.ID,
		KeyType:      keyType,
		PublicKey:    pub,
		URI:          imported.PKCS11URI,
		SSHPublicKey: imported.SSHPublicKey,
	}, nil
}

// ImportKey stores an existing private key on every token in the
// high-availability set.
//
// Partial import is the failure mode to avoid: a key present on some replicas
// and absent from others turns a failover into an outage that only shows up
// under load. The import therefore runs against every member and, if any member
// rejects it, reports which ones hold the key so the operator can finish or
// unwind the job deliberately rather than discovering the split later.
func (p *PKCS11HAProvider) ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error) {
	if _, err := validateImportSpec(spec); err != nil {
		return nil, err
	}
	var first *KeyInfo
	var done []string
	for _, m := range p.members {
		info, err := m.provider.ImportKey(ctx, spec)
		if err != nil {
			if len(done) == 0 {
				return nil, fmt.Errorf("keyprovider: importing key onto token %s: %w", m.name, err)
			}
			return nil, fmt.Errorf("keyprovider: key %q was imported onto %v but token %s rejected it: %w; "+
				"the high-availability set is now inconsistent — remove the key from the listed tokens or complete the import before relying on failover",
				spec.Label, done, m.name, err)
		}
		done = append(done, m.name)
		if first == nil {
			first = info
		}
	}
	if first == nil {
		return nil, fmt.Errorf("keyprovider: no tokens configured")
	}
	return first, nil
}

// importUsage maps a KeySpec usage string to the pki-layer usage selector.
func importUsage(usage string) pki.ImportKeyUsage {
	if usage == KeyUsageDecrypt {
		return pki.ImportUsageDecrypt
	}
	return pki.ImportUsageSign
}

// ImportKey forwards to the wrapped provider's KeyImporter implementation and
// records the operation on the metrics/audit path, so an import through the
// instrumented wrapper is observed exactly like a generation.
func (p *instrumentedProvider) ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error) {
	imp, ok := p.Provider.(KeyImporter)
	if !ok {
		return nil, fmt.Errorf("%w (backend %q)", ErrImportUnsupported, p.Name())
	}
	ctx, span := tracing.Start(ctx, "hsm.import_key",
		attribute.String("hsm.operation", "import"),
		attribute.String("hsm.key.label", spec.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	info, err := imp.ImportKey(ctx, spec)
	metrics.ObserveHSM("import", start, err)
	tracing.RecordError(ctx, err)
	return info, err
}

// ImportKey forwards to the wrapped provider's KeyImporter implementation and
// marks the device as operated, so the HSM audit-log collector drains the
// device log after an import just as it does after a signature.
func (p *recordingProvider) ImportKey(ctx context.Context, spec ImportSpec) (*KeyInfo, error) {
	imp, ok := p.Provider.(KeyImporter)
	if !ok {
		return nil, fmt.Errorf("%w (backend %q)", ErrImportUnsupported, p.Name())
	}
	info, err := imp.ImportKey(ctx, spec)
	p.operated()
	return info, err
}
