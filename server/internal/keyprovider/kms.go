package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// ProviderKMS stores and uses keys in a cloud key-management service (AWS KMS or
// Azure Key Vault). Like the PKCS#11 backend, the private key never leaves the
// service: generation, signing, and public-key export all happen through the
// cloud API, and there is no operation that returns private key material. See
// docs/cloud-kms.md for backend selection and IAM requirements.
const ProviderKMS ProviderType = "kms"

// Cloud-KMS backend identifiers accepted by KMSSettings.Backend.
const (
	// KMSBackendAWS uses AWS KMS. Keys are addressed by an alias derived from the
	// key label; signing and public-key export use the KMS API.
	KMSBackendAWS = "aws"
	// KMSBackendAzure uses Azure Key Vault. Keys are addressed by name derived
	// from the key label.
	KMSBackendAzure = "azure"
	// KMSBackendFake uses an in-process, in-memory KMS emulation. It generates
	// real keys with the Go standard library but exposes only the same surface a
	// real cloud KMS does (no private-key export), so unit and integration tests
	// exercise the KMSProvider code paths without cloud credentials.
	KMSBackendFake = "fake"
	// KMSBackendVault uses the HashiCorp Vault Transit secrets engine. Keys are
	// addressed by a name derived from the label; signing, public-key export, and
	// wrap/unwrap all go through the Transit REST API. Defined in kms_vault.go.
	// (KMSBackendVault is declared there alongside the backend implementation.)
)

// KMSSettings configures the cloud-KMS backend.
type KMSSettings struct {
	// Backend selects the provider: "aws", "azure", "vault", or "fake".
	Backend string
	// Region is the AWS region (e.g. "eu-central-1"). Required for the AWS
	// backend; ignored otherwise. When empty the AWS SDK's default resolution
	// (AWS_REGION, shared config) applies.
	Region string
	// KeyPrefix is prepended to the key label to form the cloud-side key
	// identifier (an AWS KMS alias name, or an Azure key name). It namespaces this
	// deployment's keys within a shared account/vault. AWS aliases and Azure key
	// names have different character rules, so the backend sanitizes as needed.
	KeyPrefix string
	// VaultURL is the Azure Key Vault base URL
	// (e.g. "https://my-vault.vault.azure.net/"). Required for the Azure backend.
	VaultURL string
	// Vault configures the HashiCorp Vault Transit backend (Backend == "vault").
	Vault VaultSettings
	// GCP configures the Google Cloud KMS backend (Backend == "gcpkms").
	GCP GCPKMSSettings
}

// KMSBackend is the narrow interface the KMSProvider needs from a concrete cloud
// KMS. It deliberately exposes no operation that returns private key material,
// enforcing the non-extractability invariant at the type level: an implementation
// physically cannot leak a private key through this surface. Concrete backends
// (AWS KMS, Azure Key Vault, and the in-memory fake) implement it.
//
// Implementations must be safe for concurrent use.
type KMSBackend interface {
	// BackendName identifies the concrete backend ("aws", "azure", "vault", "fake").
	BackendName() string
	// CreateKey provisions a new asymmetric signing key of the given canonical
	// key type, addressable later by label. It fails if a key with the same label
	// already exists.
	CreateKey(ctx context.Context, label, keyType string) (*RemoteKey, error)
	// ResolveKey locates an existing key by label, returning its cloud-side
	// identifier, key type, and public key. It returns an error that unwraps to
	// ErrKeyNotFound when no key matches.
	ResolveKey(ctx context.Context, label string) (*RemoteKey, error)
	// Sign produces a signature over digest using the referenced key. hash is the
	// digest algorithm (the digest is already computed by the caller); pss selects
	// RSA-PSS over RSASSA-PKCS1v1.5 for RSA keys and is ignored for ECDSA.
	Sign(ctx context.Context, keyID string, keyType string, digest []byte, hash crypto.Hash, pss bool) ([]byte, error)
	// ListKeys enumerates the keys managed under this backend's prefix.
	ListKeys(ctx context.Context) ([]RemoteKey, error)
	// Ping performs a lightweight reachability/authorization check that requires
	// no particular key to exist.
	Ping(ctx context.Context) error
	// Close releases any long-lived backend resources.
	Close() error
}

// RemoteKey is the non-sensitive metadata a KMSBackend returns for one key.
type RemoteKey struct {
	// Label is the deployment-facing identifier the key was created under.
	Label string
	// KeyID is the cloud-side identifier used for subsequent operations (an AWS
	// KMS key ID/ARN, or an Azure key identifier URL).
	KeyID string
	// KeyType is the canonical KeyType* string.
	KeyType string
	// PublicKey is the exported public half.
	PublicKey crypto.PublicKey
	// URI is a stable reference to the key (a kms: URI). Optional; the provider
	// synthesizes one when empty.
	URI string
}

// KMSProvider adapts a KMSBackend to the keyprovider.Provider interface. It holds
// no key material of its own; every operation is delegated to the backend.
type KMSProvider struct {
	backend KMSBackend
}

// NewKMSProvider constructs a cloud-KMS provider from settings, instantiating the
// selected backend (AWS KMS, Azure Key Vault, or the in-memory fake).
func NewKMSProvider(cfg KMSSettings) (*KMSProvider, error) {
	backend, err := newKMSBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &KMSProvider{backend: backend}, nil
}

// NewKMSProviderWithBackend wraps an already-constructed backend. It is used by
// tests to inject the in-memory fake, and by callers that build a backend
// directly.
func NewKMSProviderWithBackend(backend KMSBackend) *KMSProvider {
	return &KMSProvider{backend: backend}
}

// newKMSBackend dispatches to the concrete backend selected by cfg.Backend.
func newKMSBackend(cfg KMSSettings) (KMSBackend, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case KMSBackendFake:
		return NewFakeKMSBackend(cfg.KeyPrefix), nil
	case KMSBackendAWS:
		return newAWSKMSBackend(cfg)
	case KMSBackendAzure:
		return newAzureKeyVaultBackend(cfg)
	case KMSBackendVault:
		return newVaultTransitBackend(cfg)
	case KMSBackendGCP:
		return newGCPKMSBackend(cfg)
	case "":
		return nil, fmt.Errorf("keyprovider: kms backend is required (aws, azure, gcpkms, vault, or fake)")
	default:
		return nil, fmt.Errorf("keyprovider: unknown kms backend %q (supported: %s, %s, %s, %s, %s)",
			cfg.Backend, KMSBackendAWS, KMSBackendAzure, KMSBackendGCP, KMSBackendVault, KMSBackendFake)
	}
}

// kmsWrapBackend is an optional capability a KMSBackend may implement when it can
// wrap and unwrap opaque data (a data-encryption key) with a key-encryption key
// that never leaves the backend — a symmetric KEK. Only the Vault Transit backend
// implements it; AWS KMS and Azure Key Vault expose no such symmetric operation
// for these roles. The KMSProvider surfaces it via the KeyWrapper interface.
type kmsWrapBackend interface {
	// CreateWrappingKey provisions a new symmetric KEK addressable by label. It
	// fails if a key with the same label already exists.
	CreateWrappingKey(ctx context.Context, label string) (*RemoteKey, error)
	// WrapKey seals plaintext (a DEK) under the label's KEK, returning an opaque,
	// backend-defined ciphertext blob.
	WrapKey(ctx context.Context, label string, plaintext []byte) ([]byte, error)
	// UnwrapKey opens a blob produced by WrapKey under the same KEK.
	UnwrapKey(ctx context.Context, label string, ciphertext []byte) ([]byte, error)
}

func (p *KMSProvider) Name() string { return string(ProviderKMS) }

func (p *KMSProvider) Close() error { return p.backend.Close() }

// Ping delegates to the backend's reachability probe, satisfying Prober.
func (p *KMSProvider) Ping(ctx context.Context) error { return p.backend.Ping(ctx) }

// GenerateKey provisions a new key in the cloud KMS. For signing keys (the
// default usage) cloud KMS backends support ECDSA (P-256/384/521) and RSA
// (2048/4096); Ed25519 and post-quantum key types are rejected, since no cloud
// KMS offers them for the CA/TSA/OCSP signing roles this backend serves. For a
// key-encryption key (KeyUsageDecrypt) the backend must support wrapping (only
// the Vault Transit backend does), in which case a symmetric KEK is provisioned.
func (p *KMSProvider) GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("keyprovider: key label is required")
	}
	if spec.Usage == KeyUsageDecrypt {
		wb, ok := p.backend.(kmsWrapBackend)
		if !ok {
			return nil, fmt.Errorf("keyprovider: kms backend %q does not support key-encryption (KEK) keys", p.backend.BackendName())
		}
		rk, err := wb.CreateWrappingKey(ctx, spec.Label)
		if err != nil {
			return nil, err
		}
		return keyInfoFromRemote(rk, spec.ID)
	}
	if spec.Usage != "" && spec.Usage != KeyUsageSign {
		return nil, fmt.Errorf("keyprovider: kms backend supports only sign or decrypt usage, not %q", spec.Usage)
	}
	keyType, err := NormalizeKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}
	if err := fips.CheckKeyType(keyType); err != nil {
		return nil, fmt.Errorf("keyprovider: %w", err)
	}
	if err := kmsSupportsKeyType(keyType); err != nil {
		return nil, err
	}
	rk, err := p.backend.CreateKey(ctx, spec.Label, keyType)
	if err != nil {
		return nil, err
	}
	return keyInfoFromRemote(rk, spec.ID)
}

// WrapKey seals plaintext (a data-encryption key) under the referenced KEK,
// returning an opaque backend ciphertext. It requires a backend that supports
// wrapping (Vault Transit); other backends return ErrWrapUnsupported. It
// satisfies KeyWrapper.
func (p *KMSProvider) WrapKey(ctx context.Context, ref KeyRef, plaintext []byte) ([]byte, error) {
	wb, ok := p.backend.(kmsWrapBackend)
	if !ok {
		return nil, ErrWrapUnsupported
	}
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	return wb.WrapKey(ctx, label, plaintext)
}

// UnwrapKey opens a blob produced by WrapKey under the referenced KEK. It
// requires a wrapping-capable backend and satisfies KeyWrapper.
func (p *KMSProvider) UnwrapKey(ctx context.Context, ref KeyRef, ciphertext []byte) ([]byte, error) {
	wb, ok := p.backend.(kmsWrapBackend)
	if !ok {
		return nil, ErrWrapUnsupported
	}
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	return wb.UnwrapKey(ctx, label, ciphertext)
}

func (p *KMSProvider) FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	rk, err := p.backend.ResolveKey(ctx, label)
	if err != nil {
		return nil, err
	}
	return keyInfoFromRemote(rk, ref.ID)
}

func (p *KMSProvider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	return info.PublicKey, nil
}

func (p *KMSProvider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	rk, err := p.backend.ResolveKey(ctx, label)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{
		ctx:     ctx,
		backend: p.backend,
		keyID:   rk.KeyID,
		keyType: rk.KeyType,
		pub:     rk.PublicKey,
	}, nil
}

// ListKeys enumerates the backend's keys as non-sensitive descriptors. Every key
// is reported Extractable=false and Sensitive=true: a cloud KMS never releases
// private key material, the same trust boundary an HSM provides.
func (p *KMSProvider) ListKeys(ctx context.Context) ([]KeyDescriptor, error) {
	keys, err := p.backend.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]KeyDescriptor, 0, len(keys))
	for _, k := range keys {
		out = append(out, KeyDescriptor{
			Label:       k.Label,
			ID:          k.KeyID,
			KeyType:     k.KeyType,
			URI:         kmsURI(p.backend.BackendName(), k),
			Extractable: false,
			Sensitive:   true,
		})
	}
	return out, nil
}

// kmsSigner is a crypto.Signer backed by a cloud-KMS key. It carries the context
// from the Signer() call because crypto.Signer.Sign has no context parameter; the
// x509/CMS signing paths derive a per-signer instance, so this is request-scoped.
type kmsSigner struct {
	ctx     context.Context
	backend KMSBackend
	keyID   string
	keyType string
	pub     crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.pub }

func (s *kmsSigner) KeyType() string { return s.keyType }

func (s *kmsSigner) Close() error { return nil }

// Sign computes a signature over digest through the cloud KMS. It mirrors the
// standard-library contract: for RSA keys, an *rsa.PSSOptions selects RSA-PSS,
// otherwise RSASSA-PKCS1v1.5; for ECDSA keys the ASN.1 DER signature is returned.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := crypto.Hash(0)
	if opts != nil {
		hash = opts.HashFunc()
	}
	_, pss := opts.(*rsa.PSSOptions)
	// Reject a request that does not match the key family, so a misconfigured
	// profile fails loudly rather than producing an unverifiable signature.
	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		if hash == 0 {
			return nil, fmt.Errorf("keyprovider: kms ECDSA signing requires a hash")
		}
	case *rsa.PublicKey:
		if hash == 0 {
			return nil, fmt.Errorf("keyprovider: kms RSA signing requires a hash")
		}
	default:
		return nil, fmt.Errorf("keyprovider: kms signer has unsupported public key type %T", s.pub)
	}
	return s.backend.Sign(s.ctx, s.keyID, s.keyType, digest, hash, pss)
}

// kmsSupportsKeyType reports whether a canonical key type can be provisioned in a
// cloud KMS, with a clear error naming the supported set otherwise.
func kmsSupportsKeyType(keyType string) error {
	switch keyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521, KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		return nil
	default:
		return fmt.Errorf("keyprovider: cloud KMS does not support key type %q "+
			"(supported: %s, %s, %s, %s, %s, %s)", keyType,
			KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521, KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096)
	}
}

// keyInfoFromRemote builds a KeyInfo (including the SSH public key) from backend
// metadata.
func keyInfoFromRemote(rk *RemoteKey, id string) (*KeyInfo, error) {
	if rk == nil {
		return nil, fmt.Errorf("keyprovider: kms backend returned no key")
	}
	if id == "" {
		id = rk.KeyID
	}
	info := &KeyInfo{
		Label:     rk.Label,
		ID:        id,
		KeyType:   rk.KeyType,
		PublicKey: rk.PublicKey,
		URI:       rk.URI,
	}
	if info.URI == "" {
		info.URI = "kms:" + rk.Label
	}
	if rk.PublicKey != nil {
		if sshPub, err := ssh.NewPublicKey(rk.PublicKey); err == nil {
			info.SSHPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
		}
	}
	return info, nil
}

// kmsURI synthesizes a stable kms: URI for a remote key.
func kmsURI(backend string, k RemoteKey) string {
	if k.URI != "" {
		return k.URI
	}
	return fmt.Sprintf("kms:%s:%s", backend, k.Label)
}

var (
	_ Provider   = (*KMSProvider)(nil)
	_ Prober     = (*KMSProvider)(nil)
	_ KeyLister  = (*KMSProvider)(nil)
	_ KeyWrapper = (*KMSProvider)(nil)
	_ Signer     = (*kmsSigner)(nil)
)
