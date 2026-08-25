package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

// SoftwareProvider stores private keys as PKCS#8 PEM files in a keystore
// directory, one file per key named "<label>.key". Keys are generated with the
// Go standard library and signing happens in-process. Private keys are written
// with 0600 permissions and are never exported through the Provider API — only
// public keys and signatures leave the provider, mirroring the trust boundary
// of the PKCS#11 backend.
type SoftwareProvider struct {
	dir string
	mu  sync.Mutex // serializes generation so existence checks are race-free
}

// keyFileExt is the on-disk extension for stored private keys.
const keyFileExt = ".key"

// NewSoftwareProvider creates a software provider backed by the given keystore
// directory, creating the directory (0700) if it does not exist.
func NewSoftwareProvider(cfg SoftwareSettings) (*SoftwareProvider, error) {
	dir := cfg.KeystoreDir
	if dir == "" {
		return nil, fmt.Errorf("keyprovider: software keystore directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keyprovider: creating keystore directory %q: %w", dir, err)
	}
	return &SoftwareProvider{dir: dir}, nil
}

func (p *SoftwareProvider) Name() string { return string(ProviderSoftware) }

func (p *SoftwareProvider) Close() error { return nil }

// Ping verifies the keystore directory is present and accessible. It satisfies
// the Prober interface for readiness probing. The software backend has no remote
// dependency, so a readable keystore directory means it is ready.
func (p *SoftwareProvider) Ping(_ context.Context) error {
	info, err := os.Stat(p.dir)
	if err != nil {
		return fmt.Errorf("keyprovider: keystore directory %q not accessible: %w", p.dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("keyprovider: keystore path %q is not a directory", p.dir)
	}
	return nil
}

// keyPath returns the on-disk path for a key label, guarding against path
// traversal from an attacker-influenced label.
func (p *SoftwareProvider) keyPath(label string) (string, error) {
	if label == "" {
		return "", fmt.Errorf("keyprovider: empty key label")
	}
	if strings.ContainsAny(label, `/\`) || label == "." || label == ".." {
		return "", fmt.Errorf("keyprovider: invalid key label %q", label)
	}
	return filepath.Join(p.dir, label+keyFileExt), nil
}

func (p *SoftwareProvider) GenerateKey(_ context.Context, spec KeySpec) (*KeyInfo, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("keyprovider: key label is required")
	}
	keyType, err := NormalizeKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}
	if err := fips.CheckKeyType(keyType); err != nil {
		return nil, fmt.Errorf("keyprovider: %w", err)
	}
	// A decryption key (KEK) must be an RSA key: envelope encryption wraps the
	// data key with RSA-OAEP. The stored key material is identical to a signing
	// RSA key; only the intended usage differs (the software backend does not
	// enforce per-key usage flags the way a token does).
	if spec.Usage == KeyUsageDecrypt {
		if _, bitErr := rsaBits(keyType); bitErr != nil {
			return nil, bitErr
		}
	} else if spec.Usage != "" && spec.Usage != KeyUsageSign {
		return nil, fmt.Errorf("keyprovider: unsupported key usage %q", spec.Usage)
	}
	priv, err := generatePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	der, err := marshalPKCS8(priv, keyType)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: marshaling private key: %w", err)
	}
	if err := p.writeKeyFile(spec.Label, der); err != nil {
		return nil, err
	}

	return p.keyInfo(spec.Label, spec.ID, keyType, priv.Public())
}

// writeKeyFile installs PKCS#8 key material in the keystore under label,
// refusing to overwrite an existing key. It is shared by generation and import
// (Task 194) so both land on disk the same way: 0600, and atomically — written
// to a temp file and renamed, so a crash mid-write never leaves a truncated key
// in place of a working one.
func (p *SoftwareProvider) writeKeyFile(label string, der []byte) error {
	path, err := p.keyPath(label)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, statErr := os.Stat(path); statErr == nil {
		return fmt.Errorf("keyprovider: key %q already exists", label)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("keyprovider: checking for existing key %q: %w", label, statErr)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp, err := os.CreateTemp(p.dir, label+"-*.tmp")
	if err != nil {
		return fmt.Errorf("keyprovider: creating temp key file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keyprovider: chmod temp key file: %w", err)
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keyprovider: writing key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyprovider: closing key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keyprovider: installing key file: %w", err)
	}
	return nil
}

func (p *SoftwareProvider) FindKey(_ context.Context, ref KeyRef) (*KeyInfo, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	priv, keyType, err := p.load(label)
	if err != nil {
		return nil, err
	}
	return p.keyInfo(label, ref.ID, keyType, priv.Public())
}

func (p *SoftwareProvider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	return info.PublicKey, nil
}

func (p *SoftwareProvider) Signer(_ context.Context, ref KeyRef) (Signer, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	priv, keyType, err := p.load(label)
	if err != nil {
		return nil, err
	}
	return &softwareSigner{Signer: priv, keyType: keyType}, nil
}

// Decrypter returns a Decrypter for the referenced RSA KEK. The private key is
// loaded from the keystore and used in-process; it implements crypto.Decrypter
// (rsa.PrivateKey supports RSA-OAEP).
func (p *SoftwareProvider) Decrypter(_ context.Context, ref KeyRef) (Decrypter, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	priv, _, err := p.load(label)
	if err != nil {
		return nil, err
	}
	dec, ok := priv.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("keyprovider: key %q cannot be used for decryption (not RSA)", label)
	}
	if _, ok := priv.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("keyprovider: key %q is not an RSA key and cannot be used for decryption", label)
	}
	return &softwareDecrypter{Decrypter: dec}, nil
}

// ListKeys enumerates the keys in the keystore directory, returning
// non-sensitive metadata for each. It satisfies the KeyLister interface. The
// software backend stores keys as on-disk files, so every key is reported as
// Extractable=true and Sensitive=false — a deliberately honest contrast with a
// hardware token, and the reason production CA/KEK keys belong on an HSM.
func (p *SoftwareProvider) ListKeys(_ context.Context) ([]KeyDescriptor, error) {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: reading keystore directory %q: %w", p.dir, err)
	}
	var out []KeyDescriptor
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), keyFileExt) {
			continue
		}
		label := strings.TrimSuffix(e.Name(), keyFileExt)
		desc := KeyDescriptor{
			Label:       label,
			URI:         "software:" + label,
			Extractable: true,
			Sensitive:   false,
		}
		// Best-effort key-type resolution; a load failure still lists the key.
		if _, keyType, lerr := p.load(label); lerr == nil {
			desc.KeyType = keyType
		}
		out = append(out, desc)
	}
	return out, nil
}

// load reads and parses the private key stored under label. All keys written by
// this provider are asymmetric signing keys, so the result is a crypto.Signer.
func (p *SoftwareProvider) load(label string) (crypto.Signer, string, error) {
	path, err := p.keyPath(label)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("%w: %q", ErrKeyNotFound, label)
		}
		return nil, "", fmt.Errorf("keyprovider: reading key %q: %w", label, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("keyprovider: key %q is not valid PEM", label)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Not a classical PKCS#8 key: try the post-quantum (ML-DSA) parser before
		// giving up, so ML-DSA keys stored by this provider load back correctly.
		if sk, keyType, pqcErr := pqc.ParsePKCS8PrivateKey(block.Bytes); pqcErr == nil {
			return sk, keyType, nil
		}
		return nil, "", fmt.Errorf("keyprovider: parsing key %q: %w", label, err)
	}
	priv, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("keyprovider: key %q is not a signing key", label)
	}
	keyType, err := keyTypeOf(priv.Public())
	if err != nil {
		return nil, "", fmt.Errorf("keyprovider: key %q: %w", label, err)
	}
	return priv, keyType, nil
}

// marshalPKCS8 encodes a freshly generated private key for on-disk storage,
// dispatching to the post-quantum encoder for ML-DSA keys (which the standard
// library cannot marshal) and to the standard PKCS#8 encoder otherwise.
func marshalPKCS8(priv crypto.Signer, keyType string) ([]byte, error) {
	if pqc.IsPQC(keyType) {
		return pqc.MarshalPKCS8PrivateKey(priv)
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// keyInfo builds a KeyInfo including the SSH public key and software: URI.
// ML-DSA keys have no SSH representation, so SSHPublicKey is left empty for them.
func (p *SoftwareProvider) keyInfo(label, id, keyType string, pub crypto.PublicKey) (*KeyInfo, error) {
	info := &KeyInfo{
		Label:     label,
		ID:        id,
		KeyType:   keyType,
		PublicKey: pub,
		URI:       "software:" + label,
	}
	if pqc.IsPQC(keyType) {
		return info, nil
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: building SSH public key: %w", err)
	}
	info.SSHPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return info, nil
}

// generatePrivateKey creates a new private key of the given canonical type.
// All supported key types implement crypto.Signer.
func generatePrivateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		if pqc.IsPQC(keyType) {
			return pqc.GenerateKey(keyType)
		}
		return nil, fmt.Errorf("keyprovider: unsupported key type %q", keyType)
	}
}

// keyTypeOf derives the canonical key-type string from a public key.
func keyTypeOf(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return KeyTypeEd25519, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return KeyTypeECDSAP256, nil
		case elliptic.P384():
			return KeyTypeECDSAP384, nil
		case elliptic.P521():
			return KeyTypeECDSAP521, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve")
		}
	case *rsa.PublicKey:
		switch {
		case k.N.BitLen() > 3072:
			return KeyTypeRSA4096, nil
		case k.N.BitLen() > 2048:
			return KeyTypeRSA3072, nil
		default:
			return KeyTypeRSA2048, nil
		}
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

// softwareSigner adapts an in-memory crypto.Signer to the keyprovider.Signer
// interface. Close is a no-op because there are no backend resources to release.
type softwareSigner struct {
	crypto.Signer
	keyType string
}

func (s *softwareSigner) KeyType() string { return s.keyType }

func (s *softwareSigner) Close() error { return nil }

// softwareDecrypter adapts an in-memory crypto.Decrypter (an *rsa.PrivateKey)
// to the keyprovider.Decrypter interface. Close is a no-op.
type softwareDecrypter struct {
	crypto.Decrypter
}

func (d *softwareDecrypter) Close() error { return nil }

var _ Provider = (*SoftwareProvider)(nil)
var _ Signer = (*softwareSigner)(nil)
var _ DecrypterProvider = (*SoftwareProvider)(nil)
var _ Decrypter = (*softwareDecrypter)(nil)
var _ KeyLister = (*SoftwareProvider)(nil)
