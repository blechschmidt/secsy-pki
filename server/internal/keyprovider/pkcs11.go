package keyprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// PKCS11Provider generates and uses keys on a PKCS#11 token (HSM). It delegates
// the low-level Cryptoki interaction to the pki package, which is already
// exercised against YubiHSM and SoftHSM. Keys are addressed by their CKA_LABEL,
// which is also encoded as the object= attribute of the pkcs11: URI stored with
// each CA.
//
// A fresh module session is opened per operation (generate / sign) and torn
// down afterwards. This keeps the provider stateless and safe for concurrent
// use, at the cost of a login round-trip per request — acceptable for a CA that
// signs interactively rather than in a hot loop.
type PKCS11Provider struct {
	cfg pki.PKCS11Config
}

// NewPKCS11Provider constructs a PKCS#11-backed provider. It validates that a
// module path is configured but defers opening the module until first use, so
// that a server can start even if the HSM is temporarily unreachable.
func NewPKCS11Provider(s PKCS11Settings) (*PKCS11Provider, error) {
	if s.ModulePath == "" {
		return nil, fmt.Errorf("keyprovider: pkcs11 module_path is required")
	}
	return &PKCS11Provider{
		cfg: pki.PKCS11Config{
			ModulePath:        s.ModulePath,
			Pin:               s.Pin,
			TokenLabel:        s.TokenLabel,
			TokenSerial:       s.TokenSerial,
			TokenManufacturer: s.TokenManufacturer,
		},
	}, nil
}

func (p *PKCS11Provider) Name() string { return string(ProviderPKCS11) }

func (p *PKCS11Provider) Close() error { return nil }

func (p *PKCS11Provider) GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("keyprovider: key label is required")
	}
	keyType, err := NormalizeKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}

	// Enforce the Provider contract that GenerateKey fails if a key with the
	// same label already exists. On a PKCS#11 token, generating a second key
	// with a duplicate CKA_LABEL is permitted by Cryptoki but leaves the token
	// in a state where object lookups by label are ambiguous — the private and
	// public halves resolved for a signer can come from different key pairs,
	// yielding signatures that fail verification. Refuse up front instead.
	if existing, err := p.FindKey(ctx, KeyRef{Label: spec.Label}); err == nil {
		_ = existing
		return nil, fmt.Errorf("keyprovider: a key labeled %q already exists on the token", spec.Label)
	} else if !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("keyprovider: checking for existing key %q: %w", spec.Label, err)
	}

	var generated *pki.GeneratedHSMKey
	switch spec.Usage {
	case "", KeyUsageSign:
		generated, err = pki.GenerateKeyOnHSM(p.cfg, spec.Label, keyType)
	case KeyUsageDecrypt:
		bits, bitErr := rsaBits(keyType)
		if bitErr != nil {
			return nil, bitErr
		}
		generated, err = pki.GenerateRSAKEKOnHSM(p.cfg, spec.Label, bits)
	default:
		return nil, fmt.Errorf("keyprovider: unsupported key usage %q", spec.Usage)
	}
	if err != nil {
		return nil, fmt.Errorf("keyprovider: generating key on HSM: %w", err)
	}

	pub, err := publicKeyFromSSH(generated.SSHPublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyInfo{
		Label:        spec.Label,
		ID:           spec.ID,
		KeyType:      keyType,
		PublicKey:    pub,
		URI:          generated.PKCS11URI,
		SSHPublicKey: generated.SSHPublicKey,
	}, nil
}

func (p *PKCS11Provider) FindKey(_ context.Context, ref KeyRef) (*KeyInfo, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	// Opening a signer performs the object lookup and public-key parse. We
	// immediately close it — this is a read-only existence/metadata probe.
	signer, err := pki.NewPKCS11Signer(p.cfg, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	defer signer.Close()

	pub := signer.Public()
	keyType, err := keyTypeOf(pub)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %q: %w", label, err)
	}
	sshPub, err := signer.SSHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %q: %w", label, err)
	}

	return &KeyInfo{
		Label:        label,
		ID:           ref.ID,
		KeyType:      keyType,
		PublicKey:    pub,
		URI:          pki.BuildPKCS11URI(p.cfg, label),
		SSHPublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}, nil
}

func (p *PKCS11Provider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	return info.PublicKey, nil
}

func (p *PKCS11Provider) Signer(_ context.Context, ref KeyRef) (Signer, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	signer, err := pki.NewPKCS11Signer(p.cfg, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	keyType, err := keyTypeOf(signer.Public())
	if err != nil {
		signer.Close()
		return nil, fmt.Errorf("keyprovider: key %q: %w", label, err)
	}
	return &pkcs11Signer{inner: signer, keyType: keyType}, nil
}

// wrapNotFound maps a "not found" error from the pki layer onto ErrKeyNotFound
// while preserving the original message for other failures.
func wrapNotFound(label string, err error) error {
	if err != nil && strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("%w: %q (%v)", ErrKeyNotFound, label, err)
	}
	return fmt.Errorf("keyprovider: opening PKCS#11 key %q: %w", label, err)
}

// publicKeyFromSSH parses an authorized_keys line into a crypto.PublicKey.
func publicKeyFromSSH(authorizedKey string) (crypto.PublicKey, error) {
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, fmt.Errorf("keyprovider: parsing generated SSH public key: %w", err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("keyprovider: generated key does not expose a crypto public key")
	}
	return cryptoPub.CryptoPublicKey(), nil
}

// pkcs11Signer adapts *pki.PKCS11Signer (whose Close returns nothing) to the
// keyprovider.Signer interface. Close is idempotent.
type pkcs11Signer struct {
	inner   *pki.PKCS11Signer
	keyType string
	closed  bool
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.inner.Public() }

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(rand, digest, opts)
}

func (s *pkcs11Signer) KeyType() string { return s.keyType }

func (s *pkcs11Signer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.inner.Close()
	return nil
}

// Decrypter returns a Decrypter for the referenced RSA KEK. The private key
// never leaves the token; unwrapping happens on the device via C_Decrypt.
func (p *PKCS11Provider) Decrypter(_ context.Context, ref KeyRef) (Decrypter, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	signer, err := pki.NewPKCS11Signer(p.cfg, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		signer.Close()
		return nil, fmt.Errorf("keyprovider: key %q is not an RSA key and cannot be used for decryption", label)
	}
	return &pkcs11Decrypter{inner: signer}, nil
}

// pkcs11Decrypter adapts *pki.PKCS11Signer (which also implements C_Decrypt via
// its Decrypt method) to the keyprovider.Decrypter interface. Close is
// idempotent.
type pkcs11Decrypter struct {
	inner  *pki.PKCS11Signer
	closed bool
}

func (d *pkcs11Decrypter) Public() crypto.PublicKey { return d.inner.Public() }

func (d *pkcs11Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.inner.Decrypt(rand, ciphertext, opts)
}

func (d *pkcs11Decrypter) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	d.inner.Close()
	return nil
}

// rsaBits maps a canonical RSA key-type to its modulus size, rejecting
// non-RSA types since a KEK must be an RSA key.
func rsaBits(keyType string) (int, error) {
	switch keyType {
	case KeyTypeRSA2048:
		return 2048, nil
	case KeyTypeRSA4096:
		return 4096, nil
	default:
		return 0, fmt.Errorf("keyprovider: a decryption key (KEK) must be RSA, got %q", keyType)
	}
}

var _ Provider = (*PKCS11Provider)(nil)
var _ Signer = (*pkcs11Signer)(nil)
var _ DecrypterProvider = (*PKCS11Provider)(nil)
var _ Decrypter = (*pkcs11Decrypter)(nil)
