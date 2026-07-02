package keyprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

// DefaultSessionPoolSize is the number of concurrent PKCS#11 sessions the
// provider maintains when no size is configured. It bounds how many signing /
// decryption operations may hit the token at once; requests beyond it queue.
// See docs/benchmarks.md for tuning guidance.
const DefaultSessionPoolSize = 8

// PKCS11Provider generates and uses keys on a PKCS#11 token (HSM). It delegates
// the low-level Cryptoki interaction to the pki package, which is already
// exercised against YubiHSM and SoftHSM. Keys are addressed by their CKA_LABEL,
// which is also encoded as the object= attribute of the pkcs11: URI stored with
// each CA.
//
// The provider keeps a bounded pool of long-lived, already-logged-in sessions
// (see pki.SessionPool). Operations borrow a session, use it, and return it, so
// there is no per-operation module load, login, or finalize. This is both
// faster than the historical open-per-operation design and safe under
// concurrency on tokens (SoftHSM included) whose login/finalize state is
// per-application rather than per-session. Pool size is the primary throughput
// tuning knob.
//
// The pool is built lazily on first use so the server can start even when the
// HSM is momentarily unreachable; a construction failure is not memoized, so a
// later request retries once the token is back.
type PKCS11Provider struct {
	cfg      pki.PKCS11Config
	poolSize int

	mu   sync.Mutex
	pool *pki.SessionPool
}

// NewPKCS11Provider constructs a PKCS#11-backed provider. It validates that a
// module path is configured but defers opening the module until first use, so
// that a server can start even if the HSM is temporarily unreachable.
func NewPKCS11Provider(s PKCS11Settings) (*PKCS11Provider, error) {
	if s.ModulePath == "" {
		return nil, fmt.Errorf("keyprovider: pkcs11 module_path is required")
	}
	size := s.SessionPoolSize
	if size <= 0 {
		size = DefaultSessionPoolSize
	}
	return &PKCS11Provider{
		poolSize: size,
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

// getPool returns the shared session pool, building it lazily on first use.
// Construction (which logs in) is retried on a later call if it fails, so a
// transient HSM outage or a not-yet-present token does not permanently wedge the
// provider.
func (p *PKCS11Provider) getPool(_ context.Context) (*pki.SessionPool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pool != nil {
		return p.pool, nil
	}
	pool, err := pki.NewSessionPool(p.cfg, p.poolSize)
	if err != nil {
		return nil, err
	}
	p.pool = pool
	return pool, nil
}

// Close releases the session pool (closing every session, logging out, and
// releasing the module reference). It is safe to call on a provider whose pool
// was never built.
func (p *PKCS11Provider) Close() error {
	p.mu.Lock()
	pool := p.pool
	p.pool = nil
	p.mu.Unlock()
	if pool != nil {
		return pool.Close()
	}
	return nil
}

// Ping verifies the token is reachable and the PIN is accepted, without
// requiring any key to exist. It satisfies the Prober interface for readiness
// probing. Building the pool performs the login round-trip; once built, a probe
// simply confirms a pooled session is still live.
func (p *PKCS11Provider) Ping(ctx context.Context) error {
	pool, err := p.getPool(ctx)
	if err != nil {
		return err
	}
	return pool.Ping(ctx)
}

func (p *PKCS11Provider) GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("keyprovider: key label is required")
	}
	keyType, err := NormalizeKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}
	// Post-quantum keys are not (yet) supported by the PKCS#11 backend. SoftHSM
	// in particular has no ML-DSA mechanism, so callers must use the software key
	// provider for PQC keys; fail closed with an actionable message rather than
	// emitting an opaque Cryptoki mechanism error.
	if pqc.IsPQC(keyType) {
		return nil, fmt.Errorf("keyprovider: ML-DSA key type %q is not supported by the PKCS#11 backend "+
			"(the token/HSM lacks a post-quantum mechanism); use the software key provider for PQC keys", keyType)
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

	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}

	var generated *pki.GeneratedHSMKey
	switch spec.Usage {
	case "", KeyUsageSign:
		generated, err = pool.GenerateSignKey(ctx, spec.Label, keyType)
	case KeyUsageDecrypt:
		bits, bitErr := rsaBits(keyType)
		if bitErr != nil {
			return nil, bitErr
		}
		generated, err = pool.GenerateRSAKEK(ctx, spec.Label, bits)
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

func (p *PKCS11Provider) FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	pub, _, _, err := pool.PublicKey(ctx, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	keyType, err := keyTypeOf(pub)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %q: %w", label, err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
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

func (p *PKCS11Provider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	pub, _, _, err := pool.PublicKey(ctx, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	keyType, err := keyTypeOf(pub)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %q: %w", label, err)
	}
	return &pkcs11Signer{pool: pool, ctx: ctx, label: label, pub: pub, keyType: keyType}, nil
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

// pkcs11Signer is a keyprovider.Signer bound to a pooled session backend. It
// holds no session of its own: each Sign borrows a session from the pool for the
// duration of the on-device operation and returns it. Close is therefore a
// bookkeeping no-op (there is nothing per-signer to release) and is idempotent.
type pkcs11Signer struct {
	pool    *pki.SessionPool
	ctx     context.Context
	label   string
	pub     crypto.PublicKey
	keyType string
	closed  bool
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.pub }

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.closed {
		return nil, fmt.Errorf("keyprovider: signer is closed")
	}
	return s.pool.Sign(s.ctx, s.label, digest, opts)
}

func (s *pkcs11Signer) KeyType() string { return s.keyType }

func (s *pkcs11Signer) Close() error {
	s.closed = true
	return nil
}

// ListKeys enumerates the private-key objects on the token, returning only
// non-sensitive metadata (label, id, key type, and the extractability /
// sensitivity policy flags). Private key material is never read. It satisfies
// the KeyLister interface for inventory and DR verification.
func (p *PKCS11Provider) ListKeys(ctx context.Context) ([]KeyDescriptor, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	hsmKeys, err := pool.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: listing keys on token: %w", err)
	}
	out := make([]KeyDescriptor, 0, len(hsmKeys))
	for _, k := range hsmKeys {
		out = append(out, KeyDescriptor{
			Label:       k.Label,
			ID:          k.ID,
			KeyType:     k.KeyType,
			URI:         pki.BuildPKCS11URI(p.cfg, k.Label),
			Extractable: k.Extractable,
			Sensitive:   k.Sensitive,
		})
	}
	return out, nil
}

// Decrypter returns a Decrypter for the referenced RSA KEK. The private key
// never leaves the token; unwrapping happens on the device via C_Decrypt.
func (p *PKCS11Provider) Decrypter(ctx context.Context, ref KeyRef) (Decrypter, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	pub, _, _, err := pool.PublicKey(ctx, label)
	if err != nil {
		return nil, wrapNotFound(label, err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("keyprovider: key %q is not an RSA key and cannot be used for decryption", label)
	}
	return &pkcs11Decrypter{pool: pool, ctx: ctx, label: label, pub: pub}, nil
}

// pkcs11Decrypter is a keyprovider.Decrypter bound to a pooled session backend.
// Like pkcs11Signer it holds no session of its own; each Decrypt borrows one for
// the duration of the on-device unwrap. Close is an idempotent no-op.
type pkcs11Decrypter struct {
	pool   *pki.SessionPool
	ctx    context.Context
	label  string
	pub    crypto.PublicKey
	closed bool
}

func (d *pkcs11Decrypter) Public() crypto.PublicKey { return d.pub }

func (d *pkcs11Decrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.closed {
		return nil, fmt.Errorf("keyprovider: decrypter is closed")
	}
	return d.pool.Decrypt(d.ctx, d.label, ciphertext, opts)
}

func (d *pkcs11Decrypter) Close() error {
	d.closed = true
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
var _ KeyLister = (*PKCS11Provider)(nil)
