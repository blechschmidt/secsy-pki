package keyprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
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
	// pinSource resolves the user PIN lazily at login time (when the pool is first
	// built), keeping the PIN out of cfg — and thus out of any dumped config — until
	// it is needed for C_Login. It is never nil (the inline source wraps cfg's PIN).
	pinSource PinSource

	mu   sync.Mutex
	pool *pki.SessionPool
}

// NewPKCS11Provider constructs a PKCS#11-backed provider. It validates that a
// module path is configured but defers opening the module until first use, so
// that a server can start even if the HSM is temporarily unreachable.
func NewPKCS11Provider(s PKCS11Settings) (*PKCS11Provider, error) {
	// Backfill any module/token/PIN fields left unset from a self-describing
	// RFC 7512 URI before validating that a module path is present.
	s, err := applyPKCS11URI(s)
	if err != nil {
		return nil, err
	}
	if s.ModulePath == "" {
		return nil, fmt.Errorf("keyprovider: pkcs11 module_path is required")
	}
	size := s.SessionPoolSize
	if size <= 0 {
		size = DefaultSessionPoolSize
	}
	// Build the PIN source up front (this validates static config and constructs any
	// backend client, but performs no I/O). The inline Pin is intentionally left out
	// of cfg: it is resolved through pinSource at login time instead.
	pinSource, err := newPinSource(s.PinSource, s.Pin)
	if err != nil {
		return nil, err
	}
	return &PKCS11Provider{
		poolSize:  size,
		pinSource: pinSource,
		cfg: pki.PKCS11Config{
			ModulePath:        s.ModulePath,
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
func (p *PKCS11Provider) getPool(ctx context.Context) (*pki.SessionPool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pool != nil {
		return p.pool, nil
	}
	// Resolve the PIN lazily, here at first login, so an unreachable credential
	// source fails the operation closed (with a clear error) rather than at process
	// start, and so the PIN is fetched only when the HSM is actually used. The
	// resolved value lives only on this local cfg copy for the login round-trip.
	cfg := p.cfg
	if p.pinSource != nil {
		pin, err := p.pinSource.Resolve(ctx)
		if err != nil {
			return nil, fmt.Errorf("keyprovider: resolving HSM PIN from %s: %w", p.pinSource.Describe(), err)
		}
		cfg.Pin = pin
	}
	pool, err := pki.NewSessionPool(cfg, p.poolSize)
	if err != nil {
		return nil, err
	}
	p.pool = pool
	return pool, nil
}

// tokenIdentity returns the token's actual identity (label/serial/model/
// manufacturer/slot-id) if the session pool has already been built. It returns
// ok=false when the pool is not yet built — the pool is lazy and this must not
// force a login just to answer a token-match query. The HA layer uses it to pin
// an operation to a specific token by RFC 7512 serial/slot-id addressing.
func (p *PKCS11Provider) tokenIdentity() (pki.TokenIdentity, bool) {
	p.mu.Lock()
	pool := p.pool
	p.mu.Unlock()
	if pool == nil {
		return pki.TokenIdentity{}, false
	}
	return pool.Identity(), true
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
	if err := fips.CheckKeyType(keyType); err != nil {
		return nil, fmt.Errorf("keyprovider: %w", err)
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
	loc, err := locatorFor(ref)
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	rk, err := pool.Resolve(ctx, loc)
	if err != nil {
		return nil, wrapNotFound(loc.Describe(), err)
	}
	keyType, err := keyTypeOf(rk.Public)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %s: %w", loc.Describe(), err)
	}
	sshPub, err := ssh.NewPublicKey(rk.Public)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %s: %w", loc.Describe(), err)
	}

	return &KeyInfo{
		Label:        rk.Label,
		ID:           hex.EncodeToString(rk.ID),
		KeyType:      keyType,
		PublicKey:    rk.Public,
		URI:          p.buildKeyURI(rk.Label, rk.ID),
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
	loc, err := locatorFor(ref)
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	rk, err := pool.Resolve(ctx, loc)
	if err != nil {
		return nil, wrapNotFound(loc.Describe(), err)
	}
	keyType, err := keyTypeOf(rk.Public)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: key %s: %w", loc.Describe(), err)
	}
	return &pkcs11Signer{pool: pool, ctx: ctx, loc: loc, pub: rk.Public, keyType: keyType}, nil
}

// signOp performs a signing operation for the located key on this token's session
// pool. It is the per-token signing core the HA provider (PKCS11HAProvider)
// composes with failover; the public pooled Signer path reaches the same
// pool.Sign, so single-token and multi-token deployments sign identically.
func (p *PKCS11Provider) signOp(ctx context.Context, loc pki.KeyLocator, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	return pool.Sign(ctx, loc, digest, opts)
}

// decryptOp performs an on-device unwrap for the located KEK on this token's
// session pool. Like signOp it is the per-token core the HA provider composes
// with failover.
func (p *PKCS11Provider) decryptOp(ctx context.Context, loc pki.KeyLocator, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	return pool.Decrypt(ctx, loc, ciphertext, opts)
}

// buildKeyURI renders the RFC 7512 URI for a resolved key. A label-only key keeps
// the historical token;object;type ordering (BuildPKCS11URI); an id-bearing key
// additionally carries the id= object selector.
func (p *PKCS11Provider) buildKeyURI(label string, id []byte) string {
	if len(id) == 0 {
		return pki.BuildPKCS11URI(p.cfg, label)
	}
	u := &pki.PKCS11URI{
		Token:        p.cfg.TokenLabel,
		Serial:       p.cfg.TokenSerial,
		Manufacturer: p.cfg.TokenManufacturer,
		Object:       label,
		ID:           id,
		Type:         pki.PKCS11TypePrivate,
	}
	return u.String()
}

// locatorFor builds the pki key locator (CKA_LABEL and/or CKA_ID) for a KeyRef.
// The KeyRef's ID is a hex-encoded CKA_ID, decoded here to the raw bytes the
// token matches on. At least one of label / id must be present.
func locatorFor(ref KeyRef) (pki.KeyLocator, error) {
	loc := pki.KeyLocator{Label: ref.Label}
	if ref.ID != "" {
		raw, err := hex.DecodeString(ref.ID)
		if err != nil {
			return pki.KeyLocator{}, fmt.Errorf("keyprovider: invalid CKA_ID %q (want hex): %w", ref.ID, err)
		}
		loc.ID = raw
	}
	if loc.IsZero() {
		return pki.KeyLocator{}, fmt.Errorf("keyprovider: key reference has neither label nor CKA_ID")
	}
	return loc, nil
}

// applyPKCS11URI backfills any module/token/PIN field of s left unset from its
// self-describing RFC 7512 URI (s.URI). Explicit fields always take precedence;
// the URI only fills gaps. It performs no I/O.
func applyPKCS11URI(s PKCS11Settings) (PKCS11Settings, error) {
	if strings.TrimSpace(s.URI) == "" {
		return s, nil
	}
	u, err := pki.ParsePKCS11URI(s.URI)
	if err != nil {
		return s, fmt.Errorf("keyprovider: parsing pkcs11 uri: %w", err)
	}
	if s.ModulePath == "" {
		s.ModulePath = u.ModulePath
	}
	if s.TokenLabel == "" {
		s.TokenLabel = u.Token
	}
	if s.TokenSerial == "" {
		s.TokenSerial = u.Serial
	}
	if s.TokenManufacturer == "" {
		s.TokenManufacturer = u.Manufacturer
	}
	// Derive the PIN from the URI only when nothing else configures it, so an
	// explicit pin / pin_source always wins.
	if s.PinSource.Type == "" && s.Pin == "" {
		ps, inline, ok, perr := PinSourceFromURI(u)
		if perr != nil {
			return s, perr
		}
		if ok {
			s.PinSource = ps
			s.Pin = inline
		}
	}
	return s, nil
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
	loc     pki.KeyLocator
	pub     crypto.PublicKey
	keyType string
	closed  bool
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.pub }

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.closed {
		return nil, fmt.Errorf("keyprovider: signer is closed")
	}
	return s.pool.Sign(s.ctx, s.loc, digest, opts)
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
	loc, err := locatorFor(ref)
	if err != nil {
		return nil, err
	}
	pool, err := p.getPool(ctx)
	if err != nil {
		return nil, err
	}
	rk, err := pool.Resolve(ctx, loc)
	if err != nil {
		return nil, wrapNotFound(loc.Describe(), err)
	}
	if _, ok := rk.Public.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("keyprovider: key %s is not an RSA key and cannot be used for decryption", loc.Describe())
	}
	return &pkcs11Decrypter{pool: pool, ctx: ctx, loc: loc, pub: rk.Public}, nil
}

// pkcs11Decrypter is a keyprovider.Decrypter bound to a pooled session backend.
// Like pkcs11Signer it holds no session of its own; each Decrypt borrows one for
// the duration of the on-device unwrap. Close is an idempotent no-op.
type pkcs11Decrypter struct {
	pool   *pki.SessionPool
	ctx    context.Context
	loc    pki.KeyLocator
	pub    crypto.PublicKey
	closed bool
}

func (d *pkcs11Decrypter) Public() crypto.PublicKey { return d.pub }

func (d *pkcs11Decrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.closed {
		return nil, fmt.Errorf("keyprovider: decrypter is closed")
	}
	return d.pool.Decrypt(d.ctx, d.loc, ciphertext, opts)
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
