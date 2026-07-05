package secret

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// rsaOAEPWrapper wraps and unwraps data-encryption keys using an RSA
// key-encryption key held by a keyprovider. Wrapping uses the exported public
// key (no HSM round-trip); unwrapping is delegated to the provider's Decrypter,
// which for the PKCS#11 backend runs on the token so the KEK private key never
// leaves the HSM.
//
// wrapAlg is the algorithm chosen for new ciphertext, negotiated once against
// the token's capabilities: SHA-256 is preferred, but SoftHSM supports only
// SHA-1 for RSA-OAEP, so the wrapper falls back to SHA-1 when the token rejects
// SHA-256. The chosen algorithm is recorded in each envelope; Unwrap honors the
// algorithm read back from the envelope rather than assuming wrapAlg, so old
// ciphertext remains decryptable across changes.
type rsaOAEPWrapper struct {
	provider keyprovider.Provider
	ref      keyprovider.KeyRef
	pub      *rsa.PublicKey
	label    string
	uri      string
	wrapAlg  string
	// version is the KEK's rotation version within its family (1 for the
	// initial key), stamped into the header of newly sealed envelopes.
	version int
}

func (w *rsaOAEPWrapper) Label() string        { return w.label }
func (w *rsaOAEPWrapper) URI() string          { return w.uri }
func (w *rsaOAEPWrapper) ProviderName() string { return w.provider.Name() }
func (w *rsaOAEPWrapper) Version() int         { return w.version }

// algHash maps a wrapping-algorithm identifier to its OAEP hash. Under the
// FIPS policy the SHA-1 algorithm is refused even for decryption of existing
// envelopes: fail closed, and tell the operator how to migrate (rotate the KEK
// to a SHA-256-capable provider and re-wrap, Task 63) rather than silently
// keep exercising SHA-1.
func algHash(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRSAOAEPSHA256:
		return crypto.SHA256, nil
	case AlgRSAOAEPSHA1:
		if fips.PolicyEnforced() {
			return 0, fmt.Errorf("secret: envelope wrap algorithm %s is %w; re-wrap existing envelopes under a SHA-256-capable KEK (secsy-secret rotate-kek/rewrap) before enabling security.fips", alg, fips.ErrNotApproved)
		}
		return crypto.SHA1, nil
	default:
		return 0, fmt.Errorf("secret: unsupported wrap algorithm %q", alg)
	}
}

// Wrap encrypts a DEK under the KEK public key using the negotiated algorithm.
func (w *rsaOAEPWrapper) Wrap(dek []byte) ([]byte, string, error) {
	h, err := algHash(w.wrapAlg)
	if err != nil {
		return nil, "", err
	}
	wrapped, err := rsa.EncryptOAEP(h.New(), rand.Reader, w.pub, dek, nil)
	if err != nil {
		return nil, "", err
	}
	return wrapped, w.wrapAlg, nil
}

// Unwrap decrypts a wrapped DEK via the provider's Decrypter (on-HSM for
// PKCS#11), using the OAEP hash named by alg (from the envelope). A fresh
// Decrypter is opened and closed per call to keep the token session
// short-lived, matching the rest of the codebase.
func (w *rsaOAEPWrapper) Unwrap(wrapped []byte, alg string) ([]byte, error) {
	h, err := algHash(alg)
	if err != nil {
		return nil, err
	}
	dp, ok := w.provider.(keyprovider.DecrypterProvider)
	if !ok {
		return nil, fmt.Errorf("secret: key provider %q does not support decryption", w.provider.Name())
	}
	dec, err := dp.Decrypter(context.Background(), w.ref)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: h})
}

// negotiateWrapAlg determines the strongest RSA-OAEP hash the KEK's provider
// can actually unwrap with, by performing a wrap/unwrap self-test with a random
// probe value. SHA-256 is tried first, then SHA-1 (for SoftHSM). This runs once
// per Service and adapts transparently to the backend without configuration.
//
// Under the FIPS policy (security.fips) the SHA-1 fallback is refused: a token
// that cannot unwrap with SHA-256 OAEP — SoftHSM 2.6.x notably — makes the
// Service constructor fail with an actionable error instead of silently
// downgrading. `secsy-ca doctor` runs this same negotiation and reports the
// failure as a fips.secret_oaep finding.
func negotiateWrapAlg(ctx context.Context, provider keyprovider.Provider, ref keyprovider.KeyRef, pub *rsa.PublicKey) (string, error) {
	dp, ok := provider.(keyprovider.DecrypterProvider)
	if !ok {
		return "", fmt.Errorf("secret: key provider %q does not support decryption", provider.Name())
	}
	probe := make([]byte, dekSize)
	if _, err := rand.Read(probe); err != nil {
		return "", err
	}
	candidates := []string{AlgRSAOAEPSHA256, AlgRSAOAEPSHA1}
	if fips.PolicyEnforced() {
		candidates = candidates[:1]
	}
	var lastErr error
	for _, alg := range candidates {
		h, _ := algHash(alg)
		wrapped, err := rsa.EncryptOAEP(h.New(), rand.Reader, pub, probe, nil)
		if err != nil {
			lastErr = err
			continue
		}
		dec, err := dp.Decrypter(ctx, ref)
		if err != nil {
			return "", err
		}
		out, err := dec.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: h})
		dec.Close()
		if err == nil && subtleEqual(out, probe) {
			return alg, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no supported OAEP hash")
	}
	if fips.PolicyEnforced() {
		return "", fmt.Errorf("secret: KEK %q cannot RSA-OAEP unwrap with SHA-256, and security.fips refuses the SHA-1 fallback (SoftHSM supports only SHA-1 OAEP — use an HSM/provider with SHA-256 OAEP for FIPS deployments): %w", ref.Label, lastErr)
	}
	return "", fmt.Errorf("secret: KEK %q cannot RSA-OAEP unwrap with SHA-256 or SHA-1: %w", ref.Label, lastErr)
}

// subtleEqual reports whether two byte slices are equal in constant time.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Service performs envelope encryption and decryption against a single KEK. It
// is safe for concurrent use: each operation opens its own provider resources.
type Service struct {
	wrapper *rsaOAEPWrapper
}

// NewService binds a Service to the KEK identified by kekRef within the given
// key provider. The KEK must already exist (see ProvisionKEK) and be an RSA
// key; NewService fails otherwise. The KEK is treated as rotation version 1 of
// its family; rotation-aware callers use NewVersionedService (via LoadRing).
func NewService(ctx context.Context, provider keyprovider.Provider, kekRef keyprovider.KeyRef) (*Service, error) {
	return NewVersionedService(ctx, provider, kekRef, 1)
}

// NewVersionedService is NewService for a KEK that is a specific rotation
// version of its family; the version is stamped into the header of every
// envelope the Service seals.
func NewVersionedService(ctx context.Context, provider keyprovider.Provider, kekRef keyprovider.KeyRef, version int) (*Service, error) {
	svc, pub, err := newServiceCommon(ctx, provider, kekRef, version)
	if err != nil {
		return nil, err
	}
	wrapAlg, err := negotiateWrapAlg(ctx, provider, svc.wrapper.ref, pub)
	if err != nil {
		return nil, err
	}
	svc.wrapper.wrapAlg = wrapAlg
	return svc, nil
}

// newDecryptOnlyService binds a Service that can only open envelopes (used by
// the Ring for previous KEK versions during a rotation window). It skips the
// wrap-algorithm negotiation — two HSM round-trips that only matter for
// sealing new ciphertext, since Unwrap always honors the algorithm recorded in
// the envelope being opened.
func newDecryptOnlyService(ctx context.Context, provider keyprovider.Provider, kekRef keyprovider.KeyRef, version int) (*Service, error) {
	svc, _, err := newServiceCommon(ctx, provider, kekRef, version)
	return svc, err
}

// newServiceCommon locates and vets the KEK and assembles the Service, leaving
// the wrap algorithm to the caller.
func newServiceCommon(ctx context.Context, provider keyprovider.Provider, kekRef keyprovider.KeyRef, version int) (*Service, *rsa.PublicKey, error) {
	if provider == nil {
		return nil, nil, fmt.Errorf("secret: nil key provider")
	}
	if _, ok := provider.(keyprovider.DecrypterProvider); !ok {
		return nil, nil, fmt.Errorf("secret: key provider %q cannot decrypt (no KEK support)", provider.Name())
	}
	if version < 1 {
		return nil, nil, fmt.Errorf("secret: KEK version must be at least 1 (got %d)", version)
	}
	info, err := provider.FindKey(ctx, kekRef)
	if err != nil {
		return nil, nil, fmt.Errorf("secret: locating KEK: %w", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("secret: KEK %q is not an RSA key (type %T); a KEK must be RSA", info.Label, info.PublicKey)
	}
	if pub.N.BitLen() < 2048 {
		return nil, nil, fmt.Errorf("secret: KEK %q is too small (%d bits); minimum is 2048", info.Label, pub.N.BitLen())
	}
	return &Service{wrapper: &rsaOAEPWrapper{
		provider: provider,
		ref:      kekRef,
		pub:      pub,
		label:    info.Label,
		uri:      info.URI,
		version:  version,
	}}, pub, nil
}

// Encrypt seals plaintext into a versioned Envelope. context is an optional
// encryption context bound into the authenticated data; if supplied, the same
// context must be given to Decrypt. It is not stored in the envelope.
func (s *Service) Encrypt(plaintext, context []byte) (*Envelope, error) {
	return seal(s.wrapper, plaintext, context, nil, nil)
}

// EncryptWithEscrow is Encrypt with an additional M-of-N key-escrow policy: the
// DEK is Shamir-split across the policy's recovery agents so a quorum can
// recover the plaintext under dual control if the original requester loses
// access. A nil policy is equivalent to Encrypt.
func (s *Service) EncryptWithEscrow(plaintext, context []byte, escrow *EscrowPolicy) (*Envelope, error) {
	return seal(s.wrapper, plaintext, context, escrow, nil)
}

// EncryptToJSON is Encrypt followed by Marshal, returning the serialized
// envelope ready for storage or transport.
func (s *Service) EncryptToJSON(plaintext, context []byte) ([]byte, error) {
	env, err := s.Encrypt(plaintext, context)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// EncryptWithEscrowToJSON is EncryptWithEscrow followed by Marshal.
func (s *Service) EncryptWithEscrowToJSON(plaintext, context []byte, escrow *EscrowPolicy) ([]byte, error) {
	env, err := s.EncryptWithEscrow(plaintext, context, escrow)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Decrypt recovers the plaintext from an Envelope. context must match what was
// supplied to Encrypt.
func (s *Service) Decrypt(env *Envelope, context []byte) ([]byte, error) {
	return open(s.wrapper, env, context, nil)
}

// DecryptJSON parses a serialized envelope and decrypts it.
func (s *Service) DecryptJSON(data, context []byte) ([]byte, error) {
	env, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	return s.Decrypt(env, context)
}

// KEKInfo describes the KEK a Service is bound to.
type KEKInfo struct {
	Label    string
	URI      string
	Provider string
	KeyBits  int
	WrapAlg  string
	// Version is the KEK's rotation version within its family (1 for the
	// initial key).
	Version int
}

// KEKInfo returns metadata about the bound KEK.
func (s *Service) KEKInfo() KEKInfo {
	return KEKInfo{
		Label:    s.wrapper.label,
		URI:      s.wrapper.uri,
		Provider: s.wrapper.ProviderName(),
		KeyBits:  s.wrapper.pub.N.BitLen(),
		WrapAlg:  s.wrapper.wrapAlg,
		Version:  s.wrapper.version,
	}
}

// ProvisionKEK generates a new RSA key-encryption key on the given provider
// under label, if one does not already exist. keyType must be an RSA type
// ("rsa-2048" or "rsa-4096"; empty defaults to rsa-4096). It returns a Service
// bound to the freshly created KEK. If a key with the label already exists,
// ProvisionKEK returns an error — rotating a KEK is a deliberate,
// separately-managed operation, since re-generating over an in-use KEK would
// render all existing ciphertext undecryptable.
func ProvisionKEK(ctx context.Context, provider keyprovider.Provider, label, keyType string) (*Service, error) {
	if label == "" {
		return nil, fmt.Errorf("secret: KEK label is required")
	}
	if keyType == "" {
		keyType = keyprovider.KeyTypeRSA4096
	}
	if _, err := provider.GenerateKey(ctx, keyprovider.KeySpec{
		Label:   label,
		KeyType: keyType,
		Usage:   keyprovider.KeyUsageDecrypt,
	}); err != nil {
		return nil, fmt.Errorf("secret: generating KEK: %w", err)
	}
	return NewService(ctx, provider, keyprovider.KeyRef{Label: label})
}
