package secret

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

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
}

func (w *rsaOAEPWrapper) Label() string        { return w.label }
func (w *rsaOAEPWrapper) URI() string          { return w.uri }
func (w *rsaOAEPWrapper) ProviderName() string { return w.provider.Name() }

// algHash maps a wrapping-algorithm identifier to its OAEP hash.
func algHash(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRSAOAEPSHA256:
		return crypto.SHA256, nil
	case AlgRSAOAEPSHA1:
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
func negotiateWrapAlg(ctx context.Context, provider keyprovider.Provider, ref keyprovider.KeyRef, pub *rsa.PublicKey) (string, error) {
	dp, ok := provider.(keyprovider.DecrypterProvider)
	if !ok {
		return "", fmt.Errorf("secret: key provider %q does not support decryption", provider.Name())
	}
	probe := make([]byte, dekSize)
	if _, err := rand.Read(probe); err != nil {
		return "", err
	}
	var lastErr error
	for _, alg := range []string{AlgRSAOAEPSHA256, AlgRSAOAEPSHA1} {
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
// key; NewService fails otherwise.
func NewService(ctx context.Context, provider keyprovider.Provider, kekRef keyprovider.KeyRef) (*Service, error) {
	if provider == nil {
		return nil, fmt.Errorf("secret: nil key provider")
	}
	if _, ok := provider.(keyprovider.DecrypterProvider); !ok {
		return nil, fmt.Errorf("secret: key provider %q cannot decrypt (no KEK support)", provider.Name())
	}
	info, err := provider.FindKey(ctx, kekRef)
	if err != nil {
		return nil, fmt.Errorf("secret: locating KEK: %w", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("secret: KEK %q is not an RSA key (type %T); a KEK must be RSA", info.Label, info.PublicKey)
	}
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("secret: KEK %q is too small (%d bits); minimum is 2048", info.Label, pub.N.BitLen())
	}
	wrapAlg, err := negotiateWrapAlg(ctx, provider, kekRef, pub)
	if err != nil {
		return nil, err
	}
	return &Service{wrapper: &rsaOAEPWrapper{
		provider: provider,
		ref:      kekRef,
		pub:      pub,
		label:    info.Label,
		uri:      info.URI,
		wrapAlg:  wrapAlg,
	}}, nil
}

// Encrypt seals plaintext into a versioned Envelope. context is an optional
// encryption context bound into the authenticated data; if supplied, the same
// context must be given to Decrypt. It is not stored in the envelope.
func (s *Service) Encrypt(plaintext, context []byte) (*Envelope, error) {
	return seal(s.wrapper, plaintext, context)
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

// Decrypt recovers the plaintext from an Envelope. context must match what was
// supplied to Encrypt.
func (s *Service) Decrypt(env *Envelope, context []byte) ([]byte, error) {
	return open(s.wrapper, env, context)
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
}

// KEKInfo returns metadata about the bound KEK.
func (s *Service) KEKInfo() KEKInfo {
	return KEKInfo{
		Label:    s.wrapper.label,
		URI:      s.wrapper.uri,
		Provider: s.wrapper.ProviderName(),
		KeyBits:  s.wrapper.pub.N.BitLen(),
		WrapAlg:  s.wrapper.wrapAlg,
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
