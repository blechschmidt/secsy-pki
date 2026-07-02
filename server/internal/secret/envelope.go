// Package secret implements HSM-backed envelope encryption for passwords and
// other small secrets.
//
// The scheme follows the standard envelope pattern used by cloud KMS systems:
//
//   - A fresh 256-bit data-encryption key (DEK) is generated per message.
//   - The plaintext is sealed with AES-256-GCM under the DEK.
//   - The DEK is wrapped (encrypted) with a key-encryption key (KEK) whose
//     private half lives in an HSM (via PKCS#11) or the software keystore. The
//     KEK is an RSA key; wrapping uses RSA-OAEP-SHA256 against the exported
//     public key and can be done with no HSM present. Unwrapping asks the token
//     to RSA-OAEP decrypt the wrapped DEK — the KEK private key never leaves the
//     device.
//
// The resulting Envelope carries everything needed to decrypt except the KEK
// private key (held by the HSM) and any caller-supplied encryption context. It
// is serialized as a self-describing, versioned JSON document so the format can
// evolve without ambiguity.
//
// # Security properties
//
//   - Confidentiality & integrity of the plaintext come from AES-256-GCM.
//   - The envelope header (version, algorithms, KEK label, and any caller
//     context) is bound into the GCM additional-authenticated-data (AAD). An
//     attacker cannot swap algorithms, point the record at a different KEK, or
//     replay a ciphertext under a different context without GCM detecting it.
//   - Forward compatibility: the Version field is checked on decrypt; unknown
//     versions are rejected rather than silently mis-parsed.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	// FormatVersion1 is the current envelope format version.
	FormatVersion1 = 1

	// AlgAES256GCM is the only supported data-encryption algorithm.
	AlgAES256GCM = "AES-256-GCM"
	// AlgRSAOAEPSHA256 is the preferred DEK-wrapping algorithm, used by
	// production HSMs and the software backend.
	AlgRSAOAEPSHA256 = "RSA-OAEP-SHA256"
	// AlgRSAOAEPSHA1 is the fallback DEK-wrapping algorithm for tokens that
	// support only SHA-1 for RSA-OAEP (notably SoftHSM). OAEP's security does
	// not rely on the collision resistance of its hash, so SHA-1 here does not
	// expose the scheme to SHA-1 collision attacks; SHA-256 is still preferred.
	AlgRSAOAEPSHA1 = "RSA-OAEP-SHA1"

	dekSize   = 32 // AES-256
	nonceSize = 12 // AES-GCM standard nonce
)

// supportedWrapAlgs is the set of DEK-wrapping algorithms this build accepts.
var supportedWrapAlgs = map[string]bool{
	AlgRSAOAEPSHA256: true,
	AlgRSAOAEPSHA1:   true,
}

// Envelope is the versioned, self-describing ciphertext container. It is safe to
// store or transmit; it reveals only metadata (algorithms and the KEK label),
// never plaintext or key material. []byte fields are base64-encoded by
// encoding/json.
type Envelope struct {
	// Version is the format version (currently FormatVersion1).
	Version int `json:"version"`
	// Provider records which backend holds the KEK ("pkcs11" or "software"),
	// for operator diagnostics. It is informational and bound into the AAD.
	Provider string `json:"provider,omitempty"`
	// KEKLabel is the label of the key-encryption key needed to unwrap the DEK.
	KEKLabel string `json:"kek_label"`
	// KEKURI is a stable reference to the KEK (a pkcs11: or software: URI).
	KEKURI string `json:"kek_uri,omitempty"`
	// WrapAlg is the DEK-wrapping algorithm (AlgRSAOAEPSHA256).
	WrapAlg string `json:"wrap_alg"`
	// DataAlg is the data-encryption algorithm (AlgAES256GCM).
	DataAlg string `json:"data_alg"`
	// WrappedDEK is the DEK encrypted under the KEK.
	WrappedDEK []byte `json:"wrapped_dek"`
	// Nonce is the AES-GCM nonce.
	Nonce []byte `json:"nonce"`
	// Ciphertext is the AES-GCM output (ciphertext followed by the auth tag).
	Ciphertext []byte `json:"ciphertext"`
	// ContextBound is true when a caller-supplied encryption context was mixed
	// into the AAD at encryption time and must be supplied again to decrypt.
	// The context itself is deliberately not stored.
	ContextBound bool `json:"context_bound,omitempty"`
}

// wrapper is the minimal DEK wrap/unwrap capability the envelope layer needs.
// It is satisfied by the KEK types in kek.go. Defining it here keeps
// envelope.go free of any keyprovider dependency and trivially testable.
type wrapper interface {
	// Wrap encrypts a DEK under the KEK, returning the wrapped bytes and the
	// wrapping algorithm identifier actually used (which is recorded in the
	// envelope so Unwrap can select the matching parameters).
	Wrap(dek []byte) (wrapped []byte, alg string, err error)
	// Unwrap decrypts a wrapped DEK under the KEK using the given algorithm
	// (read back from the envelope).
	Unwrap(wrapped []byte, alg string) ([]byte, error)
	// Label, URI and ProviderName describe the KEK for the envelope header.
	Label() string
	URI() string
	ProviderName() string
}

// seal performs the envelope encryption given a wrapper. context is optional
// additional-authenticated-data supplied by the caller (an "encryption
// context"); when non-empty it must be supplied identically to open.
func seal(w wrapper, plaintext, context []byte) (*Envelope, error) {
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("secret: generating data key: %w", err)
	}
	defer zero(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("secret: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: init GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secret: generating nonce: %w", err)
	}

	// Wrap the DEK first so the actual wrapping algorithm is known before it is
	// bound into the AAD — the algorithm identifier is authenticated, so it must
	// be finalized before the GCM seal.
	wrapped, wrapAlg, err := w.Wrap(dek)
	if err != nil {
		return nil, fmt.Errorf("secret: wrapping data key: %w", err)
	}
	if !supportedWrapAlgs[wrapAlg] {
		return nil, fmt.Errorf("secret: wrapper produced unsupported algorithm %q", wrapAlg)
	}

	env := &Envelope{
		Version:      FormatVersion1,
		Provider:     w.ProviderName(),
		KEKLabel:     w.Label(),
		KEKURI:       w.URI(),
		WrapAlg:      wrapAlg,
		DataAlg:      AlgAES256GCM,
		WrappedDEK:   wrapped,
		Nonce:        nonce,
		ContextBound: len(context) > 0,
	}

	aad := env.aad(context)
	env.Ciphertext = gcm.Seal(nil, nonce, plaintext, aad)

	return env, nil
}

// open reverses seal. context must match what was supplied at encryption time.
func open(w wrapper, env *Envelope, context []byte) ([]byte, error) {
	if err := env.validate(); err != nil {
		return nil, err
	}
	if env.ContextBound && len(context) == 0 {
		return nil, fmt.Errorf("secret: this ciphertext requires an encryption context to decrypt")
	}
	if !env.ContextBound && len(context) > 0 {
		return nil, fmt.Errorf("secret: an encryption context was supplied but this ciphertext was not bound to one")
	}

	dek, err := w.Unwrap(env.WrappedDEK, env.WrapAlg)
	if err != nil {
		// Deliberately generic: unwrap failures must not leak padding details.
		return nil, fmt.Errorf("secret: unwrapping data key failed")
	}
	defer zero(dek)
	if len(dek) != dekSize {
		return nil, fmt.Errorf("secret: unwrapped data key has wrong length")
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("secret: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: init GCM: %w", err)
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("secret: invalid nonce length")
	}

	aad := env.aad(context)
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		// A GCM failure means tampering, a wrong KEK, or a wrong context.
		return nil, fmt.Errorf("secret: decryption failed (wrong key/context or corrupted ciphertext)")
	}
	return plaintext, nil
}

// validate checks that an envelope declares a supported version and algorithms
// and carries the required fields, before any cryptographic work is attempted.
func (e *Envelope) validate() error {
	if e.Version != FormatVersion1 {
		return fmt.Errorf("secret: unsupported envelope version %d (this build supports %d)", e.Version, FormatVersion1)
	}
	if !supportedWrapAlgs[e.WrapAlg] {
		return fmt.Errorf("secret: unsupported wrap algorithm %q", e.WrapAlg)
	}
	if e.DataAlg != AlgAES256GCM {
		return fmt.Errorf("secret: unsupported data algorithm %q", e.DataAlg)
	}
	if e.KEKLabel == "" {
		return fmt.Errorf("secret: envelope is missing kek_label")
	}
	if len(e.WrappedDEK) == 0 || len(e.Nonce) == 0 || len(e.Ciphertext) == 0 {
		return fmt.Errorf("secret: envelope is missing ciphertext material")
	}
	return nil
}

// aad builds the deterministic additional-authenticated-data bound into the GCM
// tag. It commits to the format version, both algorithm identifiers, the KEK
// label, and any caller-supplied context, so none of these can be altered
// without invalidating the tag. The encoding is length-prefixed to be
// unambiguous (no field can be confused with an adjacent one).
func (e *Envelope) aad(context []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("secsy-envelope\x00")
	writeLP := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf.Write(n[:])
		buf.Write(b)
	}
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], uint32(e.Version))
	buf.Write(ver[:])
	writeLP([]byte(e.WrapAlg))
	writeLP([]byte(e.DataAlg))
	writeLP([]byte(e.KEKLabel))
	writeLP(context)
	return buf.Bytes()
}

// Marshal serializes the envelope to indented JSON suitable for storage or
// transport.
func (e *Envelope) Marshal() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(e, "", "  ")
}

// Unmarshal parses an envelope from its JSON representation, rejecting unknown
// fields and unsupported versions/algorithms.
func Unmarshal(data []byte) (*Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("secret: parsing envelope: %w", err)
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// zero overwrites a byte slice, used to scrub key material from memory as soon
// as it is no longer needed. It is best-effort (Go may still copy the backing
// array elsewhere) but removes the obvious lingering copy.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
