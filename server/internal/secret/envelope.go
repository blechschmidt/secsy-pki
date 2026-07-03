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
// # Format versions
//
// Version 1 bound the KEK label and wrap algorithm into the GCM
// additional-authenticated-data. That makes the wrap header immutable — and
// therefore makes KEK rotation impossible without re-encrypting the data.
//
// Version 2 (the format new envelopes are sealed in) instead binds a
// key-commitment — SHA-256 over the DEK under a fixed domain-separation tag —
// into the AAD, and leaves the wrap header (provider, KEK label/URI/version,
// wrap algorithm, wrapped DEK) outside it. A KEK rotation can then re-wrap the
// DEK under a new KEK by rewriting only the header: the nonce, ciphertext, and
// escrow block are untouched (see Ring.Rewrap in rotation.go). The commitment
// is at least as strong a binding as v1's label: substituting a different KEK
// or wrapped DEK yields a different DEK, which fails the commitment check
// before any data decryption is attempted, and forging a passing header
// requires knowing the DEK itself — a party that could already decrypt. The
// commitment also gives the scheme key-commitment, which plain AES-GCM lacks.
//
// A v1 envelope that has been re-wrapped is upgraded in place to version 2
// with an Origin block recording the immutable v1 AAD inputs (the original KEK
// label and wrap algorithm), so its unchanged GCM tag keeps verifying while
// the live wrap header points at the current KEK.
//
// # Security properties
//
//   - Confidentiality & integrity of the plaintext come from AES-256-GCM.
//   - The authenticated envelope header (format version, data algorithm, DEK
//     commitment — or, for v1 and upgraded-v1 envelopes, the original KEK label
//     and wrap algorithm — plus any caller context and the escrow block) is
//     bound into the GCM AAD. An attacker cannot swap algorithms, substitute
//     the wrapped key material, or replay a ciphertext under a different
//     context without the commitment check or GCM detecting it.
//   - Forward compatibility: the Version field is checked on decrypt; unknown
//     versions are rejected rather than silently mis-parsed.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

const (
	// FormatVersion1 is the legacy envelope format version, still accepted for
	// decryption. Its AAD binds the KEK label, so a v1 envelope cannot have its
	// wrap header rewritten in place; re-wrapping upgrades it to version 2 with
	// an Origin block (see the package comment).
	FormatVersion1 = 1
	// FormatVersion2 is the current envelope format version, sealed by Encrypt.
	// Its AAD binds a DEK commitment instead of the KEK label, making the wrap
	// header rewritable for KEK rotation.
	FormatVersion2 = 2

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
	// KEKVersion is the rotation version of the KEK the DEK is currently
	// wrapped under (1 for a family's initial key). Version-2 envelopes only;
	// it is rewritten by Rewrap alongside the other wrap-header fields.
	KEKVersion int `json:"kek_version,omitempty"`
	// WrapAlg is the DEK-wrapping algorithm (AlgRSAOAEPSHA256).
	WrapAlg string `json:"wrap_alg"`
	// DataAlg is the data-encryption algorithm (AlgAES256GCM).
	DataAlg string `json:"data_alg"`
	// WrappedDEK is the DEK encrypted under the KEK.
	WrappedDEK []byte `json:"wrapped_dek"`
	// DEKCommit is a SHA-256 key-commitment to the DEK (see dekCommitment). On a
	// natively sealed version-2 envelope it is bound into the GCM AAD and is the
	// authenticated replacement for v1's KEK-label binding; on an upgraded-v1
	// envelope it is advisory (the v1 AAD cannot be extended) and the GCM tag
	// remains the authoritative check. It is always verified after unwrap when
	// present, so a wrong or substituted KEK fails closed before any data
	// decryption is attempted.
	DEKCommit []byte `json:"dek_commit,omitempty"`
	// Origin, present only on a v1 envelope that was upgraded by a KEK re-wrap,
	// freezes the immutable v1 AAD inputs (the KEK label and wrap algorithm the
	// envelope was originally sealed under) so the unchanged GCM tag keeps
	// verifying. Tampering with these fields alters the reconstructed AAD and is
	// caught by GCM. They never change again, even across further re-wraps.
	Origin *OriginBinding `json:"origin,omitempty"`
	// Nonce is the AES-GCM nonce.
	Nonce []byte `json:"nonce"`
	// Ciphertext is the AES-GCM output (ciphertext followed by the auth tag).
	Ciphertext []byte `json:"ciphertext"`
	// ContextBound is true when a caller-supplied encryption context was mixed
	// into the AAD at encryption time and must be supplied again to decrypt.
	// The context itself is deliberately not stored.
	ContextBound bool `json:"context_bound,omitempty"`
	// Escrow, when present, carries an M-of-N key-escrow block: the DEK split
	// across recovery-agent-wrapped Shamir shares, so a quorum of recovery agents
	// can reconstruct it under dual control (see escrow.go). It is bound into the
	// GCM AAD so it cannot be tampered with or substituted. It is optional;
	// envelopes without escrow are unaffected.
	Escrow *EscrowBlock `json:"escrow,omitempty"`
}

// OriginBinding carries the immutable AAD inputs of a v1 envelope that was
// upgraded to v2 by a KEK re-wrap: the KEK label and wrap algorithm it was
// originally sealed under. See Envelope.Origin.
type OriginBinding struct {
	KEKLabel string `json:"kek_label"`
	WrapAlg  string `json:"wrap_alg"`
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
	// Version is the KEK's rotation version (1 for a family's initial key),
	// recorded in the envelope header of newly sealed ciphertext.
	Version() int
}

// dekCommitTag domain-separates the DEK commitment from any other use of
// SHA-256 over key material.
const dekCommitTag = "secsy-dek-commit-v1\x00"

// dekCommitment returns the key-commitment bound into a v2 envelope's AAD:
// SHA-256 over a fixed domain-separation tag and the DEK. Publishing it is
// safe — the DEK is 256 bits of fresh randomness, so the preimage cannot be
// searched — and it lets decrypt verify that an unwrap produced the DEK this
// envelope was sealed with before the DEK is used.
func dekCommitment(dek []byte) []byte {
	h := sha256.New()
	h.Write([]byte(dekCommitTag))
	h.Write(dek)
	return h.Sum(nil)
}

// seal performs the envelope encryption given a wrapper. context is optional
// additional-authenticated-data supplied by the caller (an "encryption
// context"); when non-empty it must be supplied identically to open. escrow is
// an optional M-of-N key-escrow policy; when non-nil the DEK is additionally
// split across recovery-agent-wrapped Shamir shares and the resulting escrow
// block is bound into the AAD.
func seal(w wrapper, plaintext, context []byte, escrow *EscrowPolicy) (*Envelope, error) {
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
		Version:      FormatVersion2,
		Provider:     w.ProviderName(),
		KEKLabel:     w.Label(),
		KEKURI:       w.URI(),
		KEKVersion:   w.Version(),
		WrapAlg:      wrapAlg,
		DataAlg:      AlgAES256GCM,
		WrappedDEK:   wrapped,
		DEKCommit:    dekCommitment(dek),
		Nonce:        nonce,
		ContextBound: len(context) > 0,
	}

	// Produce the escrow block (if configured) from the same DEK before sealing,
	// so it is finalized and can be bound into the authenticated data.
	if escrow != nil {
		escrowBlock, err := escrow.sealEscrow(dek)
		if err != nil {
			return nil, err
		}
		env.Escrow = escrowBlock
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
		// A FIPS-policy rejection is decided from the envelope header before any
		// decryption is attempted, so surfacing it leaks no padding details —
		// and the operator needs its remediation text (re-wrap before enabling
		// security.fips).
		if errors.Is(err, fips.ErrNotApproved) {
			return nil, err
		}
		// Deliberately generic: unwrap failures must not leak padding details.
		return nil, fmt.Errorf("secret: unwrapping data key failed")
	}
	defer zero(dek)
	return openWithDEK(env, dek, context)
}

// openWithDEK performs the AES-GCM decryption of an envelope given an
// already-recovered DEK. It is shared by the normal KEK-unwrap path (open) and
// the escrow-recovery path (RecoveryService.Recover), so both enforce the same
// DEK-length, commitment, nonce, and AAD checks. The DEK is the caller's to
// zeroize.
func openWithDEK(env *Envelope, dek, context []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, fmt.Errorf("secret: data key has wrong length")
	}
	// Verify the key-commitment before the DEK touches any cipher state: a
	// wrong or substituted KEK (or a mis-reconstructed escrow quorum) fails
	// closed here. The error is as generic as a GCM failure so the two are
	// indistinguishable to a caller probing the endpoint.
	if len(env.DEKCommit) > 0 && !subtleEqual(dekCommitment(dek), env.DEKCommit) {
		return nil, fmt.Errorf("secret: decryption failed (wrong key/context or corrupted ciphertext)")
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
// and carries the required fields — including the per-version shape rules —
// before any cryptographic work is attempted.
func (e *Envelope) validate() error {
	switch e.Version {
	case FormatVersion1:
		// The legacy shape: none of the v2 fields may appear on a v1 envelope.
		if e.KEKVersion != 0 || len(e.DEKCommit) != 0 || e.Origin != nil {
			return fmt.Errorf("secret: version-1 envelope carries version-2 fields")
		}
	case FormatVersion2:
		if e.KEKVersion < 1 {
			return fmt.Errorf("secret: version-2 envelope is missing kek_version")
		}
		if e.Origin == nil {
			// Natively sealed v2: the commitment is mandatory (it is the
			// authenticated binding that replaced the v1 KEK-label binding).
			if len(e.DEKCommit) != sha256.Size {
				return fmt.Errorf("secret: version-2 envelope has a missing or malformed dek_commit")
			}
		} else {
			// Upgraded from v1 by a re-wrap: the origin block must reconstruct a
			// valid v1 AAD; the commitment is optional but well-formed if present.
			if e.Origin.KEKLabel == "" {
				return fmt.Errorf("secret: upgraded envelope is missing origin kek_label")
			}
			if !supportedWrapAlgs[e.Origin.WrapAlg] {
				return fmt.Errorf("secret: upgraded envelope has unsupported origin wrap algorithm %q", e.Origin.WrapAlg)
			}
			if len(e.DEKCommit) != 0 && len(e.DEKCommit) != sha256.Size {
				return fmt.Errorf("secret: upgraded envelope has a malformed dek_commit")
			}
		}
	default:
		return fmt.Errorf("secret: unsupported envelope version %d (this build supports %d and %d)",
			e.Version, FormatVersion1, FormatVersion2)
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
	if e.Escrow != nil {
		if err := e.Escrow.validate(); err != nil {
			return err
		}
	}
	return nil
}

// aad builds the deterministic additional-authenticated-data bound into the GCM
// tag. The encoding is length-prefixed to be unambiguous (no field can be
// confused with an adjacent one), and the format version leads, so the v1 and
// v2 shapes are domain-separated from the first bytes.
//
// The v1 shape commits to the wrap algorithm and KEK label; because the AAD is
// frozen at seal time, an upgraded-v1 envelope (Origin != nil) reconstructs
// exactly those original bytes from its Origin block regardless of what the
// live wrap header now says. The v2 shape commits to the DEK commitment
// instead, which is what makes the wrap header rewritable for KEK rotation
// (see the package comment for why this binding is equivalent).
func (e *Envelope) aad(context []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("secsy-envelope\x00")
	writeLP := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf.Write(n[:])
		buf.Write(b)
	}
	writeVer := func(v uint32) {
		var ver [4]byte
		binary.BigEndian.PutUint32(ver[:], v)
		buf.Write(ver[:])
	}
	switch {
	case e.Version == FormatVersion1 || e.Origin != nil:
		// The v1 AAD — either a live v1 envelope (fields in the header) or an
		// upgraded one (fields frozen in the Origin block).
		wrapAlg, kekLabel := e.WrapAlg, e.KEKLabel
		if e.Origin != nil {
			wrapAlg, kekLabel = e.Origin.WrapAlg, e.Origin.KEKLabel
		}
		writeVer(FormatVersion1)
		writeLP([]byte(wrapAlg))
		writeLP([]byte(e.DataAlg))
		writeLP([]byte(kekLabel))
		writeLP(context)
	default:
		writeVer(FormatVersion2)
		writeLP([]byte(e.DataAlg))
		writeLP(e.DEKCommit)
		writeLP(context)
	}
	// Bind the escrow block (if any) so recovery agents and shares cannot be
	// tampered with, substituted, or stripped without invalidating the GCM tag.
	// Envelopes without escrow append nothing, so the AAD of pre-escrow
	// ciphertext is byte-for-byte unchanged and remains decryptable.
	if e.Escrow != nil {
		writeLP(e.Escrow.digest())
	}
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
