package secret

// Post-quantum hybrid KEK wrapping for the envelope layer (Task 137).
//
// A future adversary with a large quantum computer can record ciphertext today
// and decrypt it later once RSA is broken ("harvest now, decrypt later"). To
// resist that for data at rest, the hybrid mode protects each envelope's data
// key (DEK) with BOTH the existing classical HSM KEK wrap AND an ML-KEM-1024
// (FIPS 203) encapsulation, combined through a KDF so an attacker must defeat
// BOTH primitives:
//
//	ssC              = a fresh 256-bit classical shared secret
//	WrappedDEK (env) = RSA-OAEP(KEK_pub, ssC)                 // HSM unwraps ssC
//	(ssPQ, kemCT)    = ML-KEM-1024.Encapsulate(encapKey)      // KEM ciphertext in the PQC block
//	wk               = HKDF-SHA256(ssC || ssPQ, info)         // 256-bit wrapping key
//	PQC.WrappedDEK   = AES-256-GCM(wk, DEK)                   // the real DEK, sealed under wk
//
// Recovering the DEK needs ssC (only the HSM can unwrap it) AND ssPQ (only the
// ML-KEM decapsulation key can produce it). Breaking RSA alone yields ssC but
// not ssPQ; breaking ML-KEM alone yields ssPQ but not ssC. The KEM ciphertext
// and the AES-GCM-wrapped DEK sit in the harvested envelope, but the ML-KEM
// decapsulation key does not — it is stored once, sealed under the HSM KEK, in
// the key-management store, never copied into each ciphertext. So a quantum
// adversary who later breaks the RSA in a harvested envelope still faces
// ML-KEM-1024 to obtain ssPQ. That is the harvest-now-decrypt-later resistance.
//
// The ML-KEM decapsulation key itself is sealed under the classical HSM KEK
// (its 64-byte seed is RSA-OAEP-encrypted), so decapsulation requires the HSM:
// the HSM stays in the trust path and the non-extractability of the classical
// secret is preserved. Following the Task 29 (ML-DSA) precedent, the ML-KEM
// operations run in software (crypto/mlkem) — SoftHSM and PKCS#11 tokens have
// no ML-KEM mechanism — while the classical KEK may still live in the HSM.
//
// Threat-model boundary (stated honestly, not overclaimed): because the sealed
// decapsulation key is itself protected only by the classical KEK, the
// harvest-now-decrypt-later resistance holds for a harvest of the ENVELOPES.
// An adversary who ALSO exfiltrates the one sealed decapsulation-key blob from
// the key store and later breaks RSA can decapsulate, so against a full
// key-store compromise the guarantee degrades to classical. The win is real for
// the common case — ciphertext is typically stored and distributed far more
// widely than the central key store — and it is the necessary consequence of
// keeping a classical HSM in the trust path (no shipping HSM does ML-KEM). A
// deployment that must resist a full-store harvest should also restrict access
// to and separately protect the pqc_hybrid_keys material.
//
// ML-KEM-1024 is a FIPS 203 algorithm implemented by the Go standard library
// (crypto/mlkem), inside the Go Cryptographic Module's boundary — unlike the
// CIRCL-based ML-DSA of Task 29, which the FIPS policy rejects as outside the
// module. The hybrid layer therefore does NOT relax the FIPS policy; it inherits
// the classical layer's FIPS behavior (the RSA-OAEP wrap must use SHA-256, never
// the SoftHSM SHA-1 fallback — see negotiateWrapAlg).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	// mlkem1024CiphertextSize is the ML-KEM-1024 encapsulation ciphertext length.
	mlkem1024CiphertextSize = 1568
	// mlkem1024EncapKeySize is the ML-KEM-1024 encapsulation (public) key length.
	mlkem1024EncapKeySize = 1568
	// mlkem1024SeedSize is the length of the "d || z" decapsulation-key seed
	// returned by DecapsulationKey1024.Bytes.
	mlkem1024SeedSize = 64
)

// pqcKDFInfoTag domain-separates the hybrid wrapping-key derivation from any
// other HKDF use in the codebase.
const pqcKDFInfoTag = "secsy-pqc-hybrid-kek-v1\x00"

// PQCHybridKEK is a KEK family's ML-KEM-1024 hybrid key material bound to a live
// key provider. The encapsulation key seals new envelopes; the sealed
// decapsulation-key seed is unwrapped on the HSM (via unwrapper) to open them,
// keeping the HSM in the trust path. It is safe for concurrent use — each open
// unseals its own transient copy of the decapsulation key.
type PQCHybridKEK struct {
	keyID    string
	encapKey *mlkem.EncapsulationKey1024
	// sealedDK is the ML-KEM decapsulation-key seed sealed under a classical KEK
	// version via RSA-OAEP; sealAlg names the algorithm used.
	sealedDK []byte
	sealAlg  string
	// unwrapper is the classical KEK wrapper for the version that sealed the
	// decapsulation key (the family's active or a still-retiring version). Its
	// Unwrap runs on the HSM.
	unwrapper wrapper
}

// KeyID returns the stable identifier of this ML-KEM keypair, recorded in every
// envelope it seals.
func (h *PQCHybridKEK) KeyID() string { return h.keyID }

// sealDEK produces the PQC block for a hybrid envelope: it encapsulates to the
// ML-KEM public key, derives the wrapping key by combining the caller's
// classical shared secret ssC with the ML-KEM shared secret through HKDF, and
// seals the DEK under it with AES-256-GCM. ssC and dek are the caller's to
// zeroize.
func (h *PQCHybridKEK) sealDEK(ssC, dek []byte) (*PQCBlock, error) {
	if len(dek) != dekSize {
		return nil, fmt.Errorf("secret: data key has wrong length")
	}
	ssPQ, kemCT := h.encapKey.Encapsulate()
	defer zero(ssPQ)
	if len(kemCT) != mlkem1024CiphertextSize {
		return nil, fmt.Errorf("secret: unexpected ML-KEM ciphertext length %d", len(kemCT))
	}

	wk, err := hybridWrappingKey(ssC, ssPQ, h.keyID, kemCT)
	if err != nil {
		return nil, err
	}
	defer zero(wk)

	gcm, err := newGCM(wk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secret: generating PQC wrap nonce: %w", err)
	}
	wrapped := gcm.Seal(nil, nonce, dek, pqcWrapAAD(h.keyID, kemCT))

	return &PQCBlock{
		Alg:             AlgMLKEM1024,
		KeyID:           h.keyID,
		KEMCiphertext:   kemCT,
		WrapNonce:       nonce,
		WrappedDEK:      wrapped,
		ClassicalCommit: dekCommitment(ssC),
	}, nil
}

// recoverDEK reverses sealDEK given the classical shared secret ssC (already
// unwrapped by the HSM and commitment-checked by the caller). It unseals the
// ML-KEM decapsulation key on the HSM, decapsulates the KEM ciphertext,
// re-derives the wrapping key, and unwraps the DEK. The returned DEK is the
// caller's to zeroize.
func (h *PQCHybridKEK) recoverDEK(block *PQCBlock, ssC []byte) ([]byte, error) {
	// Unseal the ML-KEM decapsulation-key seed on the HSM: this is the classical
	// KEK round-trip that keeps the HSM in the trust path.
	seed, err := h.unwrapper.Unwrap(h.sealedDK, h.sealAlg)
	if err != nil {
		return nil, fmt.Errorf("secret: unsealing ML-KEM decapsulation key: %w", err)
	}
	defer zero(seed)
	if len(seed) != mlkem1024SeedSize {
		return nil, fmt.Errorf("secret: unsealed ML-KEM decapsulation key has wrong length")
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, fmt.Errorf("secret: reconstructing ML-KEM decapsulation key: %w", err)
	}
	ssPQ, err := dk.Decapsulate(block.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("secret: ML-KEM decapsulation failed: %w", err)
	}
	defer zero(ssPQ)

	wk, err := hybridWrappingKey(ssC, ssPQ, h.keyID, block.KEMCiphertext)
	if err != nil {
		return nil, err
	}
	defer zero(wk)

	gcm, err := newGCM(wk)
	if err != nil {
		return nil, err
	}
	if len(block.WrapNonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("secret: PQC wrap nonce has wrong length")
	}
	dek, err := gcm.Open(nil, block.WrapNonce, block.WrappedDEK, pqcWrapAAD(h.keyID, block.KEMCiphertext))
	if err != nil {
		return nil, fmt.Errorf("secret: unwrapping data key failed")
	}
	return dek, nil
}

// hybridWrappingKey derives the 256-bit AES wrapping key from the two shared
// secrets via HKDF-SHA256. Both secrets are inputs, so the key is unknown unless
// BOTH are known. The info string binds the KEM identifier, the key ID, and the
// KEM ciphertext so the derived key is unique to this exact encapsulation and
// cannot be transplanted onto another envelope.
func hybridWrappingKey(ssC, ssPQ []byte, keyID string, kemCT []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(ssC)+len(ssPQ))
	ikm = append(ikm, ssC...)
	ikm = append(ikm, ssPQ...)
	defer zero(ikm)
	info := pqcKDFInfoTag + AlgMLKEM1024 + "\x00" + keyID + "\x00" + string(kemCT)
	wk, err := hkdf.Key(sha256.New, ikm, nil, info, dekSize)
	if err != nil {
		return nil, fmt.Errorf("secret: deriving hybrid wrapping key: %w", err)
	}
	return wk, nil
}

// pqcWrapAAD is the additional-authenticated-data for the inner AES-GCM that
// seals the DEK under the hybrid wrapping key. Binding the key ID and KEM
// ciphertext ties the wrapped DEK to its encapsulation independently of the
// outer envelope AAD.
func pqcWrapAAD(keyID string, kemCT []byte) []byte {
	out := make([]byte, 0, len("secsy-pqc-wrap\x00")+len(keyID)+1+len(kemCT))
	out = append(out, "secsy-pqc-wrap\x00"...)
	out = append(out, keyID...)
	out = append(out, 0)
	out = append(out, kemCT...)
	return out
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: init GCM: %w", err)
	}
	return gcm, nil
}

// pqcKeyID derives a stable, non-secret identifier for an ML-KEM keypair from
// its public encapsulation key, so an envelope can name which decapsulation key
// opens it even after the classical KEK rotates.
func pqcKeyID(encapKey []byte) string {
	sum := sha256.Sum256(encapKey)
	return "mlkem1024-" + hex.EncodeToString(sum[:8])
}

// GeneratePQCHybridKEK creates fresh ML-KEM-1024 hybrid key material for a KEK
// family and seals its decapsulation key under the given (active) classical KEK
// service, returning the persistable record. The plaintext ML-KEM private key
// exists only transiently in this call — the record carries only the sealed
// seed. The classical seal fails closed under the FIPS policy if the KEK cannot
// RSA-OAEP with SHA-256 (see negotiateWrapAlg / algHash).
func GeneratePQCHybridKEK(active *Service, family string) (*models.PQCHybridKey, error) {
	if active == nil || active.wrapper == nil {
		return nil, fmt.Errorf("secret: an active classical KEK is required to seal the ML-KEM decapsulation key")
	}
	if family == "" {
		return nil, fmt.Errorf("secret: KEK family is required")
	}
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("secret: generating ML-KEM-1024 keypair: %w", err)
	}
	seed := dk.Bytes()
	defer zero(seed)
	sealed, sealAlg, err := active.wrapper.Wrap(seed)
	if err != nil {
		return nil, fmt.Errorf("secret: sealing ML-KEM decapsulation key under KEK %q: %w", active.wrapper.label, err)
	}
	if !supportedWrapAlgs[sealAlg] {
		return nil, fmt.Errorf("secret: classical KEK produced unsupported wrap algorithm %q", sealAlg)
	}
	encap := dk.EncapsulationKey().Bytes()
	return &models.PQCHybridKey{
		Family:             family,
		KeyID:              pqcKeyID(encap),
		Alg:                AlgMLKEM1024,
		EncapKey:           encap,
		SealedDecapKey:     sealed,
		SealAlg:            sealAlg,
		SealedUnderVersion: active.wrapper.version,
		Status:             models.PQCKeyStatusActive,
	}, nil
}

// newPQCHybridKEK binds a stored PQC record to a live classical wrapper (the
// KEK version that sealed the decapsulation key), producing the runtime handle
// used by seal/open. It validates the record's shape but performs no HSM work.
func newPQCHybridKEK(rec *models.PQCHybridKey, unwrapper wrapper) (*PQCHybridKEK, error) {
	if rec == nil {
		return nil, fmt.Errorf("secret: nil PQC hybrid key record")
	}
	if rec.Alg != AlgMLKEM1024 {
		return nil, fmt.Errorf("secret: unsupported PQC hybrid algorithm %q (want %s)", rec.Alg, AlgMLKEM1024)
	}
	if len(rec.EncapKey) != mlkem1024EncapKeySize {
		return nil, fmt.Errorf("secret: PQC record has a malformed encapsulation key (%d bytes, want %d)", len(rec.EncapKey), mlkem1024EncapKeySize)
	}
	if !supportedWrapAlgs[rec.SealAlg] {
		return nil, fmt.Errorf("secret: PQC record has unsupported seal algorithm %q", rec.SealAlg)
	}
	if len(rec.SealedDecapKey) == 0 {
		return nil, fmt.Errorf("secret: PQC record is missing the sealed decapsulation key")
	}
	ek, err := mlkem.NewEncapsulationKey1024(rec.EncapKey)
	if err != nil {
		return nil, fmt.Errorf("secret: parsing ML-KEM encapsulation key: %w", err)
	}
	// Guard against a corrupted store: the record's KeyID must match the key.
	if want := pqcKeyID(rec.EncapKey); want != rec.KeyID {
		return nil, fmt.Errorf("secret: PQC record key_id %q does not match its encapsulation key (%q)", rec.KeyID, want)
	}
	return &PQCHybridKEK{
		keyID:     rec.KeyID,
		encapKey:  ek,
		sealedDK:  rec.SealedDecapKey,
		sealAlg:   rec.SealAlg,
		unwrapper: unwrapper,
	}, nil
}

// reseal re-encrypts the ML-KEM decapsulation-key seed under a new classical KEK
// wrapper (the family's current active version), returning the updated sealed
// seed and its algorithm. It is used before retiring the KEK version that
// currently seals the decapsulation key: the seed is unwrapped on the HSM under
// the old wrapper and immediately re-wrapped under the new one, never leaving
// the process in cleartext beyond that transient copy. A no-op-equivalent
// re-seal (old == new version) is allowed and refreshes the material harmlessly.
func (h *PQCHybridKEK) reseal(active *Service) (sealed []byte, alg string, err error) {
	if active == nil || active.wrapper == nil {
		return nil, "", fmt.Errorf("secret: an active classical KEK is required to re-seal the ML-KEM decapsulation key")
	}
	seed, err := h.unwrapper.Unwrap(h.sealedDK, h.sealAlg)
	if err != nil {
		return nil, "", fmt.Errorf("secret: unsealing ML-KEM decapsulation key: %w", err)
	}
	defer zero(seed)
	if len(seed) != mlkem1024SeedSize {
		return nil, "", fmt.Errorf("secret: unsealed ML-KEM decapsulation key has wrong length")
	}
	sealed, alg, err = active.wrapper.Wrap(seed)
	if err != nil {
		return nil, "", fmt.Errorf("secret: re-sealing ML-KEM decapsulation key under KEK %q: %w", active.wrapper.label, err)
	}
	if !supportedWrapAlgs[alg] {
		return nil, "", fmt.Errorf("secret: classical KEK produced unsupported wrap algorithm %q", alg)
	}
	return sealed, alg, nil
}

// PQCHybridApproved reports the FIPS-policy status of ML-KEM-1024. It is always
// nil: ML-KEM-1024 is a FIPS 203 algorithm implemented inside the Go
// Cryptographic Module, so the hybrid mode is FIPS-approvable — the only FIPS
// constraint on a hybrid envelope is that its classical RSA-OAEP wrap use
// SHA-256 (enforced by the shared negotiation/algHash path). Unlike ML-DSA
// (CIRCL, outside the module), stdlib ML-KEM is not rejected. This helper exists
// so callers and tests can assert that intent explicitly rather than assuming
// it.
func PQCHybridApproved() error { return nil }
