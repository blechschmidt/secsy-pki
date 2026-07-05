package secret

// Keyed-MAC primitives for the stateless HMAC crypto service (Task 138).
//
// The service computes and verifies a keyed HMAC over caller-supplied data with
// a symmetric MAC key that never exists in the clear at rest: a random seed is
// sealed as an ordinary envelope under the family's HSM-held KEK (so unwrapping
// it is an on-token operation, exactly like a data key) and a purpose-bound MAC
// key is derived from it per use via HKDF. Deriving rather than using the seed
// directly domain-separates the MAC key from any other use of the same seed and
// binds it to the family and version, so a token produced under one version can
// never verify under another. This file holds only the pure crypto; the sealed
// seed's persistence and lifecycle live in the database and handler layers.

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	// MACSeedBytes is the size of the random seed sealed under the KEK. 256 bits
	// matches the derived MAC-key and HMAC-SHA256 output sizes.
	MACSeedBytes = 32
	// macKeyBytes is the size of the HKDF-derived MAC key.
	macKeyBytes = 32
	// HMACAlgSHA256 is the only supported MAC algorithm. It is embedded in the
	// returned token so verification is unambiguous and future algorithms can be
	// added without breaking existing tokens.
	HMACAlgSHA256 = "HMAC-SHA256"
	// macKDFInfoTag domain-separates the HMAC-key derivation from every other use
	// of HKDF in this package (see pqcKDFInfoTag).
	macKDFInfoTag = "secsy-pki/secret/hmac-key-v1\x00"
)

// DeriveMACKey derives the per-use MAC key from an unwrapped seed via
// HKDF-SHA256, domain-separated by the KEK family and MAC-key version so a key
// derived for one (family, version) is independent of every other. The seed must
// be MACSeedBytes long. The caller is responsible for zeroizing both the seed and
// the returned key.
func DeriveMACKey(seed []byte, family string, version int) ([]byte, error) {
	if len(seed) != MACSeedBytes {
		return nil, fmt.Errorf("secret: MAC seed must be %d bytes, got %d", MACSeedBytes, len(seed))
	}
	if version <= 0 {
		return nil, fmt.Errorf("secret: MAC key version must be positive, got %d", version)
	}
	info := macKDFInfoTag + family + "\x00" + strconv.Itoa(version)
	key, err := hkdf.Key(sha256.New, seed, nil, info, macKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("secret: deriving MAC key: %w", err)
	}
	return key, nil
}

// ComputeHMAC returns HMAC-SHA256(macKey, data). It is a pure function over its
// inputs; callers zeroize macKey when done.
func ComputeHMAC(macKey, data []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC reports whether want equals HMAC-SHA256(macKey, data) using a
// constant-time comparison, so a verification endpoint cannot be turned into a
// timing oracle on the expected tag.
func VerifyHMAC(macKey, data, want []byte) bool {
	return hmac.Equal(want, ComputeHMAC(macKey, data))
}

// MACStore is the minimal persistence the keyed-HMAC orchestration needs.
// *database.DB satisfies it structurally; keeping it an interface here lets both
// the REST/gRPC handlers and the secsy-secret CLI share one implementation
// without the secret package depending on the database package.
type MACStore interface {
	GetActiveMACKey(family string) (*models.MACKey, error)
	GetMACKeyVersion(family string, version int) (*models.MACKey, error)
	MaxMACKeyVersion(family string) (int, error)
	InsertMACKey(k *models.MACKey) error
}

// EnsureActiveMACKey returns the family's active MAC key, lazily provisioning a
// fresh version on first use: it mints a random seed via seedRand (the HSM RNG
// when available), seals it as an ordinary envelope under the ring's active KEK,
// and persists the sealed row. The (family, version) primary key resolves a
// concurrent first-use race — the loser re-reads the winner's row.
func EnsureActiveMACKey(ctx context.Context, store MACStore, ring *Ring, family string, seedRand func(n int) ([]byte, error)) (*models.MACKey, error) {
	active, err := store.GetActiveMACKey(family)
	if err != nil {
		return nil, fmt.Errorf("secret: reading MAC key state: %w", err)
	}
	if active != nil {
		return active, nil
	}
	seed, err := seedRand(MACSeedBytes)
	if err != nil {
		return nil, fmt.Errorf("secret: generating MAC key seed: %w", err)
	}
	defer zero(seed)
	env, err := ring.EncryptToJSON(seed, nil)
	if err != nil {
		return nil, fmt.Errorf("secret: sealing MAC key seed: %w", err)
	}
	maxVer, err := store.MaxMACKeyVersion(family)
	if err != nil {
		return nil, fmt.Errorf("secret: reading MAC key version: %w", err)
	}
	k := &models.MACKey{Family: family, Version: maxVer + 1, Envelope: string(env), Status: models.MACKeyStatusActive}
	if err := store.InsertMACKey(k); err != nil {
		// A concurrent request may have provisioned the same version first; the
		// PK conflict is expected — re-read and use the winner.
		if a, rerr := store.GetActiveMACKey(family); rerr == nil && a != nil {
			return a, nil
		}
		return nil, fmt.Errorf("secret: provisioning MAC key: %w", err)
	}
	return k, nil
}

// macKeyFromRow unwraps a MAC-key row's sealed seed on the HSM (via the ring's
// KEK) and derives the per-use MAC key for the row's version. The caller must
// zeroize the returned key.
func macKeyFromRow(ctx context.Context, ring *Ring, row *models.MACKey) ([]byte, error) {
	seed, err := ring.DecryptJSON(ctx, []byte(row.Envelope), nil)
	if err != nil {
		return nil, fmt.Errorf("secret: unwrapping MAC key seed: %w", err)
	}
	defer zero(seed)
	return DeriveMACKey(seed, row.Family, row.Version)
}

// TagHMAC computes the keyed HMAC over data with the MAC key sealed in row,
// unwrapping and deriving it on the fly (never leaving the derived key alive
// past the call).
func TagHMAC(ctx context.Context, ring *Ring, row *models.MACKey, data []byte) ([]byte, error) {
	key, err := macKeyFromRow(ctx, ring, row)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	return ComputeHMAC(key, data), nil
}

// CheckHMAC constant-time verifies mac against the keyed HMAC of data under the
// MAC key sealed in row.
func CheckHMAC(ctx context.Context, ring *Ring, row *models.MACKey, data, mac []byte) (bool, error) {
	key, err := macKeyFromRow(ctx, ring, row)
	if err != nil {
		return false, err
	}
	defer zero(key)
	return VerifyHMAC(key, data, mac), nil
}
