package secret

// Named HSM-backed asymmetric digital signatures for the crypto service (Task
// 153): the Transit-style sign/verify counterpart to the symmetric data-key and
// keyed-HMAC primitives. A signing key is a real asymmetric key pair generated
// non-extractable inside the key provider (the HSM under PKCS#11); only its
// public half is exported and persisted (see models.SigningKey). Every signature
// is a raw, application-level signature over caller data — this is deliberately
// distinct from the CMS/X.509 artifact-signing service, which produces structured
// signature containers.
//
// The algorithm — curve/modulus and, for RSA, the PSS-vs-PKCS#1-v1.5 scheme — is
// fixed when the key is created; the message hash (SHA-256/384/512) is chosen per
// signing request, and the caller may sign either a message (hashed here) or a
// pre-computed digest. This file holds the pure algorithm model plus the
// provider-driven orchestration (create/sign) and the HSM-independent verify; the
// persistence lives behind the SigningKeyStore interface so the REST/gRPC handlers
// and the secsy-secret CLI share one implementation without this package
// depending on the database package (mirroring MACStore).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 so crypto.Hash.New/Available work
	_ "crypto/sha512" // register SHA-384/512 so crypto.Hash.New/Available work
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// SigningAlgorithm is the fixed signing algorithm of a named signing key. It
// bundles the key type (curve or RSA modulus) with the signature scheme so a key
// is unambiguous end to end: sign and verify never have to guess whether an RSA
// key is used with PSS or PKCS#1 v1.5.
type SigningAlgorithm string

const (
	// AlgECDSAP256 is ECDSA on NIST P-256, ASN.1 (r,s) signatures.
	AlgECDSAP256 SigningAlgorithm = "ecdsa-p256"
	// AlgECDSAP384 is ECDSA on NIST P-384.
	AlgECDSAP384 SigningAlgorithm = "ecdsa-p384"
	// AlgECDSAP521 is ECDSA on NIST P-521 (default hash SHA-512).
	AlgECDSAP521 SigningAlgorithm = "ecdsa-p521"
	// AlgEd25519 is pure Ed25519 (RFC 8032). It signs the message directly — there
	// is no selectable message hash and no pre-hashed mode (Ed25519 hashes
	// internally with SHA-512 as part of the scheme).
	AlgEd25519 SigningAlgorithm = "ed25519"
	// AlgRSAPSS2048 is RSASSA-PSS with a 2048-bit key (salt length = hash length).
	AlgRSAPSS2048 SigningAlgorithm = "rsa-pss-2048"
	// AlgRSAPSS3072 is RSASSA-PSS with a 3072-bit key.
	AlgRSAPSS3072 SigningAlgorithm = "rsa-pss-3072"
	// AlgRSAPSS4096 is RSASSA-PSS with a 4096-bit key.
	AlgRSAPSS4096 SigningAlgorithm = "rsa-pss-4096"
	// AlgRSAPKCS1v152048 is RSASSA-PKCS1-v1_5 with a 2048-bit key.
	AlgRSAPKCS1v152048 SigningAlgorithm = "rsa-pkcs1v15-2048"
	// AlgRSAPKCS1v153072 is RSASSA-PKCS1-v1_5 with a 3072-bit key.
	AlgRSAPKCS1v153072 SigningAlgorithm = "rsa-pkcs1v15-3072"
	// AlgRSAPKCS1v154096 is RSASSA-PKCS1-v1_5 with a 4096-bit key.
	AlgRSAPKCS1v154096 SigningAlgorithm = "rsa-pkcs1v15-4096"
)

// sigScheme is the signature scheme a SigningAlgorithm uses.
type sigScheme int

const (
	schemeECDSA sigScheme = iota
	schemeRSAPSS
	schemeRSAPKCS1v15
	// schemeEd25519 is pure EdDSA: the message is signed verbatim (no external
	// hashing, no pre-hashed digest), so it bypasses the hash-and-digest path.
	schemeEd25519
)

// algoSpec is the static description of one SigningAlgorithm.
type algoSpec struct {
	keyType     string      // key-provider key type to generate
	scheme      sigScheme   // signature scheme
	defaultHash crypto.Hash // hash used when a request does not specify one
}

// signingAlgorithms is the closed set of supported algorithms and their fixed
// key type / scheme / default hash.
var signingAlgorithms = map[SigningAlgorithm]algoSpec{
	AlgECDSAP256: {keyprovider.KeyTypeECDSAP256, schemeECDSA, crypto.SHA256},
	AlgECDSAP384: {keyprovider.KeyTypeECDSAP384, schemeECDSA, crypto.SHA384},
	AlgECDSAP521: {keyprovider.KeyTypeECDSAP521, schemeECDSA, crypto.SHA512},
	// Ed25519 has no selectable message hash; crypto.Hash(0) marks "sign the
	// message directly" (the crypto.Signer contract for an ed25519 key).
	AlgEd25519:         {keyprovider.KeyTypeEd25519, schemeEd25519, crypto.Hash(0)},
	AlgRSAPSS2048:      {keyprovider.KeyTypeRSA2048, schemeRSAPSS, crypto.SHA256},
	AlgRSAPSS3072:      {keyprovider.KeyTypeRSA3072, schemeRSAPSS, crypto.SHA256},
	AlgRSAPSS4096:      {keyprovider.KeyTypeRSA4096, schemeRSAPSS, crypto.SHA256},
	AlgRSAPKCS1v152048: {keyprovider.KeyTypeRSA2048, schemeRSAPKCS1v15, crypto.SHA256},
	AlgRSAPKCS1v153072: {keyprovider.KeyTypeRSA3072, schemeRSAPKCS1v15, crypto.SHA256},
	AlgRSAPKCS1v154096: {keyprovider.KeyTypeRSA4096, schemeRSAPKCS1v15, crypto.SHA256},
}

// SupportedSigningAlgorithms returns the canonical algorithm identifiers, for
// help text and API discovery.
func SupportedSigningAlgorithms() []string {
	return []string{
		string(AlgECDSAP256), string(AlgECDSAP384), string(AlgECDSAP521),
		string(AlgEd25519),
		string(AlgRSAPSS2048), string(AlgRSAPSS3072), string(AlgRSAPSS4096),
		string(AlgRSAPKCS1v152048), string(AlgRSAPKCS1v153072), string(AlgRSAPKCS1v154096),
	}
}

// NormalizeSigningAlgorithm maps a user-supplied algorithm string (with a few
// obvious aliases) to a canonical SigningAlgorithm, or errors for an unknown one.
func NormalizeSigningAlgorithm(s string) (SigningAlgorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ecdsa-p256", "ecdsa-sha2-nistp256", "p256", "nistp256", "es256":
		return AlgECDSAP256, nil
	case "ecdsa-p384", "ecdsa-sha2-nistp384", "p384", "nistp384", "es384":
		return AlgECDSAP384, nil
	case "ecdsa-p521", "ecdsa-sha2-nistp521", "p521", "nistp521", "es512":
		return AlgECDSAP521, nil
	case "ed25519", "ed-25519", "eddsa", "ssh-ed25519":
		return AlgEd25519, nil
	case "rsa-pss-2048", "rsapss-2048", "pss-2048":
		return AlgRSAPSS2048, nil
	case "rsa-pss-3072", "rsapss-3072", "pss-3072":
		return AlgRSAPSS3072, nil
	case "rsa-pss-4096", "rsapss-4096", "pss-4096":
		return AlgRSAPSS4096, nil
	case "rsa-pkcs1v15-2048", "rsa-2048", "pkcs1v15-2048", "rs256-2048":
		return AlgRSAPKCS1v152048, nil
	case "rsa-pkcs1v15-3072", "rsa-3072", "pkcs1v15-3072", "rs256-3072":
		return AlgRSAPKCS1v153072, nil
	case "rsa-pkcs1v15-4096", "rsa-4096", "pkcs1v15-4096", "rs256-4096":
		return AlgRSAPKCS1v154096, nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q (supported: %s)", s, strings.Join(SupportedSigningAlgorithms(), ", "))
	}
}

// spec returns the algoSpec for a (validated) algorithm string, and whether it
// is known.
func (a SigningAlgorithm) spec() (algoSpec, bool) {
	s, ok := signingAlgorithms[a]
	return s, ok
}

// DefaultHash returns the algorithm's default message hash.
func (a SigningAlgorithm) DefaultHash() crypto.Hash {
	if s, ok := a.spec(); ok {
		return s.defaultHash
	}
	return crypto.SHA256
}

// SignInputError marks a sign/verify failure caused by bad caller input — an
// unsupported hash, an unavailable hash, or a pre-hashed digest of the wrong
// length — as distinct from an internal/HSM failure, so the transport layer can
// map it to 400 / InvalidArgument.
type SignInputError struct{ msg string }

func (e *SignInputError) Error() string { return e.msg }

// ParseHash maps a hash identifier to a crypto.Hash, or errors for an
// unsupported one. It accepts sha256/sha384/sha512 and common spellings.
func ParseHash(s string) (crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sha256", "sha-256", "sha2-256":
		return crypto.SHA256, nil
	case "sha384", "sha-384", "sha2-384":
		return crypto.SHA384, nil
	case "sha512", "sha-512", "sha2-512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash %q (supported: sha256, sha384, sha512)", s)
	}
}

// HashName renders a crypto.Hash as its canonical lowercase identifier.
// crypto.Hash(0) — used by Ed25519, which signs the message directly — renders as
// "none" rather than the stdlib's "unknown hash value 0".
func HashName(h crypto.Hash) string {
	switch h {
	case crypto.Hash(0):
		return "none"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return h.String()
	}
}

// resolveHash returns the concrete hash for a request: the requested one when
// non-empty, else the algorithm default. It also validates the hash is linked.
func resolveHash(alg SigningAlgorithm, requested string) (crypto.Hash, error) {
	h := alg.DefaultHash()
	if strings.TrimSpace(requested) != "" {
		var err error
		if h, err = ParseHash(requested); err != nil {
			return 0, &SignInputError{err.Error()}
		}
	}
	if !h.Available() {
		return 0, &SignInputError{fmt.Sprintf("hash %v is not available in this build", h)}
	}
	return h, nil
}

// signerOptsFor builds the crypto.SignerOpts a signature scheme needs. For PSS it
// pins SaltLength to the hash length, the interoperable choice that verifies both
// against crypto/rsa and against openssl's default; ECDSA and PKCS#1 v1.5 carry
// only the hash.
func signerOptsFor(scheme sigScheme, hash crypto.Hash) crypto.SignerOpts {
	if scheme == schemeRSAPSS {
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
	}
	return hash
}

// digestFor returns the digest to sign/verify: the caller-supplied message hashed
// with hash, or — when preHashed — the message verbatim after checking it is the
// right length for the hash (so a mismatched pre-hash cannot silently produce an
// unverifiable signature).
func digestFor(message []byte, hash crypto.Hash, preHashed bool) ([]byte, error) {
	if preHashed {
		if len(message) != hash.Size() {
			return nil, &SignInputError{fmt.Sprintf("pre-hashed digest is %d bytes, but %s expects %d", len(message), HashName(hash), hash.Size())}
		}
		return message, nil
	}
	h := hash.New()
	h.Write(message)
	return h.Sum(nil), nil
}

// ed25519Data validates a sign/verify request against an Ed25519 key and returns
// the message to operate on. Ed25519 is pure EdDSA (RFC 8032): it signs the
// message directly and hashes internally, so a caller-selected message hash or a
// pre-computed digest is a request error rather than something we silently ignore
// — fail closed on the mismatch, mirroring the rest of the service.
func ed25519Data(data []byte, hashName string, preHashed bool) ([]byte, error) {
	if preHashed {
		return nil, &SignInputError{"ed25519 signs the message directly; pre-hashed input (digest) is not supported"}
	}
	if strings.TrimSpace(hashName) != "" {
		return nil, &SignInputError{"ed25519 does not take a selectable message hash (it hashes internally); omit the hash"}
	}
	return data, nil
}

// --- persistence boundary -------------------------------------------------

// SigningKeyStore is the minimal persistence the signing orchestration needs.
// *database.DB satisfies it structurally; keeping it an interface here lets the
// REST/gRPC handlers and the secsy-secret CLI share one implementation without
// this package depending on the database package (mirroring MACStore).
type SigningKeyStore interface {
	GetSigningKey(tenantID, name string) (*models.SigningKey, error)
	InsertSigningKey(k *models.SigningKey) error
	ListSigningKeys(tenantID string) ([]*models.SigningKey, error)
}

// ErrSigningKeyNameTaken is returned by CreateSigningKey when the tenant already
// has a signing key with the requested name.
var ErrSigningKeyNameTaken = errors.New("a signing key with this name already exists for the tenant")

// CreateSigningKeySpec describes a signing key to create.
type CreateSigningKeySpec struct {
	TenantID  string
	Name      string
	Algorithm SigningAlgorithm
	CreatedBy string
}

// signingKeyLabel derives the provider/HSM object label from a key id. Basing it
// on the immutable, unique id (not the mutable friendly name) guarantees two keys
// never collide on a CKA_LABEL — the ambiguity the PKCS#11 provider refuses.
func signingKeyLabel(id string) string { return "secsy-sig-" + id }

// randomID mints a 128-bit random hex identifier for a signing key.
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating key id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateSigningKey generates a new named signing key: it mints the key pair
// non-extractable in the provider (the HSM under PKCS#11), exports only the public
// half, and persists the metadata row. The private key never leaves the backend.
// A duplicate name is rejected up front (ErrSigningKeyNameTaken) so the common
// case does not leave an orphaned provider key.
func CreateSigningKey(ctx context.Context, provider keyprovider.Provider, store SigningKeyStore, spec CreateSigningKeySpec) (*models.SigningKey, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return nil, fmt.Errorf("signing key name is required")
	}
	if strings.TrimSpace(spec.TenantID) == "" {
		return nil, fmt.Errorf("tenant is required")
	}
	aspec, ok := spec.Algorithm.spec()
	if !ok {
		return nil, fmt.Errorf("unsupported signing algorithm %q", spec.Algorithm)
	}
	// Reject a duplicate name before touching the provider so a repeated create
	// does not generate an orphaned key. The UNIQUE constraint is the backstop
	// for a concurrent race.
	existing, err := store.GetSigningKey(spec.TenantID, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("checking for an existing signing key: %w", err)
	}
	if existing != nil {
		return nil, ErrSigningKeyNameTaken
	}

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	info, err := provider.GenerateKey(ctx, keyprovider.KeySpec{
		Label:   signingKeyLabel(id),
		KeyType: aspec.keyType,
		Usage:   keyprovider.KeyUsageSign,
	})
	if err != nil {
		return nil, fmt.Errorf("generating signing key on the provider: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	row := &models.SigningKey{
		ID:           id,
		TenantID:     spec.TenantID,
		Name:         spec.Name,
		Algorithm:    string(spec.Algorithm),
		KeyType:      aspec.keyType,
		KeyRef:       info.URI,
		PublicKeyDER: base64.StdEncoding.EncodeToString(spki),
		Provider:     provider.Name(),
		CreatedBy:    spec.CreatedBy,
	}
	if err := store.InsertSigningKey(row); err != nil {
		return nil, err
	}
	return row, nil
}

// SignResult carries a produced signature and the parameters it was made under.
type SignResult struct {
	Signature []byte
	Algorithm SigningAlgorithm
	Hash      crypto.Hash
}

// Sign produces a signature over data with the named key's private half in the
// provider. hashName selects the message hash (empty = the algorithm default);
// when preHashed, data is already the digest. The private key is used only inside
// the backend — this call resolves a short-lived provider Signer and closes it.
func Sign(ctx context.Context, provider keyprovider.Provider, row *models.SigningKey, data []byte, hashName string, preHashed bool) (*SignResult, error) {
	alg := SigningAlgorithm(row.Algorithm)
	aspec, ok := alg.spec()
	if !ok {
		return nil, fmt.Errorf("stored key has unsupported algorithm %q", row.Algorithm)
	}

	// Ed25519 signs the message verbatim (no external hash, no pre-hashed digest);
	// crypto.Hash(0) is the crypto.Signer signal for "sign the message directly".
	if aspec.scheme == schemeEd25519 {
		msg, err := ed25519Data(data, hashName, preHashed)
		if err != nil {
			return nil, err
		}
		signer, err := provider.Signer(ctx, keyprovider.KeyRefFor(row.KeyRef))
		if err != nil {
			return nil, fmt.Errorf("resolving signing key %q: %w", row.Name, err)
		}
		defer func() { _ = signer.Close() }()
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("signing: %w", err)
		}
		return &SignResult{Signature: sig, Algorithm: alg, Hash: crypto.Hash(0)}, nil
	}

	hash, err := resolveHash(alg, hashName)
	if err != nil {
		return nil, err
	}
	digest, err := digestFor(data, hash, preHashed)
	if err != nil {
		return nil, err
	}
	signer, err := provider.Signer(ctx, keyprovider.KeyRefFor(row.KeyRef))
	if err != nil {
		return nil, fmt.Errorf("resolving signing key %q: %w", row.Name, err)
	}
	defer func() { _ = signer.Close() }()

	sig, err := signer.Sign(rand.Reader, digest, signerOptsFor(aspec.scheme, hash))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return &SignResult{Signature: sig, Algorithm: alg, Hash: hash}, nil
}

// PublicKey parses the stored SPKI DER back into a crypto.PublicKey.
func PublicKey(row *models.SigningKey) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(row.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("decoding stored public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing stored public key: %w", err)
	}
	return pub, nil
}

// PublicKeyDER returns the raw DER SubjectPublicKeyInfo of the stored public key.
func PublicKeyDER(row *models.SigningKey) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(row.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("decoding stored public key: %w", err)
	}
	return der, nil
}

// PublicKeyPEM returns the stored public key as a PEM "PUBLIC KEY" (SPKI) block,
// the form external verifiers (openssl, JOSE libraries) expect.
func PublicKeyPEM(row *models.SigningKey) ([]byte, error) {
	der, err := PublicKeyDER(row)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Verify checks a signature over data against the key's stored public half. It
// needs no provider/HSM — the public key alone verifies — so it also models what
// an external verifier does. A signature that simply does not match yields
// (false, nil); only a malformed key, unsupported algorithm, or bad parameters is
// an error.
func Verify(row *models.SigningKey, data, sig []byte, hashName string, preHashed bool) (bool, error) {
	pub, err := PublicKey(row)
	if err != nil {
		return false, err
	}
	return VerifyWithPublicKey(SigningAlgorithm(row.Algorithm), pub, data, sig, hashName, preHashed)
}

// ParsePublicKey parses a caller-supplied public key from either a PEM "PUBLIC
// KEY" (SPKI) block or raw DER SubjectPublicKeyInfo. It lets a caller verify a
// signature against a key this service does not manage.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, &SignInputError{fmt.Sprintf("parsing supplied public key (expected SPKI PEM or DER): %v", err)}
	}
	return pub, nil
}

// VerifyWithPublicKey checks a signature over data against an explicitly supplied
// public key and algorithm, needing neither a stored key nor the HSM. It is the
// shared verification core used both by Verify (stored key) and by the
// supplied-public-key verify path. A signature that simply does not match yields
// (false, nil); a malformed key, an algorithm/key-type mismatch, or bad request
// parameters is an error.
func VerifyWithPublicKey(alg SigningAlgorithm, pub crypto.PublicKey, data, sig []byte, hashName string, preHashed bool) (bool, error) {
	aspec, ok := alg.spec()
	if !ok {
		return false, &SignInputError{fmt.Sprintf("unsupported algorithm %q", alg)}
	}

	// Ed25519 verifies the message directly against the public key (no hash, no
	// pre-hashed digest), matching how Sign produced it.
	if aspec.scheme == schemeEd25519 {
		msg, err := ed25519Data(data, hashName, preHashed)
		if err != nil {
			return false, err
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false, &SignInputError{"supplied key is not an Ed25519 public key"}
		}
		return ed25519.Verify(edPub, msg, sig), nil
	}

	hash, err := resolveHash(alg, hashName)
	if err != nil {
		return false, err
	}
	digest, err := digestFor(data, hash, preHashed)
	if err != nil {
		return false, err
	}

	switch aspec.scheme {
	case schemeECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false, &SignInputError{"supplied key is not an ECDSA public key"}
		}
		return ecdsa.VerifyASN1(ecPub, digest, sig), nil
	case schemeRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false, &SignInputError{"supplied key is not an RSA public key"}
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
		return rsa.VerifyPSS(rsaPub, hash, digest, sig, opts) == nil, nil
	case schemeRSAPKCS1v15:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false, &SignInputError{"supplied key is not an RSA public key"}
		}
		return rsa.VerifyPKCS1v15(rsaPub, hash, digest, sig) == nil, nil
	default:
		return false, fmt.Errorf("unsupported scheme")
	}
}
