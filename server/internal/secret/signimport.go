package secret

// Adopting an existing signing key into the named-signing-key registry (Task
// 194), the secret-layer counterpart to `secsy-ca ca import`.
//
// The case is the same shape as a legacy CA: an application already signs
// something — release manifests, licence files, webhook payloads — with a key
// whose public half is embedded in clients that have shipped. Rotating it means
// updating every verifier. Importing it means the private half stops living in
// the application's config and starts living in the HSM, with everything else
// unchanged.
//
// An imported key is otherwise indistinguishable from a generated one: same
// registry row, same sign/verify paths, same non-extractable storage. What is
// not the same is provenance, and the audit event for the import is the record
// of that.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ImportSigningKeySpec describes an existing signing key to adopt.
type ImportSigningKeySpec struct {
	TenantID string
	Name     string
	// PrivateKey is the existing key material: *rsa.PrivateKey,
	// *ecdsa.PrivateKey, or ed25519.PrivateKey.
	PrivateKey crypto.PrivateKey
	// Algorithm fixes the signature scheme. It may be left empty for ECDSA and
	// Ed25519, where the key type determines it; an RSA key must name one,
	// because the same key can be used with PSS or PKCS#1 v1.5 and the choice
	// has to match whatever the existing verifiers already do.
	Algorithm SigningAlgorithm
	CreatedBy string
}

// ImportSigningKey adopts an existing private key as a named signing key: the
// material is written into the provider (non-extractable, sign-only), proved
// usable there, and the metadata row is persisted. The key is then used exactly
// like a generated one.
func ImportSigningKey(ctx context.Context, provider keyprovider.Provider, store SigningKeyStore, spec ImportSigningKeySpec) (*models.SigningKey, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return nil, fmt.Errorf("signing key name is required")
	}
	if strings.TrimSpace(spec.TenantID) == "" {
		return nil, fmt.Errorf("tenant is required")
	}
	if spec.PrivateKey == nil {
		return nil, fmt.Errorf("no private key supplied")
	}
	signer, ok := spec.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the supplied private key of type %T cannot sign", spec.PrivateKey)
	}
	alg, err := resolveImportAlgorithm(spec.PrivateKey, spec.Algorithm)
	if err != nil {
		return nil, err
	}
	aspec, _ := alg.spec()

	// Reject a duplicate name before touching the provider, so a repeated import
	// does not strand key material under a label no row points at.
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
	label := signingKeyLabel(id)
	info, err := keyprovider.ImportKey(ctx, provider, keyprovider.ImportSpec{
		Label:      label,
		Usage:      keyprovider.KeyUsageSign,
		PrivateKey: spec.PrivateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("importing the signing key into the provider: %w", err)
	}
	// Prove the provider can sign with it before a registry row claims it can.
	if err := keyprovider.VerifyKeyUsable(ctx, provider, keyprovider.KeyRef{Label: label}, signer.Public()); err != nil {
		return nil, fmt.Errorf("the imported signing key is not usable: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	row := &models.SigningKey{
		ID:           id,
		TenantID:     spec.TenantID,
		Name:         spec.Name,
		Algorithm:    string(alg),
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

// resolveImportAlgorithm derives (or validates) the signing algorithm for
// imported key material. ECDSA and Ed25519 are fully determined by the key; RSA
// is not, so the caller must choose the scheme the existing verifiers use —
// guessing would produce signatures nothing accepts.
func resolveImportAlgorithm(priv crypto.PrivateKey, requested SigningAlgorithm) (SigningAlgorithm, error) {
	var derived SigningAlgorithm
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			derived = AlgECDSAP256
		case "P-384":
			derived = AlgECDSAP384
		case "P-521":
			derived = AlgECDSAP521
		default:
			return "", fmt.Errorf("unsupported elliptic curve %s", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		derived = AlgEd25519
	case *rsa.PrivateKey:
		if requested == "" {
			return "", fmt.Errorf("an RSA signing key needs an explicit algorithm: choose rsa-pss-* or rsa-pkcs1v15-* to match what existing verifiers expect")
		}
	default:
		return "", fmt.Errorf("unsupported private key type %T", priv)
	}

	if requested == "" {
		return derived, nil
	}
	aspec, ok := requested.spec()
	if !ok {
		return "", fmt.Errorf("unsupported signing algorithm %q", requested)
	}
	// Whatever was asked for must match the key that was actually supplied: an
	// rsa-pss-4096 label on a 2048-bit key would sign happily and mislead
	// everyone reading the registry.
	keyType, err := providerKeyType(priv)
	if err != nil {
		return "", err
	}
	if aspec.keyType != keyType {
		return "", fmt.Errorf("algorithm %q expects a %s key, but the supplied key is %s", requested, aspec.keyType, keyType)
	}
	return requested, nil
}

// providerKeyType maps in-memory key material to the key-provider key type.
func providerKeyType(priv crypto.PrivateKey) (string, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return keyprovider.KeyTypeECDSAP256, nil
		case "P-384":
			return keyprovider.KeyTypeECDSAP384, nil
		case "P-521":
			return keyprovider.KeyTypeECDSAP521, nil
		}
		return "", fmt.Errorf("unsupported elliptic curve %s", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		return keyprovider.KeyTypeEd25519, nil
	case *rsa.PrivateKey:
		switch bits := k.N.BitLen(); {
		case bits < 2048:
			return "", fmt.Errorf("RSA key is %d bits; the minimum is 2048", bits)
		case bits <= 2048:
			return keyprovider.KeyTypeRSA2048, nil
		case bits <= 3072:
			return keyprovider.KeyTypeRSA3072, nil
		default:
			return keyprovider.KeyTypeRSA4096, nil
		}
	default:
		return "", fmt.Errorf("unsupported private key type %T", priv)
	}
}
