package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// azureKeyVaultBackend implements KMSBackend against Azure Key Vault. Key Vault
// keys are non-extractable by API (there is no private-key GET), satisfying the
// non-extractability invariant; for hardware protection, target a Premium vault
// or Managed HSM.
type azureKeyVaultBackend struct {
	client azureKeyVaultClient
	prefix string
}

// azureKeyVaultClient is the concrete client method set the backend calls. The
// real *azkeys.Client satisfies it. Key operations address keys by name and use
// the latest version.
type azureKeyVaultClient interface {
	CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, opts *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	Sign(ctx context.Context, name, version string, params azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error)
	NewListKeyPropertiesPager(opts *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse]
}

// newAzureKeyVaultBackend constructs the Azure Key Vault backend using the default
// Azure credential chain (environment, workload identity, managed identity).
func newAzureKeyVaultBackend(cfg KMSSettings) (KMSBackend, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("keyprovider: azure key vault requires kms.vault_url")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: azure credential: %w", err)
	}
	client, err := azkeys.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: azure key vault client: %w", err)
	}
	return &azureKeyVaultBackend{client: client, prefix: cfg.KeyPrefix}, nil
}

func (b *azureKeyVaultBackend) BackendName() string { return KMSBackendAzure }

func (b *azureKeyVaultBackend) Close() error { return nil }

// keyName maps a deployment label to an Azure key name (alphanumerics and hyphens
// only), replacing any other character with a hyphen.
func (b *azureKeyVaultBackend) keyName(label string) string {
	raw := b.prefix + label
	var sb strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

func (b *azureKeyVaultBackend) Ping(ctx context.Context) error {
	// A GetKey for a name that is unlikely to exist still round-trips
	// authentication and reachability; "not found" means the vault answered.
	_, err := b.client.GetKey(ctx, b.keyName("__secsy_healthprobe__"), "", nil)
	if err != nil && !isAzureNotFound(err) {
		return fmt.Errorf("keyprovider: azure key vault unreachable: %w", err)
	}
	return nil
}

func (b *azureKeyVaultBackend) CreateKey(ctx context.Context, label, keyType string) (*RemoteKey, error) {
	name := b.keyName(label)
	if _, err := b.client.GetKey(ctx, name, "", nil); err == nil {
		return nil, fmt.Errorf("keyprovider: azure key %q already exists", label)
	} else if !isAzureNotFound(err) {
		return nil, fmt.Errorf("keyprovider: checking azure key %q: %w", label, err)
	}
	params, err := azureCreateParams(keyType)
	if err != nil {
		return nil, err
	}
	resp, err := b.client.CreateKey(ctx, name, params, nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: azure CreateKey %q: %w", label, err)
	}
	return b.remoteFromBundle(label, keyType, resp.Key)
}

func (b *azureKeyVaultBackend) ResolveKey(ctx context.Context, label string) (*RemoteKey, error) {
	name := b.keyName(label)
	resp, err := b.client.GetKey(ctx, name, "", nil)
	if err != nil {
		if isAzureNotFound(err) {
			return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, label)
		}
		return nil, fmt.Errorf("keyprovider: azure GetKey %q: %w", label, err)
	}
	keyType, err := azureKeyType(resp.Key)
	if err != nil {
		return nil, err
	}
	return b.remoteFromBundle(label, keyType, resp.Key)
}

func (b *azureKeyVaultBackend) Sign(ctx context.Context, keyID, keyType string, digest []byte, hash crypto.Hash, pss bool) ([]byte, error) {
	algo, err := azureSignatureAlgorithm(keyType, hash, pss)
	if err != nil {
		return nil, err
	}
	// keyID here is the key name (see remoteFromBundle); latest version ("").
	resp, err := b.client.Sign(ctx, keyID, "", azkeys.SignParameters{
		Algorithm: &algo,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: azure Sign: %w", err)
	}
	sig := resp.Result
	// Azure returns ECDSA signatures in IEEE P1363 (r||s) form; x509/CMS verifiers
	// expect ASN.1 DER, so convert. RSA signatures are returned ready-to-use.
	if keyType == KeyTypeECDSAP256 || keyType == KeyTypeECDSAP384 || keyType == KeyTypeECDSAP521 {
		return p1363ToASN1(sig)
	}
	return sig, nil
}

func (b *azureKeyVaultBackend) ListKeys(ctx context.Context) ([]RemoteKey, error) {
	var out []RemoteKey
	pager := b.client.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("keyprovider: azure ListKeyProperties: %w", err)
		}
		for _, kp := range page.Value {
			if kp == nil || kp.KID == nil {
				continue
			}
			name := kp.KID.Name()
			if !strings.HasPrefix(name, b.prefix) {
				continue
			}
			label := strings.TrimPrefix(name, b.prefix)
			rk := RemoteKey{Label: label, KeyID: name, URI: "kms:azure:" + name}
			if resolved, rerr := b.ResolveKey(ctx, label); rerr == nil {
				rk.KeyType = resolved.KeyType
				rk.PublicKey = resolved.PublicKey
			}
			out = append(out, rk)
		}
	}
	return out, nil
}

// remoteFromBundle builds RemoteKey metadata from a Key Vault key bundle. The
// backend addresses keys by name for subsequent operations, so KeyID is the name.
func (b *azureKeyVaultBackend) remoteFromBundle(label, keyType string, jwk *azkeys.JSONWebKey) (*RemoteKey, error) {
	pub, err := azurePublicKey(jwk)
	if err != nil {
		return nil, err
	}
	return &RemoteKey{
		Label:     label,
		KeyID:     b.keyName(label),
		KeyType:   keyType,
		PublicKey: pub,
		URI:       "kms:azure:" + b.keyName(label),
	}, nil
}

func azureCreateParams(keyType string) (azkeys.CreateKeyParameters, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return ecParams(azkeys.CurveNameP256), nil
	case KeyTypeECDSAP384:
		return ecParams(azkeys.CurveNameP384), nil
	case KeyTypeECDSAP521:
		return ecParams(azkeys.CurveNameP521), nil
	case KeyTypeRSA2048:
		return rsaParams(2048), nil
	case KeyTypeRSA4096:
		return rsaParams(4096), nil
	default:
		return azkeys.CreateKeyParameters{}, fmt.Errorf("keyprovider: azure unsupported key type %q", keyType)
	}
}

func ecParams(curve azkeys.CurveName) azkeys.CreateKeyParameters {
	kty := azkeys.KeyTypeEC
	c := curve
	return azkeys.CreateKeyParameters{Kty: &kty, Curve: &c}
}

func rsaParams(bits int32) azkeys.CreateKeyParameters {
	kty := azkeys.KeyTypeRSA
	n := bits
	return azkeys.CreateKeyParameters{Kty: &kty, KeySize: &n}
}

// azureKeyType derives the canonical key type from a returned JWK.
func azureKeyType(jwk *azkeys.JSONWebKey) (string, error) {
	if jwk == nil || jwk.Kty == nil {
		return "", fmt.Errorf("keyprovider: azure key bundle missing key type")
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		if jwk.Crv == nil {
			return "", fmt.Errorf("keyprovider: azure EC key missing curve")
		}
		switch *jwk.Crv {
		case azkeys.CurveNameP256:
			return KeyTypeECDSAP256, nil
		case azkeys.CurveNameP384:
			return KeyTypeECDSAP384, nil
		case azkeys.CurveNameP521:
			return KeyTypeECDSAP521, nil
		default:
			return "", fmt.Errorf("keyprovider: azure unsupported curve %q", *jwk.Crv)
		}
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		if len(jwk.N) > 384 {
			return KeyTypeRSA4096, nil
		}
		return KeyTypeRSA2048, nil
	default:
		return "", fmt.Errorf("keyprovider: azure unsupported key type %q", *jwk.Kty)
	}
}

// azurePublicKey reconstructs a crypto.PublicKey from an Azure JWK.
func azurePublicKey(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil || jwk.Kty == nil {
		return nil, fmt.Errorf("keyprovider: azure key bundle has no key material")
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		var curve elliptic.Curve
		switch {
		case jwk.Crv == nil:
			return nil, fmt.Errorf("keyprovider: azure EC key missing curve")
		case *jwk.Crv == azkeys.CurveNameP256:
			curve = elliptic.P256()
		case *jwk.Crv == azkeys.CurveNameP384:
			curve = elliptic.P384()
		case *jwk.Crv == azkeys.CurveNameP521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("keyprovider: azure unsupported curve %q", *jwk.Crv)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(jwk.X),
			Y:     new(big.Int).SetBytes(jwk.Y),
		}, nil
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		if len(jwk.N) == 0 || len(jwk.E) == 0 {
			return nil, fmt.Errorf("keyprovider: azure RSA key missing modulus/exponent")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(jwk.N),
			E: int(new(big.Int).SetBytes(jwk.E).Int64()),
		}, nil
	default:
		return nil, fmt.Errorf("keyprovider: azure unsupported key type %q", *jwk.Kty)
	}
}

func azureSignatureAlgorithm(keyType string, hash crypto.Hash, pss bool) (azkeys.SignatureAlgorithm, error) {
	isRSA := keyType == KeyTypeRSA2048 || keyType == KeyTypeRSA4096
	if isRSA {
		switch {
		case pss && hash == crypto.SHA256:
			return azkeys.SignatureAlgorithmPS256, nil
		case pss && hash == crypto.SHA384:
			return azkeys.SignatureAlgorithmPS384, nil
		case pss && hash == crypto.SHA512:
			return azkeys.SignatureAlgorithmPS512, nil
		case !pss && hash == crypto.SHA256:
			return azkeys.SignatureAlgorithmRS256, nil
		case !pss && hash == crypto.SHA384:
			return azkeys.SignatureAlgorithmRS384, nil
		case !pss && hash == crypto.SHA512:
			return azkeys.SignatureAlgorithmRS512, nil
		}
		return "", fmt.Errorf("keyprovider: azure unsupported RSA hash %v", hash)
	}
	switch hash {
	case crypto.SHA256:
		return azkeys.SignatureAlgorithmES256, nil
	case crypto.SHA384:
		return azkeys.SignatureAlgorithmES384, nil
	case crypto.SHA512:
		return azkeys.SignatureAlgorithmES512, nil
	default:
		return "", fmt.Errorf("keyprovider: azure unsupported ECDSA hash %v", hash)
	}
}

// isAzureNotFound reports whether an Azure error is a 404 (key not found).
func isAzureNotFound(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "404") ||
		strings.Contains(strings.ToLower(err.Error()), "keynotfound") ||
		strings.Contains(strings.ToLower(err.Error()), "not found"))
}

// p1363ToASN1 converts an IEEE P1363 (fixed-width r||s) ECDSA signature to the
// ASN.1 DER SEQUENCE{r,s} form the Go standard library verifies.
func p1363ToASN1(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("keyprovider: invalid P1363 ECDSA signature length %d", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	type ecdsaSig struct{ R, S *big.Int }
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

var _ KMSBackend = (*azureKeyVaultBackend)(nil)
