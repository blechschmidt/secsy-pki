package keyprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// awsKMSClient is the subset of the AWS KMS API the backend uses. Defining it as
// an interface keeps the backend unit-testable and documents the exact IAM
// actions required (kms:CreateKey, kms:CreateAlias, kms:GetPublicKey, kms:Sign,
// kms:DescribeKey, kms:ListAliases).
type awsKMSClient interface {
	CreateKey(ctx context.Context, in *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(ctx context.Context, in *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	ListAliases(ctx context.Context, in *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
}

// awsKMSBackend implements KMSBackend against AWS KMS. Keys are provisioned as
// asymmetric SIGN_VERIFY keys and given an alias derived from the key label, so
// deployment-facing labels resolve to KMS key IDs without a local mapping table.
type awsKMSBackend struct {
	client awsKMSClient
	prefix string
}

// newAWSKMSBackend constructs the AWS KMS backend using the default AWS credential
// chain (environment, shared config, IRSA/instance role). The IAM principal must
// be granted the actions listed on awsKMSClient; see docs/hsm/cloud-kms.md.
func newAWSKMSBackend(cfg KMSSettings) (KMSBackend, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: loading AWS config: %w", err)
	}
	return &awsKMSBackend{client: kms.NewFromConfig(awsCfg), prefix: cfg.KeyPrefix}, nil
}

func (b *awsKMSBackend) BackendName() string { return KMSBackendAWS }

func (b *awsKMSBackend) Close() error { return nil }

// aliasName maps a deployment label to a fully qualified KMS alias, sanitizing to
// the alias charset (alphanumerics plus /_-).
func (b *awsKMSBackend) aliasName(label string) string {
	raw := b.prefix + label
	var sb strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '/', r == '_', r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	return "alias/" + sb.String()
}

func (b *awsKMSBackend) Ping(ctx context.Context) error {
	if _, err := b.client.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(1)}); err != nil {
		return fmt.Errorf("keyprovider: AWS KMS unreachable: %w", err)
	}
	return nil
}

func (b *awsKMSBackend) CreateKey(ctx context.Context, label, keyType string) (*RemoteKey, error) {
	spec, err := awsKeySpec(keyType)
	if err != nil {
		return nil, err
	}
	alias := b.aliasName(label)
	// Fail if the alias is already taken, preserving the Provider contract that a
	// duplicate label is an error rather than a silent second key.
	if _, derr := b.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(alias)}); derr == nil {
		return nil, fmt.Errorf("keyprovider: AWS KMS key %q already exists", label)
	} else if !isAWSNotFound(derr) {
		return nil, fmt.Errorf("keyprovider: checking AWS KMS key %q: %w", label, derr)
	}
	out, err := b.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:     spec,
		KeyUsage:    kmstypes.KeyUsageTypeSignVerify,
		Description: aws.String("secsy-pki " + label),
	})
	if err != nil {
		return nil, fmt.Errorf("keyprovider: AWS KMS CreateKey: %w", err)
	}
	keyID := aws.ToString(out.KeyMetadata.KeyId)
	if _, err := b.client.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(alias),
		TargetKeyId: aws.String(keyID),
	}); err != nil {
		return nil, fmt.Errorf("keyprovider: AWS KMS CreateAlias for %q: %w", label, err)
	}
	pub, err := b.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return &RemoteKey{
		Label:     label,
		KeyID:     keyID,
		KeyType:   keyType,
		PublicKey: pub,
		URI:       awsKMSURI(keyID),
	}, nil
}

func (b *awsKMSBackend) ResolveKey(ctx context.Context, label string) (*RemoteKey, error) {
	alias := b.aliasName(label)
	out, err := b.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(alias)})
	if err != nil {
		if isAWSNotFound(err) {
			return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, label)
		}
		return nil, fmt.Errorf("keyprovider: AWS KMS DescribeKey %q: %w", label, err)
	}
	keyID := aws.ToString(out.KeyMetadata.KeyId)
	keyType, err := awsKeyTypeFromSpec(out.KeyMetadata.KeySpec)
	if err != nil {
		return nil, err
	}
	pub, err := b.getPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return &RemoteKey{
		Label:     label,
		KeyID:     keyID,
		KeyType:   keyType,
		PublicKey: pub,
		URI:       awsKMSURI(keyID),
	}, nil
}

func (b *awsKMSBackend) ListKeys(ctx context.Context) ([]RemoteKey, error) {
	prefix := "alias/" + b.prefix
	var out []RemoteKey
	paginator := kms.NewListAliasesPaginator(b.client, &kms.ListAliasesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("keyprovider: AWS KMS ListAliases: %w", err)
		}
		for _, a := range page.Aliases {
			name := aws.ToString(a.AliasName)
			if !strings.HasPrefix(name, prefix) || a.TargetKeyId == nil {
				continue
			}
			label := strings.TrimPrefix(name, "alias/"+b.prefix)
			rk := RemoteKey{Label: label, KeyID: aws.ToString(a.TargetKeyId), URI: awsKMSURI(aws.ToString(a.TargetKeyId))}
			// Best-effort enrichment; a permissions gap on one key still lists it.
			if dk, derr := b.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: a.TargetKeyId}); derr == nil {
				if kt, kerr := awsKeyTypeFromSpec(dk.KeyMetadata.KeySpec); kerr == nil {
					rk.KeyType = kt
				}
			}
			out = append(out, rk)
		}
	}
	return out, nil
}

func (b *awsKMSBackend) Sign(ctx context.Context, keyID, keyType string, digest []byte, hash crypto.Hash, pss bool) ([]byte, error) {
	algo, err := awsSigningAlgorithm(keyType, hash, pss)
	if err != nil {
		return nil, err
	}
	out, err := b.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: algo,
	})
	if err != nil {
		return nil, fmt.Errorf("keyprovider: AWS KMS Sign: %w", err)
	}
	return out.Signature, nil
}

func (b *awsKMSBackend) getPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	out, err := b.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("keyprovider: AWS KMS GetPublicKey: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: parsing AWS KMS public key: %w", err)
	}
	return pub, nil
}

// isAWSNotFound reports whether an AWS error is a NotFoundException.
func isAWSNotFound(err error) bool {
	var nf *kmstypes.NotFoundException
	return errors.As(err, &nf)
}

func awsKMSURI(keyID string) string { return "kms:aws:" + keyID }

func awsKeySpec(keyType string) (kmstypes.KeySpec, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return kmstypes.KeySpecEccNistP256, nil
	case KeyTypeECDSAP384:
		return kmstypes.KeySpecEccNistP384, nil
	case KeyTypeECDSAP521:
		return kmstypes.KeySpecEccNistP521, nil
	case KeyTypeRSA2048:
		return kmstypes.KeySpecRsa2048, nil
	case KeyTypeRSA3072:
		return kmstypes.KeySpecRsa3072, nil
	case KeyTypeRSA4096:
		return kmstypes.KeySpecRsa4096, nil
	default:
		return "", fmt.Errorf("keyprovider: AWS KMS unsupported key type %q", keyType)
	}
}

func awsKeyTypeFromSpec(spec kmstypes.KeySpec) (string, error) {
	switch spec {
	case kmstypes.KeySpecEccNistP256:
		return KeyTypeECDSAP256, nil
	case kmstypes.KeySpecEccNistP384:
		return KeyTypeECDSAP384, nil
	case kmstypes.KeySpecEccNistP521:
		return KeyTypeECDSAP521, nil
	case kmstypes.KeySpecRsa2048:
		return KeyTypeRSA2048, nil
	case kmstypes.KeySpecRsa3072:
		return KeyTypeRSA3072, nil
	case kmstypes.KeySpecRsa4096:
		return KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("keyprovider: AWS KMS unsupported key spec %q", spec)
	}
}

// awsSigningAlgorithm maps a key family, digest, and PSS flag to the KMS signing
// algorithm. It rejects combinations the CA/TSA/OCSP paths never emit.
func awsSigningAlgorithm(keyType string, hash crypto.Hash, pss bool) (kmstypes.SigningAlgorithmSpec, error) {
	isRSA := keyType == KeyTypeRSA2048 || keyType == KeyTypeRSA3072 || keyType == KeyTypeRSA4096
	if isRSA {
		switch {
		case pss && hash == crypto.SHA256:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha256, nil
		case pss && hash == crypto.SHA384:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha384, nil
		case pss && hash == crypto.SHA512:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha512, nil
		case !pss && hash == crypto.SHA256:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case !pss && hash == crypto.SHA384:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case !pss && hash == crypto.SHA512:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
		return "", fmt.Errorf("keyprovider: AWS KMS unsupported RSA hash %v", hash)
	}
	switch hash {
	case crypto.SHA256:
		return kmstypes.SigningAlgorithmSpecEcdsaSha256, nil
	case crypto.SHA384:
		return kmstypes.SigningAlgorithmSpecEcdsaSha384, nil
	case crypto.SHA512:
		return kmstypes.SigningAlgorithmSpecEcdsaSha512, nil
	default:
		return "", fmt.Errorf("keyprovider: AWS KMS unsupported ECDSA hash %v", hash)
	}
}

var _ KMSBackend = (*awsKMSBackend)(nil)
