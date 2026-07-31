package keyprovider

// This file adds a Google Cloud KMS backend to the cloud-KMS key provider,
// alongside the Task 41 AWS KMS / Azure Key Vault backends and the Task 92
// HashiCorp Vault Transit backend. Signing keys live as Cloud KMS
// CryptoKeyVersions inside a key ring: generation, signing, and public-key
// export all happen through the Cloud KMS API, and there is no operation that
// returns private key material — the non-extractability invariant an HSM
// provides, enforced here at the type level (see kms.go's KMSBackend). See
// docs/cloud-kms.md for the IAM / key-ring prerequisites.

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/auth/credentials"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// gcpCloudPlatformScope is the OAuth2 scope covering Cloud KMS and Secret Manager,
// requested when an explicit service-account key is loaded.
const gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// KMSBackendGCP selects Google Cloud KMS as the cloud-KMS backend. Keys are
// provisioned as ASYMMETRIC_SIGN CryptoKeys under a pre-existing key ring and
// addressed by a CryptoKey id derived from the deployment label; signing and
// public-key export go through the Cloud KMS API.
const KMSBackendGCP = "gcpkms"

// GCP CryptoKeyVersion generation can be asynchronous (particularly for the HSM
// protection level): the auto-created first version starts in
// PENDING_GENERATION and GetPublicKey fails until it becomes ENABLED. These
// bound a best-effort wait in CreateKey so a freshly provisioned key is usable
// on return, while still honoring the caller's context deadline.
const (
	gcpVersionReadyAttempts = 30
	gcpVersionReadyBackoff  = 1 * time.Second
)

// GCPKMSSettings configures the Google Cloud KMS backend (Backend == "gcpkms").
// Credentials follow Application Default Credentials by default (workload
// identity, GOOGLE_APPLICATION_CREDENTIALS, gcloud login); an explicit
// service-account key may instead be supplied by file path or inline JSON.
type GCPKMSSettings struct {
	// Project is the GCP project id that owns the key ring. Required.
	Project string
	// Location is the Cloud KMS location, e.g. "global" or "europe-west1".
	// Required; it must match the key ring's location.
	Location string
	// KeyRing is the id of a pre-existing key ring within Project/Location that
	// holds this deployment's signing keys. Required. secsy-pki does not create
	// key rings (that is an infrastructure/IAM concern); it creates CryptoKeys
	// inside this ring.
	KeyRing string
	// CredentialsFile is the path to a service-account JSON key file. When set it
	// overrides Application Default Credentials. Prefer ADC / workload identity in
	// production and reserve this for environments without a metadata server.
	CredentialsFile string
	// CredentialsJSON is the inline service-account JSON key. It is a credential
	// (it embeds a private key); prefer CredentialsFile or ADC. Redacted from any
	// dumped config.
	CredentialsJSON string
	// ProtectionLevel selects where the key material lives: "software" (default),
	// "hsm" (Cloud HSM, FIPS 140-2 L3), or "external". "hsm" keeps CA/TSA keys in
	// a hardware module, matching the on-prem PKCS#11 posture.
	ProtectionLevel string
	// RSAPSS provisions new RSA keys with an RSASSA-PSS algorithm instead of the
	// default RSASSA-PKCS1v1.5. It only affects key creation; signing with either
	// scheme is supported for keys that already exist. The default (false) matches
	// the Go x509 default for RSA CA keys.
	RSAPSS bool
	// Endpoint overrides the Cloud KMS API endpoint, for a local KMS emulator or
	// test double. When set, request authentication is disabled (emulators are
	// unauthenticated). Leave empty for the real service.
	Endpoint string
}

// gcpKMSClient is the narrow subset of the Cloud KMS API the backend uses,
// declared as an interface so an in-memory fake can substitute for the real
// *kms.KeyManagementClient in tests. The list methods return slices rather than
// the SDK's concrete iterator types so the interface is implementable without
// the SDK. Documenting the surface here also names the exact IAM permissions
// required: cloudkms.cryptoKeys.{create,get,list}, cloudkms.cryptoKeyVersions.
// {list,viewPublicKey,useToSign}, and cloudkms.keyRings.get.
type gcpKMSClient interface {
	CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) ([]*kmspb.CryptoKey, error)
	ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) ([]*kmspb.CryptoKeyVersion, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error)
	Close() error
}

// gcpKMSBackend implements KMSBackend against Google Cloud KMS.
type gcpKMSBackend struct {
	client     gcpKMSClient
	keyRing    string // full resource name: projects/P/locations/L/keyRings/R
	prefix     string // sanitized label prefix, forming the CryptoKey id
	protection kmspb.ProtectionLevel
	rsaPSS     bool
}

// newGCPKMSBackend constructs the Google Cloud KMS backend. It validates the
// static configuration and builds the API client (which resolves credentials
// lazily via ADC or the supplied service-account key); no network I/O happens
// until the first key operation or Ping.
func newGCPKMSBackend(cfg KMSSettings) (KMSBackend, error) {
	g := cfg.GCP
	if strings.TrimSpace(g.Project) == "" {
		return nil, fmt.Errorf("keyprovider: gcp kms: project is required")
	}
	if strings.TrimSpace(g.Location) == "" {
		return nil, fmt.Errorf("keyprovider: gcp kms: location is required")
	}
	if strings.TrimSpace(g.KeyRing) == "" {
		return nil, fmt.Errorf("keyprovider: gcp kms: key_ring is required")
	}
	protection, err := gcpProtectionLevel(g.ProtectionLevel)
	if err != nil {
		return nil, err
	}
	opts, err := gcpClientOptions(g.CredentialsFile, g.CredentialsJSON, g.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms: %w", err)
	}
	client, err := kms.NewKeyManagementClient(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms: creating client: %w", err)
	}
	return &gcpKMSBackend{
		client:     &gcpAPIClient{inner: client},
		keyRing:    fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.Project, g.Location, g.KeyRing),
		prefix:     gcpSanitize(cfg.KeyPrefix),
		protection: protection,
		rsaPSS:     g.RSAPSS,
	}, nil
}

// gcpClientOptions builds the client options for the Cloud KMS / Secret Manager
// clients from the credential settings. With neither a credentials file nor
// inline JSON, no auth option is added and the client falls back to Application
// Default Credentials (the recommended path). When Endpoint is set (an emulator)
// authentication is disabled, since emulators are unauthenticated. It is shared
// by the KMS backend and the Secret Manager PIN source.
func gcpClientOptions(credentialsFile, credentialsJSON, endpoint string) ([]option.ClientOption, error) {
	if e := strings.TrimSpace(endpoint); e != "" {
		return []option.ClientOption{option.WithEndpoint(e), option.WithoutAuthentication()}, nil
	}
	// Load an explicit service-account key (file or inline JSON) into a credentials
	// object; empty settings leave it to the client's own ADC resolution. The
	// credential type is pinned to ServiceAccount (rather than the deprecated,
	// unvalidated CredentialsFile/JSON detect fields) so a config that is not a
	// plain service-account key — an external_account with attacker-controlled URLs,
	// say — is rejected rather than trusted.
	detect := &credentials.DetectOptions{Scopes: []string{gcpCloudPlatformScope}}
	switch {
	case strings.TrimSpace(credentialsFile) != "":
		creds, err := credentials.NewCredentialsFromFile(credentials.ServiceAccount, strings.TrimSpace(credentialsFile), detect)
		if err != nil {
			return nil, fmt.Errorf("loading service-account key file: %w", err)
		}
		return []option.ClientOption{option.WithAuthCredentials(creds)}, nil
	case strings.TrimSpace(credentialsJSON) != "":
		creds, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, []byte(credentialsJSON), detect)
		if err != nil {
			return nil, fmt.Errorf("loading service-account key JSON: %w", err)
		}
		return []option.ClientOption{option.WithAuthCredentials(creds)}, nil
	default:
		return nil, nil // Application Default Credentials
	}
}

func (b *gcpKMSBackend) BackendName() string { return KMSBackendGCP }

func (b *gcpKMSBackend) Close() error { return b.client.Close() }

// cryptoKeyID maps a deployment label to a Cloud KMS CryptoKey id, sanitized to
// the id charset ([a-zA-Z0-9_-], <=63 chars).
func (b *gcpKMSBackend) cryptoKeyID(label string) string {
	return gcpSanitize(b.prefix + label)
}

// cryptoKeyName is the full resource name of a CryptoKey for a label.
func (b *gcpKMSBackend) cryptoKeyName(label string) string {
	return b.keyRing + "/cryptoKeys/" + b.cryptoKeyID(label)
}

// Ping verifies the key ring is reachable and the credentials are authorized by
// reading the key-ring resource. It requires no particular key to exist.
func (b *gcpKMSBackend) Ping(ctx context.Context) error {
	if _, err := b.client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: b.keyRing}); err != nil {
		return fmt.Errorf("keyprovider: gcp kms key ring %q unreachable: %w", b.keyRing, err)
	}
	return nil
}

func (b *gcpKMSBackend) CreateKey(ctx context.Context, label, keyType string) (*RemoteKey, error) {
	if strings.TrimSpace(label) == "" {
		return nil, fmt.Errorf("keyprovider: gcp kms: empty label")
	}
	algorithm, err := gcpAlgorithmForKey(keyType, b.rsaPSS)
	if err != nil {
		return nil, err
	}
	id := b.cryptoKeyID(label)
	// Fail if the CryptoKey already exists, preserving the Provider contract that a
	// duplicate label is an error rather than a silent second key.
	name := b.cryptoKeyName(label)
	if _, gerr := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name}); gerr == nil {
		return nil, fmt.Errorf("keyprovider: gcp kms key %q already exists", label)
	} else if !isGCPNotFound(gerr) {
		return nil, fmt.Errorf("keyprovider: gcp kms checking key %q: %w", label, gerr)
	}
	if _, err := b.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      b.keyRing,
		CryptoKeyId: id,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: b.protection,
				Algorithm:       algorithm,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms CreateCryptoKey %q: %w", label, err)
	}
	// The first version is auto-created; wait for it to finish generating so the
	// returned key is immediately usable.
	return b.remoteForVersion(ctx, label, name+"/cryptoKeyVersions/1", true)
}

func (b *gcpKMSBackend) ResolveKey(ctx context.Context, label string) (*RemoteKey, error) {
	name := b.cryptoKeyName(label)
	if _, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name}); err != nil {
		if isGCPNotFound(err) {
			return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, label)
		}
		return nil, fmt.Errorf("keyprovider: gcp kms GetCryptoKey %q: %w", label, err)
	}
	versionName, err := b.latestEnabledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	return b.remoteForVersion(ctx, label, versionName, false)
}

func (b *gcpKMSBackend) ListKeys(ctx context.Context) ([]RemoteKey, error) {
	keys, err := b.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: b.keyRing})
	if err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms ListCryptoKeys: %w", err)
	}
	var out []RemoteKey
	for _, ck := range keys {
		if ck.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN {
			continue
		}
		id := lastSegment(ck.GetName())
		if !strings.HasPrefix(id, b.prefix) {
			continue
		}
		label := strings.TrimPrefix(id, b.prefix)
		rk := RemoteKey{Label: label, KeyID: ck.GetName(), URI: gcpKMSURI(ck.GetName())}
		// Best-effort key-type enrichment from the key's version template; a key
		// with an unrecognized algorithm still lists.
		if vt := ck.GetVersionTemplate(); vt != nil {
			if kt, kerr := gcpKeyTypeFromAlgorithm(vt.GetAlgorithm()); kerr == nil {
				rk.KeyType = kt
			}
		}
		out = append(out, rk)
	}
	return out, nil
}

func (b *gcpKMSBackend) Sign(ctx context.Context, keyID, keyType string, digest []byte, hash crypto.Hash, _ bool) ([]byte, error) {
	dg, err := gcpDigest(hash, digest)
	if err != nil {
		return nil, err
	}
	// The signature scheme (PKCS#1 v1.5 vs PSS) is determined by the CryptoKey
	// version's own algorithm, not by the request, so the caller's pss flag is not
	// forwarded; the digest field must match the algorithm's hash, which Cloud KMS
	// validates and rejects on mismatch (fail closed).
	resp, err := b.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: keyID, Digest: dg})
	if err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms AsymmetricSign: %w", err)
	}
	if err := verifyGCPCRC32C(resp.GetSignature(), resp.GetSignatureCrc32C().GetValue()); err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms signature integrity check failed: %w", err)
	}
	return resp.GetSignature(), nil
}

// remoteForVersion fetches the public key for a CryptoKeyVersion and builds the
// non-sensitive RemoteKey. When wait is set (the create path) it retries while
// the version is still generating.
func (b *gcpKMSBackend) remoteForVersion(ctx context.Context, label, versionName string, wait bool) (*RemoteKey, error) {
	pub, keyType, err := b.publicKey(ctx, versionName, wait)
	if err != nil {
		return nil, err
	}
	return &RemoteKey{
		Label:     label,
		KeyID:     versionName,
		KeyType:   keyType,
		PublicKey: pub,
		URI:       gcpKMSURI(versionName),
	}, nil
}

// publicKey retrieves and parses the public key of a CryptoKeyVersion, returning
// it together with the canonical key type derived from the version's algorithm.
// When wait is set it retries while Cloud KMS reports the version is still
// generating (PENDING_GENERATION surfaces as FailedPrecondition/NotFound).
func (b *gcpKMSBackend) publicKey(ctx context.Context, versionName string, wait bool) (crypto.PublicKey, string, error) {
	attempts := 1
	if wait {
		attempts = gcpVersionReadyAttempts
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		pk, err := b.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err == nil {
			keyType, kerr := gcpKeyTypeFromAlgorithm(pk.GetAlgorithm())
			if kerr != nil {
				return nil, "", kerr
			}
			pub, perr := parseGCPPublicKey(pk.GetPem(), pk.GetPemCrc32C().GetValue())
			if perr != nil {
				return nil, "", perr
			}
			return pub, keyType, nil
		}
		lastErr = err
		if !wait || !gcpVersionPending(err) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(gcpVersionReadyBackoff):
		}
	}
	return nil, "", fmt.Errorf("keyprovider: gcp kms GetPublicKey %q: %w", versionName, lastErr)
}

// latestEnabledVersion returns the resource name of the newest ENABLED version
// of a CryptoKey. secsy-pki rotates CA keys at the CA layer (a new labelled key),
// not by rotating a Cloud KMS version in place, but an operator may still have
// rotated the underlying version, so the newest enabled one is selected.
func (b *gcpKMSBackend) latestEnabledVersion(ctx context.Context, cryptoKeyName string) (string, error) {
	versions, err := b.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: cryptoKeyName})
	if err != nil {
		return "", fmt.Errorf("keyprovider: gcp kms ListCryptoKeyVersions %q: %w", cryptoKeyName, err)
	}
	var enabled []string
	for _, v := range versions {
		if v.GetState() == kmspb.CryptoKeyVersion_ENABLED {
			enabled = append(enabled, v.GetName())
		}
	}
	if len(enabled) == 0 {
		return "", fmt.Errorf("keyprovider: gcp kms key %q has no enabled version", lastSegment(cryptoKeyName))
	}
	// Sort by the trailing integer version id so the newest is last.
	sort.Slice(enabled, func(i, j int) bool {
		return versionNumber(enabled[i]) < versionNumber(enabled[j])
	})
	return enabled[len(enabled)-1], nil
}

// gcpAPIClient adapts the concrete *kms.KeyManagementClient to the gcpKMSClient
// interface, draining the SDK's list iterators into slices.
type gcpAPIClient struct {
	inner *kms.KeyManagementClient
}

func (c *gcpAPIClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return c.inner.CreateCryptoKey(ctx, req)
}

func (c *gcpAPIClient) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return c.inner.GetCryptoKey(ctx, req)
}

func (c *gcpAPIClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	return c.inner.GetPublicKey(ctx, req)
}

func (c *gcpAPIClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return c.inner.AsymmetricSign(ctx, req)
}

func (c *gcpAPIClient) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	return c.inner.GetKeyRing(ctx, req)
}

func (c *gcpAPIClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) ([]*kmspb.CryptoKey, error) {
	it := c.inner.ListCryptoKeys(ctx, req)
	var out []*kmspb.CryptoKey
	for {
		ck, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, ck)
	}
	return out, nil
}

func (c *gcpAPIClient) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) ([]*kmspb.CryptoKeyVersion, error) {
	it := c.inner.ListCryptoKeyVersions(ctx, req)
	var out []*kmspb.CryptoKeyVersion
	for {
		v, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (c *gcpAPIClient) Close() error { return c.inner.Close() }

// --- helpers ----------------------------------------------------------------

// gcpProtectionLevel maps the configured protection level to the proto enum.
func gcpProtectionLevel(level string) (kmspb.ProtectionLevel, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "software":
		return kmspb.ProtectionLevel_SOFTWARE, nil
	case "hsm":
		return kmspb.ProtectionLevel_HSM, nil
	case "external":
		return kmspb.ProtectionLevel_EXTERNAL, nil
	default:
		return 0, fmt.Errorf("keyprovider: gcp kms: invalid protection_level %q (must be \"software\", \"hsm\", or \"external\")", level)
	}
}

// gcpAlgorithmForKey maps a canonical key type (and the RSA scheme choice) to a
// Cloud KMS signing algorithm. Cloud KMS does not offer ECDSA P-521, so it is
// rejected with a clear error even though the other cloud backends support it.
func gcpAlgorithmForKey(keyType string, pss bool) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	case KeyTypeECDSAP384:
		return kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	case KeyTypeECDSAP521:
		return 0, fmt.Errorf("keyprovider: gcp kms does not support key type %q (Cloud KMS offers no EC_SIGN_P521); use ecdsa-p256/p384 or an RSA key", keyType)
	case KeyTypeRSA2048:
		if pss {
			return kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, nil
		}
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, nil
	case KeyTypeRSA3072:
		if pss {
			return kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, nil
		}
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, nil
	case KeyTypeRSA4096:
		if pss {
			return kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, nil
		}
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, nil
	default:
		return 0, fmt.Errorf("keyprovider: gcp kms unsupported key type %q (supported: %s, %s, %s, %s, %s)",
			keyType, KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096)
	}
}

// gcpKeyTypeFromAlgorithm maps a Cloud KMS signing algorithm back to a canonical
// key type, covering both the PKCS#1 v1.5 and PSS RSA families.
func gcpKeyTypeFromAlgorithm(a kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (string, error) {
	switch a {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return KeyTypeECDSAP256, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return KeyTypeECDSAP384, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:
		return KeyTypeRSA2048, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:
		return KeyTypeRSA3072, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("keyprovider: gcp kms unsupported signing algorithm %q", a.String())
	}
}

// gcpDigest wraps a precomputed digest in the request field matching its hash.
// Cloud KMS validates the digest length against the key's bound algorithm.
func gcpDigest(hash crypto.Hash, digest []byte) (*kmspb.Digest, error) {
	switch hash {
	case crypto.SHA256:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}, nil
	case crypto.SHA384:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}, nil
	case crypto.SHA512:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}, nil
	case 0:
		return nil, fmt.Errorf("keyprovider: gcp kms signing requires a hash")
	default:
		return nil, fmt.Errorf("keyprovider: gcp kms unsupported digest algorithm %v", hash)
	}
}

// parseGCPPublicKey decodes the PEM public key Cloud KMS returns. When Cloud KMS
// supplies a non-zero CRC32C over the PEM it is verified first, guarding against
// corruption of the public key in transit.
func parseGCPPublicKey(pemStr string, pemCRC int64) (crypto.PublicKey, error) {
	if err := verifyGCPCRC32C([]byte(pemStr), pemCRC); err != nil {
		return nil, fmt.Errorf("keyprovider: gcp kms public-key PEM failed its CRC32C integrity check: %w", err)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("keyprovider: gcp kms returned a public key that is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: parsing gcp kms public key: %w", err)
	}
	return pub, nil
}

// crc32cTable is the Castagnoli table Cloud KMS uses for its integrity CRCs.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// verifyGCPCRC32C checks a Cloud KMS-supplied CRC32C over a returned blob (e.g.
// a signature). A nil/zero CRC (as an emulator or the fake may omit) is skipped.
func verifyGCPCRC32C(data []byte, crc int64) error {
	if crc == 0 {
		return nil
	}
	if uint32(crc) != crc32.Checksum(data, crc32cTable) {
		return fmt.Errorf("CRC32C mismatch")
	}
	return nil
}

// gcpVersionPending reports whether an error means a CryptoKeyVersion is still
// being generated (so a create-time wait should retry rather than give up).
func gcpVersionPending(err error) bool {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.NotFound:
		return true
	default:
		return false
	}
}

// isGCPNotFound reports whether an error is a gRPC NotFound status.
func isGCPNotFound(err error) bool { return status.Code(err) == codes.NotFound }

// gcpKMSURI synthesizes a stable kms: URI for a Cloud KMS resource name.
func gcpKMSURI(resourceName string) string { return "kms:gcpkms:" + resourceName }

// gcpSanitize maps an arbitrary string to the Cloud KMS id charset
// ([a-zA-Z0-9_-], at most 63 characters), so a deployment label or prefix forms
// a valid CryptoKey id.
func gcpSanitize(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	out := sb.String()
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// lastSegment returns the final path segment of a slash-separated resource name.
func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// versionNumber extracts the trailing integer version id from a CryptoKeyVersion
// resource name (…/cryptoKeyVersions/N), or 0 when it is not numeric.
func versionNumber(versionName string) int {
	n, err := strconv.Atoi(lastSegment(versionName))
	if err != nil {
		return 0
	}
	return n
}

var _ KMSBackend = (*gcpKMSBackend)(nil)
