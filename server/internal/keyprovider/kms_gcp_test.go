package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeGCPKMSClient is an in-memory emulation of the Cloud KMS API surface the
// gcpKMSBackend uses. It generates real asymmetric keys with the Go standard
// library and signs in-memory, applying the signature scheme bound to each key's
// algorithm exactly as Cloud KMS does — but exposes only the gcpKMSClient
// interface (no private-key export), so it faithfully models the trust boundary
// while requiring no cloud credentials. It returns gRPC status errors so the
// backend's NotFound handling is exercised. Optional fault hooks let tests force
// integrity-check failures. It is safe for concurrent use.
type fakeGCPKMSClient struct {
	mu       sync.Mutex
	keyRing  string
	keys     map[string]*fakeGCPKey // keyed by CryptoKey resource name
	corrupt  bool                   // when set, returned CRC32Cs are wrong (fault injection)
	pending  bool                   // when set, the first GetPublicKey per version reports "still generating"
	seenOnce map[string]bool
}

type fakeGCPKey struct {
	name       string
	algorithm  kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	protection kmspb.ProtectionLevel
	versions   []*fakeGCPVersion
}

type fakeGCPVersion struct {
	name  string
	state kmspb.CryptoKeyVersion_CryptoKeyVersionState
	priv  crypto.Signer
}

func newFakeGCPKMSClient(keyRing string) *fakeGCPKMSClient {
	return &fakeGCPKMSClient{keyRing: keyRing, keys: map[string]*fakeGCPKey{}, seenOnce: map[string]bool{}}
}

func (c *fakeGCPKMSClient) Close() error { return nil }

func (c *fakeGCPKMSClient) GetKeyRing(_ context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if req.GetName() != c.keyRing {
		return nil, status.Errorf(codes.NotFound, "key ring %q not found", req.GetName())
	}
	return &kmspb.KeyRing{Name: c.keyRing}, nil
}

func (c *fakeGCPKMSClient) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if req.GetParent() != c.keyRing {
		return nil, status.Errorf(codes.NotFound, "key ring %q not found", req.GetParent())
	}
	name := req.GetParent() + "/cryptoKeys/" + req.GetCryptoKeyId()
	if _, ok := c.keys[name]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "crypto key %q exists", name)
	}
	ck := req.GetCryptoKey()
	algo := ck.GetVersionTemplate().GetAlgorithm()
	keyType, err := gcpKeyTypeFromAlgorithm(algo)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	priv, err := generateKMSKey(keyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	state := kmspb.CryptoKeyVersion_ENABLED
	if c.pending {
		state = kmspb.CryptoKeyVersion_PENDING_GENERATION
	}
	k := &fakeGCPKey{name: name, algorithm: algo, protection: ck.GetVersionTemplate().GetProtectionLevel()}
	k.versions = append(k.versions, &fakeGCPVersion{name: name + "/cryptoKeyVersions/1", state: state, priv: priv})
	c.keys[name] = k
	return c.cryptoKeyProto(k), nil
}

func (c *fakeGCPKMSClient) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.keys[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "crypto key %q not found", req.GetName())
	}
	return c.cryptoKeyProto(k), nil
}

func (c *fakeGCPKMSClient) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) ([]*kmspb.CryptoKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*kmspb.CryptoKey
	for _, k := range c.keys {
		if strings.HasPrefix(k.name, req.GetParent()+"/cryptoKeys/") {
			out = append(out, c.cryptoKeyProto(k))
		}
	}
	return out, nil
}

func (c *fakeGCPKMSClient) ListCryptoKeyVersions(_ context.Context, req *kmspb.ListCryptoKeyVersionsRequest) ([]*kmspb.CryptoKeyVersion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.keys[req.GetParent()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "crypto key %q not found", req.GetParent())
	}
	var out []*kmspb.CryptoKeyVersion
	for _, v := range k.versions {
		out = append(out, &kmspb.CryptoKeyVersion{Name: v.name, State: v.state, Algorithm: k.algorithm})
	}
	return out, nil
}

func (c *fakeGCPKMSClient) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ver := c.findVersion(req.GetName())
	if ver == nil {
		return nil, status.Errorf(codes.NotFound, "version %q not found", req.GetName())
	}
	// Model asynchronous generation: report the first probe as still generating.
	if c.pending && !c.seenOnce[ver.name] {
		c.seenOnce[ver.name] = true
		ver.state = kmspb.CryptoKeyVersion_ENABLED
		return nil, status.Errorf(codes.FailedPrecondition, "version %q is not enabled", req.GetName())
	}
	der, err := x509.MarshalPKIXPublicKey(ver.priv.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	crc := int64(crc32.Checksum([]byte(pemStr), crc32cTable))
	if c.corrupt {
		crc++
	}
	return &kmspb.PublicKey{
		Pem:             pemStr,
		Algorithm:       key.algorithm,
		Name:            ver.name,
		ProtectionLevel: key.protection,
		PemCrc32C:       wrapperspb.Int64(crc),
	}, nil
}

func (c *fakeGCPKMSClient) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ver := c.findVersion(req.GetName())
	if ver == nil {
		return nil, status.Errorf(codes.NotFound, "version %q not found", req.GetName())
	}
	digest := digestBytes(req.GetDigest())
	if digest == nil {
		return nil, status.Errorf(codes.InvalidArgument, "no digest")
	}
	sig, err := fakeGCPSign(ver.priv, key.algorithm, digest)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	crc := int64(crc32.Checksum(sig, crc32cTable))
	if c.corrupt {
		crc++
	}
	return &kmspb.AsymmetricSignResponse{Signature: sig, SignatureCrc32C: wrapperspb.Int64(crc)}, nil
}

// findVersion locates a version by its resource name. Caller holds c.mu.
func (c *fakeGCPKMSClient) findVersion(versionName string) (*fakeGCPKey, *fakeGCPVersion) {
	for _, k := range c.keys {
		for _, v := range k.versions {
			if v.name == versionName {
				return k, v
			}
		}
	}
	return nil, nil
}

// cryptoKeyProto renders the non-sensitive proto view of a stored key. Caller
// holds c.mu.
func (c *fakeGCPKMSClient) cryptoKeyProto(k *fakeGCPKey) *kmspb.CryptoKey {
	return &kmspb.CryptoKey{
		Name:    k.name,
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: k.protection,
			Algorithm:       k.algorithm,
		},
	}
}

func digestBytes(d *kmspb.Digest) []byte {
	switch v := d.GetDigest().(type) {
	case *kmspb.Digest_Sha256:
		return v.Sha256
	case *kmspb.Digest_Sha384:
		return v.Sha384
	case *kmspb.Digest_Sha512:
		return v.Sha512
	default:
		return nil
	}
}

// fakeGCPSign signs a digest with the scheme bound to the key's algorithm,
// mirroring Cloud KMS (the scheme comes from the key, not the request).
func fakeGCPSign(priv crypto.Signer, algo kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, digest []byte) ([]byte, error) {
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		hash := crypto.SHA256
		switch algo {
		case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
			hash = crypto.SHA512
		}
		if isGCPPSSAlgorithm(algo) {
			return rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		}
		return rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	default:
		return nil, fmt.Errorf("fake gcp: unsupported key %T", priv)
	}
}

func isGCPPSSAlgorithm(a kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch a {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return true
	default:
		return false
	}
}

var _ gcpKMSClient = (*fakeGCPKMSClient)(nil)

// --- test helpers ------------------------------------------------------------

const testGCPKeyRing = "projects/secsy-test/locations/global/keyRings/pki"

// newFakeGCPBackend builds a gcpKMSBackend wired to a fresh in-memory fake
// client, the same shape newGCPKMSBackend produces against real Cloud KMS.
func newFakeGCPBackend(pss bool) *gcpKMSBackend {
	return &gcpKMSBackend{
		client:     newFakeGCPKMSClient(testGCPKeyRing),
		keyRing:    testGCPKeyRing,
		prefix:     gcpSanitize("secsy/"),
		protection: kmspb.ProtectionLevel_SOFTWARE,
		rsaPSS:     pss,
	}
}

func newFakeGCPProvider(t *testing.T, pss bool) *KMSProvider {
	t.Helper()
	p := NewKMSProviderWithBackend(newFakeGCPBackend(pss))
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// --- tests -------------------------------------------------------------------

// TestGCPKMSGenerateResolveSign exercises the whole provider surface for every
// GCP-supported key type: generate, resolve, export the public key, and sign a
// digest that must verify against the exported public half, plus a real x509
// self-signature.
func TestGCPKMSGenerateResolveSign(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		keyType string
		hash    crypto.Hash
	}{
		{KeyTypeECDSAP256, crypto.SHA256},
		{KeyTypeECDSAP384, crypto.SHA384},
		{KeyTypeRSA2048, crypto.SHA256},
		{KeyTypeRSA3072, crypto.SHA256},
		{KeyTypeRSA4096, crypto.SHA256},
	} {
		t.Run(tc.keyType, func(t *testing.T) {
			p := newFakeGCPProvider(t, false)
			label := "role-" + tc.keyType

			gen, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: tc.keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if gen.KeyType != tc.keyType {
				t.Errorf("KeyType = %q, want %q", gen.KeyType, tc.keyType)
			}
			if gen.PublicKey == nil {
				t.Fatal("nil public key")
			}
			if !strings.HasPrefix(gen.URI, "kms:gcpkms:") {
				t.Errorf("URI = %q, want kms:gcpkms: prefix", gen.URI)
			}

			found, err := p.FindKey(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("FindKey: %v", err)
			}
			if found.KeyType != tc.keyType {
				t.Errorf("FindKey KeyType = %q, want %q", found.KeyType, tc.keyType)
			}

			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			h := tc.hash.New()
			h.Write([]byte("hello gcp kms"))
			digest := h.Sum(nil)
			sig, err := signer.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			verifyDigest(t, gen.PublicKey, digest, sig, false)

			// The digest field passed to the KMS API must match the signature's hash,
			// so a real x509 signing round-trip is the ground truth.
			assertGCPSignsCert(t, signer, tc.keyType)
		})
	}
}

// assertGCPSignsCert signs a self-signed certificate through the provider signer
// and verifies it, the guarantee that matters for the CA/TSA roles.
func assertGCPSignsCert(t *testing.T, signer Signer, keyType string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "GCP KMS CA " + keyType},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signature verification failed: %v", err)
	}
}

// TestGCPKMSSignRSAPSS proves RSA-PSS keys (RSA_SIGN_PSS_*) are provisioned and
// sign correctly when the backend is configured for PSS.
func TestGCPKMSSignRSAPSS(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, true) // rsaPSS = true

	gen, err := p.GenerateKey(ctx, KeySpec{Label: "pss", KeyType: KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "pss"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	h := crypto.SHA256.New()
	h.Write([]byte("pss message"))
	digest := h.Sum(nil)
	sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}
	verifyDigest(t, gen.PublicKey, digest, sig, true)
}

// TestGCPKMSRejectsP521 confirms ECDSA P-521 is rejected with a clear error,
// since Cloud KMS offers no EC_SIGN_P521 algorithm.
func TestGCPKMSRejectsP521(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, false)
	_, err := p.GenerateKey(ctx, KeySpec{Label: "p521", KeyType: KeyTypeECDSAP521})
	if err == nil {
		t.Fatal("expected P-521 to be rejected by the GCP backend")
	}
	if !strings.Contains(err.Error(), "EC_SIGN_P521") {
		t.Errorf("error %q should mention the missing EC_SIGN_P521 algorithm", err)
	}
}

// TestGCPKMSListKeys checks the inventory surface reports keys as
// non-extractable and sensitive — the Cloud KMS trust boundary.
func TestGCPKMSListKeys(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, false)
	for _, l := range []string{"ca", "tsa", "ocsp"} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: l, KeyType: KeyTypeECDSAP256}); err != nil {
			t.Fatalf("GenerateKey %s: %v", l, err)
		}
	}
	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("ListKeys returned %d keys, want 3", len(keys))
	}
	for _, k := range keys {
		if k.Extractable {
			t.Errorf("key %q reported Extractable=true; Cloud KMS keys must be non-extractable", k.Label)
		}
		if !k.Sensitive {
			t.Errorf("key %q reported Sensitive=false", k.Label)
		}
		if k.KeyType != KeyTypeECDSAP256 {
			t.Errorf("key %q KeyType = %q, want %q", k.Label, k.KeyType, KeyTypeECDSAP256)
		}
	}
}

// TestGCPKMSPing verifies the reachability probe: it succeeds against the
// configured key ring and fails (fail-closed) when the ring is absent.
func TestGCPKMSPing(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, false)
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// A backend pointed at a non-existent key ring must fail its probe.
	bad := &gcpKMSBackend{client: newFakeGCPKMSClient("projects/x/locations/global/keyRings/other"), keyRing: testGCPKeyRing}
	if err := bad.Ping(ctx); err == nil {
		t.Fatal("expected Ping to fail for a missing key ring")
	}
}

// TestGCPKMSDuplicateLabelRejected mirrors the PKCS#11/software contract: a
// second key with an existing label is an error.
func TestGCPKMSDuplicateLabelRejected(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, false)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err == nil {
		t.Fatal("expected duplicate label to be rejected")
	}
}

// TestGCPKMSFindNotFound checks the ErrKeyNotFound contract.
func TestGCPKMSFindNotFound(t *testing.T) {
	ctx := context.Background()
	p := newFakeGCPProvider(t, false)
	if _, err := p.FindKey(ctx, KeyRef{Label: "nope"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestGCPKMSIntegrityChecks proves the CRC32C integrity checks fail closed: a
// corrupted signature or public-key CRC surfaces as an error rather than a
// silently-wrong result.
func TestGCPKMSIntegrityChecks(t *testing.T) {
	ctx := context.Background()
	fake := newFakeGCPKMSClient(testGCPKeyRing)
	backend := &gcpKMSBackend{client: fake, keyRing: testGCPKeyRing, prefix: "", protection: kmspb.ProtectionLevel_SOFTWARE}
	p := NewKMSProviderWithBackend(backend)
	defer p.Close()

	if _, err := p.GenerateKey(ctx, KeySpec{Label: "crc", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "crc"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	// Now corrupt every returned CRC. The public-key CRC is checked on resolve and
	// the signature CRC on sign; both must fail.
	fake.corrupt = true
	digest := make([]byte, 32)
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA256); err == nil {
		t.Error("expected Sign to fail on a corrupted signature CRC32C")
	}
	if _, err := p.FindKey(ctx, KeyRef{Label: "crc"}); err == nil {
		t.Error("expected FindKey to fail on a corrupted public-key CRC32C")
	}
}

// TestGCPKMSPendingVersionWaits verifies CreateKey tolerates a version that is
// still generating: the first GetPublicKey reports FailedPrecondition, and the
// backend retries until the version is ENABLED.
func TestGCPKMSPendingVersionWaits(t *testing.T) {
	ctx := context.Background()
	fake := newFakeGCPKMSClient(testGCPKeyRing)
	fake.pending = true
	backend := &gcpKMSBackend{client: fake, keyRing: testGCPKeyRing, protection: kmspb.ProtectionLevel_SOFTWARE}
	p := NewKMSProviderWithBackend(backend)
	defer p.Close()

	gen, err := p.GenerateKey(ctx, KeySpec{Label: "async", KeyType: KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("GenerateKey with pending version: %v", err)
	}
	if gen.PublicKey == nil {
		t.Fatal("nil public key after waiting for generation")
	}
}

// TestGCPKMSBackendSelection proves kms.backend=gcpkms routes to the GCP backend
// through both the low-level dispatch and the public keyprovider.New entry point,
// without needing cloud credentials (an emulator endpoint disables auth).
func TestGCPKMSBackendSelection(t *testing.T) {
	settings := KMSSettings{
		Backend: KMSBackendGCP,
		GCP: GCPKMSSettings{
			Project:  "p",
			Location: "global",
			KeyRing:  "kr",
			Endpoint: "localhost:1", // emulator endpoint → WithoutAuthentication, lazy dial
		},
	}
	backend, err := newKMSBackend(settings)
	if err != nil {
		t.Fatalf("newKMSBackend(gcpkms): %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if backend.BackendName() != KMSBackendGCP {
		t.Errorf("BackendName = %q, want %q", backend.BackendName(), KMSBackendGCP)
	}
	if _, ok := backend.(*gcpKMSBackend); !ok {
		t.Errorf("backend type = %T, want *gcpKMSBackend", backend)
	}

	p, err := New(Config{Type: ProviderKMS, KMS: settings})
	if err != nil {
		t.Fatalf("New(kms gcpkms): %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if p.Name() != string(ProviderKMS) {
		t.Errorf("Name = %q, want %q", p.Name(), ProviderKMS)
	}
}

// TestGCPKMSMissingSettings confirms the required GCP fields are validated at
// construction with clear errors.
func TestGCPKMSMissingSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		gcp  GCPKMSSettings
		want string
	}{
		{"no project", GCPKMSSettings{Location: "global", KeyRing: "kr"}, "project is required"},
		{"no location", GCPKMSSettings{Project: "p", KeyRing: "kr"}, "location is required"},
		{"no key ring", GCPKMSSettings{Project: "p", Location: "global"}, "key_ring is required"},
		{"bad protection", GCPKMSSettings{Project: "p", Location: "global", KeyRing: "kr", ProtectionLevel: "bogus"}, "protection_level"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newKMSBackend(KMSSettings{Backend: KMSBackendGCP, GCP: tc.gcp})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// TestGCPKMSPerRoleIndependentBackends models per-role backend selection at the
// provider layer: a CA key and a TSA key living in independent GCP backends both
// sign correctly and do not see each other's keys.
func TestGCPKMSPerRoleIndependentBackends(t *testing.T) {
	ctx := context.Background()
	caProv := newFakeGCPProvider(t, false)
	tsaProv := newFakeGCPProvider(t, false)

	if _, err := caProv.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("ca GenerateKey: %v", err)
	}
	if _, err := tsaProv.GenerateKey(ctx, KeySpec{Label: "tsa", KeyType: KeyTypeRSA2048}); err != nil {
		t.Fatalf("tsa GenerateKey: %v", err)
	}
	// The TSA backend must not see the CA's key and vice versa.
	if _, err := tsaProv.FindKey(ctx, KeyRef{Label: "ca"}); err == nil {
		t.Error("tsa backend unexpectedly resolved the ca key")
	}
	if _, err := caProv.FindKey(ctx, KeyRef{Label: "tsa"}); err == nil {
		t.Error("ca backend unexpectedly resolved the tsa key")
	}

	// Both sign under their own key type.
	for _, tc := range []struct {
		prov  *KMSProvider
		label string
	}{{caProv, "ca"}, {tsaProv, "tsa"}} {
		signer, err := tc.prov.Signer(ctx, KeyRef{Label: tc.label})
		if err != nil {
			t.Fatalf("%s Signer: %v", tc.label, err)
		}
		digest := make([]byte, 32)
		sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Fatalf("%s Sign: %v", tc.label, err)
		}
		verifyDigest(t, signer.Public(), digest, sig, false)
		signer.Close()
	}
}

// TestGCPSanitize checks the CryptoKey id sanitizer honors the id charset and
// length limit.
func TestGCPSanitize(t *testing.T) {
	if got := gcpSanitize("secsy/ca root!"); got != "secsy_ca_root_" {
		t.Errorf("gcpSanitize = %q, want %q", got, "secsy_ca_root_")
	}
	long := strings.Repeat("a", 100)
	if got := gcpSanitize(long); len(got) != 63 {
		t.Errorf("gcpSanitize length = %d, want 63", len(got))
	}
}
