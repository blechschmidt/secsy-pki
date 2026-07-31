package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sort"
	"sync"
)

// FakeKMSBackend is an in-process emulation of a cloud KMS. It generates real
// asymmetric keys with the Go standard library and signs in-memory, but exposes
// only the KMSBackend surface — there is no method that returns private key
// material — so it faithfully models the trust boundary of AWS KMS / Azure Key
// Vault while requiring no cloud credentials. It exists so unit and integration
// tests can exercise the KMSProvider end to end (generate, resolve, sign,
// public-key export, list, probe) deterministically and offline.
//
// It is safe for concurrent use.
type FakeKMSBackend struct {
	prefix string
	mu     sync.Mutex
	keys   map[string]*fakeKMSKey // keyed by label
}

type fakeKMSKey struct {
	keyID   string
	keyType string
	priv    crypto.Signer
}

// NewFakeKMSBackend returns an empty in-memory KMS backend. prefix namespaces the
// synthesized key IDs, matching the real backends' KeyPrefix behavior.
func NewFakeKMSBackend(prefix string) *FakeKMSBackend {
	return &FakeKMSBackend{prefix: prefix, keys: make(map[string]*fakeKMSKey)}
}

func (b *FakeKMSBackend) BackendName() string { return KMSBackendFake }

func (b *FakeKMSBackend) Close() error { return nil }

// Ping always succeeds: an in-memory backend is reachable whenever the process is.
func (b *FakeKMSBackend) Ping(context.Context) error { return nil }

func (b *FakeKMSBackend) CreateKey(_ context.Context, label, keyType string) (*RemoteKey, error) {
	if label == "" {
		return nil, fmt.Errorf("keyprovider: fake kms: empty label")
	}
	if err := kmsSupportsKeyType(keyType); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.keys[label]; ok {
		return nil, fmt.Errorf("keyprovider: fake kms: key %q already exists", label)
	}
	priv, err := generateKMSKey(keyType)
	if err != nil {
		return nil, err
	}
	k := &fakeKMSKey{
		keyID:   "fake:" + b.prefix + label,
		keyType: keyType,
		priv:    priv,
	}
	b.keys[label] = k
	return b.remote(label, k), nil
}

func (b *FakeKMSBackend) ResolveKey(_ context.Context, label string) (*RemoteKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.keys[label]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, label)
	}
	return b.remote(label, k), nil
}

func (b *FakeKMSBackend) ListKeys(context.Context) ([]RemoteKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	labels := make([]string, 0, len(b.keys))
	for label := range b.keys {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	out := make([]RemoteKey, 0, len(labels))
	for _, label := range labels {
		out = append(out, *b.remote(label, b.keys[label]))
	}
	return out, nil
}

func (b *FakeKMSBackend) Sign(_ context.Context, keyID, keyType string, digest []byte, hash crypto.Hash, pss bool) ([]byte, error) {
	b.mu.Lock()
	var priv crypto.Signer
	for _, k := range b.keys {
		if k.keyID == keyID {
			priv = k.priv
			break
		}
	}
	b.mu.Unlock()
	if priv == nil {
		return nil, fmt.Errorf("%w: keyID %q", ErrKeyNotFound, keyID)
	}
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		// ecdsa.SignASN1 returns the ASN.1 DER encoding x509/CMS verifiers expect.
		return ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		if pss {
			return rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
		}
		return rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	default:
		return nil, fmt.Errorf("keyprovider: fake kms: unsupported key type %q", keyType)
	}
}

// remote builds the non-sensitive metadata view of a stored key. Caller holds mu.
func (b *FakeKMSBackend) remote(label string, k *fakeKMSKey) *RemoteKey {
	return &RemoteKey{
		Label:     label,
		KeyID:     k.keyID,
		KeyType:   k.keyType,
		PublicKey: k.priv.Public(),
		URI:       "kms:fake:" + label,
	}
}

// generateKMSKey creates a private key of a KMS-supported type. It is shared by
// the fake backend and is deliberately limited to the ECDSA/RSA families a cloud
// KMS offers.
func generateKMSKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("keyprovider: cloud KMS cannot generate key type %q", keyType)
	}
}

var _ KMSBackend = (*FakeKMSBackend)(nil)
