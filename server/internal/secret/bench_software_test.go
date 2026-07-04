package secret

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// This file holds the HSM-FREE half of the secret-layer benchmark suite. The
// benchmarks in bench_test.go drive SoftHSM and skip without a token; the ones
// here drive the keystore-backed SoftwareProvider, so the envelope seal/open
// round-trip runs with no HSM. These feed the CI benchmark-regression gate:
// sealing is a public-key wrap + AES-GCM (CPU only), and opening is an in-process
// RSA-OAEP unwrap, both deterministic enough for benchstat to catch a regression.
//
// Run just this set with:
//
//	go test -run '^$' -bench 'SoftwareSecret' -benchmem ./internal/secret/

// benchSoftwareKeyProvider builds a keystore-backed provider in a temp directory.
func benchSoftwareKeyProvider(b *testing.B) *keyprovider.SoftwareProvider {
	b.Helper()
	p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewSoftwareProvider: %v", err)
	}
	b.Cleanup(func() { _ = p.Close() })
	return p
}

// benchSoftwareService provisions a fresh RSA KEK in a software keystore and binds
// a Service to it, returning both the service and the provider (so a second
// service can bind the same KEK if needed).
func benchSoftwareService(b *testing.B) *Service {
	b.Helper()
	ctx := context.Background()
	p := benchSoftwareKeyProvider(b)
	label := "bench-kek"
	if _, err := ProvisionKEK(ctx, p, label, keyprovider.KeyTypeRSA2048); err != nil {
		b.Fatalf("ProvisionKEK: %v", err)
	}
	svc, err := NewService(ctx, p, keyprovider.KeyRef{Label: label})
	if err != nil {
		b.Fatalf("NewService: %v", err)
	}
	return svc
}

// BenchmarkSoftwareSecretEncrypt measures envelope-sealing latency (RSA public-key
// wrap of the data key + AES-GCM), single-threaded. The HSM-free analogue of
// BenchmarkSecretEncrypt.
func BenchmarkSoftwareSecretEncrypt(b *testing.B) {
	svc := benchSoftwareService(b)
	plaintext := []byte("correct horse battery staple - a representative secret")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Encrypt(plaintext, nil); err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
	}
}

// BenchmarkSoftwareSecretDecrypt measures envelope-opening latency (in-process
// RSA-OAEP unwrap of the data key + AES-GCM open), single-threaded. The HSM-free
// analogue of BenchmarkSecretDecrypt.
func BenchmarkSoftwareSecretDecrypt(b *testing.B) {
	svc := benchSoftwareService(b)
	env, err := svc.Encrypt([]byte("a representative secret payload"), nil)
	if err != nil {
		b.Fatalf("Encrypt: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Decrypt(env, nil); err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
	}
}
