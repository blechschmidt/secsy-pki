package secret

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// This file benchmarks envelope encryption and decryption against SoftHSM.
//
// Encryption wraps the data key with the KEK's public half and never touches the
// HSM, so it is CPU-bound and highly parallel. Decryption unwraps the data key
// on the device (C_Decrypt), so its throughput is governed by the PKCS#11
// session pool — hence the pool-size sweep. See docs/benchmarks.md.
//
// Run with:
//
//	eval "$(scripts/setup-softhsm.sh --export-env)"
//	go test -run '^$' -bench 'Secret' -benchtime=2s ./internal/secret/
//
// Skips unless SoftHSM is configured.

var benchSecretPoolSizes = []int{1, 2, 4, 8}

func benchSecretProvider(b *testing.B, size int) *keyprovider.PKCS11Provider {
	b.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		b.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath:      module,
		Pin:             pin,
		TokenLabel:      token,
		SessionPoolSize: size,
	})
	if err != nil {
		b.Fatalf("NewPKCS11Provider: %v", err)
	}
	b.Cleanup(func() { p.Close() })
	return p
}

// benchProvisionKEK generates a fresh KEK and returns its label. The KEK persists
// on the token so pool-size sub-benchmarks can each bind a fresh Service to it.
func benchProvisionKEK(b *testing.B) string {
	b.Helper()
	p := benchSecretProvider(b, 1)
	var s [4]byte
	if _, err := rand.Read(s[:]); err != nil {
		b.Fatal(err)
	}
	label := fmt.Sprintf("bench-kek-%x", s)
	if _, err := ProvisionKEK(context.Background(), p, label, keyprovider.KeyTypeRSA2048); err != nil {
		b.Fatalf("ProvisionKEK: %v", err)
	}
	return label
}

// BenchmarkSecretEncrypt measures envelope-sealing throughput. It is CPU-bound
// (public-key wrap + AES-GCM) and does not touch the HSM, so it scales with CPU.
func BenchmarkSecretEncrypt(b *testing.B) {
	ctx := context.Background()
	label := benchProvisionKEK(b)
	svc, err := NewService(ctx, benchSecretProvider(b, 8), keyprovider.KeyRef{Label: label})
	if err != nil {
		b.Fatalf("NewService: %v", err)
	}
	plaintext := []byte("correct horse battery staple - a representative secret")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := svc.Encrypt(plaintext, nil); err != nil {
				b.Fatalf("Encrypt: %v", err)
			}
		}
	})
}

// BenchmarkSecretDecrypt measures envelope-opening throughput under concurrency
// across pool sizes. Each decrypt unwraps the data key on the HSM, so throughput
// should rise with pool size until the token saturates.
func BenchmarkSecretDecrypt(b *testing.B) {
	ctx := context.Background()
	label := benchProvisionKEK(b)

	// Seal one envelope up front; every iteration opens it.
	sealSvc, err := NewService(ctx, benchSecretProvider(b, 1), keyprovider.KeyRef{Label: label})
	if err != nil {
		b.Fatalf("NewService (seal): %v", err)
	}
	env, err := sealSvc.Encrypt([]byte("a representative secret payload"), nil)
	if err != nil {
		b.Fatalf("Encrypt: %v", err)
	}

	for _, size := range benchSecretPoolSizes {
		b.Run(fmt.Sprintf("pool-%d", size), func(b *testing.B) {
			svc, err := NewService(ctx, benchSecretProvider(b, size), keyprovider.KeyRef{Label: label})
			if err != nil {
				b.Fatalf("NewService: %v", err)
			}
			b.SetParallelism(size)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := svc.Decrypt(env, nil); err != nil {
						b.Fatalf("Decrypt: %v", err)
					}
				}
			})
		})
	}
}
