package keyprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// This file benchmarks the HSM-bound hot paths through the key provider against
// SoftHSM, with an emphasis on how throughput scales with the PKCS#11 session
// pool size. It is the evidence behind docs/development/benchmarks.md.
//
// All benchmarks skip unless SoftHSM is configured (SECSY_PKCS11_MODULE /
// SECSY_TOKEN_LABEL), so `go test -bench .` on a machine without an HSM stays
// green. Run them with:
//
//	eval "$(scripts/setup-softhsm.sh --export-env)"
//	go test -run '^$' -bench 'PKCS11' -benchmem ./internal/keyprovider/
//
// Pool sizes swept by the concurrency benchmarks. Size 1 is the effective
// behavior of the historical open-per-operation design (fully serialized on the
// token); larger sizes show the concurrency the pool unlocks.
var benchPoolSizes = []int{1, 2, 4, 8, 16}

func benchSkipIfNoHSM(b *testing.B) (module, token, pin string) {
	b.Helper()
	module = os.Getenv("SECSY_PKCS11_MODULE")
	token = os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		b.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin = os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	return module, token, pin
}

// benchProvider builds a pooled PKCS#11 provider with the given session pool
// size, registering cleanup.
func benchProvider(b *testing.B, size int) *PKCS11Provider {
	b.Helper()
	module, token, pin := benchSkipIfNoHSM(b)
	p, err := NewPKCS11Provider(PKCS11Settings{
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

// benchGenerateKey generates a fresh, uniquely-labeled key of the given type/
// usage and returns its label. The key persists on the token; benchmarks look
// it up by label. A dedicated short-lived provider is used so the generation
// cost is not attributed to the benchmark under test.
func benchGenerateKey(b *testing.B, keyType, usage string) string {
	b.Helper()
	p := benchProvider(b, 1)
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		b.Fatal(err)
	}
	label := fmt.Sprintf("bench-%s-%x", keyType, suffix)
	if _, err := p.GenerateKey(context.Background(), KeySpec{Label: label, KeyType: keyType, Usage: usage}); err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	return label
}

// BenchmarkPKCS11SignLatency measures single-operation signing latency (no
// concurrency) for each key type — the floor an individual request pays.
func BenchmarkPKCS11SignLatency(b *testing.B) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("secsy-pki benchmark"))
	for _, keyType := range []string{KeyTypeEd25519, KeyTypeECDSAP256, KeyTypeRSA2048} {
		b.Run(keyType, func(b *testing.B) {
			label := benchGenerateKey(b, keyType, KeyUsageSign)
			p := benchProvider(b, 1)
			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				b.Fatalf("Signer: %v", err)
			}
			defer signer.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
					b.Fatalf("Sign: %v", err)
				}
			}
		})
	}
}

// BenchmarkPKCS11SignThroughput measures signing throughput under concurrency
// across pool sizes. This is the primary evidence that a bounded session pool
// relieves the per-session serialization of the previous design: ops/sec should
// rise with pool size until the token itself saturates.
func BenchmarkPKCS11SignThroughput(b *testing.B) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("secsy-pki benchmark"))
	// A single ECDSA P-256 key is reused across all pool sizes (a token object,
	// visible to every session).
	label := benchGenerateKey(b, KeyTypeECDSAP256, KeyUsageSign)
	for _, size := range benchPoolSizes {
		b.Run(fmt.Sprintf("pool-%d", size), func(b *testing.B) {
			p := benchProvider(b, size)
			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				b.Fatalf("Signer: %v", err)
			}
			defer signer.Close()
			// Enough goroutines to keep every session busy; borrow() bounds the
			// actual concurrency to the pool size.
			b.SetParallelism(size)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
						b.Fatalf("Sign: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkPKCS11DecryptThroughput measures RSA-OAEP unwrap throughput (the
// secret-decryption hot path) under concurrency across pool sizes. SoftHSM only
// supports SHA-1 for OAEP, so the wrapping matches that.
func BenchmarkPKCS11DecryptThroughput(b *testing.B) {
	ctx := context.Background()
	label := benchGenerateKey(b, KeyTypeRSA2048, KeyUsageDecrypt)

	// Wrap a fixed data key with the KEK's public half (SHA-1 OAEP to match
	// SoftHSM's capability). The provider unwraps it on the device.
	setup := benchProvider(b, 1)
	info, err := setup.FindKey(ctx, KeyRef{Label: label})
	if err != nil {
		b.Fatalf("FindKey: %v", err)
	}
	rsaPub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		b.Fatalf("KEK public key is %T, want *rsa.PublicKey", info.PublicKey)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		b.Fatal(err)
	}
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, dek, nil)
	if err != nil {
		b.Fatalf("EncryptOAEP: %v", err)
	}

	for _, size := range benchPoolSizes {
		b.Run(fmt.Sprintf("pool-%d", size), func(b *testing.B) {
			p := benchProvider(b, size)
			dec, err := p.Decrypter(ctx, KeyRef{Label: label})
			if err != nil {
				b.Fatalf("Decrypter: %v", err)
			}
			defer dec.Close()
			opts := &rsa.OAEPOptions{Hash: crypto.SHA1}
			b.SetParallelism(size)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := dec.Decrypt(rand.Reader, wrapped, opts); err != nil {
						b.Fatalf("Decrypt: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkPKCS11SignerOpen measures the cost of obtaining a Signer (the key
// lookup / public-key parse). With the pool this is a cached, session-local
// lookup rather than a module load + login, so it should be inexpensive.
func BenchmarkPKCS11SignerOpen(b *testing.B) {
	ctx := context.Background()
	label := benchGenerateKey(b, KeyTypeECDSAP256, KeyUsageSign)
	p := benchProvider(b, 8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer, err := p.Signer(ctx, KeyRef{Label: label})
		if err != nil {
			b.Fatalf("Signer: %v", err)
		}
		signer.Close()
	}
}
