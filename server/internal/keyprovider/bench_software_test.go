package keyprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// This file holds the HSM-FREE half of the benchmark suite. Unlike bench_test.go
// (which skips unless SoftHSM is configured), every benchmark here runs entirely
// in software via the keystore-backed SoftwareProvider, so it produces numbers on
// any machine with no HSM, token, or PIN.
//
// These are the benchmarks the CI benchmark-regression gate runs and compares
// against the committed baseline (docs/benchmarks.md#regression-gate): a software
// signature is pure Go/asm on the CPU, so the numbers are deterministic and
// portable enough for benchstat to flag a real algorithmic regression, while the
// SoftHSM benchmarks stay the tool for tuning a specific device. Keep them fast
// and single-threaded — the gate measures per-operation cost, not concurrency
// scaling (which is a property of the pooled PKCS#11 backend, not the CPU).
//
// Run just this set with:
//
//	go test -run '^$' -bench 'Software' -benchmem ./internal/keyprovider/

// benchSoftwareProvider builds a keystore-backed provider in a temp directory,
// registering cleanup.
func benchSoftwareProvider(b *testing.B) *SoftwareProvider {
	b.Helper()
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewSoftwareProvider: %v", err)
	}
	b.Cleanup(func() { _ = p.Close() })
	return p
}

// BenchmarkSoftwareSignLatency measures single-operation signing latency for each
// key type through the software backend — the CPU floor a signature pays with no
// token in the path. It is the HSM-free analogue of BenchmarkPKCS11SignLatency.
func BenchmarkSoftwareSignLatency(b *testing.B) {
	ctx := context.Background()
	message := []byte("secsy-pki benchmark")
	digest := sha256.Sum256(message)
	for _, keyType := range []string{KeyTypeEd25519, KeyTypeECDSAP256, KeyTypeRSA2048} {
		b.Run(keyType, func(b *testing.B) {
			p := benchSoftwareProvider(b)
			if _, err := p.GenerateKey(ctx, KeySpec{Label: "sign", KeyType: keyType, Usage: KeyUsageSign}); err != nil {
				b.Fatalf("GenerateKey: %v", err)
			}
			signer, err := p.Signer(ctx, KeyRef{Label: "sign"})
			if err != nil {
				b.Fatalf("Signer: %v", err)
			}
			defer signer.Close()
			// Ed25519 signs the raw message (SignerOpts hash must be zero); ECDSA
			// and RSA sign a pre-computed digest under SHA-256.
			input, opts := digest[:], crypto.SignerOpts(crypto.SHA256)
			if keyType == KeyTypeEd25519 {
				input, opts = message, crypto.Hash(0)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := signer.Sign(rand.Reader, input, opts); err != nil {
					b.Fatalf("Sign: %v", err)
				}
			}
		})
	}
}

// BenchmarkSoftwareSignerOpen measures the cost of obtaining a Signer from the
// software keystore (read the PEM file + parse the PKCS#8 key). It is the HSM-free
// analogue of BenchmarkPKCS11SignerOpen and tracks the per-request key-load cost
// on the signing path.
func BenchmarkSoftwareSignerOpen(b *testing.B) {
	ctx := context.Background()
	p := benchSoftwareProvider(b)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "open", KeyType: KeyTypeECDSAP256, Usage: KeyUsageSign}); err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer, err := p.Signer(ctx, KeyRef{Label: "open"})
		if err != nil {
			b.Fatalf("Signer: %v", err)
		}
		signer.Close()
	}
}
