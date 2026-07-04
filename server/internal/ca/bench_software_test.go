//go:build sqlite

package ca

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// This file holds the HSM-FREE half of the CA benchmark suite. The benchmarks in
// bench_test.go drive SoftHSM and skip when no token is configured; the ones here
// drive the keystore-backed SoftwareProvider, so end-to-end issuance, OCSP, and
// CRL signing all run with no HSM. These are the benchmarks the CI
// benchmark-regression gate compares against the committed baseline — a software
// signature is CPU-bound and deterministic, so benchstat can flag a genuine
// regression on the issuance/OCSP/CRL hot paths without a token in the loop.
//
// They reuse the provider-agnostic helpers from bench_test.go (benchManager,
// benchRoot, benchCSR, mustParseCert); only the provider differs.
//
// Run just this set with:
//
//	go test -tags sqlite -run '^$' -bench 'SoftwareCA_' -benchmem ./internal/ca/

// benchSoftwareProvider builds a keystore-backed provider in a temp directory.
func benchSoftwareProvider(b *testing.B) keyprovider.Provider {
	b.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: b.TempDir()},
	})
	if err != nil {
		b.Fatalf("software provider: %v", err)
	}
	b.Cleanup(func() { p.Close() })
	return p
}

// BenchmarkSoftwareCA_IssueCertificate measures end-to-end leaf issuance latency
// (CSR -> software-signed certificate + database insert), single-threaded. The
// HSM-free analogue of BenchmarkCA_IssueCertificate.
func BenchmarkSoftwareCA_IssueCertificate(b *testing.B) {
	ctx := context.Background()
	mgr := benchManager(b, benchSoftwareProvider(b))
	root := benchRoot(b, mgr)
	csr := benchCSR(b, "leaf.bench.example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server"}); err != nil {
			b.Fatalf("IssueCertificate: %v", err)
		}
	}
}

// BenchmarkSoftwareCA_OCSPRespond measures OCSP response generation latency (a DB
// status lookup plus a software signature), single-threaded. The HSM-free
// analogue of BenchmarkCA_OCSPRespond.
func BenchmarkSoftwareCA_OCSPRespond(b *testing.B) {
	ctx := context.Background()
	mgr := benchManager(b, benchSoftwareProvider(b))
	root := benchRoot(b, mgr)
	issued, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: benchCSR(b, "ocsp.bench.example.com"), Profile: "server",
	})
	if err != nil {
		b.Fatalf("IssueCertificate: %v", err)
	}
	reqDER, err := pki.BuildOCSPRequest(issued.Certificate, mustParseCert(b, root.Certificate))
	if err != nil {
		b.Fatalf("BuildOCSPRequest: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mgr.OCSPRespond(ctx, root.ID, reqDER); err != nil {
			b.Fatalf("OCSPRespond: %v", err)
		}
	}
}

// BenchmarkSoftwareCA_GenerateCRL measures CRL generation latency (a revocation
// list read plus a software signature), single-threaded. The HSM-free analogue of
// BenchmarkCA_GenerateCRL.
func BenchmarkSoftwareCA_GenerateCRL(b *testing.B) {
	ctx := context.Background()
	mgr := benchManager(b, benchSoftwareProvider(b))
	root := benchRoot(b, mgr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mgr.GenerateCRL(ctx, root.ID); err != nil {
			b.Fatalf("GenerateCRL: %v", err)
		}
	}
}
