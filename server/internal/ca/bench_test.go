//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// This file benchmarks the certificate-authority hot paths — issuance, OCSP
// response signing, and CRL generation — end to end against SoftHSM, sweeping
// the PKCS#11 session pool size. It backs docs/benchmarks.md.
//
// Run with:
//
//	eval "$(scripts/setup-softhsm.sh --export-env)"
//	go test -tags sqlite -run '^$' -bench 'CA_' -benchtime=2s ./internal/ca/
//
// Note: issuance and OCSP also touch the SQLite database (serial allocation,
// certificate inserts, revocation lookups). SQLite serializes writers, so
// issuance throughput is partly database-bound; the OCSP/CRL benchmarks are
// read-mostly on the database side and track the HSM signing path more closely.

var benchCAPoolSizes = []int{1, 2, 4, 8}

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
// size.
func benchProvider(b *testing.B, size int) keyprovider.Provider {
	b.Helper()
	module, token, pin := benchSkipIfNoHSM(b)
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:      module,
			Pin:             pin,
			TokenLabel:      token,
			SessionPoolSize: size,
		},
	})
	if err != nil {
		b.Fatalf("pkcs11 provider: %v", err)
	}
	b.Cleanup(func() { p.Close() })
	return p
}

// benchManager builds a Manager backed by a fresh SQLite database and the given
// provider.
func benchManager(b *testing.B, provider keyprovider.Provider) *Manager {
	b.Helper()
	dsn := filepath.Join(b.TempDir(), "ca-bench.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		b.Fatalf("opening database: %v", err)
	}
	b.Cleanup(func() { db.Close() })
	return NewManager(db, provider)
}

func benchUniqueLabel(b *testing.B, base string) string {
	b.Helper()
	var s [6]byte
	if _, err := rand.Read(s[:]); err != nil {
		b.Fatal(err)
	}
	return fmt.Sprintf("cabench-%s-%x", base, s)
}

func benchRoot(b *testing.B, mgr *Manager) *models.CA {
	b.Helper()
	root, err := mgr.InitRoot(context.Background(), RootSpec{
		Label:    benchUniqueLabel(b, "root"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "CA Bench Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		b.Fatalf("InitRoot: %v", err)
	}
	return root
}

func benchCSR(b *testing.B, cn string) []byte {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		b.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// BenchmarkCA_IssueCertificate measures end-to-end leaf issuance latency
// (CSR -> HSM-signed certificate + database insert), single-threaded.
func BenchmarkCA_IssueCertificate(b *testing.B) {
	ctx := context.Background()
	mgr := benchManager(b, benchProvider(b, 8))
	root := benchRoot(b, mgr)
	csr := benchCSR(b, "leaf.bench.example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server"}); err != nil {
			b.Fatalf("IssueCertificate: %v", err)
		}
	}
}

// BenchmarkCA_OCSPRespond measures OCSP response generation throughput (a DB
// status lookup plus an on-HSM signature) under concurrency across pool sizes.
// It uses the CA Manager directly, i.e. the uncached path, so it reflects the
// cost the OCSP cache (see handlers) is designed to avoid.
func BenchmarkCA_OCSPRespond(b *testing.B) {
	ctx := context.Background()
	for _, size := range benchCAPoolSizes {
		b.Run(fmt.Sprintf("pool-%d", size), func(b *testing.B) {
			mgr := benchManager(b, benchProvider(b, size))
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
			b.SetParallelism(size)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := mgr.OCSPRespond(ctx, root.ID, reqDER); err != nil {
						b.Fatalf("OCSPRespond: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkCA_GenerateCRL measures CRL generation throughput (a revocation-list
// read plus an on-HSM signature) under concurrency across pool sizes.
func BenchmarkCA_GenerateCRL(b *testing.B) {
	ctx := context.Background()
	for _, size := range benchCAPoolSizes {
		b.Run(fmt.Sprintf("pool-%d", size), func(b *testing.B) {
			mgr := benchManager(b, benchProvider(b, size))
			root := benchRoot(b, mgr)
			b.SetParallelism(size)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := mgr.GenerateCRL(ctx, root.ID); err != nil {
						b.Fatalf("GenerateCRL: %v", err)
					}
				}
			})
		})
	}
}

func mustParseCert(b *testing.B, pemStr string) *x509.Certificate {
	b.Helper()
	cert, err := pki.ParseCertificatePEM([]byte(pemStr))
	if err != nil {
		b.Fatalf("parsing certificate: %v", err)
	}
	return cert
}
