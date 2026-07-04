//go:build sqlite

package grpcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// newGRPCIssuerService builds a gRPC service backed by a real software provider
// and a real root CA, so IssueCertificate actually mints certificates.
func newGRPCIssuerService(t *testing.T) (*service, string) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	instrumented := keyprovider.Instrument(prov)
	api := handlers.NewAPI(db, instrumented, nil, hsm.Config{}, true, "")
	root, err := ca.NewManager(db, instrumented).InitRoot(context.Background(), ca.RootSpec{
		Label:    "grpc-ms-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "gRPC Must-Staple Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return &service{api: api}, root.ID
}

func grpcCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func grpcLeafHasMustStaple(t *testing.T, resp *pkiv1.CertificateResponse) bool {
	t.Helper()
	cert, err := pki.ParseCertificatePEM([]byte(resp.GetCertificatePem()))
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(pki.OIDTLSFeature) {
			feats, err := pki.ParseTLSFeature(ext.Value)
			if err != nil {
				t.Fatalf("malformed TLS feature extension: %v", err)
			}
			return pki.TLSFeatureListed(feats, pki.TLSFeatureStatusRequest)
		}
	}
	return false
}

// TestGRPCIssueMustStapleOverride covers the gRPC per-request override wiring
// (IssueCertificateRequest.must_staple → ca.IssueSpec.MustStaple).
func TestGRPCIssueMustStapleOverride(t *testing.T) {
	svc, caID := newGRPCIssuerService(t)
	ctx := withUser(&models.UserInfo{Subject: "root", IsRoot: true})

	issue := func(cn, profile string, override *bool) *pkiv1.CertificateResponse {
		t.Helper()
		resp, err := svc.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
			CaId:       caID,
			CsrPem:     grpcCSR(t, cn),
			Profile:    profile,
			MustStaple: override,
		})
		if err != nil {
			t.Fatalf("IssueCertificate(profile=%s): %v", profile, err)
		}
		return resp
	}

	// Profile default on (server-muststaple).
	if !grpcLeafHasMustStaple(t, issue("a.example.com", "server-muststaple", nil)) {
		t.Error("server-muststaple leaf missing the Must-Staple extension over gRPC")
	}
	// Override off suppresses it (server-muststaple permits overrides).
	on := true
	off := false
	if grpcLeafHasMustStaple(t, issue("b.example.com", "server-muststaple", &off)) {
		t.Error("must_staple=false override did not suppress the extension over gRPC")
	}
	// server profile forbids overrides: must_staple=true is ignored.
	if grpcLeafHasMustStaple(t, issue("c.example.com", "server", &on)) {
		t.Error("must_staple=true honored on a profile that forbids overrides over gRPC")
	}
}
