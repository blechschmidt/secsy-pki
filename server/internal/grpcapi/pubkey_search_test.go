//go:build sqlite

package grpcapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestGRPCListCertificates_PublicKeyFilter mirrors the REST key-compromise
// search over gRPC: the public_key_sha256 request field selects certificates
// sharing a leaked key, a malformed value is InvalidArgument, and the CA scope
// (hence tenant scope) is honored.
func TestGRPCListCertificates_PublicKeyFilter(t *testing.T) {
	svc := newGRPCAuthzService(t) // provides ca-a (tenant a) and ca-b (tenant b)
	db := svc.api.DB()
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := keycheck.Fingerprint(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(k.Public())
	sum := sha256.Sum256(spki)
	leakedHex := hex.EncodeToString(sum[:])

	rec := func(caID, serial string) {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: caID + "-" + serial, CAID: caID, Serial: serial,
			CommonName: "host-" + serial, Profile: "server", Certificate: "PEM",
			NotBefore: base, NotAfter: base.Add(24 * time.Hour * 365),
			Status: models.CertStatusValid, PublicKeyFingerprint: canonical, CreatedAt: base,
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%s/%s): %v", caID, serial, err)
		}
	}
	rec("ca-a", "1")
	rec("ca-a", "2")
	rec("ca-b", "1") // same key, different CA/tenant

	ctx := withUser(grpcAuditorA)

	t.Run("match", func(t *testing.T) {
		resp, err := svc.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: "ca-a", PublicKeySha256: leakedHex})
		if err != nil {
			t.Fatalf("ListCertificates: %v", err)
		}
		if resp.GetTotal() != 2 || len(resp.GetCertificates()) != 2 {
			t.Fatalf("total=%d items=%d, want 2/2", resp.GetTotal(), len(resp.GetCertificates()))
		}
	})

	t.Run("canonical-form", func(t *testing.T) {
		resp, err := svc.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: "ca-a", PublicKeySha256: canonical})
		if err != nil {
			t.Fatalf("ListCertificates: %v", err)
		}
		if resp.GetTotal() != 2 {
			t.Fatalf("canonical total = %d, want 2", resp.GetTotal())
		}
	})

	t.Run("malformed-invalid-argument", func(t *testing.T) {
		_, err := svc.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: "ca-a", PublicKeySha256: "not-a-fingerprint"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed = %v, want InvalidArgument", status.Code(err))
		}
	})
}
