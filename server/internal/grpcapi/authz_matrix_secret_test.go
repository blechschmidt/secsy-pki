//go:build sqlite

package grpcapi

// Task 138: the gRPC SecretService mirror of the REST secret authorization
// matrix. Each RPC delegates to the same handlers.API core the REST secret
// handlers use, so the same contract holds:
//
//	(b) authenticated but lacking the capability      -> PermissionDenied
//	(c) tenant-scoped principal naming another tenant  -> PermissionDenied
//	(d) a correctly-capable principal                  -> NOT PermissionDenied/Unauthenticated
//
// TestGRPCSecretAuthzMatrixCoversMethods forces a new SecretService RPC to be
// declared here, the gRPC route-completeness gate for the crypto service.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// newGRPCSecretService builds a SecretService backed by a software KEK so a
// capable principal exercises real crypto (the (d) case succeeds) while the
// denial paths short-circuit before touching it.
func newGRPCSecretService(t *testing.T) *secretService {
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
	if _, err := prov.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label: "grpc-secret-kek", KeyType: "rsa-2048", Usage: keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatalf("GenerateKey KEK: %v", err)
	}
	api := handlers.NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "grpc-secret-kek")
	for _, id := range []string{"a", "b"} {
		if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
			t.Fatalf("CreateTenant(%s): %v", id, err)
		}
	}
	return &secretService{api: api}
}

// grpcSecretCase is one SecretService RPC's authorization contract, invoked
// against tenant "a" with the principal on ctx. Every crypto RPC is tenant
// scoped, so the cross-tenant principal (admin of "b") is always PermissionDenied.
type grpcSecretCase struct {
	method string
	invoke func(ctx context.Context, s *secretService) error
}

func grpcSecretAuthzMatrix() []grpcSecretCase {
	return []grpcSecretCase{
		{"GenerateDataKey", func(ctx context.Context, s *secretService) error {
			_, err := s.GenerateDataKey(ctx, &pkiv1.GenerateDataKeyRequest{Tenant: "a"})
			return err
		}},
		{"GenerateHMAC", func(ctx context.Context, s *secretService) error {
			_, err := s.GenerateHMAC(ctx, &pkiv1.GenerateHMACRequest{Tenant: "a", Data: []byte("data")})
			return err
		}},
		{"VerifyHMAC", func(ctx context.Context, s *secretService) error {
			_, err := s.VerifyHMAC(ctx, &pkiv1.VerifyHMACRequest{Tenant: "a", Data: []byte("data"), Hmac: []byte("tag")})
			return err
		}},
		{"GenerateRandom", func(ctx context.Context, s *secretService) error {
			_, err := s.GenerateRandom(ctx, &pkiv1.GenerateRandomRequest{Tenant: "a", NumBytes: 16})
			return err
		}},
		{"TransformEncode", func(ctx context.Context, s *secretService) error {
			_, err := s.TransformEncode(ctx, &pkiv1.TransformRequest{Tenant: "a", Template: "t", Value: "1234567890"})
			return err
		}},
		{"TransformDecode", func(ctx context.Context, s *secretService) error {
			_, err := s.TransformDecode(ctx, &pkiv1.TransformRequest{Tenant: "a", Template: "t", Value: "1234567890"})
			return err
		}},
		// Task 153: named HSM-backed signing keys. The authz check runs before any
		// content validation, so the denial cases short-circuit; the (d) case reaches
		// an InvalidArgument (empty algorithm / no data / unknown key), which is not a
		// denial — exactly what the matrix asserts.
		{"CreateSigningKey", func(ctx context.Context, s *secretService) error {
			_, err := s.CreateSigningKey(ctx, &pkiv1.CreateSigningKeyRequest{Tenant: "a", Name: "k"})
			return err
		}},
		{"ListSigningKeys", func(ctx context.Context, s *secretService) error {
			_, err := s.ListSigningKeys(ctx, &pkiv1.ListSigningKeysRequest{Tenant: "a"})
			return err
		}},
		{"GetSigningKey", func(ctx context.Context, s *secretService) error {
			_, err := s.GetSigningKey(ctx, &pkiv1.GetSigningKeyRequest{Tenant: "a", Name: "k"})
			return err
		}},
		{"Sign", func(ctx context.Context, s *secretService) error {
			_, err := s.Sign(ctx, &pkiv1.SignRequest{Tenant: "a", Key: "k", Message: []byte("m")})
			return err
		}},
		{"Verify", func(ctx context.Context, s *secretService) error {
			_, err := s.Verify(ctx, &pkiv1.VerifyRequest{Tenant: "a", Key: "k", Message: []byte("m"), Signature: []byte("s")})
			return err
		}},
		{"VerifyWithPublicKey", func(ctx context.Context, s *secretService) error {
			_, err := s.VerifyWithPublicKey(ctx, &pkiv1.VerifyWithPublicKeyRequest{Tenant: "a", Algorithm: "ecdsa-p256", PublicKeyPem: "x", Message: []byte("m"), Signature: []byte("s")})
			return err
		}},
	}
}

// TestGRPCSecretAuthzMatrix asserts (b)/(c)/(d) for every SecretService RPC.
func TestGRPCSecretAuthzMatrix(t *testing.T) {
	svc := newGRPCSecretService(t)
	for _, c := range grpcSecretAuthzMatrix() {
		c := c
		t.Run(c.method, func(t *testing.T) {
			// (b) authenticated, no capability -> PermissionDenied.
			if got := status.Code(c.invoke(withUser(grpcNobody), svc)); got != codes.PermissionDenied {
				t.Errorf("(b) roleless: code=%s, want PermissionDenied", got)
			}
			// (c) cross-tenant principal (admin of "b") on tenant "a" -> PermissionDenied.
			if got := status.Code(c.invoke(withUser(grpcAdminB), svc)); got != codes.PermissionDenied {
				t.Errorf("(c) cross-tenant admin-b: code=%s, want PermissionDenied", got)
			}
			// (d) capable principal -> not denied.
			if got := status.Code(c.invoke(withUser(grpcAdminA), svc)); got == codes.PermissionDenied || got == codes.Unauthenticated {
				t.Errorf("(d) capable admin-a: code=%s (denied), want authorized", got)
			}
		})
	}
}

// TestGRPCSecretAuthzMatrixCoversMethods forces every SecretService RPC to have a
// matrix entry, the gRPC route-completeness gate for the crypto service.
func TestGRPCSecretAuthzMatrixCoversMethods(t *testing.T) {
	declared := map[string]bool{}
	for _, c := range grpcSecretAuthzMatrix() {
		declared[c.method] = true
	}
	rpcNames := map[string]bool{}
	for _, m := range pkiv1.SecretService_ServiceDesc.Methods {
		rpcNames[m.MethodName] = true
	}
	for _, st := range pkiv1.SecretService_ServiceDesc.Streams {
		rpcNames[st.StreamName] = true
	}
	for name := range rpcNames {
		if !declared[name] {
			t.Errorf("SecretService RPC %q has no gRPC authorization-matrix entry; declare its authz intent in grpcSecretAuthzMatrix()", name)
		}
	}
	for name := range declared {
		if !rpcNames[name] {
			t.Errorf("gRPC matrix entry %q matches no SecretService RPC (stale)", name)
		}
	}
}
