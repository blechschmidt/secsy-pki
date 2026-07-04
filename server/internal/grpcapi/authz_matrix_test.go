//go:build sqlite

package grpcapi

// Task 106: the gRPC mirror of the REST authorization + tenant-isolation matrix
// (internal/handlers/authz_matrix_test.go). Every PKIService RPC delegates to the
// same handlers.API authorization the REST handlers use, so the same four
// contract points must hold here:
//
//	(a) unauthenticated                          -> Unauthenticated
//	    (proved at the credential layer via AuthenticateRPC / authInterceptor)
//	(b) authenticated but lacking the capability -> PermissionDenied
//	(c) tenant-scoped principal on another tenant's CA -> PermissionDenied (issue)
//	    or NotFound (read, non-disclosure)
//	(d) a correctly-capable principal            -> NOT PermissionDenied/Unauthenticated
//
// TestGRPCAuthzMatrixCoversMethods forces a new PKIService method to be declared
// here, mirroring the REST route-completeness gate.

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// --- principals ---

func tuser(sub, tenant, role string) *models.UserInfo {
	return &models.UserInfo{Subject: sub, TenantRoles: map[string][]string{tenant: {role}}}
}

var (
	grpcNobody   = &models.UserInfo{Subject: "nobody"}
	grpcAdminA   = tuser("admin-a", "a", "admin")
	grpcAdminB   = tuser("admin-b", "b", "admin")
	grpcAuditorA = tuser("auditor-a", "a", "auditor")
	grpcAuditorB = tuser("auditor-b", "b", "auditor")
)

func withUser(u *models.UserInfo) context.Context {
	return context.WithValue(middleware.WithTenantHolder(context.Background()), middleware.UserInfoKey, u)
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// --- fixture ---

func newGRPCAuthzService(t *testing.T) *service {
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
	api := handlers.NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	for _, id := range []string{"a", "b"} {
		if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
			t.Fatalf("CreateTenant(%s): %v", id, err)
		}
	}
	mkCA := func(id, tenant string) {
		if err := db.CreateCA(&models.CA{
			ID: id, TenantID: tenant, Label: id, PKCS11URI: "pkcs11:object=" + id,
			KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
		}); err != nil {
			t.Fatalf("CreateCA(%s): %v", id, err)
		}
	}
	mkCA("ca-a", "a")
	mkCA("ca-b", "b")
	return &service{api: api}
}

// grpcCase is one RPC's authorization contract. invoke calls the RPC against
// ca-a (tenant "a") with the principal on ctx; the assertions read only the
// gRPC status code, so no valid request payload is required.
type grpcCase struct {
	method    string
	invoke    func(ctx context.Context, svc *service) error
	crossUser *models.UserInfo // tenant-"b" principal for the cross-tenant check
	crossCode codes.Code       // expected code for the cross-tenant principal
	capable   *models.UserInfo // principal that must NOT be denied
}

// issueCase / readCase capture the two authorization classes. Issue RPCs deny a
// foreign-tenant principal with PermissionDenied; read RPCs answer NotFound
// (non-disclosure), exactly as AuthorizeIssueOn / AuthorizeCARead do over REST.
func issueCase(method string, invoke func(context.Context, *service) error) grpcCase {
	return grpcCase{method: method, invoke: invoke, crossUser: grpcAdminB, crossCode: codes.PermissionDenied, capable: grpcAdminA}
}

func readCase(method string, invoke func(context.Context, *service) error) grpcCase {
	return grpcCase{method: method, invoke: invoke, crossUser: grpcAuditorB, crossCode: codes.NotFound, capable: grpcAuditorA}
}

func grpcAuthzMatrix() []grpcCase {
	return []grpcCase{
		issueCase("IssueCertificate", func(ctx context.Context, s *service) error {
			_, err := s.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{CaId: "ca-a", CsrPem: "bad"})
			return err
		}),
		issueCase("RenewCertificate", func(ctx context.Context, s *service) error {
			_, err := s.RenewCertificate(ctx, &pkiv1.RenewCertificateRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		issueCase("RevokeCertificate", func(ctx context.Context, s *service) error {
			_, err := s.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		issueCase("SuspendCertificate", func(ctx context.Context, s *service) error {
			_, err := s.SuspendCertificate(ctx, &pkiv1.SuspendCertificateRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		issueCase("ReleaseCertificate", func(ctx context.Context, s *service) error {
			_, err := s.ReleaseCertificate(ctx, &pkiv1.ReleaseCertificateRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		readCase("GetCertificate", func(ctx context.Context, s *service) error {
			_, err := s.GetCertificate(ctx, &pkiv1.GetCertificateRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		readCase("GetCertificateStatus", func(ctx context.Context, s *service) error {
			_, err := s.GetCertificateStatus(ctx, &pkiv1.GetCertificateStatusRequest{CaId: "ca-a", Serial: "01"})
			return err
		}),
		readCase("ListCertificates", func(ctx context.Context, s *service) error {
			_, err := s.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: "ca-a"})
			return err
		}),
		readCase("GetCRLMetadata", func(ctx context.Context, s *service) error {
			_, err := s.GetCRLMetadata(ctx, &pkiv1.GetCRLMetadataRequest{CaId: "ca-a"})
			return err
		}),
		readCase("GetOCSPMetadata", func(ctx context.Context, s *service) error {
			_, err := s.GetOCSPMetadata(ctx, &pkiv1.GetOCSPMetadataRequest{CaId: "ca-a"})
			return err
		}),
	}
}

// TestGRPCAuthzMatrix asserts (b)/(c)/(d) for every PKIService RPC.
func TestGRPCAuthzMatrix(t *testing.T) {
	svc := newGRPCAuthzService(t)
	for _, c := range grpcAuthzMatrix() {
		c := c
		t.Run(c.method, func(t *testing.T) {
			// (b) authenticated, no capability -> PermissionDenied.
			if got := status.Code(c.invoke(withUser(grpcNobody), svc)); got != codes.PermissionDenied {
				t.Errorf("(b) roleless: code=%s, want PermissionDenied", got)
			}
			// (c) cross-tenant principal -> PermissionDenied (issue) / NotFound (read).
			if got := status.Code(c.invoke(withUser(c.crossUser), svc)); got != c.crossCode {
				t.Errorf("(c) cross-tenant %s: code=%s, want %s", c.crossUser.Subject, got, c.crossCode)
			}
			// (d) capable principal -> not denied (some other code from business logic is fine).
			if got := status.Code(c.invoke(withUser(c.capable), svc)); got == codes.PermissionDenied || got == codes.Unauthenticated {
				t.Errorf("(d) capable %s: code=%s (denied), want authorized", c.capable.Subject, got)
			}
		})
	}
}

// TestGRPCAuthzMatrixCoversMethods forces every PKIService method to have a
// matrix entry — the gRPC analogue of the REST route-completeness gate.
func TestGRPCAuthzMatrixCoversMethods(t *testing.T) {
	declared := map[string]bool{}
	for _, c := range grpcAuthzMatrix() {
		declared[c.method] = true
	}
	for _, m := range pkiv1.PKIService_ServiceDesc.Methods {
		if !declared[m.MethodName] {
			t.Errorf("PKIService RPC %q has no gRPC authorization-matrix entry; declare its authz intent in grpcAuthzMatrix()", m.MethodName)
		}
	}
	for name := range declared {
		found := false
		for _, m := range pkiv1.PKIService_ServiceDesc.Methods {
			if m.MethodName == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("gRPC matrix entry %q matches no PKIService RPC (stale)", name)
		}
	}
}

// --- credential layer: the (a) analogue lives in AuthenticateRPC ---

type grpcTestVerifier struct{}

func (grpcTestVerifier) VerifyToken(_ context.Context, raw string) (*auth.Claims, error) {
	if raw == "bad" {
		return nil, errors.New("invalid token")
	}
	return &auth.Claims{Subject: raw, EmailVerified: true}, nil
}

// TestAuthenticateRPCCredentialLayer proves the gRPC auth interceptor's credential
// handling: no credential -> ErrNoCredentials (mapped to Unauthenticated), a bad
// credential -> ErrInvalidCredentials, and a good credential resolves the same
// principal (with roles) the REST middleware would.
func TestAuthenticateRPCCredentialLayer(t *testing.T) {
	authMw := middleware.NewAuthMiddleware(grpcTestVerifier{}, "root", "rootpw")
	authMw.SetTenantRoleResolver(func(u *models.UserInfo) map[string][]string {
		if u.Subject == "svc-a" {
			return map[string][]string{"a": {"issuer"}}
		}
		return nil
	})
	ctx := context.Background()

	// (a) no credential.
	if _, err := authMw.AuthenticateRPC(ctx, "", nil); !errors.Is(err, middleware.ErrNoCredentials) {
		t.Errorf("no credential: err=%v, want ErrNoCredentials", err)
	}
	// A malformed / rejected credential.
	if _, err := authMw.AuthenticateRPC(ctx, "Bearer bad", nil); !errors.Is(err, middleware.ErrInvalidCredentials) {
		t.Errorf("bad bearer: err=%v, want ErrInvalidCredentials", err)
	}
	if _, err := authMw.AuthenticateRPC(ctx, "Basic bogus", nil); err == nil {
		t.Error("garbage Basic credential was accepted")
	}
	// A good bearer resolves the principal and its tenant roles.
	u, err := authMw.AuthenticateRPC(ctx, "Bearer svc-a", nil)
	if err != nil {
		t.Fatalf("valid bearer: %v", err)
	}
	if len(u.TenantRoles["a"]) != 1 || u.TenantRoles["a"][0] != "issuer" {
		t.Errorf("resolved roles = %v, want tenant a issuer", u.TenantRoles)
	}
	// Root basic-auth resolves the superuser.
	root, err := authMw.AuthenticateRPC(ctx, basicHeader("root", "rootpw"), nil)
	if err != nil || !root.IsRoot {
		t.Errorf("root basic auth: user=%+v err=%v", root, err)
	}
}

// TestGRPCPublicMethods confirms only reflection/health are exempt from auth; a
// PKIService method is never public.
func TestGRPCPublicMethods(t *testing.T) {
	public := []string{"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "/grpc.health.v1.Health/Check"}
	for _, m := range public {
		if !isPublicMethod(m) {
			t.Errorf("%s should be public (no auth)", m)
		}
	}
	if isPublicMethod("/pki.v1.PKIService/IssueCertificate") {
		t.Error("PKIService.IssueCertificate must NOT be public")
	}
}
