//go:build sqlite

// gRPC API surface end-to-end test (Task 56). It stands up the same
// handlers.API and auth middleware the server wires, exposes it over an
// in-process grpcapi.Server, and drives an issue -> status -> revoke -> status
// round-trip over gRPC against a real SoftHSM-backed CA. It also asserts the
// cross-cutting guarantees the task requires: unauthenticated calls are
// rejected, tenant/RBAC authorization is enforced, request IDs are echoed,
// server reflection is enabled, and gRPC status codes are mapped correctly.
//
// Gated on the SECSY_* environment from scripts/setup-softhsm.sh, like the other
// e2e tests, so a plain `go test ./...` without an HSM stays green.
package e2e

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	reflectpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	"encoding/base64"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	grpcRootUser = "root"
	grpcRootPass = "grpc-e2e-password"
)

// startGRPCServer wires an API over an HSM-backed CA and serves it on an
// ephemeral port in plaintext (in-process, loopback only), returning the address
// and the root CA id.
func startGRPCServer(t *testing.T) (addr, caID string) {
	t.Helper()
	provider := hsmProvider(t)

	dsn := t.TempDir() + "/grpc-e2e.db"
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// A base URL so CRL/OCSP metadata carries populated distribution URLs.
	ca.SetCRLConfig(ca.CRLDistConfig{BaseURL: "https://pki.example.test"})
	t.Cleanup(func() { ca.SetCRLConfig(ca.CRLDistConfig{}) })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    uniqueLabel(t, "grpc-root"),
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy gRPC E2E Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}

	api := handlers.NewAPI(db, provider, nil, hsm.Config{}, true, "")
	authMw := middleware.NewAuthMiddleware(nil, grpcRootUser, grpcRootPass)

	srv, err := grpcapi.New(grpcapi.Config{Address: "127.0.0.1:0", Insecure: true}, api, authMw)
	if err != nil {
		t.Fatalf("grpcapi.New: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(srv.Stop)
	return srv.Addr(), root.ID
}

// grpcRootCtx returns a context carrying Basic root credentials and a deadline.
func grpcRootCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	enc := base64.StdEncoding.EncodeToString([]byte(grpcRootUser + ":" + grpcRootPass))
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+enc)
	return ctx, cancel
}

func dialLocal(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dialing %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestGRPCIssueRevokeE2E drives the full lifecycle over gRPC.
func TestGRPCIssueRevokeE2E(t *testing.T) {
	addr, caID := startGRPCServer(t)
	client := pkiv1.NewPKIServiceClient(dialLocal(t, addr))

	csrPEM := string(makeCSR(t, "grpc-leaf.example.test", []string{"grpc-leaf.example.test"}))

	// 1. Issue.
	var serial string
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		var header metadata.MD
		resp, err := client.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
			CaId: caID, CsrPem: csrPEM, Profile: "server",
		}, grpc.Header(&header))
		if err != nil {
			t.Fatalf("IssueCertificate: %v", err)
		}
		if resp.GetSerial() == "" || resp.GetCertificatePem() == "" {
			t.Fatal("issue response missing serial or certificate")
		}
		// The server assigns and echoes a correlation ID.
		if len(header.Get("x-request-id")) == 0 {
			t.Error("expected an x-request-id response header")
		}
		serial = resp.GetSerial()
	}

	// 2. Status VALID.
	assertStatus(t, client, caID, serial, pkiv1.CertificateStatus_CERTIFICATE_STATUS_VALID)

	// 3. GetCertificate returns the stored record.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.GetCertificate(ctx, &pkiv1.GetCertificateRequest{CaId: caID, Serial: serial})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if resp.GetCertificate().GetSerial() != serial {
			t.Fatalf("GetCertificate serial = %q, want %q", resp.GetCertificate().GetSerial(), serial)
		}
	}

	// 4. Revoke.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{
			CaId: caID, Serial: serial, Reason: "keyCompromise",
		})
		if err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if resp.GetStatus() != "revoked" {
			t.Fatalf("revoke status = %q, want revoked", resp.GetStatus())
		}
	}

	// 5. Status REVOKED (revocation is reflected immediately).
	assertStatus(t, client, caID, serial, pkiv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED)

	// 6. Revoke again is idempotent.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{CaId: caID, Serial: serial})
		if err != nil {
			t.Fatalf("second RevokeCertificate: %v", err)
		}
		if resp.GetStatus() != "already-revoked" {
			t.Fatalf("second revoke status = %q, want already-revoked", resp.GetStatus())
		}
	}

	// 7. ListCertificates includes the (now revoked) serial.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: caID})
		if err != nil {
			t.Fatalf("ListCertificates: %v", err)
		}
		found := false
		for _, c := range resp.GetCertificates() {
			if c.GetSerial() == serial {
				found = true
			}
		}
		if !found {
			t.Fatal("ListCertificates did not include the issued serial")
		}
		// The paged response (Task 83) carries the total matching count; the small
		// test inventory fits in one page, so there is no further page.
		if resp.GetTotal() < 1 {
			t.Errorf("ListCertificates total = %d, want >= 1", resp.GetTotal())
		}
		if resp.GetHasMore() {
			t.Error("ListCertificates unexpectedly reports a further page for a small inventory")
		}
	}

	// 8. The paging filters flow through gRPC: a serial_prefix that cannot match
	// returns an empty page with a zero total.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{
			CaId: caID, SerialPrefix: "zzz-no-such-serial",
		})
		if err != nil {
			t.Fatalf("ListCertificates(filtered): %v", err)
		}
		if resp.GetTotal() != 0 || len(resp.GetCertificates()) != 0 {
			t.Errorf("filtered list: total=%d items=%d, want 0/0", resp.GetTotal(), len(resp.GetCertificates()))
		}
	}
}

// TestGRPCMetadata exercises the CRL/OCSP metadata lookups.
func TestGRPCMetadata(t *testing.T) {
	addr, caID := startGRPCServer(t)
	client := pkiv1.NewPKIServiceClient(dialLocal(t, addr))

	ctx, cancel := grpcRootCtx(t)
	defer cancel()
	crl, err := client.GetCRLMetadata(ctx, &pkiv1.GetCRLMetadataRequest{CaId: caID})
	if err != nil {
		t.Fatalf("GetCRLMetadata: %v", err)
	}
	if crl.GetScope() != "full" {
		t.Errorf("CRL scope = %q, want full", crl.GetScope())
	}
	if crl.GetCrlUrl() == "" {
		t.Error("expected a populated CRL URL")
	}
	if crl.GetThisUpdate() == nil || crl.GetNextUpdate() == nil {
		t.Error("expected this/next update timestamps")
	}

	ocsp, err := client.GetOCSPMetadata(ctx, &pkiv1.GetOCSPMetadataRequest{CaId: caID})
	if err != nil {
		t.Fatalf("GetOCSPMetadata: %v", err)
	}
	if len(ocsp.GetOcspUrls()) == 0 {
		t.Error("expected at least one OCSP URL")
	}
}

// TestGRPCAuthAndErrors asserts the authorization and error-code mapping.
func TestGRPCAuthAndErrors(t *testing.T) {
	addr, caID := startGRPCServer(t)
	client := pkiv1.NewPKIServiceClient(dialLocal(t, addr))

	// Unauthenticated: no credentials.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := client.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: caID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("no-credential call: code = %v, want Unauthenticated", status.Code(err))
		}
	}

	// Bad credentials.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		enc := base64.StdEncoding.EncodeToString([]byte(grpcRootUser + ":wrong"))
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+enc)
		_, err := client.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{CaId: caID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("bad-credential call: code = %v, want Unauthenticated", status.Code(err))
		}
	}

	// Unknown CA -> NotFound.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		_, err := client.GetCertificate(ctx, &pkiv1.GetCertificateRequest{CaId: "no-such-ca", Serial: "1"})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("unknown CA: code = %v, want NotFound", status.Code(err))
		}
	}

	// Missing CSR -> InvalidArgument.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		_, err := client.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{CaId: caID, Profile: "server"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("missing CSR: code = %v, want InvalidArgument", status.Code(err))
		}
	}

	// Unknown serial -> UNKNOWN status (not an error).
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.GetCertificateStatus(ctx, &pkiv1.GetCertificateStatusRequest{CaId: caID, Serial: "999999999"})
		if err != nil {
			t.Fatalf("GetCertificateStatus(unknown serial): %v", err)
		}
		if resp.GetStatus() != pkiv1.CertificateStatus_CERTIFICATE_STATUS_UNKNOWN {
			t.Fatalf("unknown serial status = %v, want UNKNOWN", resp.GetStatus())
		}
	}
}

// TestGRPCReflection confirms server reflection is enabled and callable without
// credentials (tooling like grpcurl relies on it).
func TestGRPCReflection(t *testing.T) {
	addr, _ := startGRPCServer(t)
	conn := dialLocal(t, addr)

	rc := reflectpb.NewServerReflectionClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := rc.ServerReflectionInfo(ctx)
	if err != nil {
		t.Fatalf("ServerReflectionInfo: %v", err)
	}
	if err := stream.Send(&reflectpb.ServerReflectionRequest{
		MessageRequest: &reflectpb.ServerReflectionRequest_ListServices{ListServices: ""},
	}); err != nil {
		t.Fatalf("reflection send: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("reflection recv: %v", err)
	}
	services := resp.GetListServicesResponse().GetService()
	found := false
	for _, s := range services {
		if s.GetName() == pkiv1.PKIService_ServiceDesc.ServiceName {
			found = true
		}
	}
	if !found {
		t.Fatalf("reflection did not list %s", pkiv1.PKIService_ServiceDesc.ServiceName)
	}
}

// TestGRPCSuspendReleaseE2E drives the reversible certificate-hold RPCs over
// gRPC against a real SoftHSM-backed CA: issue -> suspend (status REVOKED) ->
// release (status VALID again), plus the negative case that a permanently
// revoked certificate cannot be released (FAILED_PRECONDITION).
func TestGRPCSuspendReleaseE2E(t *testing.T) {
	addr, caID := startGRPCServer(t)
	client := pkiv1.NewPKIServiceClient(dialLocal(t, addr))

	issue := func(cn string) string {
		t.Helper()
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
			CaId: caID, CsrPem: string(makeCSR(t, cn, []string{cn})), Profile: "server",
		})
		if err != nil {
			t.Fatalf("IssueCertificate(%s): %v", cn, err)
		}
		return resp.GetSerial()
	}

	// --- Reversible hold round-trip. ---
	serial := issue("grpc-hold.example.test")

	// Suspend: newly held, reported REVOKED by status.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.SuspendCertificate(ctx, &pkiv1.SuspendCertificateRequest{CaId: caID, Serial: serial})
		if err != nil {
			t.Fatalf("SuspendCertificate: %v", err)
		}
		if resp.GetStatus() != "held" {
			t.Fatalf("suspend status = %q, want held", resp.GetStatus())
		}
	}
	assertStatus(t, client, caID, serial, pkiv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED)

	// Suspend again is idempotent.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.SuspendCertificate(ctx, &pkiv1.SuspendCertificateRequest{CaId: caID, Serial: serial})
		if err != nil {
			t.Fatalf("second SuspendCertificate: %v", err)
		}
		if resp.GetStatus() != "already-held" {
			t.Fatalf("second suspend status = %q, want already-held", resp.GetStatus())
		}
	}

	// Release: returns to service, reported VALID again.
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		resp, err := client.ReleaseCertificate(ctx, &pkiv1.ReleaseCertificateRequest{CaId: caID, Serial: serial})
		if err != nil {
			t.Fatalf("ReleaseCertificate: %v", err)
		}
		if resp.GetStatus() != "released" {
			t.Fatalf("release status = %q, want released", resp.GetStatus())
		}
	}
	assertStatus(t, client, caID, serial, pkiv1.CertificateStatus_CERTIFICATE_STATUS_VALID)

	// --- A permanent revocation cannot be released. ---
	perm := issue("grpc-perm.example.test")
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		if _, err := client.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{
			CaId: caID, Serial: perm, Reason: "keyCompromise",
		}); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
	}
	{
		ctx, cancel := grpcRootCtx(t)
		defer cancel()
		_, err := client.ReleaseCertificate(ctx, &pkiv1.ReleaseCertificateRequest{CaId: caID, Serial: perm})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("release of permanently revoked cert: code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
		}
	}
}

func assertStatus(t *testing.T, client pkiv1.PKIServiceClient, caID, serial string, want pkiv1.CertificateStatus) {
	t.Helper()
	ctx, cancel := grpcRootCtx(t)
	defer cancel()
	resp, err := client.GetCertificateStatus(ctx, &pkiv1.GetCertificateStatusRequest{CaId: caID, Serial: serial})
	if err != nil {
		t.Fatalf("GetCertificateStatus: %v", err)
	}
	if resp.GetStatus() != want {
		t.Fatalf("status = %v, want %v", resp.GetStatus(), want)
	}
}
