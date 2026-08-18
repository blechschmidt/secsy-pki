//go:build sqlite

package grpcapi_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/unixsocket"
)

// newSocketAPI builds the same API and auth middleware the REST surface uses,
// backed by an in-memory store and a software key provider.
func newSocketAPI(t *testing.T) (*handlers.API, *middleware.AuthMiddleware) {
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
	return handlers.NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, ""),
		middleware.NewAuthMiddleware(nil, "root", "rootpw")
}

// newSocketServer starts the gRPC surface on a Unix-domain socket and returns
// the socket path.
func newSocketServer(t *testing.T, cfg unixsocket.Config) (*grpcapi.Server, string) {
	t.Helper()
	api, authMw := newSocketAPI(t)

	// No Address and no TLS: the socket alone must be enough to start, which is
	// the whole point of Unix-socket mode.
	srv, err := grpcapi.New(grpcapi.Config{UnixSocket: cfg}, api, authMw)
	if err != nil {
		t.Fatalf("grpcapi.New: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(srv.Stop)
	return srv, cfg.SocketPath()
}

func socketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "g.sock")
}

// TestGRPCOverUnixSocket is the end-to-end proof: a server that binds no TCP
// port at all still answers RPCs over the socket, dialled with the "unix://"
// target gRPC resolves natively.
func TestGRPCOverUnixSocket(t *testing.T) {
	path := socketPath(t)
	srv, _ := newSocketServer(t, unixsocket.Config{Path: path})

	if srv.Addr() != path {
		t.Errorf("Addr() = %q, want the socket path %q", srv.Addr(), path)
	}

	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health/Check over the socket: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("health status = %v, want SERVING", resp.GetStatus())
	}
}

// TestGRPCUnixSocketBindsNoPort pins the "only over a socket" contract: the
// default gRPC port must be free while the socket server is running.
func TestGRPCUnixSocketBindsNoPort(t *testing.T) {
	path := socketPath(t)
	newSocketServer(t, unixsocket.Config{Path: path})

	// grpcapi.New would have used ":9443" had it fallen back to a TCP bind;
	// claiming the port here proves it did not.
	lis, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		t.Fatalf("the gRPC port should be free in socket mode: %v", err)
	}
	_ = lis.Close()
}

// TestGRPCUnixSocketPermissions checks that the socket the gRPC listener leaves
// on disk carries the configured mode — the access boundary in socket mode.
func TestGRPCUnixSocketPermissions(t *testing.T) {
	path := socketPath(t)
	newSocketServer(t, unixsocket.Config{Path: path, Mode: "0660"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket", path)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %#o, want 0660", got)
	}
}

// TestGRPCRequiresTLSOrSocket keeps the fail-closed rule intact for TCP: without
// TLS and without an insecure opt-in, only a Unix socket may serve cleartext.
func TestGRPCRequiresTLSOrSocket(t *testing.T) {
	_, err := grpcapi.New(grpcapi.Config{Address: "127.0.0.1:0"}, nil, nil)
	if err == nil {
		t.Fatal("a TCP listener without TLS must be refused")
	}
	if !strings.Contains(err.Error(), "no TLS configured") {
		t.Errorf("error should explain the refusal, got: %v", err)
	}

	if _, err := grpcapi.New(grpcapi.Config{}, nil, nil); err == nil {
		t.Fatal("a server with neither an address nor a socket must be refused")
	}
}

// TestGRPCUnixSocketBadPathFails surfaces a socket that cannot be bound as a
// startup error rather than a silently port-bound server.
func TestGRPCUnixSocketBadPathFails(t *testing.T) {
	occupied := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(occupied, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	api, authMw := newSocketAPI(t)
	_, err := grpcapi.New(grpcapi.Config{UnixSocket: unixsocket.Config{Path: occupied}}, api, authMw)
	if err == nil {
		t.Fatal("binding over a regular file must fail")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error should name the conflict, got: %v", err)
	}
}
