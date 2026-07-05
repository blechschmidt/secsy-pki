package grpcapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// Config configures the gRPC listener.
type Config struct {
	// Address is the host:port the gRPC server listens on (e.g. ":9443").
	Address string
	// TLSCert / TLSKey are the PEM files for the server's TLS certificate. When
	// both are set the server serves gRPC over TLS. When empty the server serves
	// plaintext h2c — refused unless the operator has opted into insecure mode
	// (see the caller). An enterprise deployment always terminates TLS.
	TLSCert string
	TLSKey  string
	// ClientCAs, when non-nil, enables mutual-TLS: the server requests a client
	// certificate and the pool is offered for chain verification. As on the REST
	// listener, a presented cert is verified-if-given (not required) so callers
	// authenticating by Bearer/Basic still connect; the auth interceptor binds a
	// presented, trusted cert to a principal.
	ClientCAs *x509.CertPool
	// Insecure permits serving plaintext gRPC (no TLS). Set only when the operator
	// explicitly opted into insecure HTTP, e.g. behind a trusted TLS-terminating
	// proxy or in tests.
	Insecure bool
}

// Server wraps a configured *grpc.Server for the PKI service. It reuses the same
// handlers.API (issuance, RBAC, audit, HSM, OCSP cache) and auth middleware
// (mTLS binder, OIDC verifier, root credentials) as the REST surface, so the two
// protocols enforce identical authorization and audit semantics.
type Server struct {
	api    *handlers.API
	authMw *middleware.AuthMiddleware
	grpc   *grpc.Server
	lis    net.Listener
	addr   string
}

// New constructs a Server: it opens the listener, builds the gRPC server with
// the context/auth/recovery interceptors and TLS credentials, registers the PKI
// service, a health service, and server reflection. Call Serve to run it.
func New(cfg Config, api *handlers.API, authMw *middleware.AuthMiddleware) (*Server, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("grpc: address is required")
	}
	s := &Server{api: api, authMw: authMw, addr: cfg.Address}

	var opts []grpc.ServerOption
	switch {
	case cfg.TLSCert != "" && cfg.TLSKey != "":
		creds, err := serverTLS(cfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	case cfg.Insecure:
		// Plaintext gRPC; the caller has opted into insecure mode.
	default:
		return nil, fmt.Errorf("grpc: no TLS configured (set server.tls_cert/tls_key) — " +
			"refusing to serve cleartext gRPC unless insecure HTTP is explicitly allowed")
	}

	// Interceptor order (outermost first): recovery, then context (request-ID,
	// trace, tenant holder, span), then auth. Authentication runs innermost so it
	// executes within the per-call span and correlation ID. The streaming chain
	// mirrors the unary one so server-streaming RPCs (StreamEvents) share the same
	// context propagation and authentication.
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			s.recoveryInterceptor,
			s.contextInterceptor,
			s.authInterceptor,
		),
		grpc.ChainStreamInterceptor(
			s.streamRecoveryInterceptor,
			s.streamContextInterceptor,
			s.streamAuthInterceptor,
		),
	)

	s.grpc = grpc.NewServer(opts...)
	pkiv1.RegisterPKIServiceServer(s.grpc, &service{api: api})
	// The stateless crypto service (Task 138) is served only when a KEK is
	// configured, mirroring the REST secret routes; when disabled its RPCs return
	// Unimplemented rather than a per-call error.
	secretEnabled := api.SecretEnabled()
	if secretEnabled {
		pkiv1.RegisterSecretServiceServer(s.grpc, &secretService{api: api})
	}

	// Health service for load-balancer / Kubernetes gRPC probes. Report SERVING
	// for the whole server and the PKI service.
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus(pkiv1.PKIService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	if secretEnabled {
		hs.SetServingStatus(pkiv1.SecretService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	}
	healthpb.RegisterHealthServer(s.grpc, hs)

	// Server reflection so grpcurl and other tooling can discover the schema.
	reflection.Register(s.grpc)

	lis, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("grpc: listen on %s: %w", cfg.Address, err)
	}
	s.lis = lis
	return s, nil
}

// Addr returns the actual address the server is listening on (useful when the
// configured port was 0 and the OS assigned one, e.g. in tests).
func (s *Server) Addr() string {
	if s.lis != nil {
		return s.lis.Addr().String()
	}
	return s.addr
}

// Serve runs the gRPC server until the listener is closed or GracefulStop is
// called. It blocks; run it in its own goroutine.
func (s *Server) Serve() error { return s.grpc.Serve(s.lis) }

// GracefulStop stops the server, letting in-flight RPCs finish.
func (s *Server) GracefulStop() { s.grpc.GracefulStop() }

// Stop stops the server immediately, cancelling in-flight RPCs.
func (s *Server) Stop() { s.grpc.Stop() }

// serverTLS builds the transport credentials for the gRPC listener, mirroring
// the REST listener's TLS policy: TLS 1.2 minimum, and — when a client-CA pool
// is supplied — request (but do not require) a client certificate so both mTLS
// and Bearer/Basic callers can connect.
func serverTLS(cfg Config) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("grpc: loading TLS key pair: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if cfg.ClientCAs != nil {
		tlsCfg.ClientCAs = cfg.ClientCAs
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return credentials.NewTLS(tlsCfg), nil
}
