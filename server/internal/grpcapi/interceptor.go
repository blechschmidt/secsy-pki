package grpcapi

import (
	"context"
	"crypto/x509"
	"log"
	"runtime/debug"
	"strings"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
)

// requestIDMetaKey is the call-metadata key used to receive and echo the
// per-call correlation ID, matching the REST X-Request-ID header (lower-cased,
// as gRPC metadata keys are).
const requestIDMetaKey = "x-request-id"

// contextInterceptor is the outermost unary interceptor. It continues any
// upstream W3C trace carried in call metadata, assigns/propagates a correlation
// ID, installs the tenant holder, opens a per-call span, and echoes the
// correlation ID back to the caller. It mirrors the HTTP observability
// middleware so gRPC calls share the same request-ID and tracing plumbing.
func (s *Server) contextInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	md, _ := metadata.FromIncomingContext(ctx)

	// Continue any upstream trace propagated over metadata (W3C traceparent).
	ctx = otel.GetTextMapPropagator().Extract(ctx, metadataCarrier(md))

	// Assign or continue the correlation ID and stash it for the audit layer.
	reqID := sanitizeRequestID(firstMeta(md, requestIDMetaKey))
	if reqID == "" {
		reqID = uuid.NewString()
	}
	ctx = middleware.WithRequestID(ctx, reqID)
	ctx = middleware.WithTenantHolder(ctx)
	// Echo the correlation ID so clients can tie their logs to ours.
	_ = grpc.SetHeader(ctx, metadata.Pairs(requestIDMetaKey, reqID))

	ctx, span := tracing.Start(ctx, "grpc "+info.FullMethod)
	defer span.End()

	resp, err := handler(ctx, req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return resp, err
}

// authInterceptor authenticates every application RPC using the same credential
// set as the REST middleware (Authorization metadata: Basic root / Bearer OIDC;
// or a bound mutual-TLS client certificate), installing the resolved principal
// on the context. The gRPC server-reflection service is exempt: it exposes only
// the (public) schema and is commonly consumed by tooling without credentials.
func (s *Server) authInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if isPublicMethod(info.FullMethod) {
		return handler(ctx, req)
	}

	md, _ := metadata.FromIncomingContext(ctx)
	authorization := firstMeta(md, "authorization")
	peerCerts := peerCertificates(ctx)

	user, err := s.authMw.AuthenticateRPC(ctx, authorization, peerCerts)
	if err != nil {
		metrics.RecordAuthLogin("grpc", false)
		switch err {
		case middleware.ErrNoCredentials:
			return nil, status.Error(grpccodes.Unauthenticated, "authorization required")
		case middleware.ErrInvalidCredentials:
			return nil, status.Error(grpccodes.Unauthenticated, "invalid credentials")
		default:
			return nil, status.Error(grpccodes.Unauthenticated, err.Error())
		}
	}
	metrics.RecordAuthLogin("grpc", true)

	ctx = context.WithValue(ctx, middleware.UserInfoKey, user)
	return handler(ctx, req)
}

// recoveryInterceptor converts a panic in a handler into an Internal status so a
// single malformed call cannot crash the server process.
func (s *Server) recoveryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("gRPC handler panic in %s: %v\n%s", info.FullMethod, r, debug.Stack())
			err = status.Error(grpccodes.Internal, "internal error")
		}
	}()
	return handler(ctx, req)
}

// isPublicMethod reports whether a fully-qualified method may be called without
// authentication. Only the reflection and health services qualify.
func isPublicMethod(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, "/grpc.reflection.") ||
		strings.HasPrefix(fullMethod, "/grpc.health.")
}

// peerCertificates returns the verified client-certificate chain from the TLS
// peer on ctx, or nil for a plaintext connection or one without a client cert.
func peerCertificates(ctx context.Context) []*x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return tlsInfo.State.PeerCertificates
}

// peerIP returns the client IP of the gRPC peer on ctx, for audit attribution.
func peerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// firstMeta returns the first value for key in md, or "".
func firstMeta(md metadata.MD, key string) string {
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// sanitizeRequestID bounds and filters an inbound correlation ID to printable
// ASCII, preventing log/metadata injection. It mirrors the HTTP middleware's
// handling.
func sanitizeRequestID(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return ""
		}
	}
	return s
}

// metadataCarrier adapts gRPC metadata to the OpenTelemetry TextMapCarrier so
// the global propagator can extract W3C trace context from incoming calls.
type metadataCarrier metadata.MD

func (c metadataCarrier) Get(key string) string {
	vals := metadata.MD(c).Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (c metadataCarrier) Set(key, value string) { metadata.MD(c).Set(key, value) }

func (c metadataCarrier) Keys() []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}

// ensure metadataCarrier satisfies the propagation carrier interface.
var _ propagation.TextMapCarrier = metadataCarrier{}
