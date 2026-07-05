package grpcapi

// gRPC transport for the stateless crypto service (Task 138): data-key, keyed
// HMAC, and CSPRNG random bytes. Like the certificate service, every RPC is a
// thin adapter over the shared handlers.API core methods, so the gRPC and REST
// surfaces enforce identical authorization, tenant scoping, quota, audit, and
// metrics. This file contains no crypto or policy of its own — only request/
// response marshaling and status-code mapping.

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// secretService implements pkiv1.SecretServiceServer by delegating to the shared
// API. It is registered only when the secret feature is enabled (a KEK is
// configured), mirroring how the REST secret routes are mounted; when disabled,
// the service is absent and the RPCs return Unimplemented.
type secretService struct {
	pkiv1.UnimplementedSecretServiceServer
	api *handlers.API
}

// mapSecretTenantErr maps a tenant-resolution failure to a status code, matching
// the REST secret path: a suspended tenant is a PermissionDenied gate, anything
// else (unknown tenant, malformed selector) is InvalidArgument.
func mapSecretTenantErr(err error) error {
	var suspended *models.TenantSuspendedError
	if errors.As(err, &suspended) {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return status.Error(codes.InvalidArgument, err.Error())
}

// mapSecretOpErr maps a crypto-service core error to a status code using the
// shared classification, so REST and gRPC never diverge on the same failure.
func mapSecretOpErr(err error) error {
	switch handlers.SecretErrorKind(err) {
	case "forbidden":
		return status.Error(codes.PermissionDenied, err.Error())
	case "bad_request":
		return status.Error(codes.InvalidArgument, err.Error())
	case "quota":
		return status.Error(codes.ResourceExhausted, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// GenerateDataKey mints a fresh data key and returns it in the clear plus wrapped
// under the family KEK.
func (s *secretService) GenerateDataKey(ctx context.Context, req *pkiv1.GenerateDataKeyRequest) (*pkiv1.GenerateDataKeyResponse, error) {
	tenant, kekLabel, err := s.api.ResolveSecretTenant(ctx, req.GetTenant())
	if err != nil {
		return nil, mapSecretTenantErr(err)
	}
	bits := int(req.GetBits())
	if bits == 0 {
		bits = 256
	}
	res, err := s.api.GenerateDataKeyOp(ctx, peerIP(ctx), tenant, kekLabel, bits, req.GetContext(), req.GetWrappedOnly())
	if err != nil {
		return nil, mapSecretOpErr(err)
	}
	return &pkiv1.GenerateDataKeyResponse{
		Plaintext:  res.Plaintext, // nil when wrapped_only
		Wrapped:    res.Envelope,
		Bits:       int32(res.Bits),
		KekLabel:   res.KEKLabel,
		KekVersion: int32(res.KEKVersion),
	}, nil
}

// GenerateHMAC computes a keyed HMAC over the supplied data.
func (s *secretService) GenerateHMAC(ctx context.Context, req *pkiv1.GenerateHMACRequest) (*pkiv1.GenerateHMACResponse, error) {
	tenant, kekLabel, err := s.api.ResolveSecretTenant(ctx, req.GetTenant())
	if err != nil {
		return nil, mapSecretTenantErr(err)
	}
	res, err := s.api.GenerateHMACOp(ctx, peerIP(ctx), tenant, kekLabel, req.GetData())
	if err != nil {
		return nil, mapSecretOpErr(err)
	}
	return &pkiv1.GenerateHMACResponse{
		Hmac:      res.MAC,
		Version:   int32(res.KeyVersion),
		Algorithm: res.Algorithm,
	}, nil
}

// VerifyHMAC constant-time verifies a keyed HMAC.
func (s *secretService) VerifyHMAC(ctx context.Context, req *pkiv1.VerifyHMACRequest) (*pkiv1.VerifyHMACResponse, error) {
	tenant, kekLabel, err := s.api.ResolveSecretTenant(ctx, req.GetTenant())
	if err != nil {
		return nil, mapSecretTenantErr(err)
	}
	res, err := s.api.VerifyHMACOp(ctx, peerIP(ctx), tenant, kekLabel, req.GetData(), req.GetHmac(), int(req.GetVersion()))
	if err != nil {
		return nil, mapSecretOpErr(err)
	}
	return &pkiv1.VerifyHMACResponse{Valid: res.Valid, Version: int32(res.KeyVersion)}, nil
}

// GenerateRandom returns CSPRNG bytes sourced from the HSM RNG when available.
func (s *secretService) GenerateRandom(ctx context.Context, req *pkiv1.GenerateRandomRequest) (*pkiv1.GenerateRandomResponse, error) {
	tenant, _, err := s.api.ResolveSecretTenant(ctx, req.GetTenant())
	if err != nil {
		return nil, mapSecretTenantErr(err)
	}
	res, err := s.api.GenerateRandomOp(ctx, peerIP(ctx), tenant, int(req.GetNumBytes()))
	if err != nil {
		return nil, mapSecretOpErr(err)
	}
	return &pkiv1.GenerateRandomResponse{Random: res.Bytes, Source: res.Source}, nil
}

// TransformEncode format-preserving-enciphers a value through a named FF1
// transform template.
func (s *secretService) TransformEncode(ctx context.Context, req *pkiv1.TransformRequest) (*pkiv1.TransformResponse, error) {
	return s.transform(ctx, req, true)
}

// TransformDecode inverts TransformEncode for the same template and tweak.
func (s *secretService) TransformDecode(ctx context.Context, req *pkiv1.TransformRequest) (*pkiv1.TransformResponse, error) {
	return s.transform(ctx, req, false)
}

// transform is the shared adapter for the encode/decode RPCs over the core
// TransformOp, so both share identical tenant scoping and status-code mapping.
func (s *secretService) transform(ctx context.Context, req *pkiv1.TransformRequest, encode bool) (*pkiv1.TransformResponse, error) {
	tenant, kekLabel, err := s.api.ResolveSecretTenant(ctx, req.GetTenant())
	if err != nil {
		return nil, mapSecretTenantErr(err)
	}
	res, err := s.api.TransformOp(ctx, peerIP(ctx), tenant, kekLabel, req.GetTemplate(), req.GetValue(), req.GetTweak(), encode)
	if err != nil {
		return nil, mapSecretOpErr(err)
	}
	return &pkiv1.TransformResponse{
		Template:      res.Template,
		Result:        res.Result,
		Deterministic: res.Deterministic,
	}, nil
}
