package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blechschmidt/secsy-pki/server/internal/certvalidate"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ValidateChain builds and validates a supplied leaf (and optional intermediates)
// against a CA's configured trust anchors and returns a structured verdict
// (Task 123). It reuses the same tenant-scoped read authorization (AuthorizeCARead)
// and transport-agnostic validation core (api.RunChainValidation) as the REST
// endpoint, so both surfaces enforce identical semantics. It is a pure read: no
// HSM, no signing, no serial, no audit event, and no metric.
func (s *service) ValidateChain(ctx context.Context, req *pkiv1.ValidateChainRequest) (*pkiv1.ValidateChainResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caModel, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId())
	if err != nil {
		return nil, mapAuthzError(err)
	}
	if strings.TrimSpace(req.GetLeafPem()) == "" {
		return nil, status.Error(codes.InvalidArgument, "leaf_pem is required")
	}

	intermediates := make([][]byte, 0, len(req.GetIntermediatesPem()))
	for _, im := range req.GetIntermediatesPem() {
		if strings.TrimSpace(im) == "" {
			continue
		}
		intermediates = append(intermediates, []byte(im))
	}

	report, err := s.api.RunChainValidation(ctx, caModel, []byte(req.GetLeafPem()), intermediates, req.GetSkipRevocation())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return validateChainResponse(caModel, report), nil
}

// validateChainResponse renders a certvalidate.Report as the gRPC response.
func validateChainResponse(caModel *models.CA, r *certvalidate.Report) *pkiv1.ValidateChainResponse {
	resp := &pkiv1.ValidateChainResponse{
		CaId:        caModel.ID,
		CaLabel:     caModel.Label,
		TrustAnchor: r.TrustAnchor,
		ChainBuilt:  r.ChainBuilt,
		Valid:       r.Valid,
		Decision:    r.Decision,
		EvaluatedAt: timestamppb.New(r.Now),
		ValidFrom:   timestamppb.New(r.ValidFrom),
		ValidUntil:  timestamppb.New(r.ValidUntil),
		Reasons:     r.Reasons,
		Warnings:    r.Warnings,
	}
	for _, ci := range r.Chain {
		vc := &pkiv1.ValidatedCertificate{
			Position:           int32(ci.Position),
			Subject:            ci.Subject,
			Issuer:             ci.Issuer,
			SerialNumber:       ci.SerialNumber,
			NotBefore:          timestamppb.New(ci.NotBefore),
			NotAfter:           timestamppb.New(ci.NotAfter),
			IsCa:               ci.IsCA,
			IsTrustAnchor:      ci.IsTrustAnchor,
			SelfSigned:         ci.SelfSigned,
			KeyAlgorithm:       ci.KeyAlgorithm,
			KeySize:            int32(ci.KeySize),
			SignatureAlgorithm: ci.SignatureAlgorithm,
			Fingerprint:        ci.Fingerprint,
			SubjectKeyId:       ci.SubjectKeyID,
			AuthorityKeyId:     ci.AuthorityKeyID,
			KeyUsage:           ci.KeyUsage,
			ExtKeyUsage:        ci.ExtKeyUsage,
			Policies:           ci.Policies,
			Expired:            ci.Expired,
			NotYetValid:        ci.NotYetValid,
			WeakKey:            ci.WeakKey,
			WeakSignature:      ci.WeakSignature,
			WeakKeyReasons:     ci.WeakKeyReasons,
		}
		if ci.Revocation != nil {
			vc.Revocation = &pkiv1.ValidationRevocation{
				State:      string(ci.Revocation.State),
				Reason:     int32(ci.Revocation.Reason),
				ReasonText: ci.Revocation.ReasonText,
				Source:     ci.Revocation.Source,
			}
			if !ci.Revocation.RevokedAt.IsZero() {
				vc.Revocation.RevokedAt = timestamppb.New(ci.Revocation.RevokedAt)
			}
		}
		resp.Chain = append(resp.Chain, vc)
	}
	for _, c := range r.Checks {
		resp.Checks = append(resp.Checks, &pkiv1.ValidationCheck{
			Name:     c.Name,
			Status:   string(c.Status),
			Detail:   c.Detail,
			Findings: c.Findings,
		})
	}
	return resp
}
