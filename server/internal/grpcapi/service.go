// Package grpcapi exposes the core PKI operations over gRPC alongside the
// existing REST surface (Task 56). It is a thin transport: every RPC delegates
// to the same ca.Manager issuance/revocation logic and the same
// handlers.API authorization, tenant-scoping, audit, HSM-audit, and OCSP-cache
// plumbing that backs the REST handlers, so both protocols enforce identical
// semantics with no duplicated business logic.
package grpcapi

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// service implements pkiv1.PKIServiceServer by delegating to the shared API.
type service struct {
	pkiv1.UnimplementedPKIServiceServer
	api *handlers.API
}

// newManager builds a per-call ca.Manager from the shared DB + key provider,
// mirroring how the REST handlers construct one per request.
func (s *service) newManager() *ca.Manager {
	return ca.NewManager(s.api.DB(), s.api.KeyProvider())
}

// IssueCertificate signs a CSR into an end-entity certificate. It reuses the
// REST authorization (AuthorizeIssueOn), HSM-audit bracketing, metrics, and
// audit-event recording so the two transports are behaviorally identical.
func (s *service) IssueCertificate(ctx context.Context, req *pkiv1.IssueCertificateRequest) (*pkiv1.CertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("issue", metrics.ResultDenied)
		s.audit(ctx, audit.ActionCertIssue, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if strings.TrimSpace(req.GetCsrPem()) == "" {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	// Per-profile manual issuance-approval gate (Task 84). Machine protocol flows
	// (ACME/EST/SCEP/CMP) bypass this; operator/API gRPC issuance under a
	// require_approval profile is held for approval and answered with a
	// FailedPrecondition carrying the request id, so the same four-eyes queue
	// backs both transports. The certificate is fetched over REST/CLI/console once
	// approved.
	if pa, gated, clientErr, gateErr := s.api.IssuanceApprovalGate(
		ctx, caID, req.GetProfile(), req.GetCsrPem(), int(req.GetValidityDays()), user, peerIP(ctx)); clientErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", clientErr)
	} else if gateErr != nil {
		return nil, status.Errorf(codes.Internal, "approval gate error: %v", gateErr)
	} else if gated {
		return nil, status.Errorf(codes.FailedPrecondition,
			"certificate issuance requires four-eyes approval: request %s needs %d distinct approver(s); once approved, fetch it via GET /api/approvals/%s/certificate",
			pa.ID, pa.RequiredApprovals, pa.ID)
	}

	mgr := s.newManager()
	s.api.ConsumeHSMAuditLogs("")
	result, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:        caID,
		CSRPEM:      []byte(req.GetCsrPem()),
		Profile:     req.GetProfile(),
		Validity:    daysToDuration(s.api.CapValidityDays(int(req.GetValidityDays()))),
		RequestedBy: user.Subject,
		MustStaple:  req.MustStaple,
		UPNs:        req.GetUpns(),
	})
	s.api.ConsumeHSMAuditLogs("")
	metrics.RecordCertificate("issue", err)
	if err != nil {
		s.audit(ctx, audit.ActionCertIssue, caID, "", audit.ResultError, err.Error())
		return nil, mapIssueError(err)
	}

	s.audit(ctx, audit.ActionCertIssue, caID, result.Serial.String(), audit.ResultSuccess,
		"profile="+result.Profile+" "+result.CT.Summary())
	return certificateResponse(result), nil
}

// PreviewCertificate validates a would-be issuance through the full fail-closed
// pre-issuance gate stack without signing, persisting, or consuming a serial
// (Task 113). It reuses the same authorization and transport-agnostic preview
// core (api.PreviewIssuance) as the REST endpoint, so both surfaces enforce
// identical semantics. It records no audit event and no metric — the preview is
// a pure read.
func (s *service) PreviewCertificate(ctx context.Context, req *pkiv1.PreviewCertificateRequest) (*pkiv1.PreviewCertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("issue", metrics.ResultDenied)
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	spec, berr := previewSpecFromGRPC(caID, req, user)
	if berr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	result, err := s.api.PreviewIssuance(ctx, spec)
	if err != nil {
		return nil, mapIssueError(err)
	}
	return previewResponse(result), nil
}

// RenewCertificate reissues a certificate with a fresh serial and validity.
func (s *service) RenewCertificate(ctx context.Context, req *pkiv1.RenewCertificateRequest) (*pkiv1.CertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("renew", metrics.ResultDenied)
		s.audit(ctx, audit.ActionCertRenew, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	mgr := s.newManager()
	s.api.ConsumeHSMAuditLogs("")
	result, err := mgr.RenewCertificate(ctx, ca.RenewSpec{
		CAID:        caID,
		Serial:      req.GetSerial(),
		CSRPEM:      []byte(req.GetCsrPem()),
		Validity:    daysToDuration(s.api.CapValidityDays(int(req.GetValidityDays()))),
		RequestedBy: user.Subject,
	})
	s.api.ConsumeHSMAuditLogs("")
	metrics.RecordCertificate("renew", err)
	if err != nil {
		s.audit(ctx, audit.ActionCertRenew, caID, req.GetSerial(), audit.ResultError, err.Error())
		return nil, mapIssueError(err)
	}

	s.audit(ctx, audit.ActionCertRenew, caID, result.Serial.String(), audit.ResultSuccess,
		"renewed_from="+req.GetSerial()+" "+result.CT.Summary())
	return certificateResponse(result), nil
}

// RevokeCertificate records a revocation and invalidates any cached OCSP
// response for the serial.
func (s *service) RevokeCertificate(ctx context.Context, req *pkiv1.RevokeCertificateRequest) (*pkiv1.RevokeCertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("revoke", metrics.ResultDenied)
		s.audit(ctx, audit.ActionCertRevoke, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	mgr := s.newManager()
	applied, err := mgr.RevokeCertificate(ctx, caID, req.GetSerial(), req.GetReason())
	metrics.RecordCertificate("revoke", err)
	if err != nil {
		s.audit(ctx, audit.ActionCertRevoke, caID, req.GetSerial(), audit.ResultError, err.Error())
		return nil, mapIssueError(err)
	}

	// Serve the new revoked status immediately rather than after the cache TTL.
	s.api.InvalidateOCSPCache(caID, req.GetSerial())

	statusStr := "revoked"
	if !applied {
		statusStr = "already-revoked"
	}
	s.audit(ctx, audit.ActionCertRevoke, caID, req.GetSerial(), audit.ResultSuccess,
		"reason="+req.GetReason()+" status="+statusStr)
	return &pkiv1.RevokeCertificateResponse{Serial: req.GetSerial(), Status: statusStr}, nil
}

// SuspendCertificate places a certificate on hold (RFC 5280 certificateHold), a
// reversible revocation. It shares the single-revocation authorization and
// OCSP-cache invalidation with RevokeCertificate.
func (s *service) SuspendCertificate(ctx context.Context, req *pkiv1.SuspendCertificateRequest) (*pkiv1.SuspendCertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("suspend", metrics.ResultDenied)
		s.audit(ctx, audit.ActionCertSuspend, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	mgr := s.newManager()
	applied, err := mgr.SuspendCertificate(ctx, caID, req.GetSerial())
	metrics.RecordCertificate("suspend", err)
	if err != nil {
		s.audit(ctx, audit.ActionCertSuspend, caID, req.GetSerial(), audit.ResultError, err.Error())
		return nil, mapIssueError(err)
	}

	s.api.InvalidateOCSPCache(caID, req.GetSerial())

	statusStr := "held"
	if !applied {
		statusStr = "already-held"
	}
	s.audit(ctx, audit.ActionCertSuspend, caID, req.GetSerial(), audit.ResultSuccess, "reason=certificateHold status="+statusStr)
	return &pkiv1.SuspendCertificateResponse{Serial: req.GetSerial(), Status: statusStr}, nil
}

// ReleaseCertificate removes a certificate hold. It succeeds only for a
// certificate on hold; a permanent revocation cannot be released
// (FAILED_PRECONDITION).
func (s *service) ReleaseCertificate(ctx context.Context, req *pkiv1.ReleaseCertificateRequest) (*pkiv1.ReleaseCertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	caID := req.GetCaId()

	ok, err := s.api.AuthorizeIssueOn(ctx, user, caID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
	}
	if !ok {
		metrics.Certificates.Inc("release", metrics.ResultDenied)
		s.audit(ctx, audit.ActionCertRelease, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		return nil, status.Error(codes.PermissionDenied, "no SIGN_CERTIFICATE permission on this CA")
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	if err := s.requireCA(caID); err != nil {
		return nil, err
	}

	mgr := s.newManager()
	err = mgr.ReleaseCertificate(ctx, caID, req.GetSerial())
	metrics.RecordCertificate("release", err)
	if err != nil {
		s.audit(ctx, audit.ActionCertRelease, caID, req.GetSerial(), audit.ResultError, err.Error())
		switch {
		case errors.Is(err, ca.ErrNotOnHold):
			return nil, status.Error(codes.FailedPrecondition, "certificate is not on hold; a permanent revocation cannot be released")
		case errors.Is(err, ca.ErrNotRevoked):
			return nil, status.Error(codes.FailedPrecondition, "certificate is not on hold (it is not revoked)")
		default:
			return nil, mapIssueError(err)
		}
	}

	s.api.InvalidateOCSPCache(caID, req.GetSerial())

	s.audit(ctx, audit.ActionCertRelease, caID, req.GetSerial(), audit.ResultSuccess, "removed hold; removeFromCRL in next delta CRL")
	return &pkiv1.ReleaseCertificateResponse{Serial: req.GetSerial(), Status: "released"}, nil
}

// GetCertificate returns the authority's stored copy of a certificate, gated by
// tenant-scoped read authorization.
func (s *service) GetCertificate(ctx context.Context, req *pkiv1.GetCertificateRequest) (*pkiv1.GetCertificateResponse, error) {
	user := middleware.GetUserInfo(ctx)
	if _, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId()); err != nil {
		return nil, mapAuthzError(err)
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	// Reflect expiry lazily so the returned status is accurate.
	_, _ = s.api.DB().MarkExpiredCertificates(req.GetCaId(), time.Now())
	cert, err := s.api.DB().GetIssuedCertificate(req.GetCaId(), req.GetSerial())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load certificate: %v", err)
	}
	if cert == nil {
		return nil, status.Error(codes.NotFound, "certificate not found")
	}
	return &pkiv1.GetCertificateResponse{Certificate: certificateInfo(cert)}, nil
}

// GetCertificateStatus returns only the coarse lifecycle status for a serial.
func (s *service) GetCertificateStatus(ctx context.Context, req *pkiv1.GetCertificateStatusRequest) (*pkiv1.GetCertificateStatusResponse, error) {
	user := middleware.GetUserInfo(ctx)
	if _, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId()); err != nil {
		return nil, mapAuthzError(err)
	}
	if strings.TrimSpace(req.GetSerial()) == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	_, _ = s.api.DB().MarkExpiredCertificates(req.GetCaId(), time.Now())
	cert, err := s.api.DB().GetIssuedCertificate(req.GetCaId(), req.GetSerial())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load certificate: %v", err)
	}
	if cert == nil {
		// A serial the authority never issued: report UNKNOWN rather than an error,
		// so callers can distinguish "no record" from "denied".
		return &pkiv1.GetCertificateStatusResponse{Status: pkiv1.CertificateStatus_CERTIFICATE_STATUS_UNKNOWN}, nil
	}
	resp := &pkiv1.GetCertificateStatusResponse{
		Status:           certStatus(cert.Status),
		RevocationReason: int32(cert.RevocationReason),
	}
	if cert.RevokedAt != nil {
		resp.RevokedAt = timestamppb.New(*cert.RevokedAt)
	}
	return resp, nil
}

// ListCertificates returns one keyset page of the certificates a CA has issued,
// newest first (Task 83). It mirrors the REST endpoint's pagination and filter
// surface: limit/cursor plus status/profile/query/serial_prefix/expires_before.
func (s *service) ListCertificates(ctx context.Context, req *pkiv1.ListCertificatesRequest) (*pkiv1.ListCertificatesResponse, error) {
	user := middleware.GetUserInfo(ctx)
	if _, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId()); err != nil {
		return nil, mapAuthzError(err)
	}
	filter := database.CertFilter{
		Status:       req.GetStatus(),
		Profile:      req.GetProfile(),
		Query:        req.GetQuery(),
		SerialPrefix: req.GetSerialPrefix(),
	}
	if req.GetExpiresBefore() != nil {
		filter.ExpiresBefore = req.GetExpiresBefore().AsTime()
	}
	page := database.CertPageRequest{Limit: int(req.GetLimit()), Cursor: req.GetCursor()}

	_, _ = s.api.DB().MarkExpiredCertificates(req.GetCaId(), time.Now())
	result, err := s.api.DB().PageIssuedCertificates(req.GetCaId(), filter, page)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCursor) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to list certificates: %v", err)
	}
	out := &pkiv1.ListCertificatesResponse{
		Certificates: make([]*pkiv1.CertificateInfo, 0, len(result.Items)),
		NextCursor:   result.NextCursor,
		Total:        int32(result.Total),
		HasMore:      result.HasMore,
	}
	for i := range result.Items {
		out.Certificates = append(out.Certificates, certificateInfo(&result.Items[i]))
	}
	return out, nil
}

// GetCRLMetadata returns distribution metadata for a CA's CRL. It regenerates
// the CRL on the HSM only when the published copy is stale, then reports the
// stored base (and delta, if any) numbers, update windows, and public URLs.
func (s *service) GetCRLMetadata(ctx context.Context, req *pkiv1.GetCRLMetadataRequest) (*pkiv1.GetCRLMetadataResponse, error) {
	user := middleware.GetUserInfo(ctx)
	if _, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId()); err != nil {
		return nil, mapAuthzError(err)
	}

	shard := ca.FullScope
	if req.Shard != nil {
		shard = int(req.GetShard())
	}

	mgr := s.newManager()
	s.api.ConsumeHSMAuditLogs("")
	if _, err := mgr.GetBaseCRL(ctx, req.GetCaId(), shard); err != nil {
		s.api.ConsumeHSMAuditLogs("")
		return nil, status.Errorf(codes.Internal, "failed to build CRL: %v", err)
	}
	s.api.ConsumeHSMAuditLogs("")

	scope := scopeName(shard)
	base, err := s.api.DB().GetPublishedCRL(req.GetCaId(), scope, "base")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read CRL metadata: %v", err)
	}
	if base == nil {
		return nil, status.Error(codes.NotFound, "no CRL published for this scope")
	}

	resp := &pkiv1.GetCRLMetadataResponse{
		Scope:       scope,
		CrlNumber:   base.Number,
		ThisUpdate:  timestamppb.New(base.ThisUpdate),
		NextUpdate:  timestamppb.New(base.NextUpdate),
		CrlUrl:      ca.PublicCRLURL(req.GetCaId(), shard),
		DeltaCrlUrl: ca.PublicDeltaCRLURL(req.GetCaId(), shard),
		ShardCount:  int32(ca.CRLShardCount()),
	}
	// Report delta metadata only when a delta has actually been published.
	if delta, err := s.api.DB().GetPublishedCRL(req.GetCaId(), scope, "delta"); err == nil && delta != nil {
		resp.DeltaAvailable = true
		resp.DeltaCrlNumber = delta.Number
		resp.DeltaThisUpdate = timestamppb.New(delta.ThisUpdate)
		resp.DeltaNextUpdate = timestamppb.New(delta.NextUpdate)
	}
	return resp, nil
}

// GetOCSPMetadata returns the OCSP responder endpoint(s) and hardening options.
func (s *service) GetOCSPMetadata(ctx context.Context, req *pkiv1.GetOCSPMetadataRequest) (*pkiv1.GetOCSPMetadataResponse, error) {
	user := middleware.GetUserInfo(ctx)
	if _, err := s.api.AuthorizeCARead(ctx, user, req.GetCaId()); err != nil {
		return nil, mapAuthzError(err)
	}
	nonce, delegated := s.api.OCSPResponderInfo()
	resp := &pkiv1.GetOCSPMetadataResponse{
		NonceSupported:     nonce,
		DelegatedResponder: delegated,
	}
	if u := ca.PublicOCSPURL(req.GetCaId()); u != "" {
		resp.OcspUrls = []string{u}
	}
	return resp, nil
}

// audit appends a tamper-evident audit event, deriving the client IP from the
// gRPC peer address carried on ctx.
func (s *service) audit(ctx context.Context, action, target, targetName, result, detail string) {
	s.api.RecordAuditEvent(ctx, peerIP(ctx), action, target, targetName, result, detail)
}

// requireCA maps an unknown CA to a clean NotFound before invoking the manager,
// so callers get NOT_FOUND rather than an INVALID_ARGUMENT wrapping an internal
// "CA not found" string.
func (s *service) requireCA(caID string) error {
	caModel, err := s.api.DB().GetCA(caID)
	if err != nil {
		return status.Errorf(codes.Internal, "database error: %v", err)
	}
	if caModel == nil {
		return status.Errorf(codes.NotFound, "CA %q not found", caID)
	}
	return nil
}

// --- conversion + error-mapping helpers ---

// daysToDuration converts a validity-in-days value to a Duration. Non-positive
// values yield zero, which downstream treats as "use the profile default".
func daysToDuration(days int) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// scopeName maps a shard index to its persisted scope string ("full" or
// "partition:N").
func scopeName(shard int) string {
	if shard < 0 {
		return "full"
	}
	return "partition:" + strconv.Itoa(shard)
}

// previewSpecFromGRPC builds a ca.PreviewSpec from a PreviewCertificate request.
// The requested validity is passed through raw (not globally capped) so the
// validity gate can report a request that exceeds the profile maximum.
func previewSpecFromGRPC(caID string, req *pkiv1.PreviewCertificateRequest, user *models.UserInfo) (ca.PreviewSpec, error) {
	spec := ca.PreviewSpec{
		CAID:        caID,
		CSRPEM:      []byte(req.GetCsrPem()),
		Profile:     req.GetProfile(),
		Validity:    daysToDuration(int(req.GetValidityDays())),
		RequestedBy: user.Subject,
		MustStaple:  req.MustStaple,
		UPNs:        req.GetUpns(),
	}
	if strings.TrimSpace(req.GetCsrPem()) == "" {
		spec.Subject = pkix.Name{CommonName: req.GetCommonName()}
		spec.DNSNames = req.GetDnsNames()
		spec.EmailAddresses = req.GetEmailAddresses()
		spec.URIs = req.GetUris()
		for _, ip := range req.GetIpAddresses() {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return ca.PreviewSpec{}, fmt.Errorf("invalid ip_addresses entry %q", ip)
			}
			spec.IPAddresses = append(spec.IPAddresses, parsed)
		}
	}
	return spec, nil
}

// previewResponse renders a ca.PreviewResult as the gRPC preview response.
func previewResponse(r *ca.PreviewResult) *pkiv1.PreviewCertificateResponse {
	resp := &pkiv1.PreviewCertificateResponse{
		CaId:                  r.CAID,
		CaLabel:               r.CALabel,
		Profile:               r.Profile,
		Decision:              r.Decision,
		WouldIssue:            r.WouldIssue,
		WouldPark:             r.WouldPark,
		RequiresApproval:      r.RequiresApproval,
		Subject:               r.Subject,
		Sans:                  r.SANs,
		KeyUsages:             r.KeyUsages,
		ExtKeyUsages:          r.ExtKeyUsages,
		NotBefore:             timestamppb.New(r.NotBefore),
		NotAfter:              timestamppb.New(r.NotAfter),
		ValidityDays:          int32(r.ValidityDays),
		RequestedValidityDays: int32(r.RequestedValidityDays),
		MaxValidityDays:       int32(r.MaxValidityDays),
		SubjectKeyId:          r.SubjectKeyID,
		AuthorityKeyId:        r.AuthorityKeyID,
		SubjectKeyProvided:    r.SubjectKeyProvided,
		MustStaple:            r.MustStaple,
	}
	for _, e := range r.Extensions {
		resp.Extensions = append(resp.Extensions, &pkiv1.PreviewExtension{
			Oid:      e.OID,
			Name:     e.Name,
			Critical: e.Critical,
		})
	}
	for _, g := range r.Gates {
		resp.Gates = append(resp.Gates, &pkiv1.PreviewGate{
			Name:     g.Name,
			Status:   string(g.Status),
			Reason:   g.Reason,
			Findings: g.Findings,
		})
	}
	return resp
}

// certificateResponse renders an issuance result as the gRPC response.
func certificateResponse(result *ca.IssueResult) *pkiv1.CertificateResponse {
	resp := &pkiv1.CertificateResponse{
		CertificatePem: string(result.PEM),
		ChainPem:       string(result.ChainPEM),
		Serial:         result.Serial.String(),
		Profile:        result.Profile,
		NotBefore:      timestamppb.New(result.Certificate.NotBefore),
		NotAfter:       timestamppb.New(result.Certificate.NotAfter),
	}
	if ct := result.CT; ct != nil && ct.Enabled {
		info := &pkiv1.CTInfo{
			Enabled:  true,
			Embedded: ct.Embedded,
			SctCount: int32(ct.SCTCount),
		}
		if result.Record != nil {
			info.Status = string(result.Record.CTStatus)
		}
		for _, r := range ct.Logs {
			info.Logs = append(info.Logs, &pkiv1.CTLogOutcome{Log: r.Log, Ok: r.OK, Error: r.Error})
		}
		resp.Ct = info
	}
	return resp
}

// certificateInfo renders a stored certificate record as the gRPC message.
func certificateInfo(c *models.IssuedCertificate) *pkiv1.CertificateInfo {
	info := &pkiv1.CertificateInfo{
		CaId:             c.CAID,
		Serial:           c.Serial,
		Subject:          c.Subject,
		CommonName:       c.CommonName,
		Sans:             c.SANs,
		Profile:          c.Profile,
		CertificatePem:   c.Certificate,
		NotBefore:        timestamppb.New(c.NotBefore),
		NotAfter:         timestamppb.New(c.NotAfter),
		Status:           certStatus(c.Status),
		RevocationReason: int32(c.RevocationReason),
		RequestedBy:      c.RequestedBy,
		CreatedAt:        timestamppb.New(c.CreatedAt),
	}
	if c.RevokedAt != nil {
		info.RevokedAt = timestamppb.New(*c.RevokedAt)
	}
	return info
}

// certStatus maps the stored certificate status to the protobuf enum. A held
// (suspended) certificate is reported REVOKED: it is revoked from a relying
// party's perspective (OCSP revoked, on the base CRL) for as long as the hold
// stands, and the enum has no dedicated on-hold value.
func certStatus(s models.CertStatus) pkiv1.CertificateStatus {
	switch s {
	case models.CertStatusValid:
		return pkiv1.CertificateStatus_CERTIFICATE_STATUS_VALID
	case models.CertStatusRevoked, models.CertStatusHeld:
		return pkiv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED
	case models.CertStatusExpired:
		return pkiv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	default:
		return pkiv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED
	}
}

// mapAuthzError maps the handlers authorization sentinels to gRPC status codes.
func mapAuthzError(err error) error {
	switch {
	case errors.Is(err, handlers.ErrForbidden):
		return status.Error(codes.PermissionDenied, "read access requires a role (admin, issuer, signer, or auditor)")
	case errors.Is(err, handlers.ErrNotFound):
		return status.Error(codes.NotFound, "CA not found")
	default:
		return status.Errorf(codes.Internal, "authorization failed: %v", err)
	}
}

// mapIssueError maps a manager issuance/renewal/revocation error to a gRPC
// status. The REST handlers return HTTP 400 for these; the closest gRPC code is
// InvalidArgument for client-caused failures (bad CSR, profile, policy/lint/CAA
// rejection), with a context cancellation surfaced faithfully. Tenant gate
// refusals (Task 61) map to their own codes, mirroring REST's 429/403.
func mapIssueError(err error) error {
	var quota *models.QuotaExceededError
	var susp *models.TenantSuspendedError
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case errors.As(err, &quota):
		// ResourceExhausted is gRPC's equivalent of HTTP 429; clients should
		// back off until the daily window resets.
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.As(err, &susp):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.InvalidArgument, err.Error())
	}
}
