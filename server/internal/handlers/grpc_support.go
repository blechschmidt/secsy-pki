package handlers

import (
	"context"
	"errors"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// This file exposes a small, context-based facade over the API's existing
// authorization, audit, and HSM plumbing so an alternative transport (the gRPC
// server, Task 56) can reuse the exact same business logic as the REST handlers
// rather than duplicating it. Every method here delegates to the same unexported
// helpers the HTTP handlers use, so RBAC, tenant scoping, and the tamper-evident
// audit chain behave identically across both protocols.

// Authorization outcomes surfaced to non-HTTP transports. The gRPC layer maps
// these to the appropriate transport status codes (PermissionDenied / NotFound).
var (
	// ErrForbidden indicates the caller lacks the capability for the operation.
	ErrForbidden = errors.New("forbidden")
	// ErrNotFound indicates the target CA does not exist or is not visible to the
	// caller (existence is not disclosed to non-members).
	ErrNotFound = errors.New("not found")
)

// DB returns the underlying persistence handle. Alternative transports use it
// for read-only lookups (certificate/status/CRL metadata) that have no signing
// side effects.
func (a *API) DB() *database.DB { return a.db }

// KeyProvider returns the HSM-backed key provider so an alternative transport
// can construct a ca.Manager identical to the one the REST handlers build.
func (a *API) KeyProvider() keyprovider.Provider { return a.keyProvider }

// AuthorizeIssueOn reports whether user may perform issuing/signing operations
// on caID, resolving and recording the CA's owning tenant on ctx exactly as the
// REST issue/renew/revoke handlers do (canIssueOn). The recorded tenant is what
// a subsequent RecordAuditEvent attributes the event to.
func (a *API) AuthorizeIssueOn(ctx context.Context, user *models.UserInfo, caID string) (bool, error) {
	return a.canIssueOn(ctx, user, caID)
}

// AuthorizeCARead verifies that user may read caID and returns the CA. It is the
// context-based analogue of authorizeCARead: it requires a read-bearing role and
// tenant membership, records the resolved tenant on ctx, and does not disclose a
// CA's existence to non-members (returning ErrNotFound rather than ErrForbidden).
func (a *API) AuthorizeCARead(ctx context.Context, user *models.UserInfo, caID string) (*models.CA, error) {
	if !a.canRead(user) {
		return nil, ErrForbidden
	}
	ca, err := a.db.GetCA(caID)
	if err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, ErrNotFound
	}
	middleware.SetTenant(ctx, ca.TenantID)
	if !a.isTenantMember(user, ca.TenantID) {
		// Do not disclose existence to non-members.
		return nil, ErrNotFound
	}
	return ca, nil
}

// RecordAuditEvent appends a sealed entry to the tamper-evident audit event log
// using the actor/tenant/correlation-ID carried on ctx and an explicit client
// IP (the gRPC peer address). It is the context-based recordEvent used by
// non-HTTP transports.
func (a *API) RecordAuditEvent(ctx context.Context, ip, action, target, targetName, result, detail string) {
	a.recordEventCtx(ctx, ip, action, target, targetName, result, detail)
}

// CapValidityDays clamps a requested validity (in days) to the configured global
// policy maximum, matching the REST issue/renew path.
func (a *API) CapValidityDays(days int) int { return a.capValidityDays(days) }

// InvalidateOCSPCache drops any cached OCSP response for (caID, serial) so a new
// revocation status is served immediately, matching the REST revoke path.
func (a *API) InvalidateOCSPCache(caID, serial string) { a.ocspCache.Invalidate(caID, serial) }

// ConsumeHSMAuditLogs fetches and persists any pending HSM-side audit entries,
// linking sign commands to signAuditID when provided. It brackets on-HSM signing
// operations exactly as the REST handlers do.
func (a *API) ConsumeHSMAuditLogs(signAuditID string) { a.consumeHSMAuditLogs(signAuditID) }

// OCSPResponderInfo reports the responder-hardening options in effect, for the
// OCSP metadata RPC.
func (a *API) OCSPResponderInfo() (nonceEnabled, delegated bool) {
	return a.ocspPolicy.NonceEnabled, a.ocspPolicy.Delegated
}
