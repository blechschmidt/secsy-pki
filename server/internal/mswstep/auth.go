package mswstep

import (
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// authResult is the outcome of authenticating an MS-WSTEP/MS-XCEP request.
type authResult struct {
	// actor is the audit-actor label for the authenticated caller.
	actor string
	// principal is the resolved RBAC principal for a token- or operator-mTLS-
	// authenticated request; nil for the device-certificate (machine-renewal)
	// path, which is authorized by the CA's own prior issuance rather than a role.
	principal *models.UserInfo
	// deviceCert is true when the caller authenticated with a certificate this CA
	// previously issued (the machine-renewal path). Such a caller needs no RBAC
	// role — the CA already vouched for the identity.
	deviceCert bool
}

// authenticate resolves the caller's identity from the request's credentials,
// trying each Kerberos-free mechanism in turn:
//
//  1. a native scoped API token (Task 86) in the Authorization header — the
//     primary machine-auth mechanism;
//  2. a mutual-TLS client certificate bound to an RBAC principal through the
//     operator client-CA pool;
//  3. a mutual-TLS client certificate this enrollment CA previously issued (the
//     machine-renewal path), when allow_client_cert_issued_by_ca is set.
//
// It returns ok=false when no recognized credential is present or a presented one
// is invalid. Authorization (the RBAC/tenant capability check) is a separate step
// (authorizeIssue) so GetPolicies can authenticate without requiring the issuing
// capability.
func (s *Server) authenticate(r *http.Request) (authResult, bool) {
	// 1. Native scoped API token.
	if s.cfg.Tokens != nil {
		if secret, ok := apiTokenCredential(r.Header.Get("Authorization")); ok {
			info, err := s.cfg.Tokens.Verify(secret, clientIP(r))
			if err != nil {
				// A presented-but-invalid token fails closed rather than falling
				// through to another mechanism.
				return authResult{}, false
			}
			return authResult{actor: tokenActor(info), principal: info}, true
		}
	}

	// 2. Operator mutual-TLS certificate (client-CA pool -> RBAC principal).
	if s.cfg.CertBinder != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if info, ok := s.cfg.CertBinder.Authenticate(r.TLS.PeerCertificates); ok {
			return authResult{actor: "mswstep-mtls:" + info.Subject, principal: info}, true
		}
	}

	// 3. A certificate this enrollment CA previously issued (machine renewal).
	if s.cfg.AllowClientCertIssuedByCA && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if cert := s.validClientCert(r.TLS.PeerCertificates[0]); cert != nil {
			return authResult{actor: "mswstep-cert:" + cert.Subject.CommonName, deviceCert: true}, true
		}
	}

	return authResult{}, false
}

// authorizeIssue reports whether the authenticated caller may enroll (obtain a
// certificate) on the issuing CA. A device-certificate caller is authorized by
// prior issuance; any other principal must hold the cert:issue capability WITHIN
// the CA's tenant (a platform-wide issuer role, or an issuer role in that tenant)
// — the check that blocks a token scoped to a different tenant. Cross-tenant
// enrollment is therefore denied here, complementing the fail-closed tenant gate
// inside ca.Manager.
func (s *Server) authorizeIssue(res authResult) bool {
	if res.deviceCert {
		return true
	}
	u := res.principal
	if u == nil {
		return false
	}
	if u.IsRoot {
		return true
	}
	// Platform-wide roles span every tenant.
	if rbac.Can(rolesOf(u.Roles), rbac.ActionIssue) {
		return true
	}
	// Otherwise the capability must come from a role within the CA's tenant.
	return rbac.Can(rolesOf(u.TenantRoles[s.caTenant()]), rbac.ActionIssue)
}

// validClientCert returns cert when it is a currently-valid, non-revoked
// certificate this CA issued (used to authorize the machine-renewal path). It
// mirrors the EST certificate-based client-authentication check.
func (s *Server) validClientCert(cert *x509.Certificate) *x509.Certificate {
	caCert, err := s.caCert()
	if err != nil {
		return nil
	}
	if cert.CheckSignatureFrom(caCert) != nil {
		return nil
	}
	now := s.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil
	}
	rec, err := s.db.GetIssuedCertificate(s.cfg.CAID, cert.SerialNumber.String())
	if err != nil || rec == nil || rec.Status != models.CertStatusValid {
		return nil
	}
	return cert
}

// rolesOf converts role-name strings to typed rbac.Role values.
func rolesOf(names []string) []rbac.Role {
	roles := make([]rbac.Role, 0, len(names))
	for _, n := range names {
		roles = append(roles, rbac.Role(n))
	}
	return roles
}

// tokenActor labels a token-authenticated caller for the audit trail.
func tokenActor(u *models.UserInfo) string {
	if u == nil || u.Subject == "" {
		return "mswstep-token:unknown"
	}
	return "mswstep-" + u.Subject // e.g. "mswstep-token:<id>"
}

// apiTokenCredential extracts a native API-token secret from an Authorization
// header value, or reports ok=false. It accepts the canonical "Token <secret>"
// scheme and, for clients that can only send Bearer, a "Bearer <secret>" whose
// secret carries the self-identifying secsy_pat_ prefix — mirroring the auth
// middleware so the same credential works everywhere.
func apiTokenCredential(authorization string) (secret string, ok bool) {
	authorization = strings.TrimSpace(authorization)
	i := strings.IndexByte(authorization, ' ')
	if i <= 0 {
		return "", false
	}
	scheme, cred := authorization[:i], strings.TrimSpace(authorization[i+1:])
	if strings.EqualFold(scheme, authn.TokenAuthScheme) {
		return cred, true
	}
	if strings.EqualFold(scheme, "Bearer") && authn.LooksLikeToken(cred) {
		return cred, true
	}
	return "", false
}
