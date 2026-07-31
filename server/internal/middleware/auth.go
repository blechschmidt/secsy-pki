package middleware

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ErrNoCredentials is returned by AuthenticateRPC when a call carries no
// recognizable credential (no Authorization header and no bound client
// certificate). Callers map it to an "unauthenticated" transport status.
var ErrNoCredentials = errors.New("authorization required")

// ErrInvalidCredentials is returned by AuthenticateRPC when a presented
// credential is malformed or rejected (bad basic-auth password, invalid bearer
// token, or an unbindable client certificate).
var ErrInvalidCredentials = errors.New("invalid credentials")

type contextKey string

const UserInfoKey contextKey = "user_info"

// sessionKey stores the *authn.Session for a cookie-authenticated request, so a
// step-up gate can consult its WebAuthn step-up state without re-reading the
// cookie.
const sessionKey contextKey = "authn_session"

// GetSession returns the console session bound to a cookie-authenticated request,
// or nil for requests authenticated by another mechanism (basic/bearer/mTLS).
func GetSession(ctx context.Context) *authn.Session {
	if s, ok := ctx.Value(sessionKey).(*authn.Session); ok {
		return s
	}
	return nil
}

// tenantHolderKey stores a mutable *tenantHolder in the request context. A
// mutable holder (rather than a plain value) lets a handler record the tenant it
// resolved mid-request — after authorization loads the acted-on CA's tenant —
// so the audit event can be stamped with it without re-plumbing the request
// context through every layer.
const tenantHolderKey contextKey = "tenant_holder"

type tenantHolder struct{ id string }

func GetUserInfo(ctx context.Context) *models.UserInfo {
	if info, ok := ctx.Value(UserInfoKey).(*models.UserInfo); ok {
		return info
	}
	return nil
}

// WithTenantHolder attaches a fresh, empty tenant holder to ctx so that
// subsequent SetTenant/GetTenant calls on the request work. The auth middleware
// installs it automatically; it is exported so tests can construct an equivalent
// request context without going through authentication.
func WithTenantHolder(ctx context.Context) context.Context {
	return context.WithValue(ctx, tenantHolderKey, &tenantHolder{})
}

// SetTenant records the tenant resolved for the current request so subsequent
// audit events are attributed to it. It is a no-op if no holder is present.
func SetTenant(ctx context.Context, tenantID string) {
	if h, ok := ctx.Value(tenantHolderKey).(*tenantHolder); ok {
		h.id = tenantID
	}
}

// GetTenant returns the tenant resolved for the current request, or "" if none
// has been set (a platform-level operation not scoped to a tenant).
func GetTenant(ctx context.Context) string {
	if h, ok := ctx.Value(tenantHolderKey).(*tenantHolder); ok {
		return h.id
	}
	return ""
}

// TokenVerifier is an interface for verifying OIDC tokens.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, rawToken string) (*auth.Claims, error)
}

type AuthMiddleware struct {
	oidcProvider TokenVerifier
	rootUsername string
	rootPassword string
	// rootEnabled gates the built-in basic-auth root user. When false, root
	// credentials are rejected outright (production may prefer OIDC + RBAC only).
	rootEnabled bool
	// roleResolver, if set, populates the platform-wide RBAC roles for an
	// authenticated OIDC subject (from central config + group membership). It is
	// nil for the root user, which is always a superuser.
	roleResolver func(*models.UserInfo) []string
	// tenantRoleResolver, if set, populates the per-tenant RBAC roles for an
	// authenticated OIDC subject (tenant ID -> roles). Combined with roleResolver
	// these determine which tenants the subject may act on.
	tenantRoleResolver func(*models.UserInfo) map[string][]string

	// sessions, when set, enables cookie-based console sessions (OIDC/password
	// interactive login). sessionCookie is the cookie name to read.
	sessions      *authn.SessionStore
	sessionCookie string
	// binder, when set, enables mutual-TLS client-certificate authentication for
	// machine/API callers, binding a verified certificate to a principal.
	binder *authn.CertBinder
	// stepUpOps is the set of high-risk operation names that require an active
	// WebAuthn step-up for session-authenticated (console) callers.
	stepUpOps map[string]bool
	// tokens, when set, enables native scoped API-token (service-account)
	// authentication for machine callers (Task 86). Tokens are presented under a
	// distinct Authorization scheme from OIDC Bearer and verified fail-closed.
	tokens *authn.TokenAuthenticator
	// ldap, when set, authenticates HTTP Basic / RPC Basic credentials that are not
	// the built-in root user against an LDAP / Active Directory server (Task 159),
	// so machine/CLI callers can present directory credentials. The credential is a
	// real bind per request; it is only accepted over TLS (the server refuses
	// cleartext HTTP by default).
	ldap DirectoryAuthenticator
}

// DirectoryAuthenticator authenticates a username/password against an LDAP /
// Active Directory server and returns the resolved principal. *authn.LDAPAuthenticator
// satisfies it; the interface keeps the middleware decoupled from the concrete
// type and lets the basic-auth glue be unit-tested with a stub.
type DirectoryAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (*models.UserInfo, error)
}

func NewAuthMiddleware(oidcProvider TokenVerifier, rootUsername, rootPassword string) *AuthMiddleware {
	return &AuthMiddleware{
		oidcProvider: oidcProvider,
		rootUsername: rootUsername,
		rootPassword: rootPassword,
		rootEnabled:  true,
	}
}

// SetRoleResolver installs a function that resolves platform-wide RBAC roles for
// OIDC users.
func (am *AuthMiddleware) SetRoleResolver(f func(*models.UserInfo) []string) {
	am.roleResolver = f
}

// SetTenantRoleResolver installs a function that resolves per-tenant RBAC roles
// (tenant ID -> roles) for OIDC users.
func (am *AuthMiddleware) SetTenantRoleResolver(f func(*models.UserInfo) map[string][]string) {
	am.tenantRoleResolver = f
}

// SetRootEnabled toggles acceptance of the built-in basic-auth root user.
func (am *AuthMiddleware) SetRootEnabled(enabled bool) {
	am.rootEnabled = enabled
}

// SetSessions enables cookie-based console session authentication.
func (am *AuthMiddleware) SetSessions(store *authn.SessionStore, cookieName string) {
	am.sessions = store
	if cookieName == "" {
		cookieName = authn.DefaultSessionCookie
	}
	am.sessionCookie = cookieName
}

// SetCertBinder enables mutual-TLS client-certificate authentication.
func (am *AuthMiddleware) SetCertBinder(b *authn.CertBinder) {
	am.binder = b
}

// SetTokenAuthenticator enables native scoped API-token (service-account)
// authentication for machine callers.
func (am *AuthMiddleware) SetTokenAuthenticator(t *authn.TokenAuthenticator) {
	am.tokens = t
}

// SetLDAPAuthenticator enables LDAP / Active Directory authentication of HTTP
// Basic and RPC Basic credentials that are not the built-in root user.
func (am *AuthMiddleware) SetLDAPAuthenticator(l DirectoryAuthenticator) {
	am.ldap = l
}

// SetStepUpOperations declares the high-risk operation names that require an
// active WebAuthn step-up for console (session) callers.
func (am *AuthMiddleware) SetStepUpOperations(ops []string) {
	if len(ops) == 0 {
		am.stepUpOps = nil
		return
	}
	set := make(map[string]bool, len(ops))
	for _, o := range ops {
		set[o] = true
	}
	am.stepUpOps = set
}

func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try basic auth first: the built-in root user, then (when configured) an
		// LDAP / Active Directory bind for directory operators. Each mechanism is
		// tried in turn; only if none accepts the credential do we 401.
		if username, password, ok := r.BasicAuth(); ok {
			// 1. Built-in root user (constant-time comparison).
			if am.rootEnabled &&
				subtle.ConstantTimeCompare([]byte(username), []byte(am.rootUsername)) == 1 &&
				subtle.ConstantTimeCompare([]byte(password), []byte(am.rootPassword)) == 1 {
				info := &models.UserInfo{
					Subject: "root",
					Name:    "Root User",
					IsRoot:  true,
				}
				ctx := context.WithValue(r.Context(), UserInfoKey, info)
				ctx = WithTenantHolder(ctx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 2. LDAP / Active Directory directory user (binds per request; the
			// authenticator maps directory groups to RBAC roles). Failures fall
			// through to the generic 401 — never to another mechanism.
			if am.ldap != nil {
				info, err := am.ldap.Authenticate(r.Context(), username, password)
				metrics.RecordAuthLogin(authn.MethodLDAP, err == nil)
				if err == nil {
					am.serveAs(w, r, next, info, nil)
					return
				}
			}
			if !am.rootEnabled && am.ldap == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "basic-auth login is disabled"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		authHeader := r.Header.Get("Authorization")

		// Try a native scoped API token / service account (Task 86). It is carried
		// under a distinct Authorization scheme from OIDC Bearer, so the two verify
		// paths never conflate: the canonical "Token <secret>" form, plus a
		// "Bearer secsy_pat_…" convenience for clients that can only emit Bearer
		// (the prefix makes it unambiguously a token, never an OIDC JWT).
		// Verification is fail-closed: a presented-but-invalid token is rejected
		// outright rather than falling through to another mechanism. When the
		// feature is not installed the scheme is simply unrecognized and falls
		// through to the generic 401 below.
		if am.tokens != nil {
			if secret, ok := apiTokenCredential(authHeader); ok {
				info, err := am.tokens.Verify(secret, clientIP(r))
				if err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api token"})
					return
				}
				am.serveAs(w, r, next, info, nil)
				return
			}
		}

		// Try Bearer token (OIDC access/id token, for machine/API callers).
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if am.oidcProvider == nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "OIDC not configured"})
				return
			}
			claims, err := am.oidcProvider.VerifyToken(r.Context(), token)
			if err != nil {
				log.Printf("OIDC token verification failed: %v", err)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
			info := &models.UserInfo{
				Subject:       claims.Subject,
				Email:         claims.Email,
				EmailVerified: claims.EmailVerified,
				Name:          claims.Name,
				IsRoot:        false,
			}
			if am.roleResolver != nil {
				info.Roles = am.roleResolver(info)
			}
			if am.tenantRoleResolver != nil {
				info.TenantRoles = am.tenantRoleResolver(info)
			}
			am.serveAs(w, r, next, info, nil)
			return
		}

		// Try a console session cookie (interactive OIDC/password login). A
		// cookie-authenticated, state-changing request must carry a valid CSRF
		// token — the session cookie alone is not sufficient to authorize it.
		if am.sessions != nil && am.sessionCookie != "" {
			if c, err := r.Cookie(am.sessionCookie); err == nil {
				if sess, ok := am.sessions.Get(c.Value); ok {
					if !authn.CheckCSRF(r, sess) {
						writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
						return
					}
					am.serveAs(w, r, next, sess.User, sess)
					return
				}
			}
		}

		// Try a mutual-TLS client certificate (machine/API callers). The server
		// requests client certs without handshake-time verification (so EST device
		// certs do not break the handshake); the binder verifies the presented
		// chain against the operator client-CA pool and resolves it to a principal.
		// A presented-but-unbound certificate falls through rather than 401, so a
		// device presenting an EST/PKI certificate can still reach the public
		// endpoints and the console can be reached without a client cert.
		if am.binder != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if info, ok := am.binder.Authenticate(r.TLS.PeerCertificates); ok {
				am.serveAs(w, r, next, info, nil)
				return
			}
		}

		if authHeader != "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization header"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
	})
}

// serveAs installs the resolved principal (and, for cookie auth, the session)
// into the request context and dispatches to the next handler.
func (am *AuthMiddleware) serveAs(w http.ResponseWriter, r *http.Request, next http.Handler, info *models.UserInfo, sess *authn.Session) {
	ctx := context.WithValue(r.Context(), UserInfoKey, info)
	ctx = WithTenantHolder(ctx)
	if sess != nil {
		ctx = context.WithValue(ctx, sessionKey, sess)
	}
	next.ServeHTTP(w, r.WithContext(ctx))
}

// StepUpGate wraps a high-risk handler so a console (session) caller must have
// completed a WebAuthn step-up within the configured window. Callers
// authenticated by a strong non-interactive credential (root basic-auth, a
// bearer token, or a bound mutual-TLS certificate) are not session-based and are
// allowed through: step-up is a control for interactive console operators. The
// gate is inert unless the operation was declared via SetStepUpOperations.
func (am *AuthMiddleware) StepUpGate(operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if am.stepUpOps[operation] {
				if sess := GetSession(r.Context()); sess != nil && !sess.StepUpValid() {
					metrics.RecordAuthStepUp(metrics.ResultDenied)
					writeJSON(w, http.StatusForbidden, map[string]interface{}{
						"error":     "this operation requires WebAuthn step-up authentication",
						"code":      "step_up_required",
						"operation": operation,
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthenticateRPC resolves a principal for a non-HTTP (gRPC) call from the same
// credential set the HTTP middleware accepts: an Authorization header value
// (Basic root credentials or a Bearer OIDC access/ID token) and/or a verified
// mutual-TLS client-certificate chain. It returns the resolved principal with
// its platform and per-tenant RBAC roles populated, exactly as the HTTP path
// would. The browser session-cookie path has no gRPC analogue and is omitted.
//
// It returns ErrNoCredentials when nothing was presented and ErrInvalidCredentials
// when a presented credential is malformed or rejected, so the gRPC interceptor
// can map them to Unauthenticated without leaking detail.
func (am *AuthMiddleware) AuthenticateRPC(ctx context.Context, authorization string, peerCerts []*x509.Certificate) (*models.UserInfo, error) {
	authorization = strings.TrimSpace(authorization)

	// Basic auth (built-in root user, then LDAP directory user), mirroring
	// r.BasicAuth() semantics and the HTTP path's ordering.
	if user, pass, ok := parseBasicAuth(authorization); ok {
		if am.rootEnabled &&
			subtle.ConstantTimeCompare([]byte(user), []byte(am.rootUsername)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(am.rootPassword)) == 1 {
			return &models.UserInfo{Subject: "root", Name: "Root User", IsRoot: true}, nil
		}
		if am.ldap != nil {
			info, err := am.ldap.Authenticate(ctx, user, pass)
			metrics.RecordAuthLogin(authn.MethodLDAP, err == nil)
			if err == nil {
				return info, nil
			}
		}
		return nil, ErrInvalidCredentials
	}

	// Native scoped API token / service account (Task 86), under a distinct
	// scheme from OIDC Bearer. Mirrors the HTTP path and fails closed: a
	// presented-but-invalid token is rejected rather than falling through.
	if am.tokens != nil {
		if secret, ok := apiTokenCredential(authorization); ok {
			info, err := am.tokens.Verify(secret, "")
			if err != nil {
				return nil, ErrInvalidCredentials
			}
			return info, nil
		}
	}

	// Bearer token (OIDC access/ID token for machine/API callers).
	if strings.HasPrefix(authorization, "Bearer ") {
		token := strings.TrimPrefix(authorization, "Bearer ")
		if am.oidcProvider == nil {
			return nil, errors.New("OIDC not configured")
		}
		claims, err := am.oidcProvider.VerifyToken(ctx, token)
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		info := &models.UserInfo{
			Subject:       claims.Subject,
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			Name:          claims.Name,
		}
		if am.roleResolver != nil {
			info.Roles = am.roleResolver(info)
		}
		if am.tenantRoleResolver != nil {
			info.TenantRoles = am.tenantRoleResolver(info)
		}
		return info, nil
	}

	if authorization != "" {
		// A header was presented but not in a form we accept.
		return nil, ErrInvalidCredentials
	}

	// Mutual-TLS client certificate (machine/API callers). The binder verifies
	// the presented chain against the operator client-CA pool and resolves it to
	// a principal; an unbound certificate is treated as no credential.
	if am.binder != nil && len(peerCerts) > 0 {
		if info, ok := am.binder.Authenticate(peerCerts); ok {
			return info, nil
		}
	}

	return nil, ErrNoCredentials
}

// apiTokenCredential extracts a native API-token secret from an Authorization
// header value, or reports ok=false when the value is not a token. It accepts
// the canonical distinct scheme "Token <secret>" and, as a convenience for
// clients that can only send Bearer, a "Bearer <secret>" whose secret carries
// the self-identifying secsy_pat_ prefix (which an OIDC JWT never does), so the
// two verification paths stay cleanly separated regardless of the scheme word.
func apiTokenCredential(authorization string) (secret string, ok bool) {
	scheme, cred, split := splitAuthScheme(authorization)
	if !split {
		return "", false
	}
	if strings.EqualFold(scheme, authn.TokenAuthScheme) {
		return cred, true
	}
	if strings.EqualFold(scheme, "Bearer") && authn.LooksLikeToken(cred) {
		return cred, true
	}
	return "", false
}

// splitAuthScheme splits an Authorization value into its scheme and credential
// (e.g. "Token abc" -> ("Token", "abc", true)). It returns ok=false when there
// is no scheme/credential separator.
func splitAuthScheme(authorization string) (scheme, credential string, ok bool) {
	authorization = strings.TrimSpace(authorization)
	i := strings.IndexByte(authorization, ' ')
	if i <= 0 {
		return "", "", false
	}
	return authorization[:i], strings.TrimSpace(authorization[i+1:]), true
}

// parseBasicAuth decodes a "Basic base64(user:pass)" Authorization value. It
// mirrors net/http's BasicAuth parsing so the gRPC and HTTP paths accept
// identical credentials.
func parseBasicAuth(authorization string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(authorization) < len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(authorization[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
