package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

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
		// Try basic auth first (root user)
		if username, password, ok := r.BasicAuth(); ok {
			if !am.rootEnabled {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "basic-auth root login is disabled"})
				return
			}
			if subtle.ConstantTimeCompare([]byte(username), []byte(am.rootUsername)) == 1 &&
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
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		// Try Bearer token (OIDC access/id token, for machine/API callers).
		authHeader := r.Header.Get("Authorization")
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
