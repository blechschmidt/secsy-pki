package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

type contextKey string

const UserInfoKey contextKey = "user_info"

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

		// Try Bearer token (OIDC)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization header"})
			return
		}

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
		ctx := context.WithValue(r.Context(), UserInfoKey, info)
		ctx = WithTenantHolder(ctx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
