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

func GetUserInfo(ctx context.Context) *models.UserInfo {
	if info, ok := ctx.Value(UserInfoKey).(*models.UserInfo); ok {
		return info
	}
	return nil
}

// TokenVerifier is an interface for verifying OIDC tokens.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, rawToken string) (*auth.Claims, error)
}

type AuthMiddleware struct {
	oidcProvider TokenVerifier
	rootUsername string
	rootPassword string
}

func NewAuthMiddleware(oidcProvider TokenVerifier, rootUsername, rootPassword string) *AuthMiddleware {
	return &AuthMiddleware{
		oidcProvider: oidcProvider,
		rootUsername: rootUsername,
		rootPassword: rootPassword,
	}
}

func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try basic auth first (root user)
		if username, password, ok := r.BasicAuth(); ok {
			if subtle.ConstantTimeCompare([]byte(username), []byte(am.rootUsername)) == 1 &&
				subtle.ConstantTimeCompare([]byte(password), []byte(am.rootPassword)) == 1 {
				info := &models.UserInfo{
					Subject: "root",
					Name:    "Root User",
					IsRoot:  true,
				}
				ctx := context.WithValue(r.Context(), UserInfoKey, info)
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
			Subject: claims.Subject,
			Email:   claims.Email,
			Name:    claims.Name,
			IsRoot:  false,
		}
		ctx := context.WithValue(r.Context(), UserInfoKey, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
