package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// okHandler records that the request reached the handler and echoes the resolved
// principal for assertions.
func principalHandler(seen **models.UserInfo, sawSession *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = GetUserInfo(r.Context())
		if sawSession != nil {
			*sawSession = GetSession(r.Context()) != nil
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestSessionCookieAuth(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")
	sessions := authn.NewSessionStore(time.Hour, time.Minute)
	mw.SetSessions(sessions, "")
	sess := sessions.Create(&models.UserInfo{Subject: "op@example.com", Roles: []string{"issuer"}}, authn.MethodOIDC)

	var seen *models.UserInfo
	var hadSession bool
	handler := mw.Authenticate(principalHandler(&seen, &hadSession))

	t.Run("GET with cookie authenticates", func(t *testing.T) {
		seen = nil
		req := httptest.NewRequest("GET", "/api/keys", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: sess.ID})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if seen == nil || seen.Subject != "op@example.com" {
			t.Fatalf("principal = %+v", seen)
		}
		if !hadSession {
			t.Error("session should be present in context for cookie auth")
		}
	})

	t.Run("POST without CSRF token is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/ca/x/issue", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: sess.ID})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST without CSRF = %d, want 403", rec.Code)
		}
	})

	t.Run("POST with CSRF token passes", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/ca/x/issue", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: sess.ID})
		req.Header.Set(authn.CSRFHeader, sess.CSRFToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST with CSRF = %d, want 200", rec.Code)
		}
	})

	t.Run("unknown session id is unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/keys", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: "bogus"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unknown session = %d, want 401", rec.Code)
		}
	})
}

func TestMTLSAuth(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")
	binder := authn.NewCertBinder([]authn.CertBinding{
		{SubjectCN: "robot-1", Subject: "svc:robot-1", Roles: []rbac.Role{rbac.RoleIssuer}},
	}, nil)
	mw.SetCertBinder(binder)

	var seen *models.UserInfo
	handler := mw.Authenticate(principalHandler(&seen, nil))

	t.Run("bound client cert authenticates", func(t *testing.T) {
		seen = nil
		req := httptest.NewRequest("GET", "/api/keys", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "robot-1"}},
		}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if seen == nil || seen.Subject != "svc:robot-1" || len(seen.Roles) != 1 || seen.Roles[0] != "issuer" {
			t.Fatalf("principal = %+v", seen)
		}
	})

	t.Run("unbound client cert is rejected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/keys", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "stranger"}},
		}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unbound cert = %d, want 401", rec.Code)
		}
	})
}

func TestStepUpGate(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")
	sessions := authn.NewSessionStore(time.Hour, time.Minute)
	mw.SetSessions(sessions, "")
	mw.SetStepUpOperations([]string{"cert.revoke"})

	reached := false
	gated := mw.Authenticate(mw.StepUpGate("cert.revoke")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))

	t.Run("session without step-up is blocked", func(t *testing.T) {
		reached = false
		sess := sessions.Create(&models.UserInfo{Subject: "op"}, authn.MethodOIDC)
		req := httptest.NewRequest("POST", "/api/ca/x/revoke", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: sess.ID})
		req.Header.Set(authn.CSRFHeader, sess.CSRFToken)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if reached {
			t.Error("handler must not run without step-up")
		}
	})

	t.Run("session with step-up passes", func(t *testing.T) {
		reached = false
		sess := sessions.Create(&models.UserInfo{Subject: "op"}, authn.MethodOIDC)
		sessions.MarkStepUp(sess.ID)
		req := httptest.NewRequest("POST", "/api/ca/x/revoke", nil)
		req.AddCookie(&http.Cookie{Name: authn.DefaultSessionCookie, Value: sess.ID})
		req.Header.Set(authn.CSRFHeader, sess.CSRFToken)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !reached {
			t.Fatalf("status = %d reached=%v, want 200/true", rec.Code, reached)
		}
	})

	t.Run("non-session principal (root basic-auth) bypasses step-up", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest("POST", "/api/ca/x/revoke", nil)
		req.SetBasicAuth("root", "secret")
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !reached {
			t.Fatalf("root should bypass step-up: status=%d reached=%v", rec.Code, reached)
		}
	})
}
