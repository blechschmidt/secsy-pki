package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// stubDirectory is a fake DirectoryAuthenticator: it accepts one directory user
// and rejects everything else, so the middleware basic-auth glue can be tested
// without a live directory (the bind path itself is covered in internal/authn).
type stubDirectory struct {
	user, pass string
	roles      []string
	calls      int
}

func (s *stubDirectory) Authenticate(_ context.Context, u, p string) (*models.UserInfo, error) {
	s.calls++
	if u == s.user && p == s.pass {
		return &models.UserInfo{Subject: "cn=" + u, Name: u, Roles: s.roles}, nil
	}
	return nil, errors.New("invalid directory credentials")
}

func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func TestLDAPBasicAuthHTTP(t *testing.T) {
	dir := &stubDirectory{user: "alice", pass: "pw", roles: []string{"issuer"}}
	mw := NewAuthMiddleware(nil, "root", "rootpass")
	mw.SetLDAPAuthenticator(dir)

	var got *models.UserInfo
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = GetUserInfo(r.Context())
		w.WriteHeader(200)
	}))

	// 1. Directory user authenticates via HTTP Basic and is served as themselves.
	req := httptest.NewRequest("GET", "/api/ca", nil)
	req.Header.Set("Authorization", basic("alice", "pw"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("directory login: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got == nil || got.Subject != "cn=alice" || len(got.Roles) != 1 || got.Roles[0] != "issuer" {
		t.Fatalf("principal = %+v", got)
	}

	// 2. The built-in root user still authenticates and is NOT sent to the directory.
	dir.calls = 0
	req = httptest.NewRequest("GET", "/api/ca", nil)
	req.Header.Set("Authorization", basic("root", "rootpass"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || got == nil || !got.IsRoot {
		t.Fatalf("root login: status=%d principal=%+v", w.Code, got)
	}
	if dir.calls != 0 {
		t.Fatalf("root credentials must not be sent to the directory (calls=%d)", dir.calls)
	}

	// 3. A wrong directory password fails closed with 401.
	req = httptest.NewRequest("GET", "/api/ca", nil)
	req.Header.Set("Authorization", basic("alice", "wrong"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("bad directory password: status = %d, want 401", w.Code)
	}
}

// TestLDAPBasicAuthHTTPRootDisabled: with root disabled, a directory user still
// authenticates and a bad credential still 401s (not "login disabled").
func TestLDAPBasicAuthHTTPRootDisabled(t *testing.T) {
	dir := &stubDirectory{user: "alice", pass: "pw", roles: []string{"auditor"}}
	mw := NewAuthMiddleware(nil, "root", "rootpass")
	mw.SetRootEnabled(false)
	mw.SetLDAPAuthenticator(dir)

	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/api/ca", nil)
	req.Header.Set("Authorization", basic("alice", "pw"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("directory login with root disabled: status = %d, want 200", w.Code)
	}

	// The root credentials are now rejected (root disabled), falling through to the
	// directory, which does not know "root" → 401.
	req = httptest.NewRequest("GET", "/api/ca", nil)
	req.Header.Set("Authorization", basic("root", "rootpass"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("root while disabled: status = %d, want 401", w.Code)
	}
}

func TestLDAPBasicAuthRPC(t *testing.T) {
	dir := &stubDirectory{user: "bob", pass: "s3cret", roles: []string{"signer"}}
	mw := NewAuthMiddleware(nil, "root", "rootpass")
	mw.SetLDAPAuthenticator(dir)

	info, err := mw.AuthenticateRPC(context.Background(), basic("bob", "s3cret"), nil)
	if err != nil {
		t.Fatalf("AuthenticateRPC(directory): %v", err)
	}
	if info.Subject != "cn=bob" || len(info.Roles) != 1 || info.Roles[0] != "signer" {
		t.Fatalf("principal = %+v", info)
	}

	// Wrong password → ErrInvalidCredentials (fail closed, no fall-through).
	if _, err := mw.AuthenticateRPC(context.Background(), basic("bob", "nope"), nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad RPC directory password: err = %v, want ErrInvalidCredentials", err)
	}

	// Root still works over RPC and bypasses the directory.
	dir.calls = 0
	info, err = mw.AuthenticateRPC(context.Background(), basic("root", "rootpass"), nil)
	if err != nil || !info.IsRoot {
		t.Fatalf("root RPC: err=%v info=%+v", err, info)
	}
	if dir.calls != 0 {
		t.Fatalf("root RPC credentials must not hit the directory (calls=%d)", dir.calls)
	}
}
