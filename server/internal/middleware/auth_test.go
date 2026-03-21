package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestBasicAuthRoot(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserInfo(r.Context())
		if user == nil {
			t.Fatal("user is nil")
		}
		if !user.IsRoot || user.Subject != "root" {
			t.Errorf("user = %+v", user)
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestBasicAuthWrongPassword(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestNoAuth(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "authorization required" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestBearerNoOIDC(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 503 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestInvalidAuthHeader(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Token xyz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGetUserInfoNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	user := GetUserInfo(req.Context())
	if user != nil {
		t.Error("should be nil without context")
	}
}

func TestGetUserInfoFromContext(t *testing.T) {
	mw := NewAuthMiddleware(nil, "admin", "pass")
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserInfo(r.Context())
		json.NewEncoder(w).Encode(user)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "pass")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var user models.UserInfo
	json.Unmarshal(w.Body.Bytes(), &user)
	if user.Subject != "root" {
		t.Errorf("subject = %q", user.Subject)
	}
}
