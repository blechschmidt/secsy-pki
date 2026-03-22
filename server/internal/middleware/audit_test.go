//go:build sqlite

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func setUserContext(r *http.Request, user *models.UserInfo) *http.Request {
	ctx := context.WithValue(r.Context(), UserInfoKey, user)
	return r.WithContext(ctx)
}

func TestAuditLogBasic(t *testing.T) {
	db := testDB(t)
	user := &models.UserInfo{Subject: "user-1", Name: "Test User"}

	handler := AuditLog(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/cas", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req = setUserContext(req, user)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	entries, total, err := db.ListAccessLog(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected 1 entry, got %d", total)
	}
	e := entries[0]
	if e.UserSub != "user-1" {
		t.Errorf("UserSub = %q, want %q", e.UserSub, "user-1")
	}
	if e.Method != "GET" {
		t.Errorf("Method = %q, want %q", e.Method, "GET")
	}
	if e.Path != "/api/cas" {
		t.Errorf("Path = %q, want %q", e.Path, "/api/cas")
	}
	if e.Status != 200 {
		t.Errorf("Status = %d, want %d", e.Status, 200)
	}
	if e.IP != "192.168.1.1:12345" {
		t.Errorf("IP = %q, want %q", e.IP, "192.168.1.1:12345")
	}
}

func TestAuditLogXForwardedFor(t *testing.T) {
	db := testDB(t)
	user := &models.UserInfo{Subject: "user-2"}

	handler := AuditLog(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/sign", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req = setUserContext(req, user)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	entries, _, err := db.ListAccessLog(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].IP != "203.0.113.50" {
		t.Errorf("IP = %q, want %q", entries[0].IP, "203.0.113.50")
	}
}

func TestAuditLogCapturesNon200Status(t *testing.T) {
	db := testDB(t)
	user := &models.UserInfo{Subject: "user-3"}

	handler := AuditLog(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest("DELETE", "/api/cas/999", nil)
	req.RemoteAddr = "10.0.0.2:8080"
	req = setUserContext(req, user)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	entries, _, err := db.ListAccessLog(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != 404 {
		t.Errorf("Status = %d, want %d", entries[0].Status, 404)
	}
	if entries[0].Method != "DELETE" {
		t.Errorf("Method = %q, want %q", entries[0].Method, "DELETE")
	}
}

func TestAuditLogNoUserSkipsLog(t *testing.T) {
	db := testDB(t)

	handler := AuditLog(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No user in context
	req := httptest.NewRequest("GET", "/api/cas", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	_, total, err := db.ListAccessLog(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Errorf("expected 0 entries when no user, got %d", total)
	}
}

func TestAuditLogDefaultStatus(t *testing.T) {
	db := testDB(t)
	user := &models.UserInfo{Subject: "user-4"}

	// Handler that does NOT call WriteHeader explicitly; default should be 200
	handler := AuditLog(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/api/health", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req = setUserContext(req, user)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	entries, _, err := db.ListAccessLog(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != 200 {
		t.Errorf("Status = %d, want %d (default)", entries[0].Status, 200)
	}
}

func TestStatusWriterWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}

	sw.WriteHeader(http.StatusForbidden)

	if sw.status != http.StatusForbidden {
		t.Errorf("statusWriter.status = %d, want %d", sw.status, http.StatusForbidden)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("underlying ResponseWriter status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStatusWriterWriteHeaderMultiple(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}

	sw.WriteHeader(http.StatusCreated)
	// Second call - statusWriter captures each call; underlying behavior is HTTP standard
	sw.WriteHeader(http.StatusInternalServerError)

	if sw.status != http.StatusInternalServerError {
		t.Errorf("statusWriter.status = %d, want %d", sw.status, http.StatusInternalServerError)
	}
}
