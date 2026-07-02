package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestSessionStoreLifecycle(t *testing.T) {
	store := NewSessionStore(time.Hour, 5*time.Minute)
	user := &models.UserInfo{Subject: "op@example.com", Roles: []string{"issuer"}}

	sess := store.Create(user, MethodOIDC)
	if sess.ID == "" || sess.CSRFToken == "" {
		t.Fatal("session must have an id and CSRF token")
	}
	got, ok := store.Get(sess.ID)
	if !ok || got.User.Subject != "op@example.com" {
		t.Fatalf("Get returned %v, %v", got, ok)
	}
	if got.StepUpValid() {
		t.Error("fresh session should not be stepped up")
	}
	if !store.MarkStepUp(sess.ID) {
		t.Fatal("MarkStepUp should succeed for a live session")
	}
	if got, _ := store.Get(sess.ID); !got.StepUpValid() {
		t.Error("session should be stepped up after MarkStepUp")
	}
	if !store.Delete(sess.ID) {
		t.Fatal("Delete should report the session existed")
	}
	if _, ok := store.Get(sess.ID); ok {
		t.Error("session should be gone after Delete")
	}
}

func TestSessionStoreExpiry(t *testing.T) {
	store := NewSessionStore(time.Hour, time.Minute)
	base := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return base }
	sess := store.Create(&models.UserInfo{Subject: "x"}, MethodPassword)

	// Advance past the TTL; Get must evict and report absence.
	store.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, ok := store.Get(sess.ID); ok {
		t.Error("expired session should not be returned")
	}
}

func TestCheckCSRF(t *testing.T) {
	store := NewSessionStore(time.Hour, time.Minute)
	sess := store.Create(&models.UserInfo{Subject: "x"}, MethodOIDC)

	// Safe method is always allowed, even without a token.
	get := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	if !CheckCSRF(get, sess) {
		t.Error("GET should be exempt from CSRF")
	}

	// Unsafe method without a token is rejected.
	post := httptest.NewRequest(http.MethodPost, "/api/ca/x/issue", nil)
	if CheckCSRF(post, sess) {
		t.Error("POST without CSRF token must be rejected")
	}

	// Unsafe method with the correct header token passes.
	post = httptest.NewRequest(http.MethodPost, "/api/ca/x/issue", nil)
	post.Header.Set(CSRFHeader, sess.CSRFToken)
	if !CheckCSRF(post, sess) {
		t.Error("POST with valid CSRF token should pass")
	}

	// A wrong token is rejected.
	post = httptest.NewRequest(http.MethodPost, "/api/ca/x/issue", nil)
	post.Header.Set(CSRFHeader, "not-the-token")
	if CheckCSRF(post, sess) {
		t.Error("POST with wrong CSRF token must be rejected")
	}
}
