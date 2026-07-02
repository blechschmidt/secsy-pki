package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObservabilityAssignsAndEchoesRequestID(t *testing.T) {
	var buf bytes.Buffer
	obs := NewObservability(&buf)

	var seenID string
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	h.ServeHTTP(rec, req)

	if seenID == "" {
		t.Fatal("handler did not see a request ID in context")
	}
	if got := rec.Header().Get(RequestIDHeader); got != seenID {
		t.Errorf("response %s header = %q, want %q", RequestIDHeader, got, seenID)
	}

	var line requestLog
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("log line not valid JSON: %v (%q)", err, buf.String())
	}
	if line.RequestID != seenID {
		t.Errorf("log request_id = %q, want %q", line.RequestID, seenID)
	}
	if line.Status != http.StatusOK {
		t.Errorf("log status = %d, want 200", line.Status)
	}
	if line.Method != http.MethodGet {
		t.Errorf("log method = %q", line.Method)
	}
}

func TestObservabilityHonorsInboundRequestID(t *testing.T) {
	var buf bytes.Buffer
	obs := NewObservability(&buf)
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(RequestIDHeader, "trace-abc_123")
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get(RequestIDHeader); got != "trace-abc_123" {
		t.Errorf("did not echo inbound request id: %q", got)
	}
}

func TestObservabilityRejectsUnsafeInboundRequestID(t *testing.T) {
	var buf bytes.Buffer
	obs := NewObservability(&buf)
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// Header/log-injection attempt must be rejected and replaced.
	req.Header.Set(RequestIDHeader, "bad\nvalue\"here")
	h.ServeHTTP(rec, req)

	got := rec.Header().Get(RequestIDHeader)
	if got == "bad\nvalue\"here" || got == "" {
		t.Errorf("unsafe request id not sanitized: %q", got)
	}
	if strings.ContainsAny(got, "\n\"") {
		t.Errorf("sanitized id still contains unsafe chars: %q", got)
	}
}

func TestObservabilityCapturesStatusAndBytes(t *testing.T) {
	var buf bytes.Buffer
	obs := NewObservability(&buf)
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("hello"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/brew", nil)
	h.ServeHTTP(rec, req)

	var line requestLog
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("log line not valid JSON: %v", err)
	}
	if line.Status != http.StatusTeapot {
		t.Errorf("status = %d, want 418", line.Status)
	}
	if line.BytesOut != 5 {
		t.Errorf("bytes_out = %d, want 5", line.BytesOut)
	}
}

func TestObservabilityNoSecretsLogged(t *testing.T) {
	var buf bytes.Buffer
	obs := NewObservability(&buf)
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/secret?token=SUPERSECRET", nil)
	req.Header.Set("Authorization", "Bearer SECRET-TOKEN")
	req.SetBasicAuth("root", "hunter2")
	h.ServeHTTP(rec, req)

	logged := buf.String()
	for _, leak := range []string{"SUPERSECRET", "SECRET-TOKEN", "hunter2", "Authorization"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log line leaked %q: %s", leak, logged)
		}
	}
}

func TestSanitizeRequestID(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"ok-id_1.2":              "ok-id_1.2",
		"has space":              "",
		"has\ttab":               "",
		strings.Repeat("a", 129): "",
		strings.Repeat("a", 128): strings.Repeat("a", 128),
	}
	for in, want := range cases {
		if got := sanitizeRequestID(in); got != want {
			t.Errorf("sanitizeRequestID(%q) = %q, want %q", in, got, want)
		}
	}
}
