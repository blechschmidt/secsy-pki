package middleware

import (
	"log"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/google/uuid"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// Flush lets streaming handlers (the operator live audit-event SSE feed) flush
// buffered bytes through the access-log recorder to the underlying connection.
// Without it, embedding http.ResponseWriter hides the concrete writer's Flusher,
// and a Server-Sent Events response would never reach the client incrementally.
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func AuditLog(db *database.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserInfo(r.Context())

			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)

			if user == nil {
				return
			}

			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = fwd
			}

			entry := &models.AccessLogEntry{
				ID:        uuid.New().String(),
				UserSub:   user.Subject,
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    sw.status,
				IP:        ip,
				RequestID: RequestID(r.Context()),
			}
			if err := db.CreateAccessLogEntry(entry); err != nil {
				log.Printf("WARNING: failed to write access log: %v", err)
			}
		})
	}
}
