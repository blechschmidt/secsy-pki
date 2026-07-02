package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// RequestIDHeader is the HTTP header used to receive and echo a request's
// correlation ID.
const RequestIDHeader = "X-Request-ID"

// requestIDKey is the context key under which the per-request correlation ID is
// stored.
const requestIDKey contextKey = "request_id"

// RequestID returns the correlation ID assigned to the request carried by ctx,
// or "" if none was set. Handlers and the audit layer use it to tie their
// records back to the structured request log.
func RequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// maxRequestIDLen bounds an inbound X-Request-ID we are willing to trust and
// echo, preventing header/log injection and unbounded log lines.
const maxRequestIDLen = 128

// Observability captures HTTP metrics and emits one structured (JSON) log line
// per request. It is intended to wrap the entire handler tree (outermost
// middleware) so it observes every route — API, ACME, static assets, and the
// health/metrics endpoints — and so the correlation ID it assigns is visible to
// all downstream handlers, the access log, and the audit event log.
//
// It never logs request or response bodies, headers that may carry credentials
// (Authorization, Cookie), or query strings — only method, matched route,
// status, size, latency, client IP, user agent, and the correlation ID.
type Observability struct {
	out   io.Writer
	mu    sync.Mutex
	now   func() time.Time
	newID func() string
}

// NewObservability returns middleware that logs JSON lines to w (os.Stdout when
// nil).
func NewObservability(w io.Writer) *Observability {
	if w == nil {
		w = os.Stdout
	}
	return &Observability{
		out:   w,
		now:   time.Now,
		newID: func() string { return uuid.NewString() },
	}
}

// requestLog is the JSON schema of a single request log line. Field names are
// snake_case for consistency with the rest of the API and with common log
// pipelines.
type requestLog struct {
	Time       string  `json:"time"`
	Level      string  `json:"level"`
	Msg        string  `json:"msg"`
	RequestID  string  `json:"request_id"`
	Method     string  `json:"method"`
	Route      string  `json:"route,omitempty"`
	Path       string  `json:"path"`
	Status     int     `json:"status"`
	DurationMs float64 `json:"duration_ms"`
	BytesOut   int     `json:"bytes_out"`
	RemoteIP   string  `json:"remote_ip,omitempty"`
	UserAgent  string  `json:"user_agent,omitempty"`
	// TraceID and SpanID tie this log line to the distributed trace for the same
	// request, so an operator can pivot from a log entry to its trace (and back).
	// They are populated only when tracing is enabled and the request is sampled.
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
}

// Handler wraps next with request-ID assignment, metrics, and structured
// logging.
func (o *Observability) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := o.now()

		id := sanitizeRequestID(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = o.newID()
		}
		// Echo the correlation ID so clients and proxies can tie their own logs
		// to ours, and stash it in the context for the audit/access layers.
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)

		// Distributed tracing: continue any upstream trace carried in the request's
		// W3C traceparent header, then start the per-request root span. The span is
		// a no-op (and this is nearly free) when tracing is disabled. The route
		// pattern is not known until the mux has routed the request, so the span is
		// started under the method and renamed once the route is known.
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))
		ctx, span := tracing.Start(ctx, "HTTP "+r.Method,
			semconv.HTTPRequestMethodKey.String(r.Method),
			semconv.URLPath(r.URL.Path),
			attribute.String("request_id", id),
		)
		defer span.End()

		r = r.WithContext(ctx)

		rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		metrics.HTTPInFlight.Inc()
		defer metrics.HTTPInFlight.Dec()

		next.ServeHTTP(rw, r)

		dur := o.now().Sub(start)

		// Use the matched route pattern (e.g. "GET /api/ca/{id}/issue") as the
		// metric/label dimension to keep cardinality bounded — never the raw path,
		// which embeds unbounded IDs and serials.
		route := routeLabel(r)
		status := strconv.Itoa(rw.status)

		metrics.HTTPRequests.Inc(r.Method, route, status)
		metrics.HTTPDuration.Observe(dur.Seconds(), r.Method, route)

		// Finalize the span: rename it to the low-cardinality route, record the
		// outcome, and mark server errors as span failures for trace-level alerting.
		span.SetName(route)
		span.SetAttributes(
			semconv.HTTPRoute(route),
			semconv.HTTPResponseStatusCode(rw.status),
		)
		if rw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rw.status))
		}

		// Correlate the log line with the trace: emit the trace/span IDs when the
		// request was sampled and recorded.
		var traceID, spanID string
		if sc := span.SpanContext(); sc.IsValid() {
			traceID = sc.TraceID().String()
			spanID = sc.SpanID().String()
		}

		o.write(requestLog{
			Time:       o.now().UTC().Format(time.RFC3339Nano),
			Level:      "info",
			Msg:        "http_request",
			RequestID:  id,
			Method:     r.Method,
			Route:      route,
			Path:       r.URL.Path,
			Status:     rw.status,
			DurationMs: float64(dur.Microseconds()) / 1000.0,
			BytesOut:   rw.bytes,
			RemoteIP:   clientIP(r),
			UserAgent:  r.UserAgent(),
			TraceID:    traceID,
			SpanID:     spanID,
		})
	})
}

func (o *Observability) write(entry requestLog) {
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	b = append(b, '\n')
	o.mu.Lock()
	o.out.Write(b)
	o.mu.Unlock()
}

// routeLabel returns the matched route pattern for metrics/logging, falling
// back to a low-cardinality placeholder for unmatched requests so a scanner
// hitting random paths cannot explode the metric's series count.
func routeLabel(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.Method + " <unmatched>"
}

// clientIP returns the best-effort client address, honoring X-Forwarded-For
// (the deployment terminates TLS at a trusted proxy). It mirrors the handler
// package's logic so access-log and request-log IPs agree.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// Take the first hop (the original client) and trim spaces.
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	return r.RemoteAddr
}

// sanitizeRequestID accepts an inbound correlation ID only if it is short and
// composed of safe characters (so it cannot inject into a log line or HTTP
// header). Anything else is rejected, causing a fresh ID to be generated.
func sanitizeRequestID(s string) string {
	if s == "" || len(s) > maxRequestIDLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '-' || c == '_' || c == '.' ||
			(c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z')
		if !ok {
			return ""
		}
	}
	return s
}

// responseRecorder captures the status code and byte count written to the
// response so the middleware can log and meter them.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (rw *responseRecorder) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// Flush lets streaming handlers (if any) flush through the recorder.
func (rw *responseRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
