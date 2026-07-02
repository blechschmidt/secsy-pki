package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func installRecordingTracer(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return exp
}

// TestObservabilityStartsRootSpanAndCorrelatesLog verifies that the request
// middleware starts a per-request root span, names it after the matched route,
// stamps the request ID as a span attribute, and emits the trace/span IDs into
// the structured log line so logs and traces correlate.
func TestObservabilityStartsRootSpanAndCorrelatesLog(t *testing.T) {
	exp := installRecordingTracer(t)

	var buf bytes.Buffer
	obs := NewObservability(&buf)

	var inSpan trace.SpanContext
	// Register on a mux so r.Pattern (the route) is populated, exercising the
	// span rename to the low-cardinality route.
	mux := http.NewServeMux()
	mux.Handle("GET /api/ca/{id}/issue", obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inSpan = trace.SpanContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ca/abc/issue", nil)
	mux.ServeHTTP(rec, req)

	// A span must have been recorded for the request.
	stubs := exp.GetSpans()
	if len(stubs) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(stubs))
	}
	span := stubs[0]

	// The handler must have observed a valid, recording span (so downstream child
	// spans nest under the request).
	if !inSpan.IsValid() {
		t.Fatal("handler did not observe a valid span context")
	}
	if inSpan.TraceID() != span.SpanContext.TraceID() {
		t.Error("handler span trace ID does not match the recorded request span")
	}

	// The span is renamed to the matched route (bounded cardinality).
	if span.Name != "GET /api/ca/{id}/issue" {
		t.Errorf("span name = %q, want the matched route pattern", span.Name)
	}

	// The request ID is on the span, and the same ID is echoed to the client.
	echoed := rec.Header().Get(RequestIDHeader)
	var spanRequestID string
	for _, a := range span.Attributes {
		if string(a.Key) == "request_id" {
			spanRequestID = a.Value.AsString()
		}
	}
	if spanRequestID == "" || spanRequestID != echoed {
		t.Errorf("span request_id = %q, response header = %q; want equal and non-empty", spanRequestID, echoed)
	}

	// The log line carries the trace/span IDs matching the recorded span.
	var line requestLog
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("log line not valid JSON: %v (%q)", err, buf.String())
	}
	if line.TraceID != span.SpanContext.TraceID().String() {
		t.Errorf("log trace_id = %q, want %q", line.TraceID, span.SpanContext.TraceID())
	}
	if line.SpanID != span.SpanContext.SpanID().String() {
		t.Errorf("log span_id = %q, want %q", line.SpanID, span.SpanContext.SpanID())
	}
	if line.RequestID != spanRequestID {
		t.Errorf("log request_id = %q, want %q", line.RequestID, spanRequestID)
	}
}

// TestObservabilityContinuesUpstreamTrace verifies W3C traceparent propagation:
// a request carrying an inbound traceparent continues that trace rather than
// starting a fresh one.
func TestObservabilityContinuesUpstreamTrace(t *testing.T) {
	exp := installRecordingTracer(t)

	obs := NewObservability(&bytes.Buffer{})
	h := obs.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// A well-formed W3C traceparent: version-traceid-spanid-flags (sampled).
	const upstreamTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	req.Header.Set("traceparent", "00-"+upstreamTrace+"-00f067aa0ba902b7-01")
	h.ServeHTTP(rec, req)

	stubs := exp.GetSpans()
	if len(stubs) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(stubs))
	}
	if got := stubs[0].SpanContext.TraceID().String(); got != upstreamTrace {
		t.Errorf("request span trace ID = %q, want the upstream trace %q", got, upstreamTrace)
	}
	if !stubs[0].Parent.IsValid() {
		t.Error("request span has no parent; upstream traceparent was not continued")
	}
}
