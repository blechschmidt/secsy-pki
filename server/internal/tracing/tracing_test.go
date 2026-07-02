package tracing

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// TestInitDisabledInstallsNoopTracer confirms the default (disabled) path is a
// true no-op: Init installs a non-recording tracer, so spans started through the
// package helpers do not record, and Shutdown is a harmless no-op. This is what
// keeps the instrumentation sprinkled through the codebase free when an operator
// has not turned tracing on.
func TestInitDisabledInstallsNoopTracer(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	p, err := Init(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Init(disabled): %v", err)
	}
	if p == nil {
		t.Fatal("Init returned a nil Provider")
	}

	_, span := Start(context.Background(), "should-not-record")
	if span.IsRecording() {
		t.Error("span is recording with tracing disabled; want a no-op span")
	}
	if span.SpanContext().IsSampled() {
		t.Error("span is sampled with tracing disabled")
	}
	span.End()

	// A propagator must still be installed so inbound trace context is parsed even
	// when tracing is disabled.
	if otel.GetTextMapPropagator() == nil {
		t.Error("no text-map propagator installed")
	}

	// Shutdown of a disabled provider must not error.
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(disabled): %v", err)
	}
}

// TestHelpersAreSafeWithoutRecordingSpan confirms the context-threaded helpers
// tolerate a context with no active span (the common case on background paths):
// AddEvent/SetAttributes/RecordError must be no-ops rather than panicking.
func TestHelpersAreSafeWithoutRecordingSpan(t *testing.T) {
	ctx := context.Background()
	// None of these should panic or mutate anything observable.
	AddEvent(ctx, "evt")
	SetAttributes(ctx)
	RecordError(ctx, nil)
	RecordError(ctx, context.Canceled)

	if got := SpanFromContext(ctx); got == nil {
		t.Error("SpanFromContext returned nil; want a non-recording span")
	}
	var _ trace.Span = SpanFromContext(ctx)
}

// TestInitEnabledBuildsProvider confirms that enabling tracing with a valid OTLP
// gRPC endpoint constructs a real (recording) tracer provider. The exporter
// connects lazily, so no collector need be running for Init to succeed; Shutdown
// then tears it down within the timeout.
func TestInitEnabledBuildsProvider(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	p, err := Init(context.Background(), Config{
		Enabled:     true,
		Endpoint:    "127.0.0.1:4317",
		Protocol:    "grpc",
		Insecure:    true,
		SampleRatio: 1,
		ServiceName: "secsy-pki-test",
		Timeout:     500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Init(enabled): %v", err)
	}
	// Bound the shutdown so a flush to the (absent) collector cannot hang the test.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = p.Shutdown(ctx)
	})

	_, span := Start(context.Background(), "recorded")
	if !span.IsRecording() {
		t.Error("span is not recording with tracing enabled and ratio=1")
	}
	span.End()
}

// TestInitEnabledRejectsUnknownProtocol confirms a misconfigured protocol is a
// hard error at Init rather than a silent fallback.
func TestInitEnabledRejectsUnknownProtocol(t *testing.T) {
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	_, err := Init(context.Background(), Config{
		Enabled:  true,
		Endpoint: "127.0.0.1:4317",
		Protocol: "carrier-pigeon",
	})
	if err == nil {
		t.Fatal("Init accepted an unknown OTLP protocol; want an error")
	}
}
