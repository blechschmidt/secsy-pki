// Package tracing provides OpenTelemetry (OTLP) distributed tracing for the
// secsy-pki server. It complements the Prometheus metrics (internal/metrics) and
// the structured request log (internal/middleware) with end-to-end spans across
// the request-handling middleware and the key hot paths: CA signing,
// keyprovider/HSM operations (including PKCS#11 session-pool wait time and
// multi-token failover events), CRL/OCSP generation, the pre-issuance
// lint/CAA/CT gates, and the persistence store.
//
// Design goals:
//
//   - Disabled by default. When tracing is not configured the package installs a
//     no-op tracer, so every Start/Span/AddEvent call is a cheap no-op and no
//     exporter, sampler, or background goroutine is created. Instrumentation
//     sprinkled through the codebase therefore costs effectively nothing until an
//     operator turns tracing on.
//
//   - Centralized, context-threaded helpers. Like the metrics package, the
//     helpers here are package-level and reached through context.Context, so any
//     layer can add a span or event without threading a *TracerProvider through
//     every call site. They always read the process-global OpenTelemetry
//     TracerProvider, which Init installs (and which tests may install directly).
//
//   - W3C trace-context propagation. Init installs a TraceContext+Baggage
//     propagator so inbound traceparent headers continue an upstream trace and
//     outbound calls carry the current context.
package tracing

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// instrumentationName is the tracer name reported on every span this codebase
// emits. It identifies the library (this repository) that produced the
// instrumentation, distinct from the service.name resource attribute.
const instrumentationName = "github.com/blechschmidt/secsy-pki/server"

// Config configures the OTLP exporter and sampler. It is populated from the
// server config's `tracing` block. The zero value (Enabled=false) yields a
// fully disabled, no-op tracer.
type Config struct {
	// Enabled turns tracing on. When false, Init installs a no-op tracer and no
	// exporter or background processor is started.
	Enabled bool
	// Endpoint is the OTLP collector endpoint, e.g. "otel-collector:4317" for
	// gRPC or "otel-collector:4318" for HTTP. Host:port form (no scheme); TLS is
	// controlled by Insecure. Required when Enabled.
	Endpoint string
	// Protocol selects the OTLP transport: "grpc" (default) or "http" (HTTP/protobuf).
	Protocol string
	// Insecure disables transport TLS to the collector (plaintext gRPC / http://).
	// Intended for in-cluster collectors reached over a trusted network.
	Insecure bool
	// SampleRatio is the head-based parent-respecting sample probability in
	// [0,1]. 0 samples nothing, 1 samples everything (the default when unset and
	// Enabled). A sampled parent is always honored so a trace is not truncated.
	SampleRatio float64
	// ServiceName is the service.name resource attribute (default "secsy-pki").
	ServiceName string
	// ServiceVersion is the optional service.version resource attribute.
	ServiceVersion string
	// Headers are optional static headers sent to the collector (e.g. an
	// authorization token for a managed OTLP endpoint).
	Headers map[string]string
	// Timeout bounds a single export attempt. Defaults to 10s when unset.
	Timeout time.Duration
}

// Provider owns the SDK TracerProvider so the caller can flush and shut it down
// on exit. When tracing is disabled it is still non-nil, with a no-op Shutdown,
// so callers need not special-case the disabled path.
type Provider struct {
	tp       *sdktrace.TracerProvider
	shutdown func(context.Context) error
}

// Init configures OpenTelemetry from cfg and installs the global TracerProvider
// and W3C propagator. It returns a Provider whose Shutdown flushes and releases
// the exporter; callers should defer it. When cfg.Enabled is false Init installs
// a no-op tracer (leaving the global propagator in place so inbound trace
// context is still parsed for any handler that wants it) and returns a Provider
// with a no-op Shutdown.
//
// Init is safe to call once at startup. It never fails when disabled; when
// enabled it returns an error only if the exporter cannot be constructed.
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	// Always install the W3C trace-context + baggage propagator. Even with
	// tracing disabled this lets the server parse and forward inbound traceparent
	// headers, and it is required for spans to link across process boundaries.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled {
		// Explicitly install a no-op tracer provider so any previously-set global
		// (e.g. from a prior test) does not leak in, and so Tracer() is a true no-op.
		otel.SetTracerProvider(noop())
		return &Provider{shutdown: func(context.Context) error { return nil }}, nil
	}

	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("tracing: building OTLP exporter: %w", err)
	}

	res, err := newResource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("tracing: building resource: %w", err)
	}

	ratio := cfg.SampleRatio
	if ratio <= 0 {
		// Enabled but no explicit ratio: sample everything. Operators dial this
		// down in production via config; a conservative default here would silently
		// drop traces an operator expects to see after turning tracing on.
		ratio = 1
	}
	if ratio > 1 {
		ratio = 1
	}
	// ParentBased ensures a sampled upstream trace is always continued (and an
	// unsampled one is not resurrected), so distributed traces are not truncated
	// at this hop regardless of the local ratio.
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	return &Provider{
		tp:       tp,
		shutdown: tp.Shutdown,
	}, nil
}

// newExporter builds the OTLP exporter for the configured protocol.
func newExporter(ctx context.Context, cfg Config) (*otlptrace.Exporter, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Protocol)) {
	case "", "grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
			otlptracegrpc.WithTimeout(timeout),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		return otlptracegrpc.New(ctx, opts...)
	case "http", "https", "http/protobuf":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
			otlptracehttp.WithTimeout(timeout),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		return otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unknown OTLP protocol %q (want grpc or http)", cfg.Protocol)
	}
}

// newResource builds the OpenTelemetry resource describing this service.
func newResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	name := strings.TrimSpace(cfg.ServiceName)
	if name == "" {
		name = "secsy-pki"
	}
	attrs := []attribute.KeyValue{semconv.ServiceName(name)}
	if v := strings.TrimSpace(cfg.ServiceVersion); v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	// Merge with the default resource so SDK/telemetry attributes (SDK name and
	// version, and any OTEL_RESOURCE_ATTRIBUTES from the environment) are retained.
	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
}

// Shutdown flushes any buffered spans and releases the exporter. It is safe to
// call on a Provider returned for a disabled configuration (no-op).
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// noop returns a no-op TracerProvider.
func noop() trace.TracerProvider { return tracenoop.NewTracerProvider() }

// --- context-threaded helpers ---------------------------------------------
//
// These read the process-global TracerProvider (installed by Init, or by a test
// harness). When tracing is disabled the global is a no-op provider and every
// call below is a cheap no-op returning the original context and a non-recording
// span.

// Tracer returns the instrumentation tracer from the global provider.
func Tracer() trace.Tracer { return otel.Tracer(instrumentationName) }

// Start begins a new span named name as a child of the span in ctx (if any) and
// returns the derived context and the span. The caller MUST End the returned
// span, typically with `defer span.End()`. attrs are attached at start.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// SpanFromContext returns the current span carried by ctx (a non-recording span
// when none is set), so callers can add attributes or events to an
// already-started span without starting a new one.
func SpanFromContext(ctx context.Context) trace.Span { return trace.SpanFromContext(ctx) }

// AddEvent records a named, timestamped event on the current span in ctx. It is
// used for point-in-time occurrences that do not warrant their own span, such as
// an HSM failover or a session-pool wait completing.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).AddEvent(name, trace.WithAttributes(attrs...))
}

// SetAttributes attaches attributes to the current span in ctx.
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(attrs...)
}

// End finishes span, recording err (if non-nil) as an exception event and
// marking the span's status Error. It is a convenience for the common
// `defer tracing.End(span, err)` pattern via a captured error variable, but
// since deferred arguments are evaluated eagerly, prefer EndSpan for the deferred
// form. End is exported for call sites that end a span inline.
func End(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// RecordError marks the current span in ctx as failed with err. It is a no-op
// when err is nil or no span is recording.
func RecordError(ctx context.Context, err error) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
