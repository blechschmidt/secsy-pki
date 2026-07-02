//go:build sqlite

package ca

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// installRecordingTracer installs a process-global SDK tracer that records every
// span (AlwaysSample) into an in-memory exporter, and returns it. The previous
// global provider is restored on cleanup so tests do not leak tracing state into
// one another. This is the standard OpenTelemetry test seam: the tracing helpers
// throughout the codebase read the global provider, so installing one here makes
// their spans observable without any special wiring.
func installRecordingTracer(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return exp
}

// spanNames returns the set of span names recorded so far.
func spanNames(exp *tracetest.InMemoryExporter) map[string]bool {
	got := map[string]bool{}
	for _, s := range exp.GetSpans() {
		got[s.Name] = true
	}
	return got
}

// TestIssuanceEmitsSpans is the Task 45 acceptance test for the issuance path:
// it drives a full CSR-based issuance through the instrumented key provider and
// asserts that the trace covers each hot path the task calls out — the CA
// signing operation, the keyprovider/HSM sign, the pre-issuance lint/CAA/
// name-constraint gates, and the persistence-store write — all under one trace
// rooted at the caller's span.
func TestIssuanceEmitsSpans(t *testing.T) {
	exp := installRecordingTracer(t)

	// Wrap the software provider in the instrumented wrapper exactly as the server
	// does (buildRoleProvider), so the hsm.* spans are emitted on the key path.
	provider := keyprovider.Instrument(softwareProvider(t))
	mgr := newTestManager(t, provider)

	// Root a parent span so we can confirm the issuance spans share its trace —
	// this is what ties the HTTP request span to the CA/HSM spans in production.
	ctx, root := otel.Tracer("test").Start(context.Background(), "test.request")

	ca := newRoot(t, mgr, "spans")
	csr := makeCSR(t, "leaf.example.com", []string{"leaf.example.com"})
	issued, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    ca.ID,
		CSRPEM:  csr,
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	root.End()

	got := spanNames(exp)
	want := []string{
		"ca.issue_leaf",                   // CA issuance operation
		"ca.build_leaf",                   // template assembly + gates
		"ca.gate.lint",                    // pre-issuance CA/B lint gate
		"ca.gate.caa",                     // pre-issuance CAA gate
		"ca.gate.name_constraints",        // pre-issuance name-constraints gate
		"ca.sign_certificate",             // certificate construction
		"store.record_issued_certificate", // persistence store write
		"hsm.signer",                      // obtaining the HSM signer
		"hsm.sign",                        // the on-device signing operation
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("issuance trace missing span %q (got %v)", name, keys(got))
		}
	}

	// Every issuance span must belong to the same trace as the root request span,
	// so an operator can follow a request end-to-end. Verify the CA sign span and
	// the HSM sign span share the root's trace ID.
	rootTID := root.SpanContext().TraceID()
	var sawIssue, sawSign bool
	for _, s := range exp.GetSpans() {
		if s.SpanContext.TraceID() != rootTID {
			continue
		}
		switch s.Name {
		case "ca.issue_leaf":
			sawIssue = true
		case "hsm.sign":
			sawSign = true
		}
	}
	if !sawIssue {
		t.Error("ca.issue_leaf span is not part of the request trace")
	}
	if !sawSign {
		t.Error("hsm.sign span is not part of the request trace")
	}

	// The issued serial should be stamped on the issue span for log/trace joins.
	var stamped bool
	for _, s := range exp.GetSpans() {
		if s.Name != "ca.issue_leaf" {
			continue
		}
		for _, a := range s.Attributes {
			if string(a.Key) == "cert.serial" && a.Value.AsString() == issued.Serial.String() {
				stamped = true
			}
		}
	}
	if !stamped {
		t.Error("ca.issue_leaf span missing cert.serial attribute matching the issued serial")
	}
}

// keys returns the keys of a set, for readable failure messages.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
