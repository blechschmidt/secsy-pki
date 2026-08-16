package keyprovider

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// installRecordingTracer installs a process-global recording tracer backed by an
// in-memory exporter and restores the previous global on cleanup. The failover
// path emits span events on the current span, so the caller starts a span whose
// events these tests inspect once it ends.
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

// TestFailoverEmitsSpanEvents is the Task 45 acceptance test for HSM failover
// visibility (Task 44): when an operation errs on the primary token and is
// retried on the backup, the trace must show the token error, the failover, and
// which token ultimately served the operation — as events on the operation's
// span.
func TestFailoverEmitsSpanEvents(t *testing.T) {
	exp := installRecordingTracer(t)

	p := newBareHA(PolicyPrimaryBackup, 1, "tok-a", "tok-b")

	ctx, span := otel.Tracer("test").Start(context.Background(), "hsm.op")
	transportErr := errors.New("pkcs11: session handle invalid")
	err := p.withFailover(ctx, "sign", nil, func(m *haMember) error {
		if m.name == "tok-a" {
			return transportErr // primary fails → charge health, fail over
		}
		return nil // backup succeeds
	})
	span.End()
	if err != nil {
		t.Fatalf("withFailover returned %v, want nil (failover to backup)", err)
	}

	// Collect the events recorded on the operation span.
	stubs := exp.GetSpans()
	if len(stubs) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(stubs))
	}
	events := map[string]map[string]string{}
	for _, ev := range stubs[0].Events {
		attrs := map[string]string{}
		for _, a := range ev.Attributes {
			attrs[string(a.Key)] = a.Value.String()
		}
		events[ev.Name] = attrs
	}

	// The primary's error must be recorded, attributed to the right token/op.
	tokErr, ok := events["hsm.token.error"]
	if !ok {
		t.Fatalf("missing hsm.token.error event (got events %v)", eventNames(events))
	}
	if tokErr["hsm.token"] != "tok-a" {
		t.Errorf("hsm.token.error hsm.token = %q, want tok-a", tokErr["hsm.token"])
	}
	if tokErr["hsm.operation"] != "sign" {
		t.Errorf("hsm.token.error hsm.operation = %q, want sign", tokErr["hsm.operation"])
	}

	// The failover itself must be recorded, naming the token failed away from and
	// the token failed over to.
	fo, ok := events["hsm.failover"]
	if !ok {
		t.Fatalf("missing hsm.failover event (got events %v)", eventNames(events))
	}
	if fo["hsm.token.from"] != "tok-a" || fo["hsm.token.to"] != "tok-b" {
		t.Errorf("hsm.failover = %v, want from=tok-a to=tok-b", fo)
	}

	// And the backup must be recorded as the token that served the operation.
	served, ok := events["hsm.failover.served"]
	if !ok {
		t.Fatalf("missing hsm.failover.served event (got events %v)", eventNames(events))
	}
	if served["hsm.token"] != "tok-b" {
		t.Errorf("hsm.failover.served hsm.token = %q, want tok-b", served["hsm.token"])
	}
}

// TestNoFailoverEmitsNoFailoverEvent confirms the happy path is quiet: when the
// primary serves the operation, no failover/served/error events are emitted, so
// the events are a true signal of a failover rather than noise on every request.
func TestNoFailoverEmitsNoFailoverEvent(t *testing.T) {
	exp := installRecordingTracer(t)

	p := newBareHA(PolicyPrimaryBackup, 1, "tok-a", "tok-b")
	ctx, span := otel.Tracer("test").Start(context.Background(), "hsm.op")
	err := p.withFailover(ctx, "sign", nil, func(m *haMember) error { return nil })
	span.End()
	if err != nil {
		t.Fatalf("withFailover returned %v, want nil", err)
	}

	stubs := exp.GetSpans()
	if len(stubs) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(stubs))
	}
	for _, ev := range stubs[0].Events {
		switch ev.Name {
		case "hsm.failover", "hsm.failover.served", "hsm.token.error":
			t.Errorf("unexpected event %q on the no-failover happy path", ev.Name)
		}
	}
}

func eventNames(m map[string]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
