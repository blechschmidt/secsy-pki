package siem

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// fakeSource is an in-memory event log with a per-sink cursor store.
type fakeSource struct {
	mu      sync.Mutex
	events  []audit.Event
	cursors map[string]int64
}

func newFakeSource(n int) *fakeSource {
	fs := &fakeSource{cursors: map[string]int64{}}
	for i := 1; i <= n; i++ {
		fs.events = append(fs.events, audit.Event{
			Seq: int64(i), ID: fmt.Sprintf("e%d", i), Timestamp: time.Unix(int64(i), 0).UTC(),
			Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess, Hash: fmt.Sprintf("h%d", i),
		})
	}
	return fs
}

func (f *fakeSource) ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Event
	for _, e := range f.events {
		if e.Seq > afterSeq {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeSource) MaxEventSeq() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return 0, nil
	}
	return f.events[len(f.events)-1].Seq, nil
}

func (f *fakeSource) GetSIEMCursor(sink string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cursors[sink], nil
}

func (f *fakeSource) SetSIEMCursor(sink string, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cursors[sink] = seq
	return nil
}

func (f *fakeSource) cursor(sink string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cursors[sink]
}

// fakeSink records delivered events and can be told to fail its first failUntil
// delivery attempts (to exercise retry / at-least-once).
type fakeSink struct {
	name string
	mu   sync.Mutex
	// delivered accumulates the seqs the sink acknowledged, in order.
	delivered []int64
	attempts  int
	failUntil int
	// deliverErr, when set, is returned for every attempt (permanent failure).
	deliverErr error
}

func (s *fakeSink) Name() string { return s.name }

func (s *fakeSink) Deliver(_ context.Context, events []audit.Event, _ Formatter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.deliverErr != nil {
		return s.deliverErr
	}
	if s.attempts <= s.failUntil {
		return fmt.Errorf("transient failure #%d", s.attempts)
	}
	for _, e := range events {
		s.delivered = append(s.delivered, e.Seq)
	}
	return nil
}

func (s *fakeSink) Close() error { return nil }

func (s *fakeSink) got() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.delivered...)
}

// waitFor polls fn until it returns true or the deadline elapses.
func waitFor(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func fastOpts() Options {
	return Options{
		PollInterval: 5 * time.Millisecond,
		BatchSize:    256,
		RetryBackoff: 2 * time.Millisecond,
		MaxBackoff:   10 * time.Millisecond,
	}
}

func TestExporterDeliversAllInOrder(t *testing.T) {
	src := newFakeSource(5)
	sink := &fakeSink{name: "s1"}
	exp := NewExporter(src, src, []boundSink{BindSink(sink, mustFormatter(t))}, fastOpts())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()

	waitFor(t, 2*time.Second, func() bool { return src.cursor("s1") == 5 })
	cancel()
	<-done

	got := sink.got()
	if len(got) != 5 {
		t.Fatalf("delivered %d events, want 5: %v", len(got), got)
	}
	for i, seq := range got {
		if seq != int64(i+1) {
			t.Fatalf("out-of-order delivery: %v", got)
		}
	}
}

// TestExporterAtLeastOnceOnFailure verifies the cursor is not advanced while the
// sink is failing, and every event is eventually delivered once the sink
// recovers. The batch is retried, not skipped.
func TestExporterAtLeastOnceOnFailure(t *testing.T) {
	src := newFakeSource(3)
	sink := &fakeSink{name: "s1", failUntil: 3} // first 3 attempts fail
	exp := NewExporter(src, src, []boundSink{BindSink(sink, mustFormatter(t))}, fastOpts())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()

	// The cursor must stay at 0 until a delivery succeeds.
	waitFor(t, 2*time.Second, func() bool { return src.cursor("s1") == 3 })
	cancel()
	<-done

	got := sink.got()
	if len(got) != 3 {
		t.Fatalf("delivered %d events, want 3 (no loss): %v", len(got), got)
	}
	if sink.attempts < 4 {
		t.Errorf("expected retries before success, got %d attempts", sink.attempts)
	}
}

// TestExporterResumesFromCursor verifies a pre-existing cursor is honored so
// already-delivered events are not re-sent on (re)start.
func TestExporterResumesFromCursor(t *testing.T) {
	src := newFakeSource(5)
	src.SetSIEMCursor("s1", 3) // pretend 1..3 were delivered before

	sink := &fakeSink{name: "s1"}
	exp := NewExporter(src, src, []boundSink{BindSink(sink, mustFormatter(t))}, fastOpts())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()

	waitFor(t, 2*time.Second, func() bool { return src.cursor("s1") == 5 })
	cancel()
	<-done

	got := sink.got()
	want := []int64{4, 5}
	if len(got) != len(want) || got[0] != 4 || got[1] != 5 {
		t.Fatalf("resumed delivery = %v, want %v", got, want)
	}
}

// TestExporterBatchingBackpressure verifies a small batch size splits a large
// backlog into multiple bounded deliveries (no unbounded in-flight set).
func TestExporterBatchingBackpressure(t *testing.T) {
	src := newFakeSource(10)
	sink := &fakeSink{name: "s1"}
	opts := fastOpts()
	opts.BatchSize = 3
	exp := NewExporter(src, src, []boundSink{BindSink(sink, mustFormatter(t))}, opts)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()
	waitFor(t, 2*time.Second, func() bool { return src.cursor("s1") == 10 })
	cancel()
	<-done

	// 10 events in batches of 3 => at least 4 delivery attempts (3+3+3+1).
	if sink.attempts < 4 {
		t.Errorf("expected >=4 bounded batches, got %d attempts", sink.attempts)
	}
	if got := sink.got(); len(got) != 10 {
		t.Fatalf("delivered %d, want 10", len(got))
	}
}

// TestExporterIndependentSinks verifies a permanently-failing sink does not
// block a healthy one — each has its own cursor and worker.
func TestExporterIndependentSinks(t *testing.T) {
	src := newFakeSource(4)
	healthy := &fakeSink{name: "healthy"}
	broken := &fakeSink{name: "broken", deliverErr: fmt.Errorf("always down")}
	exp := NewExporter(src, src, []boundSink{
		BindSink(healthy, mustFormatter(t)),
		BindSink(broken, mustFormatter(t)),
	}, fastOpts())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()

	waitFor(t, 2*time.Second, func() bool { return src.cursor("healthy") == 4 })
	// The broken sink never advances.
	if c := src.cursor("broken"); c != 0 {
		t.Errorf("broken sink cursor = %d, want 0 (never acknowledged)", c)
	}
	cancel()
	<-done

	if len(healthy.got()) != 4 {
		t.Errorf("healthy sink delivered %d, want 4", len(healthy.got()))
	}
	if len(broken.got()) != 0 {
		t.Errorf("broken sink should have delivered nothing, got %v", broken.got())
	}
}

func mustFormatter(t *testing.T) Formatter {
	t.Helper()
	f, err := NewFormatter(FormatJSON, FormatterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
