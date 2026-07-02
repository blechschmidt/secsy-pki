package siem

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// EventSource reads the audit event log forward. *database.DB satisfies it.
type EventSource interface {
	// ListEventsSince returns up to limit events with seq > afterSeq, ascending.
	ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error)
	// MaxEventSeq returns the highest sequence number in the log (0 if empty).
	MaxEventSeq() (int64, error)
}

// CursorStore persists the per-sink delivery high-water mark. *database.DB
// satisfies it.
type CursorStore interface {
	// GetSIEMCursor returns the last delivered seq for sink (0 if never delivered).
	GetSIEMCursor(sink string) (int64, error)
	// SetSIEMCursor durably records seq as delivered for sink.
	SetSIEMCursor(sink string, seq int64) error
}

// Options tunes the streaming exporter. Zero values fall back to defaults.
type Options struct {
	// PollInterval is how often a caught-up worker re-checks for new events.
	// Default 5s.
	PollInterval time.Duration
	// BatchSize bounds how many events a worker reads and delivers per iteration.
	// This is the primary backpressure knob: a slow or failing sink can never
	// accumulate more than BatchSize in flight, and reading is bounded regardless
	// of how far behind the cursor is. Default 256.
	BatchSize int
	// RetryBackoff is the initial delay after a failed delivery; it doubles up to
	// MaxBackoff. The cursor is not advanced on failure, so the same batch is
	// retried (at-least-once). Default 1s.
	RetryBackoff time.Duration
	// MaxBackoff caps the retry delay. Default 30s.
	MaxBackoff time.Duration
	// Logger receives operational messages. Defaults to the standard logger.
	Logger *log.Logger
}

func (o Options) withDefaults() Options {
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Second
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 256
	}
	if o.RetryBackoff <= 0 {
		o.RetryBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	return o
}

// boundSink pairs a configured sink with the formatter it emits.
type boundSink struct {
	sink      Sink
	formatter Formatter
}

// Exporter streams the audit event log to one or more sinks. Each sink is driven
// by its own worker goroutine reading from its own durable cursor, so a slow or
// down sink never blocks the others and never loses events: on restart every
// worker resumes from its persisted cursor.
type Exporter struct {
	source  EventSource
	cursors CursorStore
	sinks   []boundSink
	opts    Options
}

// NewExporter builds an exporter over source/cursors with the given sinks.
func NewExporter(source EventSource, cursors CursorStore, sinks []boundSink, opts Options) *Exporter {
	return &Exporter{source: source, cursors: cursors, sinks: sinks, opts: opts.withDefaults()}
}

// BindSink pairs a sink with a formatter for NewExporter.
func BindSink(sink Sink, formatter Formatter) boundSink {
	return boundSink{sink: sink, formatter: formatter}
}

// Run starts one worker per sink and blocks until ctx is cancelled, then closes
// every sink. It is intended to run in its own goroutine for the process
// lifetime.
func (e *Exporter) Run(ctx context.Context) {
	done := make(chan struct{}, len(e.sinks))
	for i := range e.sinks {
		bs := e.sinks[i]
		go func() {
			defer func() { done <- struct{}{} }()
			e.runWorker(ctx, bs)
		}()
	}
	for range e.sinks {
		<-done
	}
	for _, bs := range e.sinks {
		if err := bs.sink.Close(); err != nil {
			e.opts.Logger.Printf("siem: closing sink %s: %v", bs.sink.Name(), err)
		}
	}
}

// runWorker drives a single sink: read from the cursor, deliver, advance the
// cursor on success, back off and retry on failure — until ctx is cancelled.
func (e *Exporter) runWorker(ctx context.Context, bs boundSink) {
	name := bs.sink.Name()
	backoff := e.opts.RetryBackoff

	cursor, err := e.cursors.GetSIEMCursor(name)
	if err != nil {
		e.opts.Logger.Printf("siem: sink %s: loading cursor: %v; starting from genesis", name, err)
		cursor = 0
	}
	e.opts.Logger.Printf("siem: sink %s (%s) started at cursor seq=%d", name, bs.formatter.Name(), cursor)

	for {
		if ctx.Err() != nil {
			return
		}

		head, err := e.source.MaxEventSeq()
		if err != nil {
			e.opts.Logger.Printf("siem: sink %s: reading head: %v", name, err)
			if !e.sleep(ctx, e.opts.PollInterval) {
				return
			}
			continue
		}
		metrics.RecordAuditExportLag(name, cursor, head)

		if cursor >= head {
			// Caught up; wait for new events.
			if !e.sleep(ctx, e.opts.PollInterval) {
				return
			}
			continue
		}

		batch, err := e.source.ListEventsSince(cursor, e.opts.BatchSize)
		if err != nil {
			e.opts.Logger.Printf("siem: sink %s: reading events: %v", name, err)
			if !e.sleep(ctx, e.opts.PollInterval) {
				return
			}
			continue
		}
		if len(batch) == 0 {
			if !e.sleep(ctx, e.opts.PollInterval) {
				return
			}
			continue
		}

		// Bound each delivery attempt by a timeout derived from the poll interval
		// floor so a hung sink cannot wedge the worker indefinitely.
		deliverCtx, cancel := context.WithTimeout(ctx, e.deliveryTimeout())
		err = bs.sink.Deliver(deliverCtx, batch, bs.formatter)
		cancel()
		if err != nil {
			// At-least-once: do NOT advance the cursor; retry the same batch after
			// a bounded, growing backoff.
			metrics.RecordAuditExportFailure(name, len(batch))
			e.opts.Logger.Printf("siem: sink %s: delivery of %d event(s) from seq=%d failed: %v (retrying in %s)",
				name, len(batch), cursor+1, err, backoff)
			if !e.sleep(ctx, backoff) {
				return
			}
			backoff = minDuration(backoff*2, e.opts.MaxBackoff)
			continue
		}

		last := batch[len(batch)-1].Seq
		if err := e.cursors.SetSIEMCursor(name, last); err != nil {
			// The batch was delivered but the cursor write failed. Leaving the
			// cursor where it is means the batch will be redelivered next round —
			// acceptable under at-least-once. Back off to avoid a hot loop.
			e.opts.Logger.Printf("siem: sink %s: persisting cursor at seq=%d failed: %v (batch delivered; will redeliver)",
				name, last, err)
			if !e.sleep(ctx, backoff) {
				return
			}
			backoff = minDuration(backoff*2, e.opts.MaxBackoff)
			continue
		}

		cursor = last
		backoff = e.opts.RetryBackoff // reset after a clean delivery
		metrics.RecordAuditExportSuccess(name, cursor, head, len(batch), time.Now())
		// Loop immediately to drain any remaining backlog without waiting.
	}
}

// deliveryTimeout bounds a single Deliver call. It is generous relative to the
// poll interval so large batches over a slow link still complete.
func (e *Exporter) deliveryTimeout() time.Duration {
	t := e.opts.PollInterval * 4
	if t < 30*time.Second {
		t = 30 * time.Second
	}
	return t
}

// sleep waits for d or until ctx is cancelled. It returns false if ctx was
// cancelled (the caller should stop).
func (e *Exporter) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
