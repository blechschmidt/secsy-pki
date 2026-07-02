package monitor

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// Runner drives a Monitor on a fixed interval, dispatching each scan's report to
// the configured notification sinks. It is started once at server boot and
// stopped on shutdown.
type Runner struct {
	monitor   *Monitor
	interval  time.Duration
	autoRenew bool
	bindings  []sinkBinding
	logger    *log.Logger
}

// NewRunner assembles a Runner from the application monitor config. The Monitor
// carries the thresholds/auto-renew policy; cfg drives the interval and the
// notification sinks. A log sink is always installed so warnings are never
// silently dropped.
func NewRunner(m *Monitor, cfg config.MonitorConfig, logger *log.Logger) (*Runner, error) {
	if logger == nil {
		logger = log.Default()
	}
	bindings, err := buildSinks(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &Runner{
		monitor:   m,
		interval:  time.Duration(cfg.IntervalHours) * time.Hour,
		autoRenew: cfg.AutoRenew,
		bindings:  bindings,
		logger:    logger,
	}, nil
}

// buildSinks resolves the configured notification sinks. When none are
// configured, a single log sink at the warning threshold is used so operators
// still see expiry warnings in the server log.
func buildSinks(cfg config.MonitorConfig, logger *log.Logger) ([]sinkBinding, error) {
	if len(cfg.Notifications) == 0 {
		return []sinkBinding{{sink: NewLogSink(logger), minSeverity: SeverityWarning}}, nil
	}
	bindings := make([]sinkBinding, 0, len(cfg.Notifications))
	for _, n := range cfg.Notifications {
		min, err := ParseSeverity(n.MinSeverity)
		if err != nil {
			return nil, err
		}
		var sink Sink
		switch n.Type {
		case "log":
			sink = NewLogSink(logger)
		case "webhook":
			sink = NewWebhookSink(n.URL, n.Headers, time.Duration(n.TimeoutSeconds)*time.Second)
		}
		bindings = append(bindings, sinkBinding{sink: sink, minSeverity: min})
	}
	return bindings, nil
}

// Run scans immediately, then on every interval tick, until ctx is cancelled.
// It blocks; callers run it in a goroutine.
func (r *Runner) Run(ctx context.Context) {
	r.logger.Printf("cert-expiry monitor started (interval=%s, auto_renew=%v)", r.interval, r.autoRenew)
	r.runOnce(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("cert-expiry monitor stopped")
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce performs a single scan-and-notify cycle, logging any scan error.
func (r *Runner) runOnce(ctx context.Context) {
	report, err := r.monitor.Scan(ctx, ScanRequest{AutoRenew: r.autoRenew, RequestedBy: "monitor"})
	if err != nil {
		r.logger.Printf("cert-expiry monitor: scan failed: %v", err)
		return
	}
	r.monitor.Dispatch(ctx, report, r.bindings)
}
