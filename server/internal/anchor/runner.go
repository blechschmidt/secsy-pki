package anchor

import (
	"context"
	"log"
	"time"
)

// DefaultInterval is the anchor cadence when the operator does not configure
// one. Daily anchoring bounds the window an undetected truncation can cover to
// one day of events while costing one TSA signature per day.
const DefaultInterval = 24 * time.Hour

// Runner drives the anchor service on a fixed interval. It is started once at
// server boot and stopped by cancelling the context passed to Run.
type Runner struct {
	svc      *Service
	interval time.Duration
	logger   *log.Logger
}

// NewRunner assembles a Runner. interval <= 0 selects DefaultInterval.
func NewRunner(svc *Service, interval time.Duration, logger *log.Logger) *Runner {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{svc: svc, interval: interval, logger: logger}
}

// Run anchors immediately, then on every interval tick, until ctx is
// cancelled. It blocks; callers run it in a goroutine. Before the first run it
// seeds the anchor-age metrics from the persisted state so a restart does not
// blank them.
func (r *Runner) Run(ctx context.Context) {
	r.logger.Printf("audit-chain anchoring started (interval=%s, tsa=%s)", r.interval, r.svc.sourceLabel())
	if err := r.svc.SeedMetrics(); err != nil {
		r.logger.Printf("audit anchor: seeding metrics from stored anchors: %v", err)
	}
	r.runOnce(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("audit-chain anchoring stopped")
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce performs a single anchoring attempt. Failures are logged, not fatal:
// the head is retried on the next tick (and the failure is visible via the
// secsy_audit_anchors_total{result="error"} counter and the audit trail).
func (r *Runner) runOnce(ctx context.Context) {
	res, err := r.svc.AnchorOnce(ctx, false)
	if err != nil {
		r.logger.Printf("audit anchor: %v", err)
		return
	}
	if res.Skipped {
		return
	}
	r.logger.Printf("audit anchor: anchored head seq=%d hash=%s (tsa=%s, gen_time=%s)",
		res.Anchor.Seq, res.Anchor.HeadHash, r.svc.sourceLabel(), res.Anchor.GenTime.Format(time.RFC3339))
}
