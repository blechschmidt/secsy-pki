package ers

import (
	"context"
	"log"
	"time"
)

// DefaultInterval is the preservation cadence when the operator does not
// configure one. Daily is ample: renewal is driven by TSA-certificate expiry and
// algorithm deprecation, which move on the scale of months to years, and daily
// generation bounds each Evidence Record to roughly a day of audit events.
const DefaultInterval = 24 * time.Hour

// Runner drives the preservation service on a fixed interval. It is registered
// on the leader elector so exactly one replica preserves at a time, and stopped
// by cancelling the context passed to Run.
type Runner struct {
	svc           *Service
	interval      time.Duration
	preserveAudit bool
	logger        *log.Logger
}

// NewRunner assembles a Runner. interval <= 0 selects DefaultInterval.
func NewRunner(svc *Service, interval time.Duration, preserveAudit bool, logger *log.Logger) *Runner {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{svc: svc, interval: interval, preserveAudit: preserveAudit, logger: logger}
}

// Run performs one cycle immediately, then on every interval tick, until ctx is
// cancelled. It blocks; callers register it as a leader-elected background job.
// Before the first cycle it seeds the record-count/freshness metrics from the
// store so a restart does not blank them.
func (r *Runner) Run(ctx context.Context) {
	r.logger.Printf("evidence-record preservation started (interval=%s, hash=%s, lookahead=%s, preserve_audit=%t, tsa=%s)",
		r.interval, HashName(r.svc.hash), r.svc.lookahead, r.preserveAudit, r.svc.ts.Source())
	if err := r.svc.SeedMetrics(); err != nil {
		r.logger.Printf("ers: seeding metrics from stored records: %v", err)
	}
	r.svc.RunOnce(ctx, r.preserveAudit)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("evidence-record preservation stopped")
			return
		case <-ticker.C:
			r.svc.RunOnce(ctx, r.preserveAudit)
		}
	}
}
