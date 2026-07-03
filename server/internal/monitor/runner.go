package monitor

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// Rotator triggers HSM-backed key rotation of intermediate CAs that are nearing
// expiry. *ca.Manager satisfies it. It is optional: rotation runs only when the
// Runner is configured with one and monitor.rotate_intermediates is set.
type Rotator interface {
	AutoRotateDue(ctx context.Context, spec ca.AutoRotateSpec) ([]ca.RotationResult, error)
}

// Runner drives a Monitor on a fixed interval, dispatching each scan's report to
// the configured notification sinks. It is started once at server boot and
// stopped on shutdown.
type Runner struct {
	monitor      *Monitor
	interval     time.Duration
	autoRenew    bool
	bindings     []sinkBinding
	logger       *log.Logger
	rotator      Rotator
	rotateAfter  bool          // whether auto-rotation of intermediates is enabled
	rotateBefore time.Duration // remaining-validity threshold to rotate an intermediate
	auditSink    AuditSink
	// secretKEKCheck, when set, runs each tick to refresh the secret-layer KEK
	// rotation gauges (secsy_secret_on_old_kek and friends) and returns warning
	// lines for secrets lingering on superseded KEK versions (Task 63).
	secretKEKCheck func(ctx context.Context) ([]string, error)
	// secretLifecycle, when set, scans stored-secret TTL/rotation schedules
	// each tick and dispatches storm-filtered reminders through the same
	// notification sinks (Task 73).
	secretLifecycle *SecretLifecycleScanner
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
		monitor:      m,
		interval:     time.Duration(cfg.IntervalHours) * time.Hour,
		autoRenew:    cfg.AutoRenew,
		bindings:     bindings,
		logger:       logger,
		rotateAfter:  cfg.RotateIntermediates,
		rotateBefore: time.Duration(cfg.RotateBeforeDays) * 24 * time.Hour,
	}, nil
}

// WithRotation enables scan-driven auto-rotation of intermediate CA keys. The
// rotator (an *ca.Manager) performs the HSM-backed rollover and auditSink (may
// be nil) records rotation events. Rotation still only runs when the config's
// rotate_intermediates flag is set.
func (r *Runner) WithRotation(rotator Rotator, auditSink AuditSink) *Runner {
	r.rotator = rotator
	r.auditSink = auditSink
	return r
}

// WithSecretKEKCheck wires the secret-layer KEK rotation check into the scan
// loop: each tick, check refreshes the per-family rotation gauges and returns
// warning lines (secrets still on an old or retired KEK version), which the
// runner surfaces in the monitor log. check is typically a closure over
// secret.RefreshKEKMetrics and the store.
func (r *Runner) WithSecretKEKCheck(check func(ctx context.Context) ([]string, error)) *Runner {
	r.secretKEKCheck = check
	return r
}

// WithSecretLifecycle wires stored-secret TTL/rotation reminder scanning into
// the scan loop. Findings that pass the scanner's storm filter are delivered
// through the runner's notification sinks, honoring each sink's minimum
// severity like certificate-expiry warnings.
func (r *Runner) WithSecretLifecycle(scanner *SecretLifecycleScanner) *Runner {
	r.secretLifecycle = scanner
	return r
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

// runOnce performs a single scan-and-notify cycle, logging any scan error, and
// (when configured) auto-rotates intermediate CA keys nearing expiry first so a
// freshly rotated-in key is already active for the scan's downstream renewals.
func (r *Runner) runOnce(ctx context.Context) {
	r.rotateOnce(ctx)
	r.checkSecretKEK(ctx)
	r.scanSecretLifecycle(ctx)

	report, err := r.monitor.Scan(ctx, ScanRequest{AutoRenew: r.autoRenew, RequestedBy: "monitor"})
	if err != nil {
		r.logger.Printf("cert-expiry monitor: scan failed: %v", err)
		return
	}
	r.monitor.Dispatch(ctx, report, r.bindings)
}

// scanSecretLifecycle runs the stored-secret TTL/rotation scan and dispatches
// the storm-filtered findings through the notification sinks, each binding
// filtered by its minimum severity. Failures are logged, not fatal: the scan
// reruns on the next tick.
func (r *Runner) scanSecretLifecycle(ctx context.Context) {
	if r.secretLifecycle == nil {
		return
	}
	items, err := r.secretLifecycle.Scan(ctx)
	if err != nil {
		r.logger.Printf("cert-expiry monitor: secret lifecycle scan failed: %v", err)
		return
	}
	due := r.secretLifecycle.FilterForNotify(items)
	if len(due) == 0 {
		return
	}
	for _, b := range r.bindings {
		var filtered []SecretItem
		for _, it := range due {
			if it.Severity.atLeast(b.minSeverity) {
				filtered = append(filtered, it)
			}
		}
		if len(filtered) == 0 {
			continue
		}
		n := Notification{
			GeneratedAt:    time.Now(),
			MinSeverity:    b.minSeverity,
			Counts:         map[Severity]int{},
			SecretWarnings: filtered,
		}
		if err := b.sink.Notify(ctx, n); err != nil {
			r.logger.Printf("cert-expiry monitor: notification sink %s failed: %v", b.sink.Name(), err)
		}
	}
}

// checkSecretKEK refreshes the secret-layer KEK rotation gauges and logs any
// secrets lingering on superseded KEK versions. Failures are logged, not
// fatal: the check reruns on the next tick.
func (r *Runner) checkSecretKEK(ctx context.Context) {
	if r.secretKEKCheck == nil {
		return
	}
	warnings, err := r.secretKEKCheck(ctx)
	if err != nil {
		r.logger.Printf("cert-expiry monitor: secret KEK rotation check failed: %v", err)
		return
	}
	for _, w := range warnings {
		r.logger.Printf("cert-expiry monitor: secret KEK: %s", w)
	}
}

// rotateOnce triggers HSM-backed rotation of any active intermediate CA whose
// own certificate falls within the rotate-before window. It is a no-op unless
// rotation is both configured and enabled. Failures are logged, not fatal: a CA
// that cannot rotate this cycle is retried on the next tick.
func (r *Runner) rotateOnce(ctx context.Context) {
	if !r.rotateAfter || r.rotator == nil {
		return
	}
	results, err := r.rotator.AutoRotateDue(ctx, ca.AutoRotateSpec{
		Before:      r.rotateBefore,
		RequestedBy: "monitor",
	})
	for _, res := range results {
		r.logger.Printf("cert-expiry monitor: rotated intermediate CA %q -> %q (new key active; overlap window open)",
			res.OldCA.Label, res.NewCA.Label)
		r.recordRotationAudit(res)
	}
	if err != nil {
		r.logger.Printf("cert-expiry monitor: intermediate rotation error: %v", err)
	}
}

// recordRotationAudit appends a best-effort audit event for one auto-rotation.
func (r *Runner) recordRotationAudit(res ca.RotationResult) {
	if r.auditSink == nil {
		return
	}
	detail := "old_ca=" + res.OldCA.ID + " new_ca=" + res.NewCA.ID + " new_serial=" + res.NewCA.Serial
	if res.RetireAfter != nil {
		detail += " retire_after=" + res.RetireAfter.Format(time.RFC3339)
	}
	if err := r.auditSink.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Action:     audit.ActionCARotate,
		Actor:      "monitor",
		ActorRoles: "system",
		Target:     res.NewCA.ID,
		TargetName: res.NewCA.Label,
		Result:     audit.ResultSuccess,
		Detail:     detail,
	}); err != nil {
		r.logger.Printf("cert-expiry monitor: WARNING: failed to append rotation audit event: %v", err)
	}
}
