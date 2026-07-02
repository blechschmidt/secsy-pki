package discovery

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Store is the persistence surface the discovery runner needs: the CA list (to
// build the "issued by this PKI" trust pool) and the discovered-certificate
// inventory. *database.DB satisfies it.
type Store interface {
	ListCAs() ([]models.CA, error)
	RecordDiscoveredCertificate(d *models.DiscoveredCertificate) error
}

// KnownRootsFromStore builds the trust pool of this PKI's own CA certificates
// from the store, so served leaves that chain to one of them are recognized as
// issued-by-this-PKI. Returns nil when the deployment has no CA certificates yet.
func KnownRootsFromStore(store Store) (*x509.CertPool, error) {
	cas, err := store.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}
	var pems []string
	for _, c := range cas {
		if c.Certificate != "" {
			pems = append(pems, c.Certificate)
		}
	}
	return PoolFromCerts(pems), nil
}

// Runner ties a Scanner to the store and the notification sinks: it scans a set
// of targets, optionally records the findings to the inventory, and optionally
// dispatches flagged findings through the expiry-monitor sinks. It is used by the
// CLI, the API, and the optional background scan.
type Runner struct {
	store       Store
	monitorCfg  config.MonitorConfig
	expiryDays  int
	dialTimeout time.Duration
	concurrency int
	tenantID    string
	logger      *log.Logger
}

// NewRunner builds a discovery Runner. monitorCfg supplies the notification sinks
// (shared with the expiry monitor); a nil logger uses the standard logger.
func NewRunner(store Store, monitorCfg config.MonitorConfig, expiryDays int, logger *log.Logger) *Runner {
	if logger == nil {
		logger = log.Default()
	}
	if expiryDays <= 0 {
		expiryDays = DefaultExpiryDays
	}
	return &Runner{
		store:      store,
		monitorCfg: monitorCfg,
		expiryDays: expiryDays,
		tenantID:   models.DefaultTenantID,
		logger:     logger,
	}
}

// WithDialTimeout overrides the per-endpoint handshake timeout.
func (r *Runner) WithDialTimeout(d time.Duration) *Runner {
	r.dialTimeout = d
	return r
}

// WithConcurrency overrides the parallel-dial bound.
func (r *Runner) WithConcurrency(n int) *Runner {
	r.concurrency = n
	return r
}

// WithTenant scopes recorded findings to a tenant (defaults to the built-in one).
func (r *Runner) WithTenant(tenantID string) *Runner {
	if tenantID != "" {
		r.tenantID = tenantID
	}
	return r
}

// ScanResult is what a runner cycle returns: the report plus how many records it
// persisted.
type ScanResult struct {
	Report *Report `json:"report"`
	Stored int     `json:"stored"`
}

// Scan probes the targets, then (when requested) records the findings and
// dispatches flagged ones to the notification sinks. store and notify are
// independent: a read-only report sets both false.
func (r *Runner) Scan(ctx context.Context, targets []Target, store, notify bool) (*ScanResult, error) {
	roots, err := KnownRootsFromStore(r.store)
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{
		ExpiryDays:  r.expiryDays,
		DialTimeout: r.dialTimeout,
		Concurrency: r.concurrency,
		KnownRoots:  roots,
	}
	findings := scanner.Scan(ctx, targets)
	report := BuildReport(findings, r.expiryDays, time.Now())

	result := &ScanResult{Report: report}
	if store {
		for _, f := range findings {
			rec, ok := f.ToModel(r.tenantID, uuid.New().String())
			if !ok {
				continue
			}
			if err := r.store.RecordDiscoveredCertificate(rec); err != nil {
				r.logger.Printf("discovery: WARNING: failed to record %s: %v", rec.Endpoint, err)
				continue
			}
			result.Stored++
		}
	}
	if notify {
		Dispatch(ctx, r.monitorCfg, report, r.logger)
	}
	return result, nil
}

// BackgroundRunner periodically scans the configured targets on an interval,
// recording and alerting per the discovery config. It is started once at server
// boot and stopped on shutdown.
type BackgroundRunner struct {
	runner   *Runner
	targets  []Target
	interval time.Duration
	store    bool
	notify   bool
	logger   *log.Logger
}

// NewBackgroundRunner assembles a periodic scan from the discovery config. It
// returns (nil, nil) when discovery is disabled or has no targets, so the caller
// can simply skip starting it.
func NewBackgroundRunner(store Store, cfg config.DiscoveryConfig, monitorCfg config.MonitorConfig, logger *log.Logger) (*BackgroundRunner, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	targets, err := ParseTargets(TargetSpec{
		Endpoints:   cfg.Targets,
		HostsFile:   cfg.HostsFile,
		CIDRs:       cfg.CIDRs,
		DefaultPort: cfg.DefaultPort,
	})
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if logger == nil {
		logger = log.Default()
	}
	runner := NewRunner(store, monitorCfg, cfg.ExpiryDays, logger)
	if cfg.DialTimeoutSeconds > 0 {
		runner.WithDialTimeout(time.Duration(cfg.DialTimeoutSeconds) * time.Second)
	}
	if cfg.Concurrency > 0 {
		runner.WithConcurrency(cfg.Concurrency)
	}
	interval := time.Duration(cfg.IntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &BackgroundRunner{
		runner:   runner,
		targets:  targets,
		interval: interval,
		store:    cfg.Store,
		notify:   cfg.Notify,
		logger:   logger,
	}, nil
}

// Run scans immediately, then on every interval tick, until ctx is cancelled. It
// blocks; callers run it in a goroutine.
func (b *BackgroundRunner) Run(ctx context.Context) {
	b.logger.Printf("certificate discovery scanner started (interval=%s, targets=%d, store=%v, notify=%v)",
		b.interval, len(b.targets), b.store, b.notify)
	b.runOnce(ctx)

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			b.logger.Printf("certificate discovery scanner stopped")
			return
		case <-ticker.C:
			b.runOnce(ctx)
		}
	}
}

func (b *BackgroundRunner) runOnce(ctx context.Context) {
	res, err := b.runner.Scan(ctx, b.targets, b.store, b.notify)
	if err != nil {
		b.logger.Printf("certificate discovery: scan failed: %v", err)
		return
	}
	c := res.Report.Counts
	b.logger.Printf("certificate discovery: %d endpoint(s) scanned, %d stored — expiring=%d weak=%d sha1=%d rogue=%d",
		c.Total, res.Stored, c.ExpiringSoon, c.WeakKey, c.SHA1, c.Rogue)
}
