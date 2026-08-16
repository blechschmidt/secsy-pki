package hsmaudit

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// FreshnessRunner obtains a timestamp attestation over the audit head on a
// schedule.
//
// It has to be a background job rather than something the export path does on
// demand, and the reason is the whole point of the feature. A timestamp taken at
// export time proves only that the export happened when it says it did — the CA
// could still have withheld the export for a month, and every intervening
// signature would sit outside any attested window. Attestations obtained
// continuously, on a cadence nobody chooses after the fact, are what divide the
// timeline into intervals that a later abuse cannot slip between.
//
// It is leader-elected for the same reason the collector is: several replicas
// attesting concurrently would interleave proofs covering overlapping heads,
// and VerifyFreshness would read the resulting non-monotonic sequence as an
// earlier state being re-attested — a genuine tampering signal, raised by a
// deployment mistake.
type FreshnessRunner struct {
	svc      *Service
	ts       Timestamper
	interval time.Duration
	logger   *log.Logger
}

// NewFreshnessRunner returns a runner over svc. interval <= 0 selects
// FreshnessInterval.
func NewFreshnessRunner(svc *Service, ts Timestamper, interval time.Duration, logger *log.Logger) *FreshnessRunner {
	if interval <= 0 {
		interval = FreshnessInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &FreshnessRunner{svc: svc, ts: ts, interval: interval, logger: logger}
}

// Run attests on the configured cadence until ctx is cancelled.
//
// It attests once at startup rather than waiting out the first interval. A
// process that restarts more often than the interval would otherwise never
// attest at all, which is exactly the deployment whose log would quietly go
// stale while every other check kept reporting OK.
func (r *FreshnessRunner) Run(ctx context.Context) {
	r.logger.Printf("HSM audit freshness attestation started (interval %s, source %s)",
		r.interval, sourceLabel(r.ts))
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		r.once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// once obtains a single attestation, logging the outcome.
//
// A failure is logged and counted but does not stop the loop: a TSA outage must
// not take the CA down. The staleness gauge is what turns a persistent failure
// into an alert, and the verifier fails closed on the resulting gap regardless
// of what this process believed at the time.
func (r *FreshnessRunner) once(ctx context.Context) {
	p, err := r.svc.Timestamp(ctx, r.ts)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		r.logger.Printf("ERROR: HSM audit freshness attestation failed: %v", err)
		metrics.RecordHSMAuditAttestation(time.Time{}, err)
		return
	}
	r.logger.Printf("HSM audit: head attested at %s by %s (device entry %d, %d signature(s), ledger %d)",
		p.GenTime.Format(time.RFC3339), sourceLabel(r.ts),
		p.Head.DeviceNumber, p.Head.Signatures, p.Head.LedgerSeq)
	metrics.RecordHSMAuditAttestation(p.GenTime, nil)
}

// sourceLabel renders a Timestamper's origin for logs.
func sourceLabel(ts Timestamper) string {
	if ts == nil {
		return "none"
	}
	if s := ts.Source(); s != "" {
		return s
	}
	return "the in-process TSA"
}
