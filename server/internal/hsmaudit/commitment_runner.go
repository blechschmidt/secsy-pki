package hsmaudit

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// CommitmentRunner obtains a device-signed, timestamped binding of the audit
// head to the device serial on a schedule.
//
// Like the freshness attestation this has to run continuously rather than at
// export time, and for a sharper reason. A commitment taken when the auditor
// asks binds only the state at that moment; every stretch of history between two
// such requests would be device-unbound, which is precisely the window an
// operator who fabricated entries would want. Commitments on a cadence nobody
// chooses after the fact divide the log into segments that each end in a
// hardware signature.
//
// It is leader-elected for a stronger reason than the freshness runner. A
// commitment is not a read: it generates a key at a reserved handle, attests it
// and deletes it. Two replicas doing that concurrently would collide on the
// handle — one would find the other's key in the slot — and would interleave
// commitments covering overlapping heads, which VerifyCommitments reads as an
// earlier state being re-bound.
type CommitmentRunner struct {
	svc      *Service
	ts       Timestamper
	interval time.Duration
	logger   *log.Logger
}

// NewCommitmentRunner returns a runner over svc. interval <= 0 selects
// CommitmentInterval.
func NewCommitmentRunner(svc *Service, ts Timestamper, interval time.Duration, logger *log.Logger) *CommitmentRunner {
	if interval <= 0 {
		interval = CommitmentInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &CommitmentRunner{svc: svc, ts: ts, interval: interval, logger: logger}
}

// Run commits on the configured cadence until ctx is cancelled.
//
// It commits once at startup rather than waiting out the first interval, for the
// same reason the freshness runner attests immediately: a process that restarts
// more often than the interval would otherwise never commit at all, and its log
// would quietly become device-unbound while every other check kept reporting OK.
func (r *CommitmentRunner) Run(ctx context.Context) {
	r.logger.Printf("HSM audit device commitment started (interval %s, dated by %s)",
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

// once obtains a single commitment, logging the outcome.
//
// A failure is logged and counted but does not stop the loop: neither a TSA
// outage nor a busy device must take the CA down. The staleness gauge is what
// turns a persistent failure into an alert, and the verifier fails closed on the
// resulting gap regardless of what this process believed at the time.
func (r *CommitmentRunner) once(ctx context.Context) {
	// Commit returns a commitment together with an error when the binding was
	// made and recorded but could not be dated, or left the device untidy. Those
	// are warnings about the deployment, not failed cycles — and counting them as
	// failures would make the metric say the device had stopped signing when it
	// had not.
	c, err := r.svc.Commit(ctx, r.ts)
	if c == nil {
		if ctx.Err() != nil {
			return
		}
		r.logger.Printf("ERROR: HSM audit device commitment failed: %v", err)
		metrics.RecordHSMAuditCommitment(time.Time{}, err)
		return
	}
	if err != nil {
		r.logger.Printf("WARNING: HSM audit device commitment: %v", err)
	}
	if c.GenTime.IsZero() {
		// An undated binding is not evidence, so it must not advance the age gauge:
		// doing so would report a freshly bound log while the auditor's verdict
		// would be that nothing bounds it in time.
		metrics.RecordHSMAuditCommitment(time.Time{}, err)
		return
	}
	r.logger.Printf("HSM audit: device %s bound itself to the log at %s, dated by %s "+
		"(device entry %d, %d signature(s), ledger %d, label %s)",
		c.Head.DeviceSerial, c.GenTime.Format(time.RFC3339), sourceLabel(r.ts),
		c.Head.DeviceNumber, c.Head.Signatures, c.Head.LedgerSeq, c.Label)
	metrics.RecordHSMAuditCommitment(c.GenTime, nil)
}
