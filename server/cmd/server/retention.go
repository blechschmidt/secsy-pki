package main

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/retention"
)

// setupRetention wires the certificate-inventory retention/archival loop (Task
// 157): a leader-elected background job that ages out long-expired, terminal
// issued-certificate rows so a high-volume CA (short-lived STAR/ACME issuance)
// does not grow issued_certificates unbounded.
//
// It is leader-gated (Task 68) — a singleton, so replicas do not race each
// other's archive/prune transactions — and never blocks issuance: it operates
// only on already-terminal rows, in bounded batched transactions, and never
// touches the authoritative revoked_certificates table, so OCSP/CRL for every
// retained serial is unaffected. It never needs the HSM.
//
// Leader election bounds the replica count to one; it says nothing about what else
// in THAT process prunes. POST /api/inventory/retention/run drives the same
// runner over the same rows from the same binary, so each pass here takes
// handlers.TryRetentionLock — the process-wide single-flight the endpoint takes —
// and skips the tick rather than interleaving its hard deletes with an
// operator-triggered pass.
func setupRetention(cfg *config.Config, db *database.DB, elector *leader.Elector) {
	rc := cfg.Retention
	if !rc.Enabled {
		return
	}
	runner, err := retention.New(db, rc, log.Default())
	if err != nil {
		log.Fatalf("Certificate inventory retention configuration error: %v", err)
	}
	log.Printf("Certificate inventory retention enabled (mode %s, interval %s, min_age %dd, batch %d)",
		rc.ResolvedMode(), rc.Interval(), int(rc.MinAge().Hours()/24), rc.Batch())
	elector.Register("inventory-retention", func(ctx context.Context) {
		retentionLoop(ctx, runner, rc.Interval())
	})
}

// retentionLoop is runner.Run's schedule with the single-flight held across each
// pass. It is spelled out here rather than calling runner.Run because the guard
// has to be taken per PASS: holding it for the lifetime of the loop would lock out
// the REST endpoint entirely, and taking it nowhere would leave the endpoint and
// this loop pruning the same archive concurrently.
func retentionLoop(ctx context.Context, runner *retention.Runner, interval time.Duration) {
	pass := func() {
		release, free := handlers.TryRetentionLock()
		if !free {
			log.Printf("inventory retention: skipping this tick — an operator-triggered pass is in flight")
			return
		}
		defer release()
		runner.RunOnce(ctx)
	}
	pass()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("certificate inventory retention stopped")
			return
		case <-ticker.C:
			pass()
		}
	}
}
