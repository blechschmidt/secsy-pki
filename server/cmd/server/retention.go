package main

import (
	"log"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
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
	elector.Register("inventory-retention", runner.Run)
}
