package main

import (
	"log"

	"github.com/blechschmidt/secsy-pki/server/internal/backup"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// setupBackup wires the scheduled encrypted-backup loop (Task 89) and, when
// enabled, the automated restore-verification drill (Task 94).
//
// The backup loop, every interval, produces the disaster-recovery backup
// artifact (logical DB dump + config + public CA material + audit-chain head
// fingerprint), encrypts it under the secret-layer KEK on the HSM, and writes it
// to the configured directory or S3-compatible store with an atomic swap, a
// manifest, and keep-N / max-age retention.
//
// The verify loop closes the loop: an untested backup is not a backup. Every
// interval it pulls the newest published artifact, decrypts it, restores the DB
// dump into an isolated scratch database, runs the HSM-independent integrity
// gate, and confirms the restored audit-head fingerprint matches the manifest.
//
// Both are leader-gated (Task 68): each is a singleton — one replica producing
// artifacts avoids racing atomic swaps against the same destination, and one
// replica verifying avoids redundant restores and duplicate alerts; handovers
// are idempotent. Neither blocks issuance: the writer reads the store and takes
// an online snapshot / MVCC dump, touching the HSM only to bind the KEK ring;
// the verifier restores entirely within the scratch database.
func setupBackup(cfg *config.Config, db *database.DB, provider keyprovider.Provider, configPath string, elector *leader.Elector) {
	bc := cfg.Backup
	if !bc.Enabled {
		return
	}
	kekLabel := bc.EffectiveKEKLabel(cfg.Secret.KEKLabel)
	if kekLabel == "" {
		log.Fatalf("Scheduled backup enabled but no KEK configured (set backup.kek_label or secret.kek_label)")
	}
	store, err := backup.NewStore(bc)
	if err != nil {
		log.Fatalf("Scheduled backup configuration error: %v", err)
	}
	src := backup.Source{
		DB:         db,
		Provider:   provider,
		DSN:        cfg.Database.DSN,
		ConfigPath: configPath,
	}
	runner, err := backup.New(src, store, bc, kekLabel, log.Default())
	if err != nil {
		log.Fatalf("Scheduled backup configuration error: %v", err)
	}
	log.Printf("Scheduled encrypted backups enabled (backend %s, interval %s, keep %d, kek %s)",
		store.Name(), bc.Interval(), bc.Keep(), kekLabel)
	elector.Register("scheduled-backup", runner.Run)

	// Automated restore-verification drill (Task 94). Opt-in: the PostgreSQL path
	// needs psql on PATH and CREATE/DROP scratch-database privilege, so it is only
	// started when explicitly enabled. Failures are alerted through the same
	// notification sinks the expiry monitor uses.
	if bc.VerifyEnabled() {
		notifier, err := monitor.NewNotifier(cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("Backup restore-verification notification configuration error: %v", err)
		}
		// The verifier reads from the same destination the writer publishes to; a
		// separate store handle keeps their retention/pruning state independent.
		verifyStore, err := backup.NewStore(bc)
		if err != nil {
			log.Fatalf("Backup restore-verification configuration error: %v", err)
		}
		verifier, err := backup.NewVerifier(src, verifyStore, bc, kekLabel, notifier, log.Default())
		if err != nil {
			log.Fatalf("Backup restore-verification configuration error: %v", err)
		}
		log.Printf("Automated backup restore-verification enabled (interval %s)", bc.VerifyInterval())
		elector.Register("backup-verify", verifier.Run)
	}
}
