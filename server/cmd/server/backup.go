package main

import (
	"context"
	"log"

	"github.com/blechschmidt/secsy-pki/server/internal/backup"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// setupBackup wires the scheduled encrypted-backup loop (Task 89): every
// interval it produces the disaster-recovery backup artifact (logical DB dump +
// config + public CA material + audit-chain head fingerprint), encrypts it under
// the secret-layer KEK on the HSM, and writes it to the configured directory or
// S3-compatible store with an atomic swap, a manifest, and keep-N / max-age
// retention.
//
// The loop is leader-gated (Task 68): a scheduled backup is a singleton — one
// replica producing artifacts avoids racing atomic swaps against the same
// destination and duplicating dumps, and a handover is idempotent (the new
// leader's first backup simply supersedes the old leader's last one). It never
// blocks issuance: it reads the store and takes an online snapshot / MVCC dump,
// and touches the HSM only to bind the KEK ring.
func setupBackup(cfg *config.Config, db *database.DB, provider keyprovider.Provider, configPath string, elector *leader.Elector) {
	bc := cfg.Backup
	if !bc.Enabled {
		return
	}
	kekLabel := bc.EffectiveKEKLabel(cfg.Secret.KEKLabel)
	if kekLabel == "" {
		log.Fatalf("Scheduled backup enabled but no KEK configured (set backup.kek_label or secret.kek_label)")
	}
	store, err := newBackupStore(bc)
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
}

// newBackupStore constructs the configured backup destination backend, reusing
// the Task 58 publish sinks. The local-directory backend is created with keep =
// the retention count so its built-in count-based pruning aligns with keep-N;
// the backup runner additionally enforces max-age.
func newBackupStore(bc config.BackupConfig) (publish.Store, error) {
	if bc.Backend() == "s3" {
		return publish.NewS3Store(context.Background(), publish.S3Config{
			Endpoint:        bc.S3.Endpoint,
			Region:          bc.S3.Region,
			Bucket:          bc.S3.Bucket,
			Prefix:          bc.S3.Prefix,
			AccessKeyID:     bc.S3.AccessKeyID,
			SecretAccessKey: bc.S3.SecretAccessKey,
			SessionToken:    bc.S3.SessionToken,
			ForcePathStyle:  bc.S3.ForcePathStyle,
			Concurrency:     bc.S3.Concurrency,
		})
	}
	return publish.NewDirStore(bc.Dir.Path, bc.Keep())
}
