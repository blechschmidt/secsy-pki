package backup

import (
	"context"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// NewStore constructs the configured backup destination backend, reusing the
// Task 58 publish sinks. Setting s3.bucket selects the S3-compatible backend;
// otherwise the local directory is used. The directory backend is created with
// keep = the retention count so its built-in count-based pruning aligns with
// keep-N (the scheduled backup runner additionally enforces max-age).
//
// Both the scheduled backup writer (cmd/server) and the restore-verification
// reader (the CLI and the leader-elected verifier) construct the store from the
// same BackupConfig through this helper, so a verify always reads exactly the
// destination a backup wrote to.
func NewStore(bc config.BackupConfig) (publish.Store, error) {
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
