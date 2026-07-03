package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// cmdPublish publishes the PKI's public revocation and trust artifacts — CRLs,
// delta CRLs, partition shards, issuer chains, and pre-signed OCSP responses —
// as one static snapshot to the configured directory or S3-compatible store
// (Task 58). With -verify it instead audits the currently published snapshot
// against its manifest, which deliberately needs neither the HSM nor a fresh
// signature: an operator can prove artifact integrity during an HSM outage.
//
// The key provider is constructed lazily (only when publishing), passed in via
// newProvider, so -verify works with the token absent or locked.
func cmdPublish(db *database.DB, cfg *config.Config, newProvider func() (keyprovider.Provider, error), args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cas := fs.String("ca", "", "comma-separated CA ids or labels to publish (default: config publish.cas, else all X.509 CAs)")
	outDir := fs.String("out", "", "publish to this directory (overrides the configured backend)")
	skipOCSP := fs.Bool("skip-ocsp", false, "publish only CRLs/chains, no pre-signed OCSP responses")
	validity := fs.Duration("ocsp-validity", 0, "pre-signed OCSP response validity (default from config, else 24h)")
	verify := fs.Bool("verify", false, "verify the currently published snapshot against its manifest (no HSM needed)")
	quiet := fs.Bool("quiet", false, "suppress the per-CA summary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub := cfg.Publish
	if *outDir != "" {
		pub.Dir.Path = *outDir
		pub.S3.Bucket = "" // an explicit -out always selects the directory backend
	}
	store, err := newPublishStore(pub)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if *verify {
		manifest, err := publish.Verify(ctx, store)
		if err != nil {
			return fmt.Errorf("snapshot verification FAILED: %w", err)
		}
		fmt.Printf("snapshot OK: %d artifacts across %d CAs (generated %s",
			len(manifest.Artifacts), len(manifest.CAs), manifest.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
		if manifest.EarliestExpiry != nil {
			fmt.Printf(", earliest artifact expiry %s", manifest.EarliestExpiry.Format("2006-01-02 15:04:05 UTC"))
		}
		fmt.Println(")")
		return nil
	}

	provider, err := newProvider()
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	mgr := ca.NewManager(db, provider)
	includeOCSP := pub.IncludeOCSPEnabled() && !*skipOCSP
	var presigner *ca.OCSPPresigner
	if includeOCSP {
		v := *validity
		if v <= 0 {
			v = cfg.Server.OCSP.Presign.Validity()
		}
		presigner = ca.NewOCSPPresigner(mgr, ca.OCSPPresignerConfig{
			Validity:     v,
			ExpiredGrace: cfg.Server.OCSP.Presign.ExpiredGrace(),
		})
	}

	caIDs := pub.CAs
	if *cas != "" {
		caIDs = splitComma(*cas)
	}
	artifacts, caInfos, err := publish.BuildSnapshot(ctx, publish.SnapshotSource{
		Mgr: mgr, DB: db, Presigner: presigner,
	}, publish.SnapshotOptions{
		CAIDs:       caIDs,
		IncludeOCSP: includeOCSP,
		FreshOCSP:   true,
	})
	if err != nil {
		return err
	}

	manifest, err := publish.NewPublisher(store).Publish(ctx, caInfos, artifacts)
	if err != nil {
		return err
	}

	if !*quiet {
		for _, c := range caInfos {
			fmt.Printf("  %-36s  %-20s  ocsp=%d  shards=%d\n", c.ID, c.Label, c.OCSPResponses, c.CRLShards)
		}
	}
	target := pub.Dir.Path
	if pub.Backend() == "s3" {
		target = "s3://" + pub.S3.Bucket + "/" + strings.Trim(pub.S3.Prefix, "/")
	}
	fmt.Printf("published %d artifacts for %d CAs to %s (%s backend)\n",
		len(manifest.Artifacts), len(caInfos), target, store.Name())
	return nil
}

// newPublishStore constructs the configured publish backend, defaulting to a
// directory under the working directory when nothing is configured so the
// one-shot CLI is usable without a publish: block.
func newPublishStore(pub config.PublishConfig) (publish.Store, error) {
	if pub.Backend() == "s3" {
		return publish.NewS3Store(context.Background(), publish.S3Config{
			Endpoint:        pub.S3.Endpoint,
			Region:          pub.S3.Region,
			Bucket:          pub.S3.Bucket,
			Prefix:          pub.S3.Prefix,
			AccessKeyID:     pub.S3.AccessKeyID,
			SecretAccessKey: pub.S3.SecretAccessKey,
			SessionToken:    pub.S3.SessionToken,
			ForcePathStyle:  pub.S3.ForcePathStyle,
			Concurrency:     pub.S3.Concurrency,
		})
	}
	path := pub.Dir.Path
	if path == "" {
		path = "publish"
		fmt.Fprintf(os.Stderr, "no publish backend configured; publishing to ./%s\n", path)
	}
	return publish.NewDirStore(path, pub.Dir.KeepSnapshots)
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
