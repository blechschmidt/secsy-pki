package main

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// setupOCSPPresign wires the background OCSP pre-signing loop (Task 58): every
// refresh interval it batch-signs a response for all known serials of every CA
// and fills the shared response cache, so the public OCSP endpoint serves from
// memory without touching the HSM — and keeps serving through an HSM outage
// for as long as the responses remain valid. Returns the presigner for the
// publisher to reuse (nil when disabled).
func setupOCSPPresign(cfg *config.Config, db *database.DB, provider keyprovider.Provider, api *handlers.API) *ca.OCSPPresigner {
	pc := cfg.Server.OCSP.Presign
	if !pc.Enabled {
		return nil
	}

	presignCfg := ca.OCSPPresignerConfig{
		Validity:     pc.Validity(),
		ExpiredGrace: pc.ExpiredGrace(),
		Cache:        api.OCSPCache(),
		Delegated:    api.DelegatedResponderCache(),
	}
	if pc.TrackRecentlyQueried() {
		presignCfg.Recent = ca.NewRecentSerialTracker(pc.RecentCapacity)
		api.SetOCSPRecentTracker(presignCfg.Recent)
	}
	presigner := ca.NewOCSPPresigner(ca.NewManager(db, provider), presignCfg)

	refresh := pc.Refresh()
	log.Printf("OCSP pre-signing enabled (validity %s, refresh %s, delegated=%v, recent-tracking=%v)",
		pc.Validity(), refresh, presignCfg.Delegated != nil, presignCfg.Recent != nil)

	go func() {
		ctx := context.Background()
		runPresign := func() {
			stats, err := presigner.Run(ctx)
			if err != nil {
				// Previously pre-signed responses stay servable from the cache
				// until their own NextUpdate, so a failed batch degrades
				// gracefully; the staleness gauge is the operator's signal.
				log.Printf("WARNING: OCSP pre-signing batch failed (previous responses remain servable): %v", err)
				return
			}
			log.Printf("OCSP pre-signing batch complete: %d responses across %d CAs", stats.Signed, stats.CAs)
		}
		runPresign()
		ticker := time.NewTicker(refresh)
		defer ticker.Stop()
		for range ticker.C {
			runPresign()
		}
	}()
	return presigner
}

// setupPublish wires the background static-artifact publish loop (Task 58):
// every interval it snapshots the CRLs, delta CRLs, partition shards, issuer
// chains, and pre-signed OCSP responses and writes them to the configured
// directory or S3-compatible store with an atomic swap and integrity check.
func setupPublish(cfg *config.Config, db *database.DB, provider keyprovider.Provider, presigner *ca.OCSPPresigner) {
	pub := cfg.Publish
	if !pub.Enabled {
		return
	}

	store, err := newPublishStore(pub)
	if err != nil {
		log.Fatalf("Static artifact publishing configuration error: %v", err)
	}
	publisher := publish.NewPublisher(store)
	src := publish.SnapshotSource{
		Mgr:       ca.NewManager(db, provider),
		DB:        db,
		Presigner: presigner,
	}
	opts := publish.SnapshotOptions{
		CAIDs:       pub.CAs,
		IncludeOCSP: pub.IncludeOCSPEnabled() && presigner != nil,
	}
	interval := pub.Interval(cfg.Server.OCSP.Presign)
	log.Printf("Static artifact publishing enabled (backend %s, interval %s, ocsp=%v)",
		store.Name(), interval, opts.IncludeOCSP)

	go func() {
		ctx := context.Background()
		runPublish := func() {
			artifacts, cas, err := publish.BuildSnapshot(ctx, src, opts)
			if err != nil {
				log.Printf("WARNING: publish snapshot build failed (previous snapshot remains current): %v", err)
				return
			}
			manifest, err := publisher.Publish(ctx, cas, artifacts)
			if err != nil {
				log.Printf("WARNING: publish failed (previous snapshot remains current): %v", err)
				return
			}
			log.Printf("Published %d artifacts for %d CAs to %s", len(manifest.Artifacts), len(cas), store.Name())
		}
		// First publish waits for the initial presign batch to have something to
		// publish; a short delay keeps startup ordering simple without coupling
		// the two loops.
		if opts.IncludeOCSP {
			time.Sleep(5 * time.Second)
		}
		runPublish()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			runPublish()
		}
	}()
}

// newPublishStore constructs the configured publish backend.
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
	return publish.NewDirStore(pub.Dir.Path, pub.Dir.KeepSnapshots)
}
