package main

import (
	"fmt"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/ers"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// setupErs wires the RFC 4998 Evidence-Record preservation job (Task 161) onto
// the leader elector when ers.enabled is set. It reuses the internal TSA (or an
// external URL) for archive timestamps, exactly like audit anchoring, so exactly
// one replica preserves and renews at a time. A misconfiguration fails fast at
// startup rather than silently disabling long-term preservation.
func setupErs(cfg *config.Config, db *database.DB, tsaAuthority *tsa.Authority, elector *leader.Elector) {
	if !cfg.Ers.Enabled {
		return
	}
	ts, err := buildErsTimestamper(cfg, tsaAuthority)
	if err != nil {
		log.Fatalf("Evidence-record configuration error: %v", err)
	}
	hash := ers.HashByName(cfg.Ers.ResolvedHash())
	if hash == 0 {
		log.Fatalf("Evidence-record configuration error: unsupported ers.hash %q", cfg.Ers.Hash)
	}
	svc := ers.NewService(db, ts, ers.Options{
		Hash:             hash,
		RenewalLookahead: cfg.Ers.RenewalLookahead(),
		Batch:            cfg.Ers.Batch(),
		Logf:             log.Printf,
	})
	runner := ers.NewRunner(svc, cfg.Ers.Interval(), cfg.Ers.PreserveAuditEnabled(), log.Default())
	log.Printf("Evidence-record preservation enabled (RFC 4998; interval %s, hash %s, lookahead %s, preserve_audit %t, tsa %s)",
		cfg.Ers.Interval(), cfg.Ers.ResolvedHash(), cfg.Ers.RenewalLookahead(), cfg.Ers.PreserveAuditEnabled(), ersTSASource(cfg))
	elector.Register("ers", runner.Run)
}

// buildErsTimestamper selects the archive-timestamp source: the external TSA URL
// when configured, else the in-process authority. Config validation already
// requires one of the two.
func buildErsTimestamper(cfg *config.Config, authority *tsa.Authority) (ers.Timestamper, error) {
	if url := cfg.Ers.TSAURL; url != "" {
		return ers.NewHTTPTimestamper(url, time.Duration(cfg.Ers.TimeoutSeconds)*time.Second), nil
	}
	if authority == nil {
		return nil, fmt.Errorf("ers.enabled requires the internal TSA (tsa.enabled: true) or ers.tsa_url")
	}
	return ers.NewAuthorityTimestamper(authority), nil
}

// ersTSASource renders the timestamp source for the startup log.
func ersTSASource(cfg *config.Config) string {
	if cfg.Ers.TSAURL != "" {
		return cfg.Ers.TSAURL
	}
	return "internal"
}
