package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/discovery"
)

// cmdDiscover scans external TLS endpoints for their served certificates, records
// the leaf details into the discovered-certificate inventory, and flags expiring,
// weak, SHA-1-signed, self-signed, hostname-mismatched, and rogue (not-issued-by-
// this-PKI) certificates. It performs no HSM operations: it is a TLS client plus
// X.509 analysis, cross-referenced against this deployment's own CA certificates.
func cmdDiscover(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	targets := fs.String("targets", "", "comma-separated host[:port][#sni] endpoints to scan")
	hostsFile := fs.String("hosts-file", "", "file of endpoints, one host[:port][#sni] per line ('#' comments)")
	cidrs := fs.String("cidr", "", "comma-separated CIDR ranges to expand into targets (default port)")
	port := fs.Int("port", 0, "default port for targets without one (default from config, else 443)")
	expiryDays := fs.Int("expiry-days", 0, "flag certificates expiring within this many days (default from config, else 30)")
	timeout := fs.Duration("timeout", 0, "per-endpoint dial timeout (default 8s)")
	concurrency := fs.Int("concurrency", 0, "max parallel endpoint dials (default 16)")
	tenant := fs.String("tenant", "", "tenant to record findings under (default: built-in tenant)")
	store := fs.Bool("store", false, "record findings into the discovered-certificate inventory")
	notify := fs.Bool("notify", false, "dispatch flagged findings through the monitor notification sinks")
	rogueOnly := fs.Bool("rogue-only", false, "exit non-zero if any rogue (not-issued-by-this-PKI) certificate is found")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	// Merge CLI targets with the configured discovery targets so an operator can
	// scan either an ad-hoc list or the deployment's declared endpoints.
	spec := discovery.TargetSpec{
		HostsFile:   *hostsFile,
		DefaultPort: *port,
	}
	spec.Endpoints = append(spec.Endpoints, splitList(*targets)...)
	spec.CIDRs = append(spec.CIDRs, splitList(*cidrs)...)
	if len(spec.Endpoints) == 0 && spec.HostsFile == "" && len(spec.CIDRs) == 0 {
		// Fall back to the configured discovery targets.
		spec.Endpoints = append(spec.Endpoints, cfg.Discovery.Targets...)
		spec.CIDRs = append(spec.CIDRs, cfg.Discovery.CIDRs...)
		if spec.HostsFile == "" {
			spec.HostsFile = cfg.Discovery.HostsFile
		}
		if spec.DefaultPort == 0 {
			spec.DefaultPort = cfg.Discovery.DefaultPort
		}
	}

	parsed, err := discovery.ParseTargets(spec)
	if err != nil {
		return fmt.Errorf("parsing targets: %w", err)
	}
	if len(parsed) == 0 {
		fs.Usage()
		return fmt.Errorf("no targets given: use -targets, -hosts-file, -cidr, or configure discovery.targets")
	}

	days := *expiryDays
	if days == 0 {
		days = cfg.Discovery.ExpiryDays
	}
	runner := discovery.NewRunner(db, cfg.Monitor, days, nil)
	if *timeout > 0 {
		runner.WithDialTimeout(*timeout)
	}
	if *concurrency > 0 {
		runner.WithConcurrency(*concurrency)
	}
	if *tenant != "" {
		runner.WithTenant(*tenant)
	}

	fmt.Fprintf(os.Stderr, "Scanning %d endpoint(s)…\n", len(parsed))
	res, err := runner.Scan(context.Background(), parsed, *store, *notify)
	if err != nil {
		return fmt.Errorf("discovery scan: %w", err)
	}

	if asJSON {
		if err := cliout.Emit(res.Report); err != nil {
			return err
		}
	} else {
		res.Report.WriteText(os.Stdout)
	}

	if *store {
		fmt.Fprintf(os.Stderr, "Recorded %d certificate(s) into the inventory.\n", res.Stored)
	}

	if *rogueOnly && res.Report.Counts.Rogue > 0 {
		return fmt.Errorf("discovery: %d rogue certificate(s) found (not issued by this PKI)", res.Report.Counts.Rogue)
	}
	return nil
}

// splitList splits a comma-separated flag value into trimmed, non-empty items.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
