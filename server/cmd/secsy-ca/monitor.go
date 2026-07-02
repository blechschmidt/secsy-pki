package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// monitorOptions resolves the expiry-monitor thresholds from the loaded config.
func monitorOptions(cfg *config.Config) monitor.Options {
	return monitor.OptionsFromDays(
		cfg.Monitor.WarningDays, cfg.Monitor.CriticalDays,
		cfg.Monitor.RenewBeforeDays, cfg.Monitor.RenewProfiles)
}

// cmdExpiring lists certificates by remaining validity. It performs a read-only
// scan (never auto-renews) using the configured warning/critical thresholds.
func cmdExpiring(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("expiring", flag.ContinueOnError)
	caRef := fs.String("ca", "", "restrict to a CA id or label (default: all CAs)")
	days := fs.Int("days", 0, "only show certs expiring within N days (0 = all)")
	severity := fs.String("severity", "", "only show certs at/above this severity (warning|critical|expired)")
	showSuperseded := fs.Bool("superseded", false, "include stale certs superseded by a newer reissue")
	asJSON := fs.Bool("json", false, "emit the full report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var minSeverity monitor.Severity
	if *severity != "" {
		s, err := monitor.ParseSeverity(*severity)
		if err != nil {
			return err
		}
		minSeverity = s
	}

	caID := ""
	if *caRef != "" {
		id, err := resolveCA(db, *caRef)
		if err != nil {
			return err
		}
		caID = id
	}

	m := monitor.New(db, nil, nil, monitorOptions(cfg))
	report, err := m.Scan(context.Background(), monitor.ScanRequest{CAID: caID})
	if err != nil {
		return err
	}

	cutoff := time.Duration(*days) * 24 * time.Hour
	var items []monitor.CertItem
	for _, it := range report.Items {
		if it.Superseded && !*showSuperseded {
			continue
		}
		if minSeverity != "" && !severityAtLeast(it.Severity, minSeverity) {
			continue
		}
		if *days > 0 && time.Duration(it.ExpiresInSeconds)*time.Second > cutoff {
			continue
		}
		items = append(items, it)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"generated_at":  report.GeneratedAt,
			"warning_days":  report.WarningDays,
			"critical_days": report.CriticalDays,
			"counts":        report.Counts,
			"certificates":  items,
		})
	}

	fmt.Printf("Expiry report (%s) — warning<=%dd, critical<=%dd\n",
		report.GeneratedAt.Format(time.RFC3339), report.WarningDays, report.CriticalDays)
	fmt.Printf("  ok=%d warning=%d critical=%d expired=%d\n\n",
		report.Counts[monitor.SeverityOK], report.Counts[monitor.SeverityWarning],
		report.Counts[monitor.SeverityCritical], report.Counts[monitor.SeverityExpired])

	if len(items) == 0 {
		fmt.Println("No certificates match.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tEXPIRES IN\tSERIAL\tCA\tPROFILE\tCOMMON NAME\tNOT AFTER")
	for _, it := range items {
		marker := ""
		if it.Superseded {
			marker = " (superseded)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s%s\t%s\n",
			it.Severity, it.ExpiresIn, it.Serial, it.CALabel, it.Profile,
			it.CommonName, marker, it.NotAfter.Format("2006-01-02"))
	}
	return tw.Flush()
}

// cmdMonitorRun performs a single expiry-monitor scan, optionally auto-renewing
// eligible certificates through the HSM-backed issuance path. It emits audit
// events and metrics exactly like the background monitor.
func cmdMonitorRun(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("monitor-run", flag.ContinueOnError)
	caRef := fs.String("ca", "", "restrict to a CA id or label (default: all CAs)")
	autoRenew := fs.Bool("auto-renew", false, "auto-renew eligible certificates before expiry")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caID := ""
	if *caRef != "" {
		id, err := resolveCA(db, *caRef)
		if err != nil {
			return err
		}
		caID = id
	}

	m := monitor.New(db, mgr, db, monitorOptions(cfg))
	report, err := m.Scan(context.Background(), monitor.ScanRequest{
		CAID:        caID,
		AutoRenew:   *autoRenew,
		RequestedBy: "secsy-ca-cli",
	})
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Printf("Scan complete (%s): ok=%d warning=%d critical=%d expired=%d\n",
		report.GeneratedAt.Format(time.RFC3339),
		report.Counts[monitor.SeverityOK], report.Counts[monitor.SeverityWarning],
		report.Counts[monitor.SeverityCritical], report.Counts[monitor.SeverityExpired])
	if *autoRenew {
		fmt.Printf("Auto-renew: %d renewed, %d failed\n", report.Renewed, report.RenewFailed)
		for _, it := range report.Items {
			if it.Renewed {
				fmt.Printf("  renewed %s -> %s (CN=%q)\n", it.Serial, it.NewSerial, it.CommonName)
			} else if it.RenewError != "" {
				fmt.Printf("  FAILED  %s (CN=%q): %s\n", it.Serial, it.CommonName, it.RenewError)
			}
		}
	}
	return nil
}

// severityAtLeast reports whether s is at least as urgent as min.
func severityAtLeast(s, min monitor.Severity) bool {
	rank := map[monitor.Severity]int{
		monitor.SeverityOK:       0,
		monitor.SeverityWarning:  1,
		monitor.SeverityCritical: 2,
		monitor.SeverityExpired:  3,
	}
	return rank[s] >= rank[min]
}
