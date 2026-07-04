package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/ctmonitor"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// cmdCT dispatches the Certificate Transparency inclusion-monitoring subcommands
// (Task 93). All are HSM-free: they read/write the store and talk to CT logs
// over HTTP, verifying inclusion with the logs' public keys.
func cmdCT(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-ca ct <verify-inclusion|inclusion-status> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "verify-inclusion":
		return cmdCTVerifyInclusion(db, cfg, rest)
	case "inclusion-status", "status":
		return cmdCTInclusionStatus(db, cfg, rest)
	default:
		return fmt.Errorf("unknown ct subcommand %q (want verify-inclusion|inclusion-status)", sub)
	}
}

// cmdCTVerifyInclusion runs one inclusion-verification scan on demand: for every
// issued certificate whose embedded SCTs are past their log's Maximum Merge
// Delay, it fetches the log's signed tree head and inclusion proof, verifies the
// Merkle audit path, and records the per-SCT state — exactly what the background
// monitor does, but once, synchronously, with the result printed. It never
// dispatches alert notifications (the operator sees the result directly).
func cmdCTVerifyInclusion(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("ct verify-inclusion", flag.ContinueOnError)
	maxCerts := fs.Int("max", 0, "maximum certificates to check this run (0 = config/default)")
	asJSON := fs.Bool("json", false, "emit the scan result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	submitter, err := buildCTSubmitterFromConfig(cfg.CertificateTransparency)
	if err != nil {
		return err
	}
	if submitter == nil {
		return fmt.Errorf("no CT logs configured (certificate_transparency.logs); nothing to verify inclusion against")
	}

	imCfg := cfg.CertificateTransparency.InclusionMonitor
	if *maxCerts > 0 {
		imCfg.MaxCertsPerRun = *maxCerts
	}
	mon, err := ctmonitor.New(db, submitter, imCfg, nil, log.New(os.Stderr, "", 0))
	if err != nil {
		return err
	}

	res := mon.RunOnce(context.Background())
	if res.Err != nil {
		return res.Err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	fmt.Printf("CT inclusion scan complete (%s):\n", res.StartedAt.Format(time.RFC3339))
	fmt.Printf("  certificates examined: %d\n", res.Certs)
	fmt.Printf("  SCT checks:            %d\n", res.Checked)
	fmt.Printf("    included:    %d\n", res.Included)
	fmt.Printf("    pending:     %d\n", res.Pending)
	fmt.Printf("    failed:      %d\n", res.Failed)
	fmt.Printf("    unknown-log: %d\n", res.UnknownLog)
	fmt.Printf("    errors:      %d\n", res.Errors)
	if res.NewMisbehavior > 0 {
		fmt.Printf("\n  ⚠ %d NEW CT log-misbehavior event(s) detected (a log failed to honor an embedded SCT).\n", res.NewMisbehavior)
		fmt.Printf("    Run `secsy-ca ct inclusion-status -status failed` for details.\n")
		return fmt.Errorf("CT log misbehavior detected")
	}
	if res.Failed > 0 {
		return fmt.Errorf("%d SCT(s) remain in the failed state (CT log misbehavior)", res.Failed)
	}
	return nil
}

// cmdCTInclusionStatus prints the recorded SCT inclusion state from the store,
// either the whole set (optionally filtered by status) or the per-log rows of
// one certificate.
func cmdCTInclusionStatus(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("ct inclusion-status", flag.ContinueOnError)
	status := fs.String("status", "", "filter by status (included|pending|failed|unknown_log)")
	caRef := fs.String("ca", "", "restrict to a CA id or label (requires -serial)")
	serial := fs.String("serial", "", "restrict to one certificate serial (requires -ca)")
	limit := fs.Int("limit", 200, "maximum rows to list")
	asJSON := fs.Bool("json", false, "emit the rows as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	counts, err := db.CountSCTInclusionByStatus()
	if err != nil {
		return fmt.Errorf("reading inclusion counts: %w", err)
	}

	var rows []models.SCTInclusion
	switch {
	case *caRef != "" && *serial != "":
		caID, err := resolveCA(db, *caRef)
		if err != nil {
			return err
		}
		rows, err = db.ListSCTInclusionForCert(caID, *serial)
		if err != nil {
			return err
		}
	case *caRef != "" || *serial != "":
		return fmt.Errorf("-ca and -serial must be given together")
	default:
		rows, err = db.ListSCTInclusionByStatus(*status, *limit)
		if err != nil {
			return err
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"counts": counts, "rows": rows})
	}

	total := 0
	for _, n := range counts {
		total += n
	}
	fmt.Printf("CT SCT inclusion state — %d total: included=%d pending=%d failed=%d unknown_log=%d\n\n",
		total, counts[models.SCTInclusionIncluded], counts[models.SCTInclusionPending],
		counts[models.SCTInclusionFailed], counts[models.SCTInclusionUnknownLog])

	if len(rows) == 0 {
		fmt.Println("No inclusion rows match.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCA\tSERIAL\tLOG\tSCT TIME\tTREE SIZE\tLEAF\tLAST CHECK\tDETAIL")
	for _, r := range rows {
		last := "-"
		if r.LastCheckedAt != nil {
			last = r.LastCheckedAt.Format("2006-01-02 15:04")
		}
		logName := r.LogName
		if logName == "" {
			logName = r.LogID[:min(12, len(r.LogID))]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			r.Status, r.CAID, r.Serial, logName, r.SCTTimestamp.Format("2006-01-02"),
			r.TreeSize, r.LeafIndex, last, truncateDetail(r.LastError))
	}
	return tw.Flush()
}

// buildCTSubmitterFromConfig constructs a ct.Submitter from the configured logs,
// mirroring the server's builder. It returns (nil, nil) when no logs are
// configured.
func buildCTSubmitterFromConfig(cfg config.CTConfig) (*ct.Submitter, error) {
	if len(cfg.Logs) == 0 {
		return nil, nil
	}
	logs := make([]ct.LogConfig, 0, len(cfg.Logs))
	for _, l := range cfg.Logs {
		pubPEM := l.PublicKey
		if pubPEM == "" && l.PublicKeyFile != "" {
			data, err := os.ReadFile(l.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("reading public_key_file for CT log %q: %w", l.Name, err)
			}
			pubPEM = string(data)
		}
		logs = append(logs, ct.LogConfig{Name: l.Name, URL: l.URL, PublicKeyPEM: pubPEM, MMD: l.MMD()})
	}
	return ct.NewSubmitter(logs, &http.Client{Timeout: 30 * time.Second})
}

// truncateDetail shortens a detail string for tabular display.
func truncateDetail(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
