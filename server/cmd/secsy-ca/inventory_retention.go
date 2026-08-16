package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/retention"
)

// `secsy-ca inventory retention <run|dry-run|status>` — operate the
// certificate-inventory retention/archival job (Task 157) from the CLI. It reads
// and writes only the store and never touches the HSM, so it is dispatched before
// the key provider is built and works during an HSM outage.
//
// The subcommands share the same fail-safe engine the leader-elected background
// loop uses, so a run started here obeys the identical policy: only long-expired,
// terminal, non-held, non-approval-pinned rows are eligible, and the authoritative
// revoked_certificates table is never touched (OCSP/CRL for retained serials is
// unaffected). This file is deliberately cliout-free.

func inventoryRetentionUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca inventory retention — certificate-inventory retention/archival (Task 157)

Usage:
  secsy-ca inventory retention status [-json]
      Report the current policy (mode, grace window) and how many rows are
      eligible to archive / prune right now, plus the newest recorded run.

  secsy-ca inventory retention dry-run [-json]
      Report exactly what a run would archive/prune (counts + manifest digest)
      WITHOUT mutating anything.

  secsy-ca inventory retention run [-json]
      Execute one retention pass: move long-expired terminal rows into
      issued_certificates_archive (archive mode) and, in prune mode, hard-delete
      archive rows past the prune window. Records an inventory.retention audit
      event. Exits non-zero on failure.

Policy is taken from the config's retention block (mode, min_age_days,
prune_after_days, batch_size). A still-valid, revoked-but-not-yet-expired, held,
or open-approval-pinned certificate is NEVER eligible.
`)
}

// cmdInventoryRetention dispatches the retention subcommands. It is invoked from
// main for `inventory retention ...` before the key provider is built.
func cmdInventoryRetention(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		inventoryRetentionUsage()
		return fmt.Errorf("inventory retention: no subcommand given (want run|dry-run|status)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "run":
		return cmdInventoryRetentionRun(db, cfg, rest)
	case "dry-run", "dryrun", "plan":
		return cmdInventoryRetentionDryRun(db, cfg, rest)
	case "status":
		return cmdInventoryRetentionStatus(db, cfg, rest)
	case "help", "-h", "--help":
		inventoryRetentionUsage()
		return nil
	default:
		inventoryRetentionUsage()
		return fmt.Errorf("inventory retention: unknown subcommand %q", sub)
	}
}

// quietRunner builds a retention Runner whose internal logging is discarded, so
// only the CLI's own output reaches the operator.
func quietRunner(db *database.DB, cfg *config.Config) (*retention.Runner, error) {
	return retention.New(db, cfg.Retention, log.New(io.Discard, "", 0))
}

func cmdInventoryRetentionRun(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("inventory retention run", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runner, err := quietRunner(db, cfg)
	if err != nil {
		return err
	}
	res, runErr := runner.RunNow(context.Background())
	if *asJSON {
		if emitErr := emitJSON(res); emitErr != nil {
			return emitErr
		}
	} else {
		printRetentionResult(res)
	}
	if runErr != nil {
		return fmt.Errorf("retention run failed: %w", runErr)
	}
	return nil
}

func cmdInventoryRetentionDryRun(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("inventory retention dry-run", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the projected result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runner, err := quietRunner(db, cfg)
	if err != nil {
		return err
	}
	res, err := runner.Plan(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(res)
	}
	printRetentionResult(res)
	return nil
}

func cmdInventoryRetentionStatus(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("inventory retention status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the status as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runner, err := quietRunner(db, cfg)
	if err != nil {
		return err
	}
	snap, err := runner.Snapshot(context.Background())
	if err != nil {
		return err
	}
	// The newest recorded run comes from the audit log — the same offline source
	// of truth doctor's retention.freshness check uses.
	var last *audit.Event
	if events, _, lerr := db.ListEvents(audit.ActionInventoryRetention, "", "", 1, 0); lerr == nil && len(events) > 0 {
		last = &events[0]
	}

	if *asJSON {
		return emitJSON(struct {
			Enabled  bool   `json:"enabled"`
			Interval string `json:"interval"`
			retention.Snapshot
			LastRun *audit.Event `json:"last_run,omitempty"`
		}{
			Enabled:  cfg.Retention.Enabled,
			Interval: cfg.Retention.Interval().String(),
			Snapshot: snap,
			LastRun:  last,
		})
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Enabled:\t%t\n", cfg.Retention.Enabled)
	fmt.Fprintf(tw, "Mode:\t%s\n", snap.Mode)
	fmt.Fprintf(tw, "Interval:\t%s\n", cfg.Retention.Interval())
	fmt.Fprintf(tw, "Grace window:\t%s\n", snap.Window)
	fmt.Fprintf(tw, "Eligible now:\t%d\n", snap.Eligible)
	if snap.Mode == config.RetentionModePrune {
		fmt.Fprintf(tw, "Prunable now:\t%d\n", snap.Prunable)
	}
	fmt.Fprintf(tw, "Archive size:\t%d\n", snap.ArchiveSize)
	if last != nil {
		fmt.Fprintf(tw, "Last run:\t%s ago (%s) — %s\n",
			time.Since(last.Timestamp).Round(time.Second), last.Result, last.Detail)
	} else {
		fmt.Fprintf(tw, "Last run:\t(none recorded)\n")
	}
	if !cfg.Retention.Enabled {
		fmt.Fprintln(tw, "\nNote: the background retention loop is DISABLED (retention.enabled is false).")
		fmt.Fprintln(tw, "You can still run it on demand with `secsy-ca inventory retention run`.")
	}
	return tw.Flush()
}

// printRetentionResult renders a retention Result as a human-readable summary.
func printRetentionResult(res retention.Result) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	verb := "Archived"
	if res.DryRun {
		verb = "Would archive"
		fmt.Fprintln(tw, "DRY RUN — no rows were modified.")
	}
	fmt.Fprintf(tw, "Mode:\t%s\n", res.Mode)
	fmt.Fprintf(tw, "Grace window:\t%s (eligible: not_after before %s)\n", res.Window, res.Cutoff.Format(time.RFC3339))
	fmt.Fprintf(tw, "Eligible:\t%d\n", res.Eligible)
	fmt.Fprintf(tw, "%s:\t%d\n", verb, res.Archived)
	if res.Mode == config.RetentionModePrune {
		pverb := "Pruned"
		if res.DryRun {
			pverb = "Would prune"
		}
		fmt.Fprintf(tw, "%s (hard-deleted):\t%d\n", pverb, res.Pruned)
	}
	if res.ProtectedByApprovals > 0 {
		fmt.Fprintf(tw, "Protected by open approvals:\t%d\n", res.ProtectedByApprovals)
	}
	fmt.Fprintf(tw, "Backlog remaining:\t%d\n", res.Backlog)
	fmt.Fprintf(tw, "Archive size:\t%d\n", res.ArchiveSize)
	fmt.Fprintf(tw, "Manifest digest:\t%s\n", res.Digest)
	_ = tw.Flush()
}

// emitJSON writes v as indented JSON to stdout. Kept local so this command does
// not depend on the (uncommitted) cliout WIP.
func emitJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
