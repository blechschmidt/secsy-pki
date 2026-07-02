package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/siem"
)

// cmdAudit dispatches the "audit" subcommands.
func cmdAudit(db *database.DB, args []string) error {
	if len(args) == 0 {
		auditUsage()
		return fmt.Errorf("audit: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "verify":
		return cmdAuditVerify(db, rest)
	case "export":
		return cmdAuditExport(db, rest)
	case "help", "-h", "--help":
		auditUsage()
		return nil
	default:
		auditUsage()
		return fmt.Errorf("audit: unknown subcommand %q", sub)
	}
}

func auditUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca audit — tamper-evident audit log tools

Usage:
  secsy-ca audit verify [-json]
      Re-walk the audit hash chain end-to-end and report the first broken link.
      Exit status is non-zero if the chain is broken (tamper detected).

  secsy-ca audit export [-from RFC3339] [-to RFC3339] [-format rfc5424|cef|json] [-out FILE]
      Export audit events over a time range for offline batch delivery to a SIEM.
      Records are written one per line in the chosen format (default json).
`)
}

// cmdAuditVerify re-walks the full hash chain and reports the first broken link.
func cmdAuditVerify(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the verification result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := db.VerifyEventChain()
	if err != nil {
		return fmt.Errorf("verifying audit chain: %w", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else if res.Valid {
		fmt.Printf("audit chain OK: %d event(s) verified, hash chain intact.\n", res.Count)
	} else {
		fmt.Printf("audit chain BROKEN at seq %d: %s\n", res.BrokenAtSeq, res.Reason)
		fmt.Printf("verified %d event(s) before the break.\n", res.Count)
	}

	if !res.Valid {
		// A broken chain is an operational alarm; signal it via a non-zero exit so
		// scripts and cron jobs can trip on it.
		return fmt.Errorf("audit chain verification failed at seq %d", res.BrokenAtSeq)
	}
	return nil
}

// cmdAuditExport writes audit events over a time range in the chosen format for
// offline delivery to a SIEM (e.g. a scheduled batch job or an air-gapped
// transfer). It reuses the same formatters as the streaming exporter.
func cmdAuditExport(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	fromStr := fs.String("from", "", "start of the range (RFC3339, inclusive); empty = from the beginning")
	toStr := fs.String("to", "", "end of the range (RFC3339, exclusive); empty = up to now")
	format := fs.String("format", "json", "record format: rfc5424, cef, or json")
	out := fs.String("out", "", "write to this file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var from, to time.Time
	var err error
	if *fromStr != "" {
		if from, err = time.Parse(time.RFC3339, *fromStr); err != nil {
			return fmt.Errorf("parsing -from: %w", err)
		}
	}
	if *toStr != "" {
		if to, err = time.Parse(time.RFC3339, *toStr); err != nil {
			return fmt.Errorf("parsing -to: %w", err)
		}
	}
	if !from.IsZero() && !to.IsZero() && !to.After(from) {
		return fmt.Errorf("-to (%s) must be after -from (%s)", to, from)
	}

	formatter, err := siem.NewFormatter(siem.Format(*format), siem.FormatterOptions{})
	if err != nil {
		return err
	}

	events, err := db.ListEventsByTimeRange(from, to)
	if err != nil {
		return fmt.Errorf("loading events: %w", err)
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("opening -out: %w", err)
		}
		defer f.Close()
		w = f
	}

	for i := range events {
		if _, err := w.Write(formatter.Format(events[i])); err != nil {
			return err
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Exported %d audit event(s) in %s format.\n", len(events), formatter.Name())
	return nil
}
