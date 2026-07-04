package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
)

// cmdDoctor runs the read-only preflight diagnostic suite and renders the
// report as a human table or JSON. It is dispatched before the config is
// loaded so a broken config file is itself a reported finding rather than a
// hard CLI error.
//
// Exit codes (CI-friendly, see docs/RUNBOOK.md):
//
//	0  every check passed (or was skipped)
//	1  at least one check failed
//	2  no failures, but at least one warning
func cmdDoctor(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	deep := fs.Bool("deep", false, "additionally run the full store-integrity gate (walks the entire audit chain; same as \"secsy-ca db verify\")")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time budget for the run")
	expiryWarnDays := fs.Int("expiry-warn-days", 30, "warn when a certificate expires within this many days")
	expiryFailDays := fs.Int("expiry-fail-days", 7, "fail when a certificate expires within this many days")
	auditSample := fs.Int("audit-sample", 1000, "number of newest audit events to re-verify")
	noListener := fs.Bool("no-listener", false, "skip the live TLS probe of the configured listener address")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ca [-config config.yaml] doctor [flags]")
		fmt.Fprintln(os.Stderr, "\nRuns read-only preflight diagnostics: config, HSM/KMS reachability, key")
		fmt.Fprintln(os.Stderr, "self-tests, HA token health, database + pending migrations, audit chain,")
		fmt.Fprintln(os.Stderr, "certificate expiry, CRL freshness, clock skew, and listener TLS.")
		fmt.Fprintln(os.Stderr, "\nExit codes: 0 = pass, 1 = failure(s), 2 = warning(s) only.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := doctor.Run(ctx, doctor.Options{
		ConfigPath:      cfgPath,
		BuildProvider:   buildProvider,
		BuildPinSources: buildPinSources,
		ExpiryWarn:      time.Duration(*expiryWarnDays) * 24 * time.Hour,
		ExpiryFail:      time.Duration(*expiryFailDays) * 24 * time.Hour,
		AuditSample:     *auditSample,
		SkipListener:    *noListener,
		Deep:            *deep,
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printDoctorReport(report)
	}

	// doctor.Run has released every resource it opened, so exiting directly is
	// safe and gives CI the documented tri-state code.
	if code := report.ExitCode(); code != doctor.ExitOK {
		os.Exit(code)
	}
	return nil
}

func printDoctorReport(r *doctor.Report) {
	fmt.Printf("secsy-ca doctor — %s (config %s)\n\n", r.CheckedAt.Format(time.RFC3339), r.ConfigPath)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", doctorMark(c.Status), c.Name, c.Detail)
	}
	_ = tw.Flush()

	s := r.Summary
	fmt.Printf("\n%d passed, %d warning%s, %d failed, %d skipped\n",
		s.Pass, s.Warn, pluralS(s.Warn), s.Fail, s.Skip)
	switch {
	case s.Fail > 0:
		fmt.Println("RESULT: FAIL — resolve the failures above before starting/serving.")
	case s.Warn > 0:
		fmt.Println("RESULT: WARN — operational, but the warnings above need attention.")
	default:
		fmt.Println("RESULT: OK")
	}
}

func doctorMark(s doctor.Status) string {
	switch s {
	case doctor.StatusPass:
		return "✓ pass"
	case doctor.StatusWarn:
		return "! warn"
	case doctor.StatusFail:
		return "✗ FAIL"
	default:
		return "- skip"
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
