package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// cmdRevokeBulk is the incident-response mass-revocation command (Task 70).
// It plans a revocation over the CA's inventory (plus an optional explicit
// serial list), previews it as a dry run, and — only with the dry-run count
// confirmed — applies it in batches, regenerates the base+delta CRLs once at
// the end, and appends per-certificate audit events plus a summary event.
//
// An interrupted run is resumed by re-running the same command: the selection
// only ever covers not-yet-revoked certificates. See docs/incident-response.md
// for the full key-compromise runbook.
func cmdRevokeBulk(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("revoke-bulk", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	profile := fs.String("profile", "", "only certificates issued under this profile")
	pattern := fs.String("pattern", "", "case-insensitive glob matched against CN and SANs (e.g. '*.corp.example.com')")
	issuedAfter := fs.String("issued-after", "", "only certificates with NotBefore at/after this time (RFC 3339 or YYYY-MM-DD)")
	issuedBefore := fs.String("issued-before", "", "only certificates with NotBefore at/before this time (RFC 3339 or YYYY-MM-DD)")
	serialsFile := fs.String("serials-file", "", "file with one serial per line ('#' comments allowed); unknown serials are revoked as bare CRL entries")
	serialFormat := fs.String("serial-format", "decimal", "how to read -serials-file entries: decimal|hex (a 0x prefix always means hex)")
	reason := fs.String("reason", "keyCompromise", "RFC 5280 reason applied to every certificate")
	includeExpired := fs.Bool("include-expired", false, "also revoke certificates already past their NotAfter")
	batchSize := fs.Int("batch-size", ca.DefaultBulkRevokeBatchSize, "certificates revoked per store transaction")
	dryRun := fs.Bool("dry-run", false, "compute and print the plan without revoking anything")
	confirm := fs.Int("confirm", -1, "execute, requiring the selection to still count exactly this many certificates (the dry-run total)")
	force := fs.Bool("force", false, "execute without the count confirmation (emergency use when concurrent issuance keeps shifting the count)")
	opID := fs.String("operation-id", "", "operation id correlating audit events across resumed runs (default: generated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	filter := ca.BulkRevokeFilter{
		Profile:        *profile,
		Pattern:        *pattern,
		IncludeExpired: *includeExpired,
	}
	if filter.IssuedAfter, err = parseBulkTime(*issuedAfter, false); err != nil {
		return fmt.Errorf("-issued-after: %w", err)
	}
	if filter.IssuedBefore, err = parseBulkTime(*issuedBefore, true); err != nil {
		return fmt.Errorf("-issued-before: %w", err)
	}
	if *serialsFile != "" {
		if filter.Serials, err = readSerialsFile(*serialsFile, *serialFormat); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Read %d serial(s) from %s.\n", len(filter.Serials), *serialsFile)
	}

	spec := ca.BulkRevokeSpec{
		CAID:         caID,
		Filter:       filter,
		Reason:       *reason,
		RequestedBy:  "secsy-ca-cli",
		OperationID:  *opID,
		BatchSize:    *batchSize,
		ConfirmCount: *confirm,
		Progress: func(revoked, total int) {
			fmt.Fprintf(os.Stderr, "  revoked %d/%d...\n", revoked, total)
		},
	}
	revoker := ca.NewBulkRevoker(mgr, ca.BulkRevokerConfig{})

	// Preview first in every mode: the plan is what the operator confirms, and
	// even a confirmed run benefits from seeing it before batches start.
	plan, err := revoker.Preview(context.Background(), spec)
	if err != nil {
		return err
	}
	printBulkPlan(plan)

	execute := *force || *confirm >= 0
	if *dryRun || !execute {
		if !*dryRun {
			fmt.Fprintf(os.Stderr, "\nDRY RUN — nothing was revoked. To execute, re-run with -confirm %d (or -force).\n", plan.Total)
		} else {
			fmt.Fprintln(os.Stderr, "\nDRY RUN — nothing was revoked.")
		}
		return nil
	}
	if *force {
		spec.ConfirmCount = -1
	}
	// Reuse the previewed operation id so a generated id still ties the
	// per-certificate events to the summary of this very invocation.
	spec.OperationID = plan.OperationID

	if plan.Total == 0 {
		fmt.Fprintln(os.Stderr, "Nothing to revoke; selection is empty (already fully revoked?).")
	}

	fmt.Fprintf(os.Stderr, "\nExecuting bulk revocation (operation %s)...\n", plan.OperationID)
	result, err := revoker.Execute(context.Background(), spec)
	if result != nil {
		fmt.Fprintf(os.Stderr,
			"\nBulk revocation %s:\n  revoked:          %d (planned %d, %d already revoked by a concurrent operation)\n  batches:          %d\n  CRLs regenerated: %s\n  duration:         %s\n",
			resultWord(err), result.Revoked, result.Planned, result.AlreadySkipped,
			result.Batches, strings.Join(result.CRLScopes, ", "), result.Duration.Round(time.Millisecond))
		if result.PresignError != "" {
			fmt.Fprintf(os.Stderr, "  presign refresh:  FAILED (%s)\n", result.PresignError)
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nVerify propagation: secsy-ca gen-crl -ca %s | openssl crl -noout -text\n", *caRef)
	return nil
}

func resultWord(err error) string {
	if err != nil {
		return "INCOMPLETE"
	}
	return "complete"
}

// printBulkPlan renders a dry-run plan for the operator.
func printBulkPlan(p *ca.BulkRevokePlan) {
	fmt.Printf("Bulk revocation plan for CA %s (%s)\n", p.CALabel, p.CAID)
	fmt.Printf("  operation id:      %s\n", p.OperationID)
	fmt.Printf("  reason:            %s\n", p.Reason)
	fmt.Printf("  filter:            %s\n", p.Filter)
	fmt.Printf("  WILL REVOKE:       %d certificate(s)\n", p.Total)
	fmt.Printf("    from inventory:  %d\n", p.Known)
	if p.Unknown > 0 {
		fmt.Printf("    unknown serials: %d (not in inventory; revoked as bare CRL entries)\n", p.Unknown)
	}
	if p.AlreadyRevoked > 0 {
		fmt.Printf("  already revoked:   %d (skipped — resuming an earlier run?)\n", p.AlreadyRevoked)
	}
	if p.FilteredOut > 0 {
		fmt.Printf("  filtered out:      %d (listed serials excluded by the other filters)\n", p.FilteredOut)
	}
	if p.ExpiredExcluded > 0 {
		fmt.Printf("  expired excluded:  %d (pass -include-expired to revoke them too)\n", p.ExpiredExcluded)
	}
	if len(p.Sample) > 0 {
		fmt.Println("  sample:")
		for _, s := range p.Sample {
			if s.Known {
				fmt.Printf("    %s  %s  (%s, expires %s)\n", s.Serial, s.CommonName, s.Profile, s.NotAfter.Format("2006-01-02"))
			} else {
				fmt.Printf("    %s  <not in inventory>\n", s.Serial)
			}
		}
		if p.Total > len(p.Sample) {
			fmt.Printf("    ... and %d more\n", p.Total-len(p.Sample))
		}
	}
}

// parseBulkTime parses an -issued-after/-issued-before value: RFC 3339, or a
// bare date which means start-of-day (after) / end-of-day (before) UTC.
func parseBulkTime(s string, endOfDay bool) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, fmt.Errorf("%q is neither RFC 3339 nor YYYY-MM-DD", s)
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return &t, nil
}

// readSerialsFile loads one serial per line, tolerating '#' comments, blank
// lines, and openssl-style colon-separated hex. format selects how digits-only
// entries are interpreted; a 0x/0X prefix always forces hex. Every serial is
// canonicalized to the decimal string form the store uses.
func readSerialsFile(path, format string) ([]string, error) {
	switch format {
	case "decimal", "hex":
	default:
		return nil, fmt.Errorf("-serial-format must be decimal or hex (got %q)", format)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading serials file: %w", err)
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		serial, err := parseSerial(line, format)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		out = append(out, serial)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading serials file: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("serials file %s contains no serials", path)
	}
	return out, nil
}

// parseSerial canonicalizes one serial entry to its decimal string form.
func parseSerial(s, format string) (string, error) {
	base := 10
	if format == "hex" {
		base = 16
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	if base == 16 {
		// openssl prints serials as colon-separated hex bytes.
		s = strings.ReplaceAll(s, ":", "")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok || n.Sign() < 0 {
		return "", fmt.Errorf("invalid serial %q (base %d)", s, base)
	}
	return n.String(), nil
}
