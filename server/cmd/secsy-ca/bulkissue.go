package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// cmdIssueBulk is the mass device/service provisioning command (Task 101), the
// batch counterpart of `revoke-bulk`. It reads a manifest of certificate
// requests, previews the batch as a dry run, and — only with the count
// confirmed — issues every item under the CA's HSM key with bounded concurrency,
// writing each issued certificate to an output directory and printing a per-item
// result. Like `secsy-ca issue`, the CLI path calls ca.Manager directly and so
// bypasses the per-profile manual approval gate by construction; use the REST
// API when a require_approval profile must route through four-eyes approval.
//
// Manifest format (JSON array); csr paths are resolved relative to the manifest
// file's directory when not absolute:
//
//	[
//	  {"ref": "device-001", "csr": "csrs/device-001.pem", "profile": "server", "validity_days": 90},
//	  {"ref": "device-002", "csr": "csrs/device-002.pem", "profile": "server"}
//	]
func cmdIssueBulk(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("issue-bulk", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	manifest := fs.String("manifest", "", "path to a JSON manifest of {ref,csr,profile,validity_days} items, or '-' for stdin (required)")
	defaultProfile := fs.String("profile", "server", "profile applied to manifest items that do not set one")
	outDir := fs.String("out-dir", "", "directory to write each issued certificate PEM to (as <ref>.pem); omit to skip writing")
	chain := fs.Bool("chain", false, "write the full chain (leaf + issuer) instead of just the leaf")
	concurrency := fs.Int("concurrency", ca.DefaultBulkIssueConcurrency, "certificates issued in parallel (bounded server-side)")
	dryRun := fs.Bool("dry-run", false, "validate the manifest and print the plan without issuing anything")
	confirm := fs.Int("confirm", -1, "execute, requiring the manifest to contain exactly this many items")
	force := fs.Bool("force", false, "execute without the count confirmation")
	opID := fs.String("operation-id", "", "operation id correlating audit events (default: generated)")
	jsonOut := fs.Bool("json", false, "print the full result as JSON to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *manifest == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -manifest are required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	items, err := readIssueManifest(*manifest, *defaultProfile)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Read %d item(s) from %s.\n", len(items), *manifest)

	spec := ca.BulkIssueSpec{
		CAID:         caID,
		Items:        items,
		RequestedBy:  "secsy-ca-cli",
		OperationID:  *opID,
		Concurrency:  *concurrency,
		ConfirmCount: *confirm,
		Progress: func(done, total int) {
			fmt.Fprintf(os.Stderr, "  issued %d/%d...\n", done, total)
		},
	}
	issuer := ca.NewBulkIssuer(mgr, ca.BulkIssuerConfig{}) // nil gate: CLI bypasses manual approval

	// Preview first in every mode: the plan is what the operator confirms.
	plan, err := issuer.Preview(context.Background(), spec)
	if err != nil {
		return err
	}
	printIssueBulkPlan(plan)
	spec.OperationID = plan.OperationID

	execute := *force || *confirm >= 0
	if *dryRun || !execute {
		if !*dryRun {
			fmt.Fprintf(os.Stderr, "\nDRY RUN — nothing was issued. To execute, re-run with -confirm %d (or -force).\n", plan.Requested)
		} else {
			fmt.Fprintln(os.Stderr, "\nDRY RUN — nothing was issued.")
		}
		return nil
	}
	if plan.Invalid > 0 {
		// The preview already listed the invalid items. Proceed with partial
		// success (they will be reported "failed" below) — the operator confirmed
		// the full count with them in view — rather than blocking the batch.
		fmt.Fprintf(os.Stderr, "\nNote: %d manifest item(s) are invalid and will be reported as failed (see the plan above).\n", plan.Invalid)
	}
	if *force {
		spec.ConfirmCount = -1
	}

	fmt.Fprintf(os.Stderr, "\nExecuting batch issuance (operation %s)...\n", plan.OperationID)
	result, err := issuer.Execute(context.Background(), spec)
	if err != nil {
		return err
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return fmt.Errorf("creating -out-dir: %w", err)
		}
	}
	for i := range result.Items {
		it := &result.Items[i]
		if it.Status == ca.BulkIssueStatusIssued && *outDir != "" {
			pem := it.Certificate
			if *chain {
				pem = it.Chain
			}
			name := filepath.Join(*outDir, sanitizeRef(it.Ref)+".pem")
			if err := os.WriteFile(name, []byte(pem), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", name, err)
			}
		}
	}

	printIssueBulkResult(result, *outDir)
	if *jsonOut {
		if err := cliout.Emit(result); err != nil {
			return err
		}
	}
	if result.Failed > 0 {
		return fmt.Errorf("%d of %d item(s) failed (see the per-item results above)", result.Failed, result.Requested)
	}
	return nil
}

// issueManifestItem is one entry of the JSON manifest read by issue-bulk.
type issueManifestItem struct {
	Ref          string `json:"ref"`
	CSR          string `json:"csr"` // path to a PEM CSR (relative to the manifest dir when not absolute)
	Profile      string `json:"profile"`
	ValidityDays int    `json:"validity_days"`
}

// readIssueManifest loads the manifest and reads each referenced CSR file into a
// batch item. A missing/unreadable CSR file fails the whole load (the manifest
// is malformed) rather than being deferred to a per-item issuance error.
func readIssueManifest(path, defaultProfile string) ([]ca.BulkIssueItem, error) {
	raw, err := readInput(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var manifest []issueManifestItem
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}
	if len(manifest) == 0 {
		return nil, fmt.Errorf("manifest %s contains no items", path)
	}
	baseDir := "."
	if path != "-" {
		baseDir = filepath.Dir(path)
	}
	items := make([]ca.BulkIssueItem, 0, len(manifest))
	for i, m := range manifest {
		if m.CSR == "" {
			return nil, fmt.Errorf("manifest item %d (ref %q) has no csr path", i, m.Ref)
		}
		csrPath := m.CSR
		if !filepath.IsAbs(csrPath) {
			csrPath = filepath.Join(baseDir, csrPath)
		}
		csrPEM, err := os.ReadFile(csrPath)
		if err != nil {
			return nil, fmt.Errorf("manifest item %d (ref %q): reading csr %s: %w", i, m.Ref, csrPath, err)
		}
		profile := m.Profile
		if profile == "" {
			profile = defaultProfile
		}
		items = append(items, ca.BulkIssueItem{
			Ref:          m.Ref,
			CSRPEM:       csrPEM,
			Profile:      profile,
			ValidityDays: m.ValidityDays,
		})
	}
	return items, nil
}

// printIssueBulkPlan renders a dry-run plan for the operator.
func printIssueBulkPlan(p *ca.BulkIssuePlan) {
	fmt.Printf("Batch issuance plan for CA %s (%s)\n", p.CALabel, p.CAID)
	fmt.Printf("  operation id:    %s\n", p.OperationID)
	fmt.Printf("  WILL ISSUE:      %d certificate(s)\n", p.Valid)
	if p.NeedApproval > 0 {
		fmt.Printf("    need approval: %d (profile requires manual approval; issued via the API only after four-eyes sign-off)\n", p.NeedApproval)
	}
	if p.Invalid > 0 {
		fmt.Printf("  INVALID:         %d (will not be issued)\n", p.Invalid)
	}
	for _, it := range p.Items {
		if it.Valid {
			fmt.Printf("    [%s] %s  (profile %s%s)\n", it.Ref, firstNonEmpty(it.Subject, strings.Join(it.SANs, ",")), it.Profile, approvalTag(it.RequiresApproval))
		} else {
			fmt.Printf("    [%s] INVALID: %s\n", it.Ref, it.Error)
		}
	}
}

// printIssueBulkResult renders an executed batch result for the operator.
func printIssueBulkResult(r *ca.BulkIssueResult, outDir string) {
	fmt.Fprintf(os.Stderr, "\nBatch issuance %s:\n  issued:   %d\n  pending:  %d (held for approval)\n  failed:   %d\n  requested:%d\n  duration: %s\n",
		issueResultWord(r), r.Issued, r.Pending, r.Failed, r.Requested, r.Duration.Round(time.Millisecond))
	for i := range r.Items {
		it := &r.Items[i]
		switch it.Status {
		case ca.BulkIssueStatusIssued:
			fmt.Fprintf(os.Stderr, "    [%s] issued  serial=%s\n", it.Ref, it.Serial)
		case ca.BulkIssueStatusPending:
			fmt.Fprintf(os.Stderr, "    [%s] pending approval=%s (needs %d approver(s))\n", it.Ref, it.ApprovalID, it.RequiredApprovals)
		default:
			fmt.Fprintf(os.Stderr, "    [%s] FAILED  [%s] %s\n", it.Ref, it.ErrorCode, it.Error)
		}
	}
	if outDir != "" && r.Issued > 0 {
		fmt.Fprintf(os.Stderr, "\nWrote %d certificate(s) to %s/\n", r.Issued, outDir)
	}
}

func issueResultWord(r *ca.BulkIssueResult) string {
	if r.Failed > 0 {
		return "completed with failures"
	}
	return "complete"
}

// sanitizeRef makes a manifest ref safe to use as a filename.
func sanitizeRef(ref string) string {
	out := make([]rune, 0, len(ref))
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "cert"
	}
	return string(out)
}

func approvalTag(need bool) string {
	if need {
		return ", needs approval"
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return "(no subject)"
}
