package main

// `secsy-ca approvals` — operate the four-eyes / maker-checker approval queue
// (Task 81): list pending requests, inspect one, approve or reject, and run the
// expiry sweep. Approve/reject go through the same approval.Engine the server
// uses, so a request created by a REST-guarded operation can be signed off from
// the CLI and vice versa. Every decision is appended to the tamper-evident audit
// log by the engine.
//
// This file also provides the CLI-side gate helper (guardCLI) wired into the
// guarded commands (init-root, issue-intermediate, rotate/retire-intermediate,
// revoke-bulk): the very first attempt records a pending request and stops; once
// enough distinct approvers sign off, re-running the command executes.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/issueapproval"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// approvalPolicy builds the engine policy from configuration.
func approvalPolicy(cfg *config.Config) approval.Policy {
	return approval.Policy{
		Enabled:          cfg.Approvals.Enabled,
		DefaultThreshold: cfg.Approvals.ApprovalDefaultThreshold(),
		Thresholds:       cfg.Approvals.Thresholds,
		TTL:              cfg.Approvals.ApprovalTTL(),
	}
}

// newApprovalEngine constructs the approval engine over the shared database
// (which is both the Store and the audit Auditor). It installs the Task 84
// terminal hook so a cert.issue request rejected or expired from the CLI records
// the same cert.issue.denied domain event and metric as the server would.
func newApprovalEngine(db *database.DB, cfg *config.Config) *approval.Engine {
	eng := approval.NewEngine(db, db, approvalPolicy(cfg))
	eng.SetTerminalHook(issueapproval.NewTerminalHook(db))
	return eng
}

// guardCLI runs the approval gate for a CLI-initiated guarded operation. It
// returns nil to proceed (gate disabled/unguarded, or an approved request was
// consumed) or a descriptive error to abort — a pending-approval notice or a
// gate failure. The gate is fail-closed: a store error aborts the operation.
func guardCLI(db *database.DB, cfg *config.Config, req approval.GuardRequest) error {
	if !cfg.Approvals.Enabled {
		return nil
	}
	if req.Actor == "" {
		req.Actor = cliActor()
	}
	res, err := newApprovalEngine(db, cfg).Guard(context.Background(), req)
	if err != nil {
		return fmt.Errorf("approval gate: %w", err)
	}
	if res.Allowed {
		return nil
	}
	pa := res.Approval
	return fmt.Errorf("operation requires four-eyes approval — held as request %s\n"+
		"  needs %d distinct approver(s); %d recorded so far\n"+
		"  approvers run:  secsy-ca approvals approve %s\n"+
		"  then re-run this command to execute",
		pa.ID, pa.RequiredApprovals, pa.ApprovalsCount, pa.ID)
}

// cmdApprovals dispatches the `approvals` subcommands. Most need only the
// database and config (no key provider), so main dispatches it early; the
// `certificate` subcommand completes a per-profile issuance approval (Task 84),
// which signs on the HSM, so it builds a key provider lazily via providerFn.
func cmdApprovals(db *database.DB, cfg *config.Config, providerFn func() (keyprovider.Provider, error), args []string) error {
	if len(args) == 0 {
		approvalsUsage()
		return fmt.Errorf("approvals: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdApprovalsList(db, cfg, rest)
	case "show":
		return cmdApprovalsShow(db, cfg, rest)
	case "approve":
		return cmdApprovalsDecide(db, cfg, approval.DecisionApprove, rest)
	case "reject":
		return cmdApprovalsDecide(db, cfg, approval.DecisionReject, rest)
	case "certificate", "cert":
		return cmdApprovalsCertificate(db, cfg, providerFn, rest)
	case "expire":
		return cmdApprovalsExpire(db, cfg, rest)
	case "help", "-h", "--help":
		approvalsUsage()
		return nil
	default:
		approvalsUsage()
		return fmt.Errorf("approvals: unknown subcommand %q", sub)
	}
}

func approvalsUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca approvals — four-eyes / maker-checker approval queue (Task 81)

Usage:
  secsy-ca approvals list [-status pending|approved|rejected|executed|expired] [-class CLASS] [-tenant ID] [-json]
      List approval requests, newest first.

  secsy-ca approvals show <id> [-json]
      Show one request with its full decision log.

  secsy-ca approvals approve <id> [-approver ID] [-comment TEXT]
      Record an approval. Self-approval (approver == requester) is refused, as
      is a repeat vote by the same approver. When the distinct-approver
      threshold is met the request becomes 'approved' and the guarded operation
      may then execute (re-run it).

  secsy-ca approvals reject <id> [-approver ID] [-comment TEXT]
      Veto a request (terminal). The requester may also reject to withdraw.

  secsy-ca approvals certificate <id> [-out FILE] [-chain] [-json]
      Complete and fetch the certificate for an APPROVED per-profile issuance
      request (Task 84). Once the approver threshold is met this issues the
      certificate on the HSM (exactly once) and prints it (PEM). Before approval
      it reports the request is still pending; after rejection/expiry it reports
      the request will never issue.

  secsy-ca approvals expire [-json]
      Retire every request whose approval window has elapsed.

The gate is active only when approvals.enabled is set in the config.
`)
}

func cmdApprovalsList(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("approvals list", flag.ContinueOnError)
	status := fs.String("status", "", "filter by status")
	class := fs.String("class", "", "filter by operation class")
	tenant := fs.String("tenant", "", "filter by tenant id")
	asJSON := fs.Bool("json", false, "emit JSON")
	limit := fs.Int("limit", 200, "maximum rows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	list, err := newApprovalEngine(db, cfg).List(approval.Query{
		TenantID: *tenant, Status: *status, Class: *class, Limit: *limit,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(list)
	}
	if !cfg.Approvals.Enabled {
		fmt.Fprintln(os.Stderr, "note: the approval gate is DISABLED (approvals.enabled is false); existing requests are shown for reference.")
	}
	if len(list) == 0 {
		fmt.Println("No approval requests.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLASS\tRESOURCE\tSTATUS\tAPPROVALS\tREQUESTER\tCREATED")
	for _, pa := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n",
			pa.ID, pa.OperationClass, pa.ResourceKey, pa.Status,
			pa.ApprovalsCount, pa.RequiredApprovals, pa.RequestedBy,
			pa.CreatedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

// splitIDAndFlags accepts the request id either before or after the flags, so
// both `approvals approve <id> -approver X` and `approvals approve -approver X
// <id>` work (Go's flag package otherwise stops parsing at the first
// positional, silently dropping flags placed after the id).
func splitIDAndFlags(args []string) (id string, rest []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func cmdApprovalsShow(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("approvals show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	id, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca approvals show <id>")
	}
	pa, err := newApprovalEngine(db, cfg).Get(id)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(pa)
	}
	printApproval(pa)
	return nil
}

func printApproval(pa *models.PendingApproval) {
	fmt.Printf("Request:    %s\n", pa.ID)
	fmt.Printf("Class:      %s (%s)\n", pa.OperationClass, approval.ClassTitle(pa.OperationClass))
	fmt.Printf("Resource:   %s\n", pa.ResourceKey)
	fmt.Printf("Summary:    %s\n", pa.Summary)
	if pa.Details != "" {
		fmt.Printf("Details:    %s\n", pa.Details)
	}
	fmt.Printf("Tenant:     %s\n", pa.TenantID)
	fmt.Printf("Requester:  %s\n", pa.RequestedBy)
	fmt.Printf("Status:     %s (%d of %d distinct approver(s))\n", pa.Status, pa.ApprovalsCount, pa.RequiredApprovals)
	fmt.Printf("Created:    %s\n", pa.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Expires:    %s\n", pa.ExpiresAt.Format(time.RFC3339))
	if pa.ExecutedAt != nil {
		fmt.Printf("Executed:   %s\n", pa.ExecutedAt.Format(time.RFC3339))
	}
	if len(pa.Decisions) > 0 {
		fmt.Println("Decisions:")
		for _, d := range pa.Decisions {
			line := fmt.Sprintf("  - %s by %s at %s", d.Decision, d.Approver, d.CreatedAt.Format(time.RFC3339))
			if d.Comment != "" {
				line += " — " + d.Comment
			}
			fmt.Println(line)
		}
	}
}

func cmdApprovalsDecide(db *database.DB, cfg *config.Config, decision string, args []string) error {
	fs := flag.NewFlagSet("approvals "+decision, flag.ContinueOnError)
	approver := fs.String("approver", "", "approver identity recorded in the decision (default: CLI user)")
	comment := fs.String("comment", "", "optional note recorded with the decision")
	id, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca approvals %s <id> [-approver ID]", decision)
	}
	actor := *approver
	if actor == "" {
		actor = cliActor()
	}
	eng := newApprovalEngine(db, cfg)
	var (
		pa  *models.PendingApproval
		err error
	)
	if decision == approval.DecisionApprove {
		pa, err = eng.Approve(context.Background(), id, actor, "", *comment, "")
	} else {
		pa, err = eng.Reject(context.Background(), id, actor, "", *comment, "")
	}
	if err != nil {
		return err
	}
	switch pa.Status {
	case approval.StatusApproved:
		if pa.OperationClass == approval.ClassCertIssue {
			fmt.Printf("Request %s is now APPROVED (%d of %d) — fetch the certificate with:\n"+
				"  secsy-ca approvals certificate %s\n",
				pa.ID, pa.ApprovalsCount, pa.RequiredApprovals, pa.ID)
		} else {
			fmt.Printf("Request %s is now APPROVED (%d of %d) — the operation may be re-run to execute.\n",
				pa.ID, pa.ApprovalsCount, pa.RequiredApprovals)
		}
	case approval.StatusRejected:
		fmt.Printf("Request %s is REJECTED.\n", pa.ID)
	default:
		fmt.Printf("Recorded. Request %s is %s (%d of %d approver(s)).\n",
			pa.ID, pa.Status, pa.ApprovalsCount, pa.RequiredApprovals)
	}
	return nil
}

func cmdApprovalsExpire(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("approvals expire", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The sweep is a no-op when the gate is disabled; force it on for a manual
	// run so an operator can clean up requests left from a previously-enabled gate.
	eng := approval.NewEngine(db, db, approval.Policy{Enabled: true,
		DefaultThreshold: cfg.Approvals.ApprovalDefaultThreshold(), TTL: cfg.Approvals.ApprovalTTL()})
	eng.SetTerminalHook(issueapproval.NewTerminalHook(db))
	n, err := eng.SweepExpired(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]int{"expired": n})
	}
	fmt.Printf("Expired %d stale request(s).\n", n)
	return nil
}

// cmdApprovalsCertificate completes and fetches the certificate for an approved
// per-profile issuance request (Task 84). It reuses the shared issueapproval
// completion driver, so the certificate is issued on the HSM exactly once and
// the same certificate is returned on any subsequent fetch.
func cmdApprovalsCertificate(db *database.DB, cfg *config.Config, providerFn func() (keyprovider.Provider, error), args []string) error {
	fs := flag.NewFlagSet("approvals certificate", flag.ContinueOnError)
	out := fs.String("out", "", "write the certificate PEM to FILE instead of stdout")
	chain := fs.Bool("chain", false, "print the full chain (leaf + issuer) rather than just the leaf")
	asJSON := fs.Bool("json", false, "emit the full issuance response as JSON")
	id, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca approvals certificate <id>")
	}

	provider, err := providerFn()
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	eng := newApprovalEngine(db, cfg)
	mgr := ca.NewManager(db, provider)
	outcome, err := issueapproval.Complete(context.Background(), eng, mgr, db, id, cliActor(), "", "")
	if err != nil {
		return err
	}

	switch outcome.State {
	case issueapproval.StateDelivered:
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"serial":      outcome.Issued.Serial,
				"profile":     outcome.Issued.Profile,
				"not_before":  outcome.Issued.NotBefore.Format(time.RFC3339),
				"not_after":   outcome.Issued.NotAfter.Format(time.RFC3339),
				"certificate": outcome.Issued.Certificate,
				"chain":       outcome.ChainPEM,
			})
		}
		pem := outcome.Issued.Certificate
		if *chain {
			pem = outcome.ChainPEM
		}
		if *out != "" {
			if err := os.WriteFile(*out, []byte(pem), 0o600); err != nil {
				return fmt.Errorf("writing certificate: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Certificate for approval %s (serial %s) written to %s\n",
				id, outcome.Issued.Serial, *out)
			return nil
		}
		fmt.Print(pem)
		return nil
	case issueapproval.StatePending:
		return fmt.Errorf("request %s is still awaiting approval (%s); the certificate is not issued yet",
			id, outcome.Reason)
	case issueapproval.StateDenied:
		return fmt.Errorf("request %s will not issue: %s", id, outcome.Reason)
	case issueapproval.StateFailed:
		return fmt.Errorf("issuance failed after approval for request %s: %s", id, outcome.Err)
	default:
		return fmt.Errorf("request %s: %s", id, outcome.Reason)
	}
}
