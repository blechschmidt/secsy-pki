package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/siem"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// cmdAudit dispatches the "audit" subcommands. verify/export/anchor -list never
// touch key material; "audit anchor" builds the TSA key provider lazily, and
// only when the internal TSA is the token source.
func cmdAudit(db *database.DB, cfg *config.Config, args []string) error {
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
	case "anchor":
		return cmdAuditAnchor(db, cfg, rest)
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
  secsy-ca audit verify [-json] [-tsa-ca FILE]
      Re-walk the audit hash chain end-to-end and report the first broken link,
      then validate every stored RFC 3161 anchor: the anchored head must still
      exist with the anchored hash (detecting truncation/rewrite behind an
      anchor) and each token's CMS signature and message imprint must verify.
      -tsa-ca supplies PEM trust anchor(s) to additionally chain the TSA
      certificate. Exit status is non-zero on any chain or anchor failure.

  secsy-ca audit anchor [-force] [-json]
      Anchor the current chain head now: obtain an RFC 3161 timestamp token
      over the head (seq, hash) — from audit.anchor.tsa_url when configured,
      else the internal TSA (tsa: config + TSA key) — and persist it. Skips
      when nothing new happened since the last anchor unless -force is given.

  secsy-ca audit anchor -list [-json]
      List the stored anchors (JSON includes the base64 DER tokens for
      external archival/verification).

  secsy-ca audit export [-from RFC3339] [-to RFC3339] [-format rfc5424|cef|json] [-out FILE]
      Export audit events over a time range for offline batch delivery to a SIEM.
      Records are written one per line in the chosen format (default json).
`)
}

// auditVerifyOutput is the JSON shape of "audit verify": the chain result
// (fields unchanged for existing consumers) plus the per-anchor checks.
type auditVerifyOutput struct {
	audit.VerifyResult
	AnchorsValid bool                 `json:"anchors_valid"`
	Anchors      []anchor.CheckResult `json:"anchors,omitempty"`
}

// cmdAuditVerify re-walks the full hash chain, reports the first broken link,
// and validates every stored anchor against the chain and its RFC 3161 token.
func cmdAuditVerify(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	out := cliout.Register(fs)
	tsaCAFile := fs.String("tsa-ca", "", "PEM file with TSA trust anchor(s); when set, each anchor token's TSA certificate must chain to one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	var roots []*x509.Certificate
	if *tsaCAFile != "" {
		var err error
		if roots, err = readCertChainFile(*tsaCAFile); err != nil {
			return fmt.Errorf("-tsa-ca: %w", err)
		}
	}

	events, err := db.ListAllEventsAsc()
	if err != nil {
		return fmt.Errorf("loading event log: %w", err)
	}
	res := audit.VerifyFullChain(events)

	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		return fmt.Errorf("loading audit anchors: %w", err)
	}
	checks := anchor.VerifyAnchors(events, anchors, roots, time.Now())
	anchorsValid := true
	for _, c := range checks {
		if !c.Valid {
			anchorsValid = false
		}
	}

	if asJSON {
		if err := cliout.Emit(auditVerifyOutput{VerifyResult: res, AnchorsValid: anchorsValid, Anchors: checks}); err != nil {
			return err
		}
	} else {
		if res.Valid {
			fmt.Printf("audit chain OK: %d event(s) verified, hash chain intact.\n", res.Count)
		} else {
			fmt.Printf("audit chain BROKEN at seq %d: %s\n", res.BrokenAtSeq, res.Reason)
			fmt.Printf("verified %d event(s) before the break.\n", res.Count)
		}
		switch {
		case len(checks) == 0:
			fmt.Println("audit anchors: none stored (enable audit.anchor or run 'secsy-ca audit anchor').")
		case anchorsValid:
			latest := checks[len(checks)-1]
			fmt.Printf("audit anchors OK: %d anchor(s) verified; latest attests seq %d at %s (tsa=%s).\n",
				len(checks), latest.Seq, latest.GenTime.Format(time.RFC3339), latest.TSA)
		default:
			for _, c := range checks {
				if !c.Valid {
					fmt.Printf("audit anchor BROKEN (seq %d, gen_time %s): %s\n",
						c.Seq, c.GenTime.Format(time.RFC3339), c.Reason)
				}
			}
		}
	}

	// A broken chain or anchor is an operational alarm; signal it via a non-zero
	// exit so scripts and cron jobs can trip on it.
	if !res.Valid {
		return fmt.Errorf("audit chain verification failed at seq %d", res.BrokenAtSeq)
	}
	if !anchorsValid {
		return fmt.Errorf("audit anchor verification failed (chain truncated/rewritten behind an anchor, or a token is invalid)")
	}
	return nil
}

// cmdAuditAnchor anchors the current chain head on demand, or lists the stored
// anchors with -list.
func cmdAuditAnchor(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	list := fs.Bool("list", false, "list stored anchors instead of creating one")
	force := fs.Bool("force", false, "anchor even if nothing new happened since the last anchor")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	if *list {
		return listAuditAnchors(db, asJSON)
	}

	ts, cleanup, err := buildAnchorTimestamperCLI(db, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	svc := anchor.NewService(db, ts).WithActor("secsy-ca-cli")
	res, err := svc.AnchorOnce(context.Background(), *force)
	if err != nil {
		return err
	}

	if asJSON {
		return cliout.Emit(res)
	}
	if res.Skipped {
		fmt.Printf("anchor skipped: %s (use -force to anchor anyway)\n", res.Reason)
		return nil
	}
	src := res.Anchor.TSASource
	if src == "" {
		src = "internal"
	}
	fmt.Printf("anchored audit chain head: seq=%d head=%s\n", res.Anchor.Seq, res.Anchor.HeadHash)
	fmt.Printf("  token: %d bytes DER, gen_time=%s, tsa=%s, anchor id=%s\n",
		len(res.Anchor.Token), res.Anchor.GenTime.Format(time.RFC3339), src, res.Anchor.ID)
	return nil
}

// listAuditAnchors prints the stored anchors, newest last (chain order).
func listAuditAnchors(db *database.DB, asJSON bool) error {
	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		return err
	}
	if asJSON {
		return cliout.Emit(anchors)
	}
	if len(anchors) == 0 {
		fmt.Println("No audit anchors stored.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tHEAD HASH\tGEN TIME\tTSA\tCREATED\tID")
	for _, a := range anchors {
		src := a.TSASource
		if src == "" {
			src = "internal"
		}
		head := a.HeadHash
		if len(head) > 16 {
			head = head[:16] + "…"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			a.Seq, head, a.GenTime.Format(time.RFC3339), src, a.CreatedAt.Format(time.RFC3339), a.ID)
	}
	return tw.Flush()
}

// buildAnchorTimestamperCLI selects the anchor token source for the CLI: the
// configured external TSA URL, else an in-process authority over the TSA-role
// key provider (constructed lazily, so verify/list/export never need the HSM).
// cleanup releases the provider when one was opened.
func buildAnchorTimestamperCLI(db *database.DB, cfg *config.Config) (anchor.Timestamper, func(), error) {
	noop := func() {}
	if url := cfg.Audit.Anchor.TSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, time.Duration(cfg.Audit.Anchor.TimeoutSeconds)*time.Second), noop, nil
	}
	if cfg.TSA.KeyLabel == "" || cfg.TSA.CertificateFile == "" {
		return nil, noop, fmt.Errorf("anchoring needs a token source: configure audit.anchor.tsa_url (external TSA) or the internal tsa: block (key_label + certificate_file; provision with 'secsy-ca tsa-key')")
	}
	tsaCfg, err := tsa.LoadAuthorityConfig(db, cfg.TSA)
	if err != nil {
		return nil, noop, err
	}
	provider, err := buildProvider(cfg, "tsa")
	if err != nil {
		return nil, noop, fmt.Errorf("initializing TSA key provider: %w", err)
	}
	authority, err := tsa.New(db, provider, tsaCfg)
	if err != nil {
		provider.Close()
		return nil, noop, err
	}
	return anchor.NewAuthorityTimestamper(authority), func() { provider.Close() }, nil
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
		defer func() { _ = f.Close() }()
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
