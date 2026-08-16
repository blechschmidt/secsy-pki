package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// `secsy-ca hsm-audit` drives the HSM audit subsystem (Task 167).
//
// The subcommands split along a trust boundary. provision/collect/export/status
// run on the CA host and touch the device and the database. verify runs
// anywhere — it is the auditor's tool, takes a JSON bundle and nothing else,
// and is dispatched in main before the database or key provider is opened so
// that a third party can check the CA's claims on a laptop with no access to
// either.

func hsmAuditUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca hsm-audit <subcommand> [flags]

Subcommands:
  status                Show device audit configuration and collection state
  provision             Commission a factory-reset YubiHSM: force irreversible
                        audit logging and pin the chain anchor
  collect               Drain the device log into durable storage once
  timestamp             Obtain one RFC 3161 attestation that the current audit
                        head existed now, proving later exports are not stale
  export  -out FILE     Write a remotely verifiable audit bundle
  verify  -bundle FILE  Verify a bundle offline (no database, no HSM)

Verification flags (verify):
  -anchor HEX           Genesis anchor recorded when the device was commissioned.
                        Without it the bundle is only checked for internal
                        consistency, which cannot detect a wholly forged history.
  -serial SERIAL        Expected device serial number.
  -previous FILE        A previously exported bundle; checks that this one
                        extends it without rewriting history, and reports what
                        the device signed in between.
  -published FILE       File of hex artifact digests, one per line, obtained
                        independently of the CA. Each ledger entry must match one.
  -tsa-roots FILE       PEM trust anchors for the timestamp authority. Without
                        them a token minted by an authority the CA controls
                        would pass the freshness check.
  -max-age DURATION     How stale the newest attestation may be before the
                        bundle is rejected as outdated (default 25h). Use 0 to
                        report the age without failing on it.
  -require-external-tsa Reject attestations produced by the CA's own in-process
                        TSA, which signs with the HSM under audit.
  -skip-freshness       Report on the history without checking whether it is
                        current. Not for real audits.
  -json                 Emit the full machine-readable verdict.
`)
}

func cmdHSMAudit(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		hsmAuditUsage()
		return fmt.Errorf("hsm-audit: no subcommand given")
	}
	sub, rest := args[0], args[1:]

	dev := hsmaudit.NewShellDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	svc := hsmaudit.NewService(dev, db)
	ctx := context.Background()

	switch sub {
	case "status":
		return cmdHSMAuditStatus(ctx, svc, rest)
	case "provision":
		return cmdHSMAuditProvision(ctx, svc, rest)
	case "collect":
		return cmdHSMAuditCollect(ctx, dev, db, rest)
	case "timestamp":
		return cmdHSMAuditTimestamp(ctx, svc, db, cfg, rest)
	case "export":
		return cmdHSMAuditExport(ctx, svc, rest)
	case "help", "-h", "--help":
		hsmAuditUsage()
		return nil
	default:
		hsmAuditUsage()
		return fmt.Errorf("hsm-audit: unknown subcommand %q", sub)
	}
}

func cmdHSMAuditStatus(ctx context.Context, svc *hsmaudit.Service, args []string) error {
	fs := flag.NewFlagSet("hsm-audit status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := svc.Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(st)
	}
	if st.Device != nil {
		fmt.Printf("Device:          %s (firmware %s)\n", st.Device.Serial, st.Device.Version)
		fmt.Printf("Device log:      %s used\n", st.LogUsed)
	} else {
		fmt.Println("Device:          unreachable")
	}
	if !st.Provisioned {
		fmt.Println("Provisioned:     no — run `secsy-ca hsm-audit provision` on a factory-reset device")
		return nil
	}
	fmt.Printf("Provisioned:     yes\n")
	fmt.Printf("Chain anchor:    %s\n", st.Anchor)
	fmt.Printf("Collected up to: entry %d\n", st.Tail.Number)
	fmt.Printf("Stored entries:  %d (%d signature(s))\n", st.StoredEntries, st.Signatures)
	fmt.Printf("Ledger entries:  %d\n", st.LedgerEntries)
	if st.LastAttestedAt == nil {
		fmt.Printf("Last attested:   never — exports cannot prove they are current " +
			"(run `secsy-ca hsm-audit timestamp`)\n")
	} else {
		fmt.Printf("Last attested:   %s (%s ago, %d proof(s))\n",
			st.LastAttestedAt.Format(time.RFC3339),
			time.Since(*st.LastAttestedAt).Round(time.Second), st.FreshnessProofs)
	}
	if st.OptionsError != "" {
		fmt.Printf("\nWARNING: %s\n", st.OptionsError)
		fmt.Println("The device is not configured to guarantee that every signature is logged.")
		return fmt.Errorf("device audit configuration is insufficient")
	}
	fmt.Println("Audit config:    forced (irreversible until factory reset)")
	if st.Signatures != st.LedgerEntries {
		fmt.Printf("\nWARNING: the device recorded %d signature(s) but the CA accounts for %d.\n",
			st.Signatures, st.LedgerEntries)
	}
	return nil
}

func cmdHSMAuditProvision(ctx context.Context, svc *hsmaudit.Service, args []string) error {
	fs := flag.NewFlagSet("hsm-audit provision", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := svc.Provision(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("Device %s (firmware %s) provisioned for audited operation.\n", res.Device.Serial, res.Device.Version)
	fmt.Printf("Forced audit logging is enabled for %d command(s) and cannot be disabled without a factory reset.\n",
		len(res.Options.RequiredForced()))
	fmt.Printf("Collected %d initial log entr(ies).\n\n", res.Collected)
	fmt.Printf("CHAIN ANCHOR: %s\n\n", res.Anchor)
	fmt.Println("Record this anchor outside this system — an auditor who learns it only from")
	fmt.Println("the CA cannot tell a genuine history from a fabricated one, because the device")
	fmt.Println("seeds it randomly at each factory reset and it cannot be recomputed.")
	return nil
}

func cmdHSMAuditCollect(ctx context.Context, dev hsmaudit.Device, store hsmaudit.Store, args []string) error {
	fs := flag.NewFlagSet("hsm-audit collect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := hsmaudit.NewCollector(dev, store, 0, nil).Collect(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("Collected %d entr(ies) (%d signature(s)); collection now at entry %d; device log %s used.\n",
		res.Collected, res.Signatures, res.Tail.Number, res.LogUsed)
	return nil
}

// cmdHSMAuditTimestamp obtains one freshness attestation on demand.
//
// The background job on the server is what actually keeps a deployment
// attestable; this exists for commissioning (so the very first export carries a
// proof rather than none) and for an operator who needs to demonstrate current
// state during an incident without waiting out the interval.
func cmdHSMAuditTimestamp(ctx context.Context, svc *hsmaudit.Service, db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-audit timestamp", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ts, cleanup, err := buildFreshnessTimestamperCLI(db, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	p, err := svc.Timestamp(ctx, ts)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	src := p.Source
	if src == "" {
		src = "the internal TSA (signs with the HSM under audit)"
	}
	fmt.Printf("Attested audit head at %s by %s.\n", p.GenTime.Format(time.RFC3339), src)
	fmt.Printf("  device %s, log entry %d, %d signature(s), ledger seq %d\n",
		p.Head.DeviceSerial, p.Head.DeviceNumber, p.Head.Signatures, p.Head.LedgerSeq)
	fmt.Printf("  head digest %s, token %d bytes DER\n", p.HeadDigest, len(p.Token))
	return nil
}

// buildFreshnessTimestamperCLI selects the token source for freshness
// attestations: the dedicated external TSA when configured, else the audit-chain
// anchor's TSA, else this PKI's own in-process authority.
//
// The fallback chain exists so a deployment that already configured an
// independent TSA for audit anchoring (Task 64) gets an independent one here
// without configuring it twice — the two features want exactly the same
// property from an authority.
func buildFreshnessTimestamperCLI(db *database.DB, cfg *config.Config) (hsmaudit.Timestamper, func(), error) {
	noop := func() {}
	timeout := time.Duration(cfg.YubiHSM.AuditFreshnessTimeoutSeconds) * time.Second
	if url := cfg.YubiHSM.AuditFreshnessTSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, timeout), noop, nil
	}
	if url := cfg.Audit.Anchor.TSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, time.Duration(cfg.Audit.Anchor.TimeoutSeconds)*time.Second), noop, nil
	}
	if cfg.TSA.KeyLabel == "" || cfg.TSA.CertificateFile == "" {
		return nil, noop, fmt.Errorf("freshness attestation needs a timestamp authority: set " +
			"yubihsm.audit_freshness_tsa_url to an external RFC 3161 TSA (recommended — the internal one signs " +
			"with the very HSM being audited), or provision the internal tsa: block with 'secsy-ca tsa-key'")
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

func cmdHSMAuditExport(ctx context.Context, svc *hsmaudit.Service, args []string) error {
	fs := flag.NewFlagSet("hsm-audit export", flag.ContinueOnError)
	out := fs.String("out", "", "file to write the bundle to (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := svc.Export(ctx)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if *out == "" {
		_, err := os.Stdout.Write(append(raw, '\n'))
		return err
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	fp, err := b.Fingerprint()
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%d device log entr(ies), %d ledger entr(ies)).\n",
		*out, len(b.LogEntries), len(b.Ledger))
	fmt.Printf("Bundle fingerprint: %s\n", fp)
	return nil
}

// cmdHSMAuditVerify is the auditor-side offline verifier. It deliberately takes
// no database and no device: everything it needs is in the bundle, plus the
// anchor and artifact digests the auditor holds independently.
func cmdHSMAuditVerify(args []string) error {
	fs := flag.NewFlagSet("hsm-audit verify", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "bundle JSON file to verify")
	prevPath := fs.String("previous", "", "previously exported bundle to check continuation against")
	publishedPath := fs.String("published", "", "file of published artifact digests, one hex digest per line")
	expectedAnchor := fs.String("anchor", "", "expected genesis chain anchor")
	serial := fs.String("serial", "", "expected device serial")
	tsaRootsPath := fs.String("tsa-roots", "", "PEM file of timestamp-authority trust anchors")
	maxAge := fs.Duration("max-age", hsmaudit.DefaultMaxAge,
		"reject the bundle when the newest attestation is older than this (0 reports the age without failing)")
	requireExternalTSA := fs.Bool("require-external-tsa", false,
		"reject attestations produced by the CA's own in-process TSA")
	skipFreshness := fs.Bool("skip-freshness", false, "do not check whether the bundle is current")
	asJSON := fs.Bool("json", false, "emit the full machine-readable verdict")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		hsmAuditUsage()
		return fmt.Errorf("hsm-audit verify: -bundle is required")
	}

	b, err := readBundle(*bundlePath)
	if err != nil {
		return err
	}
	opts := hsmaudit.VerifyOptions{
		ExpectedAnchor: *expectedAnchor,
		ExpectedSerial: *serial,
		SkipFreshness:  *skipFreshness,
		Freshness: hsmaudit.FreshnessOptions{
			// A -max-age of 0 means "report but do not fail", which
			// FreshnessOptions spells as a negative duration (its own zero
			// selects the default).
			MaxAge:                orZero(*maxAge),
			RequireIndependentTSA: *requireExternalTSA,
		},
	}
	if *publishedPath != "" {
		digests, err := readDigests(*publishedPath)
		if err != nil {
			return err
		}
		opts.PublishedDigests = digests
	}
	if *tsaRootsPath != "" {
		roots, err := readTSARoots(*tsaRootsPath)
		if err != nil {
			return err
		}
		opts.Freshness.Roots = roots
	}

	res := hsmaudit.VerifyBundle(b, opts)

	var cont *hsmaudit.ContinuationResult
	if *prevPath != "" {
		prev, err := readBundle(*prevPath)
		if err != nil {
			return err
		}
		cont = hsmaudit.VerifyContinuation(prev, b)
	}

	if *asJSON {
		payload := map[string]any{"bundle": res}
		if cont != nil {
			payload["continuation"] = cont
		}
		if err := json.NewEncoder(os.Stdout).Encode(payload); err != nil {
			return err
		}
	} else {
		printHSMAuditVerdict(res, cont, opts)
	}

	if !res.OK {
		return fmt.Errorf("verification failed")
	}
	if cont != nil && !cont.OK {
		return fmt.Errorf("continuation check failed")
	}
	return nil
}

func printHSMAuditVerdict(res *hsmaudit.BundleResult, cont *hsmaudit.ContinuationResult, opts hsmaudit.VerifyOptions) {
	fmt.Println(res.Summary)
	fmt.Println()
	if res.Reconciliation != nil {
		for _, k := range res.Reconciliation.Keys {
			label := k.KeyLabel
			if label == "" {
				label = "(unlabelled)"
			}
			status := "balanced"
			if !k.Balanced {
				status = fmt.Sprintf("SURPLUS %+d", k.Surplus)
			}
			fmt.Printf("  key 0x%04x %-24s device %3d  ledger %3d  %s\n",
				k.KeyID, label, k.DeviceSignatures, k.LedgerSignatures, status)
		}
		fmt.Println()
	}
	if f := res.Freshness; f != nil {
		switch {
		case f.Stale:
			fmt.Printf("Freshness: STALE — last attested %s (%s ago); this export cannot show what the HSM has signed since.\n",
				f.NewestGenTime.Format(time.RFC3339), f.Age.Round(time.Second))
		case f.Verified > 0:
			fmt.Printf("Freshness: last attested %s (%s ago), %d/%d proof(s) verified.\n",
				f.NewestGenTime.Format(time.RFC3339), f.Age.Round(time.Second), f.Verified, f.Proofs)
		default:
			fmt.Printf("Freshness: NOT ESTABLISHED — %d proof(s) present, none verified.\n", f.Proofs)
		}
		for _, n := range f.Notes {
			fmt.Printf("  NOTE: %s\n", n)
		}
		fmt.Println()
	}
	if cont != nil {
		if cont.OK {
			fmt.Printf("Continuation: OK — %d new device log entr(ies), %d new signature(s) since the previous export.\n",
				cont.NewEntries, cont.NewSignatures)
			if cont.Interval != "" {
				fmt.Printf("  %s\n", cont.Interval)
			}
			fmt.Println()
		} else {
			fmt.Printf("Continuation: FAILED — %s\n\n", cont.Err())
		}
	}
	if res.AnchorErr != "" && res.OK {
		fmt.Printf("NOTE: %s\n\n", res.AnchorErr)
	}
	if opts.PublishedDigests == nil && res.OK {
		fmt.Println("NOTE: no published-artifact digests supplied (-published). The bundle proves the")
		fmt.Println("device signed exactly what the CA's ledger records, but not that those records")
		fmt.Println("correspond to artifacts the CA actually published.")
		fmt.Println()
	}
	for _, f := range res.Findings {
		fmt.Printf("  - %s\n", f)
	}
}

func readBundle(path string) (*hsmaudit.Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle %s: %w", path, err)
	}
	var b hsmaudit.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parsing bundle %s: %w", path, err)
	}
	return &b, nil
}

// orZero maps the CLI's "0 means do not fail on age" to the negative duration
// FreshnessOptions uses for it, since its own zero selects the default.
func orZero(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

// readTSARoots parses a PEM bundle of timestamp-authority trust anchors.
//
// Supplying them is what turns the freshness check from "some authority signed
// this" into "an authority you trust signed this" — without them a CA could
// mint its own TSA and attest to whatever time it liked.
func readTSARoots(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading TSA roots %s: %w", path, err)
	}
	var roots []*x509.Certificate
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing TSA root in %s: %w", path, err)
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %s", path)
	}
	return roots, nil
}

// readDigests reads one hex digest per line, ignoring blanks and # comments so
// an auditor can annotate the list with where each artifact came from.
func readDigests(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading published digests %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Non-nil even when empty: an empty file means "the auditor found nothing
	// published", which must fail the match rather than skip it.
	digests := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		digests = append(digests, strings.ToLower(strings.Fields(line)[0]))
	}
	return digests, sc.Err()
}
