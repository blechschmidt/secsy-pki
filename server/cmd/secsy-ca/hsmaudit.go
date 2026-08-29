package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
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
  commit                Have the device sign a commitment binding the current
                        audit head to its own serial number, and date it with the
                        TSA. The log itself carries no device identity, so this is
                        what ties it to real hardware
  export  -out FILE     Write a remotely verifiable audit bundle
  verify  -bundle FILE  Verify a bundle offline (no database, no HSM)
  verify-file -file F   Verify an append-only device log file offline: every
                        record's digest is re-derived from the raw device
                        records, with no database, device or configuration

Collection flags (collect):
  -log-file FILE        Append collected records to this append-only file as
                        well as the database. Defaults to yubihsm.audit_log_file

Log-file flags (verify-file):
  -anchor HEX           Genesis anchor recorded when the device was commissioned
  -serial SERIAL        Expected device serial number
  -tail N               Entry number the file must reach, as reported by
                        hsm-audit status. No chain can detect its own truncation,
                        so this is what catches records removed from the end of
                        the file
  -strict               Also fail when the file documents gaps in its coverage
  -json                 Emit the full machine-readable verdict

Verification flags (verify):
  -key FILE             Certificate or public key to prove. Repeatable. Answers
                        "has THIS key signed anything that was not published",
                        by binding it to an on-device handle through the
                        device's own key attestation. Without it the verdict is
                        about the device rather than about a key you hold.
  -anchor HEX           Genesis anchor recorded when the device was commissioned.
                        Without it the bundle is only checked for internal
                        consistency, which cannot detect a wholly forged history.
  -serial SERIAL        Expected device serial number.
  -attest-roots FILE    PEM trust anchors for YubiHSM key attestation. Empty
                        uses Yubico's published roots, embedded in the binary.
  -require-anchored-attestation
                        Fail unless each device attestation certificate chains
                        to one of those roots, i.e. the attesting device is
                        provably a genuine YubiHSM. On by default; stock
                        hardware anchors with no configuration. Pass =false
                        only for a device whose factory attestation key was
                        replaced. See docs/hsm/key-attestation.md.
  -allow-unattested-keys
                        Report rather than fail when a key that signed is not
                        attested. Not for real audits: without attestation the
                        bundle bounds what the device did, not what a key did.
  -allow-unbound-log    Report rather than fail when no device-signed commitment
                        binds the log to the device it names. Not for real
                        audits: a YubiHSM audit log carries no serial and no
                        signature, so without a commitment every other check
                        holds just as well over a log fabricated offline.
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

	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	svc := hsmaudit.NewService(dev, db)
	// Provisioning records the pinned chain anchor into the hash-chained event
	// log, which is what dates it — see hsmaudit.Service.SetAuditor.
	svc.SetAuditor(db)
	svc.SetActor(cliActor())
	if id := cfg.YubiHSM.AuditCommitmentKeyID; id != 0 {
		svc.SetCommitmentKeyID(uint16(id))
	}
	ctx := context.Background()

	switch sub {
	case "status":
		return cmdHSMAuditStatus(ctx, svc, cfg, rest)
	case "provision":
		return cmdHSMAuditProvision(ctx, svc, rest)
	case "collect":
		return cmdHSMAuditCollect(ctx, dev, db, cfg, rest)
	case "timestamp":
		return cmdHSMAuditTimestamp(ctx, svc, db, cfg, rest)
	case "commit":
		return cmdHSMAuditCommit(ctx, svc, db, cfg, rest)
	case "export":
		return cmdHSMAuditExport(ctx, svc, rest)
	case "verify-file":
		// Normally dispatched in main before any config is read; reachable here
		// only if a caller routed to cmdHSMAudit directly.
		return cmdHSMAuditVerifyFile(rest)
	case "help", "-h", "--help":
		hsmAuditUsage()
		return nil
	default:
		hsmAuditUsage()
		return fmt.Errorf("hsm-audit: unknown subcommand %q", sub)
	}
}

func cmdHSMAuditStatus(ctx context.Context, svc *hsmaudit.Service, cfg *config.Config, args []string) error {
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
	defer func() { printAuditLogFileStatus(cfg, st.Tail) }()
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
	if len(st.SigningKeys) > 0 {
		handles := make([]string, 0, len(st.SigningKeys))
		for _, id := range st.SigningKeys {
			handles = append(handles, fmt.Sprintf("0x%04x", id))
		}
		fmt.Printf("Signing keys:    %s\n", strings.Join(handles, ", "))
		if !st.CanAttest {
			fmt.Println("                 WARNING: no attester configured — exports will carry no key")
			fmt.Println("                 attestations, and a verifier cannot then tell that those")
			fmt.Println("                 signatures came from keys confined to this HSM.")
		}
	}
	if st.LastAttestedAt == nil {
		fmt.Printf("Last attested:   never — exports cannot prove they are current " +
			"(run `secsy-ca hsm-audit timestamp`)\n")
	} else {
		fmt.Printf("Last attested:   %s (%s ago, %d proof(s))\n",
			st.LastAttestedAt.Format(time.RFC3339),
			time.Since(*st.LastAttestedAt).Round(time.Second), st.FreshnessProofs)
	}
	switch {
	case !st.CanCommit:
		fmt.Println("Device binding:  unavailable — no committer configured, so exports cannot show")
		fmt.Println("                 which device produced the log.")
	case st.LastCommittedAt == nil && st.Commitments > 0:
		fmt.Printf("Device binding:  %d binding(s), none dated — an undated binding bounds nothing in time.\n",
			st.Commitments)
		fmt.Println("                 Configure a reachable timestamp authority and run `hsm-audit commit`.")
	case st.LastCommittedAt == nil:
		fmt.Println("Device binding:  never — the log is attributed to this device by the CA alone " +
			"(run `secsy-ca hsm-audit commit`)")
	default:
		fmt.Printf("Device binding:  %s (%s ago, %d commitment(s))\n",
			st.LastCommittedAt.Format(time.RFC3339),
			time.Since(*st.LastCommittedAt).Round(time.Second), st.Commitments)
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
	fmt.Println()
	fmt.Println("It has also been written to the hash-chained event log, so the next RFC 3161")
	fmt.Println("audit-chain anchoring run will place it under a timestamp the CA cannot")
	fmt.Println("backdate (`secsy-ca audit anchor`). That dates the anchor; only recording it")
	fmt.Println("out of band gives an auditor a copy the CA cannot revise.")
	return nil
}

func cmdHSMAuditCollect(ctx context.Context, dev hsmaudit.Device, store hsmaudit.Store, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-audit collect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	logFile := fs.String("log-file", "", "append-only file to write collected records to "+
		"(default: yubihsm.audit_log_file from the configuration)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := hsmaudit.NewCollector(dev, store, 0, nil)
	path := *logFile
	if path == "" && cfg != nil {
		path = cfg.YubiHSM.AuditLogFile
	}
	if strings.TrimSpace(path) != "" {
		f, err := hsmaudit.OpenLogFile(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		c.AddSink(f)
	}
	res, err := c.Collect(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("Collected %d entr(ies) (%d signature(s)); collection now at entry %d; device log %s used.\n",
		res.Collected, res.Signatures, res.Tail.Number, res.LogUsed)
	if strings.TrimSpace(path) != "" {
		fmt.Printf("Records appended to %s\n", path)
	}
	return nil
}

// printAuditLogFileStatus reports on the append-only device-log file and
// cross-checks it against the collection tail the database holds.
//
// The cross-check is the part that matters. A file verifies its own chain, but
// no chain can detect its own truncation — remove the newest records and what
// is left is a shorter, perfectly valid chain. The database's tail is an
// independent statement of how far collection has got, so comparing the two
// catches a truncation of either copy: one of them lags, and neither can fake
// the other's position.
//
// It says so explicitly when no file is configured, rather than printing
// nothing: "the database is the only copy of this log" is exactly the sort of
// fact an operator should learn from a status command rather than from an
// incident.
func printAuditLogFileStatus(cfg *config.Config, dbTail hsmaudit.Tail) {
	if cfg == nil {
		return
	}
	path := strings.TrimSpace(cfg.YubiHSM.AuditLogFile)
	if path == "" {
		fmt.Println("Log file:        none — the database is the only copy of the device log " +
			"(set yubihsm.audit_log_file for an append-only second copy)")
		return
	}
	res, err := hsmaudit.VerifyLogFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// Configured but not yet written: the ordinary state between setting the
		// path and the first drain, and not something to alarm an operator with.
		fmt.Printf("Log file:        %s (not written yet — it is created by the first collection)\n", path)
		return
	}
	if err != nil {
		fmt.Printf("Log file:        %s — UNREADABLE: %v\n", path, err)
		return
	}
	verdict := "verified"
	if !res.OK {
		verdict = fmt.Sprintf("FAILED VERIFICATION (%d problem(s))", len(res.Problems))
	} else if !res.Continuous {
		verdict = fmt.Sprintf("verified, %d documented gap(s)", len(res.Gaps))
	}
	fmt.Printf("Log file:        %s (%d entr(ies) up to %d, %s)\n", path, res.Entries, res.Last, verdict)
	switch {
	case dbTail.Number == 0:
	case res.Last == dbTail.Number && strings.EqualFold(res.Tail.Digest, dbTail.Digest):
		fmt.Println("                 agrees with the database at entry " + fmt.Sprint(dbTail.Number))
	case res.Last == dbTail.Number:
		fmt.Printf("                 WARNING: both copies end at entry %d but with different digests "+
			"(%s in the file, %s in the database): one of them was altered\n",
			dbTail.Number, res.Tail.Digest, strings.ToLower(dbTail.Digest))
	default:
		fmt.Printf("                 WARNING: the file ends at entry %d but the database has collected to %d. "+
			"A file that lags has lost records the database still holds — no chain can detect its own "+
			"truncation, which is why this comparison exists. Protect it with `chattr +a`.\n",
			res.Last, dbTail.Number)
	}
}

// cmdHSMAuditVerifyFile checks an append-only device-log file on its own terms.
//
// Like `verify`, it is dispatched before the database or the key provider is
// opened, because the whole point of the file is to be checkable somewhere the
// CA is not: an auditor holding a copy shipped off the host has neither.
func cmdHSMAuditVerifyFile(args []string) error {
	fs := flag.NewFlagSet("hsm-audit verify-file", flag.ContinueOnError)
	path := fs.String("file", "", "append-only device log file to verify (required)")
	anchor := fs.String("anchor", "", "genesis anchor recorded when the device was commissioned")
	serial := fs.String("serial", "", "expected device serial number")
	tail := fs.Uint("tail", 0, "entry number the file must reach — the collection tail the CA reports, "+
		"obtained independently. No chain can detect its own truncation, so this is what catches records "+
		"removed from the end")
	strict := fs.Bool("strict", false, "also fail when the file documents gaps in its own coverage")
	asJSON := fs.Bool("json", false, "emit the full machine-readable verdict")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("hsm-audit verify-file: -file is required")
	}
	res, err := hsmaudit.VerifyLogFile(*path)
	if err != nil {
		return err
	}

	// The anchor and serial are checked here rather than inside verification
	// because they are the auditor's inputs, not the file's: a file cannot
	// attest to the values it would be checked against.
	var extra []string
	switch {
	case *anchor == "":
	case !res.FromGenesis:
		extra = append(extra, "an anchor was supplied but the file does not start at the device-init "+
			"sentinel, so there is nothing for it to pin")
	case !strings.EqualFold(strings.TrimSpace(*anchor), res.Anchor):
		// The same verdict the bundle path reaches on a mismatched anchor: the
		// chain may be internally consistent and still be some other device's
		// history, or a fabricated one, rather than the one commissioned.
		extra = append(extra, fmt.Sprintf(
			"file anchor %s does not match the pinned anchor %s: this is a different device history "+
				"(the device was reset, or the file was fabricated)",
			res.Anchor, strings.ToLower(strings.TrimSpace(*anchor))))
	}
	if *serial != "" && !strings.EqualFold(strings.TrimSpace(*serial), res.Device) {
		extra = append(extra, fmt.Sprintf("file names device %q, expected %q", res.Device, *serial))
	}
	if *tail != 0 && uint(res.Last) != *tail {
		extra = append(extra, fmt.Sprintf(
			"the file ends at entry %d but should reach %d: %d record(s) were removed from the end, "+
				"which the chain alone cannot show — a truncated chain is still a valid chain",
			res.Last, *tail, int(*tail)-int(res.Last)))
	}

	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
			return err
		}
	} else {
		printLogFileResult(res, *tail != 0, *anchor != "")
		for _, e := range extra {
			fmt.Printf("  ! %s\n", e)
		}
	}

	if err := res.Err(); err != nil {
		return err
	}
	if len(extra) > 0 {
		return fmt.Errorf("hsm-audit verify-file: %s", strings.Join(extra, "; "))
	}
	if *strict && !res.Continuous {
		return fmt.Errorf("hsm-audit verify-file: the file documents %d gap(s) in its own coverage; "+
			"the entries inside them are only in the database", len(res.Gaps))
	}
	return nil
}

func printLogFileResult(res *hsmaudit.LogFileResult, checkedTail, checkedAnchor bool) {
	fmt.Printf("File:            %s\n", res.Path)
	fmt.Printf("Device:          %s\n", orNone(res.Device))
	fmt.Printf("Records:         %d (%d device log entr(ies), %d signature(s))\n",
		res.Records, res.Entries, res.Signatures)
	if res.Entries > 0 {
		fmt.Printf("Entry range:     %d - %d\n", res.First, res.Last)
	}
	if res.FromGenesis {
		fmt.Println("Coverage:        from the device-init sentinel (the device's whole history)")
		fmt.Printf("Anchor:          %s\n", res.Anchor)
	} else {
		fmt.Println("Coverage:        a suffix of the device history (this file does not start at a factory reset)")
	}
	for _, g := range res.Gaps {
		fmt.Printf("  gap:           after entry %d, next entry %d — %s\n", g.After, g.Before, g.Reason)
	}
	for _, p := range res.Problems {
		if p.Number != 0 {
			fmt.Printf("  PROBLEM:       entry %d: %s (%s)\n", p.Number, p.Detail, p.Kind)
			continue
		}
		fmt.Printf("  PROBLEM:       %s (%s)\n", p.Detail, p.Kind)
	}
	switch {
	case !res.OK:
		fmt.Println("Verdict:         FAILED — this file is not a faithful copy of the device log")
	case res.Continuous:
		fmt.Println("Verdict:         OK — every record chains, with no gaps")
	default:
		fmt.Printf("Verdict:         OK — every record chains, but the file documents %d gap(s)\n", len(res.Gaps))
	}
	if res.OK && !checkedTail {
		fmt.Println("Note:             this checks the file against itself. Records removed from the *end* leave a")
		fmt.Println("                  shorter chain that still verifies, so pass -tail with the collection tail the")
		fmt.Println("                  CA reports, and keep the file append-only (`chattr +a`) on the CA host.")
	}
	if res.OK && !checkedAnchor && res.FromGenesis {
		fmt.Println("Note:             no -anchor was supplied, so the chain was checked for internal consistency")
		fmt.Println("                  only. Pass the anchor pinned when the device was commissioned to establish")
		fmt.Println("                  that this is that device's history rather than some other consistent one.")
	}
}

func orNone(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return s
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

// cmdHSMAuditCommit obtains one device-signed, timestamped binding of the audit
// head to the device serial on demand.
//
// The background job on the server is what keeps a deployment bound; this exists
// for commissioning — so the very first export carries a commitment rather than
// none — and for an operator who needs to demonstrate during an incident that the
// device in front of them is the one the log describes.
func cmdHSMAuditCommit(ctx context.Context, svc *hsmaudit.Service, db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-audit commit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ts, cleanup, err := buildFreshnessTimestamperCLI(db, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	// A non-nil commitment with a non-nil error means the binding was made and
	// recorded but could not be dated, or left the device untidy. Reporting it and
	// exiting non-zero is right; hiding the commitment would not be, since the
	// device has already written the log entries that produced it.
	c, err := svc.Commit(ctx, ts)
	if c == nil {
		return err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
	}
	if *asJSON {
		if encErr := json.NewEncoder(os.Stdout).Encode(c); encErr != nil {
			return encErr
		}
		return err
	}
	if c.GenTime.IsZero() {
		fmt.Printf("Device %s signed a commitment to the audit head, but it is UNDATED.\n", c.Head.DeviceSerial)
	} else {
		src := c.Source
		if src == "" {
			src = "the internal TSA (signs with the HSM under audit)"
		}
		fmt.Printf("Device %s signed a commitment to the audit head, dated %s by %s.\n",
			c.Head.DeviceSerial, c.GenTime.Format(time.RFC3339), src)
	}
	fmt.Printf("  log entry %d, %d signature(s), ledger seq %d\n",
		c.Head.DeviceNumber, c.Head.Signatures, c.Head.LedgerSeq)
	fmt.Printf("  commitment label %s (attested on object 0x%04x)\n", c.Label, c.ObjectID)
	fmt.Printf("  head digest %s, token %d bytes DER\n", c.Head.Digest(), len(c.Token))
	fmt.Println()
	fmt.Println("The device's factory attestation key signed that label, and its certificate carries")
	fmt.Println("the serial as a device assertion chaining to Yubico's attestation PKI. This is what")
	fmt.Println("connects the exported log to real hardware: the log's own entries carry no serial")
	fmt.Println("number and no signature, so on their own they show only internal consistency.")
	return err
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
	b, report, err := svc.ExportWithReport(ctx)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// Attestation failures go to stderr rather than into the bundle: a verifier
	// must reach its verdict from the evidence, not from the audited party's
	// account of why a piece of it is missing. The operator still needs to know,
	// because such a bundle will be refused.
	printExportWarnings(report)
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
	fmt.Printf("Wrote %s (%d device log entr(ies), %d ledger entr(ies), %d key attestation(s), %d device commitment(s)).\n",
		*out, len(b.LogEntries), len(b.Ledger), len(b.KeyAttestations), len(b.Commitments))
	fmt.Printf("Bundle fingerprint: %s\n", fp)
	return nil
}

func printExportWarnings(report *hsmaudit.ExportReport) {
	if report == nil {
		return
	}
	ids := make([]uint16, 0, len(report.AttestationErrors))
	for id := range report.AttestationErrors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		fmt.Fprintf(os.Stderr, "WARNING: could not attest key 0x%04x: %s\n", id, report.AttestationErrors[id])
	}
	if len(ids) > 0 {
		fmt.Fprintln(os.Stderr, "A bundle missing an attestation for a key that signed cannot show that key is")
		fmt.Fprintln(os.Stderr, "confined to the HSM, and verification will refuse it.")
	}
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
	var keyPaths repeatedFlag
	fs.Var(&keyPaths, "key", "certificate or public key to prove; repeatable")
	attestRoots := fs.String("attest-roots", "", "PEM file of YubiHSM attestation trust anchors")
	requireAnchoredAttestation := fs.Bool("require-anchored-attestation", true,
		"fail unless each device attestation certificate chains to a trusted attestation root; =false to opt out")
	allowUnattested := fs.Bool("allow-unattested-keys", false,
		"report rather than fail when a key that signed is not attested")
	allowUnbound := fs.Bool("allow-unbound-log", false,
		"report rather than fail when no device-signed commitment binds the log to the device it names")
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
		ExpectedAnchor:      *expectedAnchor,
		ExpectedSerial:      *serial,
		SkipFreshness:       *skipFreshness,
		AllowUnattestedKeys: *allowUnattested,
		AllowUnboundLog:     *allowUnbound,
		Freshness: hsmaudit.FreshnessOptions{
			// A -max-age of 0 means "report but do not fail", which
			// FreshnessOptions spells as a negative duration (its own zero
			// selects the default).
			MaxAge:                orZero(*maxAge),
			RequireIndependentTSA: *requireExternalTSA,
		},
	}
	for _, path := range keyPaths {
		key, err := readExpectedKey(path)
		if err != nil {
			return err
		}
		opts.ExpectedKeys = append(opts.ExpectedKeys, key)
	}
	if *attestRoots != "" || *requireAnchoredAttestation {
		pol := hsmattest.DefaultPolicy()
		pol.RequireAnchoredChain = *requireAnchoredAttestation
		if *attestRoots != "" {
			roots, inter, err := hsmattest.LoadRoots([]string{*attestRoots})
			if err != nil {
				return fmt.Errorf("reading -attest-roots: %w", err)
			}
			pol.Roots, pol.Intermediates = roots, inter
		}
		opts.AttestationPolicy = &pol
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
		attested := map[uint16]*hsmaudit.AttestedKey{}
		if res.Attestations != nil {
			for _, a := range res.Attestations.Keys {
				attested[a.ObjectID] = a
			}
		}
		for _, k := range res.Reconciliation.Keys {
			label := k.KeyLabel
			if label == "" {
				label = "(unlabelled)"
			}
			status := "balanced"
			if !k.Balanced {
				status = fmt.Sprintf("SURPLUS %+d", k.Surplus)
			}
			// The confinement column is the point of the per-key view: a
			// balanced count for a key that is not shown to live in the HSM
			// bounds the device's activity, not the key's.
			confinement := "NOT ATTESTED"
			if a := attested[k.KeyID]; a != nil {
				switch {
				case !a.OK:
					confinement = "ATTESTATION FAILED"
				case a.Attestation.IsGeneratedOnDevice():
					confinement = "in-HSM, generated"
				default:
					confinement = "in-HSM"
				}
			}
			fmt.Printf("  key 0x%04x %-24s device %3d  ledger %3d  %-9s  %s\n",
				k.KeyID, label, k.DeviceSignatures, k.LedgerSignatures, status, confinement)
		}
		fmt.Println()
	}
	for _, k := range res.Keys {
		printKeyProof(k)
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
	// The provenance line is deliberately next to the freshness one: they are the
	// two halves of the same statement, and reading either alone overstates what
	// it shows.
	if c := res.Commitments; c != nil {
		switch {
		case c.Commitments == 0:
			fmt.Println("Device binding: NONE — no HSM has signed for this log, so the serial it names is the CA's claim.")
		case c.Verified == 0 && c.Undated == c.Commitments:
			fmt.Printf("Device binding: UNDATED — %d binding(s) present, none dated, so none bounds anything in time.\n",
				c.Commitments)
		case c.Verified == 0:
			fmt.Printf("Device binding: NOT ESTABLISHED — %d commitment(s) present, none verified.\n", c.Commitments)
		case c.Stale:
			fmt.Printf("Device binding: STALE — device %s last signed for this log at %s (%s ago).\n",
				c.DeviceSerial, c.NewestGenTime.Format(time.RFC3339), c.Age.Round(time.Second))
		default:
			fmt.Printf("Device binding: device %s signed for this log at %s (%s ago), %d/%d commitment(s) verified",
				c.DeviceSerial, c.NewestGenTime.Format(time.RFC3339), c.Age.Round(time.Second),
				c.Verified, c.Commitments)
			if c.TrustAnchor != "" {
				fmt.Printf(", anchored to %q", c.TrustAnchor)
			}
			fmt.Println(".")
		}
		for _, n := range c.Notes {
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
	if len(opts.ExpectedKeys) == 0 && res.OK {
		fmt.Println("NOTE: no public key supplied (-key). The bundle accounts for every key the device")
		fmt.Println("attests to holding, but says nothing about whether any particular key you hold —")
		fmt.Println("the one in a CA certificate, say — is among them.")
		fmt.Println()
	}
	for _, f := range res.Findings {
		fmt.Printf("  - %s\n", f)
	}
}

// printKeyProof renders the answer to "has this key signed anything that was
// not published", spelling out each link of the argument rather than only its
// conclusion — an auditor needs to see which step would have caught what.
func printKeyProof(k *hsmaudit.KeyProofResult) {
	name := k.Name
	if name == "" {
		name = k.SPKIFingerprint
	}
	fmt.Printf("Key %s\n", name)
	fmt.Printf("  Public key:       %s\n", k.SPKIFingerprint)
	if k.Key == nil {
		fmt.Printf("  Attested:         NO — this bundle does not show that key lives in the device\n")
	} else {
		a := k.Key
		fmt.Printf("  On-device handle: 0x%04x%s\n", a.ObjectID, labelParens(a.KeyLabel))
		fmt.Printf("  Non-exportable:   %s\n", yesNo(a.Attestation.IsNonExportable()))
		fmt.Printf("  Generated in HSM: %s\n", yesNo(a.Attestation.IsGeneratedOnDevice()))
		fmt.Printf("  Device-signed:    %s\n", yesNo(a.Attestation.IsDeviceBound()))
		fmt.Printf("  Chain anchored:   %s\n", yesNo(a.Attestation.IsChainAnchored()))
		if a.Lifecycle != nil {
			fmt.Printf("  Handle history:   %s\n", describeLifecycle(a.Lifecycle))
		}
		fmt.Printf("  Signatures:       device %d, accounted for %d\n", a.DeviceSignatures, a.LedgerSignatures)
		if p := k.Published; p != nil {
			fmt.Printf("  Published match:  %d of %d\n", p.Matched, p.Matched+len(p.Unpublished))
		}
		for _, w := range a.Attestation.Warnings {
			fmt.Printf("  WARNING: %s\n", w)
		}
	}
	fmt.Printf("  %s\n", k.Summary)
	for _, f := range k.Findings {
		fmt.Printf("    - %s\n", f)
	}
	fmt.Println()
}

func describeLifecycle(lc *hsmaudit.KeyLifecycle) string {
	if !lc.OK {
		return strings.Join(lc.Findings, "; ")
	}
	if len(lc.Generated) == 1 {
		return fmt.Sprintf("generated on-device at log entry %d, never deleted or exported", lc.Generated[0].Entry)
	}
	return "created once, never deleted or exported"
}

func labelParens(label string) string {
	if label == "" {
		return ""
	}
	return " (" + label + ")"
}

// repeatedFlag collects a flag given more than once, so an auditor can prove
// several keys against one bundle in a single run.
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatedFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

// readExpectedKey loads a public key to prove, from a certificate or a bare
// public key. Naming the result after the file keeps a multi-key report
// readable without the auditor having to match fingerprints by eye.
func readExpectedKey(path string) (hsmaudit.ExpectedKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return hsmaudit.ExpectedKey{}, fmt.Errorf("reading -key %s: %w", path, err)
	}
	pub, err := publicKeyFromPEM(raw)
	if err != nil {
		return hsmaudit.ExpectedKey{}, fmt.Errorf("-key %s: %w", path, err)
	}
	return hsmaudit.ExpectedKey{Name: filepath.Base(path), PublicKey: pub}, nil
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
