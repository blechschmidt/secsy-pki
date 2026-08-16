package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/ers"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// cmdErs dispatches the "ers" subcommands (RFC 4998 Evidence Records, Task 161).
// verify/export/list never touch key material; generate/renew build the TSA key
// provider lazily and only when the internal TSA is the archive-timestamp source.
func cmdErs(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		ersUsage()
		return fmt.Errorf("ers: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "generate":
		return cmdErsGenerate(db, cfg, rest)
	case "renew":
		return cmdErsRenew(db, cfg, rest)
	case "verify":
		return cmdErsVerify(db, rest)
	case "export":
		return cmdErsExport(db, rest)
	case "list":
		return cmdErsList(db, rest)
	case "help", "-h", "--help":
		ersUsage()
		return nil
	default:
		ersUsage()
		return fmt.Errorf("ers: unknown subcommand %q", sub)
	}
}

func ersUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca ers — RFC 4998 Evidence Records (long-term preservation)

Usage:
  secsy-ca ers generate (-audit-from N -audit-to M | FILE...) [-hash sha256|sha384|sha512] [-description STR] [-json]
      Mint an Evidence Record over a range of audit events, or over one or more
      artifact files. Needs the internal TSA (or ers.tsa_url).

  secsy-ca ers renew -id RECORD [-hashtree [-hash sha256|sha384|sha512]] [FILE...] [-json]
      Renew a record. Default is a time-stamp renewal (before the TSA certificate
      expires). -hashtree performs a hash-tree renewal to a stronger algorithm
      (on algorithm deprecation). Audit-scope records re-derive their events;
      artifact-scope records need the original FILE(s) for a hash-tree renewal.

  secsy-ca ers verify -id RECORD [-tsa-ca FILE] [FILE...] [-json]
  secsy-ca ers verify -in RECORD.der FILE... [-tsa-ca FILE] [-json]
      Verify a stored record (re-deriving audit events, or against the given
      artifact FILE(s)), or a standalone Evidence Record DER. Exits non-zero on
      failure. HSM-free.

  secsy-ca ers export -id RECORD [-out FILE] [-json]
      Write the Evidence Record DER to -out (or print its structure). HSM-free.

  secsy-ca ers list [-json]
      List stored Evidence Records. HSM-free.
`)
}

// cmdErsGenerate mints a new Evidence Record.
func cmdErsGenerate(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("ers generate", flag.ContinueOnError)
	auditFrom := fs.Int64("audit-from", 0, "first audit event seq to preserve (with -audit-to)")
	auditTo := fs.Int64("audit-to", 0, "last audit event seq to preserve (with -audit-from)")
	hashName := fs.String("hash", "", "hash-tree algorithm: sha256|sha384|sha512 (default from ers.hash, else sha256)")
	description := fs.String("description", "", "human label for the record")
	jsonOut := fs.Bool("json", false, "emit the record as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()

	auditMode := *auditFrom != 0 || *auditTo != 0
	if auditMode && len(files) > 0 {
		return fmt.Errorf("give either an audit range or artifact files, not both")
	}
	if !auditMode && len(files) == 0 {
		fs.Usage()
		return fmt.Errorf("nothing to preserve: give -audit-from/-audit-to or one or more artifact files")
	}

	hash := resolveErsHash(cfg, *hashName)
	if hash == 0 {
		return fmt.Errorf("unsupported -hash %q (use sha256|sha384|sha512)", *hashName)
	}

	ts, cleanup, err := buildErsTimestamperCLI(db, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	svc := ers.NewService(db, ts, ers.Options{Hash: hash}).WithActor("secsy-ca-cli")
	ctx := context.Background()

	var rec *models.EvidenceRecord
	if auditMode {
		if *auditFrom == 0 || *auditTo == 0 {
			return fmt.Errorf("-audit-from and -audit-to must be given together")
		}
		rec, err = svc.GenerateAuditRange(ctx, *auditFrom, *auditTo)
	} else {
		objs := make([]ers.DataObject, 0, len(files))
		for _, f := range files {
			data, rerr := readInput(f)
			if rerr != nil {
				return fmt.Errorf("reading %s: %w", f, rerr)
			}
			objs = append(objs, ers.DataObject{ID: f, Bytes: data})
		}
		desc := *description
		if desc == "" {
			desc = fmt.Sprintf("%d artifact(s)", len(files))
		}
		rec, err = svc.GenerateArtifact(ctx, desc, objs)
	}
	if err != nil {
		return err
	}
	return emitErsRecord(rec, *jsonOut, "generated")
}

// cmdErsRenew renews a stored record.
func cmdErsRenew(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("ers renew", flag.ContinueOnError)
	id := fs.String("id", "", "record id to renew (required)")
	hashTree := fs.Bool("hashtree", false, "perform a hash-tree renewal (new chain, stronger hash) instead of a time-stamp renewal")
	hashName := fs.String("hash", "", "target hash for -hashtree: sha256|sha384|sha512 (default from ers.hash, else sha512)")
	jsonOut := fs.Bool("json", false, "emit the renewed record as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		fs.Usage()
		return fmt.Errorf("-id is required")
	}
	rec, err := db.GetEvidenceRecord(*id)
	if err != nil {
		return fmt.Errorf("looking up record: %w", err)
	}
	if rec == nil {
		return fmt.Errorf("no evidence record with id %s", *id)
	}
	er, err := ers.Parse(rec.Record)
	if err != nil {
		return fmt.Errorf("parsing stored record: %w", err)
	}

	ts, cleanup, err := buildErsTimestamperCLI(db, cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx := context.Background()

	var renewed *ers.EvidenceRecord
	kind := "timestamp"
	if *hashTree {
		kind = "hashtree"
		var target crypto.Hash
		if *hashName != "" {
			target = ers.HashByName(*hashName)
			if target == 0 {
				return fmt.Errorf("unsupported -hash %q (use sha256|sha384|sha512)", *hashName)
			}
		} else {
			target = ersDefaultHashTreeTarget(cfg)
		}
		objs, oerr := ersRenewObjects(db, *rec, fs.Args())
		if oerr != nil {
			return oerr
		}
		renewed, err = er.RenewHashTree(ctx, ts, objs, target)
	} else {
		renewed, err = er.RenewTimestamp(ctx, ts)
	}
	if err != nil {
		return err
	}

	if err := ers.RefreshRow(rec, renewed, time.Now()); err != nil {
		return err
	}
	if err := db.UpdateEvidenceRecord(rec); err != nil {
		return fmt.Errorf("updating record: %w", err)
	}
	appendErsAudit(db, audit.ActionERSRenew, rec.ID, fmt.Sprintf("kind=%s chains=%d hash=%s", kind, rec.Chains, rec.DigestAlg))
	return emitErsRecord(rec, *jsonOut, "renewed ("+kind+")")
}

// cmdErsVerify verifies a stored record or a standalone Evidence Record DER.
func cmdErsVerify(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("ers verify", flag.ContinueOnError)
	id := fs.String("id", "", "stored record id to verify")
	in := fs.String("in", "", "path to a standalone Evidence Record DER to verify")
	tsaCA := fs.String("tsa-ca", "", "PEM file with TSA trust anchor(s) the archive timestamps must chain to")
	jsonOut := fs.Bool("json", false, "emit the verification result as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*id == "") == (*in == "") {
		fs.Usage()
		return fmt.Errorf("give exactly one of -id or -in")
	}

	roots, err := loadTSARoots(*tsaCA)
	if err != nil {
		return err
	}

	var er *ers.EvidenceRecord
	var objs []ers.DataObject
	files := fs.Args()

	if *id != "" {
		rec, gerr := db.GetEvidenceRecord(*id)
		if gerr != nil {
			return fmt.Errorf("looking up record: %w", gerr)
		}
		if rec == nil {
			return fmt.Errorf("no evidence record with id %s", *id)
		}
		er, err = ers.Parse(rec.Record)
		if err != nil {
			return fmt.Errorf("parsing stored record: %w", err)
		}
		if rec.Scope == ers.ScopeAudit && len(files) == 0 {
			// Re-derive the covered audit events from the log.
			svc := ers.NewService(db, nil, ers.Options{})
			objs, err = svc.ResolveObjects(*rec)
			if err != nil {
				return err
			}
		} else {
			objs, err = readObjectFiles(files)
			if err != nil {
				return err
			}
		}
	} else {
		der, rerr := readInput(*in)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", *in, rerr)
		}
		er, err = ers.Parse(der)
		if err != nil {
			return err
		}
		objs, err = readObjectFiles(files)
		if err != nil {
			return err
		}
	}

	res, err := ers.Verify(er, ers.VerifyOptions{Objects: objs, Roots: roots})
	if err != nil {
		return err
	}
	if *jsonOut {
		if err := emitErsJSON(res); err != nil {
			return err
		}
	} else {
		printErsVerify(res)
	}
	if !res.Valid {
		return fmt.Errorf("evidence record verification failed: %s", res.Reason)
	}
	return nil
}

// cmdErsExport writes an Evidence Record DER or prints its structure.
func cmdErsExport(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("ers export", flag.ContinueOnError)
	id := fs.String("id", "", "record id to export (required)")
	outPath := fs.String("out", "", "write the Evidence Record DER to this file (default: print structure)")
	jsonOut := fs.Bool("json", false, "emit the record structure as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		fs.Usage()
		return fmt.Errorf("-id is required")
	}
	rec, err := db.GetEvidenceRecord(*id)
	if err != nil {
		return fmt.Errorf("looking up record: %w", err)
	}
	if rec == nil {
		return fmt.Errorf("no evidence record with id %s", *id)
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, rec.Record, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", *outPath, err)
		}
		fmt.Printf("wrote %d bytes of Evidence Record DER to %s\n", len(rec.Record), *outPath)
		return nil
	}
	er, err := ers.Parse(rec.Record)
	if err != nil {
		return err
	}
	if *jsonOut {
		return emitErsJSON(er.Info())
	}
	printErsInfo(*rec, er.Info())
	return nil
}

// cmdErsList lists stored records.
func cmdErsList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("ers list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the records as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	records, _, err := db.ListEvidenceRecords(0, 0)
	if err != nil {
		return err
	}
	if *jsonOut {
		if records == nil {
			records = []models.EvidenceRecord{}
		}
		return emitErsJSON(records)
	}
	if len(records) == 0 {
		fmt.Println("No evidence records stored.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSCOPE\tHASH\tCHAINS\tOBJECTS\tCREATED\tRENEWED\tTSA EXPIRES\tDESCRIPTION")
	for _, r := range records {
		renewed := "-"
		if r.RenewedAt != nil {
			renewed = r.RenewedAt.Format("2006-01-02")
		}
		tsaExp := "-"
		if r.TSANotAfter != nil {
			tsaExp = r.TSANotAfter.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
			r.ID, r.Scope, r.DigestAlg, r.Chains, len(r.ObjectIDs),
			r.CreatedAt.Format("2006-01-02"), renewed, tsaExp, r.Description)
	}
	return tw.Flush()
}

// ---- shared helpers -------------------------------------------------------

// emitErsJSON writes v as indented JSON with a trailing newline (the cliout-free
// convention used by the other secsy-ca commands).
func emitErsJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(b); err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte("\n"))
	return err
}

// buildErsTimestamperCLI selects the archive-timestamp source for the CLI: the
// configured external TSA URL, else an in-process authority over the TSA-role key
// provider (constructed lazily, so verify/export/list never need the HSM).
func buildErsTimestamperCLI(db *database.DB, cfg *config.Config) (ers.Timestamper, func(), error) {
	noop := func() {}
	if url := cfg.Ers.TSAURL; url != "" {
		return ers.NewHTTPTimestamper(url, time.Duration(cfg.Ers.TimeoutSeconds)*time.Second), noop, nil
	}
	if cfg.TSA.KeyLabel == "" || cfg.TSA.CertificateFile == "" {
		return nil, noop, fmt.Errorf("evidence records need a timestamp source: configure ers.tsa_url (external TSA) or the internal tsa: block (key_label + certificate_file; provision with 'secsy-ca tsa-key')")
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
	return ers.NewAuthorityTimestamper(authority), func() { provider.Close() }, nil
}

// ersRenewObjects reconstructs the objects for a hash-tree renewal: audit-scope
// records re-derive from the event log; artifact-scope records need the original
// files.
func ersRenewObjects(db *database.DB, rec models.EvidenceRecord, files []string) ([]ers.DataObject, error) {
	if rec.Scope == ers.ScopeAudit && len(files) == 0 {
		svc := ers.NewService(db, nil, ers.Options{})
		return svc.ResolveObjects(rec)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("a hash-tree renewal of a %q-scope record needs the original artifact file(s)", rec.Scope)
	}
	return readObjectFiles(files)
}

// readObjectFiles reads each path (or '-' for stdin) as a protected data object.
func readObjectFiles(paths []string) ([]ers.DataObject, error) {
	objs := make([]ers.DataObject, 0, len(paths))
	for _, p := range paths {
		data, err := readInput(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		objs = append(objs, ers.DataObject{ID: p, Bytes: data})
	}
	return objs, nil
}

// resolveErsHash resolves a hash name to a crypto.Hash, defaulting to the
// configured ers.hash (or SHA-256).
func resolveErsHash(cfg *config.Config, name string) crypto.Hash {
	if name == "" {
		name = cfg.Ers.ResolvedHash()
	}
	return ers.HashByName(name)
}

// ersDefaultHashTreeTarget picks the default hash-tree-renewal target: the
// configured ers.hash if stronger than SHA-256, else SHA-512.
func ersDefaultHashTreeTarget(cfg *config.Config) crypto.Hash {
	h := ers.HashByName(cfg.Ers.ResolvedHash())
	if h != 0 && h != crypto.SHA256 {
		return h
	}
	return crypto.SHA512
}

// loadTSARoots parses an optional PEM file of TSA trust anchors.
func loadTSARoots(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading -tsa-ca %s: %w", path, err)
	}
	var roots []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parsing -tsa-ca: %w", perr)
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("-tsa-ca %s contains no certificates", path)
	}
	return roots, nil
}

// appendErsAudit records an ers.* event from the CLI, best-effort.
func appendErsAudit(db *database.DB, action, target, detail string) {
	_ = db.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      "secsy-ca-cli",
		ActorRoles: "system",
		Action:     action,
		Target:     target,
		Result:     audit.ResultSuccess,
		Detail:     detail,
	})
}

// emitErsRecord prints a freshly generated/renewed record.
func emitErsRecord(rec *models.EvidenceRecord, asJSON bool, verb string) error {
	if asJSON {
		return emitErsJSON(rec)
	}
	fmt.Printf("%s evidence record %s\n", verb, rec.ID)
	fmt.Printf("  scope=%s hash=%s chains=%d objects=%d\n", rec.Scope, rec.DigestAlg, rec.Chains, len(rec.ObjectIDs))
	if rec.Scope == ers.ScopeAudit {
		fmt.Printf("  audit events: %d-%d\n", rec.FirstSeq, rec.LastSeq)
	}
	fmt.Printf("  newest archive timestamp gen_time=%s\n", rec.LastGenTime.Format(time.RFC3339))
	if rec.TSANotAfter != nil {
		fmt.Printf("  TSA certificate expires %s\n", rec.TSANotAfter.Format(time.RFC3339))
	}
	return nil
}

// printErsVerify renders a verification result for humans.
func printErsVerify(res *ers.VerifyResult) {
	status := "VALID"
	if !res.Valid {
		status = "INVALID"
	}
	fmt.Printf("evidence record: %s\n", status)
	if res.Reason != "" {
		fmt.Printf("  reason: %s\n", res.Reason)
	}
	fmt.Printf("  chains: %d  first_gen=%s  latest_gen=%s\n",
		len(res.Chains), res.FirstGenTime.Format(time.RFC3339), res.LatestGenTime.Format(time.RFC3339))
	for _, c := range res.Chains {
		v := "ok"
		if !c.Valid {
			v = "FAILED: " + c.Reason
		}
		fmt.Printf("  chain %d [%s, %d timestamp(s)]: %s\n", c.Index, c.Hash, c.Timestamps, v)
	}
	if len(res.Objects) > 0 {
		covered := 0
		for _, o := range res.Objects {
			if o.Covered {
				covered++
			}
		}
		fmt.Printf("  objects: %d/%d covered\n", covered, len(res.Objects))
		for _, o := range res.Objects {
			if !o.Covered {
				fmt.Printf("    NOT COVERED: %s (%s)\n", o.ID, o.Reason)
			}
		}
	}
}

// printErsInfo renders a record's structure.
func printErsInfo(rec models.EvidenceRecord, info ers.Info) {
	fmt.Printf("evidence record %s\n", rec.ID)
	fmt.Printf("  scope=%s description=%q\n", rec.Scope, rec.Description)
	if rec.Scope == ers.ScopeAudit {
		fmt.Printf("  audit events: %d-%d (%d objects)\n", rec.FirstSeq, rec.LastSeq, len(rec.ObjectIDs))
	} else {
		fmt.Printf("  objects: %d\n", len(rec.ObjectIDs))
	}
	fmt.Printf("  version=%d chains=%d digest_algorithms=%v current=%s\n",
		info.Version, info.Chains, info.DigestAlgorithms, info.CurrentHash)
	fmt.Printf("  first_gen=%s latest_gen=%s\n",
		info.FirstGenTime.Format(time.RFC3339), info.LatestGenTime.Format(time.RFC3339))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  CHAIN\tINDEX\tHASH\tGEN TIME\tTSA EXPIRES\tTSA SUBJECT")
	for _, ts := range info.Timestamps {
		exp := "-"
		if !ts.TSANotAfter.IsZero() {
			exp = ts.TSANotAfter.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "  %d\t%d\t%s\t%s\t%s\t%s\n",
			ts.Chain, ts.Index, ts.Hash, ts.GenTime.Format(time.RFC3339), exp, ts.TSASubject)
	}
	_ = tw.Flush()
}
