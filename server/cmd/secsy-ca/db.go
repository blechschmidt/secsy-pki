package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// cmdDB dispatches the `db` subcommand group for persistence administration.
func cmdDB(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		dbUsage()
		return fmt.Errorf("db: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "migrate":
		return cmdDBMigrate(cfg, rest)
	case "verify":
		return cmdDBVerify(cfg, rest)
	case "help", "-h", "--help":
		dbUsage()
		return nil
	default:
		dbUsage()
		return fmt.Errorf("db: unknown subcommand %q", sub)
	}
}

func dbUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca db — persistence backend administration

Usage: secsy-ca db <subcommand> [flags]

Subcommands:
  migrate   Copy an existing store into another backend (e.g. SQLite file → PostgreSQL)
  verify    Check store integrity (audit chain, serial/CRL monotonicity, revocation
            consistency) and print a continuity fingerprint. HSM-independent.

Run "secsy-ca db migrate -h" for migration flags.
`)
}

// cmdDBVerify runs the HSM-independent store-integrity checks and prints a
// continuity fingerprint. It is the disaster-recovery post-restore gate: it
// confirms the hash-chained audit log is intact, the per-CA serial and CRL
// counters have not been rewound behind already-issued artifacts, and the
// inventory and revocation store agree. The fingerprint (in -json mode) is meant
// to be captured before a backup and compared after a point-in-time restore to
// prove no committed state was lost or rewound.
//
// It exits non-zero if any invariant fails, so a DR drill or CI job can trip on
// it. It reads the store configured for the current node; use -driver/-dsn to
// point it at a restored database instead.
func cmdDBVerify(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("db verify", flag.ContinueOnError)
	driver := fs.String("driver", "", "database driver to check (default: the configured database)")
	dsn := fs.String("dsn", "", "database DSN to check (default: the configured database)")
	asJSON := fs.Bool("json", false, "emit the full result (including the fingerprint) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	drv := *driver
	src := *dsn
	if drv == "" {
		drv = cfg.Database.Driver
	}
	if src == "" && (drv == cfg.Database.Driver || (drv == "sqlite" && cfg.Database.Driver == "sqlite3")) {
		src = cfg.Database.DSN
	}
	if src == "" {
		return fmt.Errorf("db verify: -dsn is required (no matching configured database to default from)")
	}

	db, err := database.New(drv, src)
	if err != nil {
		return fmt.Errorf("opening %s store: %w", drv, err)
	}
	defer db.Close()

	res, err := db.VerifyStoreIntegrity()
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		for _, c := range res.Checks {
			mark := "✓"
			if !c.OK {
				mark = "✗"
			}
			fmt.Printf("  %s %-24s %s\n", mark, c.Name, c.Detail)
		}
		fp := res.Fingerprint
		fmt.Printf("\nfingerprint: events=%d issued=%d revoked=%d sum_next_serial=%d sum_next_crl=%d head=%s\n",
			fp.AuditEventCount, fp.IssuedCerts, fp.RevokedCerts, fp.SumNextSerial, fp.SumNextCRLNumber, shortHash(fp.AuditHeadHash))
		if res.OK {
			fmt.Println("\nstore integrity OK")
		} else {
			fmt.Println("\nstore integrity FAILED")
		}
	}

	if !res.OK {
		return fmt.Errorf("store integrity verification failed")
	}
	return nil
}

// shortHash abbreviates a hex hash for human-readable output.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	if h == "" {
		return "(empty log)"
	}
	return h
}

// cmdDBMigrate copies a file-backed SQLite store into a target database
// (typically PostgreSQL) so a single-node deployment can move to a shared,
// multi-replica backend. It preserves the hash-chained audit log's
// tamper-evidence and the monotonic serial/CRL counters, and verifies the audit
// chain on the destination before reporting success.
func cmdDBMigrate(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("db migrate", flag.ContinueOnError)
	fromDriver := fs.String("from-driver", "sqlite", "source database driver (sqlite|postgres)")
	fromDSN := fs.String("from-dsn", "", "source DSN (default: the configured database, when it is the source driver)")
	toDriver := fs.String("to-driver", "postgres", "destination database driver (sqlite|postgres)")
	toDSN := fs.String("to-dsn", "", "destination DSN (required)")
	maxOpen := fs.Int("dest-max-open-conns", 0, "destination pool: max open connections (0 = default)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Default the source DSN to the configured database when the drivers match,
	// so the common case ("migrate my running node's DB") needs only -to-dsn.
	srcDSN := *fromDSN
	if srcDSN == "" {
		if *fromDriver == cfg.Database.Driver || (*fromDriver == "sqlite" && cfg.Database.Driver == "sqlite3") {
			srcDSN = cfg.Database.DSN
		}
	}
	if srcDSN == "" {
		return fmt.Errorf("db migrate: -from-dsn is required (no matching configured database to default from)")
	}
	if *toDSN == "" {
		return fmt.Errorf("db migrate: -to-dsn is required")
	}
	if *fromDriver == *toDriver && srcDSN == *toDSN {
		return fmt.Errorf("db migrate: source and destination are identical")
	}

	fmt.Fprintf(os.Stderr, "Opening source %s store...\n", *fromDriver)
	src, err := database.New(*fromDriver, srcDSN)
	if err != nil {
		return fmt.Errorf("opening source database: %w", err)
	}
	defer src.Close()

	fmt.Fprintf(os.Stderr, "Opening destination %s store...\n", *toDriver)
	dst, err := database.NewWithOptions(*toDriver, *toDSN, database.PoolOptions{MaxOpenConns: *maxOpen})
	if err != nil {
		return fmt.Errorf("opening destination database: %w", err)
	}
	defer dst.Close()

	// A generous ceiling: even large inventories copy in seconds-to-minutes, and
	// the operator can re-run after fixing connectivity if it is exceeded.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	fmt.Fprintln(os.Stderr, "Copying store (this preserves the audit chain and monotonic counters)...")
	report, err := database.MigrateStore(ctx, src, dst)
	if err != nil {
		return err
	}

	printMigrationReport(report)
	return nil
}

func printMigrationReport(r *database.MigrationReport) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "\nMigration %s -> %s complete.\n\n", r.SourceDrv, r.DestDrv)
	fmt.Fprintln(tw, "TABLE\tROWS")
	for _, t := range r.Tables {
		fmt.Fprintf(tw, "%s\t%d\n", t.Table, t.Rows)
	}
	fmt.Fprintf(tw, "%s\t%d\n", "TOTAL", r.TotalRows)
	tw.Flush()
	fmt.Printf("\nAudit chain verified on destination: %d events, intact=%v\n", r.ChainCount, r.ChainValid)
}
