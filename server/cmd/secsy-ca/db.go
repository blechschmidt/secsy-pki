package main

import (
	"context"
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

Run "secsy-ca db migrate -h" for migration flags.
`)
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
