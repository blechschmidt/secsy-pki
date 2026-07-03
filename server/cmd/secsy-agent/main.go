// Command secsy-agent is the host auto-enrollment agent: it keeps local
// host/service certificates fresh by enrolling against a secsy-pki server's
// EST or ACME endpoints, with keys generated locally that never leave the
// host.
//
// Usage:
//
//	secsy-agent [-config /etc/secsy/agent.yaml] <command>
//
// Commands:
//
//	run      daemon mode: evaluate and renew continuously
//	once     single pass; exit 0 = nothing to do, 2 = work done, 1 = error
//	status   print tracked certificates and next renewals as JSON
//	version  print the build version
//
// The `once` exit codes are cron/systemd-timer friendly: treat 0 and 2 as
// success (systemd: SuccessExitStatus=2), alert on 1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/blechschmidt/secsy-pki/server/internal/agent"
)

// Exit codes of the `once` command.
const (
	exitOK       = 0 // pass succeeded, nothing needed renewing
	exitError    = 1 // at least one certificate failed
	exitRenewals = 2 // pass succeeded and at least one certificate was renewed
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() {
	fmt.Fprintf(os.Stderr, `secsy-agent — host auto-enrollment agent for secsy-pki

Usage:
  secsy-agent [-config PATH] <command>

Commands:
  run      Run as a daemon, renewing certificates as they come due.
  once     Perform a single pass and exit. Exit codes: 0 nothing to do,
           2 renewed at least one certificate, 1 one or more failures.
  status   Print the tracked certificates and their next renewals as JSON.
  version  Print the build version.

Flags:
`)
	flag.PrintDefaults()
}

func run(args []string) int {
	fs := flag.NewFlagSet("secsy-agent", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/secsy/agent.yaml", "path to the agent configuration file")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage()
		fmt.Fprintln(os.Stderr, "error: no command given")
		return exitError
	}
	command, cmdArgs := rest[0], rest[1:]

	if command == "version" {
		fmt.Println(versionString())
		return exitOK
	}

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer a.Close() //nolint:errcheck // state is saved explicitly on the paths that matter

	switch command {
	case "run":
		return cmdRun(a)
	case "once":
		return cmdOnce(a, cmdArgs)
	case "status":
		return cmdStatus(a)
	default:
		usage()
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", command)
		return exitError
	}
}

// cmdRun is daemon mode: renew continuously until SIGINT/SIGTERM.
func cmdRun(a *agent.Agent) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	log.Print("agent: shutting down")
	return exitOK
}

// cmdOnce performs a single pass; the exit code reflects work done and
// errors so cron jobs and systemd timers can react.
func cmdOnce(a *agent.Agent, args []string) int {
	fs := flag.NewFlagSet("once", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the pass report as JSON")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := a.RunOnce(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	} else {
		for _, o := range report.Outcomes {
			switch o.Action {
			case "renewed":
				fmt.Printf("renewed  %-20s %s\n", o.Name, o.Reason)
			case "failed":
				fmt.Printf("FAILED   %-20s %s\n", o.Name, o.Error)
			case "fresh":
				next := ""
				if o.RenewAt != nil {
					next = "next renewal " + o.RenewAt.Local().Format("2006-01-02 15:04")
				}
				fmt.Printf("fresh    %-20s %s\n", o.Name, next)
			default:
				fmt.Printf("%-8s %-20s %s\n", o.Action, o.Name, o.Reason)
			}
		}
	}
	switch {
	case len(report.Failed()) > 0:
		return exitError
	case len(report.Renewed()) > 0:
		return exitRenewals
	default:
		return exitOK
	}
}

// cmdStatus prints the tracked certificates as JSON.
func cmdStatus(a *agent.Agent) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a.Status()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	return exitOK
}

// version is stamped by release builds via -ldflags "-X main.version=...".
var version string

// versionString prefers the stamped version, falling back to module build
// info.
func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
