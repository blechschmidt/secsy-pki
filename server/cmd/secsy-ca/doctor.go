package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// cmdDoctor runs the read-only preflight diagnostic suite and renders the
// report as a human table or JSON. It is dispatched before the config is
// loaded so a broken config file is itself a reported finding rather than a
// hard CLI error.
//
// Exit codes (CI-friendly, see docs/operations/runbook.md):
//
//	0  every check passed (or was skipped)
//	1  at least one check failed
//	2  no failures, but at least one warning
func cmdDoctor(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	out := cliout.Register(fs)
	deep := fs.Bool("deep", false, "additionally run the full store-integrity gate (walks the entire audit chain; same as \"secsy-ca db verify\")")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time budget for the run")
	expiryWarnDays := fs.Int("expiry-warn-days", 30, "warn when a certificate expires within this many days")
	expiryFailDays := fs.Int("expiry-fail-days", 7, "fail when a certificate expires within this many days")
	auditSample := fs.Int("audit-sample", 1000, "number of newest audit events to re-verify")
	noListener := fs.Bool("no-listener", false, "skip the live TLS probe of the configured listener address")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ca [-config config.yaml] doctor [flags]")
		fmt.Fprintln(os.Stderr, "\nRuns read-only preflight diagnostics: config, HSM/KMS reachability, key")
		fmt.Fprintln(os.Stderr, "self-tests, HA token health, database + pending migrations, audit chain,")
		fmt.Fprintln(os.Stderr, "certificate expiry, CRL freshness, clock skew, and listener TLS.")
		fmt.Fprintln(os.Stderr, "\nExit codes: 0 = pass, 1 = failure(s), 2 = warning(s) only.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := doctor.Run(ctx, doctor.Options{
		ConfigPath:      cfgPath,
		BuildProvider:   buildProvider,
		BuildPinSources: buildPinSources,
		BuildLDAP:       buildLDAPProbe,
		ExpiryWarn:      time.Duration(*expiryWarnDays) * 24 * time.Hour,
		ExpiryFail:      time.Duration(*expiryFailDays) * 24 * time.Hour,
		AuditSample:     *auditSample,
		SkipListener:    *noListener,
		Deep:            *deep,
	})

	if asJSON {
		if err := cliout.Emit(report); err != nil {
			return err
		}
	} else {
		printDoctorReport(report)
	}

	// doctor.Run has released every resource it opened, so exiting directly is
	// safe and gives CI the documented tri-state code.
	if code := report.ExitCode(); code != doctor.ExitOK {
		os.Exit(code)
	}
	return nil
}

func printDoctorReport(r *doctor.Report) {
	fmt.Printf("secsy-ca doctor — %s (config %s)\n\n", r.CheckedAt.Format(time.RFC3339), r.ConfigPath)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", doctorMark(c.Status), c.Name, c.Detail)
	}
	_ = tw.Flush()

	s := r.Summary
	fmt.Printf("\n%d passed, %d warning%s, %d failed, %d skipped\n",
		s.Pass, s.Warn, pluralS(s.Warn), s.Fail, s.Skip)
	switch {
	case s.Fail > 0:
		fmt.Println("RESULT: FAIL — resolve the failures above before starting/serving.")
	case s.Warn > 0:
		fmt.Println("RESULT: WARN — operational, but the warnings above need attention.")
	default:
		fmt.Println("RESULT: OK")
	}
}

func doctorMark(s doctor.Status) string {
	switch s {
	case doctor.StatusPass:
		return "✓ pass"
	case doctor.StatusWarn:
		return "! warn"
	case doctor.StatusFail:
		return "✗ FAIL"
	default:
		return "- skip"
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// buildLDAPProbe constructs a directory prober from config for the doctor
// "auth.ldap" check. It maps the auth.ldap block onto the authn authenticator —
// resolving the bind-password credential source through the shared pin_source
// machinery and reading the TLS trust material — with a deny-all resolver, since
// the check performs connectivity/bind probing only, never an end-user login.
func buildLDAPProbe(cfg *config.Config) (doctor.LDAPProber, error) {
	c := cfg.Auth.LDAP
	urls := splitLDAPURLs(c.URL)
	if len(urls) == 0 {
		return nil, fmt.Errorf("auth.ldap.url is required")
	}
	bindSource, err := keyprovider.NewPinSource(pinSourceSettings(c.BindPasswordSource), c.BindPassword)
	if err != nil {
		return nil, fmt.Errorf("bind_password_source: %w", err)
	}
	var caPEM []byte
	if c.TLS.CAFile != "" {
		if caPEM, err = os.ReadFile(c.TLS.CAFile); err != nil {
			return nil, fmt.Errorf("reading tls.ca_file %q: %w", c.TLS.CAFile, err)
		}
	}
	var minVer uint16
	switch c.TLS.MinVersion {
	case "", "1.2":
		minVer = tls.VersionTLS12
	case "1.3":
		minVer = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("tls.min_version %q must be \"1.2\" or \"1.3\"", c.TLS.MinVersion)
	}
	denyAll := func(authn.DirectoryIdentity) (*models.UserInfo, error) {
		return nil, fmt.Errorf("ldap probe: authentication not available")
	}
	return authn.NewLDAPAuthenticator(authn.LDAPConfig{
		URLs:                   urls,
		StartTLS:               c.StartTLS,
		InsecureAllowCleartext: c.InsecureAllowCleartext,
		BindDN:                 c.BindDN,
		BindPassword:           bindSource,
		UserBaseDN:             c.UserBaseDN,
		UserFilter:             c.UserFilter,
		UserDNTemplate:         c.UserDNTemplate,
		GroupBaseDN:            c.GroupBaseDN,
		GroupFilter:            c.GroupFilter,
		GroupAttribute:         c.GroupAttribute,
		UsernameAttribute:      c.UsernameAttribute,
		EmailAttribute:         c.EmailAttribute,
		NameAttribute:          c.NameAttribute,
		Timeout:                time.Duration(c.TimeoutSeconds) * time.Second,
		TLSCACertPEM:           caPEM,
		TLSServerName:          c.TLS.ServerName,
		TLSInsecureSkipVerify:  c.TLS.InsecureSkipVerify,
		TLSMinVersion:          minVer,
	}, denyAll)
}

// splitLDAPURLs splits a space/comma-separated list of directory URLs.
func splitLDAPURLs(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
