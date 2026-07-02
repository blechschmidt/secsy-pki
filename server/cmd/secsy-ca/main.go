// Command secsy-ca is an administrative CLI for HSM-backed certificate-authority
// setup. It initializes self-signed root CAs and issues intermediate CAs whose
// private keys live inside the configured key provider (an HSM via PKCS#11, or
// the software keystore). It shares the same config file, database, and key
// provider as the server.
//
// Usage:
//
//	secsy-ca [-config config.yaml] <command> [flags]
//
// Commands:
//
//	init-root           Generate a root CA key and self-signed certificate
//	issue-intermediate  Issue an intermediate CA under an existing CA
//	list                List configured CAs
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Usage = usage
	flag.CommandLine.Parse(args)

	rest := flag.Args()
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	command, cmdArgs := rest[0], rest[1:]

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Certificate linting is fully offline (no database or key provider): dispatch
	// it before opening either, so an operator can lint a certificate anywhere.
	if command == "lint" {
		return cmdLint(cfg, cmdArgs)
	}

	// The CMP client is a self-contained HTTP client (it generates its own key and
	// talks to a running /cmp endpoint), so it needs neither the database nor the
	// key provider. Dispatch it before opening either.
	if command == "cmp" {
		return cmdCMP(cmdArgs)
	}

	db, err := database.New(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Audit-log administration (chain verification, offline export) never touches
	// key material, so dispatch it before constructing the key provider. This lets
	// an auditor run "audit verify" without the HSM being present or unlocked.
	if command == "audit" {
		return cmdAudit(db, cmdArgs)
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	mgr := ca.NewManager(db, provider)

	// Install the CRL distribution policy so gen-crl (and any CDP stamping) sees
	// the configured shard count, base URL, and validity windows. Mirrors the
	// server's wiring, including the ACME base-URL fallback.
	crlBaseURL := cfg.CRL.BaseURL
	if crlBaseURL == "" {
		crlBaseURL = cfg.ACME.BaseURL
	}
	ca.SetCRLConfig(ca.CRLDistConfig{
		Shards:        cfg.CRL.Shards,
		BaseURL:       crlBaseURL,
		BaseValidity:  time.Duration(cfg.CRL.BaseValidityHours) * time.Hour,
		DeltaValidity: time.Duration(cfg.CRL.DeltaIntervalMinutes) * time.Minute,
	})

	switch command {
	case "init-root":
		return cmdInitRoot(mgr, cmdArgs)
	case "issue-intermediate":
		return cmdIssueIntermediate(db, mgr, cmdArgs)
	case "list":
		return cmdList(db)
	case "issue":
		return cmdIssue(db, mgr, cmdArgs)
	case "renew":
		return cmdRenew(db, mgr, cmdArgs)
	case "revoke":
		return cmdRevoke(db, mgr, cmdArgs)
	case "gen-crl":
		return cmdGenCRL(db, mgr, cmdArgs)
	case "list-certs":
		return cmdListCerts(db, cmdArgs)
	case "expiring":
		return cmdExpiring(db, cfg, cmdArgs)
	case "monitor-run":
		return cmdMonitorRun(db, mgr, cfg, cmdArgs)
	case "profiles":
		return cmdProfiles()
	case "svid":
		return cmdSVID(db, mgr, cmdArgs)
	case "svid-bundle":
		return cmdSVIDBundle(db, mgr, cfg, cmdArgs)
	case "inventory":
		return cmdInventory(db, provider, cmdArgs)
	case "ceremony":
		return cmdCeremony(db, mgr, provider, cmdArgs)
	case "rotate-intermediate":
		return cmdRotateIntermediate(db, mgr, cmdArgs)
	case "rotation-status":
		return cmdRotationStatus(db, mgr, cmdArgs)
	case "list-rotations":
		return cmdListRotations(db, mgr, cmdArgs)
	case "retire-intermediate":
		return cmdRetireIntermediate(db, mgr, cmdArgs)
	case "publish-chain":
		return cmdPublishChain(db, mgr, cmdArgs)
	case "tsa-key":
		return cmdTSAKey(db, mgr, provider, cmdArgs)
	case "backup":
		return cmdBackup(db, cfg, provider, cmdArgs)
	case "restore":
		return cmdRestore(db, cfg, provider, cmdArgs)
	// "audit" is dispatched earlier (before provider construction); this case is
	// unreachable but kept so the switch documents the full command set.
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `secsy-ca — HSM-backed certificate-authority setup

Usage:
  secsy-ca [-config config.yaml] <command> [flags]

Commands:
  init-root           Generate a root CA key and self-signed certificate
  issue-intermediate  Issue an intermediate CA under an existing CA
  list                List configured CAs
  issue               Sign a CSR into an end-entity certificate (by profile)
  renew               Renew a previously issued certificate by serial
  revoke              Revoke a certificate by serial
  gen-crl             Generate a signed CRL for a CA
  list-certs          List certificates issued by a CA
  expiring            List certificates by remaining validity (expiry monitor)
  monitor-run         Run one expiry-monitor scan (optionally auto-renewing)
  profiles            List the available certificate profiles
  svid                Mint a SPIFFE X.509-SVID (spiffe:// URI SAN, short-lived)
  svid-bundle         Emit a CA's SPIFFE trust bundle (JWKS) of X.509 authorities
  lint                Lint a certificate against a profile's policy (CA/B BR)
  cmp                 CMP (RFC 9483) client: enroll (ir) against a /cmp endpoint
  inventory           List keys held by the key provider (HSM/software)
  ceremony            Run an M-of-N confirmed root/intermediate key ceremony
  rotate-intermediate Rotate an intermediate CA signing key (dual-chain overlap)
  rotation-status     Show an intermediate CA's key-rollover / overlap state
  list-rotations      List CAs currently in a key-rotation lineage
  retire-intermediate Retire a superseded intermediate key after the overlap
  publish-chain       Emit the combined overlap chain (AIA/bundle) for a CA
  tsa-key             Provision an RFC 3161 TSA signing key + certificate
  backup              Export CA metadata + a DR manifest (no private keys)
  restore             Restore/verify CA metadata against the key provider
  audit               Verify the audit hash-chain, or export it for SIEM

Run "secsy-ca <command> -h" for command-specific flags.
`)
}

// subjectFlags registers the shared distinguished-name flags on a flag set.
type subjectFlags struct {
	cn, o, ou, c, st, l *string
}

func addSubjectFlags(fs *flag.FlagSet) subjectFlags {
	return subjectFlags{
		cn: fs.String("cn", "", "subject common name (required)"),
		o:  fs.String("o", "", "subject organization"),
		ou: fs.String("ou", "", "subject organizational unit"),
		c:  fs.String("c", "", "subject country"),
		st: fs.String("st", "", "subject state/province"),
		l:  fs.String("l", "", "subject locality"),
	}
}

func (s subjectFlags) subject() models.CASubject {
	return models.CASubject{
		CommonName:         *s.cn,
		Organization:       *s.o,
		OrganizationalUnit: *s.ou,
		Country:            *s.c,
		Province:           *s.st,
		Locality:           *s.l,
	}
}

// pathLenValue resolves the -path-len flag: -1 (the default) means an
// unconstrained path length (nil), any value >= 0 sets the constraint.
func pathLenValue(v int) *int {
	if v < 0 {
		return nil
	}
	return &v
}

// normalizeAlgorithm maps the CLI -algorithm value to the ca.CertAlgorithm
// string. "classical" (and the empty string) map to the classical zero value.
func normalizeAlgorithm(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "classical", "rsa", "ecdsa", "ed25519":
		return string(ca.AlgClassical)
	case "pqc", "ml-dsa", "mldsa", "post-quantum":
		return string(ca.AlgPQC)
	case "hybrid", "catalyst", "composite":
		return string(ca.AlgHybrid)
	default:
		return s // let the ca layer reject an unknown value with a clear error
	}
}

func cmdInitRoot(mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("init-root", flag.ContinueOnError)
	label := fs.String("label", "", "key label / CA name (required)")
	keyType := fs.String("key-type", "ecdsa-p384", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096, ml-dsa-44/65/87)")
	validityDays := fs.Int("validity-days", 3650, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
	algorithm := fs.String("algorithm", "classical", "signature scheme: classical | pqc (ML-DSA) | hybrid (classical + ML-DSA); pqc/hybrid require the software key provider")
	altKeyType := fs.String("alt-key-type", "ml-dsa-65", "ML-DSA parameter set for a hybrid CA's alternative key")
	subj := addSubjectFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" || *subj.cn == "" {
		fs.Usage()
		return fmt.Errorf("-label and -cn are required")
	}

	result, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:      *label,
		KeyType:    *keyType,
		Subject:    ca.PKIXName(subj.subject()),
		Validity:   time.Duration(*validityDays) * 24 * time.Hour,
		MaxPathLen: pathLenValue(*pathLen),
		Algorithm:  ca.CertAlgorithm(normalizeAlgorithm(*algorithm)),
		AltKeyType: *altKeyType,
	})
	if err != nil {
		return err
	}
	printCA("Root CA created", result)
	return nil
}

func cmdIssueIntermediate(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("issue-intermediate", flag.ContinueOnError)
	parent := fs.String("parent", "", "parent CA id or label (required)")
	label := fs.String("label", "", "key label / CA name (required)")
	keyType := fs.String("key-type", "ecdsa-p256", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096, ml-dsa-44/65/87)")
	validityDays := fs.Int("validity-days", 1825, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
	algorithm := fs.String("algorithm", "classical", "signature scheme: classical | pqc (ML-DSA) | hybrid; must match the parent CA")
	altKeyType := fs.String("alt-key-type", "ml-dsa-65", "ML-DSA parameter set for a hybrid intermediate's alternative key")
	subj := addSubjectFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *parent == "" || *label == "" || *subj.cn == "" {
		fs.Usage()
		return fmt.Errorf("-parent, -label and -cn are required")
	}

	parentID, err := resolveCA(db, *parent)
	if err != nil {
		return err
	}

	result, err := mgr.IssueIntermediate(context.Background(), ca.IntermediateSpec{
		ParentID:   parentID,
		Label:      *label,
		KeyType:    *keyType,
		Subject:    ca.PKIXName(subj.subject()),
		Validity:   time.Duration(*validityDays) * 24 * time.Hour,
		MaxPathLen: pathLenValue(*pathLen),
		Algorithm:  ca.CertAlgorithm(normalizeAlgorithm(*algorithm)),
		AltKeyType: *altKeyType,
	})
	if err != nil {
		return err
	}
	printCA("Intermediate CA created", result)
	return nil
}

func cmdList(db *database.DB) error {
	cas, err := db.ListCAs()
	if err != nil {
		return err
	}
	if len(cas) == 0 {
		fmt.Println("No CAs configured.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tLABEL\tKEY TYPE\tPARENT\tSUBJECT\tNOT AFTER")
	byID := map[string]string{}
	for _, c := range cas {
		byID[c.ID] = c.Label
	}
	for _, c := range cas {
		parent := "-"
		if c.ParentID != nil {
			if lbl, ok := byID[*c.ParentID]; ok {
				parent = lbl
			} else {
				parent = *c.ParentID
			}
		}
		subject := c.Subject
		if subject == "" {
			subject = "(SSH-only)"
		}
		notAfter := "-"
		if c.NotAfter != nil {
			notAfter = c.NotAfter.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Label, c.KeyType, parent, subject, notAfter)
	}
	return tw.Flush()
}

// resolveCA resolves a CA reference that may be either an id or a label to its
// canonical id.
func resolveCA(db *database.DB, ref string) (string, error) {
	if c, err := db.GetCA(ref); err != nil {
		return "", err
	} else if c != nil {
		return c.ID, nil
	}
	if c, err := db.GetCAByLabel(ref); err != nil {
		return "", err
	} else if c != nil {
		return c.ID, nil
	}
	return "", fmt.Errorf("no CA found with id or label %q", ref)
}

func printCA(header string, c *models.CA) {
	fmt.Printf("%s:\n", header)
	fmt.Printf("  ID:       %s\n", c.ID)
	fmt.Printf("  Label:    %s\n", c.Label)
	fmt.Printf("  Subject:  %s\n", c.Subject)
	fmt.Printf("  Key type: %s\n", c.KeyType)
	fmt.Printf("  Serial:   %s\n", c.Serial)
	fmt.Printf("  URI:      %s\n", c.PKCS11URI)
	if c.NotBefore != nil && c.NotAfter != nil {
		fmt.Printf("  Validity: %s .. %s\n", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
	}
	fmt.Printf("\n%s\n", c.Certificate)
}

func cmdIssue(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	csrPath := fs.String("csr", "", "path to a PEM CSR, or '-' for stdin (required)")
	profile := fs.String("profile", "server", "certificate profile (see 'profiles')")
	validityDays := fs.Int("validity-days", 0, "validity in days (0 = profile default)")
	out := fs.String("out", "", "write the issued certificate PEM here (default: stdout)")
	chain := fs.Bool("chain", false, "include the issuing CA certificate in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *csrPath == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -csr are required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	csrPEM, err := readInput(*csrPath)
	if err != nil {
		return fmt.Errorf("reading CSR: %w", err)
	}

	result, err := mgr.IssueCertificate(context.Background(), ca.IssueSpec{
		CAID:        caID,
		CSRPEM:      csrPEM,
		Profile:     *profile,
		Validity:    daysToDuration(*validityDays),
		RequestedBy: "secsy-ca-cli",
	})
	if err != nil {
		return err
	}

	pemOut := result.PEM
	if *chain {
		pemOut = result.ChainPEM
	}
	fmt.Fprintf(os.Stderr, "Issued certificate: serial=%s profile=%s not_after=%s\n",
		result.Serial, result.Profile, result.Certificate.NotAfter.Format(time.RFC3339))
	return writeOutput(*out, pemOut)
}

func cmdRenew(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	serial := fs.String("serial", "", "serial of the certificate to renew (required)")
	csrPath := fs.String("csr", "", "optional PEM CSR to rekey (default: reuse original key)")
	validityDays := fs.Int("validity-days", 0, "validity in days (0 = profile default)")
	out := fs.String("out", "", "write the renewed certificate PEM here (default: stdout)")
	chain := fs.Bool("chain", false, "include the issuing CA certificate in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *serial == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -serial are required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	var csrPEM []byte
	if *csrPath != "" {
		csrPEM, err = readInput(*csrPath)
		if err != nil {
			return fmt.Errorf("reading CSR: %w", err)
		}
	}

	result, err := mgr.RenewCertificate(context.Background(), ca.RenewSpec{
		CAID:        caID,
		Serial:      *serial,
		CSRPEM:      csrPEM,
		Validity:    daysToDuration(*validityDays),
		RequestedBy: "secsy-ca-cli",
	})
	if err != nil {
		return err
	}

	pemOut := result.PEM
	if *chain {
		pemOut = result.ChainPEM
	}
	fmt.Fprintf(os.Stderr, "Renewed certificate: new serial=%s (was %s) not_after=%s\n",
		result.Serial, *serial, result.Certificate.NotAfter.Format(time.RFC3339))
	return writeOutput(*out, pemOut)
}

func cmdRevoke(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	serial := fs.String("serial", "", "serial of the certificate to revoke (required)")
	reason := fs.String("reason", "unspecified", "RFC 5280 reason (keyCompromise, superseded, …)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *serial == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -serial are required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	applied, err := mgr.RevokeCertificate(context.Background(), caID, *serial, *reason)
	if err != nil {
		return err
	}
	if applied {
		fmt.Printf("Certificate serial %s revoked (reason: %s).\n", *serial, *reason)
	} else {
		fmt.Printf("Certificate serial %s was already revoked; reason updated to %s.\n", *serial, *reason)
	}
	return nil
}

func cmdGenCRL(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("gen-crl", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	out := fs.String("out", "", "write the CRL here (default: stdout)")
	der := fs.Bool("der", false, "emit DER instead of PEM")
	delta := fs.Bool("delta", false, "generate a delta CRL relative to the current base CRL")
	shard := fs.Int("shard", ca.FullScope, "CRL partition index (default: the complete, unsharded CRL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	ctx := context.Background()
	var derBytes []byte
	if *delta {
		derBytes, err = mgr.GetDeltaCRL(ctx, caID, *shard)
	} else if *shard != ca.FullScope {
		derBytes, err = mgr.GetBaseCRL(ctx, caID, *shard)
	} else {
		// Backward-compatible: the unsharded, non-delta case emits a fresh
		// ad-hoc complete CRL for export.
		derBytes, err = mgr.GenerateCRL(ctx, caID)
	}
	if err != nil {
		return err
	}
	if *der {
		return writeOutput(*out, derBytes)
	}
	return writeOutput(*out, pki.EncodeCRLPEM(derBytes))
}

func cmdListCerts(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("list-certs", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	db.MarkExpiredCertificates(caID, time.Now())
	certs, err := db.ListIssuedCertificates(caID)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		fmt.Println("No certificates issued by this CA.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERIAL\tPROFILE\tSTATUS\tSUBJECT\tNOT AFTER")
	for _, c := range certs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.Serial, c.Profile, c.Status, c.CommonName, c.NotAfter.Format("2006-01-02"))
	}
	return tw.Flush()
}

func cmdProfiles() error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDEFAULT DAYS\tMAX DAYS\tKEY USAGES\tEXT KEY USAGES\tDESCRIPTION")
	for _, p := range ca.Profiles() {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\n",
			p.Name, p.DefaultValidityDays, p.MaxValidityDays,
			strings.Join(p.KeyUsages, "+"), strings.Join(p.ExtKeyUsages, "+"), p.Description)
	}
	return tw.Flush()
}

// cmdLint runs the pre-issuance lint checks against an existing certificate for
// ad-hoc checking. It parses a PEM certificate (from a file or stdin), resolves
// the lint policy from an optional named profile plus flag overrides, prints the
// findings, and exits non-zero when an enforce-mode check fails.
func cmdLint(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	profileName := fs.String("profile", "", "apply the named profile's lint policy (default: baseline)")
	public := fs.Bool("public", false, "apply CA/Browser-Forum public-trust rules (overrides profile)")
	mode := fs.String("mode", "", "override the enforcement mode for all checks: enforce|warn")
	maxDays := fs.Int("max-validity-days", 0, "cap the validity period in days (0 = from profile)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ca lint [flags] <cert.pem>   (use - to read from stdin)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := fs.Arg(0)
	if path == "" {
		fs.Usage()
		return fmt.Errorf("a certificate path is required (use - for stdin)")
	}

	certPEM, err := readInput(path)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	// Resolve the policy: start from the named profile (honoring operator-defined
	// profiles from config), then apply flag overrides.
	var policy certlint.Policy
	if *profileName != "" {
		if err := installConfigProfiles(cfg); err != nil {
			return fmt.Errorf("loading custom profiles: %w", err)
		}
		prof, err := ca.LookupProfile(*profileName)
		if err != nil {
			return err
		}
		policy = prof.LintPolicy()
	}
	if *public {
		policy.Public = true
	}
	if *mode != "" {
		if *mode != string(certlint.ModeEnforce) && *mode != string(certlint.ModeWarn) {
			return fmt.Errorf("invalid -mode %q (want enforce or warn)", *mode)
		}
		policy.Mode = certlint.Mode(*mode)
	}
	if *maxDays > 0 {
		policy.MaxValidity = time.Duration(*maxDays) * 24 * time.Hour
	}

	res := certlint.Lint(cert, policy)

	effMode := policy.Mode
	if effMode == "" {
		effMode = certlint.ModeEnforce
	}
	fmt.Printf("Certificate: subject=%q serial=%s not_after=%s\n",
		cert.Subject.String(), cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("Policy: mode=%s public=%t max_validity=%s\n", effMode, policy.Public, policy.MaxValidity)
	if res.OK() {
		fmt.Println("Result: PASS (no findings)")
		return nil
	}
	for _, f := range res.Findings {
		fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(string(f.Mode)), f.Code, f.Description)
	}
	fmt.Printf("Result: %s\n", res.Summary())
	if res.HasErrors() {
		return fmt.Errorf("lint failed: %d enforce-mode finding(s)", len(res.Errors()))
	}
	return nil
}

// installConfigProfiles registers the operator-defined certificate profiles from
// config so their lint policies are available offline. Certificate Transparency
// is intentionally ignored here (it needs a submitter and is irrelevant to
// linting).
func installConfigProfiles(cfg *config.Config) error {
	if len(cfg.Profiles) == 0 {
		return nil
	}
	profiles := make([]ca.Profile, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		prof := ca.Profile{
			Name:                p.Name,
			Description:         p.Description,
			KeyUsages:           p.KeyUsages,
			ExtKeyUsages:        p.ExtKeyUsages,
			DefaultValidityDays: p.DefaultValidityDays,
			MaxValidityDays:     p.MaxValidityDays,
			Lint: &ca.LintConfig{
				Disabled:  p.Lint.Disabled,
				Mode:      p.Lint.Mode,
				Public:    p.Lint.Public,
				Overrides: p.Lint.Overrides,
			},
		}
		if mode := strings.ToLower(strings.TrimSpace(p.CAA.Mode)); mode != "" && mode != "off" {
			identifier := p.CAA.Identifier
			if identifier == "" {
				identifier = cfg.CAA.Identifier
			}
			prof.CAA = &ca.CAAConfig{
				Mode:           mode,
				Identifier:     identifier,
				TimeoutSeconds: p.CAA.TimeoutSeconds,
			}
		}
		profiles = append(profiles, prof)
	}
	return ca.SetCustomProfiles(profiles)
}

// daysToDuration converts validity-in-days to a Duration (0 = profile default).
func daysToDuration(days int) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// readInput reads from a file path, or from stdin when path is "-".
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// writeOutput writes to a file path, or to stdout when path is empty.
func writeOutput(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// buildProvider constructs the configured key provider, mirroring the server.
func buildProvider(cfg *config.Config) (keyprovider.Provider, error) {
	// Ensure the YubiHSM PKCS#11 module can find its connector, matching the
	// server's behavior.
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err == nil {
			os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}
	return keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProvider.Type),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			Pin:               cfg.PKCS11.Pin,
			TokenLabel:        cfg.PKCS11.TokenLabel,
			TokenSerial:       cfg.PKCS11.TokenSerial,
			TokenManufacturer: cfg.PKCS11.TokenManufacturer,
		},
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: cfg.KeyProvider.Software.KeystoreDir,
		},
	})
}
