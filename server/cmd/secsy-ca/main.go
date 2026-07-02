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

	db, err := database.New(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	provider, err := buildProvider(cfg)
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	mgr := ca.NewManager(db, provider)

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
	case "profiles":
		return cmdProfiles()
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
  profiles            List the available certificate profiles

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

func cmdInitRoot(mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("init-root", flag.ContinueOnError)
	label := fs.String("label", "", "key label / CA name (required)")
	keyType := fs.String("key-type", "ecdsa-p384", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096)")
	validityDays := fs.Int("validity-days", 3650, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
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
	keyType := fs.String("key-type", "ecdsa-p256", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096)")
	validityDays := fs.Int("validity-days", 1825, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
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

	derBytes, err := mgr.GenerateCRL(context.Background(), caID)
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
