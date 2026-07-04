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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// version is the release version, stamped by the linker (-X main.version) in
// release/container builds; "dev" otherwise.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Usage = usage
	_ = flag.CommandLine.Parse(args)

	rest := flag.Args()
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	command, cmdArgs := rest[0], rest[1:]

	// version needs nothing at all — not even a config file. The FIPS summary
	// reflects this process (module state from the build/GODEBUG; the policy is
	// per-config, so it reads "off" here unless a config was loaded).
	if command == "version" {
		fmt.Printf("secsy-ca %s %s %s\n", version, runtime.Version(), fips.Summary())
		return nil
	}

	// The doctor runs before the config is loaded: a config that fails to parse
	// is one of its findings (reported with the documented exit codes), not a
	// reason the diagnostics cannot run.
	if command == "doctor" {
		return cmdDoctor(*cfgPath, cmdArgs)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Install the operator-defined SSH signing profiles up front (they are pure
	// config, needing neither the database nor the key provider) so every ssh
	// subcommand — and the profile listing — sees the server's effective set.
	if err := installSSHProfiles(cfg); err != nil {
		return fmt.Errorf("loading ssh profiles: %w", err)
	}

	// Install the per-tenant S/MIME e-mail domain scoping up front too (pure
	// config), so CLI issuance under a tenant-owned CA enforces the same
	// allowlists as the server.
	tenantEmailDomains := make(map[string][]string)
	for _, tc := range cfg.Tenants {
		if len(tc.AllowedEmailDomains) > 0 {
			tenantEmailDomains[tc.ID] = tc.AllowedEmailDomains
		}
	}
	if err := ca.SetTenantEmailDomains(tenantEmailDomains); err != nil {
		return fmt.Errorf("loading tenant allowed_email_domains: %w", err)
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

	// The gRPC client (Task 56) is a self-contained gRPC client that talks to a
	// running server's PKIService endpoint. Like the CMP client it needs neither
	// the database nor the key provider, so dispatch it before opening either.
	if command == "grpc" {
		return cmdGRPC(cmdArgs)
	}

	// Store administration (migrate a file/SQLite store into PostgreSQL) opens its
	// own source and destination databases from explicit flags, and needs no key
	// provider. Dispatch it before the config-driven database is opened so it does
	// not require the config's database to be the one being migrated.
	if command == "db" {
		return cmdDB(cfg, cmdArgs)
	}

	db, err := database.NewWithOptions(cfg.Database.Driver, cfg.Database.DSN, database.PoolOptions{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.Database.ConnMaxLifetimeSecs) * time.Second,
		ConnMaxIdleTime: time.Duration(cfg.Database.ConnMaxIdleTimeSecs) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Audit-log administration (chain/anchor verification, offline export) is
	// dispatched before the key provider is constructed, so an auditor can run
	// "audit verify" without the HSM being present or unlocked. Only
	// "audit anchor" against the internal TSA builds a (TSA-role) provider, and
	// it does so lazily inside the command.
	if command == "audit" {
		return cmdAudit(db, cfg, cmdArgs)
	}

	// The four-eyes approval queue (Task 81) needs only the database and config
	// for most subcommands, so dispatch it here alongside audit administration.
	// The `certificate` subcommand (Task 84) completes an approved issuance on the
	// HSM, so it is handed a lazy CA key-provider factory it invokes only then.
	if command == "approvals" {
		return cmdApprovals(db, cfg, func() (keyprovider.Provider, error) {
			return buildProvider(cfg, "ca")
		}, cmdArgs)
	}

	// Certificate discovery is a TLS client plus X.509 analysis against the stored
	// CA certificates; it needs the database but never the HSM/key provider, so
	// dispatch it before the provider is constructed. This lets an operator run a
	// scan without the token being present or unlocked.
	if command == "discover" {
		return cmdDiscover(db, cfg, cmdArgs)
	}

	// Signature verification is public-key only (trust anchors come from the
	// store or a PEM file), so dispatch it before the key provider too — a
	// release can be verified anywhere, without the HSM.
	if command == "verify-signature" {
		return cmdVerifySignature(db, cmdArgs)
	}

	// CT SCT inclusion monitoring (Task 93) verifies that CT logs honored the
	// SCTs embedded at issuance — HTTP fetches plus public-key Merkle-proof
	// verification, reading/writing only the store. It never touches the HSM, so
	// dispatch it before the key provider is constructed.
	if command == "ct" {
		return cmdCT(db, cfg, cmdArgs)
	}

	// DNS pinning-record generation (Task 98) hashes stored public certificate
	// and SSH-key material — it never touches the HSM — so dispatch it before the
	// key provider is constructed. This lets an operator mint DANE/SSHFP records
	// during an HSM outage.
	if command == "dns-records" {
		return cmdDNSRecords(db, cmdArgs)
	}

	// Publishing constructs the key provider lazily so `publish -verify` (a pure
	// manifest/digest audit of the published snapshot) works during an HSM
	// outage — exactly when an operator most wants to prove the static artifacts
	// are intact. The CRL config below is installed here too since publishing
	// regenerates stale CRLs.
	if command == "publish" {
		installCRLConfig(cfg)
		return cmdPublish(db, cfg, func() (keyprovider.Provider, error) {
			return buildProvider(cfg, "ca")
		}, cmdArgs)
	}

	provider, err := buildProvider(cfg, "ca")
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	mgr := ca.NewManager(db, provider)

	// Install the CRL distribution policy so gen-crl (and any CDP stamping) sees
	// the configured shard count, base URL, and validity windows.
	installCRLConfig(cfg)

	switch command {
	case "init-root":
		return cmdInitRoot(db, mgr, cmdArgs)
	case "tenant":
		return cmdTenant(db, cmdArgs)
	case "token":
		return cmdToken(db, cfg, cmdArgs)
	case "issue-intermediate":
		return cmdIssueIntermediate(db, mgr, cmdArgs)
	case "ca":
		// Externally-signed subordinate CA flow: "ca csr" / "ca import-cert".
		return cmdCA(db, mgr, cmdArgs)
	case "list":
		return cmdList(db)
	case "issue":
		return cmdIssue(db, mgr, cmdArgs)
	case "export-p12":
		return cmdExportP12(db, mgr, provider, cfg, cmdArgs)
	case "renew":
		return cmdRenew(db, mgr, cmdArgs)
	case "revoke":
		return cmdRevoke(db, mgr, cmdArgs)
	case "suspend":
		return cmdSuspend(db, mgr, cmdArgs)
	case "release":
		return cmdRelease(db, mgr, cmdArgs)
	case "revoke-bulk":
		return cmdRevokeBulk(db, mgr, cfg, cmdArgs)
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
		return cmdRotateIntermediate(db, mgr, cfg, cmdArgs)
	case "rotation-status":
		return cmdRotationStatus(db, mgr, cmdArgs)
	case "list-rotations":
		return cmdListRotations(db, mgr, cmdArgs)
	case "retire-intermediate":
		return cmdRetireIntermediate(db, mgr, cfg, cmdArgs)
	case "publish-chain":
		return cmdPublishChain(db, mgr, cmdArgs)
	case "cross-sign":
		return cmdCrossSign(db, mgr, cmdArgs)
	case "list-cross-signs":
		return cmdListCrossSigns(db, mgr, cmdArgs)
	case "ssh":
		return cmdSSH(db, provider, cmdArgs)
	case "tsa-key":
		// The TSA signing key lives on the TSA-role backend, which may differ from
		// the CA. Build a dedicated provider when the roles resolve differently;
		// otherwise reuse the CA-role provider.
		tsaProvider := provider
		if cfg.KeyProviderTypeForRole("tsa") != cfg.KeyProviderTypeForRole("ca") {
			tp, terr := buildProvider(cfg, "tsa")
			if terr != nil {
				return fmt.Errorf("initializing TSA key provider: %w", terr)
			}
			defer tp.Close()
			tsaProvider = tp
		}
		return cmdTSAKey(db, mgr, tsaProvider, provider, cmdArgs)
	case "signing-key":
		// Artifact code-signing keys live on the signing-role backend, which may
		// differ from the CA (the certificate is still issued by the CA manager
		// on the CA-role provider).
		signingProvider := provider
		if cfg.KeyProviderTypeForRole("signing") != cfg.KeyProviderTypeForRole("ca") {
			sp, serr := buildProvider(cfg, "signing")
			if serr != nil {
				return fmt.Errorf("initializing signing key provider: %w", serr)
			}
			defer sp.Close()
			signingProvider = sp
		}
		return cmdSigningKey(db, mgr, signingProvider, cmdArgs)
	case "sign":
		// Artifact signing uses the signing-role backend for the artifact key and
		// the TSA-role backend for the optional RFC 3161 countersignature.
		signingProvider := provider
		if cfg.KeyProviderTypeForRole("signing") != cfg.KeyProviderTypeForRole("ca") {
			sp, serr := buildProvider(cfg, "signing")
			if serr != nil {
				return fmt.Errorf("initializing signing key provider: %w", serr)
			}
			defer sp.Close()
			signingProvider = sp
		}
		tsaProvider := provider
		if cfg.KeyProviderTypeForRole("tsa") != cfg.KeyProviderTypeForRole("ca") {
			tp, terr := buildProvider(cfg, "tsa")
			if terr != nil {
				return fmt.Errorf("initializing TSA key provider: %w", terr)
			}
			defer tp.Close()
			tsaProvider = tp
		}
		return cmdSign(db, cfg, signingProvider, tsaProvider, cmdArgs)
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

// installCRLConfig installs the process-wide CRL distribution policy from
// configuration, mirroring the server's wiring including the ACME base-URL
// fallback.
func installCRLConfig(cfg *config.Config) {
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
}

func usage() {
	fmt.Fprint(os.Stderr, `secsy-ca — HSM-backed certificate-authority setup

Usage:
  secsy-ca [-config config.yaml] <command> [flags]

Commands:
  init-root           Generate a root CA key and self-signed certificate
  issue-intermediate  Issue an intermediate CA under an existing CA
  ca csr              Generate an HSM-backed CA key + PKCS#10 CSR for an
                      external parent (offline corporate root / bridge) to sign
  ca import-cert      Validate and install the externally signed CA certificate
                      (+ optional external chain for chain serving)
  list                List configured CAs
  version             Print version, Go runtime, and FIPS 140-3 mode
  issue               Sign a CSR into an end-entity certificate (by profile)
  export-p12          Generate a subject key + issue a leaf, and export a
                      password-protected PKCS#12 (.p12/.pfx) bundle (key + leaf +
                      chain); optionally escrow the subject key (M-of-N)
  renew               Renew a previously issued certificate by serial
  revoke              Revoke a certificate by serial
  suspend             Place a certificate on hold (RFC 5280 certificateHold);
                      reversible with release
  release             Remove a certificate hold, returning it to service
                      (emits removeFromCRL in the next delta CRL)
  revoke-bulk         Mass-revoke certificates for compromise response (filters,
                      dry-run preview, batched, single CRL+delta regen)
  gen-crl             Generate a signed CRL for a CA
  list-certs          List certificates issued by a CA
  expiring            List certificates by remaining validity (expiry monitor)
  monitor-run         Run one expiry-monitor scan (optionally auto-renewing)
  profiles            List the available certificate profiles
  svid                Mint a SPIFFE X.509-SVID (spiffe:// URI SAN, short-lived)
  svid-bundle         Emit a CA's SPIFFE trust bundle (JWKS) of X.509 authorities
  lint                Lint a certificate against a profile's policy (CA/B BR)
  cmp                 CMP (RFC 9483) client: enroll (ir) against a /cmp endpoint
  grpc                gRPC client: issue/renew/revoke/status over the PKIService API
  inventory           List keys held by the key provider (HSM/software)
  ceremony            Run an M-of-N confirmed root/intermediate key ceremony
  rotate-intermediate Rotate an intermediate CA signing key (dual-chain overlap)
  rotation-status     Show an intermediate CA's key-rollover / overlap state
  list-rotations      List CAs currently in a key-rotation lineage
  retire-intermediate Retire a superseded intermediate key after the overlap
  publish-chain       Emit the combined overlap chain (AIA/bundle) for a CA
  cross-sign          Cross-sign a subject key under an issuer CA (bridge/root-transition)
  list-cross-signs    List a CA's cross-sign relationships or alternate chains
  tsa-key             Provision an RFC 3161 TSA signing key + certificate
  signing-key         Provision an artifact code-signing key + certificate (code-signing profile)
  sign                Sign a release artifact (file or digest) as CMS/PKCS#7, optionally RFC 3161 timestamped
  verify-signature    Verify a CMS artifact signature (file or digest) against the PKI trust anchors
  ssh                 SSH certificate authority (ca-init, sign-user, sign-host, revoke, krl)
  backup              Export CA metadata + a DR manifest (no private keys), or
                      "backup verify-restore" to prove the newest scheduled
                      encrypted backup can actually be restored (Task 94)
  restore             Restore/verify CA metadata against the key provider
  audit               Verify the audit hash-chain (incl. RFC 3161 anchors),
                      anchor the chain head, or export events for SIEM
  discover            Scan external TLS endpoints; flag expiring/weak/rogue certs
  ct                  Certificate Transparency inclusion monitoring:
                      verify-inclusion (verify embedded SCTs against the logs'
                      Merkle proofs) / inclusion-status (show recorded state)
  publish             Publish CRLs/chains/pre-signed OCSP as static artifacts (CDN offload)
  db                  Persistence administration (migrate SQLite file store → PostgreSQL)
  doctor              Read-only preflight diagnostics (config, HSM/KMS, keys, DB,
                      audit chain, expiry, CRL freshness, clock, TLS); exit 0/1/2
  token               Manage native scoped API tokens / service accounts
                      (create/list/revoke); create prints the secret once

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

func cmdInitRoot(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("init-root", flag.ContinueOnError)
	label := fs.String("label", "", "key label / CA name (required)")
	tenant := fs.String("tenant", "", "owning tenant id or slug (default: the built-in default tenant)")
	keyType := fs.String("key-type", "ecdsa-p384", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096, ml-dsa-44/65/87)")
	validityDays := fs.Int("validity-days", 3650, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
	algorithm := fs.String("algorithm", "classical", "signature scheme: classical | pqc (ML-DSA) | hybrid (classical + ML-DSA); pqc/hybrid require the software key provider")
	altKeyType := fs.String("alt-key-type", "ml-dsa-65", "ML-DSA parameter set for a hybrid CA's alternative key")
	subj := addSubjectFlags(fs)
	cons := addConstraintFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" || *subj.cn == "" {
		fs.Usage()
		return fmt.Errorf("-label and -cn are required")
	}

	tenantID, err := resolveTenant(db, *tenant)
	if err != nil {
		return err
	}

	nc, pol, err := cons.build()
	if err != nil {
		return err
	}

	result, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		TenantID:        tenantID,
		Label:           *label,
		KeyType:         *keyType,
		Subject:         ca.PKIXName(subj.subject()),
		Validity:        time.Duration(*validityDays) * 24 * time.Hour,
		MaxPathLen:      pathLenValue(*pathLen),
		Algorithm:       ca.CertAlgorithm(normalizeAlgorithm(*algorithm)),
		AltKeyType:      *altKeyType,
		NameConstraints: nc,
		Policies:        pol,
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
	cons := addConstraintFlags(fs)
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

	nc, pol, err := cons.build()
	if err != nil {
		return err
	}

	result, err := mgr.IssueIntermediate(context.Background(), ca.IntermediateSpec{
		ParentID:        parentID,
		Label:           *label,
		KeyType:         *keyType,
		Subject:         ca.PKIXName(subj.subject()),
		Validity:        time.Duration(*validityDays) * 24 * time.Hour,
		MaxPathLen:      pathLenValue(*pathLen),
		Algorithm:       ca.CertAlgorithm(normalizeAlgorithm(*algorithm)),
		AltKeyType:      *altKeyType,
		NameConstraints: nc,
		Policies:        pol,
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

// cmdSuspend places a certificate on hold (RFC 5280 certificateHold) — a
// reversible revocation that can be undone with `secsy-ca release`.
func cmdSuspend(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("suspend", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	serial := fs.String("serial", "", "serial of the certificate to suspend (required)")
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

	applied, err := mgr.SuspendCertificate(context.Background(), caID, *serial)
	if err != nil {
		return err
	}
	if applied {
		fmt.Printf("Certificate serial %s placed on hold (certificateHold). Release with: secsy-ca release -ca %s -serial %s\n", *serial, *caRef, *serial)
	} else {
		fmt.Printf("Certificate serial %s was already on hold.\n", *serial)
	}
	return nil
}

// cmdRelease removes a certificate hold, returning the certificate to service.
// It fails if the certificate was permanently revoked rather than suspended.
func cmdRelease(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	serial := fs.String("serial", "", "serial of the held certificate to release (required)")
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

	if err := mgr.ReleaseCertificate(context.Background(), caID, *serial); err != nil {
		return err
	}
	fmt.Printf("Certificate serial %s released; it is valid again. The next delta CRL carries removeFromCRL for it.\n", *serial)
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

// cmdListCerts lists a CA's issued certificates with server-side pagination,
// filtering, and search (Task 83). By default it auto-follows every page so a
// full dump stays complete while each underlying query remains bounded; passing
// -cursor or -page fetches a single page and reports the cursor to resume from.
func cmdListCerts(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("list-certs", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	limit := fs.Int("limit", 0, "page size (0 = server default; capped at the server maximum)")
	cursor := fs.String("cursor", "", "resume from this pagination cursor (fetches a single page)")
	single := fs.Bool("page", false, "fetch only one page instead of following all pages")
	statusFilter := fs.String("status", "", "filter by status: valid|revoked|held|expired")
	profileFilter := fs.String("profile", "", "filter by profile name")
	query := fs.String("filter", "", "case-insensitive substring over subject / common name / SANs")
	serialPrefix := fs.String("serial-prefix", "", "filter to serials beginning with this decimal prefix")
	expiresBefore := fs.String("expires-before", "", "only certificates expiring before this time (RFC 3339 or YYYY-MM-DD)")
	asJSON := fs.Bool("json", false, "emit the page as JSON {items,next_cursor,total,has_more}")
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
	_, _ = db.MarkExpiredCertificates(caID, time.Now())

	filter := database.CertFilter{
		Status:       *statusFilter,
		Profile:      *profileFilter,
		Query:        *query,
		SerialPrefix: *serialPrefix,
	}
	if t, err := parseBulkTime(*expiresBefore, false); err != nil {
		return fmt.Errorf("-expires-before: %w", err)
	} else if t != nil {
		filter.ExpiresBefore = *t
	}

	// A cursor or an explicit -page fetches one page; otherwise follow every page
	// so the default behavior remains a complete dump.
	followAll := *cursor == "" && !*single
	pageReq := database.CertPageRequest{Limit: *limit, Cursor: *cursor}

	var items []models.IssuedCertificate
	var last database.IssuedCertPage
	for {
		page, err := db.PageIssuedCertificates(caID, filter, pageReq)
		if err != nil {
			return err
		}
		last = page
		items = append(items, page.Items...)
		if !followAll || !page.HasMore {
			break
		}
		pageReq.Cursor = page.NextCursor
	}

	if *asJSON {
		out := struct {
			Items      []models.IssuedCertificate `json:"items"`
			NextCursor string                     `json:"next_cursor"`
			Total      int                        `json:"total"`
			HasMore    bool                       `json:"has_more"`
		}{Items: items, Total: last.Total}
		if !followAll {
			out.NextCursor = last.NextCursor
			out.HasMore = last.HasMore
		}
		if out.Items == nil {
			out.Items = []models.IssuedCertificate{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	if len(items) == 0 {
		fmt.Println("No certificates match.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERIAL\tPROFILE\tSTATUS\tSUBJECT\tNOT AFTER")
	for _, c := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.Serial, c.Profile, c.Status, c.CommonName, c.NotAfter.Format("2006-01-02"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if followAll {
		fmt.Printf("\n%d certificate(s).\n", last.Total)
	} else {
		fmt.Printf("\nShowing %d of %d matching certificate(s).\n", len(items), last.Total)
		if last.HasMore {
			fmt.Printf("Next page: secsy-ca list-certs -ca %s -cursor %s\n", *caRef, last.NextCursor)
		}
	}
	return nil
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
// ad-hoc checking. It parses a certificate (PEM or DER, from a file or stdin),
// resolves the lint policy from an optional named profile plus flag overrides,
// prints the findings, and exits non-zero when an enforce-mode check fails. With
// -zlint (and a binary built with -tags zlint) it additionally runs the
// industry-standard github.com/zmap/zlint suite.
func cmdLint(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	profileName := fs.String("profile", "", "apply the named profile's lint policy (default: baseline)")
	public := fs.Bool("public", false, "apply CA/Browser-Forum public-trust rules (overrides profile)")
	mode := fs.String("mode", "", "override the enforcement mode for all checks: enforce|warn")
	maxDays := fs.Int("max-validity-days", 0, "cap the validity period in days (0 = from profile)")
	zlintOn := fs.Bool("zlint", false, "also run the zlint backend (requires a binary built with -tags zlint)")
	zlintSources := fs.String("zlint-sources", "", "restrict zlint to these comma-separated sources (e.g. CABF_BR,RFC5280)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: secsy-ca lint [flags] <cert>   (PEM or DER; use - to read from stdin)")
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

	certBytes, err := readInput(path)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := pki.ParseCertificatePEMOrDER(certBytes)
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
	// -zlint turns the backend on (with default level mapping) even when the
	// profile does not; -zlint-sources narrows the registry. When a profile
	// already enables zlint, these flags refine that policy.
	if *zlintOn || *zlintSources != "" {
		if policy.ZLint == nil {
			policy.ZLint = &certlint.ZLintPolicy{}
		}
		if *zlintSources != "" {
			policy.ZLint.IncludeSources = splitCSV(*zlintSources)
		}
	}
	if policy.ZLint != nil && !certlint.ZLintAvailable() {
		fmt.Fprintln(os.Stderr, "note: zlint requested but this binary was not built with -tags zlint; "+
			"reporting hand-rolled checks only")
	}

	res := certlint.Lint(cert, policy)

	effMode := policy.Mode
	if effMode == "" {
		effMode = certlint.ModeEnforce
	}
	fmt.Printf("Certificate: subject=%q serial=%s not_after=%s\n",
		cert.Subject.String(), cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("Policy: mode=%s public=%t max_validity=%s zlint=%s\n",
		effMode, policy.Public, policy.MaxValidity, zlintStatus(policy.ZLint != nil))
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

// zlintStatus renders the zlint column of the lint policy line: whether the
// backend is requested and whether it is actually compiled into this binary.
func zlintStatus(requested bool) string {
	switch {
	case !requested:
		return "off"
	case certlint.ZLintAvailable():
		return "on"
	default:
		return "requested(not-compiled-in)"
	}
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
				ZLint:     zlintConfigFromConfig(p.Lint.ZLint),
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
		if p.SMIME.Enabled {
			prof.SMIME = &ca.SMIMEConfig{
				Variant:        p.SMIME.Variant,
				BRProfile:      p.SMIME.BRProfile,
				AllowedDomains: p.SMIME.AllowedDomains,
				SubjectEmail:   p.SMIME.SubjectEmail,
			}
		}
		profiles = append(profiles, prof)
	}
	return ca.SetCustomProfiles(profiles)
}

// zlintConfigFromConfig converts a profile's zlint configuration into the
// ca.ZLintConfig consumed by the lint gate, or nil when zlint is not enabled.
func zlintConfigFromConfig(c config.ProfileZLintConfig) *ca.ZLintConfig {
	if !c.Enabled {
		return nil
	}
	return &ca.ZLintConfig{
		Enabled:        true,
		ErrorMode:      c.ErrorMode,
		WarnMode:       c.WarnMode,
		NoticeMode:     c.NoticeMode,
		IncludeSources: c.IncludeSources,
		ExcludeSources: c.ExcludeSources,
		IncludeNames:   c.IncludeNames,
		ExcludeNames:   c.ExcludeNames,
		Overrides:      c.Overrides,
	}
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

// buildProvider constructs the configured key provider for a signing role ("ca"
// or "tsa"), mirroring the server. The role selects the backend via the per-role
// override (key_provider.roles), falling back to the global key_provider.type, so
// a CA on a PKCS#11 HSM and a TSA in cloud KMS can coexist.
// pkcs11TokenSettings maps the config's multi-token HA list onto keyprovider
// token settings, returning nil for the single-token case.
func pkcs11TokenSettings(tokens []config.PKCS11TokenConfig) []keyprovider.TokenSettings {
	if len(tokens) == 0 {
		return nil
	}
	out := make([]keyprovider.TokenSettings, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, keyprovider.TokenSettings{
			Name:              t.Name,
			TokenLabel:        t.TokenLabel,
			TokenSerial:       t.TokenSerial,
			TokenManufacturer: t.TokenManufacturer,
			Pin:               t.Pin,
		})
	}
	return out
}

func buildProvider(cfg *config.Config, role string) (keyprovider.Provider, error) {
	// Ensure the YubiHSM PKCS#11 module can find its connector, matching the
	// server's behavior.
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err == nil {
			_ = os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}
	return keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProviderTypeForRole(role)),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			Pin:               cfg.PKCS11.Pin,
			TokenLabel:        cfg.PKCS11.TokenLabel,
			TokenSerial:       cfg.PKCS11.TokenSerial,
			TokenManufacturer: cfg.PKCS11.TokenManufacturer,
			SessionPoolSize:   cfg.PKCS11.SessionPoolSize,
			Tokens:            pkcs11TokenSettings(cfg.PKCS11.Tokens),
			SelectionPolicy:   cfg.PKCS11.SelectionPolicy,
			FailureThreshold:  cfg.PKCS11.FailureThreshold,
			ProbeInterval:     time.Duration(cfg.PKCS11.ProbeIntervalSeconds) * time.Second,
		},
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: cfg.KeyProvider.Software.KeystoreDir,
		},
		KMS: keyprovider.KMSSettings{
			Backend:   cfg.KeyProvider.KMS.Backend,
			Region:    cfg.KeyProvider.KMS.Region,
			KeyPrefix: cfg.KeyProvider.KMS.KeyPrefix,
			VaultURL:  cfg.KeyProvider.KMS.VaultURL,
			Vault:     vaultSettings(cfg.KeyProvider.KMS.Vault),
		},
	})
}

// vaultSettings maps the config's HashiCorp Vault block onto the keyprovider
// settings type (mirrors the same helper in cmd/server).
func vaultSettings(v config.VaultProviderConfig) keyprovider.VaultSettings {
	return keyprovider.VaultSettings{
		Address:     v.Address,
		Mount:       v.Mount,
		Namespace:   v.Namespace,
		AuthMethod:  v.AuthMethod,
		Token:       v.Token,
		RoleID:      v.RoleID,
		SecretID:    v.SecretID,
		AppRolePath: v.AppRolePath,
		CACertFile:  v.CACertFile,
		Insecure:    v.Insecure,
		Timeout:     time.Duration(v.TimeoutSeconds) * time.Second,
	}
}
