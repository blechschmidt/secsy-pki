// Command secsy-secret is an administrative CLI for HSM-backed envelope
// encryption of passwords and other small secrets. It shares the same config
// file and key provider as the server.
//
// A key-encryption key (KEK) — an RSA key whose private half lives in the HSM
// (via PKCS#11) or the software keystore — wraps a fresh per-message data key.
// The plaintext is sealed with AES-256-GCM under that data key. The resulting
// versioned, self-describing JSON envelope can be stored anywhere; decrypting
// it requires access to the KEK (i.e. the HSM).
//
// Usage:
//
//	secsy-secret [-config config.yaml] <command> [flags]
//
// Commands:
//
//	init-kek   Generate the RSA key-encryption key on the configured provider
//	encrypt    Encrypt stdin/a file into a ciphertext envelope
//	decrypt    Decrypt a ciphertext envelope back to plaintext
//	kek-info   Show metadata about the configured KEK
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		// A child spawned by `exec` determines our exit status directly; its
		// own output already went to the terminal.
		var exit exitCodeError
		if errors.As(err, &exit) {
			os.Exit(exit.code)
		}
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

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// These subcommands only read the database (the tamper-evident event log,
	// the KEK rotation lineage, the stored-secret registry); they never touch
	// key material, so dispatch them before constructing the key provider. This
	// lets an auditor or operator inspect state without the HSM being present
	// or unlocked.
	switch command {
	case "audit":
		return cmdSecretAudit(cfg, cmdArgs)
	case "kek-versions":
		return cmdKEKVersions(cfg, cmdArgs)
	case "list-secrets":
		return cmdListSecrets(cfg, cmdArgs)
	case "versions":
		return cmdVersions(cfg, cmdArgs)
	case "rollback":
		// A rollback copies ciphertext between versions; no key material is
		// touched, so it works even while the HSM is unavailable.
		return cmdRollback(cfg, cmdArgs)
	case "lifecycle":
		return cmdLifecycle(cfg, cmdArgs)
	case "pqc-info":
		// Metadata-only read of the post-quantum hybrid key material.
		return cmdPQCInfo(cfg, cmdArgs)
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	switch command {
	case "init-kek":
		return cmdInitKEK(cfg, provider, cmdArgs)
	case "encrypt":
		return cmdEncrypt(cfg, provider, cmdArgs)
	case "decrypt":
		return cmdDecrypt(cfg, provider, cmdArgs)
	case "datakey":
		return cmdDataKey(cfg, provider, cmdArgs)
	case "hmac":
		return cmdHMAC(cfg, provider, cmdArgs)
	case "hmac-verify":
		return cmdHMACVerify(cfg, provider, cmdArgs)
	case "random":
		return cmdRandom(cfg, provider, cmdArgs)
	case "signing-key":
		return cmdSigningKey(cfg, provider, cmdArgs)
	case "sign":
		return cmdSign(cfg, provider, cmdArgs)
	case "verify":
		return cmdVerify(cfg, provider, cmdArgs)
	case "transform":
		return cmdTransform(cfg, provider, cmdArgs)
	case "put":
		return cmdPut(cfg, provider, cmdArgs)
	case "get":
		return cmdGet(cfg, provider, cmdArgs)
	case "exec":
		return cmdExec(cfg, provider, cmdArgs)
	case "kek-info":
		return cmdKEKInfo(cfg, provider, cmdArgs)
	case "rotate-kek":
		return cmdRotateKEK(cfg, provider, cmdArgs)
	case "retire-kek":
		return cmdRetireKEK(cfg, provider, cmdArgs)
	case "rewrap":
		return cmdRewrap(cfg, provider, cmdArgs)
	case "pqc-enable":
		return cmdPQCEnable(cfg, provider, cmdArgs)
	case "pqc-reseal":
		return cmdPQCReseal(cfg, provider, cmdArgs)
	case "escrow-config":
		return cmdEscrowConfig(cfg, provider, cmdArgs)
	case "escrow-init-agent":
		return cmdEscrowInitAgent(cfg, provider, cmdArgs)
	case "recover":
		return cmdRecover(cfg, provider, cmdArgs)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `secsy-secret — HSM-backed envelope encryption for secrets

Usage:
  secsy-secret [-config config.yaml] <command> [flags]

Commands:
  init-kek           Generate the RSA key-encryption key (KEK) on the provider
  encrypt            Encrypt stdin or a file into a ciphertext envelope (JSON)
                     (add -escrow to also wrap the data key to recovery agents,
                     -store -name NAME to persist it in the stored-secret registry)
  decrypt            Decrypt a ciphertext envelope back to plaintext
                     (accepts envelopes on any non-retired KEK version; -id decrypts
                     a stored secret from the registry)
  datakey            Mint a fresh data key, returned BOTH in the clear and wrapped
                     under the KEK for client-side envelope encryption (-bits, -wrapped-only;
                     recover the key later with the decrypt command)
  hmac               Compute a keyed HMAC over stdin/a file with the family's
                     HSM/KEK-derived MAC key (provisioned on first use)
  hmac-verify        Verify a keyed HMAC (-hmac TAG [-version N]); exits non-zero on mismatch
  random             Generate CSPRNG bytes from the HSM RNG when available (-bytes, -format)
  signing-key        Manage named HSM-backed asymmetric signing keys:
                     create (-name, -algorithm one of ecdsa-p256|ecdsa-p384|
                     ecdsa-p521|ed25519|rsa-pss-{2048,3072,4096}|
                     rsa-pkcs1v15-{2048,3072,4096}), list, public
                     (export the SPKI public key for external verifiers)
  sign               Sign stdin/a file with a named signing key (-key, -hash, -prehashed);
                     the private key never leaves the HSM
  verify             Verify a signature against a stored key's public half (-key) or a
                     supplied public-key file (-public-key + -algorithm), -signature/-sig-in;
                     exits non-zero on mismatch
  transform          Format-preserving encryption / tokenization (FF1): encode|decode a
                     value through a named secret.transforms template (-template, -value/-in)
  put                Create or update a named stored secret; every put appends a
                     new value version (-ttl-days / -rotate-every-days arm reminders)
  get                Decrypt a stored secret by name (-version N for older values)
  versions           Show a stored secret's value history
  rollback           Make an older value version current again (appends a copy;
                     history is never rewritten; works without the HSM)
  lifecycle          Show stored secrets due for TTL/rotation attention
  exec               Decrypt secrets into a child process environment and run it:
                     secsy-secret exec -secret db-pass:PGPASSWORD -- psql ...
                     ({{secret:NAME}} templating in argv and -env VAR=value; env
                     injection is preferred — argv is visible in /proc)
  kek-info           Show metadata about the configured KEK
  rotate-kek         Generate the next versioned KEK in the HSM and make it active
                     (existing envelopes keep decrypting under the retiring version)
  rewrap             Re-wrap data keys onto the active KEK version (-all, -id, or -in FILE);
                     data ciphertext and escrow shares are untouched
  retire-kek         Withdraw a superseded KEK version (fails while secrets remain on it)
  kek-versions       Show the family's rotation lineage and per-version secret counts
  pqc-enable         Provision ML-KEM-1024 post-quantum hybrid material for a KEK family
                     (new envelopes also protect the data key with an ML-KEM encapsulation
                     when secret.pqc_hybrid is enabled — harvest-now-decrypt-later resistance)
  pqc-info           Show a family's post-quantum hybrid key material (metadata only)
  pqc-reseal         Re-seal the ML-KEM decapsulation key under the active KEK version
                     (run after a classical rotation, before retiring the old sealing version)
  list-secrets       List the stored-secret registry (metadata only)
  escrow-config      Show/verify the M-of-N key-escrow configuration
  escrow-init-agent  Generate an RSA recovery-agent key on the provider
  recover            Recover plaintext under a quorum of recovery agents
  audit              Show/verify secret-lifecycle audit-log events

Run "secsy-secret <command> -h" for command-specific flags.
`)
}

// resolveKEK returns the KEK label from a -kek flag if set, otherwise the
// secret.kek_label from config.
func resolveKEK(cfg *config.Config, flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if cfg.Secret.KEKLabel != "" {
		return cfg.Secret.KEKLabel, nil
	}
	return "", fmt.Errorf("no KEK label configured: set secret.kek_label in config or pass -kek")
}

func cmdInitKEK(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("init-kek", flag.ContinueOnError)
	label := fs.String("kek", "", "KEK label (default: secret.kek_label from config)")
	keyType := fs.String("key-type", "rsa-4096", "RSA key type for the KEK (rsa-2048 or rsa-4096)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kek, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}

	svc, err := secret.ProvisionKEK(context.Background(), provider, kek, *keyType)
	if err != nil {
		return err
	}
	info := svc.KEKInfo()
	fmt.Printf("Key-encryption key created:\n")
	printKEK(info)
	fmt.Fprintf(os.Stderr, "\nAdd this to your config so the server and CLI can find it:\n  secret:\n    kek_label: %q\n", info.Label)

	// When post-quantum hybrid mode is enabled, provision the family's ML-KEM
	// material in the same step so the KEK is immediately usable for hybrid
	// sealing (Task 137).
	if cfg.Secret.PQCHybrid {
		if err := provisionPQCForKEK(cfg, svc, info.Label); err != nil {
			return fmt.Errorf("KEK was created but provisioning post-quantum hybrid material failed (run `secsy-secret pqc-enable` once the issue is resolved): %w", err)
		}
	}
	return nil
}

func cmdKEKInfo(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("kek-info", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (default: the family's ACTIVE KEK version)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ring, svc, err := serviceOrRing(cfg, provider, *label)
	if err != nil {
		return err
	}
	if ring != nil {
		svc = ring.Active()
		fmt.Printf("KEK family %q (active version %d; see `secsy-secret kek-versions` for the lineage)\n",
			ring.Family(), ring.ActiveVersion())
	}
	printKEK(svc.KEKInfo())
	return nil
}

func cmdEncrypt(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (default: the family's ACTIVE KEK version)")
	in := fs.String("in", "-", "input plaintext file, or '-' for stdin")
	out := fs.String("out", "-", "output envelope file, or '-' for stdout")
	context_ := fs.String("context", "", "optional encryption context bound to the ciphertext (required verbatim to decrypt)")
	escrow := fs.Bool("escrow", false, "additionally escrow the data key to the configured M-of-N recovery agents")
	store := fs.Bool("store", false, "persist the envelope in the stored-secret registry (requires -name and the database)")
	name := fs.String("name", "", "tenant-unique name for the stored secret (with -store)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant for the stored secret (with -store)")
	ttlDays := fs.Int("ttl-days", 0, "TTL for the stored secret: expiry reminder after this many days (with -store; 0 = none)")
	rotateEvery := fs.Int("rotate-every-days", 0, "rotation-reminder period for the stored secret in days (with -store; 0 = none)")
	operator := fs.String("operator", "", "operator identity recorded in the escrow audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store && *name == "" {
		return fmt.Errorf("-store requires -name")
	}
	if *ttlDays < 0 || *rotateEvery < 0 {
		return fmt.Errorf("-ttl-days and -rotate-every-days must be >= 0")
	}
	if *store && *label != "" {
		return fmt.Errorf("-store seals under the family's active KEK version; it cannot be combined with an explicit -kek")
	}

	// Rotation-aware sealing: encrypt under the family's active KEK version so
	// a rotated deployment never seals new ciphertext under a superseded key.
	ring, svc, err := serviceOrRing(cfg, provider, *label)
	if err != nil {
		return err
	}
	var ops envelopeOps = svc
	if ring != nil {
		ops = ring
	}

	plaintext, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading plaintext: %w", err)
	}
	defer zero(plaintext)

	// Resolve the escrow policy (if requested) before any encryption happens.
	var policy *secret.EscrowPolicy
	if *escrow {
		if policy, err = escrowPolicyFromConfig(context.Background(), cfg, provider); err != nil {
			return err
		}
	}

	blob, err := ops.EncryptWithEscrowToJSON(plaintext, []byte(*context_), policy)
	if err != nil {
		return err
	}

	family, _ := resolveKEK(cfg, *label)
	if policy != nil {
		db, err := openAuditDB(cfg)
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("threshold=%d agents=[%s]", policy.Threshold(), agentIDsCSV(policy))
		err = recordEscrowEvent(db, operatorActor(*operator), audit.ActionSecretEscrow, family, audit.ResultSuccess, detail)
		_ = db.Close()
		if err != nil {
			return fmt.Errorf("secret was escrow-encrypted but recording the audit event failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Escrowed to %d recovery agent(s), %d-of-%d quorum required for recovery.\n",
			len(policy.Agents()), policy.Threshold(), len(policy.Agents()))
	}

	if *store {
		if ring == nil {
			return fmt.Errorf("-store requires the KEK rotation state (database) to record the sealing KEK version")
		}
		db, err := openAuditDB(cfg)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		stored, err := storeEncryptedSecret(db, *tenant, *name, family, ring, blob, *context_ != "", policy != nil,
			storeSecretSpec{ttlDays: *ttlDays, rotateEveryDays: *rotateEvery, operator: operatorActor(*operator)})
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("id=%s kek_label=%s kek_version=%d escrow=%v", stored.ID, stored.KEKLabel, stored.KEKVersion, stored.Escrowed)
		if err := recordEscrowEvent(db, operatorActor(*operator), audit.ActionSecretStore, *name, audit.ResultSuccess, detail); err != nil {
			return fmt.Errorf("secret was stored but recording the audit event failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Stored secret %q (id %s) sealed under KEK version %d.\n", stored.Name, stored.ID, stored.KEKVersion)
	}
	return writeOutput(*out, append(blob, '\n'))
}

// agentIDsCSV renders a policy's recovery-agent IDs as a comma-separated string
// for the audit detail.
func agentIDsCSV(policy *secret.EscrowPolicy) string {
	ids := make([]string, 0, len(policy.Agents()))
	for _, a := range policy.Agents() {
		ids = append(ids, a.ID)
	}
	return strings.Join(ids, ",")
}

func cmdDecrypt(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (disaster-recovery path; skips the rotation state)")
	in := fs.String("in", "-", "input envelope file, or '-' for stdin")
	id := fs.String("id", "", "decrypt a stored secret from the registry by ID (instead of -in)")
	out := fs.String("out", "-", "output plaintext file, or '-' for stdout")
	context_ := fs.String("context", "", "encryption context that was bound at encryption time")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var blob []byte
	if *id != "" {
		db, err := openAuditDB(cfg)
		if err != nil {
			return err
		}
		s, err := db.GetStoredSecret(*id)
		_ = db.Close()
		if err != nil {
			return err
		}
		if s == nil {
			return fmt.Errorf("no stored secret with id %q", *id)
		}
		blob = []byte(s.Envelope)
	} else {
		var err error
		if blob, err = readInput(*in); err != nil {
			return fmt.Errorf("reading envelope: %w", err)
		}
	}

	// Rotation-aware opening: the ring accepts envelopes wrapped under the
	// active or any still-retiring KEK version (and refuses retired ones). An
	// explicit -kek override, or a missing database, falls back to a single
	// KEK — the path that keeps decryption working in disaster recovery with
	// nothing but the HSM.
	ring, svc, err := serviceOrRing(cfg, provider, *label)
	if err != nil {
		return err
	}
	var plaintext []byte
	if ring != nil {
		plaintext, err = ring.DecryptJSON(context.Background(), blob, []byte(*context_))
	} else {
		plaintext, err = svc.DecryptJSON(blob, []byte(*context_))
	}
	if err != nil {
		return err
	}
	defer zero(plaintext)
	return writeOutput(*out, plaintext)
}

func printKEK(info secret.KEKInfo) {
	fmt.Printf("  Label:    %s\n", info.Label)
	fmt.Printf("  Version:  %d\n", info.Version)
	fmt.Printf("  Provider: %s\n", info.Provider)
	fmt.Printf("  Key bits: %d\n", info.KeyBits)
	fmt.Printf("  Wrap alg: %s\n", info.WrapAlg)
	if info.URI != "" {
		fmt.Printf("  URI:      %s\n", info.URI)
	}
}

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
			URI:               t.URI,
			TokenLabel:        t.TokenLabel,
			TokenSerial:       t.TokenSerial,
			TokenManufacturer: t.TokenManufacturer,
			Pin:               t.Pin,
			PinSource:         pinSourceSettings(t.PinSource),
		})
	}
	return out
}

// vaultSettings maps the config's HashiCorp Vault block onto the keyprovider
// settings type (mirrors the helper in cmd/secsy-ca and cmd/server).
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

// pinSourceSettings maps the config pin_source block onto the keyprovider settings
// type (mirrors the helper in cmd/secsy-ca and cmd/server).
func pinSourceSettings(p config.PinSourceConfig) keyprovider.PinSourceSettings {
	return keyprovider.PinSourceSettings{
		Type: p.Type,
		Env:  keyprovider.EnvPinSourceSettings{Var: p.Env.Var},
		File: keyprovider.FilePinSourceSettings{Path: p.File.Path, AllowInsecurePerms: p.File.AllowInsecurePerms},
		Vault: keyprovider.VaultPinSourceSettings{
			VaultSettings: vaultSettings(p.Vault.VaultProviderConfig),
			Path:          p.Vault.Path,
			Field:         p.Vault.Field,
			KVVersion:     p.Vault.KVVersion,
		},
		AWS:   keyprovider.AWSPinSourceSettings{Region: p.AWS.Region, SecretID: p.AWS.SecretID, Field: p.AWS.Field},
		Azure: keyprovider.AzurePinSourceSettings{VaultURL: p.Azure.VaultURL, Name: p.Azure.Name, Version: p.Azure.Version, Field: p.Azure.Field},
		GCP: keyprovider.GCPPinSourceSettings{
			Project:         p.GCP.Project,
			Secret:          p.GCP.Secret,
			Version:         p.GCP.Version,
			CredentialsFile: p.GCP.CredentialsFile,
			CredentialsJSON: p.GCP.CredentialsJSON,
			Field:           p.GCP.Field,
			Endpoint:        p.GCP.Endpoint,
		},
	}
}

// buildProvider constructs the configured key provider, mirroring secsy-ca.
func buildProvider(cfg *config.Config) (keyprovider.Provider, error) {
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err == nil {
			_ = os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}
	return keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProvider.Type),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			URI:               cfg.PKCS11.URI,
			Pin:               cfg.PKCS11.Pin,
			PinSource:         pinSourceSettings(cfg.PKCS11.PinSource),
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
	})
}

func readInput(path string) ([]byte, error) {
	if path == "-" || path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	// Envelopes are non-secret, but plaintext output may be sensitive; write
	// with restrictive permissions.
	return os.WriteFile(path, data, 0o600)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
