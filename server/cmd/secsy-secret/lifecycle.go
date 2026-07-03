package main

// Stored-secret value lifecycle commands (Task 73): put (create-or-update a
// named secret, appending a version), get (decrypt by name, optionally an
// older version), versions (history), rollback (re-activate an older value),
// lifecycle (TTL/rotation due report), and exec (decrypt secrets into a child
// process environment — never onto disk).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"

	"flag"
)

// exitCodeError propagates a child process's exit status through run() so
// `secsy-secret exec` exits with the child's code.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("child exited with status %d", e.code) }

// tenantFamily resolves a tenant selector (id or slug) to the tenant ID and
// its effective KEK family: the tenant's own kek_label when set, otherwise
// the deployment-wide secret.kek_label — the same resolution the server
// applies to API requests.
func tenantFamily(cfg *config.Config, db *database.DB, sel string) (string, string, error) {
	if sel == "" {
		sel = models.DefaultTenantID
	}
	t, err := db.GetTenant(sel)
	if err != nil {
		return "", "", err
	}
	if t == nil {
		if t, err = db.GetTenantBySlug(sel); err != nil {
			return "", "", err
		}
	}
	if t == nil {
		return "", "", fmt.Errorf("unknown tenant %q", sel)
	}
	family := t.KEKLabel
	if family == "" {
		family = cfg.Secret.KEKLabel
	}
	if family == "" {
		return "", "", fmt.Errorf("no KEK configured: set secret.kek_label in config (or a tenant kek_label)")
	}
	return t.ID, family, nil
}

// lookupSecret resolves -name/-id to a stored secret within the tenant.
func lookupSecret(db *database.DB, tenantID, name, id string) (*models.StoredSecret, error) {
	switch {
	case name != "" && id != "":
		return nil, fmt.Errorf("pass either -name or -id, not both")
	case name != "":
		s, err := db.GetStoredSecretByName(tenantID, name)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, fmt.Errorf("no stored secret named %q in tenant %q", name, tenantID)
		}
		return s, nil
	case id != "":
		s, err := db.GetStoredSecret(id)
		if err != nil {
			return nil, err
		}
		if s == nil || s.TenantID != tenantID {
			return nil, fmt.Errorf("no stored secret with id %q in tenant %q", id, tenantID)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("-name or -id is required")
	}
}

// cmdPut creates a named secret or appends a new value version to it: the
// plaintext is sealed under the family's active KEK, the envelope stored, and
// the previous value kept in the version history.
func cmdPut(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	name := fs.String("name", "", "tenant-unique secret name (required)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (id or slug)")
	in := fs.String("in", "-", "input plaintext file, or '-' for stdin")
	context_ := fs.String("context", "", "optional encryption context bound to the ciphertext (required verbatim to decrypt)")
	escrow := fs.Bool("escrow", false, "additionally escrow the data key to the configured M-of-N recovery agents")
	ttlDays := fs.Int("ttl-days", -1, "TTL in days: expiry reminder deadline (0 clears, -1 keeps the current setting)")
	rotateEvery := fs.Int("rotate-every-days", -1, "rotation-reminder period in days (0 clears, -1 keeps the current setting)")
	comment := fs.String("comment", "", "free-form note recorded on the new version")
	expectVersion := fs.Int("expect-version", 0, "fail unless the secret is currently at this version (0 = latest)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	actor := operatorActor(*operator)

	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("put requires the database (stored secrets and audit): %w", err)
	}
	defer func() { _ = db.Close() }()
	tenantID, family, err := tenantFamily(cfg, db, *tenant)
	if err != nil {
		return err
	}
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		return err
	}
	ring, err := secret.LoadRing(context.Background(), provider, family, versions)
	if err != nil {
		return err
	}

	plaintext, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading plaintext: %w", err)
	}
	defer zero(plaintext)
	if len(plaintext) == 0 {
		return fmt.Errorf("refusing to store an empty secret")
	}

	var policy *secret.EscrowPolicy
	if *escrow {
		if policy, err = escrowPolicyFromConfig(context.Background(), cfg, provider); err != nil {
			return err
		}
	}
	blob, err := ring.EncryptWithEscrowToJSON(plaintext, []byte(*context_), policy)
	if err != nil {
		return err
	}

	existing, err := db.GetStoredSecretByName(tenantID, *name)
	if err != nil {
		return err
	}
	if existing == nil {
		if *expectVersion > 0 {
			return fmt.Errorf("secret %q does not exist yet (expect-version %d)", *name, *expectVersion)
		}
		spec := storeSecretSpec{operator: actor, comment: *comment}
		if *ttlDays > 0 {
			spec.ttlDays = *ttlDays
		}
		if *rotateEvery > 0 {
			spec.rotateEveryDays = *rotateEvery
		}
		stored, err := storeEncryptedSecret(db, tenantID, *name, family, ring, blob, *context_ != "", policy != nil, spec)
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("id=%s version=1 kek_label=%s kek_version=%d escrow=%v", stored.ID, stored.KEKLabel, stored.KEKVersion, stored.Escrowed)
		if err := recordEscrowEvent(db, actor, audit.ActionSecretStore, *name, audit.ResultSuccess, detail); err != nil {
			return fmt.Errorf("secret was stored but recording the audit event failed: %w", err)
		}
		fmt.Printf("Created secret %q (id %s), version 1, sealed under KEK version %d.\n", stored.Name, stored.ID, stored.KEKVersion)
		printSchedule(stored)
		return nil
	}

	expect := existing.CurrentVersion
	if *expectVersion > 0 {
		expect = *expectVersion
	}
	put := &database.PutSecretVersion{
		ID:            existing.ID,
		Envelope:      strings.TrimSpace(string(blob)),
		KEKFamily:     family,
		KEKLabel:      ring.ActiveLabel(),
		KEKVersion:    ring.ActiveVersion(),
		ContextBound:  *context_ != "",
		Escrowed:      policy != nil,
		CreatedBy:     actor,
		Comment:       *comment,
		ExpectVersion: expect,
	}
	if *ttlDays >= 0 {
		put.SetExpiresAt = true
		if *ttlDays > 0 {
			exp := time.Now().UTC().AddDate(0, 0, *ttlDays)
			put.ExpiresAt = &exp
		}
	}
	if *rotateEvery >= 0 {
		put.SetRotateEveryDays = true
		put.RotateEveryDays = *rotateEvery
	}
	updated, err := db.PutStoredSecretVersion(put)
	if err != nil {
		if err == database.ErrSecretVersionConflict {
			_ = recordEscrowEvent(db, actor, audit.ActionSecretPut, *name, audit.ResultError, "concurrent update")
			return fmt.Errorf("secret %q was modified concurrently (expected version %d); re-read and retry", *name, expect)
		}
		_ = recordEscrowEvent(db, actor, audit.ActionSecretPut, *name, audit.ResultError, err.Error())
		return err
	}
	detail := fmt.Sprintf("id=%s version=%d kek_label=%s kek_version=%d escrow=%v",
		updated.ID, updated.CurrentVersion, updated.KEKLabel, updated.KEKVersion, updated.Escrowed)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretPut, *name, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("secret was updated but recording the audit event failed: %w", err)
	}
	fmt.Printf("Updated secret %q (id %s) to version %d, sealed under KEK version %d.\n",
		updated.Name, updated.ID, updated.CurrentVersion, updated.KEKVersion)
	printSchedule(updated)
	return nil
}

// printSchedule reports a secret's lifecycle schedule on stdout.
func printSchedule(s *models.StoredSecret) {
	if s.ExpiresAt != nil {
		fmt.Printf("  Expires: %s\n", s.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if s.RotateEveryDays > 0 {
		fmt.Printf("  Rotation reminder: every %d day(s)\n", s.RotateEveryDays)
	}
}

// cmdGet decrypts a stored secret by name or ID — the current value, or an
// older one with -version.
func cmdGet(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	name := fs.String("name", "", "secret name")
	id := fs.String("id", "", "secret ID (alternative to -name)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (id or slug)")
	version := fs.Int("version", 0, "value-history version to decrypt (0 = current)")
	context_ := fs.String("context", "", "encryption context that was bound at encryption time")
	out := fs.String("out", "-", "output plaintext file, or '-' for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	tenantID, _, err := tenantFamily(cfg, db, *tenant)
	if err != nil {
		return err
	}
	s, err := lookupSecret(db, tenantID, *name, *id)
	if err != nil {
		return err
	}

	envelope := s.Envelope
	family := s.KEKFamily
	if *version > 0 && *version != s.CurrentVersion {
		v, err := db.GetStoredSecretVersion(s.ID, *version)
		if err != nil {
			return err
		}
		if v == nil {
			return fmt.Errorf("secret %q has no version %d", s.Name, *version)
		}
		envelope, family = v.Envelope, v.KEKFamily
	}
	if s.ExpiresAt != nil && time.Now().After(*s.ExpiresAt) {
		fmt.Fprintf(os.Stderr, "WARNING: secret %q expired %s; rotate it.\n", s.Name, s.ExpiresAt.UTC().Format(time.RFC3339))
	}

	versions, err := db.ListKEKVersions(family)
	if err != nil {
		return err
	}
	ring, err := secret.LoadRing(context.Background(), provider, family, versions)
	if err != nil {
		return err
	}
	plaintext, err := ring.DecryptJSON(context.Background(), []byte(envelope), []byte(*context_))
	if err != nil {
		return err
	}
	defer zero(plaintext)
	return writeOutput(*out, plaintext)
}

// cmdVersions prints a secret's value history (metadata only).
func cmdVersions(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	name := fs.String("name", "", "secret name")
	id := fs.String("id", "", "secret ID (alternative to -name)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (id or slug)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	tenantID, _, err := tenantFamily(cfg, db, *tenant)
	if err != nil {
		return err
	}
	s, err := lookupSecret(db, tenantID, *name, *id)
	if err != nil {
		return err
	}
	versions, err := db.ListStoredSecretVersions(s.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Secret %q (id %s) — current version %d\n\n", s.Name, s.ID, s.CurrentVersion)
	fmt.Printf("  %-8s %-8s %-24s %-4s %-20s %-16s %s\n", "VERSION", "CURRENT", "KEK LABEL", "VER", "CREATED", "BY", "COMMENT")
	for _, v := range versions {
		current := ""
		if v.Version == s.CurrentVersion {
			current = "*"
		}
		fmt.Printf("  %-8d %-8s %-24s %-4d %-20s %-16s %s\n",
			v.Version, current, v.KEKLabel, v.KEKVersion,
			v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), v.CreatedBy, v.Comment)
	}
	return nil
}

// cmdRollback re-activates an older value version by appending a copy of it
// as the new current version. Pure ciphertext copy — no HSM required — but
// refused when the target sits on a retired KEK version.
func cmdRollback(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	name := fs.String("name", "", "secret name")
	id := fs.String("id", "", "secret ID (alternative to -name)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (id or slug)")
	version := fs.Int("version", 0, "value-history version to make current again (required)")
	comment := fs.String("comment", "", "free-form note recorded on the new version")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version < 1 {
		return fmt.Errorf("-version is required")
	}
	actor := operatorActor(*operator)

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	tenantID, _, err := tenantFamily(cfg, db, *tenant)
	if err != nil {
		return err
	}
	s, err := lookupSecret(db, tenantID, *name, *id)
	if err != nil {
		return err
	}
	if *version == s.CurrentVersion {
		return fmt.Errorf("version %d is already current", *version)
	}
	v, err := db.GetStoredSecretVersion(s.ID, *version)
	if err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("secret %q has no version %d", s.Name, *version)
	}
	// Fail-closed: never make an undecryptable envelope the current value.
	kekVersions, err := db.ListKEKVersions(v.KEKFamily)
	if err != nil {
		return err
	}
	for _, kv := range kekVersions {
		if kv.Label == v.KEKLabel && kv.Status == models.KEKStatusRetired {
			return fmt.Errorf("version %d is wrapped under RETIRED KEK %q (version %d); reinstate the KEK version first",
				*version, kv.Label, kv.Version)
		}
	}

	note := *comment
	if note == "" {
		note = fmt.Sprintf("rollback to version %d", *version)
	}
	updated, err := db.PutStoredSecretVersion(&database.PutSecretVersion{
		ID:            s.ID,
		Envelope:      v.Envelope,
		KEKFamily:     v.KEKFamily,
		KEKLabel:      v.KEKLabel,
		KEKVersion:    v.KEKVersion,
		ContextBound:  v.ContextBound,
		Escrowed:      v.Escrowed,
		CreatedBy:     actor,
		Comment:       note,
		ExpectVersion: s.CurrentVersion,
	})
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRollback, s.Name, audit.ResultError, err.Error())
		return err
	}
	detail := fmt.Sprintf("id=%s from_version=%d new_version=%d", s.ID, *version, updated.CurrentVersion)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretRollback, s.Name, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("rollback applied but recording the audit event failed: %w", err)
	}
	fmt.Printf("Secret %q rolled back: version %d's value is current again as version %d.\n",
		s.Name, *version, updated.CurrentVersion)
	return nil
}

// cmdLifecycle prints the TTL/rotation due report across all tenants —
// exactly what the monitor's reminder scan would flag right now.
func cmdLifecycle(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	secrets, err := db.ListStoredSecretsWithSchedule()
	if err != nil {
		return err
	}
	warning, critical := cfg.Monitor.WarningDays, cfg.Monitor.CriticalDays
	if warning <= 0 {
		warning = 30
	}
	if critical <= 0 {
		critical = 7
	}
	items := monitor.ClassifySecrets(secrets, warning, critical, time.Now().UTC())
	if len(items) == 0 {
		fmt.Printf("No stored secrets due for TTL or rotation attention (%d with a schedule).\n", len(secrets))
		return nil
	}
	fmt.Printf("%-10s %-13s %-12s %-24s %-4s %s\n", "SEVERITY", "STATE", "TENANT", "NAME", "VER", "DETAIL")
	for _, it := range items {
		fmt.Printf("%-10s %-13s %-12s %-24s %-4d %s\n",
			it.Severity, it.State, it.TenantID, it.Name, it.CurrentVersion, it.Detail)
	}
	return nil
}

// cmdExec decrypts stored secrets into a child process's environment (and,
// via {{secret:NAME}} templating, its argv or explicit -env values), then
// runs the command. Plaintext lives only in process memory and the child's
// environment — never on disk. Argv templating is visible in /proc/<pid>/
// cmdline; prefer env injection for anything long-lived.
func cmdExec(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (id or slug)")
	var secretFlags, envFlags multiFlag
	fs.Var(&secretFlags, "secret", "secret to inject as an environment variable: NAME[@VERSION][:VAR] (repeatable; VAR defaults to the upper-cased name)")
	fs.Var(&envFlags, "env", "explicit VAR=value assignment; value may embed {{secret:NAME[@VERSION]}} placeholders (repeatable)")
	context_ := fs.String("context", "", "encryption context for context-bound secrets (applies to all)")
	noInherit := fs.Bool("no-inherit", false, "start from an empty environment instead of inheriting this process's")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("no command given: secsy-secret exec [flags] -- command [args...]")
	}
	actor := operatorActor(*operator)

	spec := secret.ExecSpec{Argv: argv}
	if !*noInherit {
		spec.BaseEnv = os.Environ()
	}
	for _, sf := range secretFlags {
		se, err := secret.ParseSecretEnv(sf)
		if err != nil {
			return err
		}
		spec.Secrets = append(spec.Secrets, se)
	}
	for _, ef := range envFlags {
		et, err := secret.ParseEnvTemplate(ef)
		if err != nil {
			return err
		}
		spec.EnvTemplates = append(spec.EnvTemplates, et)
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("exec requires the database (stored secrets and audit): %w", err)
	}
	defer func() { _ = db.Close() }()
	tenantID, _, err := tenantFamily(cfg, db, *tenant)
	if err != nil {
		return err
	}

	// Resolve each reference through the registry and the family's KEK ring;
	// rings are cached per family (a tenant's secrets may span families after
	// a tenant-KEK change).
	rings := map[string]*secret.Ring{}
	ringFor := func(family string) (*secret.Ring, error) {
		if ring, ok := rings[family]; ok {
			return ring, nil
		}
		versions, err := db.ListKEKVersions(family)
		if err != nil {
			return nil, err
		}
		ring, err := secret.LoadRing(context.Background(), provider, family, versions)
		if err != nil {
			return nil, err
		}
		rings[family] = ring
		return ring, nil
	}
	source := func(ref string) ([]byte, error) {
		refName, refVersion, err := secret.ParseSecretRef(ref)
		if err != nil {
			return nil, err
		}
		s, err := db.GetStoredSecretByName(tenantID, refName)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, fmt.Errorf("no stored secret named %q in tenant %q", refName, tenantID)
		}
		envelope, family := s.Envelope, s.KEKFamily
		if refVersion > 0 && refVersion != s.CurrentVersion {
			v, err := db.GetStoredSecretVersion(s.ID, refVersion)
			if err != nil {
				return nil, err
			}
			if v == nil {
				return nil, fmt.Errorf("secret %q has no version %d", refName, refVersion)
			}
			envelope, family = v.Envelope, v.KEKFamily
		}
		if s.ExpiresAt != nil && time.Now().After(*s.ExpiresAt) {
			fmt.Fprintf(os.Stderr, "WARNING: secret %q expired %s; rotate it.\n", refName, s.ExpiresAt.UTC().Format(time.RFC3339))
		}
		ring, err := ringFor(family)
		if err != nil {
			return nil, err
		}
		return ring.DecryptJSON(context.Background(), []byte(envelope), []byte(*context_))
	}

	childArgv, childEnv, usedRefs, err := secret.BuildExecEnv(spec, source)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretExec, strings.Join(argv, " "), audit.ResultError, err.Error())
		return err
	}
	if len(usedRefs) == 0 {
		fmt.Fprintln(os.Stderr, "note: no secrets referenced; running the command with an unmodified environment")
	}

	// The audit event must land before the child runs: which secrets, into
	// which command — never any plaintext.
	detail := fmt.Sprintf("secrets=[%s] command=%q tenant=%s", strings.Join(usedRefs, ","), childArgv[0], tenantID)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretExec, strings.Join(usedRefs, ","), audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("refusing to exec: recording the audit event failed: %w", err)
	}
	return runChild(childArgv, childEnv)
}

// runChild executes the command with the injected environment, forwarding
// termination signals and propagating the exit status.
func runChild(argv, env []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return err
	}
	sig := make(chan os.Signal, 16)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	defer close(done)
	defer signal.Stop(sig)
	go func() {
		for {
			select {
			case s := <-sig:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err = cmd.Wait()
	if ee, ok := err.(*exec.ExitError); ok {
		return exitCodeError{code: ee.ExitCode()}
	}
	return err
}
