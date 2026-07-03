package main

// KEK rotation, DEK re-wrap, and stored-secret commands (Task 63).
//
// Rotation state (the versioned KEK lineage) and the stored-secret registry
// live in the same database the server uses, so the CLI and the REST API see
// one consistent rotation posture. Every state-changing command appends to the
// tamper-evident audit log (secret.kek_rotate / secret.rewrap /
// secret.kek_retire), mirroring the escrow/recovery commands.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// newSecretID mints a stored-secret identifier.
func newSecretID() string { return uuid.New().String() }

// ringFromDB loads the KEK family's rotation lineage from the configured
// database and assembles the dual-KEK Ring. The database is only needed while
// loading; the returned ring talks to the key provider alone.
func ringFromDB(cfg *config.Config, provider keyprovider.Provider, family string) (*secret.Ring, error) {
	db, err := openAuditDB(cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		return nil, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	return secret.LoadRing(context.Background(), provider, family, versions)
}

// serviceOrRing returns the envelope service for a command: an explicit -kek
// override binds directly to that label (works with no database — the
// disaster-recovery path), otherwise the family Ring is loaded so encrypt uses
// the active KEK version and decrypt honors the dual-KEK window. When no
// database is configured the legacy single-KEK service is used with a warning,
// since a rotated deployment's state lives in the database.
type envelopeOps interface {
	EncryptToJSON(plaintext, context []byte) ([]byte, error)
	EncryptWithEscrowToJSON(plaintext, context []byte, escrow *secret.EscrowPolicy) ([]byte, error)
}

func serviceOrRing(cfg *config.Config, provider keyprovider.Provider, explicitKEK string) (*secret.Ring, *secret.Service, error) {
	if explicitKEK != "" {
		svc, err := secret.NewService(context.Background(), provider, keyprovider.KeyRef{Label: explicitKEK})
		return nil, svc, err
	}
	family, err := resolveKEK(cfg, "")
	if err != nil {
		return nil, nil, err
	}
	ring, ringErr := ringFromDB(cfg, provider, family)
	if ringErr == nil {
		return ring, nil, nil
	}
	fmt.Fprintf(os.Stderr, "warning: KEK rotation state unavailable (%v); using the base KEK %q directly\n", ringErr, family)
	svc, err := secret.NewService(context.Background(), provider, keyprovider.KeyRef{Label: family})
	return nil, svc, err
}

// recordRotationEvent appends one rotation-lifecycle event to the audit chain.
// State-changing rotation operations must be auditable; failing to record is a
// hard error, mirroring recovery ceremonies.
func recordRotationEvent(cfg *config.Config, actor, action, target, result, detail string) error {
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	return recordEscrowEvent(db, actor, action, target, result, detail)
}

// cmdRotateKEK generates the family's next versioned wrapping key in the HSM
// and makes it active. Existing envelopes keep decrypting under the superseded
// (now retiring) version until re-wrapped.
func cmdRotateKEK(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("rotate-kek", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family to rotate (default: secret.kek_label from config)")
	keyType := fs.String("key-type", "rsa-4096", "RSA key type for the new KEK version (rsa-2048 or rsa-4096)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fam, err := resolveKEK(cfg, *family)
	if err != nil {
		return err
	}
	actor := operatorActor(*operator)

	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("KEK rotation requires the database (rotation state and audit): %w", err)
	}
	defer db.Close()

	res, err := secret.RotateKEK(context.Background(), provider, db, fam, *keyType)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretKEKRotate, fam, audit.ResultError, err.Error())
		return err
	}
	detail := fmt.Sprintf("old_version=%d old_label=%s new_version=%d new_label=%s adopted=%v",
		res.OldVersion, res.OldLabel, res.NewVersion, res.NewLabel, res.Adopted)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretKEKRotate, fam, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("KEK was rotated but recording the audit event failed: %w", err)
	}
	_, _ = secret.RefreshKEKMetrics(db, fam)

	fmt.Printf("KEK family %q rotated:\n", fam)
	fmt.Printf("  Superseded: version %d (label %q) — now retiring, still decrypts\n", res.OldVersion, res.OldLabel)
	fmt.Printf("  Active:     version %d (label %q)%s\n", res.NewVersion, res.NewLabel,
		map[bool]string{true: " (adopted an orphaned key from a prior attempt)", false: ""}[res.Adopted])
	fmt.Fprintf(os.Stderr, "\nNew envelopes seal under version %d. Migrate existing secrets with:\n  secsy-secret rewrap -all\nthen withdraw the old version once drained:\n  secsy-secret retire-kek -version %d\n",
		res.NewVersion, res.OldVersion)
	return nil
}

// cmdRetireKEK withdraws a superseded KEK version from service (fail-closed:
// refused while stored secrets still sit on it, unless -force).
func cmdRetireKEK(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("retire-kek", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family (default: secret.kek_label from config)")
	version := fs.Int("version", 0, "KEK version to retire (required)")
	force := fs.Bool("force", false, "retire even while stored secrets are still wrapped under the version (they become undecryptable)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version < 1 {
		return fmt.Errorf("-version is required")
	}
	fam, err := resolveKEK(cfg, *family)
	if err != nil {
		return err
	}
	actor := operatorActor(*operator)

	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("KEK retirement requires the database (rotation state and audit): %w", err)
	}
	defer db.Close()

	retired, err := secret.RetireKEK(db, fam, *version, *force)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretKEKRetire, fam, audit.ResultError, err.Error())
		return err
	}
	detail := fmt.Sprintf("version=%d label=%s force=%v", retired.Version, retired.Label, *force)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretKEKRetire, fam, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("KEK was retired but recording the audit event failed: %w", err)
	}
	_, _ = secret.RefreshKEKMetrics(db, fam)
	fmt.Printf("KEK family %q version %d (label %q) is RETIRED: decryption under it is now refused.\n",
		fam, retired.Version, retired.Label)
	return nil
}

// cmdRewrap migrates envelopes onto the family's active KEK version. It
// operates on the stored-secret registry (-all or -id, repeatable) or on an
// envelope file (-in/-out). The data key never leaves the process in
// plaintext, and data ciphertext and escrow shares are untouched.
func cmdRewrap(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("rewrap", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family (default: secret.kek_label from config)")
	all := fs.Bool("all", false, "re-wrap every stored secret of the family not yet on the active KEK")
	var ids multiFlag
	fs.Var(&ids, "id", "stored-secret ID to re-wrap (repeat for several)")
	in := fs.String("in", "", "re-wrap a single envelope file instead of stored secrets ('-' for stdin)")
	out := fs.String("out", "", "output for -in (default: rewrite -in in place; '-' for stdout)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fam, err := resolveKEK(cfg, *family)
	if err != nil {
		return err
	}
	selections := 0
	if *all {
		selections++
	}
	if len(ids) > 0 {
		selections++
	}
	if *in != "" {
		selections++
	}
	if selections != 1 {
		return fmt.Errorf("select exactly one of -all, -id, or -in")
	}
	actor := operatorActor(*operator)

	// File mode: the envelope lives outside the registry; no batch bookkeeping.
	if *in != "" {
		ring, err := ringFromDB(cfg, provider, fam)
		if err != nil {
			return fmt.Errorf("re-wrap requires the KEK rotation state: %w", err)
		}
		blob, err := readInput(*in)
		if err != nil {
			return fmt.Errorf("reading envelope: %w", err)
		}
		rewrapped, changed, err := ring.RewrapJSON(context.Background(), blob)
		if err != nil {
			_ = recordRotationEvent(cfg, actor, audit.ActionSecretRewrap, fam, audit.ResultError, "file="+*in+" error="+err.Error())
			return err
		}
		if !changed {
			fmt.Fprintf(os.Stderr, "Envelope is already on the active KEK (version %d); nothing to do.\n", ring.ActiveVersion())
			return nil
		}
		dest := *out
		if dest == "" {
			if *in == "-" {
				dest = "-"
			} else {
				dest = *in
			}
		}
		if err := writeOutput(dest, append(rewrapped, '\n')); err != nil {
			return err
		}
		detail := fmt.Sprintf("file=%s to_version=%d to_label=%s", *in, ring.ActiveVersion(), ring.ActiveLabel())
		if err := recordRotationEvent(cfg, actor, audit.ActionSecretRewrap, fam, audit.ResultSuccess, detail); err != nil {
			return fmt.Errorf("envelope was re-wrapped but recording the audit event failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Envelope re-wrapped onto KEK version %d (label %q); data ciphertext untouched.\n",
			ring.ActiveVersion(), ring.ActiveLabel())
		return nil
	}

	// Registry mode.
	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("re-wrap requires the database (stored secrets and audit): %w", err)
	}
	defer db.Close()
	versions, err := db.ListKEKVersions(fam)
	if err != nil {
		return err
	}
	ring, err := secret.LoadRing(context.Background(), provider, fam, versions)
	if err != nil {
		return err
	}
	var idList []string // nil = fleet
	if len(ids) > 0 {
		idList = []string(ids)
	}
	report, err := secret.RewrapStoredSecrets(context.Background(), ring, db, idList)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRewrap, fam, audit.ResultError, err.Error())
		return err
	}
	result := audit.ResultSuccess
	if report.Failed > 0 {
		result = audit.ResultError
	}
	detail := fmt.Sprintf("total=%d rewrapped=%d skipped=%d conflicts=%d failed=%d to_version=%d",
		report.Total, report.Rewrapped, report.Skipped, report.Conflicts, report.Failed, report.ActiveVersion)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretRewrap, fam, result, detail); err != nil {
		return fmt.Errorf("re-wrap ran but recording the audit event failed: %w", err)
	}
	_, _ = secret.RefreshKEKMetrics(db, fam)

	fmt.Printf("Re-wrap of family %q onto version %d (label %q):\n", fam, report.ActiveVersion, report.ActiveLabel)
	fmt.Printf("  Total:     %d\n  Rewrapped: %d\n  Skipped:   %d (already current)\n  Conflicts: %d (concurrent writers; re-run to retry)\n  Failed:    %d\n",
		report.Total, report.Rewrapped, report.Skipped, report.Conflicts, report.Failed)
	for _, e := range report.Errors {
		fmt.Printf("    ! %s\n", e)
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d secret(s) failed to re-wrap", report.Failed)
	}
	return nil
}

// cmdKEKVersions prints the family's rotation posture: the lineage, statuses,
// and how many stored secrets still sit on each version.
func cmdKEKVersions(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("kek-versions", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family (default: secret.kek_label from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fam, err := resolveKEK(cfg, *family)
	if err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	st, err := secret.BuildKEKStatus(db, fam)
	if err != nil {
		return err
	}
	fmt.Printf("KEK family %q — active version %d (label %q)\n", st.Family, st.ActiveVersion, st.ActiveLabel)
	if st.NeverRotated {
		fmt.Println("  Never rotated: the base key is implicitly version 1.")
	}
	fmt.Printf("  Stored secrets: %d total, %d on old version(s), %d on RETIRED version(s)\n\n",
		st.StoredSecrets, st.SecretsOnOldKEK, st.SecretsOnRetiredKEK)
	fmt.Printf("  %-8s %-28s %-9s %-8s %-20s\n", "VERSION", "LABEL", "STATUS", "SECRETS", "CREATED")
	for _, v := range st.Versions {
		created := ""
		if !v.CreatedAt.IsZero() {
			created = v.CreatedAt.UTC().Format(time.RFC3339)
		}
		fmt.Printf("  %-8d %-28s %-9s %-8d %-20s\n", v.Version, v.Label, v.Status, v.Secrets, created)
	}
	if st.SecretsOnOldKEK > 0 && st.SecretsOnRetiredKEK == 0 {
		fmt.Fprintf(os.Stderr, "\nRun `secsy-secret rewrap -all` to migrate the remaining %d secret(s) to version %d.\n",
			st.SecretsOnOldKEK, st.ActiveVersion)
	}
	if st.SecretsOnRetiredKEK > 0 {
		fmt.Fprintf(os.Stderr, "\nWARNING: %d secret(s) sit on a RETIRED version and cannot be decrypted; reinstate the version or recover from escrow.\n",
			st.SecretsOnRetiredKEK)
	}
	return nil
}

// cmdListSecrets lists the stored-secret registry (metadata only — names,
// IDs, and which KEK version wraps each; never plaintext).
func cmdListSecrets(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("list-secrets", flag.ContinueOnError)
	tenant := fs.String("tenant", models.DefaultTenantID, "tenant whose stored secrets to list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	secrets, err := db.ListStoredSecrets(*tenant)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		fmt.Printf("No stored secrets in tenant %q.\n", *tenant)
		return nil
	}
	fmt.Printf("%-36s %-24s %-24s %-4s %-7s %-7s\n", "ID", "NAME", "KEK LABEL", "VER", "CONTEXT", "ESCROW")
	for _, s := range secrets {
		fmt.Printf("%-36s %-24s %-24s %-4d %-7v %-7v\n",
			s.ID, s.Name, s.KEKLabel, s.KEKVersion, s.ContextBound, s.Escrowed)
	}
	return nil
}

// storeEncryptedSecret persists an envelope produced by cmdEncrypt -store.
func storeEncryptedSecret(db *database.DB, tenantID, name, family string, ring *secret.Ring, blob []byte, contextBound, escrowed bool) (*models.StoredSecret, error) {
	stored := &models.StoredSecret{
		ID:           newSecretID(),
		TenantID:     tenantID,
		Name:         name,
		Envelope:     strings.TrimSpace(string(blob)),
		KEKFamily:    family,
		KEKLabel:     ring.ActiveLabel(),
		KEKVersion:   ring.ActiveVersion(),
		ContextBound: contextBound,
		Escrowed:     escrowed,
	}
	if err := db.CreateStoredSecret(stored); err != nil {
		return nil, fmt.Errorf("storing secret: %w", err)
	}
	return stored, nil
}
