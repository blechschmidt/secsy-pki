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
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
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
	defer func() { _ = db.Close() }()
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		return nil, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	// Attach the family's post-quantum ML-KEM material (Task 137) if provisioned,
	// so the ring opens hybrid envelopes; the secret.pqc_hybrid gate decides
	// whether NEW envelopes are sealed hybrid.
	pqcRec, err := db.GetPQCHybridKey(family)
	if err != nil {
		return nil, fmt.Errorf("reading post-quantum hybrid key material: %w", err)
	}
	return secret.LoadRingWithPQC(context.Background(), provider, family, versions, pqcRec, cfg.Secret.PQCHybrid)
}

// ringForFamily builds a rotation-aware Ring for a family from an already-open
// database handle, attaching the family's post-quantum ML-KEM material (Task
// 137) so hybrid envelopes open and — with the secret.pqc_hybrid gate — new
// ones seal hybrid. It is the shared path for every stored-secret command
// (put/get/exec) so none of them silently drops the post-quantum layer.
func ringForFamily(cfg *config.Config, db *database.DB, provider keyprovider.Provider, family string, versions []models.KEKVersion) (*secret.Ring, error) {
	pqcRec, err := db.GetPQCHybridKey(family)
	if err != nil {
		return nil, fmt.Errorf("reading post-quantum hybrid key material: %w", err)
	}
	return secret.LoadRingWithPQC(context.Background(), provider, family, versions, pqcRec, cfg.Secret.PQCHybrid)
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
	defer func() { _ = db.Close() }()
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
	defer func() { _ = db.Close() }()

	// Four-eyes gate (Task 81): KEK rotation is a high-risk key-management
	// operation with no REST endpoint, so this CLI gate is its only chokepoint.
	if err := guardKEKRotate(cfg, db, fam, *keyType, actor); err != nil {
		return err
	}

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
func cmdRetireKEK(cfg *config.Config, _ keyprovider.Provider, args []string) error {
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
	defer func() { _ = db.Close() }()

	// Post-quantum guard (Task 137): retiring the classical KEK version that
	// currently seals the family's ML-KEM decapsulation key would strand ALL
	// hybrid envelopes (their decapsulation key could no longer be unsealed).
	// Refuse unless the key has been re-sealed onto a newer version, or -force.
	if pqcRec, perr := db.GetPQCHybridKey(fam); perr != nil {
		return fmt.Errorf("checking post-quantum key material: %w", perr)
	} else if pqcRec != nil && pqcRec.SealedUnderVersion == *version && !*force {
		return fmt.Errorf("KEK version %d of family %q currently seals the ML-KEM decapsulation key; re-seal it onto the active version first (`secsy-secret pqc-reseal`) or pass -force to strand hybrid ciphertext", *version, fam)
	}

	// Format-preserving-encryption guard (Task 144): retiring the classical KEK
	// version that currently seals the family's FPE seed would strand ALL tokens
	// (the seed could no longer be unsealed to derive the FF1 keys). Refuse unless
	// the seed has been re-sealed onto a newer version (`secsy-secret rewrap`) or
	// -force is given.
	if n, ferr := db.CountFPESeedsOnKEK(fam, *version); ferr != nil {
		return fmt.Errorf("checking format-preserving-encryption seed: %w", ferr)
	} else if n > 0 && !*force {
		return fmt.Errorf("KEK version %d of family %q currently seals the format-preserving-encryption seed; re-seal it onto the active version first (`secsy-secret rewrap -all`) or pass -force to strand all tokens", *version, fam)
	}

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
	defer func() { _ = db.Close() }()
	versions, err := db.ListKEKVersions(fam)
	if err != nil {
		return err
	}
	ring, err := ringForFamily(cfg, db, provider, fam, versions)
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
	// Re-seal the family's format-preserving-encryption seed onto the active KEK
	// as part of a fleet re-wrap (Task 144), so the old version can be retired
	// without stranding tokens. The seed bytes — and thus every derived FF1 key and
	// every issued token — are unchanged; only the KEK wrapping advances.
	fpeResealed := false
	if *all {
		resealed, _, ferr := secret.ResealFPESeed(context.Background(), ring, db, fam)
		if ferr != nil {
			_ = recordEscrowEvent(db, actor, audit.ActionSecretRewrap, fam, audit.ResultError, "fpe_seed_reseal: "+ferr.Error())
			return fmt.Errorf("re-sealing the format-preserving-encryption seed: %w", ferr)
		}
		fpeResealed = resealed
	}
	result := audit.ResultSuccess
	if report.Failed > 0 {
		result = audit.ResultError
	}
	detail := fmt.Sprintf("total=%d rewrapped=%d skipped=%d conflicts=%d failed=%d to_version=%d fpe_seed_resealed=%v",
		report.Total, report.Rewrapped, report.Skipped, report.Conflicts, report.Failed, report.ActiveVersion, fpeResealed)
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
	if fpeResealed {
		fmt.Printf("  FPE seed:  re-sealed onto version %d\n", report.ActiveVersion)
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
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
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
	defer func() { _ = db.Close() }()

	st, err := secret.BuildKEKStatus(db, fam)
	if err != nil {
		return err
	}
	if asJSON {
		return cliout.Emit(st)
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
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	secrets, err := db.ListStoredSecrets(*tenant)
	if err != nil {
		return err
	}

	if asJSON {
		// Metadata-only projection: never emit the ciphertext envelope in a listing.
		type secretRow struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			TenantID     string `json:"tenant_id"`
			KEKLabel     string `json:"kek_label"`
			KEKVersion   int    `json:"kek_version"`
			ContextBound bool   `json:"context_bound"`
			Escrowed     bool   `json:"escrowed"`
		}
		rows := make([]secretRow, 0, len(secrets))
		for _, s := range secrets {
			rows = append(rows, secretRow{
				ID: s.ID, Name: s.Name, TenantID: s.TenantID, KEKLabel: s.KEKLabel,
				KEKVersion: s.KEKVersion, ContextBound: s.ContextBound, Escrowed: s.Escrowed,
			})
		}
		return cliout.Emit(struct {
			Tenant  string      `json:"tenant"`
			Secrets []secretRow `json:"secrets"`
		}{Tenant: *tenant, Secrets: rows})
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

// storeSecretSpec carries the optional lifecycle schedule and provenance for
// a newly stored secret (Task 73).
type storeSecretSpec struct {
	ttlDays         int
	rotateEveryDays int
	operator        string
	comment         string
}

// storeEncryptedSecret persists an envelope produced by cmdEncrypt -store or
// cmdPut, recording version 1 of its value history.
func storeEncryptedSecret(db *database.DB, tenantID, name, family string, ring *secret.Ring, blob []byte, contextBound, escrowed bool, spec storeSecretSpec) (*models.StoredSecret, error) {
	stored := &models.StoredSecret{
		ID:              newSecretID(),
		TenantID:        tenantID,
		Name:            name,
		Envelope:        strings.TrimSpace(string(blob)),
		KEKFamily:       family,
		KEKLabel:        ring.ActiveLabel(),
		KEKVersion:      ring.ActiveVersion(),
		ContextBound:    contextBound,
		Escrowed:        escrowed,
		RotateEveryDays: spec.rotateEveryDays,
	}
	if spec.ttlDays > 0 {
		exp := time.Now().UTC().AddDate(0, 0, spec.ttlDays)
		stored.ExpiresAt = &exp
	}
	comment := spec.comment
	if comment == "" {
		comment = "initial version"
	}
	if err := db.CreateStoredSecret(stored, spec.operator, comment); err != nil {
		return nil, fmt.Errorf("storing secret: %w", err)
	}
	return stored, nil
}
