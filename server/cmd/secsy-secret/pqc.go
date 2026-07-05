package main

// Post-quantum hybrid ML-KEM key-material commands (Task 137).
//
//	pqc-enable   Provision ML-KEM-1024 hybrid material for a KEK family
//	pqc-info     Show a family's post-quantum hybrid key material (metadata only)
//	pqc-reseal   Re-seal the ML-KEM decapsulation key under the active KEK version
//
// The material augments a family's classical KEK: new envelopes (with
// secret.pqc_hybrid enabled) protect the data key with BOTH the classical wrap
// and an ML-KEM-1024 encapsulation, combined via a KDF. The ML-KEM
// decapsulation key is stored only sealed under the classical HSM KEK.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// cmdPQCEnable provisions ML-KEM-1024 hybrid key material for a KEK family: it
// generates a fresh keypair, seals the decapsulation key under the family's
// active classical KEK, and records it. Re-provisioning is refused unless
// -force, because a new keypair would render existing hybrid envelopes
// undecryptable.
func cmdPQCEnable(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("pqc-enable", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family to enable hybrid mode for (default: secret.kek_label from config)")
	force := fs.Bool("force", false, "replace existing ML-KEM material (INVALIDATES all envelopes sealed under the old keypair)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fam, err := resolveKEK(cfg, *family)
	if err != nil {
		return err
	}
	actor := operatorActor(*operator)
	ctx := context.Background()

	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("enabling post-quantum hybrid mode requires the database (key material and audit): %w", err)
	}
	defer func() { _ = db.Close() }()

	existing, err := db.GetPQCHybridKey(fam)
	if err != nil {
		return err
	}
	if existing != nil && !*force {
		return fmt.Errorf("KEK family %q already has ML-KEM material (key %s, sealed under version %d); re-provisioning would make every existing hybrid envelope undecryptable — pass -force only if you are certain",
			fam, existing.KeyID, existing.SealedUnderVersion)
	}

	// Bind to the family's ACTIVE classical KEK version (no PQC gate: we are
	// provisioning it now) and seal the ML-KEM decapsulation key under it.
	versions, err := db.ListKEKVersions(fam)
	if err != nil {
		return fmt.Errorf("reading KEK rotation state: %w", err)
	}
	ring, err := secret.LoadRing(ctx, provider, fam, versions)
	if err != nil {
		return fmt.Errorf("loading KEK %q (create it with init-kek first): %w", fam, err)
	}
	rec, err := secret.GeneratePQCHybridKEK(ring.Active(), fam)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretPQCEnable, fam, audit.ResultError, err.Error())
		return err
	}
	if err := db.PutPQCHybridKey(rec); err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretPQCEnable, fam, audit.ResultError, err.Error())
		return fmt.Errorf("recording ML-KEM material: %w", err)
	}
	detail := fmt.Sprintf("key_id=%s alg=%s sealed_under_version=%d replaced=%v", rec.KeyID, rec.Alg, rec.SealedUnderVersion, existing != nil)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretPQCEnable, fam, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("ML-KEM material was provisioned but recording the audit event failed: %w", err)
	}

	fmt.Printf("Post-quantum hybrid material provisioned for KEK family %q:\n", fam)
	fmt.Printf("  Key ID:              %s\n", rec.KeyID)
	fmt.Printf("  KEM:                 %s\n", rec.Alg)
	fmt.Printf("  Decap key sealed by: classical KEK version %d\n", rec.SealedUnderVersion)
	if !cfg.Secret.PQCHybrid {
		fmt.Fprintf(os.Stderr, "\nEnable hybrid sealing so new envelopes use it:\n  secret:\n    pqc_hybrid: true\n")
	}
	return nil
}

// cmdPQCReseal re-seals the family's ML-KEM decapsulation key under the active
// classical KEK version. Run it after a classical KEK rotation and before
// retiring the version that currently seals the decapsulation key.
func cmdPQCReseal(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("pqc-reseal", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family (default: secret.kek_label from config)")
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
		return fmt.Errorf("re-sealing requires the database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if rec, err := db.GetPQCHybridKey(fam); err != nil {
		return err
	} else if rec == nil {
		return fmt.Errorf("KEK family %q has no ML-KEM material to re-seal (enable it with `secsy-secret pqc-enable`)", fam)
	}

	ring, err := ringFromDB(cfg, provider, fam)
	if err != nil {
		return err
	}
	sealed, sealAlg, version, err := ring.ReSealPQC()
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretPQCReseal, fam, audit.ResultError, err.Error())
		return err
	}
	ok, err := db.UpdatePQCSealedKey(fam, sealed, sealAlg, version)
	if err != nil {
		return fmt.Errorf("recording re-sealed ML-KEM material: %w", err)
	}
	if !ok {
		return fmt.Errorf("KEK family %q ML-KEM material disappeared during re-seal", fam)
	}
	detail := fmt.Sprintf("key_id=%s sealed_under_version=%d", ring.PQCKeyID(), version)
	if err := recordEscrowEvent(db, actor, audit.ActionSecretPQCReseal, fam, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("ML-KEM material was re-sealed but recording the audit event failed: %w", err)
	}
	fmt.Printf("Re-sealed ML-KEM decapsulation key for family %q under classical KEK version %d.\n", fam, version)
	return nil
}

// cmdPQCInfo shows a family's post-quantum hybrid key material. It is a
// metadata-only read (no key provider), so it works with the HSM absent.
func cmdPQCInfo(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("pqc-info", flag.ContinueOnError)
	family := fs.String("family", "", "KEK family (default: secret.kek_label from config)")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
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
	defer func() { _ = db.Close() }()
	rec, err := db.GetPQCHybridKey(fam)
	if err != nil {
		return err
	}

	if *asJSON {
		payload := map[string]any{
			"family":       fam,
			"provisioned":  rec != nil,
			"seal_enabled": cfg.Secret.PQCHybrid,
		}
		if rec != nil {
			payload["key_id"] = rec.KeyID
			payload["alg"] = rec.Alg
			payload["sealed_under_version"] = rec.SealedUnderVersion
			payload["seal_alg"] = rec.SealAlg
			payload["status"] = rec.Status
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	fmt.Printf("Post-quantum hybrid (ML-KEM-1024) for KEK family %q:\n", fam)
	if rec == nil {
		fmt.Printf("  Provisioned: no (run `secsy-secret pqc-enable`)\n")
		fmt.Printf("  Seal gate:   %v (secret.pqc_hybrid)\n", cfg.Secret.PQCHybrid)
		return nil
	}
	fmt.Printf("  Provisioned:          yes\n")
	fmt.Printf("  Key ID:               %s\n", rec.KeyID)
	fmt.Printf("  KEM:                  %s\n", rec.Alg)
	fmt.Printf("  Decap key sealed by:  classical KEK version %d (%s)\n", rec.SealedUnderVersion, rec.SealAlg)
	fmt.Printf("  Status:               %s\n", rec.Status)
	fmt.Printf("  Seal gate:            %v (secret.pqc_hybrid — new envelopes %s)\n",
		cfg.Secret.PQCHybrid, sealMode(cfg.Secret.PQCHybrid))
	return nil
}

func sealMode(on bool) string {
	if on {
		return "are sealed hybrid"
	}
	return "are sealed classical; existing hybrid envelopes still open"
}

// provisionPQCForKEK is called by init-kek when secret.pqc_hybrid is enabled, so
// creating the KEK also provisions its ML-KEM material in one step. It is a
// best-effort convenience: a failure is surfaced but the RSA KEK is already
// created.
func provisionPQCForKEK(cfg *config.Config, provider keyprovider.Provider, svc *secret.Service, family string) error {
	db, err := openAuditDB(cfg)
	if err != nil {
		return fmt.Errorf("post-quantum hybrid is enabled but the database (needed to store ML-KEM material) is unavailable: %w", err)
	}
	defer func() { _ = db.Close() }()
	if existing, err := db.GetPQCHybridKey(family); err != nil {
		return err
	} else if existing != nil {
		return nil // already provisioned; leave it (don't clobber in-use material)
	}
	rec, err := secret.GeneratePQCHybridKEK(svc, family)
	if err != nil {
		return err
	}
	if err := db.PutPQCHybridKey(rec); err != nil {
		return err
	}
	_ = recordEscrowEvent(db, operatorActor(""), audit.ActionSecretPQCEnable, family, audit.ResultSuccess,
		fmt.Sprintf("key_id=%s alg=%s sealed_under_version=%d via=init-kek", rec.KeyID, rec.Alg, rec.SealedUnderVersion))
	fmt.Printf("Post-quantum hybrid material provisioned (key %s).\n", rec.KeyID)
	return nil
}
