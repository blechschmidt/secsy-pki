//go:build sqlite

package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// pqcHybridResult runs checkPQCHybrid and returns the single "pqc.hybrid"
// result.
func pqcHybridResult(t *testing.T, cfg *config.Config, db *database.DB, prov keyprovider.Provider) Result {
	t.Helper()
	r := &Report{OK: true}
	providers := &roleProviders{byRole: map[string]keyprovider.Provider{}}
	if prov != nil {
		providers.byRole["ca"] = prov
	}
	checkPQCHybrid(context.Background(), r, cfg, db, true, providers)
	if len(r.Checks) != 1 {
		t.Fatalf("checkPQCHybrid produced %d results, want 1: %+v", len(r.Checks), r.Checks)
	}
	return r.Checks[0]
}

func TestCheckPQCHybrid(t *testing.T) {
	db, err := database.New("sqlite", t.TempDir()+"/pqc.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	ctx := context.Background()
	const family = "kek"
	svc, err := secret.ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}

	// Gate off, no material → skip.
	cfg := &config.Config{}
	cfg.Secret.KEKLabel = family
	if got := pqcHybridResult(t, cfg, db, prov); got.Status != StatusSkip {
		t.Fatalf("gate off/no material = %s (%s), want skip", got.Status, got.Detail)
	}

	// Gate ON but no material → fail closed with an actionable message.
	cfg.Secret.PQCHybrid = true
	got := pqcHybridResult(t, cfg, db, prov)
	if got.Status != StatusFail {
		t.Fatalf("gate on/no material = %s (%s), want fail", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "pqc-enable") {
		t.Errorf("failure should point at pqc-enable, got: %s", got.Detail)
	}

	// Provision material → gate on now passes with a round-trip probe.
	rec, err := secret.GeneratePQCHybridKEK(svc, family)
	if err != nil {
		t.Fatalf("GeneratePQCHybridKEK: %v", err)
	}
	if err := db.PutPQCHybridKey(rec); err != nil {
		t.Fatalf("PutPQCHybridKey: %v", err)
	}
	got = pqcHybridResult(t, cfg, db, prov)
	if got.Status != StatusPass {
		t.Fatalf("gate on/material present = %s (%s), want pass", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "round-trip ok") || !strings.Contains(got.Detail, rec.KeyID) {
		t.Errorf("pass detail should confirm the round-trip and key id, got: %s", got.Detail)
	}

	// Gate off but material present → still probed and healthy (pass), proving
	// the material stays usable for reads regardless of the sealing gate.
	cfg.Secret.PQCHybrid = false
	if got := pqcHybridResult(t, cfg, db, prov); got.Status != StatusPass {
		t.Fatalf("gate off/material present = %s (%s), want pass", got.Status, got.Detail)
	}

	// Corrupted stored material (bad encap key) fails the load — the probe reports
	// the fault rather than silently continuing.
	if _, err := db.UpdatePQCSealedKey(family, []byte("too-short"), rec.SealAlg, 1); err != nil {
		t.Fatal(err)
	}
	cfg.Secret.PQCHybrid = true
	if got := pqcHybridResult(t, cfg, db, prov); got.Status != StatusFail {
		t.Fatalf("corrupted material = %s (%s), want fail", got.Status, got.Detail)
	}
}
