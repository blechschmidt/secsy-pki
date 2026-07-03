//go:build sqlite

package database

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func secretTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestKEKVersionLineage covers the rotation bookkeeping: implicit-v1 backfill,
// active→retiring supersession, status transitions, and the family listing.
func TestKEKVersionLineage(t *testing.T) {
	db := secretTestDB(t)

	// A never-rotated family has no rows.
	vs, err := db.ListKEKVersions("kek-a")
	if err != nil || len(vs) != 0 {
		t.Fatalf("fresh family lineage = %v, %v", vs, err)
	}

	// First rotation: v1 is backfilled as superseded, v2 becomes active.
	if err := db.RotateKEKVersion(&models.KEKVersion{
		Family: "kek-a", Version: 2, Label: "kek-a-v2", Status: models.KEKStatusActive,
	}); err != nil {
		t.Fatalf("RotateKEKVersion: %v", err)
	}
	vs, err = db.ListKEKVersions("kek-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Fatalf("lineage rows = %d, want 2", len(vs))
	}
	if vs[0].Version != 1 || vs[0].Label != "kek-a" || vs[0].Status != models.KEKStatusRetiring || vs[0].RotatedAt == nil {
		t.Fatalf("backfilled v1 = %+v", vs[0])
	}
	if vs[1].Version != 2 || vs[1].Label != "kek-a-v2" || vs[1].Status != models.KEKStatusActive {
		t.Fatalf("v2 = %+v", vs[1])
	}

	// Second rotation: v2 → retiring, v3 active; only one active remains.
	if err := db.RotateKEKVersion(&models.KEKVersion{
		Family: "kek-a", Version: 3, Label: "kek-a-v3", Status: models.KEKStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	vs, _ = db.ListKEKVersions("kek-a")
	actives := 0
	for _, v := range vs {
		if v.Status == models.KEKStatusActive {
			actives++
		}
	}
	if len(vs) != 3 || actives != 1 {
		t.Fatalf("after second rotation: %d rows, %d active", len(vs), actives)
	}

	// A duplicate version insert collides on the primary key.
	if err := db.RotateKEKVersion(&models.KEKVersion{
		Family: "kek-a", Version: 3, Label: "kek-a-v3b", Status: models.KEKStatusActive,
	}); err == nil {
		t.Fatal("duplicate version must fail")
	}

	// Retirement stamps retired_at; reinstating clears it.
	if ok, err := db.SetKEKVersionStatus("kek-a", 1, models.KEKStatusRetired); err != nil || !ok {
		t.Fatalf("SetKEKVersionStatus = %v, %v", ok, err)
	}
	vs, _ = db.ListKEKVersions("kek-a")
	if vs[0].Status != models.KEKStatusRetired || vs[0].RetiredAt == nil {
		t.Fatalf("retired v1 = %+v", vs[0])
	}
	if ok, err := db.SetKEKVersionStatus("kek-a", 1, models.KEKStatusRetiring); err != nil || !ok {
		t.Fatal(err)
	}
	vs, _ = db.ListKEKVersions("kek-a")
	if vs[0].Status != models.KEKStatusRetiring || vs[0].RetiredAt != nil {
		t.Fatalf("reinstated v1 = %+v", vs[0])
	}
	if ok, _ := db.SetKEKVersionStatus("kek-a", 42, models.KEKStatusRetired); ok {
		t.Fatal("updating an unknown version must report no rows")
	}

	// Families listing unions lineages and stored-secret families.
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s-fam", TenantID: models.DefaultTenantID, Name: "s-fam", Envelope: "{}",
		KEKFamily: "kek-b", KEKLabel: "kek-b", KEKVersion: 1,
	}, "tester", "initial"); err != nil {
		t.Fatal(err)
	}
	fams, err := db.ListKEKFamilies()
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 2 || fams[0] != "kek-a" || fams[1] != "kek-b" {
		t.Fatalf("families = %v", fams)
	}
}

// TestStoredSecretCRUD covers the registry: create/get/list/delete, the
// tenant-scoped name uniqueness, the re-wrap work list, the optimistic
// envelope update, and the per-label counts.
func TestStoredSecretCRUD(t *testing.T) {
	db := secretTestDB(t)

	mk := func(id, name, label string, version int) {
		t.Helper()
		if err := db.CreateStoredSecret(&models.StoredSecret{
			ID: id, TenantID: models.DefaultTenantID, Name: name, Envelope: `{"v":"` + id + `"}`,
			KEKFamily: "kek", KEKLabel: label, KEKVersion: version,
			ContextBound: true, Escrowed: name == "with-escrow",
		}, "tester", "initial"); err != nil {
			t.Fatalf("CreateStoredSecret(%s): %v", id, err)
		}
	}
	mk("s1", "db-password", "kek", 1)
	mk("s2", "api-token", "kek", 1)
	mk("s3", "with-escrow", "kek-v2", 2)

	// Duplicate name within the tenant is refused.
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s4", TenantID: models.DefaultTenantID, Name: "db-password", Envelope: "{}",
		KEKFamily: "kek", KEKLabel: "kek", KEKVersion: 1,
	}, "tester", "initial"); err == nil {
		t.Fatal("duplicate tenant-scoped name must fail")
	}

	s, err := db.GetStoredSecret("s1")
	if err != nil || s == nil {
		t.Fatalf("GetStoredSecret: %v, %v", s, err)
	}
	if s.Name != "db-password" || s.Envelope == "" || !s.ContextBound || s.CreatedAt.IsZero() {
		t.Fatalf("stored secret = %+v", s)
	}
	if s, _ := db.GetStoredSecret("nope"); s != nil {
		t.Fatal("unknown ID must return nil")
	}
	byName, err := db.GetStoredSecretByName(models.DefaultTenantID, "api-token")
	if err != nil || byName == nil || byName.ID != "s2" {
		t.Fatalf("GetStoredSecretByName = %+v, %v", byName, err)
	}

	// List is metadata-only (no envelope) and name-ordered.
	list, err := db.ListStoredSecrets(models.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Name != "api-token" || list[0].Envelope != "" {
		t.Fatalf("list = %+v", list)
	}

	// Re-wrap work list: family members not on the active label.
	ids, err := db.ListStoredSecretIDsForRewrap("kek", "kek-v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "s1" || ids[1] != "s2" {
		t.Fatalf("rewrap work list = %v", ids)
	}

	// Optimistic update: succeeds against the expected label, then the stale
	// retry reports a conflict without clobbering.
	ok, err := db.UpdateStoredSecretEnvelope("s1", `{"v":"s1-rewrapped"}`, "kek-v2", 2, "kek")
	if err != nil || !ok {
		t.Fatalf("UpdateStoredSecretEnvelope = %v, %v", ok, err)
	}
	if ok, _ := db.UpdateStoredSecretEnvelope("s1", `{"v":"stale"}`, "kek-v3", 3, "kek"); ok {
		t.Fatal("stale optimistic update must not apply")
	}
	s, _ = db.GetStoredSecret("s1")
	if s.KEKLabel != "kek-v2" || s.KEKVersion != 2 || s.Envelope != `{"v":"s1-rewrapped"}` {
		t.Fatalf("after update: %+v", s)
	}

	// Counts drive the retire guard and the on-old-KEK gauge.
	if n, _ := db.CountStoredSecretsOnKEK("kek"); n != 1 {
		t.Fatalf("CountStoredSecretsOnKEK(kek) = %d, want 1", n)
	}
	counts, err := db.CountStoredSecretsByKEKLabel("kek")
	if err != nil {
		t.Fatal(err)
	}
	if counts["kek"] != 1 || counts["kek-v2"] != 2 {
		t.Fatalf("counts = %v", counts)
	}

	// Delete reports existence.
	if ok, err := db.DeleteStoredSecret("s2"); err != nil || !ok {
		t.Fatalf("DeleteStoredSecret = %v, %v", ok, err)
	}
	if ok, _ := db.DeleteStoredSecret("s2"); ok {
		t.Fatal("double delete must report not-found")
	}
}
