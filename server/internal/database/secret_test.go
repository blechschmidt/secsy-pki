//go:build sqlite

package database

import (
	"fmt"
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

// storedSecretBackends runs a subtest against the embedded SQLite store and,
// when SECSY_TEST_PG_DSN is set, a real PostgreSQL store. The value-history
// surface is worth running on both: the labels column and its backfill are
// added by engine-specific migration paths, and the retention prune and the
// optimistic version guard depend on DELETE/UPDATE row counts, which is exactly
// where the two drivers can disagree.
func storedSecretBackends(t *testing.T, fn func(t *testing.T, db *DB)) {
	t.Helper()
	for _, b := range []struct {
		name string
		open func(t *testing.T) *DB
	}{
		{"sqlite", secretTestDB},
		{"postgres", freshPostgres},
	} {
		t.Run(b.name, func(t *testing.T) { fn(t, b.open(t)) })
	}
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

// TestStoredSecretVersionHistory covers the value-history surface (Task 72):
// every put appends an immutable version, the registry row mirrors the newest
// one, point reads address older values, the optimistic guard rejects a stale
// writer, and the per-version re-wrap work list drives KEK migration of
// history so an old version stays decryptable.
func TestStoredSecretVersionHistory(t *testing.T) {
	storedSecretBackends(t, testStoredSecretBodyTestStoredSecretVersionHistory)
}

func testStoredSecretBodyTestStoredSecretVersionHistory(t *testing.T, db *DB) {

	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s1", TenantID: models.DefaultTenantID, Name: "db-password",
		Envelope: `{"v":1}`, KEKFamily: "kek", KEKLabel: "kek", KEKVersion: 1,
	}, "alice", "initial"); err != nil {
		t.Fatal(err)
	}

	// Creation seeds version 1 of the history.
	vs, err := db.ListStoredSecretVersions("s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Version != 1 || vs[0].CreatedBy != "alice" || vs[0].Comment != "initial" {
		t.Fatalf("history after create = %+v", vs)
	}

	// Two puts append versions 2 and 3 without disturbing the older rows.
	for i := 2; i <= 3; i++ {
		updated, pruned, err := db.PutStoredSecretVersion(&PutSecretVersion{
			ID: "s1", Envelope: fmt.Sprintf(`{"v":%d}`, i), KEKFamily: "kek",
			KEKLabel: "kek", KEKVersion: 1, CreatedBy: "bob",
			Comment: fmt.Sprintf("rotation %d", i), ExpectVersion: i - 1,
		})
		if err != nil {
			t.Fatalf("put v%d: %v", i, err)
		}
		if updated.CurrentVersion != i {
			t.Fatalf("put v%d: current_version = %d", i, updated.CurrentVersion)
		}
		if pruned != 0 {
			t.Fatalf("put v%d pruned %d versions with no depth configured", i, pruned)
		}
	}

	// History is newest-first and complete; each entry kept its own envelope.
	vs, err = db.ListStoredSecretVersions("s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 || vs[0].Version != 3 || vs[2].Version != 1 {
		t.Fatalf("history = %+v", vs)
	}
	// The list is metadata-only by contract; envelopes come from the point
	// read. Each entry kept the ciphertext that was current at its version.
	for _, v := range vs {
		if v.Envelope != "" {
			t.Fatalf("version %d envelope leaked into the list view: %q", v.Version, v.Envelope)
		}
		got, err := db.GetStoredSecretVersion("s1", v.Version)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf(`{"v":%d}`, v.Version); got.Envelope != want {
			t.Fatalf("version %d envelope = %q, want %q", v.Version, got.Envelope, want)
		}
	}

	// A point read addresses an older value; a missing version is (nil, nil).
	v1, err := db.GetStoredSecretVersion("s1", 1)
	if err != nil || v1 == nil || v1.Envelope != `{"v":1}` {
		t.Fatalf("GetStoredSecretVersion(1) = %+v, %v", v1, err)
	}
	if v, err := db.GetStoredSecretVersion("s1", 99); err != nil || v != nil {
		t.Fatalf("absent version = %+v, %v", v, err)
	}

	// The optimistic guard: a writer that read version 2 loses to the put
	// that already advanced the row to 3, and nothing is written.
	if _, _, err := db.PutStoredSecretVersion(&PutSecretVersion{
		ID: "s1", Envelope: `{"v":"stale"}`, KEKFamily: "kek", KEKLabel: "kek",
		KEKVersion: 1, ExpectVersion: 2,
	}); err != ErrSecretVersionConflict {
		t.Fatalf("stale put error = %v, want ErrSecretVersionConflict", err)
	}
	if vs, _ := db.ListStoredSecretVersions("s1"); len(vs) != 3 {
		t.Fatalf("conflicted put must not append: %d versions", len(vs))
	}

	// Per-version re-wrap work list: the HISTORICAL entries still on the old
	// label, which is what keeps old versions decryptable after a rotation.
	// The current version (3) is excluded — it migrates with the registry row
	// through UpdateStoredSecretEnvelope, so listing it here would re-wrap it
	// twice.
	refs, err := db.ListStoredSecretVersionRefsForRewrap("kek", "kek-v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Version != 1 || refs[1].Version != 2 {
		t.Fatalf("history re-wrap work list = %+v, want historical versions 1 and 2", refs)
	}
	ok, err := db.UpdateStoredSecretVersionEnvelope("s1", 1, `{"v":1,"rewrapped":true}`, "kek-v2", 2, "kek")
	if err != nil || !ok {
		t.Fatalf("UpdateStoredSecretVersionEnvelope = %v, %v", ok, err)
	}
	// The same update replayed against the now-stale label is refused, so a
	// concurrent re-wrap cannot clobber newer ciphertext.
	if ok, err := db.UpdateStoredSecretVersionEnvelope("s1", 1, `{"v":"clobber"}`, "kek-v3", 3, "kek"); err != nil || ok {
		t.Fatalf("stale history re-wrap = %v, %v; want refused", ok, err)
	}
	v1, err = db.GetStoredSecretVersion("s1", 1)
	if err != nil || v1.KEKLabel != "kek-v2" || v1.Envelope != `{"v":1,"rewrapped":true}` {
		t.Fatalf("re-wrapped version 1 = %+v, %v", v1, err)
	}
	// Once migrated, that entry drops off the work list, so a re-wrap batch
	// makes progress and is safe to re-run.
	if refs, _ := db.ListStoredSecretVersionRefsForRewrap("kek", "kek-v2"); len(refs) != 1 || refs[0].Version != 2 {
		t.Fatalf("work list after one re-wrap = %+v, want only version 2", refs)
	}

	// A KEK re-wrap of the CURRENT envelope must advance updated_at but not
	// value_changed_at: the rotation reminder is measured from the latter, so
	// a fleet-wide KEK migration would otherwise silently reset every
	// rotation deadline it touched.
	before, err := db.GetStoredSecret("s1")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.UpdateStoredSecretEnvelope("s1", `{"v":3,"rewrapped":true}`, "kek-v2", 2, "kek"); err != nil || !ok {
		t.Fatalf("UpdateStoredSecretEnvelope = %v, %v", ok, err)
	}
	after, err := db.GetStoredSecret("s1")
	if err != nil {
		t.Fatal(err)
	}
	if !after.ValueChangedAt.Equal(before.ValueChangedAt) {
		t.Fatalf("re-wrap moved value_changed_at from %s to %s; rotation reminders would reset",
			before.ValueChangedAt, after.ValueChangedAt)
	}
	if !after.UpdatedAt.After(before.UpdatedAt) && !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("re-wrap left updated_at behind: %s -> %s", before.UpdatedAt, after.UpdatedAt)
	}
	// The current version's history row must mirror the registry row after a
	// re-wrap. The retire guard deliberately skips current-version rows to
	// avoid double counting, so if the mirror were not kept, retiring the old
	// KEK would strand that row: reading the current value through
	// /versions/{current} would fail while reading it directly still worked.
	curHist, err := db.GetStoredSecretVersion("s1", after.CurrentVersion)
	if err != nil || curHist == nil {
		t.Fatalf("current version's history row missing: %v", err)
	}
	if curHist.KEKLabel != after.KEKLabel || curHist.Envelope != after.Envelope {
		t.Fatalf("current-version history row did not mirror the re-wrap: row=%s/%q registry=%s/%q",
			curHist.KEKLabel, curHist.Envelope, after.KEKLabel, after.Envelope)
	}

	// Deleting the secret takes its whole history with it.
	if ok, err := db.DeleteStoredSecret("s1"); err != nil || !ok {
		t.Fatalf("DeleteStoredSecret = %v, %v", ok, err)
	}
	if vs, err := db.ListStoredSecretVersions("s1"); err != nil || len(vs) != 0 {
		t.Fatalf("history after delete = %+v, %v", vs, err)
	}
}

// TestStoredSecretHistoryDepthPrunes covers the configurable retention depth:
// a put keeps only the newest N versions, never prunes the current value, and
// reports how many rows it destroyed.
func TestStoredSecretHistoryDepthPrunes(t *testing.T) {
	storedSecretBackends(t, testStoredSecretBodyTestStoredSecretHistoryDepthPrunes)
}

func testStoredSecretBodyTestStoredSecretHistoryDepthPrunes(t *testing.T, db *DB) {
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s1", TenantID: models.DefaultTenantID, Name: "rotating",
		Envelope: `{"v":1}`, KEKFamily: "kek", KEKLabel: "kek", KEKVersion: 1,
	}, "alice", "initial"); err != nil {
		t.Fatal(err)
	}

	put := func(version, depth int) int {
		t.Helper()
		_, pruned, err := db.PutStoredSecretVersion(&PutSecretVersion{
			ID: "s1", Envelope: fmt.Sprintf(`{"v":%d}`, version), KEKFamily: "kek",
			KEKLabel: "kek", KEKVersion: 1, ExpectVersion: version - 1, HistoryDepth: depth,
		})
		if err != nil {
			t.Fatalf("put v%d: %v", version, err)
		}
		return pruned
	}

	// Depth 2, writing version 2: versions {1,2} fit, nothing is pruned yet.
	if n := put(2, 2); n != 0 {
		t.Fatalf("put v2 at depth 2 pruned %d, want 0", n)
	}
	// Writing version 3 pushes version 1 out.
	if n := put(3, 2); n != 1 {
		t.Fatalf("put v3 at depth 2 pruned %d, want 1", n)
	}
	vs, err := db.ListStoredSecretVersions("s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].Version != 3 || vs[1].Version != 2 {
		t.Fatalf("retained history = %+v, want versions 3 and 2", vs)
	}
	if v, _ := db.GetStoredSecretVersion("s1", 1); v != nil {
		t.Fatal("version 1 should have been pruned")
	}

	// Depth 1 retains only the current version — the live value stays
	// readable, which is the one row pruning may never take.
	if n := put(4, 1); n != 2 {
		t.Fatalf("put v4 at depth 1 pruned %d, want 2", n)
	}
	vs, _ = db.ListStoredSecretVersions("s1")
	if len(vs) != 1 || vs[0].Version != 4 {
		t.Fatalf("depth-1 history = %+v", vs)
	}
	cur, err := db.GetStoredSecret("s1")
	if err != nil || cur.CurrentVersion != 4 || cur.Envelope != `{"v":4}` {
		t.Fatalf("current secret = %+v, %v", cur, err)
	}
	if v, _ := db.GetStoredSecretVersion("s1", 4); v == nil {
		t.Fatal("the current version must never be pruned")
	}

	// Depth 0 means unlimited: history grows again from here.
	if n := put(5, 0); n != 0 {
		t.Fatalf("put v5 at depth 0 pruned %d, want 0", n)
	}
	if vs, _ := db.ListStoredSecretVersions("s1"); len(vs) != 2 {
		t.Fatalf("history at depth 0 = %+v, want 2 entries", vs)
	}

	// A negative depth is a caller bug, not "unlimited".
	if _, _, err := db.PutStoredSecretVersion(&PutSecretVersion{
		ID: "s1", Envelope: `{"v":6}`, KEKFamily: "kek", KEKLabel: "kek",
		KEKVersion: 1, ExpectVersion: 5, HistoryDepth: -1,
	}); err == nil {
		t.Fatal("negative history depth must be refused")
	}
}

// TestStoredSecretLabels covers operator metadata: it round-trips through
// create and list, and a put's tri-state keeps, replaces or clears it.
func TestStoredSecretLabels(t *testing.T) {
	storedSecretBackends(t, testStoredSecretBodyTestStoredSecretLabels)
}

func testStoredSecretBodyTestStoredSecretLabels(t *testing.T, db *DB) {
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s1", TenantID: models.DefaultTenantID, Name: "db-password",
		Envelope: `{"v":1}`, KEKFamily: "kek", KEKLabel: "kek", KEKVersion: 1,
		Labels: map[string]string{"owner": "payments", "env": "prod"},
	}, "alice", "initial"); err != nil {
		t.Fatal(err)
	}
	s, err := db.GetStoredSecret("s1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Labels["owner"] != "payments" || s.Labels["env"] != "prod" || len(s.Labels) != 2 {
		t.Fatalf("labels after create = %+v", s.Labels)
	}
	// Labels survive the metadata-only list path too (the scanner the
	// lifecycle monitor reads through).
	list, err := db.ListStoredSecrets(models.DefaultTenantID)
	if err != nil || len(list) != 1 || list[0].Labels["owner"] != "payments" {
		t.Fatalf("labels in list = %+v, %v", list, err)
	}

	// A put that does not mention labels keeps them.
	updated, _, err := db.PutStoredSecretVersion(&PutSecretVersion{
		ID: "s1", Envelope: `{"v":2}`, KEKFamily: "kek", KEKLabel: "kek",
		KEKVersion: 1, ExpectVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Labels) != 2 || updated.Labels["env"] != "prod" {
		t.Fatalf("labels after silent put = %+v", updated.Labels)
	}

	// SetLabels replaces the whole set rather than merging.
	updated, _, err = db.PutStoredSecretVersion(&PutSecretVersion{
		ID: "s1", Envelope: `{"v":3}`, KEKFamily: "kek", KEKLabel: "kek",
		KEKVersion: 1, ExpectVersion: 2,
		SetLabels: true, Labels: map[string]string{"owner": "platform"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Labels) != 1 || updated.Labels["owner"] != "platform" {
		t.Fatalf("labels after replace = %+v", updated.Labels)
	}

	// SetLabels with an empty map clears them.
	updated, _, err = db.PutStoredSecretVersion(&PutSecretVersion{
		ID: "s1", Envelope: `{"v":4}`, KEKFamily: "kek", KEKLabel: "kek",
		KEKVersion: 1, ExpectVersion: 3, SetLabels: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Labels) != 0 {
		t.Fatalf("labels after clear = %+v", updated.Labels)
	}

	// A secret created without labels reads back as absent, not as an empty
	// object, so "unset" has one representation end to end.
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: "s2", TenantID: models.DefaultTenantID, Name: "unlabelled",
		Envelope: `{}`, KEKFamily: "kek", KEKLabel: "kek", KEKVersion: 1,
	}, "alice", "initial"); err != nil {
		t.Fatal(err)
	}
	if s2, err := db.GetStoredSecret("s2"); err != nil || s2.Labels != nil {
		t.Fatalf("unlabelled secret labels = %+v, %v", s2.Labels, err)
	}
}
