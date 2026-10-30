//go:build sqlite

package secret

// SoftHSM-backed proof that a stored secret's whole value history survives a
// KEK rotation (Task 72). The hermetic tests in rotation_test.go use an
// in-memory store and a software KEK; this one drives the real persistence
// layer against a real PKCS#11 token, so the DEK for every historical version
// is genuinely unwrapped on the device.
//
// Skipped unless SoftHSM is configured (see pkcs11Provider).

import (
	"context"
	"fmt"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestHSMKEKRotationAcrossMultiVersionSecret is the end-to-end lifecycle case:
// a secret accumulates several value versions sealed under an HSM-held KEK,
// the KEK is rotated, the re-wrap batch migrates the registry row AND every
// retained history entry, and each version still decrypts to its own original
// plaintext. Finally the old KEK version is retired — the point at which any
// envelope the batch missed would become permanently unreadable.
func TestHSMKEKRotationAcrossMultiVersionSecret(t *testing.T) {
	ctx := context.Background()
	prov := pkcs11Provider(t)
	family := uniqueKEKLabel(t)

	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Provision the family KEK on the token and seal version 1.
	if _, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: family})
	if err != nil {
		t.Fatal(err)
	}

	const secretID = "s-multi"
	plaintexts := map[int]string{
		1: "v1-initial-password",
		2: "v2-after-incident",
		3: "v3-current-password",
	}
	blob1, err := svc.EncryptToJSON([]byte(plaintexts[1]), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateStoredSecret(&models.StoredSecret{
		ID: secretID, TenantID: models.DefaultTenantID, Name: "db-password",
		Envelope: string(blob1), KEKFamily: family, KEKLabel: family, KEKVersion: 1,
		Labels: map[string]string{"owner": "payments", "env": "prod"},
	}, "tester", "initial version"); err != nil {
		t.Fatal(err)
	}

	// Versions 2 and 3, each sealed under the still-active KEK v1. A depth of
	// 3 is configured, which retains all of them.
	for v := 2; v <= 3; v++ {
		blob, err := svc.EncryptToJSON([]byte(plaintexts[v]), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, pruned, err := db.PutStoredSecretVersion(&database.PutSecretVersion{
			ID: secretID, Envelope: string(blob), KEKFamily: family,
			KEKLabel: family, KEKVersion: 1, CreatedBy: "tester",
			Comment: fmt.Sprintf("rotation to v%d", v), ExpectVersion: v - 1,
			HistoryDepth: 3,
		}); err != nil {
			t.Fatalf("put v%d: %v", v, err)
		} else if pruned != 0 {
			t.Fatalf("put v%d pruned %d versions at depth 3", v, pruned)
		}
	}

	// Rotate the family KEK: a fresh RSA key lands on the token as -v2.
	if _, err := RotateKEK(ctx, prov, db, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := LoadRing(ctx, prov, family, versions)
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}

	// Every version still opens during the dual-KEK window, before re-wrap:
	// the ring keeps the retiring version available for decryption.
	for v := 1; v <= 3; v++ {
		assertVersionDecrypts(ctx, t, db, ring, secretID, v, plaintexts[v], "before re-wrap")
	}

	// Re-wrap: one registry row plus the two historical entries.
	report, err := RewrapStoredSecrets(ctx, ring, db, nil)
	if err != nil {
		t.Fatalf("RewrapStoredSecrets: %v", err)
	}
	if report.HistoryEnvelopes != 2 {
		t.Fatalf("history envelopes = %d, want 2", report.HistoryEnvelopes)
	}
	if report.Rewrapped != 3 || report.Failed != 0 {
		t.Fatalf("re-wrap report = %+v; want 3 re-wrapped, 0 failed", report)
	}

	// Nothing is left on the old label, so the retire guard will let go.
	if n, err := db.CountStoredSecretsOnKEK(family); err != nil || n != 0 {
		t.Fatalf("envelopes still on the old KEK label = %d, %v", n, err)
	}

	// Retire KEK v1. From here the v1 key may be deleted; any envelope the
	// batch missed is now unreadable, so the assertions below are the real
	// test of the migration.
	if _, err := db.SetKEKVersionStatus(family, 1, models.KEKStatusRetired); err != nil {
		t.Fatalf("retiring KEK v1: %v", err)
	}
	versions, err = db.ListKEKVersions(family)
	if err != nil {
		t.Fatal(err)
	}
	postRetire, err := LoadRing(ctx, prov, family, versions)
	if err != nil {
		t.Fatalf("LoadRing after retire: %v", err)
	}

	for v := 1; v <= 3; v++ {
		assertVersionDecrypts(ctx, t, db, postRetire, secretID, v, plaintexts[v], "after retiring KEK v1")
	}

	// Metadata survived the migration untouched, and the value clock did not
	// move — a KEK rotation must not reset rotation reminders.
	s, err := db.GetStoredSecret(secretID)
	if err != nil {
		t.Fatal(err)
	}
	if s.KEKVersion != 2 || s.CurrentVersion != 3 {
		t.Fatalf("secret after re-wrap = kek v%d, current v%d; want kek v2, current v3", s.KEKVersion, s.CurrentVersion)
	}
	if s.Labels["owner"] != "payments" || s.Labels["env"] != "prod" {
		t.Fatalf("labels lost across rotation: %+v", s.Labels)
	}

	// A rollback to a re-wrapped historical version yields that version's
	// plaintext as the new current value — the end-to-end point of retaining
	// history across a rotation.
	v1, err := db.GetStoredSecretVersion(secretID, 1)
	if err != nil || v1 == nil {
		t.Fatalf("version 1: %v", err)
	}
	rolled, _, err := db.PutStoredSecretVersion(&database.PutSecretVersion{
		ID: secretID, Envelope: v1.Envelope, KEKFamily: v1.KEKFamily,
		KEKLabel: v1.KEKLabel, KEKVersion: v1.KEKVersion, CreatedBy: "tester",
		Comment: "rollback to version 1", ExpectVersion: 3, HistoryDepth: 3,
	})
	if err != nil {
		t.Fatalf("rollback put: %v", err)
	}
	if rolled.CurrentVersion != 4 {
		t.Fatalf("rollback produced version %d, want 4", rolled.CurrentVersion)
	}
	plain, err := postRetire.DecryptJSON(ctx, []byte(rolled.Envelope), nil)
	if err != nil {
		t.Fatalf("decrypting the rolled-back value: %v", err)
	}
	if string(plain) != plaintexts[1] {
		t.Fatalf("rolled-back value = %q, want %q", plain, plaintexts[1])
	}

	// Depth 3 with four versions written: the oldest was pruned by that put.
	hist, err := db.ListStoredSecretVersions(secretID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 3 || hist[0].Version != 4 {
		t.Fatalf("history at depth 3 = %+v, want versions 4,3,2", hist)
	}
}

// assertVersionDecrypts reads one history entry straight from the database and
// checks it opens to want under ring.
func assertVersionDecrypts(ctx context.Context, t *testing.T, db *database.DB, ring *Ring, id string, version int, want, when string) {
	t.Helper()
	v, err := db.GetStoredSecretVersion(id, version)
	if err != nil || v == nil {
		t.Fatalf("%s: version %d missing: %v", when, version, err)
	}
	got, err := ring.DecryptJSON(ctx, []byte(v.Envelope), nil)
	if err != nil {
		t.Fatalf("%s: decrypting version %d (kek %s v%d): %v", when, version, v.KEKLabel, v.KEKVersion, err)
	}
	if string(got) != want {
		t.Fatalf("%s: version %d = %q, want %q", when, version, got, want)
	}
}
