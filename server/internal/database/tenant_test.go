//go:build sqlite

package database

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func tenantTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// mkCA persists a minimal CA in the given tenant and returns its ID.
func mkCA(t *testing.T, db *DB, tenantID, label string) string {
	t.Helper()
	ca := &models.CA{
		ID:        label + "-id",
		TenantID:  tenantID,
		Label:     label,
		PKCS11URI: "pkcs11:object=" + label,
		KeyType:   "ecdsa-p256",
		PublicKey: "ssh-ed25519 AAAA " + label,
	}
	if err := db.CreateCA(ca); err != nil {
		t.Fatalf("CreateCA(%s): %v", label, err)
	}
	return ca.ID
}

// TestDefaultTenantSeeded verifies the migration seeds the built-in default
// tenant so single-organization installs work with no configuration.
func TestDefaultTenantSeeded(t *testing.T) {
	db := tenantTestDB(t)
	tn, err := db.GetTenant(models.DefaultTenantID)
	if err != nil || tn == nil {
		t.Fatalf("default tenant missing: %v", err)
	}
	if tn.Slug != models.DefaultTenantID || tn.Status != models.TenantStatusActive {
		t.Errorf("default tenant = %+v", tn)
	}
}

// TestCADefaultsToDefaultTenant proves a CA created without an explicit tenant
// lands in the default tenant (backward compatibility).
func TestCADefaultsToDefaultTenant(t *testing.T) {
	db := tenantTestDB(t)
	ca := &models.CA{ID: "x", Label: "x", PKCS11URI: "pkcs11:object=x", KeyType: "ecdsa-p256", PublicKey: "k"}
	if err := db.CreateCA(ca); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetCA("x")
	if err != nil || got == nil {
		t.Fatalf("GetCA: %v", err)
	}
	if got.TenantID != models.DefaultTenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, models.DefaultTenantID)
	}
	tid, err := db.GetCATenant("x")
	if err != nil || tid != models.DefaultTenantID {
		t.Errorf("GetCATenant = %q (%v)", tid, err)
	}
}

// TestListCAsForTenantIsolation is the core store-layer isolation check: a
// tenant's CA listing contains only its own CAs, never another tenant's.
func TestListCAsForTenantIsolation(t *testing.T) {
	db := tenantTestDB(t)
	for _, id := range []string{"a", "b"} {
		if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	mkCA(t, db, "a", "ca-a1")
	mkCA(t, db, "a", "ca-a2")
	mkCA(t, db, "b", "ca-b1")

	aCAs, err := db.ListCAsForTenant("a")
	if err != nil {
		t.Fatal(err)
	}
	if len(aCAs) != 2 {
		t.Fatalf("tenant a sees %d CAs, want 2", len(aCAs))
	}
	for _, c := range aCAs {
		if c.TenantID != "a" {
			t.Errorf("tenant a listing leaked CA from tenant %q", c.TenantID)
		}
	}
	bCAs, err := db.ListCAsForTenant("b")
	if err != nil {
		t.Fatal(err)
	}
	if len(bCAs) != 1 || bCAs[0].TenantID != "b" {
		t.Fatalf("tenant b listing = %+v", bCAs)
	}
	// The unscoped platform listing sees all three.
	if all, _ := db.ListCAs(); len(all) != 3 {
		t.Errorf("platform ListCAs = %d, want 3", len(all))
	}
}

// TestEventLogTenantScoping proves the audit trail is filterable by tenant and
// that a tenant filter never returns another tenant's events, while the tenant
// value is bound into the tamper-evident hash chain.
func TestEventLogTenantScoping(t *testing.T) {
	db := tenantTestDB(t)
	appendEvt := func(tenant, actor string) {
		if err := db.AppendEvent(&audit.Event{
			ID: actor + "-e", Actor: actor, Action: audit.ActionCertIssue,
			Tenant: tenant, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvt("a", "alice")
	appendEvt("b", "bob")
	appendEvt("a", "amy")

	aEvents, total, err := db.ListEvents("", "", "a", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(aEvents) != 2 {
		t.Fatalf("tenant a events = %d (total %d), want 2", len(aEvents), total)
	}
	for _, e := range aEvents {
		if e.Tenant != "a" {
			t.Errorf("tenant a query leaked event with tenant %q", e.Tenant)
		}
	}
	bEvents, _, _ := db.ListEvents("", "", "b", 50, 0)
	if len(bEvents) != 1 || bEvents[0].Actor != "bob" {
		t.Fatalf("tenant b events = %+v", bEvents)
	}

	// The whole chain still verifies with tenant bound in.
	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("chain invalid with tenant field: %+v", res)
	}
}

// TestRestrictionSetTenantScoping proves a tenant sees only its own restriction
// sets plus the global built-ins, never another tenant's.
func TestRestrictionSetTenantScoping(t *testing.T) {
	db := tenantTestDB(t)
	for _, id := range []string{"a", "b"} {
		if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-a", TenantID: "a", Name: "a-set", Type: models.RestrictionSetX509}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-b", TenantID: "b", Name: "b-set", Type: models.RestrictionSetX509}); err != nil {
		t.Fatal(err)
	}

	aSets, err := db.ListRestrictionSetsForTenant("a")
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range aSets {
		if rs.TenantID == "b" {
			t.Errorf("tenant a saw tenant b restriction set %q", rs.ID)
		}
	}
	// The tenant's own set must be present; the global built-ins (nil tenant) too.
	var sawOwn, sawBuiltin bool
	for _, rs := range aSets {
		if rs.ID == "rs-a" {
			sawOwn = true
		}
		if rs.ID == BuiltinDenyAllX509 {
			sawBuiltin = true
		}
	}
	if !sawOwn || !sawBuiltin {
		t.Errorf("tenant a sets: own=%v builtin=%v", sawOwn, sawBuiltin)
	}
}

// TestCountCAsForTenant supports the "cannot delete a non-empty tenant" rule.
func TestCountCAsForTenant(t *testing.T) {
	db := tenantTestDB(t)
	if err := db.CreateTenant(&models.Tenant{ID: "a", Slug: "a", Name: "a", Status: models.TenantStatusActive}); err != nil {
		t.Fatal(err)
	}
	mkCA(t, db, "a", "ca-a1")
	n, err := db.CountCAsForTenant("a")
	if err != nil || n != 1 {
		t.Fatalf("CountCAsForTenant = %d (%v), want 1", n, err)
	}
	if n, _ := db.CountCAsForTenant("b"); n != 0 {
		t.Errorf("empty tenant count = %d, want 0", n)
	}
}
