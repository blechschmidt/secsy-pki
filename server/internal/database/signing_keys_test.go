//go:build sqlite

package database

import (
	"errors"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newSigningKeyTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSigningKeys_CRUD(t *testing.T) {
	db := newSigningKeyTestDB(t)

	k := &models.SigningKey{
		ID: "id-1", TenantID: "default", Name: "app-signer",
		Algorithm: "ecdsa-p256", KeyType: "ecdsa-sha2-nistp256",
		KeyRef: "software:secsy-sig-id-1", PublicKeyDER: "AAAA", Provider: "software", CreatedBy: "op",
	}
	if err := db.InsertSigningKey(k); err != nil {
		t.Fatalf("InsertSigningKey: %v", err)
	}
	if k.CreatedAt.IsZero() {
		t.Error("InsertSigningKey did not stamp created_at")
	}

	// Get by (tenant, name).
	got, err := db.GetSigningKey("default", "app-signer")
	if err != nil || got == nil {
		t.Fatalf("GetSigningKey = (%v, %v)", got, err)
	}
	if got.Algorithm != "ecdsa-p256" || got.KeyRef != "software:secsy-sig-id-1" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Get by id.
	byID, err := db.GetSigningKeyByID("id-1")
	if err != nil || byID == nil || byID.Name != "app-signer" {
		t.Fatalf("GetSigningKeyByID = (%v, %v)", byID, err)
	}

	// Missing lookups return nil, not error.
	if got, err := db.GetSigningKey("default", "nope"); err != nil || got != nil {
		t.Errorf("GetSigningKey(missing) = (%v, %v), want (nil, nil)", got, err)
	}

	// Duplicate (tenant, name) -> ErrSigningKeyExists.
	dup := *k
	dup.ID = "id-2"
	if err := db.InsertSigningKey(&dup); !errors.Is(err, ErrSigningKeyExists) {
		t.Errorf("duplicate insert = %v, want ErrSigningKeyExists", err)
	}

	// A different tenant may reuse the same name.
	other := *k
	other.ID, other.TenantID = "id-3", "tenant-b"
	if err := db.InsertSigningKey(&other); err != nil {
		t.Errorf("insert same name in another tenant: %v", err)
	}

	// List is tenant-scoped.
	list, err := db.ListSigningKeys("default")
	if err != nil || len(list) != 1 || list[0].Name != "app-signer" {
		t.Fatalf("ListSigningKeys(default) = (%v, %v)", list, err)
	}

	// Delete forgets the metadata (not the provider key).
	deleted, err := db.DeleteSigningKey("default", "app-signer")
	if err != nil || !deleted {
		t.Fatalf("DeleteSigningKey = (%v, %v)", deleted, err)
	}
	if got, _ := db.GetSigningKey("default", "app-signer"); got != nil {
		t.Error("key still present after delete")
	}
}
