//go:build sqlite

package database

import (
	"bytes"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestPQCHybridKeyStore covers the post-quantum ML-KEM key material store
// (Task 137): absent lookup, upsert, base64 binary round-trip, re-seal update,
// and the created_at-preserving overwrite.
func TestPQCHybridKeyStore(t *testing.T) {
	db := secretTestDB(t)

	// Absent family returns (nil, nil).
	if got, err := db.GetPQCHybridKey("kek-a"); err != nil || got != nil {
		t.Fatalf("absent GetPQCHybridKey = %v, %v; want nil, nil", got, err)
	}

	encap := bytes.Repeat([]byte{0xA5}, 1568)
	sealed := bytes.Repeat([]byte{0x5A}, 256)
	rec := &models.PQCHybridKey{
		Family:             "kek-a",
		KeyID:              "mlkem1024-0011223344556677",
		Alg:                "ML-KEM-1024",
		EncapKey:           encap,
		SealedDecapKey:     sealed,
		SealAlg:            "RSA-OAEP-SHA256",
		SealedUnderVersion: 1,
		Status:             models.PQCKeyStatusActive,
	}
	if err := db.PutPQCHybridKey(rec); err != nil {
		t.Fatalf("PutPQCHybridKey: %v", err)
	}
	if rec.CreatedAt.IsZero() || rec.UpdatedAt.IsZero() {
		t.Fatal("Put should stamp created_at/updated_at")
	}
	createdAt := rec.CreatedAt

	got, err := db.GetPQCHybridKey("kek-a")
	if err != nil {
		t.Fatalf("GetPQCHybridKey: %v", err)
	}
	if got.KeyID != rec.KeyID || got.Alg != rec.Alg || got.SealAlg != rec.SealAlg || got.SealedUnderVersion != 1 {
		t.Errorf("metadata round-trip mismatch: %+v", got)
	}
	if !bytes.Equal(got.EncapKey, encap) {
		t.Errorf("encap key round-trip mismatch (%d bytes)", len(got.EncapKey))
	}
	if !bytes.Equal(got.SealedDecapKey, sealed) {
		t.Errorf("sealed decap key round-trip mismatch (%d bytes)", len(got.SealedDecapKey))
	}

	// Re-seal: only the sealed material and version change.
	newSealed := bytes.Repeat([]byte{0x3C}, 256)
	ok, err := db.UpdatePQCSealedKey("kek-a", newSealed, "RSA-OAEP-SHA256", 2)
	if err != nil || !ok {
		t.Fatalf("UpdatePQCSealedKey = %v, %v; want true, nil", ok, err)
	}
	got, _ = db.GetPQCHybridKey("kek-a")
	if !bytes.Equal(got.SealedDecapKey, newSealed) || got.SealedUnderVersion != 2 {
		t.Errorf("re-seal not applied: version %d", got.SealedUnderVersion)
	}
	if !bytes.Equal(got.EncapKey, encap) {
		t.Error("re-seal must not alter the encapsulation key")
	}

	// Re-seal of an unknown family reports no rows affected.
	if ok, err := db.UpdatePQCSealedKey("nope", newSealed, "RSA-OAEP-SHA256", 1); err != nil || ok {
		t.Errorf("UpdatePQCSealedKey(unknown) = %v, %v; want false, nil", ok, err)
	}

	// Overwrite (upsert) preserves created_at but advances updated_at.
	rec.KeyID = "mlkem1024-ffffffffffffffff"
	rec.SealedUnderVersion = 3
	if err := db.PutPQCHybridKey(rec); err != nil {
		t.Fatalf("PutPQCHybridKey overwrite: %v", err)
	}
	got, _ = db.GetPQCHybridKey("kek-a")
	if got.KeyID != "mlkem1024-ffffffffffffffff" || got.SealedUnderVersion != 3 {
		t.Errorf("overwrite not applied: %+v", got)
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("overwrite changed created_at: %v != %v", got.CreatedAt, createdAt)
	}
}
