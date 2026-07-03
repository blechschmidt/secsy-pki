//go:build sqlite

package database

import (
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestSSHStoreBothBackends exercises the SSH certificate/revocation store
// (Task 57) on SQLite (always) and PostgreSQL (when SECSY_TEST_PG_DSN is set):
// inventory round-trip, serial- and key-ID-targeted revocation with idempotent
// re-revocation, the revocation predicate feeding certificate verification, and
// the count that doubles as the KRL version.
func TestSSHStoreBothBackends(t *testing.T) {
	backends := []struct {
		name string
		open func(t *testing.T) *DB
	}{
		{"sqlite", func(t *testing.T) *DB { return testDB(t) }},
		{"postgres", freshPostgres},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)

			ca := &models.CA{
				ID: "ssh-ca-1", Label: "ssh-ca", PKCS11URI: "pkcs11:object=ssh-ca",
				KeyType: "ed25519", PublicKey: "ssh-ed25519 AAAA test",
			}
			if err := db.CreateCA(ca); err != nil {
				t.Fatalf("CreateCA: %v", err)
			}

			// Store-allocated serials are the certificate identity.
			serial, err := db.AllocateSerial(ca.ID)
			if err != nil {
				t.Fatalf("AllocateSerial: %v", err)
			}
			mkCert := func(serial int64, keyID string) *models.SSHCertificate {
				return &models.SSHCertificate{
					CAID:                 ca.ID,
					Serial:               strconv.FormatInt(serial, 10),
					CertType:             "user",
					KeyID:                keyID,
					Principals:           []string{"alice", "admin"},
					Profile:              "user-default",
					PublicKeyFingerprint: "SHA256:test",
					Certificate:          "ssh-ed25519-cert-v01@openssh.com AAAA test",
					ValidAfter:           time.Now().Add(-time.Minute).UTC(),
					ValidBefore:          time.Now().Add(time.Hour).UTC(),
					IssuedBy:             "test",
				}
			}
			if err := db.RecordSSHCertificate(mkCert(serial, "alice@corp")); err != nil {
				t.Fatalf("RecordSSHCertificate: %v", err)
			}
			serial2, _ := db.AllocateSerial(ca.ID)
			if serial2 != serial+1 {
				t.Errorf("serials not monotonic: %d then %d", serial, serial2)
			}
			if err := db.RecordSSHCertificate(mkCert(serial2, "bob@corp")); err != nil {
				t.Fatalf("RecordSSHCertificate 2: %v", err)
			}

			got, err := db.GetSSHCertificate(ca.ID, strconv.FormatInt(serial, 10))
			if err != nil || got == nil {
				t.Fatalf("GetSSHCertificate: %v (nil=%v)", err, got == nil)
			}
			if got.KeyID != "alice@corp" || len(got.Principals) != 2 || got.Status != models.CertStatusValid {
				t.Errorf("round-trip mismatch: %+v", got)
			}
			if got.TenantID != models.DefaultTenantID {
				t.Errorf("tenant backfill = %q", got.TenantID)
			}
			if list, err := db.ListSSHCertificates(ca.ID); err != nil || len(list) != 2 {
				t.Fatalf("ListSSHCertificates: %v, len=%d want 2", err, len(list))
			}

			// Serial-targeted revocation.
			newly, err := db.RevokeSSHCertificate(&models.SSHRevocation{
				CAID: ca.ID, Serial: strconv.FormatInt(serial, 10),
				Reason: "compromised", RevokedBy: "secops", RevokedAt: time.Now().UTC(),
			})
			if err != nil || !newly {
				t.Fatalf("RevokeSSHCertificate: %v newly=%v", err, newly)
			}
			// Idempotent re-revocation.
			newly, err = db.RevokeSSHCertificate(&models.SSHRevocation{
				CAID: ca.ID, Serial: strconv.FormatInt(serial, 10),
				Reason: "still compromised", RevokedAt: time.Now().UTC(),
			})
			if err != nil || newly {
				t.Fatalf("re-revoke: %v newly=%v (want false)", err, newly)
			}
			// Key-ID-targeted revocation flips matching inventory rows.
			if _, err := db.RevokeSSHCertificate(&models.SSHRevocation{
				CAID: ca.ID, KeyID: "bob@corp", RevokedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("revoke by key ID: %v", err)
			}
			// A target-less or doubly-targeted revocation is refused.
			if _, err := db.RevokeSSHCertificate(&models.SSHRevocation{CAID: ca.ID}); err == nil {
				t.Error("target-less revocation accepted")
			}
			if _, err := db.RevokeSSHCertificate(&models.SSHRevocation{
				CAID: ca.ID, Serial: "9", KeyID: "x", RevokedAt: time.Now().UTC(),
			}); err == nil {
				t.Error("doubly-targeted revocation accepted")
			}

			for _, want := range []struct {
				serial, keyID string
				revoked       bool
			}{
				{strconv.FormatInt(serial, 10), "alice@corp", true},   // by serial
				{strconv.FormatInt(serial2, 10), "bob@corp", true},    // by key ID
				{strconv.FormatInt(serial2, 10), "carol@corp", false}, // untouched serial+key
			} {
				got, err := db.IsSSHCertificateRevoked(ca.ID, want.serial, want.keyID)
				if err != nil {
					t.Fatalf("IsSSHCertificateRevoked: %v", err)
				}
				if got != want.revoked {
					t.Errorf("IsSSHCertificateRevoked(%s,%s) = %v, want %v", want.serial, want.keyID, got, want.revoked)
				}
			}

			// Inventory reflects both revocations.
			for _, s := range []int64{serial, serial2} {
				c, err := db.GetSSHCertificate(ca.ID, strconv.FormatInt(s, 10))
				if err != nil || c == nil {
					t.Fatalf("GetSSHCertificate(%d): %v", s, err)
				}
				if c.Status != models.CertStatusRevoked {
					t.Errorf("serial %d status = %q, want revoked", s, c.Status)
				}
			}

			// The revocation listing and count (KRL version) agree.
			revs, err := db.ListSSHRevocations(ca.ID)
			if err != nil {
				t.Fatalf("ListSSHRevocations: %v", err)
			}
			count, err := db.CountSSHRevocations(ca.ID)
			if err != nil {
				t.Fatalf("CountSSHRevocations: %v", err)
			}
			if len(revs) != 2 || count != 2 {
				t.Errorf("revocations list=%d count=%d, want 2/2", len(revs), count)
			}
			rev, err := db.GetSSHRevocationBySerial(ca.ID, strconv.FormatInt(serial, 10))
			if err != nil || rev == nil {
				t.Fatalf("GetSSHRevocationBySerial: %v", err)
			}
			if rev.Reason != "still compromised" {
				t.Errorf("re-revocation did not update the reason: %q", rev.Reason)
			}
		})
	}
}
