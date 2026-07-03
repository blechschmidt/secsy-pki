//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestExternalCAStoreBothBackends exercises the externally-signed subordinate
// CA persistence (Task 69) on SQLite (always) and PostgreSQL (when
// SECSY_TEST_PG_DSN is set): a pending CA round-trips its stored CSR, and
// InstallCACertificate atomically installs the certificate metadata, external
// chain, and status flip in both engines.
func TestExternalCAStoreBothBackends(t *testing.T) {
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

			csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
			ca := &models.CA{
				ID: "ext-ca-1", Label: "ext-ca", PKCS11URI: "pkcs11:object=ext-ca",
				KeyType: "ecdsa-p256", PublicKey: "ecdsa-sha2-nistp256 AAAA test",
				Subject: "CN=Ext Sub CA",
				Status:  models.CAStatusPending,
				CSR:     csrPEM,
			}
			if err := db.CreateCA(ca); err != nil {
				t.Fatalf("CreateCA: %v", err)
			}

			got, err := db.GetCA(ca.ID)
			if err != nil || got == nil {
				t.Fatalf("GetCA: %v (nil=%v)", err, got == nil)
			}
			if got.Status != models.CAStatusPending || got.CSR != csrPEM || got.Certificate != "" || got.ExternalChain != "" {
				t.Fatalf("pending round-trip mismatch: %+v", got)
			}

			// Install the externally signed certificate + chain atomically.
			nb := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
			na := nb.Add(24 * time.Hour)
			pathLen := 1
			certPEM := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
			chainPEM := "-----BEGIN CERTIFICATE-----\nMIIR\n-----END CERTIFICATE-----\n"
			if err := db.InstallCACertificate(ca.ID, certPEM, "CN=Ext Sub CA,O=Ext", "12345",
				nb, na, &pathLen, chainPEM, models.CAStatusActive); err != nil {
				t.Fatalf("InstallCACertificate: %v", err)
			}

			got, err = db.GetCA(ca.ID)
			if err != nil || got == nil {
				t.Fatalf("GetCA after install: %v", err)
			}
			if got.Status != models.CAStatusActive || got.Certificate != certPEM || got.ExternalChain != chainPEM {
				t.Errorf("install round-trip mismatch: status=%q cert=%q chain=%q", got.Status, got.Certificate, got.ExternalChain)
			}
			if got.Serial != "12345" || got.Subject != "CN=Ext Sub CA,O=Ext" {
				t.Errorf("metadata mismatch: serial=%q subject=%q", got.Serial, got.Subject)
			}
			if got.MaxPathLen == nil || *got.MaxPathLen != 1 {
				t.Errorf("max_path_len = %v, want 1", got.MaxPathLen)
			}
			if got.NotBefore == nil || got.NotAfter == nil || !got.NotBefore.Equal(nb) || !got.NotAfter.Equal(na) {
				t.Errorf("validity mismatch: %v — %v, want %v — %v", got.NotBefore, got.NotAfter, nb, na)
			}
			// The CSR is retained after install (provenance / renewal re-download).
			if got.CSR != csrPEM {
				t.Errorf("CSR not retained after install: %q", got.CSR)
			}

			// Installing onto a nonexistent CA reports it rather than succeeding.
			if err := db.InstallCACertificate("no-such-ca", certPEM, "CN=x", "1",
				nb, na, nil, "", models.CAStatusActive); err == nil {
				t.Error("InstallCACertificate on a missing CA unexpectedly succeeded")
			}

			// A NULL external_chain (no chain supplied) scans as empty, not an error.
			ca2 := &models.CA{
				ID: "ext-ca-2", Label: "ext-ca-2", PKCS11URI: "pkcs11:object=ext-ca-2",
				KeyType: "ecdsa-p256", PublicKey: "ecdsa-sha2-nistp256 AAAA test2",
				Status: models.CAStatusPending, CSR: csrPEM,
			}
			if err := db.CreateCA(ca2); err != nil {
				t.Fatalf("CreateCA 2: %v", err)
			}
			if err := db.InstallCACertificate(ca2.ID, certPEM, "CN=Two", "2",
				nb, na, nil, "", models.CAStatusActive); err != nil {
				t.Fatalf("InstallCACertificate without chain: %v", err)
			}
			got2, err := db.GetCA(ca2.ID)
			if err != nil || got2 == nil {
				t.Fatalf("GetCA 2: %v", err)
			}
			if got2.ExternalChain != "" || got2.MaxPathLen != nil {
				t.Errorf("chainless install mismatch: chain=%q pathlen=%v", got2.ExternalChain, got2.MaxPathLen)
			}
		})
	}
}
