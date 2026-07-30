//go:build sqlite

package database

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// mustKeyFingerprint generates a fresh ECDSA key and returns the canonical
// "SHA256:<base64>" SubjectPublicKeyInfo fingerprint the inventory records for
// it — exactly the value the key-compromise filter matches against.
func mustKeyFingerprint(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp, err := keycheck.Fingerprint(k.Public())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

// recordCertWithKey inserts one issued certificate on caID carrying the given
// subject-public-key fingerprint, so the key-compromise search has data to find.
func recordCertWithKey(t *testing.T, db *DB, caID, serial, fingerprint string, created time.Time) {
	t.Helper()
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID:                   caID + "-" + serial,
		CAID:                 caID,
		Serial:               serial,
		Subject:              "CN=host-" + serial + ".example.com",
		CommonName:           "host-" + serial + ".example.com",
		Profile:              "server",
		Certificate:          "PEM",
		NotBefore:            created,
		NotAfter:             created.Add(24 * time.Hour * 365),
		Status:               models.CertStatusValid,
		PublicKeyFingerprint: fingerprint,
		CreatedAt:            created,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate(%s/%s): %v", caID, serial, err)
	}
}

// TestPageIssuedCertificates_PublicKeyFilter is the key-compromise incident-
// response read: given a leaked key's SubjectPublicKeyInfo fingerprint, find
// every certificate that shares it. It covers match, no-match, and tenant/CA
// isolation (a certificate bearing the same key under a *different* CA is not
// returned by a query scoped to this CA).
func TestPageIssuedCertificates_PublicKeyFilter(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca-a")
		mustCA(t, db, "ca-b")
		base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

		leaked := mustKeyFingerprint(t) // the compromised key, shared by two certs on ca-a
		other := mustKeyFingerprint(t)  // an unrelated key on ca-a
		absent := mustKeyFingerprint(t) // a key that was never certified

		recordCertWithKey(t, db, "ca-a", "1", leaked, base)
		recordCertWithKey(t, db, "ca-a", "2", leaked, base.Add(1*time.Second))
		recordCertWithKey(t, db, "ca-a", "3", other, base.Add(2*time.Second))
		// Same leaked key certified under a different CA: must NOT leak across the
		// CA (and therefore tenant) boundary of a ca-a-scoped query.
		recordCertWithKey(t, db, "ca-b", "1", leaked, base.Add(3*time.Second))

		t.Run("match", func(t *testing.T) {
			page, err := db.PageIssuedCertificates("ca-a", CertFilter{PublicKeySHA256: leaked}, CertPageRequest{Limit: 100})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 2 || len(page.Items) != 2 {
				t.Fatalf("leaked-key match: total=%d items=%d, want 2/2", page.Total, len(page.Items))
			}
			for _, it := range page.Items {
				if it.PublicKeyFingerprint != leaked {
					t.Fatalf("returned cert %s has fingerprint %q, want %q", it.Serial, it.PublicKeyFingerprint, leaked)
				}
				if it.CAID != "ca-a" {
					t.Fatalf("returned cert %s belongs to CA %q, want ca-a (CA isolation breach)", it.Serial, it.CAID)
				}
			}
		})

		t.Run("distinct-key", func(t *testing.T) {
			page, err := db.PageIssuedCertificates("ca-a", CertFilter{PublicKeySHA256: other}, CertPageRequest{Limit: 100})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 1 {
				t.Fatalf("other-key total = %d, want 1", page.Total)
			}
		})

		t.Run("no-match", func(t *testing.T) {
			page, err := db.PageIssuedCertificates("ca-a", CertFilter{PublicKeySHA256: absent}, CertPageRequest{Limit: 100})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 0 || len(page.Items) != 0 {
				t.Fatalf("absent-key total=%d items=%d, want 0/0", page.Total, len(page.Items))
			}
		})

		t.Run("ca-isolation", func(t *testing.T) {
			// The leaked key exists on ca-b exactly once; a ca-b-scoped query sees
			// only that one, never ca-a's two.
			page, err := db.PageIssuedCertificates("ca-b", CertFilter{PublicKeySHA256: leaked}, CertPageRequest{Limit: 100})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 1 {
				t.Fatalf("ca-b leaked-key total = %d, want 1", page.Total)
			}
		})
	})
}

// TestListRevocationCandidates_PublicKeyFilter confirms the bulk-revocation
// candidate query honors the same key-compromise selector, so `revoke-bulk
// --by-public-key` revokes exactly the certificates sharing a leaked key —
// non-revoked, within validity, and scoped to the CA.
func TestListRevocationCandidates_PublicKeyFilter(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca-a")
		mustCA(t, db, "ca-b")
		base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		now := base.Add(time.Hour)

		leaked := mustKeyFingerprint(t)
		other := mustKeyFingerprint(t)

		recordCertWithKey(t, db, "ca-a", "1", leaked, base)
		recordCertWithKey(t, db, "ca-a", "2", leaked, base)
		recordCertWithKey(t, db, "ca-a", "3", other, base)
		recordCertWithKey(t, db, "ca-b", "1", leaked, base) // different CA

		// A revoked cert with the leaked key must drop out of the candidate set.
		recordCertWithKey(t, db, "ca-a", "4", leaked, base)
		if _, err := db.RevokeCertificate("ca-a", "4", 1, now); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}

		cands, err := db.ListRevocationCandidates(RevocationSelector{
			CAID:                 "ca-a",
			PublicKeyFingerprint: leaked,
			Now:                  now,
		})
		if err != nil {
			t.Fatalf("ListRevocationCandidates: %v", err)
		}
		if len(cands) != 2 {
			t.Fatalf("leaked-key candidates = %d, want 2 (serials 1,2; not the revoked 4 nor ca-b)", len(cands))
		}
		for _, c := range cands {
			if c.Serial != "1" && c.Serial != "2" {
				t.Fatalf("unexpected candidate serial %q", c.Serial)
			}
		}

		none, err := db.ListRevocationCandidates(RevocationSelector{
			CAID:                 "ca-a",
			PublicKeyFingerprint: mustKeyFingerprint(t),
			Now:                  now,
		})
		if err != nil {
			t.Fatalf("ListRevocationCandidates(absent): %v", err)
		}
		if len(none) != 0 {
			t.Fatalf("absent-key candidates = %d, want 0", len(none))
		}
	})
}
