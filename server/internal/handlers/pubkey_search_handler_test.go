//go:build sqlite

package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// keyAndHex returns the canonical SPKI fingerprint of a fresh key and its hex
// SHA-256 form (the two shapes the public_key_sha256 query param accepts).
func keyAndHex(t *testing.T) (canonical, hexForm string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = keycheck.Fingerprint(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return canonical, hex.EncodeToString(sum[:])
}

func seedCertWithFingerprint(t *testing.T, api *API, caID, serial, fp string, created time.Time) {
	t.Helper()
	if err := api.db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID: caID + "-" + serial, CAID: caID, Serial: serial,
		CommonName: "host-" + serial + ".example.com", Profile: "server", Certificate: "PEM",
		NotBefore: created, NotAfter: created.Add(24 * time.Hour * 365),
		Status: models.CertStatusValid, PublicKeyFingerprint: fp, CreatedAt: created,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate(%s/%s): %v", caID, serial, err)
	}
}

// TestListIssuedCertificatesHandler_PublicKeyFilter drives the key-compromise
// search through the REST endpoint: match (by hex and canonical form), no-match,
// a malformed value mapped to 400, and CA/tenant data isolation.
func TestListIssuedCertificatesHandler_PublicKeyFilter(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenant(t, db, "tb")
	mkTenantCA(t, db, models.DefaultTenantID, "ca-a")
	mkTenantCA(t, db, "tb", "ca-b")
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	leaked, leakedHex := keyAndHex(t)
	_, absentHex := keyAndHex(t)

	seedCertWithFingerprint(t, api, "ca-a", "1", leaked, base)
	seedCertWithFingerprint(t, api, "ca-a", "2", leaked, base.Add(time.Second))
	// Same leaked key certified under tenant B's CA: must not appear in a
	// ca-a-scoped query.
	seedCertWithFingerprint(t, api, "ca-b", "1", leaked, base.Add(2*time.Second))

	t.Run("match-hex", func(t *testing.T) {
		p := getIssuedPage(t, api, "ca-a", "?public_key_sha256="+leakedHex)
		if p.Total != 2 || len(p.Items) != 2 {
			t.Fatalf("hex match: total=%d items=%d, want 2/2", p.Total, len(p.Items))
		}
	})
	t.Run("match-canonical", func(t *testing.T) {
		// The canonical "SHA256:<base64>" form contains '+' and '/'; url-encode it.
		p := getIssuedPage(t, api, "ca-a", "?public_key_sha256="+url.QueryEscape(leaked))
		if p.Total != 2 {
			t.Fatalf("canonical match total = %d, want 2", p.Total)
		}
	})
	t.Run("no-match", func(t *testing.T) {
		p := getIssuedPage(t, api, "ca-a", "?public_key_sha256="+absentHex)
		if p.Total != 0 || len(p.Items) != 0 {
			t.Fatalf("no-match total=%d items=%d, want 0/0", p.Total, len(p.Items))
		}
	})
	t.Run("ca-isolation", func(t *testing.T) {
		// Querying ca-b for the same key returns only ca-b's single cert.
		p := getIssuedPage(t, api, "ca-b", "?public_key_sha256="+leakedHex)
		if p.Total != 1 {
			t.Fatalf("ca-b total = %d, want 1", p.Total)
		}
	})
	t.Run("malformed-400", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := reqAs(http.MethodGet, "/api/ca/ca-a/certificates?public_key_sha256=not-a-fingerprint", rootUser(), "ca-a", "")
		api.ListIssuedCertificates(rec, r)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed public_key_sha256 = %d, want 400: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("tenant-isolation-denied", func(t *testing.T) {
		// An auditor scoped to tenant A cannot read tenant B's CA, even to run a
		// key-compromise search (non-disclosing: 403/404, never 200).
		rec := httptest.NewRecorder()
		r := reqAs(http.MethodGet, "/api/ca/ca-b/certificates?public_key_sha256="+leakedHex,
			tenantUser("a-auditor", models.DefaultTenantID, "auditor"), "ca-b", "")
		api.ListIssuedCertificates(rec, r)
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant search = %d, want 403 or 404", rec.Code)
		}
	})
}
