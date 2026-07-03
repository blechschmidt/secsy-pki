//go:build sqlite

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// seedCertsForPaging records n issued certificates for caID directly in the
// store (no HSM) with strictly increasing created_at, so the list handler has a
// deterministic newest-first inventory to page over.
func seedCertsForPaging(t *testing.T, db *database.DB, caID string, n int) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: fmt.Sprintf("%s-%d", caID, i), CAID: caID, Serial: fmt.Sprintf("%d", i+1),
			CommonName: fmt.Sprintf("host%d.example.com", i+1), Profile: "server",
			Certificate: "PEM", NotBefore: base, NotAfter: base.Add(24 * time.Hour * 365),
			Status: models.CertStatusValid, CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%d): %v", i, err)
		}
	}
}

// getIssuedPage calls the paginated list handler with a raw query string and
// decodes the envelope.
func getIssuedPage(t *testing.T, api *API, caID, query string) database.IssuedCertPage {
	t.Helper()
	rec := httptest.NewRecorder()
	r := reqAs(http.MethodGet, "/api/ca/"+caID+"/certificates"+query, rootUser(), caID, "")
	api.ListIssuedCertificates(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("list (%s) = %d: %s", query, rec.Code, rec.Body.String())
	}
	var page database.IssuedCertPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v (body=%s)", err, rec.Body.String())
	}
	return page
}

// TestListIssuedCertificatesHandler_Envelope confirms the REST endpoint returns
// the {items, next_cursor, total, has_more} envelope and pages correctly.
func TestListIssuedCertificatesHandler_Envelope(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenantCA(t, db, models.DefaultTenantID, "ca")
	seedCertsForPaging(t, db, "ca", 12)

	p1 := getIssuedPage(t, api, "ca", "?limit=5")
	if p1.Total != 12 {
		t.Fatalf("total = %d, want 12", p1.Total)
	}
	if len(p1.Items) != 5 || !p1.HasMore || p1.NextCursor == "" {
		t.Fatalf("page1: items=%d hasMore=%v cursor=%q", len(p1.Items), p1.HasMore, p1.NextCursor)
	}
	// Newest first.
	if p1.Items[0].Serial != "12" {
		t.Fatalf("page1[0] serial = %s, want 12", p1.Items[0].Serial)
	}

	// Walk to the end following next_cursor; every serial exactly once.
	seen := map[string]bool{}
	for _, c := range p1.Items {
		seen[c.Serial] = true
	}
	cursor := p1.NextCursor
	for {
		page := getIssuedPage(t, api, "ca", "?limit=5&cursor="+cursor)
		for _, c := range page.Items {
			if seen[c.Serial] {
				t.Fatalf("serial %s returned twice across pages", c.Serial)
			}
			seen[c.Serial] = true
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 12 {
		t.Fatalf("walked %d distinct serials, want 12", len(seen))
	}
}

// TestListIssuedCertificatesHandler_MaxPageSize is the max-page-size enforcement
// test: a caller requesting far more than the hard maximum receives at most
// MaxPageSize items and a continuation cursor.
func TestListIssuedCertificatesHandler_MaxPageSize(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenantCA(t, db, models.DefaultTenantID, "ca")
	seedCertsForPaging(t, db, "ca", database.MaxPageSize+5)

	page := getIssuedPage(t, api, "ca", "?limit=100000")
	if len(page.Items) != database.MaxPageSize {
		t.Fatalf("items = %d, want hard cap %d", len(page.Items), database.MaxPageSize)
	}
	if !page.HasMore || page.NextCursor == "" {
		t.Fatal("expected a further page after the capped first page")
	}
}

// TestListIssuedCertificatesHandler_Filters exercises the filter query params
// through the handler.
func TestListIssuedCertificatesHandler_Filters(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenantCA(t, db, models.DefaultTenantID, "ca")
	seedCertsForPaging(t, db, "ca", 6)
	// Revoke serial 2 so the status filter has a target.
	if _, err := db.RevokeCertificate("ca", "2", 1, time.Now()); err != nil {
		t.Fatal(err)
	}

	if p := getIssuedPage(t, api, "ca", "?status=revoked"); p.Total != 1 || len(p.Items) != 1 || p.Items[0].Serial != "2" {
		t.Fatalf("status=revoked: total=%d items=%d", p.Total, len(p.Items))
	}
	if p := getIssuedPage(t, api, "ca", "?status=valid"); p.Total != 5 {
		t.Fatalf("status=valid total = %d, want 5", p.Total)
	}
	if p := getIssuedPage(t, api, "ca", "?q=host3"); p.Total != 1 {
		t.Fatalf("q=host3 total = %d, want 1", p.Total)
	}
	if p := getIssuedPage(t, api, "ca", "?profile=server"); p.Total != 6 {
		t.Fatalf("profile=server total = %d, want 6", p.Total)
	}
	if p := getIssuedPage(t, api, "ca", "?serial_prefix=1"); p.Total != 1 { // only serial "1" (1..6)
		t.Fatalf("serial_prefix=1 total = %d, want 1", p.Total)
	}
}

// TestListIssuedCertificatesHandler_BadParams maps a malformed cursor and a
// malformed expires_before to 400, not 500.
func TestListIssuedCertificatesHandler_BadParams(t *testing.T) {
	api, db := tenantAPI(t)
	mkTenantCA(t, db, models.DefaultTenantID, "ca")
	seedCertsForPaging(t, db, "ca", 3)

	for _, q := range []string{"?cursor=%21%21%21bad", "?expires_before=not-a-date"} {
		rec := httptest.NewRecorder()
		r := reqAs(http.MethodGet, "/api/ca/ca/certificates"+q, rootUser(), "ca", "")
		api.ListIssuedCertificates(rec, r)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query %s = %d, want 400: %s", q, rec.Code, rec.Body.String())
		}
	}
}

// TestListDiscoveredCertificatesHandler_Envelope confirms the discovery endpoint
// returns the paged envelope plus the legacy "certificates" alias.
func TestListDiscoveredCertificatesHandler_Envelope(t *testing.T) {
	api, db := tenantAPI(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		if err := db.RecordDiscoveredCertificate(&models.DiscoveredCertificate{
			ID: fmt.Sprintf("d-%d", i), TenantID: models.DefaultTenantID,
			Endpoint: fmt.Sprintf("h%d:443", i), CommonName: fmt.Sprintf("h%d.example.com", i),
			Fingerprint: fmt.Sprintf("fp%d", i), DiscoveredAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	r := reqAs(http.MethodGet, "/api/discovery?limit=3", rootUser(), "", "")
	api.ListDiscoveredCertificates(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery list = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items        []models.DiscoveredCertificate `json:"items"`
		Certificates []models.DiscoveredCertificate `json:"certificates"`
		NextCursor   string                         `json:"next_cursor"`
		HasMore      bool                           `json:"has_more"`
		Total        int                            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 7 || len(body.Items) != 3 || !body.HasMore || body.NextCursor == "" {
		t.Fatalf("discovery page: total=%d items=%d hasMore=%v", body.Total, len(body.Items), body.HasMore)
	}
	if len(body.Certificates) != len(body.Items) {
		t.Fatalf("legacy alias mismatch: certificates=%d items=%d", len(body.Certificates), len(body.Items))
	}
}
