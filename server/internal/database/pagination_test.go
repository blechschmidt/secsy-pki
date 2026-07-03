//go:build sqlite

package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// paginationBackends runs a subtest against both the embedded SQLite store and,
// when SECSY_TEST_PG_DSN is set, a real PostgreSQL store — the parity the task
// requires. The keyset comparison is the part most sensitive to backend
// differences (SQLite compares timestamps as text, PostgreSQL temporally), so
// every pagination assertion runs identically on both.
func paginationBackends(t *testing.T, fn func(t *testing.T, db *DB)) {
	t.Helper()
	backends := []struct {
		name string
		open func(t *testing.T) *DB
	}{
		{"sqlite", func(t *testing.T) *DB { return testDB(t) }},
		{"postgres", freshPostgres},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			fn(t, b.open(t))
		})
	}
}

// seedIssued records n issued certificates for caID with strictly increasing
// created_at timestamps (one second apart), returning the serials in issuance
// order (oldest first). Explicit created_at values make the newest-first paging
// order deterministic and let the interleaving test insert "newer" rows on
// demand.
func seedIssued(t *testing.T, db *DB, caID string, n int, base time.Time, profile string) []string {
	t.Helper()
	serials := make([]string, n)
	for i := 0; i < n; i++ {
		serial := fmt.Sprintf("%d", i+1)
		serials[i] = serial
		c := &models.IssuedCertificate{
			ID:          fmt.Sprintf("%s-%d", caID, i+1),
			CAID:        caID,
			Serial:      serial,
			Subject:     fmt.Sprintf("CN=host%d.example.com", i+1),
			CommonName:  fmt.Sprintf("host%d.example.com", i+1),
			SANs:        []string{fmt.Sprintf("host%d.example.com", i+1)},
			Profile:     profile,
			Certificate: "PEM",
			NotBefore:   base,
			NotAfter:    base.Add(24 * time.Hour * 365),
			Status:      models.CertStatusValid,
			CreatedAt:   base.Add(time.Duration(i) * time.Second),
		}
		if err := db.RecordIssuedCertificate(c); err != nil {
			t.Fatalf("RecordIssuedCertificate(%d): %v", i, err)
		}
	}
	return serials
}

func mustCA(t *testing.T, db *DB, id string) {
	t.Helper()
	if err := db.CreateCA(&models.CA{ID: id, Label: id, PKCS11URI: "pkcs11:" + id, KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x"}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
}

// TestPageIssuedCertificates_FullWalk pages through the entire inventory and
// checks that following next_cursor visits every serial exactly once, in
// newest-first order, with an accurate total and a terminal empty cursor.
func TestPageIssuedCertificates_FullWalk(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		seedIssued(t, db, "ca", 25, base, "server")

		var seen []string
		cursor := ""
		pages := 0
		for {
			page, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Limit: 10, Cursor: cursor})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 25 {
				t.Fatalf("total = %d, want 25", page.Total)
			}
			for _, c := range page.Items {
				seen = append(seen, c.Serial)
			}
			pages++
			if !page.HasMore {
				if page.NextCursor != "" {
					t.Fatalf("terminal page carried a next_cursor %q", page.NextCursor)
				}
				break
			}
			if page.NextCursor == "" {
				t.Fatal("has_more page returned an empty next_cursor")
			}
			cursor = page.NextCursor
			if pages > 10 {
				t.Fatal("pagination did not terminate")
			}
		}
		if len(seen) != 25 {
			t.Fatalf("walked %d items, want 25", len(seen))
		}
		// Newest first: serial 25 (created last) down to 1, no repeats.
		for i, serial := range seen {
			want := fmt.Sprintf("%d", 25-i)
			if serial != want {
				t.Fatalf("item %d = serial %s, want %s (order/duplication broken)", i, serial, want)
			}
		}
	})
}

// TestPageIssuedCertificates_StableUnderInserts is the core keyset guarantee:
// rows inserted *between* page fetches (and newer than the first page) must not
// shift, duplicate, or skip the rows of the pages already in flight. An
// OFFSET-based implementation fails this; keyset does not.
func TestPageIssuedCertificates_StableUnderInserts(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		seedIssued(t, db, "ca", 20, base, "server") // serials 1..20, created oldest→newest

		// Page 1: newest first → serials 20..16.
		p1, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Limit: 5})
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if got := pageSerials(p1.Items); !equalStrs(got, []string{"20", "19", "18", "17", "16"}) {
			t.Fatalf("page1 = %v, want [20 19 18 17 16]", got)
		}

		// Insert 10 brand-new (newer) certificates between page 1 and page 2.
		for i := 21; i <= 30; i++ {
			c := &models.IssuedCertificate{
				ID: fmt.Sprintf("ca-%d", i), CAID: "ca", Serial: fmt.Sprintf("%d", i),
				CommonName: fmt.Sprintf("host%d", i), Certificate: "PEM",
				NotBefore: base, NotAfter: base.Add(time.Hour),
				Status:    models.CertStatusValid,
				CreatedAt: base.Add(time.Duration(i) * time.Second), // strictly newer
			}
			if err := db.RecordIssuedCertificate(c); err != nil {
				t.Fatalf("insert newer %d: %v", i, err)
			}
		}

		// Page 2 continues from page 1's cursor: it must return the rows that were
		// next-oldest *at the time page 1 was taken* — serials 15..11 — regardless
		// of the newer inserts.
		p2, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Limit: 5, Cursor: p1.NextCursor})
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if got := pageSerials(p2.Items); !equalStrs(got, []string{"15", "14", "13", "12", "11"}) {
			t.Fatalf("page2 = %v, want [15 14 13 12 11] (keyset not stable under inserts)", got)
		}
		// The total, recomputed each page, does reflect the new rows.
		if p2.Total != 30 {
			t.Fatalf("page2 total = %d, want 30", p2.Total)
		}
	})
}

// TestPageIssuedCertificates_Filters checks each filter predicate in isolation.
func TestPageIssuedCertificates_Filters(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		// 10 "server" certs, serials 1..10.
		seedIssued(t, db, "ca", 10, base, "server")
		// A "client" profile cert whose subject/serial are distinctive.
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: "ca-special", CAID: "ca", Serial: "9001",
			Subject: "CN=special.internal", CommonName: "special.internal",
			SANs:    []string{"special.internal", "alt.special.internal"},
			Profile: "client", Certificate: "PEM",
			NotBefore: base, NotAfter: base.Add(48 * time.Hour),
			Status:    models.CertStatusValid,
			CreatedAt: base.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		// Revoke serial 3 so the status filter has something to find.
		if _, err := db.RevokeCertificate("ca", "3", 1, base.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}

		cases := []struct {
			name   string
			filter CertFilter
			want   int
		}{
			{"profile-client", CertFilter{Profile: "client"}, 1},
			{"profile-server", CertFilter{Profile: "server"}, 10},
			{"status-revoked", CertFilter{Status: string(models.CertStatusRevoked)}, 1},
			{"status-valid", CertFilter{Status: string(models.CertStatusValid)}, 10},
			{"query-special", CertFilter{Query: "special"}, 1},
			{"query-host-substring", CertFilter{Query: "host1"}, 2}, // host1 + host10
			{"query-case-insensitive", CertFilter{Query: "SPECIAL"}, 1},
			{"serial-prefix", CertFilter{SerialPrefix: "900"}, 1},
			{"serial-prefix-1", CertFilter{SerialPrefix: "1"}, 2},                      // serials 1 and 10
			{"expires-before", CertFilter{ExpiresBefore: base.Add(72 * time.Hour)}, 1}, // only the 48h special cert
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				page, err := db.PageIssuedCertificates("ca", tc.filter, CertPageRequest{Limit: 100})
				if err != nil {
					t.Fatalf("page: %v", err)
				}
				if page.Total != tc.want {
					t.Fatalf("total = %d, want %d", page.Total, tc.want)
				}
				if len(page.Items) != tc.want {
					t.Fatalf("items = %d, want %d", len(page.Items), tc.want)
				}
			})
		}
	})
}

// TestPageIssuedCertificates_MaxPageSize confirms the store caps a page at
// MaxPageSize even when a larger limit is requested, and that a further page is
// then available.
func TestPageIssuedCertificates_MaxPageSize(t *testing.T) {
	db := testDB(t)
	mustCA(t, db, "ca")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedIssued(t, db, "ca", MaxPageSize+50, base, "server")

	page, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Limit: 100000})
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page.Items) != MaxPageSize {
		t.Fatalf("items = %d, want hard cap %d", len(page.Items), MaxPageSize)
	}
	if !page.HasMore || page.NextCursor == "" {
		t.Fatal("expected a further page after the capped first page")
	}
	if page.Total != MaxPageSize+50 {
		t.Fatalf("total = %d, want %d", page.Total, MaxPageSize+50)
	}
}

// TestPageRevokedCertificates walks the revocation records and checks the
// serial-prefix filter, verifying the (revoked_at, serial) keyset.
func TestPageRevokedCertificates(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		mustCA(t, db, "ca")
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 12; i++ {
			if _, err := db.RevokeCertificate("ca", fmt.Sprintf("%d", i), 1, base.Add(time.Duration(i)*time.Second)); err != nil {
				t.Fatalf("revoke %d: %v", i, err)
			}
		}
		var seen []string
		cursor := ""
		for {
			page, err := db.PageRevokedCertificates("ca", CertFilter{}, CertPageRequest{Limit: 5, Cursor: cursor})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 12 {
				t.Fatalf("total = %d, want 12", page.Total)
			}
			for _, r := range page.Items {
				seen = append(seen, r.Serial)
			}
			if !page.HasMore {
				break
			}
			cursor = page.NextCursor
		}
		if len(seen) != 12 {
			t.Fatalf("walked %d, want 12", len(seen))
		}
		// Newest revocation first: serial 12 down to 1.
		if seen[0] != "12" || seen[len(seen)-1] != "1" {
			t.Fatalf("order broken: first=%s last=%s", seen[0], seen[len(seen)-1])
		}

		// Serials 1..12 beginning with "1": 1, 10, 11, 12 → 4.
		page, err := db.PageRevokedCertificates("ca", CertFilter{SerialPrefix: "1"}, CertPageRequest{Limit: 100})
		if err != nil {
			t.Fatalf("prefix page: %v", err)
		}
		if page.Total != 4 {
			t.Fatalf("serial-prefix '1' total = %d, want 4", page.Total)
		}
	})
}

// TestPageDiscoveredCertificates walks the discovered inventory across tenants
// and applies the substring + expiry filters over the (discovered_at, id)
// keyset.
func TestPageDiscoveredCertificates(t *testing.T) {
	paginationBackends(t, func(t *testing.T, db *DB) {
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 15; i++ {
			d := &models.DiscoveredCertificate{
				ID:           fmt.Sprintf("d-%02d", i),
				TenantID:     models.DefaultTenantID,
				Endpoint:     fmt.Sprintf("host%d.example.com:443", i),
				CommonName:   fmt.Sprintf("host%d.example.com", i),
				Subject:      fmt.Sprintf("CN=host%d.example.com", i),
				Issuer:       "CN=Public CA",
				Serial:       fmt.Sprintf("%d", i),
				Fingerprint:  fmt.Sprintf("fp%02d", i),
				NotAfter:     base.Add(time.Duration(i) * 24 * time.Hour),
				DiscoveredAt: base.Add(time.Duration(i) * time.Second),
			}
			if err := db.RecordDiscoveredCertificate(d); err != nil {
				t.Fatalf("record discovered %d: %v", i, err)
			}
		}
		var seen []string
		cursor := ""
		for {
			page, err := db.PageDiscoveredCertificates("", CertFilter{}, CertPageRequest{Limit: 4, Cursor: cursor})
			if err != nil {
				t.Fatalf("page: %v", err)
			}
			if page.Total != 15 {
				t.Fatalf("total = %d, want 15", page.Total)
			}
			for _, d := range page.Items {
				seen = append(seen, d.ID)
			}
			if !page.HasMore {
				break
			}
			cursor = page.NextCursor
		}
		if len(seen) != 15 {
			t.Fatalf("walked %d, want 15", len(seen))
		}
		// Newest discovery first.
		if seen[0] != "d-15" || seen[len(seen)-1] != "d-01" {
			t.Fatalf("order broken: first=%s last=%s", seen[0], seen[len(seen)-1])
		}

		// Substring on CN.
		page, err := db.PageDiscoveredCertificates("", CertFilter{Query: "host1.example"}, CertPageRequest{Limit: 100})
		if err != nil {
			t.Fatalf("query page: %v", err)
		}
		if page.Total != 1 {
			t.Fatalf("query host1.example total = %d, want 1", page.Total)
		}
		// Expiry window: only the earliest few expire before base+5d.
		page, err = db.PageDiscoveredCertificates("", CertFilter{ExpiresBefore: base.Add(5 * 24 * time.Hour)}, CertPageRequest{Limit: 100})
		if err != nil {
			t.Fatalf("expiry page: %v", err)
		}
		if page.Total != 4 { // i=1..4 have not_after < base+5d
			t.Fatalf("expires-before total = %d, want 4", page.Total)
		}
	})
}

// TestPaginationCursorRejectsGarbage confirms a malformed cursor is a clean
// error, not a panic or a silent full scan.
func TestPaginationCursorRejectsGarbage(t *testing.T) {
	db := testDB(t)
	mustCA(t, db, "ca")
	seedIssued(t, db, "ca", 3, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "server")
	if _, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Cursor: "!!!not-base64!!!"}); err == nil {
		t.Fatal("expected an error for a malformed cursor")
	}
	if _, err := db.PageIssuedCertificates("ca", CertFilter{}, CertPageRequest{Cursor: "YWJjZGVm"}); err == nil {
		t.Fatal("expected an error for a cursor without a separator")
	}
}

func pageSerials(items []models.IssuedCertificate) []string {
	out := make([]string, len(items))
	for i, c := range items {
		out[i] = c.Serial
	}
	return out
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
