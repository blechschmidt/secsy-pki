//go:build sqlite

package database

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestTenantUsageBothBackends exercises the Task 61 usage accounting and
// atomic quota consumption on SQLite (always) and PostgreSQL (when
// SECSY_TEST_PG_DSN is set), the two engines the "memory"/file store and the
// HA deployment run on.
func TestTenantUsageBothBackends(t *testing.T) {
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
			runTenantUsageSuite(t, db)
		})
	}
}

func mkTenant(t *testing.T, db *DB, slug string, quotas models.TenantQuotas) *models.Tenant {
	t.Helper()
	tn := &models.Tenant{ID: "usage-" + slug, Slug: slug, Name: slug, Quotas: quotas}
	if err := db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant(%s): %v", slug, err)
	}
	return tn
}

func runTenantUsageSuite(t *testing.T, db *DB) {
	day := UsageDay(time.Now())

	t.Run("quota consume and release", func(t *testing.T) {
		tn := mkTenant(t, db, "consume", models.TenantQuotas{})

		// Take 3 units against a limit of 3, then the 4th is refused.
		for i := 0; i < 3; i++ {
			ok, err := db.ConsumeTenantDailyQuota(tn.ID, day, UsageCertsIssued, 3)
			if err != nil || !ok {
				t.Fatalf("consume %d: ok=%v err=%v", i+1, ok, err)
			}
		}
		ok, err := db.ConsumeTenantDailyQuota(tn.ID, day, UsageCertsIssued, 3)
		if err != nil {
			t.Fatalf("consume at limit: %v", err)
		}
		if ok {
			t.Fatal("consume beyond the limit was admitted")
		}
		// A refused consume did not change the counter.
		u, err := db.GetTenantUsageDay(tn.ID, day)
		if err != nil {
			t.Fatalf("GetTenantUsageDay: %v", err)
		}
		if u.CertsIssued != 3 {
			t.Fatalf("certs_issued = %d, want 3", u.CertsIssued)
		}

		// Releasing one unit reopens the window for exactly one more.
		if err := db.ReleaseTenantDailyQuota(tn.ID, day, UsageCertsIssued); err != nil {
			t.Fatalf("release: %v", err)
		}
		if ok, _ = db.ConsumeTenantDailyQuota(tn.ID, day, UsageCertsIssued, 3); !ok {
			t.Fatal("consume after release was refused")
		}

		// Unlimited (limit 0) always admits and still accounts.
		for i := 0; i < 5; i++ {
			if ok, err := db.ConsumeTenantDailyQuota(tn.ID, day, UsageSecretOps, 0); err != nil || !ok {
				t.Fatalf("unlimited consume: ok=%v err=%v", ok, err)
			}
		}
		if u, _ = db.GetTenantUsageDay(tn.ID, day); u.SecretOps != 5 {
			t.Fatalf("secret_ops = %d, want 5", u.SecretOps)
		}

		// An unknown counter name is refused (whitelist), never interpolated.
		if _, err := db.ConsumeTenantDailyQuota(tn.ID, day, "certs_issued; DROP TABLE tenants", 1); err == nil {
			t.Fatal("unknown counter name must be rejected")
		}
	})

	t.Run("release never goes below zero", func(t *testing.T) {
		tn := mkTenant(t, db, "floor", models.TenantQuotas{})
		if err := db.ReleaseTenantDailyQuota(tn.ID, day, UsageCertsIssued); err != nil {
			t.Fatalf("release on empty row: %v", err)
		}
		u, err := db.GetTenantUsageDay(tn.ID, day)
		if err != nil {
			t.Fatalf("GetTenantUsageDay: %v", err)
		}
		if u.CertsIssued != 0 {
			t.Fatalf("certs_issued = %d, want 0 (floor)", u.CertsIssued)
		}
	})

	t.Run("concurrent consumption never exceeds the ceiling", func(t *testing.T) {
		tn := mkTenant(t, db, "race", models.TenantQuotas{})
		const limit, attempts = 10, 40
		var admitted int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := db.ConsumeTenantDailyQuota(tn.ID, day, UsageCertsIssued, limit)
				if err != nil {
					t.Errorf("concurrent consume: %v", err)
					return
				}
				if ok {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if admitted != limit {
			t.Errorf("admitted %d of %d attempts, want exactly %d", admitted, attempts, limit)
		}
		u, err := db.GetTenantUsageDay(tn.ID, day)
		if err != nil {
			t.Fatalf("GetTenantUsageDay: %v", err)
		}
		if u.CertsIssued != limit {
			t.Errorf("certs_issued = %d, want %d", u.CertsIssued, limit)
		}
	})

	t.Run("usage window is ordered and scoped per tenant", func(t *testing.T) {
		tnA := mkTenant(t, db, "window-a", models.TenantQuotas{})
		tnB := mkTenant(t, db, "window-b", models.TenantQuotas{})
		now := time.Now()
		for i := 0; i < 3; i++ {
			d := UsageDay(now.AddDate(0, 0, -i))
			if err := db.AddTenantUsage(tnA.ID, d, UsageCertsIssued, int64(i+1)); err != nil {
				t.Fatalf("AddTenantUsage: %v", err)
			}
		}
		if err := db.AddTenantUsage(tnB.ID, UsageDay(now), UsageCertsIssued, 99); err != nil {
			t.Fatalf("AddTenantUsage(B): %v", err)
		}

		since := UsageDay(now.AddDate(0, 0, -2))
		days, err := db.ListTenantUsageDays(tnA.ID, since)
		if err != nil {
			t.Fatalf("ListTenantUsageDays: %v", err)
		}
		if len(days) != 3 {
			t.Fatalf("window has %d rows, want 3", len(days))
		}
		for i := 1; i < len(days); i++ {
			if days[i-1].Day <= days[i].Day {
				t.Errorf("window not newest-first: %s then %s", days[i-1].Day, days[i].Day)
			}
		}
		// Tenant B's row is invisible in A's window (isolation).
		for _, d := range days {
			if d.CertsIssued == 99 {
				t.Error("tenant B usage leaked into tenant A's window")
			}
		}
		// A window starting after the old rows excludes them.
		days, err = db.ListTenantUsageDays(tnA.ID, UsageDay(now))
		if err != nil {
			t.Fatalf("ListTenantUsageDays(today): %v", err)
		}
		if len(days) != 1 {
			t.Errorf("today-only window has %d rows, want 1", len(days))
		}
	})

	t.Run("quotas round-trip through UpdateTenant", func(t *testing.T) {
		tn := mkTenant(t, db, "roundtrip", models.TenantQuotas{})
		tn.Name = "Renamed"
		tn.KEKLabel = "kek-rt"
		tn.Quotas = models.TenantQuotas{
			MaxCertsPerDay:     11,
			MaxActiveCerts:     22,
			MaxSecretOpsPerDay: 33,
			RateLimitPerSecond: 2.5,
			RateLimitBurst:     7,
		}
		if err := db.UpdateTenant(tn); err != nil {
			t.Fatalf("UpdateTenant: %v", err)
		}
		got, err := db.GetTenant(tn.ID)
		if err != nil || got == nil {
			t.Fatalf("GetTenant: %v", err)
		}
		if got.Name != "Renamed" || got.KEKLabel != "kek-rt" {
			t.Errorf("name/kek = %q/%q, want Renamed/kek-rt", got.Name, got.KEKLabel)
		}
		if got.Quotas != tn.Quotas {
			t.Errorf("quotas = %+v, want %+v", got.Quotas, tn.Quotas)
		}
		// Status and identity were untouched.
		if got.Status != models.TenantStatusActive || got.Slug != "roundtrip" {
			t.Errorf("status/slug changed: %s/%s", got.Status, got.Slug)
		}
	})

	t.Run("active counts and totals are tenant-scoped", func(t *testing.T) {
		tnA := mkTenant(t, db, "count-a", models.TenantQuotas{})
		tnB := mkTenant(t, db, "count-b", models.TenantQuotas{})
		caA := mkCA(t, db, tnA.ID, "count-ca-a")
		caB := mkCA(t, db, tnB.ID, "count-ca-b")

		now := time.Now().UTC()
		record := func(caID, serial string, notAfter time.Time, status models.CertStatus) {
			t.Helper()
			err := db.RecordIssuedCertificate(&models.IssuedCertificate{
				ID:          caID + "-" + serial,
				CAID:        caID,
				Serial:      serial,
				CommonName:  fmt.Sprintf("cn-%s", serial),
				Certificate: "PEM",
				NotBefore:   now.Add(-time.Hour),
				NotAfter:    notAfter,
				Status:      status,
			})
			if err != nil {
				t.Fatalf("RecordIssuedCertificate(%s): %v", serial, err)
			}
		}
		record(caA, "1", now.Add(24*time.Hour), models.CertStatusValid)   // active
		record(caA, "2", now.Add(24*time.Hour), models.CertStatusRevoked) // revoked
		record(caA, "3", now.Add(-time.Minute), models.CertStatusValid)   // expired
		record(caB, "4", now.Add(24*time.Hour), models.CertStatusValid)   // other tenant

		active, err := db.CountActiveCertificatesForTenant(tnA.ID, now)
		if err != nil {
			t.Fatalf("CountActiveCertificatesForTenant: %v", err)
		}
		if active != 1 {
			t.Errorf("tenant A active = %d, want 1 (revoked and expired excluded, B invisible)", active)
		}
		total, revoked, err := db.TenantCertificateTotals(tnA.ID)
		if err != nil {
			t.Fatalf("TenantCertificateTotals: %v", err)
		}
		if total != 3 || revoked != 1 {
			t.Errorf("tenant A totals = %d/%d, want 3 total / 1 revoked", total, revoked)
		}
	})
}
