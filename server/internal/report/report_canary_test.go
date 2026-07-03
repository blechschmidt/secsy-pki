package report

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeSource is an in-memory DataSource for the filter tests.
type fakeSource struct {
	cas   []models.CA
	certs map[string][]models.IssuedCertificate
}

func (s *fakeSource) ListCAs() ([]models.CA, error) { return s.cas, nil }
func (s *fakeSource) ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error) {
	return s.certs[caID], nil
}
func (s *fakeSource) ListRevokedCertificates(string) ([]models.RevokedCertificate, error) {
	return nil, nil
}
func (s *fakeSource) ListEventsByTimeRange(time.Time, time.Time) ([]audit.Event, error) {
	return nil, nil
}
func (s *fakeSource) VerifyEventChain() (audit.VerifyResult, error) {
	return audit.VerifyResult{Valid: true}, nil
}
func (s *fakeSource) MarkExpiredCertificates(string, time.Time) (int64, error) { return 0, nil }

// TestInventoryExcludesCanaryCerts proves marker-tagged synthetic certificates
// stay out of the inventory and the compliance population by default, and only
// appear when the caller opts in via IncludeSynthetic.
func TestInventoryExcludesCanaryCerts(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{
		cas: []models.CA{{ID: "ca1", Label: "Test CA"}},
		certs: map[string][]models.IssuedCertificate{
			"ca1": {
				{
					CAID: "ca1", Serial: "1", CommonName: "real.example", Profile: "server",
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
					Status: models.CertStatusValid,
				},
				{
					CAID: "ca1", Serial: "2", CommonName: "secsy-canary", Profile: "canary",
					NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
					Status: models.CertStatusRevoked, Marker: models.CertMarkerCanary,
				},
			},
		},
	}

	inv, err := BuildInventory(src, Filter{}, now)
	if err != nil {
		t.Fatalf("BuildInventory: %v", err)
	}
	if inv.Total != 1 || inv.Certificates[0].Serial != "1" {
		t.Fatalf("default inventory should hold only the real certificate, got %+v", inv.Certificates)
	}

	withSynthetic, err := BuildInventory(src, Filter{IncludeSynthetic: true}, now)
	if err != nil {
		t.Fatalf("BuildInventory(IncludeSynthetic): %v", err)
	}
	if withSynthetic.Total != 2 {
		t.Fatalf("IncludeSynthetic inventory has %d certs, want 2", withSynthetic.Total)
	}

	comp, err := BuildCompliance(src, Filter{}, now)
	if err != nil {
		t.Fatalf("BuildCompliance: %v", err)
	}
	if comp.Lint.IssuedTotal != 1 {
		t.Fatalf("compliance issued total = %d, want 1 (canary excluded)", comp.Lint.IssuedTotal)
	}
	for _, pc := range comp.ProfileBreakdown {
		if pc.Profile == "canary" {
			t.Fatalf("canary profile leaked into the compliance breakdown: %+v", comp.ProfileBreakdown)
		}
	}
}
