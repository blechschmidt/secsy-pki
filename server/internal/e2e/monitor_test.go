//go:build sqlite

// This file drives the certificate-expiry monitor and its auto-renewal workflow
// end-to-end against a real, HSM-backed CA (SoftHSM in CI). It proves:
//
//	near-expiry detection: a short-lived leaf is classified "critical"
//	auto-renew: the eligible leaf is reissued (signed on the token) with a fresh
//	            serial and a far-future NotAfter, emitting a cert.auto_renew audit
//	            event and a verifiable chain
//	storm prevention: a second auto-renew scan renews nothing (the old serial is
//	            superseded by the fresh reissue)
//	revocation safety: a revoked near-expiry leaf is never auto-renewed
//
// Every certificate signature happens on the token via the shared ca.Manager,
// so this exercises the monitor together with HSM-backed issuance. It shares the
// SECSY_* gating and helpers (hsmProvider, uniqueLabel, makeCSR, mustParse) with
// fullflow_test.go, so a plain `go test ./...` with no HSM stays green.
package e2e

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// newDBAndManager wires a fresh sqlite database and a ca.Manager to the HSM
// provider, returning both so the test can hand the DB to the monitor (as its
// certificate store and audit sink).
func newDBAndManager(t *testing.T, provider keyprovider.Provider) (*database.DB, *ca.Manager) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "monitor-e2e.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, ca.NewManager(db, provider)
}

// findItem returns the report item for a given serial, or fails.
func findItem(t *testing.T, report *monitor.Report, serial string) monitor.CertItem {
	t.Helper()
	for _, it := range report.Items {
		if it.Serial == serial {
			return it
		}
	}
	t.Fatalf("serial %s not found in report", serial)
	return monitor.CertItem{}
}

func TestExpiryMonitorAndAutoRenew(t *testing.T) {
	ctx := context.Background()
	provider := hsmProvider(t)
	db, mgr := newDBAndManager(t, provider)

	const keyType = keyprovider.KeyTypeECDSAP256

	// --- Build an HSM-backed root + intermediate CA. ---
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "mon-root"),
		KeyType:  keyType,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy Monitor Root CA"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "mon-inter"),
		KeyType:    keyType,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy Monitor Intermediate CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mustParse(t, root.Certificate))
	inters := x509.NewCertPool()
	inters.AddCert(mustParse(t, inter.Certificate))

	// --- Issue a near-expiry leaf (2h), a healthy leaf (profile default ~397d),
	//     and a near-expiry leaf that we then revoke. ---
	near, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:     inter.ID,
		CSRPEM:   makeCSR(t, "near.monitor.example", []string{"near.monitor.example"}),
		Profile:  "server",
		Validity: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue near-expiry leaf: %v", err)
	}
	healthy, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:    inter.ID,
		CSRPEM:  makeCSR(t, "healthy.monitor.example", []string{"healthy.monitor.example"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("issue healthy leaf: %v", err)
	}
	revokedLeaf, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:     inter.ID,
		CSRPEM:   makeCSR(t, "revoked.monitor.example", []string{"revoked.monitor.example"}),
		Profile:  "server",
		Validity: 90 * time.Minute,
	})
	if err != nil {
		t.Fatalf("issue revoked leaf: %v", err)
	}
	if _, err := mgr.RevokeCertificate(ctx, inter.ID, revokedLeaf.Serial.String(), "superseded"); err != nil {
		t.Fatalf("revoke leaf: %v", err)
	}

	opts := monitor.OptionsFromDays(30, 7, 7, nil)

	// --- 1. Near-expiry detection (read-only, no auto-renew). ---
	t.Run("NearExpiryDetection", func(t *testing.T) {
		m := monitor.New(db, mgr, db, opts)
		report, err := m.Scan(ctx, monitor.ScanRequest{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if got := findItem(t, report, near.Serial.String()).Severity; got != monitor.SeverityCritical {
			t.Errorf("near-expiry leaf severity = %s, want critical", got)
		}
		if got := findItem(t, report, healthy.Serial.String()).Severity; got != monitor.SeverityOK {
			t.Errorf("healthy leaf severity = %s, want ok", got)
		}
		// The revoked leaf must be excluded entirely.
		for _, it := range report.Items {
			if it.Serial == revokedLeaf.Serial.String() {
				t.Error("revoked leaf must not appear in the expiry report")
			}
		}
		if report.Counts[monitor.SeverityCritical] < 1 {
			t.Errorf("expected >=1 critical, got counts %+v", report.Counts)
		}
	})

	// --- 2. Auto-renew the eligible near-expiry leaf on the HSM. ---
	var newSerial string
	t.Run("AutoRenew", func(t *testing.T) {
		m := monitor.New(db, mgr, db, opts)
		report, err := m.Scan(ctx, monitor.ScanRequest{AutoRenew: true, RequestedBy: "e2e-monitor"})
		if err != nil {
			t.Fatalf("auto-renew scan: %v", err)
		}
		if report.Renewed < 1 {
			t.Fatalf("expected at least 1 renewal, got %d (failed=%d)", report.Renewed, report.RenewFailed)
		}
		item := findItem(t, report, near.Serial.String())
		if !item.Renewed || item.NewSerial == "" {
			t.Fatalf("near-expiry leaf was not renewed: %+v", item)
		}
		newSerial = item.NewSerial

		// The reissued certificate must exist, chain to the root, and expire far
		// in the future (profile default), proving it was actually signed.
		rec, err := db.GetIssuedCertificate(inter.ID, newSerial)
		if err != nil || rec == nil {
			t.Fatalf("renewed cert %s not recorded: %v", newSerial, err)
		}
		renewedCert := mustParse(t, rec.Certificate)
		if !renewedCert.NotAfter.After(near.Certificate.NotAfter.Add(24 * time.Hour)) {
			t.Errorf("renewed NotAfter %s is not meaningfully later than original %s",
				renewedCert.NotAfter, near.Certificate.NotAfter)
		}
		if _, err := renewedCert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inters,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("renewed leaf does not chain to the HSM root: %v", err)
		}

		// A cert.auto_renew success audit event must have been appended.
		events, _, err := db.ListEvents(audit.ActionCertAutoRenew, "", 50, 0)
		if err != nil {
			t.Fatalf("listing audit events: %v", err)
		}
		var found bool
		for _, e := range events {
			if e.Result == audit.ResultSuccess && e.Target == newSerial {
				found = true
			}
		}
		if !found {
			t.Errorf("no successful cert.auto_renew audit event for serial %s", newSerial)
		}
	})

	// --- 3. Storm prevention: a second auto-renew scan renews nothing, and the
	//        original near-expiry serial is now superseded by the reissue. ---
	t.Run("NoRenewalStorm", func(t *testing.T) {
		if newSerial == "" {
			t.Skip("prior renewal did not run")
		}
		m := monitor.New(db, mgr, db, opts)
		report, err := m.Scan(ctx, monitor.ScanRequest{AutoRenew: true, RequestedBy: "e2e-monitor"})
		if err != nil {
			t.Fatalf("second scan: %v", err)
		}
		if report.Renewed != 0 {
			t.Errorf("second scan renewed %d certs, want 0 (storm)", report.Renewed)
		}
		if !findItem(t, report, near.Serial.String()).Superseded {
			t.Error("original near-expiry serial should be superseded after renewal")
		}
		// The fresh reissue is healthy (ok) and not near expiry.
		if got := findItem(t, report, newSerial).Severity; got != monitor.SeverityOK {
			t.Errorf("renewed leaf severity = %s, want ok", got)
		}
	})
}
