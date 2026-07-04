//go:build sqlite

package doctor

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// servingCheckResult runs checkServingCert against the given state and returns
// its single result.
func servingCheckResult(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) Result {
	t.Helper()
	r := &Report{OK: true}
	opts := Options{}
	opts.applyDefaults()
	checkServingCert(r, cfg, db, schemaOK, opts)
	if len(r.Checks) != 1 || r.Checks[0].Name != "serving.self_issued" {
		t.Fatalf("checkServingCert produced %+v, want one serving.self_issued result", r.Checks)
	}
	return r.Checks[0]
}

// newServingDB opens a fresh store and inserts one CA row so ListCAs/
// ListIssuedCertificates have something to walk. It returns the store and CA id.
func newServingDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "doctor-serving.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	caID := "serving-ca"
	if err := db.CreateCA(&models.CA{
		ID:        caID,
		Label:     "serving-doctor-ca",
		KeyType:   "ecdsa-sha2-nistp256",
		PublicKey: "placeholder", // the check never reads it; NOT NULL just needs a value
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return db, caID
}

// recordServingCert inserts an issued-certificate row with the given serial,
// NotAfter, and marker.
func recordServingCert(t *testing.T, db *database.DB, caID, serial string, notAfter time.Time, marker string) {
	t.Helper()
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID:         "cert-" + caID + "-" + serial,
		CAID:       caID,
		Serial:     serial,
		CommonName: "localhost",
		Profile:    "server",
		NotBefore:  notAfter.Add(-24 * time.Hour),
		NotAfter:   notAfter,
		Status:     models.CertStatusValid,
		Marker:     marker,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}
}

// servingCfg builds an enabled self-issue config for caID with a 60-day
// renew_before window (larger than the default 30-day ExpiryWarn so the
// renew-window branch is distinguishable from generic expiry).
func servingCfg(caID string) *config.Config {
	c := &config.Config{}
	c.Server.TLS.SelfIssue.Enabled = true
	c.Server.TLS.SelfIssue.CAID = caID
	c.Server.TLS.SelfIssue.DNSNames = []string{"localhost"}
	c.Server.TLS.SelfIssue.RenewBefore = "1440h" // 60 days
	return c
}

// TestCheckServingCert walks the serving-certificate freshness check through its
// states: skip when disabled or the schema is unavailable, warn when enabled but
// no serving certificate exists, pass on a healthy long-dated certificate, warn
// once the newest certificate is inside its renew_before window, and fail when it
// is near expiry. It also confirms only serving-tls-marked records are considered.
func TestCheckServingCert(t *testing.T) {
	now := time.Now()

	// Disabled → skip (store state is irrelevant).
	db, caID := newServingDB(t)
	if res := servingCheckResult(t, &config.Config{}, db, true); res.Status != StatusSkip {
		t.Fatalf("disabled status = %s, want skip (%s)", res.Status, res.Detail)
	}

	// Enabled but schema unavailable → skip.
	if res := servingCheckResult(t, servingCfg(caID), db, false); res.Status != StatusSkip {
		t.Fatalf("schema-unavailable status = %s, want skip (%s)", res.Status, res.Detail)
	}

	// Enabled, nothing issued yet → warn.
	if res := servingCheckResult(t, servingCfg(caID), db, true); res.Status != StatusWarn {
		t.Fatalf("no-cert status = %s, want warn (%s)", res.Status, res.Detail)
	}

	// A non-serving-tls-marked certificate must be ignored — the check still warns.
	recordServingCert(t, db, caID, "1", now.Add(300*24*time.Hour), models.CertMarkerCanary)
	if res := servingCheckResult(t, servingCfg(caID), db, true); res.Status != StatusWarn {
		t.Fatalf("only-canary status = %s, want warn (%s)", res.Status, res.Detail)
	}

	// A healthy long-dated serving certificate → pass.
	recordServingCert(t, db, caID, "2", now.Add(300*24*time.Hour), models.CertMarkerServingTLS)
	if res := servingCheckResult(t, servingCfg(caID), db, true); res.Status != StatusPass {
		t.Fatalf("healthy status = %s, want pass (%s)", res.Status, res.Detail)
	}

	// Inside the renew_before window (45 days left, generic 30-day headroom still
	// clears) → warn that rotation is overdue. Use a fresh store so this record is
	// the newest by NotAfter.
	warnDB, warnCA := newServingDB(t)
	recordServingCert(t, warnDB, warnCA, "10", now.Add(45*24*time.Hour), models.CertMarkerServingTLS)
	res := servingCheckResult(t, servingCfg(warnCA), warnDB, true)
	if res.Status != StatusWarn {
		t.Fatalf("inside-renew-window status = %s, want warn (%s)", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "renew_before") {
		t.Fatalf("inside-renew-window detail %q should mention renew_before", res.Detail)
	}

	// Near expiry (2 days) → fail even though a stale big-NotAfter non-serving cert
	// also exists in the store (marker filtering keeps the serving cert selected).
	failDB, failCA := newServingDB(t)
	recordServingCert(t, failDB, failCA, "20", now.Add(365*24*time.Hour), "") // ordinary cert, ignored
	recordServingCert(t, failDB, failCA, "21", now.Add(48*time.Hour), models.CertMarkerServingTLS)
	if res := servingCheckResult(t, servingCfg(failCA), failDB, true); res.Status != StatusFail {
		t.Fatalf("near-expiry status = %s, want fail (%s)", res.Status, res.Detail)
	}
}
