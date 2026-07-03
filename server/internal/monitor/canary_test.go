package monitor

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// canaryCert builds an issued-certificate fixture carrying the canary marker.
func canaryCert(cn string, notAfter time.Time, status models.CertStatus) models.IssuedCertificate {
	c := cert(cn, "canary", notAfter, status)
	c.Marker = models.CertMarkerCanary
	return c
}

// TestScanSkipsCanaryCerts proves canary-marked certificates are invisible to
// the expiry monitor's storm logic: they produce no warning items, no severity
// counts, and — critically — no auto-renewal attempts, even when a failed
// probe leaves one valid and about to expire.
func TestScanSkipsCanaryCerts(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	// A real certificate inside the critical window — the control group.
	store.add(cert("real.example", "server", now.Add(3*24*time.Hour), models.CertStatusValid))
	// Canary leftovers from probes: one still valid and nearly expired (a
	// failed probe that could not revoke), one already expired, one revoked.
	store.add(canaryCert("secsy-canary", now.Add(30*time.Minute), models.CertStatusValid))
	store.add(canaryCert("secsy-canary", now.Add(-time.Hour), models.CertStatusValid))
	store.add(canaryCert("secsy-canary", now.Add(30*time.Minute), models.CertStatusRevoked))

	renewer := &fakeRenewer{store: store, now: now, validity: 90 * 24 * time.Hour}
	m := New(store, renewer, store, testOptions())
	report, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(report.Items) != 1 {
		t.Fatalf("scan reported %d items, want only the real certificate: %+v", len(report.Items), report.Items)
	}
	if report.Items[0].CommonName != "real.example" {
		t.Fatalf("unexpected item %q in report", report.Items[0].CommonName)
	}
	total := report.Counts[SeverityWarning] + report.Counts[SeverityCritical] + report.Counts[SeverityExpired]
	if total != 1 {
		t.Fatalf("severity counts include canary certs: %+v", report.Counts)
	}
	// The real critical cert renews; the near-expiry canary cert must not.
	if renewer.calls != 1 {
		t.Fatalf("auto-renew ran %d times, want 1 (canary certs must never renew)", renewer.calls)
	}
	for _, it := range report.Items {
		if it.Profile == "canary" {
			t.Fatalf("canary item leaked into the report: %+v", it)
		}
	}
}

// TestNotifierDeliversCanaryFailures proves canary failures ride the monitor's
// configured sinks: a webhook at min_severity critical receives the payload,
// an expired-only webhook is filtered out, and delivery happens even though
// there are no expiry warnings at all.
func TestNotifierDeliversCanaryFailures(t *testing.T) {
	type received struct {
		n Notification
	}
	got := make(chan received, 1)
	hit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var n Notification
		if err := json.Unmarshal(body, &n); err != nil {
			t.Errorf("webhook payload is not a Notification: %v", err)
		}
		got <- received{n: n}
	}))
	defer hit.Close()
	missTS := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("expired-only sink must not receive canary failures")
	}))
	defer missTS.Close()

	var logBuf strings.Builder
	notifier, err := NewNotifier(config.MonitorConfig{
		Notifications: []config.NotificationConfig{
			{Type: "webhook", URL: hit.URL, MinSeverity: "critical"},
			{Type: "webhook", URL: missTS.URL, MinSeverity: "expired"},
			{Type: "log", MinSeverity: "warning"},
		},
	}, log.New(&logBuf, "", 0))
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}

	failure := CanaryFailure{
		CAID:    "ca1",
		CALabel: "Test CA",
		Stage:   "ocsp_good",
		Serial:  "12345",
		Error:   "simulated HSM outage",
		At:      time.Now(),
	}
	notifier.NotifyCanaryFailures(context.Background(), []CanaryFailure{failure})

	select {
	case r := <-got:
		if len(r.n.CanaryFailures) != 1 {
			t.Fatalf("webhook received %d canary failures, want 1", len(r.n.CanaryFailures))
		}
		f := r.n.CanaryFailures[0]
		if f.CAID != failure.CAID || f.Stage != failure.Stage || f.Serial != failure.Serial {
			t.Fatalf("webhook payload mismatch: %+v", f)
		}
		if len(r.n.Warnings) != 0 {
			t.Fatalf("canary notification unexpectedly carries expiry warnings: %+v", r.n.Warnings)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("critical webhook sink never received the canary failure")
	}

	logged := logBuf.String()
	if !strings.Contains(logged, "issuance-canary: FAILURE") || !strings.Contains(logged, "stage=ocsp_good") {
		t.Fatalf("log sink output missing canary failure line: %q", logged)
	}
}

// TestNotifierDefaultsToLogSink proves canary failures are never silently
// dropped: with no notifications configured at all, the fallback log sink
// still reports them.
func TestNotifierDefaultsToLogSink(t *testing.T) {
	var logBuf strings.Builder
	notifier, err := NewNotifier(config.MonitorConfig{}, log.New(&logBuf, "", 0))
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	notifier.NotifyCanaryFailures(context.Background(), []CanaryFailure{{
		CAID: "ca1", CALabel: "Test CA", Stage: "issue", Error: "boom", At: time.Now(),
	}})
	if !strings.Contains(logBuf.String(), "issuance-canary: FAILURE") {
		t.Fatalf("fallback log sink did not report the failure: %q", logBuf.String())
	}
}
