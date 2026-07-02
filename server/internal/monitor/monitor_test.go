package monitor

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeStore is an in-memory CertLister + AuditSink for the logic tests. Its
// renewer counterpart appends reissued certificates back into it so a follow-up
// scan sees them, letting us prove renewal-storm prevention across scans.
type fakeStore struct {
	mu     sync.Mutex
	cas    []models.CA
	certs  map[string][]models.IssuedCertificate // caID -> certs
	events []*audit.Event
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cas:   []models.CA{{ID: "ca1", Label: "Test CA"}},
		certs: map[string][]models.IssuedCertificate{},
	}
}

func (s *fakeStore) add(c models.IssuedCertificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.CAID == "" {
		c.CAID = "ca1"
	}
	s.certs[c.CAID] = append(s.certs[c.CAID], c)
}

func (s *fakeStore) ListCAs() ([]models.CA, error) { return s.cas, nil }

func (s *fakeStore) ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.IssuedCertificate(nil), s.certs[caID]...), nil
}

func (s *fakeStore) AppendEvent(e *audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// fakeRenewer models ca.Manager.RenewCertificate: it mints a fresh long-lived
// certificate for the same identity and records it in the store, mirroring the
// real reissue-with-new-serial behavior.
type fakeRenewer struct {
	store    *fakeStore
	now      time.Time
	validity time.Duration
	calls    int
	fail     bool
}

func (r *fakeRenewer) RenewCertificate(_ context.Context, spec ca.RenewSpec) (*ca.IssueResult, error) {
	r.calls++
	if r.fail {
		return nil, fmt.Errorf("simulated renew failure")
	}
	// Locate the prior cert to copy its identity.
	var prior *models.IssuedCertificate
	for _, c := range r.store.certs[spec.CAID] {
		if c.Serial == spec.Serial {
			cc := c
			prior = &cc
			break
		}
	}
	if prior == nil {
		return nil, fmt.Errorf("no cert with serial %s", spec.Serial)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	// A validity override (as SVID renewal omits) falls back to the prior cert's
	// own lifetime, mirroring the real path where Validity 0 uses the profile
	// default. This keeps renewed SVIDs short-lived instead of long-lived.
	validity := r.validity
	if spec.Validity > 0 {
		validity = spec.Validity
	} else if r.validity == 0 && !prior.NotBefore.IsZero() {
		validity = prior.NotAfter.Sub(prior.NotBefore)
	}
	notAfter := r.now.Add(validity)
	newCert := models.IssuedCertificate{
		CAID:       prior.CAID,
		Serial:     serial.String(),
		Subject:    prior.Subject,
		CommonName: prior.CommonName,
		SANs:       prior.SANs,
		Profile:    prior.Profile,
		NotBefore:  r.now,
		NotAfter:   notAfter,
		Status:     models.CertStatusValid,
	}
	r.store.add(newCert)
	return &ca.IssueResult{
		Serial:      serial,
		Certificate: &x509.Certificate{NotAfter: notAfter},
		Profile:     prior.Profile,
	}, nil
}

func cert(cn, profile string, notAfter time.Time, status models.CertStatus) models.IssuedCertificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return models.IssuedCertificate{
		CAID:       "ca1",
		Serial:     serial.String(),
		Subject:    "CN=" + cn,
		CommonName: cn,
		Profile:    profile,
		NotAfter:   notAfter,
		Status:     status,
	}
}

func testOptions() Options {
	return OptionsFromDays(30, 7, 7, nil)
}

func TestScanClassify(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("ok.example", "server", now.Add(90*24*time.Hour), models.CertStatusValid))
	store.add(cert("warn.example", "server", now.Add(20*24*time.Hour), models.CertStatusValid))
	store.add(cert("crit.example", "server", now.Add(3*24*time.Hour), models.CertStatusValid))
	store.add(cert("dead.example", "server", now.Add(-24*time.Hour), models.CertStatusValid))
	store.add(cert("revoked.example", "server", now.Add(3*24*time.Hour), models.CertStatusRevoked))

	m := New(store, nil, nil, testOptions())
	report, err := m.Scan(context.Background(), ScanRequest{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts[SeverityOK] != 1 || report.Counts[SeverityWarning] != 1 ||
		report.Counts[SeverityCritical] != 1 || report.Counts[SeverityExpired] != 1 {
		t.Fatalf("unexpected counts: %+v", report.Counts)
	}
	// Revoked cert must not appear at all.
	if len(report.Items) != 4 {
		t.Fatalf("expected 4 non-revoked items, got %d", len(report.Items))
	}
	// Sorted most-urgent-first: expired then critical then warning then ok.
	wantOrder := []Severity{SeverityExpired, SeverityCritical, SeverityWarning, SeverityOK}
	for i, w := range wantOrder {
		if report.Items[i].Severity != w {
			t.Errorf("item %d severity = %s, want %s", i, report.Items[i].Severity, w)
		}
	}
}

func TestScanSuperseded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	// Two certs for the same identity: an old near-expiry one and a fresh reissue.
	store.add(cert("web.example", "server", now.Add(2*24*time.Hour), models.CertStatusValid))
	store.add(cert("web.example", "server", now.Add(300*24*time.Hour), models.CertStatusValid))

	m := New(store, nil, nil, testOptions())
	report, err := m.Scan(context.Background(), ScanRequest{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var superseded, ok int
	for _, it := range report.Items {
		if it.Superseded {
			superseded++
		}
		if it.Severity == SeverityOK && !it.Superseded {
			ok++
		}
	}
	if superseded != 1 {
		t.Fatalf("expected exactly 1 superseded item, got %d", superseded)
	}
	// The superseded (near-expiry) cert must not inflate the critical count.
	if report.Counts[SeverityCritical] != 0 {
		t.Fatalf("superseded near-expiry cert should not count as critical: %+v", report.Counts)
	}
	// Warnings must exclude the superseded item.
	if w := report.Warnings(SeverityWarning); len(w) != 0 {
		t.Fatalf("expected no warnings (fresh cert is ok, old is superseded), got %d", len(w))
	}
}

func TestAutoRenewAndStormPrevention(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("renew.example", "server", now.Add(3*24*time.Hour), models.CertStatusValid))
	store.add(cert("safe.example", "server", now.Add(100*24*time.Hour), models.CertStatusValid))

	renewer := &fakeRenewer{store: store, now: now, validity: 365 * 24 * time.Hour}
	m := New(store, renewer, store, testOptions())

	report, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Renewed != 1 || renewer.calls != 1 {
		t.Fatalf("expected exactly 1 renewal, got report.Renewed=%d calls=%d", report.Renewed, renewer.calls)
	}
	// An audit event for the auto-renew must have been recorded.
	if len(store.events) != 1 || store.events[0].Action != audit.ActionCertAutoRenew ||
		store.events[0].Result != audit.ResultSuccess {
		t.Fatalf("expected 1 successful auto_renew audit event, got %+v", store.events)
	}

	// A second scan must NOT renew again: the near-expiry cert is now superseded
	// by the fresh reissue (renewal-storm prevention).
	renewer.calls = 0
	report2, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatal(err)
	}
	if report2.Renewed != 0 || renewer.calls != 0 {
		t.Fatalf("second scan should renew nothing, got Renewed=%d calls=%d", report2.Renewed, renewer.calls)
	}
}

func TestAutoRenewProfileAllowlist(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("a.example", "server", now.Add(2*24*time.Hour), models.CertStatusValid))
	store.add(cert("b.example", "client", now.Add(2*24*time.Hour), models.CertStatusValid))

	opts := OptionsFromDays(30, 7, 7, []string{"server"})
	renewer := &fakeRenewer{store: store, now: now, validity: 365 * 24 * time.Hour}
	m := New(store, renewer, store, opts)

	report, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Renewed != 1 {
		t.Fatalf("only the 'server' profile cert should renew, got %d", report.Renewed)
	}
}

func TestAutoRenewFailureRecorded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("f.example", "server", now.Add(2*24*time.Hour), models.CertStatusValid))

	renewer := &fakeRenewer{store: store, now: now, validity: 365 * 24 * time.Hour, fail: true}
	m := New(store, renewer, store, testOptions())

	report, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.RenewFailed != 1 || report.Renewed != 0 {
		t.Fatalf("expected 1 failed renewal, got failed=%d renewed=%d", report.RenewFailed, report.Renewed)
	}
	if len(store.events) != 1 || store.events[0].Result != audit.ResultError {
		t.Fatalf("expected an error audit event, got %+v", store.events)
	}
}

func TestWebhookSink(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("hook.example", "server", now.Add(3*24*time.Hour), models.CertStatusValid))

	var got Notification
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "yes" {
			t.Errorf("missing custom header")
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("bad JSON body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	m := New(store, nil, nil, testOptions())
	report, err := m.Scan(context.Background(), ScanRequest{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	sink := NewWebhookSink(srv.URL, map[string]string{"X-Test": "yes"}, time.Second)
	m.Dispatch(context.Background(), report, []sinkBinding{{sink: sink, minSeverity: SeverityWarning}})

	if len(got.Warnings) != 1 || got.Warnings[0].CommonName != "hook.example" {
		t.Fatalf("webhook did not receive the expected warning: %+v", got.Warnings)
	}
}

func TestWebhookSinkSkipsEmpty(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	sink := NewWebhookSink(srv.URL, nil, time.Second)
	if err := sink.Notify(context.Background(), Notification{}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("webhook should not be called for an empty notification")
	}
}

func TestLogSink(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := newFakeStore()
	store.add(cert("l.example", "server", now.Add(3*24*time.Hour), models.CertStatusValid))
	m := New(store, nil, nil, testOptions())
	report, _ := m.Scan(context.Background(), ScanRequest{Now: now})
	sink := NewLogSink(log.New(io.Discard, "", 0))
	if err := sink.Notify(context.Background(), Notification{
		Warnings: report.Warnings(SeverityWarning),
		Counts:   report.Counts,
	}); err != nil {
		t.Fatal(err)
	}
}
