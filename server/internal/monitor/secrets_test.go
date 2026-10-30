package monitor

// Tests for stored-secret TTL/rotation lifecycle scanning (Task 72). Nothing
// previously covered this path, yet it is what turns "this password is overdue"
// into an operator-visible notification and a Prometheus gauge. Three things
// are pinned here: the classification itself, the gauge refresh (including
// clearing, so a resolved backlog does not read as a stuck alert), and the
// storm filter that decides whether a still-overdue secret notifies again.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeScheduleStore is an in-memory SecretScheduleLister.
type fakeScheduleStore struct {
	secrets []models.StoredSecret
	err     error
}

func (f *fakeScheduleStore) ListStoredSecretsWithSchedule() ([]models.StoredSecret, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]models.StoredSecret(nil), f.secrets...), nil
}

// recordingSink captures the notifications a scan dispatches.
type recordingSink struct {
	got []Notification
}

func (s *recordingSink) Name() string { return "recording" }
func (s *recordingSink) Notify(_ context.Context, n Notification) error {
	s.got = append(s.got, n)
	return nil
}

// secretFindings flattens the secret-lifecycle findings this sink received. A
// scan tick also dispatches the certificate-expiry report through the same
// sinks, so the notifications are filtered rather than counted.
func (s *recordingSink) secretFindings() []SecretItem {
	var out []SecretItem
	for _, n := range s.got {
		out = append(out, n.SecretWarnings...)
	}
	return out
}

// stateGauge reads back secsy_secrets_lifecycle_due for one state the way a
// Prometheus scrape would see it.
func stateGauge(t *testing.T, state string) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := metrics.Default.WriteTo(&buf); err != nil {
		t.Fatalf("rendering metrics: %v", err)
	}
	want := `secsy_secrets_lifecycle_due{state="` + state + `"}`
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			return strings.TrimSpace(strings.TrimPrefix(line, want))
		}
	}
	return ""
}

// TestClassifySecretsStatesAndSeverities covers every lifecycle finding: the
// TTL warning/critical windows, an expired TTL, a rotation reminder and its
// escalation, and the case that a single secret can be due for BOTH reasons
// at once (they call for different actions, so neither may mask the other).
func TestClassifySecretsStatesAndSeverities(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	secrets := []models.StoredSecret{
		// Outside the warning window: not due at all.
		{ID: "quiet", Name: "quiet", TenantID: "default", CurrentVersion: 1,
			ExpiresAt: at(90 * 24 * time.Hour)},
		// Inside warning (30d) but outside critical (7d).
		{ID: "warn", Name: "warn", TenantID: "default", CurrentVersion: 1,
			ExpiresAt: at(20 * 24 * time.Hour)},
		// Inside critical.
		{ID: "crit", Name: "crit", TenantID: "default", CurrentVersion: 1,
			ExpiresAt: at(3 * 24 * time.Hour)},
		// Past its TTL.
		{ID: "gone", Name: "gone", TenantID: "default", CurrentVersion: 1,
			ExpiresAt: at(-time.Hour)},
		// Rotation overdue by 3d on a 7d period: warning.
		{ID: "rot", Name: "rot", TenantID: "default", CurrentVersion: 2,
			RotateEveryDays: 7, ValueChangedAt: now.Add(-10 * 24 * time.Hour)},
		// Overdue by more than another full period: escalates to critical.
		{ID: "rot2", Name: "rot2", TenantID: "default", CurrentVersion: 2,
			RotateEveryDays: 7, ValueChangedAt: now.Add(-30 * 24 * time.Hour)},
		// Both a dead TTL and an overdue rotation.
		{ID: "both", Name: "both", TenantID: "default", CurrentVersion: 1,
			ExpiresAt: at(-24 * time.Hour), RotateEveryDays: 1,
			ValueChangedAt: now.Add(-10 * 24 * time.Hour)},
	}

	items := ClassifySecrets(secrets, 30, 7, now)
	type key struct {
		id    string
		state SecretState
	}
	got := map[key]Severity{}
	for _, it := range items {
		got[key{it.ID, it.State}] = it.Severity
	}
	for _, want := range []struct {
		id    string
		state SecretState
		sev   Severity
	}{
		{"warn", SecretStateExpiring, SeverityWarning},
		{"crit", SecretStateExpiring, SeverityCritical},
		{"gone", SecretStateExpired, SeverityExpired},
		{"rot", SecretStateRotationDue, SeverityWarning},
		{"rot2", SecretStateRotationDue, SeverityCritical},
		{"both", SecretStateExpired, SeverityExpired},
		{"both", SecretStateRotationDue, SeverityCritical},
	} {
		if sev, ok := got[key{want.id, want.state}]; !ok {
			t.Errorf("%s: missing %s finding", want.id, want.state)
		} else if sev != want.sev {
			t.Errorf("%s %s severity = %s, want %s", want.id, want.state, sev, want.sev)
		}
	}
	for k := range got {
		if k.id == "quiet" {
			t.Errorf("a secret %d days from expiry must not be reported", 90)
		}
	}
	// "both" yields exactly two findings, not one that hides the other.
	n := 0
	for _, it := range items {
		if it.ID == "both" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("secret due for TTL and rotation produced %d findings, want 2", n)
	}

	// A secret with no schedule at all is never due, even expired-looking.
	if items := ClassifySecrets([]models.StoredSecret{
		{ID: "none", Name: "none", CurrentVersion: 1},
	}, 30, 7, now); len(items) != 0 {
		t.Errorf("unscheduled secret produced findings: %+v", items)
	}
}

// TestClassifySecretsCarriesLabels proves operator metadata rides along into
// the finding. A "rotation due" alert that cannot say who owns the secret
// forces a second lookup before anyone can act on it.
func TestClassifySecretsCarriesLabels(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	exp := now.Add(24 * time.Hour)
	labels := map[string]string{"owner": "payments", "env": "prod"}
	items := ClassifySecrets([]models.StoredSecret{
		{ID: "s", Name: "db-password", TenantID: "default", CurrentVersion: 3,
			ExpiresAt: &exp, RotateEveryDays: 1,
			ValueChangedAt: now.Add(-10 * 24 * time.Hour), Labels: labels},
	}, 30, 7, now)
	if len(items) != 2 {
		t.Fatalf("items = %+v, want a TTL and a rotation finding", items)
	}
	for _, it := range items {
		if it.Labels["owner"] != "payments" || it.Labels["env"] != "prod" {
			t.Errorf("%s finding lost its labels: %+v", it.State, it.Labels)
		}
	}
	// The log sink renders them on the line an operator actually reads.
	if got := formatLabels(labels); got != " env=prod owner=payments" {
		t.Errorf("formatLabels = %q, want a stable sorted rendering", got)
	}
	if got := formatLabels(nil); got != "" {
		t.Errorf("formatLabels(nil) = %q, want empty", got)
	}
}

// TestSecretScanRefreshesGauge pins the metrics half of the contract: the
// gauge tracks each state per scan AND returns to zero once the backlog
// clears. A gauge that only ever counts up reads as a permanent alert.
func TestSecretScanRefreshesGauge(t *testing.T) {
	store := &fakeScheduleStore{}
	scanner := NewSecretLifecycleScanner(store, config.MonitorConfig{WarningDays: 30, CriticalDays: 7})
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	scanner.Now = func() time.Time { return now }

	expired := now.Add(-time.Hour)
	store.secrets = []models.StoredSecret{
		{ID: "a", Name: "a", CurrentVersion: 1, ExpiresAt: &expired},
		{ID: "b", Name: "b", CurrentVersion: 1, RotateEveryDays: 1, ValueChangedAt: now.Add(-48 * time.Hour)},
		{ID: "c", Name: "c", CurrentVersion: 1, RotateEveryDays: 1, ValueChangedAt: now.Add(-48 * time.Hour)},
	}
	if _, err := scanner.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stateGauge(t, "expired"); got != "1" {
		t.Errorf("expired gauge = %q, want 1", got)
	}
	if got := stateGauge(t, "rotation_due"); got != "2" {
		t.Errorf("rotation_due gauge = %q, want 2", got)
	}

	// Everything rotated/extended: the gauge must drop back to zero.
	store.secrets = nil
	if _, err := scanner.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"expiring", "expired", "rotation_due"} {
		if got := stateGauge(t, state); got != "0" {
			t.Errorf("%s gauge = %q after the backlog cleared, want 0", state, got)
		}
	}

	// A store failure surfaces as an error rather than silently zeroing the
	// gauges, which would look like "all clear".
	store.err = context.DeadlineExceeded
	if _, err := scanner.Scan(context.Background()); err == nil {
		t.Error("a failing store must report an error")
	}
}

// TestSecretScanStormFilter covers FilterForNotify: the first sighting
// notifies, an unchanged repeat is suppressed, and an escalation or a value
// change breaks through. Without this a secret that stays overdue would
// re-alert on every tick until someone muted the channel.
func TestSecretScanStormFilter(t *testing.T) {
	store := &fakeScheduleStore{}
	scanner := NewSecretLifecycleScanner(store, config.MonitorConfig{WarningDays: 30, CriticalDays: 7})
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	scanner.Now = func() time.Time { return now }

	store.secrets = []models.StoredSecret{
		{ID: "s", Name: "db-password", TenantID: "default", CurrentVersion: 1,
			RotateEveryDays: 7, ValueChangedAt: now.Add(-10 * 24 * time.Hour)},
	}
	scan := func() []SecretItem {
		t.Helper()
		items, err := scanner.Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return scanner.FilterForNotify(items)
	}

	if due := scan(); len(due) != 1 {
		t.Fatalf("first sighting notified %d findings, want 1", len(due))
	}
	if due := scan(); len(due) != 0 {
		t.Fatalf("unchanged repeat notified %+v, want suppression", due)
	}

	// Escalation to critical breaks through the filter.
	store.secrets[0].ValueChangedAt = now.Add(-30 * 24 * time.Hour)
	due := scan()
	if len(due) != 1 || due[0].Severity != SeverityCritical {
		t.Fatalf("escalation notified %+v, want one critical finding", due)
	}
	if due := scan(); len(due) != 0 {
		t.Fatalf("repeat after escalation notified %+v, want suppression", due)
	}

	// A new value version while still due is worth saying again: someone
	// acted, and the reminder is still firing.
	store.secrets[0].CurrentVersion = 2
	if due := scan(); len(due) != 1 {
		t.Fatalf("value-version change notified %d findings, want 1", len(due))
	}

	// Once it clears, the mark is dropped so a later recurrence notifies
	// immediately rather than being mistaken for the old one.
	store.secrets[0].ValueChangedAt = now
	if due := scan(); len(due) != 0 {
		t.Fatalf("a rotated secret notified %+v, want nothing", due)
	}
	store.secrets[0].ValueChangedAt = now.Add(-10 * 24 * time.Hour)
	if due := scan(); len(due) != 1 {
		t.Fatalf("recurrence after clearing notified %d findings, want 1", len(due))
	}
}

// TestRunnerDispatchesSecretLifecycle is the wiring test: the scan must run on
// the runner's tick and reach the configured sinks, with each sink seeing only
// findings at or above its minimum severity. The scanner is installed by
// cmd/server/main.go, so a refactor that drops it from runOnce would silently
// stop every rotation reminder.
func TestRunnerDispatchesSecretLifecycle(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeScheduleStore{secrets: []models.StoredSecret{
		// Warning-level rotation reminder.
		{ID: "warn", Name: "warn-secret", TenantID: "default", CurrentVersion: 1,
			RotateEveryDays: 7, ValueChangedAt: now.Add(-10 * 24 * time.Hour),
			Labels: map[string]string{"owner": "payments"}},
		// Critical-level: overdue by more than another period.
		{ID: "crit", Name: "crit-secret", TenantID: "default", CurrentVersion: 1,
			RotateEveryDays: 7, ValueChangedAt: now.Add(-40 * 24 * time.Hour)},
	}}

	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	scanner := NewSecretLifecycleScanner(store, config.MonitorConfig{WarningDays: 30, CriticalDays: 7})
	scanner.Now = func() time.Time { return now }
	r.WithSecretLifecycle(scanner)

	all, critOnly := &recordingSink{}, &recordingSink{}
	r.bindings = []sinkBinding{
		{sink: all, minSeverity: SeverityWarning},
		{sink: critOnly, minSeverity: SeverityCritical},
	}

	r.runOnce(context.Background())

	warnFindings := all.secretFindings()
	if len(warnFindings) != 2 {
		t.Fatalf("warning-level sink saw %d secret findings, want both: %+v", len(warnFindings), warnFindings)
	}
	crit := critOnly.secretFindings()
	if len(crit) != 1 || crit[0].Name != "crit-secret" {
		t.Fatalf("critical-level sink saw %+v, want only crit-secret", crit)
	}
	// The finding carries the state the sink renders as "secret rotation due".
	if crit[0].State != SecretStateRotationDue {
		t.Errorf("state = %q, want %q", crit[0].State, SecretStateRotationDue)
	}
	// Labels travelled with the warning-level finding.
	for _, it := range warnFindings {
		if it.Name == "warn-secret" && it.Labels["owner"] != "payments" {
			t.Errorf("labels lost en route to the sink: %+v", it.Labels)
		}
	}

	// A runner with no scanner installed must not panic on a tick.
	plain := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	plain.scanSecretLifecycle(context.Background())
}
