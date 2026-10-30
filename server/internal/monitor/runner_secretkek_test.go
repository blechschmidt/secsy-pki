package monitor

// Tests for the secret-layer KEK rotation hook the runner drives each scan tick
// (Task 63). The gauge arithmetic itself is covered in internal/secret; what is
// pinned here is the wiring, which nothing else exercises: the hook is a bare
// closure installed by cmd/server/main.go, so a refactor that stopped calling
// it from runOnce would leave secsy_secret_on_old_kek frozen at whatever the
// last explicit rotate/rewrap left behind — a silently stale gauge, which is
// worse than a missing one because it reads as "no secrets need re-wrapping".

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// fakeKEKStatusStore is an in-memory secret.KEKStatusStore: one family's
// lineage plus the per-label stored-secret counts the gauges are computed from.
type fakeKEKStatusStore struct {
	family   string
	versions []models.KEKVersion
	counts   map[string]int64
	err      error
}

func (f *fakeKEKStatusStore) ListKEKFamilies() ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []string{f.family}, nil
}

func (f *fakeKEKStatusStore) ListKEKVersions(string) ([]models.KEKVersion, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]models.KEKVersion(nil), f.versions...), nil
}

func (f *fakeKEKStatusStore) CountStoredSecretsByKEKLabel(string) (map[string]int64, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]int64, len(f.counts))
	for k, v := range f.counts {
		out[k] = v
	}
	return out, nil
}

// gaugeValue renders the default registry and returns the line for name
// carrying the family label, so a gauge can be read back the way a Prometheus
// scrape would see it.
func gaugeValue(t *testing.T, name, family string) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := metrics.Default.WriteTo(&buf); err != nil {
		t.Fatalf("rendering metrics: %v", err)
	}
	want := name + `{family="` + family + `"}`
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			return strings.TrimSpace(strings.TrimPrefix(line, want))
		}
	}
	return ""
}

// TestRunnerSecretKEKCheckUnset proves the hook is optional: a deployment with
// the secret layer disabled never installs one, and the tick must not panic.
func TestRunnerSecretKEKCheckUnset(t *testing.T) {
	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	r.checkSecretKEK(context.Background()) // must be a no-op, not a nil-deref
}

// TestRunnerSecretKEKCheckRunsOnEveryScanTick drives the full scan cycle
// (runOnce), not checkSecretKEK directly: the regression this guards against is
// a refactor that drops the hook from the tick, which a direct call would not
// notice. It also asserts the warning lines reach the monitor log, so "secrets
// still on an old KEK" is visible to an operator reading logs rather than only
// to a Prometheus scrape.
func TestRunnerSecretKEKCheckRunsOnEveryScanTick(t *testing.T) {
	var logBuf bytes.Buffer
	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	r.logger = log.New(&logBuf, "", 0)

	calls := 0
	r.WithSecretKEKCheck(func(context.Context) ([]string, error) {
		calls++
		return []string{"7 stored secret(s) are still wrapped under an old KEK version"}, nil
	})

	r.runOnce(context.Background())
	if calls != 1 {
		t.Fatalf("hook called %d times during a scan tick, want 1", calls)
	}
	if got := logBuf.String(); !strings.Contains(got, "old KEK version") {
		t.Errorf("warning not surfaced in the monitor log; got %q", got)
	}

	// A second tick re-runs the check: the posture is re-read every cycle
	// rather than cached from boot.
	r.runOnce(context.Background())
	if calls != 2 {
		t.Errorf("hook called %d times across two ticks, want 2", calls)
	}
}

// TestRunnerSecretKEKCheckErrorIsNotFatal proves a failing check is logged and
// the tick continues: a transient database error must not stop certificate
// expiry scanning, which is the runner's primary job.
func TestRunnerSecretKEKCheckErrorIsNotFatal(t *testing.T) {
	var logBuf bytes.Buffer
	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	r.logger = log.New(&logBuf, "", 0)
	r.WithSecretKEKCheck(func(context.Context) ([]string, error) {
		return nil, errors.New("database is down")
	})

	r.checkSecretKEK(context.Background()) // must return, not panic or exit
	if got := logBuf.String(); !strings.Contains(got, "database is down") {
		t.Errorf("check failure not logged; got %q", got)
	}
}

// TestRunnerSecretKEKCheckRefreshesGauges is the end-to-end form: the real
// secret.RefreshKEKMetrics closure that cmd/server/main.go installs, driven
// through the runner's tick, must move secsy_secret_on_old_kek and
// secsy_secret_kek_active_version. This is the "gauge feeding the expiry
// monitor" contract, asserted against a scrape of the default registry.
func TestRunnerSecretKEKCheckRefreshesGauges(t *testing.T) {
	const family = "monitor-hook-kek"
	store := &fakeKEKStatusStore{
		family: family,
		versions: []models.KEKVersion{
			{Family: family, Version: 1, Label: family, Status: models.KEKStatusRetiring},
			{Family: family, Version: 2, Label: family + "-v2", Status: models.KEKStatusActive},
		},
		// Three secrets still on v1, one already migrated to v2.
		counts: map[string]int64{family: 3, family + "-v2": 1},
	}

	var logBuf bytes.Buffer
	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	r.logger = log.New(&logBuf, "", 0)
	r.WithSecretKEKCheck(func(context.Context) ([]string, error) {
		return secret.RefreshKEKMetrics(store, family)
	})

	r.checkSecretKEK(context.Background())

	if got := gaugeValue(t, "secsy_secret_on_old_kek", family); got != "3" {
		t.Errorf("secsy_secret_on_old_kek = %q, want 3", got)
	}
	if got := gaugeValue(t, "secsy_secret_kek_active_version", family); got != "2" {
		t.Errorf("secsy_secret_kek_active_version = %q, want 2", got)
	}
	if got := logBuf.String(); !strings.Contains(got, "rewrap") {
		t.Errorf("monitor log should name the remediation; got %q", got)
	}

	// Draining v1 (the re-wrap completing) clears the gauge on the next tick:
	// the hook reports live state, so a stale non-zero value cannot persist.
	store.counts = map[string]int64{family + "-v2": 4}
	logBuf.Reset()
	r.checkSecretKEK(context.Background())

	if got := gaugeValue(t, "secsy_secret_on_old_kek", family); got != "0" {
		t.Errorf("after re-wrap secsy_secret_on_old_kek = %q, want 0", got)
	}
	if strings.Contains(logBuf.String(), "rewrap") {
		t.Errorf("a drained family should produce no re-wrap warning; got %q", logBuf.String())
	}

	// A retired version that still holds secrets is the unrecoverable case and
	// must escalate rather than read as an ordinary pending re-wrap.
	store.versions[0].Status = models.KEKStatusRetired
	store.counts = map[string]int64{family: 2, family + "-v2": 2}
	logBuf.Reset()
	r.checkSecretKEK(context.Background())

	if got := logBuf.String(); !strings.Contains(got, "CRITICAL") {
		t.Errorf("secrets on a RETIRED KEK should log CRITICAL; got %q", got)
	}
}
