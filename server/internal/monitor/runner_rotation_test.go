package monitor

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeRotator records AutoRotateDue invocations so the runner's rotation
// trigger can be tested without an HSM.
type fakeRotator struct {
	calls  int
	before time.Duration
	result []ca.RotationResult
}

func (f *fakeRotator) AutoRotateDue(_ context.Context, spec ca.AutoRotateSpec) ([]ca.RotationResult, error) {
	f.calls++
	f.before = spec.Before
	return f.result, nil
}

func newTestRunner(t *testing.T, cfg config.MonitorConfig) *Runner {
	t.Helper()
	store := newFakeStore()
	mon := New(store, nil, store, OptionsFromDays(cfg.WarningDays, cfg.CriticalDays, 0, nil))
	r, err := NewRunner(mon, cfg, log.New(log.Writer(), "", 0))
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

// TestRunnerRotationDisabled proves auto-rotation is a no-op unless the config
// flag is set, even when a rotator is wired.
func TestRunnerRotationDisabled(t *testing.T) {
	r := newTestRunner(t, config.MonitorConfig{WarningDays: 30, CriticalDays: 7, IntervalHours: 12})
	rot := &fakeRotator{}
	r.WithRotation(rot, nil)

	r.rotateOnce(context.Background())
	if rot.calls != 0 {
		t.Errorf("rotator called %d times with rotate_intermediates disabled, want 0", rot.calls)
	}
}

// TestRunnerRotationEnabled proves the runner triggers rotation with the
// configured threshold when the flag is set, and records an audit event.
func TestRunnerRotationEnabled(t *testing.T) {
	cfg := config.MonitorConfig{
		WarningDays:         30,
		CriticalDays:        7,
		IntervalHours:       12,
		RotateIntermediates: true,
		RotateBeforeDays:    45,
	}
	r := newTestRunner(t, cfg)
	sink := newFakeStore()
	rot := &fakeRotator{result: []ca.RotationResult{{
		OldCA: &models.CA{ID: "old", Label: "Old Inter"},
		NewCA: &models.CA{ID: "new", Label: "New Inter", Serial: "42"},
	}}}
	r.WithRotation(rot, sink)

	r.rotateOnce(context.Background())

	if rot.calls != 1 {
		t.Fatalf("rotator called %d times, want 1", rot.calls)
	}
	if want := 45 * 24 * time.Hour; rot.before != want {
		t.Errorf("rotate-before threshold = %s, want %s", rot.before, want)
	}
	if len(sink.events) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(sink.events))
	}
	if got := sink.events[0].Action; got != "ca.rotate" {
		t.Errorf("audit action = %q, want ca.rotate", got)
	}
	if sink.events[0].ID == "" {
		t.Error("rotation audit event missing an ID")
	}
}
