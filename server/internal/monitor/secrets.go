package monitor

// Secret-lifecycle scanning (Task 73): stored secrets can carry a TTL
// (expires_at) and/or a rotation-reminder period (rotate_every_days). The
// scanner classifies every scheduled secret against the monitor's existing
// warning/critical windows and feeds the due ones through the same
// notification sinks as certificate-expiry warnings — with storm prevention,
// so a secret that stays overdue re-notifies on escalation or after a
// re-notify interval, not on every tick. Expiry here is an operational
// reminder: decryption of an expired secret still works.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// SecretState classifies why a secret is due.
type SecretState string

const (
	// SecretStateExpiring: the TTL deadline is inside the warning/critical window.
	SecretStateExpiring SecretState = "expiring"
	// SecretStateExpired: the TTL deadline has passed.
	SecretStateExpired SecretState = "expired"
	// SecretStateRotationDue: the value is older than its rotation period.
	SecretStateRotationDue SecretState = "rotation_due"
)

// SecretItem is one due secret in a lifecycle report or notification. It
// carries metadata only — never envelopes or plaintext.
type SecretItem struct {
	TenantID       string      `json:"tenant_id"`
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	State          SecretState `json:"state"`
	Severity       Severity    `json:"severity"`
	CurrentVersion int         `json:"current_version"`
	// ExpiresAt is set for TTL findings.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// RotationDueAt (value_changed_at + rotate_every_days) is set for
	// rotation findings.
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`
	Detail        string     `json:"detail"`
}

// conditionKey identifies the finding for storm-prevention bookkeeping: one
// mark per secret per condition class (TTL vs rotation), so an escalating TTL
// re-notifies without being masked by an unchanged rotation reminder.
func (it SecretItem) conditionKey() string {
	cls := "ttl"
	if it.State == SecretStateRotationDue {
		cls = "rotation"
	}
	return it.TenantID + "/" + it.ID + "/" + cls
}

// SecretScheduleLister is the persistence the scanner needs. *database.DB
// satisfies it.
type SecretScheduleLister interface {
	ListStoredSecretsWithSchedule() ([]models.StoredSecret, error)
}

// ClassifySecrets evaluates every scheduled secret at time now. A secret can
// yield up to two findings — one for its TTL, one for its rotation reminder —
// because they call for different actions (extend/replace vs rotate).
// warningDays/criticalDays are the same windows the certificate scan uses.
func ClassifySecrets(secrets []models.StoredSecret, warningDays, criticalDays int, now time.Time) []SecretItem {
	var out []SecretItem
	for i := range secrets {
		s := &secrets[i]
		if s.ExpiresAt != nil {
			exp := s.ExpiresAt.UTC()
			remaining := exp.Sub(now)
			var item *SecretItem
			switch {
			case remaining <= 0:
				item = &SecretItem{State: SecretStateExpired, Severity: SeverityExpired,
					Detail: fmt.Sprintf("expired %s ago", roundDuration(-remaining))}
			case remaining <= time.Duration(criticalDays)*24*time.Hour:
				item = &SecretItem{State: SecretStateExpiring, Severity: SeverityCritical,
					Detail: fmt.Sprintf("expires in %s", roundDuration(remaining))}
			case remaining <= time.Duration(warningDays)*24*time.Hour:
				item = &SecretItem{State: SecretStateExpiring, Severity: SeverityWarning,
					Detail: fmt.Sprintf("expires in %s", roundDuration(remaining))}
			}
			if item != nil {
				item.TenantID, item.ID, item.Name = s.TenantID, s.ID, s.Name
				item.CurrentVersion = s.CurrentVersion
				item.ExpiresAt = &exp
				out = append(out, *item)
			}
		}
		if s.RotateEveryDays > 0 {
			ref := s.ValueChangedAt
			if ref.IsZero() {
				ref = s.UpdatedAt
			}
			period := time.Duration(s.RotateEveryDays) * 24 * time.Hour
			due := ref.UTC().Add(period)
			if !now.Before(due) {
				sev := SeverityWarning
				// A reminder ignored for another full period escalates.
				if !now.Before(due.Add(period)) {
					sev = SeverityCritical
				}
				out = append(out, SecretItem{
					TenantID: s.TenantID, ID: s.ID, Name: s.Name,
					State: SecretStateRotationDue, Severity: sev,
					CurrentVersion: s.CurrentVersion,
					RotationDueAt:  &due,
					Detail: fmt.Sprintf("rotation overdue by %s (period %dd, value last changed %s)",
						roundDuration(now.Sub(due)), s.RotateEveryDays, ref.UTC().Format("2006-01-02")),
				})
			}
		}
	}
	return out
}

// roundDuration renders a duration in whole days/hours for human-facing
// detail strings.
func roundDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d >= 48*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// secretMark is the storm-prevention state for one finding.
type secretMark struct {
	severity   Severity
	version    int
	notifiedAt time.Time
}

// SecretLifecycleScanner scans the stored-secret registry for due TTL and
// rotation reminders and decides which findings warrant a notification this
// tick. It is safe for concurrent use.
type SecretLifecycleScanner struct {
	store         SecretScheduleLister
	warningDays   int
	criticalDays  int
	renotifyEvery time.Duration
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time

	mu    sync.Mutex
	marks map[string]secretMark
}

// NewSecretLifecycleScanner builds a scanner from the monitor config, sharing
// the certificate scan's warning/critical windows. The re-notify interval
// (monitor.secret_renotify_hours) defaults to 24h.
func NewSecretLifecycleScanner(store SecretScheduleLister, cfg config.MonitorConfig) *SecretLifecycleScanner {
	warning := cfg.WarningDays
	if warning <= 0 {
		warning = 30
	}
	critical := cfg.CriticalDays
	if critical <= 0 {
		critical = 7
	}
	renotify := time.Duration(cfg.SecretRenotifyHours) * time.Hour
	if renotify <= 0 {
		renotify = 24 * time.Hour
	}
	return &SecretLifecycleScanner{
		store:         store,
		warningDays:   warning,
		criticalDays:  critical,
		renotifyEvery: renotify,
		Now:           time.Now,
		marks:         make(map[string]secretMark),
	}
}

// Scan classifies every scheduled secret and refreshes the lifecycle gauges.
// It returns ALL currently-due findings (the report view); apply
// FilterForNotify for the storm-filtered notification subset.
func (s *SecretLifecycleScanner) Scan(_ context.Context) ([]SecretItem, error) {
	secrets, err := s.store.ListStoredSecretsWithSchedule()
	if err != nil {
		return nil, fmt.Errorf("monitor: listing scheduled secrets: %w", err)
	}
	items := ClassifySecrets(secrets, s.warningDays, s.criticalDays, s.Now().UTC())
	counts := map[SecretState]int{}
	for _, it := range items {
		counts[it.State]++
	}
	for _, st := range []SecretState{SecretStateExpiring, SecretStateExpired, SecretStateRotationDue} {
		metrics.SecretsLifecycleDue.Set(float64(counts[st]), string(st))
	}
	return items, nil
}

// FilterForNotify applies storm prevention: a finding is passed through when
// it is new, when its severity escalated, when the secret's value version
// changed while still due, or when the re-notify interval elapsed since the
// last notification — otherwise it is suppressed this tick. Marks for
// findings that cleared (rotated, extended, deleted) are dropped, so a later
// recurrence notifies immediately.
func (s *SecretLifecycleScanner) FilterForNotify(items []SecretItem) []SecretItem {
	now := s.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	current := make(map[string]bool, len(items))
	var due []SecretItem
	for _, it := range items {
		key := it.conditionKey()
		current[key] = true
		mark, seen := s.marks[key]
		escalated := seen && severityRank[it.Severity] > severityRank[mark.severity]
		versionChanged := seen && it.CurrentVersion != mark.version
		if !seen || escalated || versionChanged || now.Sub(mark.notifiedAt) >= s.renotifyEvery {
			s.marks[key] = secretMark{severity: it.Severity, version: it.CurrentVersion, notifiedAt: now}
			due = append(due, it)
			metrics.SecretLifecycleNotifications.Inc(string(it.State))
		}
	}
	for key := range s.marks {
		if !current[key] {
			delete(s.marks, key)
		}
	}
	return due
}
