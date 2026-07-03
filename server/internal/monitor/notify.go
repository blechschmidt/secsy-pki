package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// Sink receives expiry notifications. Implementations are expected to be safe
// for sequential use by the Runner; a slow or failing sink must not block or
// abort the others.
type Sink interface {
	// Name identifies the sink in logs.
	Name() string
	// Notify delivers a notification. Returning an error is logged by the caller
	// but never aborts the scan or other sinks.
	Notify(ctx context.Context, n Notification) error
}

// Notification is the payload delivered to a sink: the certificates at or above
// the sink's minimum severity, plus scan-level context.
type Notification struct {
	GeneratedAt time.Time  `json:"generated_at"`
	MinSeverity Severity   `json:"min_severity"`
	Warnings    []CertItem `json:"warnings"`
	// Renewed lists certificates auto-renewed during the scan (may be empty).
	Renewed []CertItem `json:"renewed,omitempty"`
	// Counts mirrors Report.Counts for at-a-glance totals.
	Counts map[Severity]int `json:"counts"`
	// CanaryFailures lists failed synthetic issuance-canary probes (Task 71).
	// They are delivered through the same sinks as expiry warnings and are set
	// only on canary-originated notifications (never on expiry-scan ones).
	CanaryFailures []CanaryFailure `json:"canary_failures,omitempty"`
	// SecretWarnings lists stored secrets due for TTL/rotation attention
	// (Task 73), already storm-filtered. Set only on secret-lifecycle
	// notifications.
	SecretWarnings []SecretItem `json:"secret_warnings,omitempty"`
}

// CanaryFailure describes one failed synthetic issuance-canary probe for
// notification sinks: which CA's issuance path broke, at which probe stage,
// and why. A canary failure means real issuance is (or is about to be) broken,
// so it is treated as critical severity for sink filtering.
type CanaryFailure struct {
	CAID    string    `json:"ca_id"`
	CALabel string    `json:"ca_label"`
	Stage   string    `json:"stage"`
	Serial  string    `json:"serial,omitempty"` // empty when issuance itself failed
	Error   string    `json:"error"`
	At      time.Time `json:"at"`
}

// LogSink writes a concise summary of each notification to a logger. It is the
// default sink and always available.
type LogSink struct {
	logger *log.Logger
}

// NewLogSink builds a LogSink. A nil logger uses the standard logger.
func NewLogSink(logger *log.Logger) *LogSink {
	if logger == nil {
		logger = log.Default()
	}
	return &LogSink{logger: logger}
}

func (s *LogSink) Name() string { return "log" }

func (s *LogSink) Notify(_ context.Context, n Notification) error {
	if len(n.Warnings) == 0 && len(n.Renewed) == 0 && len(n.CanaryFailures) == 0 && len(n.SecretWarnings) == 0 {
		return nil
	}
	for _, f := range n.CanaryFailures {
		s.logger.Printf("issuance-canary: FAILURE ca=%s (%s) stage=%s serial=%s error=%s",
			f.CALabel, f.CAID, f.Stage, f.Serial, f.Error)
	}
	for _, w := range n.SecretWarnings {
		s.logger.Printf("secret-lifecycle: [%s] %s tenant=%s name=%q id=%s version=%d: %s",
			w.Severity, w.State, w.TenantID, w.Name, w.ID, w.CurrentVersion, w.Detail)
	}
	if len(n.Warnings) == 0 && len(n.Renewed) == 0 {
		return nil
	}
	s.logger.Printf("cert-expiry: %d certificate(s) at/above %s (warning=%d critical=%d expired=%d), %d renewed",
		len(n.Warnings), n.MinSeverity,
		n.Counts[SeverityWarning], n.Counts[SeverityCritical], n.Counts[SeverityExpired],
		len(n.Renewed))
	for _, w := range n.Warnings {
		s.logger.Printf("cert-expiry: [%s] serial=%s cn=%q ca=%s profile=%s expires_in=%s (%s)",
			w.Severity, w.Serial, w.CommonName, w.CALabel, w.Profile, w.ExpiresIn, w.NotAfter.Format(time.RFC3339))
	}
	for _, r := range n.Renewed {
		s.logger.Printf("cert-expiry: renewed serial=%s -> %s cn=%q ca=%s",
			r.Serial, r.NewSerial, r.CommonName, r.CALabel)
	}
	return nil
}

// WebhookSink POSTs the notification as JSON to a configured URL. It is intended
// for chat/alerting integrations and generic ingestion endpoints.
type WebhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhookSink builds a WebhookSink. A zero timeout defaults to 10s.
func NewWebhookSink(url string, headers map[string]string, timeout time.Duration) *WebhookSink {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WebhookSink{
		url:     url,
		headers: headers,
		client:  &http.Client{Timeout: timeout},
	}
}

func (s *WebhookSink) Name() string { return "webhook(" + s.url + ")" }

func (s *WebhookSink) Notify(ctx context.Context, n Notification) error {
	if len(n.Warnings) == 0 && len(n.Renewed) == 0 && len(n.CanaryFailures) == 0 && len(n.SecretWarnings) == 0 {
		return nil // nothing to report; don't spam the endpoint
	}
	body, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("marshaling notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// sinkBinding pairs a sink with the minimum severity it wants to receive.
type sinkBinding struct {
	sink        Sink
	minSeverity Severity
}

// Notifier delivers ad-hoc notifications (currently: issuance-canary probe
// failures) through the monitor's configured notification sinks, independent
// of an expiry scan. It lets other subsystems reuse the operator's existing
// log/webhook alerting channels without duplicating sink configuration.
type Notifier struct {
	bindings []sinkBinding
	logger   *log.Logger
}

// NewNotifier resolves the monitor config's notification sinks into a
// Notifier. Like the Runner, it always has at least a log sink, so failures
// are never silently dropped — even when monitor.notifications is empty or
// the expiry monitor itself is disabled.
func NewNotifier(cfg config.MonitorConfig, logger *log.Logger) (*Notifier, error) {
	if logger == nil {
		logger = log.Default()
	}
	bindings, err := buildSinks(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &Notifier{bindings: bindings, logger: logger}, nil
}

// NotifyCanaryFailures delivers canary probe failures to every sink whose
// minimum severity is at or below critical (a broken issuance path is always
// at least critical; sinks filtering for "expired" only are skipped). Sink
// errors are logged and do not abort delivery to the others.
func (n *Notifier) NotifyCanaryFailures(ctx context.Context, failures []CanaryFailure) {
	if len(failures) == 0 {
		return
	}
	payload := Notification{
		GeneratedAt:    time.Now(),
		MinSeverity:    SeverityCritical,
		Counts:         map[Severity]int{},
		CanaryFailures: failures,
	}
	for _, b := range n.bindings {
		if !SeverityCritical.atLeast(b.minSeverity) {
			continue
		}
		if err := b.sink.Notify(ctx, payload); err != nil {
			n.logger.Printf("canary: notification sink %s failed: %v", b.sink.Name(), err)
		}
	}
}

// Dispatch delivers a report to every sink, filtered by each sink's minimum
// severity. Sink errors are logged and do not abort the others. It is a no-op
// when there are no bindings.
func (m *Monitor) Dispatch(ctx context.Context, report *Report, bindings []sinkBinding) {
	for _, b := range bindings {
		warnings := report.Warnings(b.minSeverity)
		var renewed []CertItem
		for _, it := range report.Items {
			if it.Renewed {
				renewed = append(renewed, it)
			}
		}
		n := Notification{
			GeneratedAt: report.GeneratedAt,
			MinSeverity: b.minSeverity,
			Warnings:    warnings,
			Renewed:     renewed,
			Counts:      report.Counts,
		}
		if err := b.sink.Notify(ctx, n); err != nil {
			m.logger.Printf("monitor: notification sink %s failed: %v", b.sink.Name(), err)
		}
	}
}
