package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
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
	if len(n.Warnings) == 0 && len(n.Renewed) == 0 {
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
