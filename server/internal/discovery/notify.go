package discovery

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// boundSink pairs one of the expiry monitor's notification sinks with the minimum
// severity it wants to receive. Discovery reuses the monitor's Sink implementations
// (log/webhook) and its Notification payload so operators get discovery alerts
// through the exact same channels they already configured for expiry warnings.
type boundSink struct {
	sink        monitor.Sink
	minSeverity string
}

// bindSinks resolves each configured sink's minimum severity so dispatch can
// filter findings per sink, mirroring the monitor's sinkBinding.
func bindSinks(cfg config.MonitorConfig, logger *log.Logger) []boundSink {
	if logger == nil {
		logger = log.Default()
	}
	if len(cfg.Notifications) == 0 {
		return []boundSink{{sink: monitor.NewLogSink(logger), minSeverity: SeverityWarning}}
	}
	var bound []boundSink
	for _, n := range cfg.Notifications {
		var sink monitor.Sink
		switch n.Type {
		case "log":
			sink = monitor.NewLogSink(logger)
		case "webhook":
			sink = monitor.NewWebhookSink(n.URL, n.Headers, time.Duration(n.TimeoutSeconds)*time.Second)
		default:
			continue
		}
		min := SeverityWarning
		if n.MinSeverity != "" {
			min = n.MinSeverity
		}
		bound = append(bound, boundSink{sink: sink, minSeverity: min})
	}
	return bound
}

// severityRank orders discovery severities for min-severity filtering.
var severityRank = map[string]int{SeverityOK: 0, SeverityWarning: 1, SeverityCritical: 2}

// Dispatch delivers a report's flagged findings to the expiry-monitor sinks
// configured in cfg, filtered by each sink's minimum severity. Findings are
// mapped onto the monitor's Notification/CertItem payload so an operator's
// existing log/webhook integrations receive discovery alerts unchanged. Sink
// errors are logged and never abort the others; it is a no-op when no findings
// reach a sink's threshold.
func Dispatch(ctx context.Context, cfg config.MonitorConfig, report *Report, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	for _, b := range bindSinks(cfg, logger) {
		items := findingsAsCertItems(report.Findings, b.minSeverity)
		if len(items) == 0 {
			continue
		}
		n := monitor.Notification{
			GeneratedAt: report.GeneratedAt,
			MinSeverity: monitor.Severity(b.minSeverity),
			Warnings:    items,
			Counts: map[monitor.Severity]int{
				monitor.SeverityWarning:  report.Counts.Warning,
				monitor.SeverityCritical: report.Counts.Critical,
			},
		}
		if err := b.sink.Notify(ctx, n); err != nil {
			logger.Printf("discovery: notification sink %s failed: %v", b.sink.Name(), err)
		}
	}
}

// findingsAsCertItems maps flagged findings at/above min severity onto the
// monitor's CertItem shape. The scanned endpoint stands in for the CA label so an
// operator can see where the certificate is served, and every raised flag is
// appended to the common name so it is visible in a plain webhook payload.
func findingsAsCertItems(findings []Finding, min string) []monitor.CertItem {
	var items []monitor.CertItem
	for _, f := range findings {
		if !f.Reachable {
			continue
		}
		if severityRank[f.Severity] < severityRank[min] {
			continue
		}
		remaining := f.ExpiresInDays * 24 * 3600
		items = append(items, monitor.CertItem{
			CALabel:          f.Endpoint,
			Serial:           f.Serial,
			CommonName:       f.CommonName,
			Subject:          f.Subject,
			Profile:          "external-discovery",
			NotAfter:         f.NotAfter,
			ExpiresInSeconds: int64(remaining),
			ExpiresIn:        joinFlags(f.Flags),
			Severity:         monitor.Severity(f.Severity),
		})
	}
	return items
}
