package siem

import (
	"fmt"
	"time"
)

// SinkSpec is a transport-neutral description of one export sink, decoupled from
// the YAML config types so the siem package does not depend on internal/config.
// The server and CLI translate their config into these specs.
type SinkSpec struct {
	// Name uniquely identifies the sink; it keys the durable cursor and metrics.
	Name string
	// Type is "syslog" or "webhook".
	Type string
	// Format is "rfc5424", "cef", or "json".
	Format Format

	// Syslog transport (Type == "syslog").
	Network string        // "tcp" or "tls"
	Address string        // host:port
	Framing SyslogFraming // "octet-counting" (default) or "lf"
	TLS     SyslogTLSConfig

	// Webhook transport (Type == "webhook").
	URL     string
	Headers map[string]string

	// Timeout bounds each delivery attempt (dial+write, or one HTTP POST).
	Timeout time.Duration

	// Formatter metadata (host/product identity, enterprise number, CEF headers).
	Formatter FormatterOptions
}

// BuildSinks constructs the bound sinks for specs, validating each and rejecting
// duplicate names (which would make two sinks share a cursor). It returns the
// bound sinks ready for NewExporter.
func BuildSinks(specs []SinkSpec) ([]boundSink, error) {
	seen := make(map[string]bool, len(specs))
	bound := make([]boundSink, 0, len(specs))
	for i, spec := range specs {
		if spec.Name == "" {
			return nil, fmt.Errorf("audit export sink[%d]: name is required", i)
		}
		if seen[spec.Name] {
			return nil, fmt.Errorf("audit export sink[%d]: duplicate sink name %q", i, spec.Name)
		}
		seen[spec.Name] = true

		formatter, err := NewFormatter(spec.Format, spec.Formatter)
		if err != nil {
			return nil, fmt.Errorf("audit export sink %q: %w", spec.Name, err)
		}

		var sink Sink
		switch spec.Type {
		case "syslog":
			s, err := NewSyslogSink(SyslogSinkConfig{
				SinkName: spec.Name,
				Network:  spec.Network,
				Address:  spec.Address,
				Framing:  spec.Framing,
				Timeout:  spec.Timeout,
				TLS:      spec.TLS,
			})
			if err != nil {
				return nil, err
			}
			sink = s
		case "webhook":
			s, err := NewWebhookSink(WebhookSinkConfig{
				SinkName: spec.Name,
				URL:      spec.URL,
				Headers:  spec.Headers,
				Timeout:  spec.Timeout,
			})
			if err != nil {
				return nil, err
			}
			sink = s
		default:
			return nil, fmt.Errorf("audit export sink %q: unknown type %q (valid: syslog, webhook)", spec.Name, spec.Type)
		}
		bound = append(bound, BindSink(sink, formatter))
	}
	return bound, nil
}
