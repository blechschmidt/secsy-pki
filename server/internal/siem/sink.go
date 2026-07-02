package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// Sink is a transport that delivers a batch of formatted audit events to a
// downstream SIEM. Deliver must be all-or-nothing from the caller's point of
// view: it returns nil only if the whole batch was handed to the transport
// (written to the socket / accepted by the endpoint). On any error the exporter
// does not advance its cursor and retries the same batch, giving at-least-once
// delivery.
//
// Implementations need not be safe for concurrent Deliver calls: the exporter
// runs one worker goroutine per sink and serializes delivery on it.
type Sink interface {
	// Name uniquely identifies the sink; it keys the durable cursor and metrics,
	// so it must be stable across restarts and unique among configured sinks.
	Name() string
	// Deliver sends every event in order using formatter. It returns an error if
	// the batch was not fully accepted by the transport.
	Deliver(ctx context.Context, events []audit.Event, formatter Formatter) error
	// Close releases any transport resources (open sockets).
	Close() error
}

// --- syslog sink (RFC 5424 over TCP or TLS) ----------------------------------

// SyslogFraming selects how individual syslog messages are delimited on a stream
// transport (RFC 6587).
type SyslogFraming string

const (
	// FramingOctetCounting prefixes each message with its byte length and a space
	// (RFC 6587 §3.4.1). It is unambiguous even when a message contains newlines
	// and is the recommended framing for reliable TCP/TLS transport.
	FramingOctetCounting SyslogFraming = "octet-counting"
	// FramingLF terminates each message with a trailing LF (non-transparent
	// framing, RFC 6587 §3.4.2). Required by some collectors; only safe when
	// messages never contain embedded newlines (our formatters guarantee this).
	FramingLF SyslogFraming = "lf"
)

// SyslogSinkConfig configures a streaming syslog sink.
type SyslogSinkConfig struct {
	SinkName string
	// Network is "tcp" (cleartext) or "tls".
	Network string
	// Address is host:port of the collector.
	Address string
	// Framing selects octet-counting (default) or LF framing.
	Framing SyslogFraming
	// Timeout bounds each dial and each write. Default 10s.
	Timeout time.Duration
	// TLS holds the TLS settings used when Network is "tls".
	TLS SyslogTLSConfig
}

// SyslogTLSConfig configures TLS for a syslog sink.
type SyslogTLSConfig struct {
	// CAFile is a PEM bundle used to verify the collector. Empty uses the system
	// roots.
	CAFile string
	// ServerName overrides the SNI / verification name (defaults to the dial host).
	ServerName string
	// ClientCertFile / ClientKeyFile enable mutual TLS. Both or neither.
	ClientCertFile string
	ClientKeyFile  string
	// InsecureSkipVerify disables certificate verification. For test/lab use only;
	// the exporter logs a warning when it is set.
	InsecureSkipVerify bool
}

// SyslogSink delivers events as syslog messages over a persistent stream
// connection, reconnecting on failure. It is used by a single worker goroutine.
type SyslogSink struct {
	cfg       SyslogSinkConfig
	tlsConfig *tls.Config // non-nil only for TLS

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogSink builds a syslog sink from cfg. For a TLS sink it eagerly loads
// the certificate material so a misconfiguration fails at startup, not at first
// delivery.
func NewSyslogSink(cfg SyslogSinkConfig) (*SyslogSink, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("syslog sink %q: address is required", cfg.SinkName)
	}
	if cfg.Framing == "" {
		cfg.Framing = FramingOctetCounting
	}
	if cfg.Framing != FramingOctetCounting && cfg.Framing != FramingLF {
		return nil, fmt.Errorf("syslog sink %q: unknown framing %q (valid: octet-counting, lf)", cfg.SinkName, cfg.Framing)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	s := &SyslogSink{cfg: cfg}

	switch cfg.Network {
	case "tcp":
		// cleartext
	case "tls":
		tc, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tc
	default:
		return nil, fmt.Errorf("syslog sink %q: unknown network %q (valid: tcp, tls)", cfg.SinkName, cfg.Network)
	}
	return s, nil
}

func buildTLSConfig(cfg SyslogSinkConfig) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         cfg.TLS.ServerName,
		InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
	}
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(cfg.Address); err == nil {
			tc.ServerName = host
		}
	}
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("syslog sink %q: reading ca_file: %w", cfg.SinkName, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("syslog sink %q: ca_file contains no valid certificates", cfg.SinkName)
		}
		tc.RootCAs = pool
	}
	if cfg.TLS.ClientCertFile != "" || cfg.TLS.ClientKeyFile != "" {
		if cfg.TLS.ClientCertFile == "" || cfg.TLS.ClientKeyFile == "" {
			return nil, fmt.Errorf("syslog sink %q: client_cert_file and client_key_file must both be set for mutual TLS", cfg.SinkName)
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCertFile, cfg.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("syslog sink %q: loading client certificate: %w", cfg.SinkName, err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

func (s *SyslogSink) Name() string { return s.cfg.SinkName }

// connect dials (or redials) the collector. The caller holds s.mu.
func (s *SyslogSink) connect(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	var (
		conn net.Conn
		err  error
	)
	if s.tlsConfig != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", s.cfg.Address, s.tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", s.cfg.Address)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", s.cfg.Address, err)
	}
	s.conn = conn
	return nil
}

// dropConn closes and forgets the current connection so the next Deliver
// redials. The caller holds s.mu.
func (s *SyslogSink) dropConn() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *SyslogSink) Deliver(ctx context.Context, events []audit.Event, formatter Formatter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.connect(ctx); err != nil {
		return err
	}

	// Build the whole batch into one buffer so a partial socket write (which we
	// treat as a failed batch and retry) cannot split a message.
	var buf bytes.Buffer
	for i := range events {
		msg := formatter.Format(events[i])
		switch s.cfg.Framing {
		case FramingOctetCounting:
			buf.WriteString(strconv.Itoa(len(msg)))
			buf.WriteByte(' ')
			buf.Write(msg)
		default: // FramingLF
			buf.Write(msg)
			buf.WriteByte('\n')
		}
	}

	if dl, ok := ctx.Deadline(); ok {
		s.conn.SetWriteDeadline(dl)
	} else {
		s.conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	}
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		// A broken pipe means the collector dropped the connection; discard it so
		// the retry redials, and report the failure so the cursor does not advance.
		s.dropConn()
		return fmt.Errorf("writing to %s: %w", s.cfg.Address, err)
	}
	return nil
}

func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropConn()
	return nil
}

// --- webhook sink (newline-delimited JSON) -----------------------------------

// WebhookSinkConfig configures an NDJSON-over-HTTP sink.
type WebhookSinkConfig struct {
	SinkName string
	URL      string
	// Headers are extra HTTP headers on each POST (e.g. an Authorization token).
	Headers map[string]string
	// Timeout bounds each POST. Default 15s.
	Timeout time.Duration
	// Client, if set, overrides the HTTP client (tests inject a stub transport).
	Client *http.Client
}

// WebhookSink POSTs each batch as an application/x-ndjson body: one formatted
// record per line. It is intended for HTTP log-ingestion endpoints (Splunk HEC
// raw, Elastic, Loki, generic collectors). Delivery is acknowledged only on a
// 2xx response.
type WebhookSink struct {
	cfg    WebhookSinkConfig
	client *http.Client
}

// NewWebhookSink builds a webhook sink.
func NewWebhookSink(cfg WebhookSinkConfig) (*WebhookSink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook sink %q: url is required", cfg.SinkName)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &WebhookSink{cfg: cfg, client: client}, nil
}

func (s *WebhookSink) Name() string { return s.cfg.SinkName }

func (s *WebhookSink) Deliver(ctx context.Context, events []audit.Event, formatter Formatter) error {
	var buf bytes.Buffer
	for i := range events {
		buf.Write(formatter.Format(events[i]))
		buf.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, &buf)
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	// application/x-ndjson is the de facto content type for newline-delimited JSON.
	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to webhook %s: %w", s.cfg.URL, err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused by keep-alive.
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s returned status %d", s.cfg.URL, resp.StatusCode)
	}
	return nil
}

func (s *WebhookSink) Close() error { return nil }
