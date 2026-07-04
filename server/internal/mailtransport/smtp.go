// Package mailtransport provides the concrete outbound (SMTP) and inbound (IMAP)
// mail transports backing the ACME RFC 8823 email-reply-00 challenge
// (internal/acme). The acme package defines the MailSender / MailInbox
// interfaces and message DTOs; this package implements them over the standard
// library so the challenge can dispatch signed challenge emails and read the
// mailbox owner's replies. Both transports are constructed in cmd/server and
// injected into acme.Config; the acme tests use an in-memory fake instead, so
// this package is never in the hermetic test path.
package mailtransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
)

// SMTPConfig configures the outbound SMTP sink.
type SMTPConfig struct {
	// Host and Port are the SMTP server endpoint.
	Host string
	Port int
	// Username / Password enable SMTP AUTH (PLAIN over TLS) when set.
	Username string
	Password string
	// TLSMode selects transport security: "starttls" (default — upgrade the
	// plaintext connection), "implicit" (TLS from the first byte, i.e. SMTPS), or
	// "none" (no TLS; test/loopback only).
	TLSMode string
	// InsecureSkipVerify disables server-certificate verification (test only).
	InsecureSkipVerify bool
	// Timeout bounds the whole send (default smtpDefaultTimeout).
	Timeout time.Duration
}

const smtpDefaultTimeout = 30 * time.Second

// SMTPSender sends challenge emails over SMTP. It implements acme.MailSender.
type SMTPSender struct {
	cfg SMTPConfig
}

// NewSMTPSender validates the configuration and returns a sender.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("smtp: host is required")
	}
	if cfg.Port == 0 {
		if strings.EqualFold(cfg.TLSMode, "implicit") {
			cfg.Port = 465
		} else {
			cfg.Port = 587
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = smtpDefaultTimeout
	}
	return &SMTPSender{cfg: cfg}, nil
}

// Send transmits one rendered challenge email. The envelope uses msg.From /
// msg.To and the DATA is msg.Raw verbatim, preserving any DKIM signature.
func (s *SMTPSender) Send(ctx context.Context, msg acme.OutboundMail) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprintf("%d", s.cfg.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	tlsCfg := &tls.Config{ServerName: s.cfg.Host, InsecureSkipVerify: s.cfg.InsecureSkipVerify} //nolint:gosec // opt-in for test/loopback only
	if strings.EqualFold(s.cfg.TLSMode, "implicit") {
		conn = tls.Client(conn, tlsCfg)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Hello(heloName(msg.From)); err != nil {
		return fmt.Errorf("smtp: EHLO: %w", err)
	}
	if !strings.EqualFold(s.cfg.TLSMode, "implicit") && !strings.EqualFold(s.cfg.TLSMode, "none") {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp: STARTTLS: %w", err)
			}
		} else if !s.cfg.InsecureSkipVerify {
			return fmt.Errorf("smtp: server does not offer STARTTLS and TLS is required")
		}
	}
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp: AUTH: %w", err)
		}
	}

	if err := client.Mail(msg.From); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(msg.Raw); err != nil {
		return fmt.Errorf("smtp: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: completing message: %w", err)
	}
	return client.Quit()
}

// heloName derives a syntactically-valid EHLO argument from the sender domain.
func heloName(from string) string {
	if i := strings.LastIndexByte(from, '@'); i >= 0 && i < len(from)-1 {
		return from[i+1:]
	}
	return "localhost"
}
