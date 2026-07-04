package mailtransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
)

// IMAPConfig configures the inbound IMAP poller that reads challenge replies.
type IMAPConfig struct {
	// Host and Port are the IMAP server endpoint.
	Host string
	Port int
	// Username / Password authenticate with the mailbox.
	Username string
	Password string
	// Mailbox is the folder polled for replies (default "INBOX").
	Mailbox string
	// TLSMode selects transport security: "implicit" (default — IMAPS, TLS from
	// the first byte), "starttls" (upgrade the plaintext connection), or "none"
	// (no TLS; test/loopback only).
	TLSMode string
	// InsecureSkipVerify disables server-certificate verification (test only).
	InsecureSkipVerify bool
	// Timeout bounds each poll/ack round trip (default imapDefaultTimeout).
	Timeout time.Duration
	// MaxMessages caps how many messages a single Fetch pulls (default
	// imapDefaultMaxMessages), bounding work per poll cycle.
	MaxMessages int
}

const (
	imapDefaultTimeout     = 30 * time.Second
	imapDefaultMaxMessages = 64
)

// IMAPInbox reads challenge replies over IMAP4rev1. It implements acme.MailInbox
// with a minimal, dependency-free client: it LOGINs, SELECTs the mailbox, and
// UID SEARCH/FETCHes the unseen messages; Ack marks them \Seen so a later Fetch
// does not return them again. A fresh connection is used per call, which is
// ample for the poll cadence and keeps the client stateless.
type IMAPInbox struct {
	cfg IMAPConfig
}

// NewIMAPInbox validates the configuration and returns an inbox poller.
func NewIMAPInbox(cfg IMAPConfig) (*IMAPInbox, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("imap: host is required")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("imap: username is required")
	}
	if cfg.Port == 0 {
		if strings.EqualFold(cfg.TLSMode, "starttls") || strings.EqualFold(cfg.TLSMode, "none") {
			cfg.Port = 143
		} else {
			cfg.Port = 993
		}
	}
	if strings.TrimSpace(cfg.Mailbox) == "" {
		cfg.Mailbox = "INBOX"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = imapDefaultTimeout
	}
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = imapDefaultMaxMessages
	}
	return &IMAPInbox{cfg: cfg}, nil
}

// Fetch returns the unseen messages in the mailbox as raw RFC 5322 bytes, each
// keyed by its IMAP UID so Ack can mark it processed.
func (b *IMAPInbox) Fetch(ctx context.Context) ([]acme.InboundMail, error) {
	c, err := b.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer c.close()

	if err := c.selectMailbox(b.cfg.Mailbox); err != nil {
		return nil, err
	}
	uids, err := c.searchUnseen()
	if err != nil {
		return nil, err
	}
	if len(uids) > b.cfg.MaxMessages {
		uids = uids[:b.cfg.MaxMessages]
	}
	out := make([]acme.InboundMail, 0, len(uids))
	for _, uid := range uids {
		raw, err := c.fetchBody(uid)
		if err != nil {
			return out, err
		}
		out = append(out, acme.InboundMail{ID: uid, Raw: raw})
	}
	return out, nil
}

// Ack marks the given UIDs \Seen so a subsequent Fetch (UNSEEN) skips them.
func (b *IMAPInbox) Ack(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	c, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer c.close()
	if err := c.selectMailbox(b.cfg.Mailbox); err != nil {
		return err
	}
	return c.storeSeen(ids)
}

// connect dials the IMAP server, applies TLS per the configured mode, and reads
// the greeting and (if needed) STARTTLS-upgrades before logging in.
func (b *IMAPInbox) connect(ctx context.Context) (*imapConn, error) {
	addr := net.JoinHostPort(b.cfg.Host, fmt.Sprintf("%d", b.cfg.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("imap: dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(b.cfg.Timeout))
	}
	tlsCfg := &tls.Config{ServerName: b.cfg.Host, InsecureSkipVerify: b.cfg.InsecureSkipVerify} //nolint:gosec // opt-in for test/loopback only
	if !strings.EqualFold(b.cfg.TLSMode, "starttls") && !strings.EqualFold(b.cfg.TLSMode, "none") {
		conn = tls.Client(conn, tlsCfg)
	}
	c := newIMAPConn(conn)
	if err := c.greeting(); err != nil {
		c.close()
		return nil, err
	}
	if strings.EqualFold(b.cfg.TLSMode, "starttls") {
		if err := c.starttls(tlsCfg); err != nil {
			c.close()
			return nil, err
		}
	}
	if err := c.login(b.cfg.Username, b.cfg.Password); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// imapConn is a minimal IMAP4rev1 protocol connection.
type imapConn struct {
	conn net.Conn
	r    *bufio.Reader
	tag  int
}

func newIMAPConn(conn net.Conn) *imapConn {
	return &imapConn{conn: conn, r: bufio.NewReader(conn)}
}

func (c *imapConn) close() { _ = c.conn.Close() }

// nextTag returns a unique command tag.
func (c *imapConn) nextTag() string {
	c.tag++
	return "a" + strconv.Itoa(c.tag)
}

// readLine reads one CRLF-terminated protocol line with the terminator stripped.
func (c *imapConn) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// send writes a tagged command line.
func (c *imapConn) send(line string) error {
	_, err := io.WriteString(c.conn, line+"\r\n")
	return err
}

// greeting consumes the server's initial untagged greeting.
func (c *imapConn) greeting() error {
	line, err := c.readLine()
	if err != nil {
		return fmt.Errorf("imap: reading greeting: %w", err)
	}
	if !strings.HasPrefix(line, "* OK") && !strings.HasPrefix(line, "* PREAUTH") {
		return fmt.Errorf("imap: unexpected greeting: %q", line)
	}
	return nil
}

// simpleCommand issues a tagged command and reads (discarding) untagged
// responses — handling any literals — until the tagged completion line, which it
// requires to be OK.
func (c *imapConn) simpleCommand(cmd string) error {
	tag := c.nextTag()
	if err := c.send(tag + " " + cmd); err != nil {
		return err
	}
	_, err := c.readResponse(tag, nil)
	return err
}

func (c *imapConn) starttls(tlsCfg *tls.Config) error {
	if err := c.simpleCommand("STARTTLS"); err != nil {
		return fmt.Errorf("imap: STARTTLS: %w", err)
	}
	tconn := tls.Client(c.conn, tlsCfg)
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("imap: TLS handshake: %w", err)
	}
	c.conn = tconn
	c.r = bufio.NewReader(tconn)
	return nil
}

func (c *imapConn) login(user, pass string) error {
	if err := c.simpleCommand("LOGIN " + quoteIMAP(user) + " " + quoteIMAP(pass)); err != nil {
		return fmt.Errorf("imap: LOGIN: %w", err)
	}
	return nil
}

func (c *imapConn) selectMailbox(mailbox string) error {
	if err := c.simpleCommand("SELECT " + quoteIMAP(mailbox)); err != nil {
		return fmt.Errorf("imap: SELECT %q: %w", mailbox, err)
	}
	return nil
}

// searchUnseen returns the UIDs of unseen messages.
func (c *imapConn) searchUnseen() ([]string, error) {
	tag := c.nextTag()
	if err := c.send(tag + " UID SEARCH UNSEEN"); err != nil {
		return nil, err
	}
	var uids []string
	handler := func(line string) {
		// "* SEARCH 12 34 56" (UID SEARCH returns UIDs in the same shape).
		if rest, ok := strings.CutPrefix(line, "* SEARCH"); ok {
			for _, f := range strings.Fields(rest) {
				if _, err := strconv.Atoi(f); err == nil {
					uids = append(uids, f)
				}
			}
		}
	}
	if _, err := c.readResponse(tag, handler); err != nil {
		return nil, fmt.Errorf("imap: UID SEARCH: %w", err)
	}
	return uids, nil
}

// fetchBody fetches the full RFC 5322 message for a UID via BODY.PEEK[] (which
// does not set \Seen, so Ack controls that explicitly).
func (c *imapConn) fetchBody(uid string) ([]byte, error) {
	tag := c.nextTag()
	if err := c.send(tag + " UID FETCH " + uid + " (BODY.PEEK[])"); err != nil {
		return nil, err
	}
	var body []byte
	handler := func(line string) {}
	literal := func(b []byte) {
		// The message is the largest literal in the FETCH response (the only one
		// for a BODY.PEEK[] fetch).
		if len(b) > len(body) {
			body = b
		}
	}
	if _, err := c.readResponseLit(tag, handler, literal); err != nil {
		return nil, fmt.Errorf("imap: UID FETCH %s: %w", uid, err)
	}
	if body == nil {
		return nil, fmt.Errorf("imap: UID FETCH %s: no message body returned", uid)
	}
	return body, nil
}

// storeSeen adds the \Seen flag to the given UIDs.
func (c *imapConn) storeSeen(uids []string) error {
	set := strings.Join(uids, ",")
	if err := c.simpleCommand("UID STORE " + set + " +FLAGS.SILENT (\\Seen)"); err != nil {
		return fmt.Errorf("imap: UID STORE: %w", err)
	}
	return nil
}

// readResponse reads untagged responses (handling literals by discarding them)
// until the tagged completion line for tag, invoking onLine for each untagged
// line. It returns the tagged line and an error if the completion is not OK.
func (c *imapConn) readResponse(tag string, onLine func(string)) (string, error) {
	return c.readResponseLit(tag, onLine, nil)
}

// readResponseLit is readResponse plus a literal callback: when an untagged line
// announces a literal ({n}), the n bytes are read and passed to onLiteral (or
// discarded if nil), then response reading continues.
func (c *imapConn) readResponseLit(tag string, onLine func(string), onLiteral func([]byte)) (string, error) {
	for {
		line, err := c.readLine()
		if err != nil {
			return "", err
		}
		// A tagged completion line begins with the command tag.
		if strings.HasPrefix(line, tag+" ") {
			status := strings.TrimSpace(strings.TrimPrefix(line, tag+" "))
			if !strings.HasPrefix(status, "OK") {
				return line, fmt.Errorf("command failed: %s", status)
			}
			return line, nil
		}
		// A line ending in {n} announces an n-byte literal that follows inline.
		if n, ok := literalSize(line); ok {
			buf := make([]byte, n)
			if _, err := io.ReadFull(c.r, buf); err != nil {
				return "", fmt.Errorf("reading %d-byte literal: %w", n, err)
			}
			if onLiteral != nil {
				onLiteral(buf)
			}
			// The literal is not newline-terminated; the rest of the untagged
			// response continues on subsequent lines, which the loop keeps reading.
			continue
		}
		if onLine != nil {
			onLine(line)
		}
	}
}

// literalSize reports the byte count of an IMAP literal announced at the end of a
// line as "{n}".
func literalSize(line string) (int, bool) {
	i := strings.LastIndexByte(line, '{')
	if i < 0 || !strings.HasSuffix(line, "}") {
		return 0, false
	}
	n, err := strconv.Atoi(line[i+1 : len(line)-1])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// quoteIMAP wraps a string as an IMAP quoted-string, escaping backslashes and
// double quotes (RFC 3501 §4.3).
func quoteIMAP(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
