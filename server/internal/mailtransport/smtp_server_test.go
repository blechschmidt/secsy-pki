package mailtransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
)

// This file drives SMTPSender against a scripted fake SMTP server on a loopback
// listener. Same rules as imap_server_test.go: hermetic, no sleeps, every
// "must not hang" case bounded by a short timeout plus a watchdog.

// smtpRecorder captures the bytes the client sent (all of them, and separately
// the ones that crossed the wire before any TLS upgrade) plus the decoded DATA
// payload.
type smtpRecorder struct {
	mu    sync.Mutex
	conns int
	wire  []byte
	plain []byte
	data  [][]byte
}

func (r *smtpRecorder) read(b []byte, encrypted bool) {
	r.mu.Lock()
	r.wire = append(r.wire, b...)
	if !encrypted {
		r.plain = append(r.plain, b...)
	}
	r.mu.Unlock()
}

func (r *smtpRecorder) addData(b []byte) {
	r.mu.Lock()
	r.data = append(r.data, append([]byte(nil), b...))
	r.mu.Unlock()
}

func (r *smtpRecorder) wireString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.wire)
}

func (r *smtpRecorder) plainString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.plain)
}

func (r *smtpRecorder) messages() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.data...)
}

func (r *smtpRecorder) connCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns
}

// teeReader records everything read from the connection so tests can assert on
// the exact wire bytes (dot-stuffing included), not just the decoded message.
type teeReader struct {
	r         io.Reader
	rec       *smtpRecorder
	encrypted bool
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.rec.read(p[:n], t.encrypted)
	}
	return n, err
}

// smtpScript describes the server side of one SMTP dialogue.
type smtpScript struct {
	// greeting is the 220 line; empty means the server sends nothing at all.
	greeting string
	// ehloExts are the extension keywords advertised in the EHLO response.
	ehloExts []string
	// implicitTLS makes the listener speak TLS from the first byte (SMTPS).
	implicitTLS *tls.Config
	// starttlsCfg is used to upgrade after a STARTTLS command.
	starttlsCfg *tls.Config
	// reject maps an upper-cased verb ("MAIL", "RCPT", "DATA", "EOD", "AUTH") to
	// the error reply to send instead of the success reply.
	reject map[string]string
	// stallAt is a verb the server reads and then never answers.
	stallAt string
	rec     *smtpRecorder
}

func startSMTPServer(t *testing.T, s *smtpScript) (string, int) {
	t.Helper()
	if s.rec == nil {
		s.rec = &smtpRecorder{}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	closed := make(chan struct{})
	t.Cleanup(func() {
		close(closed)
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.rec.mu.Lock()
			s.rec.conns++
			s.rec.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(watchdog))
				go func() {
					<-closed
					_ = conn.Close()
				}()
				s.serve(conn)
			}()
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, port
}

func (s *smtpScript) serve(conn net.Conn) {
	encrypted := false
	if s.implicitTLS != nil {
		tconn := tls.Server(conn, s.implicitTLS)
		if err := tconn.Handshake(); err != nil {
			return
		}
		conn = tconn
		encrypted = true
	}
	r := bufio.NewReader(&teeReader{r: conn, rec: s.rec, encrypted: encrypted})
	if s.greeting != "" {
		if _, err := io.WriteString(conn, s.greeting+"\r\n"); err != nil {
			return
		}
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		if i := strings.IndexByte(verb, ' '); i >= 0 {
			verb = verb[:i]
		}
		if verb == s.stallAt {
			// Read and never answer: the client must hit its own deadline. The next
			// read returns only when the client closes, so no goroutine is parked.
			continue
		}
		if reply, ok := s.reject[verb]; ok {
			if _, err := io.WriteString(conn, reply+"\r\n"); err != nil {
				return
			}
			continue
		}
		switch verb {
		case "EHLO", "HELO":
			if _, err := io.WriteString(conn, ehloReply("mail.test", s.ehloExts)); err != nil {
				return
			}
		case "STARTTLS":
			if s.starttlsCfg == nil {
				if _, err := io.WriteString(conn, "454 4.7.0 TLS not available\r\n"); err != nil {
					return
				}
				continue
			}
			if _, err := io.WriteString(conn, "220 2.0.0 Ready to start TLS\r\n"); err != nil {
				return
			}
			tconn := tls.Server(conn, s.starttlsCfg)
			if err := tconn.Handshake(); err != nil {
				return
			}
			conn = tconn
			encrypted = true
			r = bufio.NewReader(&teeReader{r: conn, rec: s.rec, encrypted: true})
		case "AUTH":
			if _, err := io.WriteString(conn, "235 2.7.0 Authentication successful\r\n"); err != nil {
				return
			}
		case "MAIL", "RCPT":
			if _, err := io.WriteString(conn, "250 2.1.0 OK\r\n"); err != nil {
				return
			}
		case "DATA":
			if _, err := io.WriteString(conn, "354 End data with <CR><LF>.<CR><LF>\r\n"); err != nil {
				return
			}
			body, derr := readDotData(r)
			if derr != nil {
				return
			}
			s.rec.addData(body)
			reply := "250 2.0.0 Queued\r\n"
			if r, ok := s.reject["EOD"]; ok {
				reply = r + "\r\n"
			}
			if _, err := io.WriteString(conn, reply); err != nil {
				return
			}
		case "QUIT":
			_, _ = io.WriteString(conn, "221 2.0.0 Bye\r\n")
			return
		case "RSET", "NOOP":
			if _, err := io.WriteString(conn, "250 2.0.0 OK\r\n"); err != nil {
				return
			}
		default:
			if _, err := io.WriteString(conn, "502 5.5.2 Command not implemented\r\n"); err != nil {
				return
			}
		}
	}
}

func ehloReply(name string, exts []string) string {
	var b strings.Builder
	if len(exts) == 0 {
		b.WriteString("250 " + name + "\r\n")
		return b.String()
	}
	b.WriteString("250-" + name + "\r\n")
	for i, e := range exts {
		if i == len(exts)-1 {
			b.WriteString("250 " + e + "\r\n")
		} else {
			b.WriteString("250-" + e + "\r\n")
		}
	}
	return b.String()
}

// readDotData reads an SMTP DATA payload, undoing dot-stuffing but preserving
// line endings byte for byte. net/textproto's DotReader rewrites CRLF to LF,
// which would mask a transport that mangles the DKIM-signed message.
func readDotData(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return out, err
		}
		if line == ".\r\n" || line == ".\n" {
			return out, nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		out = append(out, line...)
	}
}

func testOutbound() acme.OutboundMail {
	return acme.OutboundMail{
		From:      "acme@pki.example.com",
		To:        "alice@example.com",
		MessageID: "<mid@pki>",
		Subject:   "ACME: tok",
		Raw:       []byte(testMessage),
	}
}

// TestNewSMTPSenderValidationAndDefaults pins the constructor's validation and
// its port defaulting, which flips with the TLS mode.
func TestNewSMTPSenderValidationAndDefaults(t *testing.T) {
	cases := []struct {
		name        string
		in          SMTPConfig
		wantErr     string
		wantPort    int
		wantTimeout time.Duration
	}{
		{name: "host required", in: SMTPConfig{}, wantErr: "host is required"},
		{name: "blank host rejected", in: SMTPConfig{Host: " \t"}, wantErr: "host is required"},
		{name: "starttls default port", in: SMTPConfig{Host: "mail.example.com"}, wantPort: 587, wantTimeout: smtpDefaultTimeout},
		{name: "explicit starttls default port", in: SMTPConfig{Host: "h", TLSMode: "StartTLS"}, wantPort: 587, wantTimeout: smtpDefaultTimeout},
		{name: "implicit default port", in: SMTPConfig{Host: "h", TLSMode: "IMPLICIT"}, wantPort: 465, wantTimeout: smtpDefaultTimeout},
		{name: "none default port", in: SMTPConfig{Host: "h", TLSMode: "none"}, wantPort: 587, wantTimeout: smtpDefaultTimeout},
		{name: "explicit values preserved", in: SMTPConfig{Host: "h", Port: 2525, Timeout: time.Second}, wantPort: 2525, wantTimeout: time.Second},
		{name: "non-positive timeout defaulted", in: SMTPConfig{Host: "h", Port: 25, Timeout: -1}, wantPort: 25, wantTimeout: smtpDefaultTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewSMTPSender(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewSMTPSender = (%v, %v), want error containing %q", got, err, tc.wantErr)
				}
				if got != nil {
					t.Fatal("NewSMTPSender returned a sender alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			if got.cfg.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.cfg.Port, tc.wantPort)
			}
			if got.cfg.Timeout != tc.wantTimeout {
				t.Errorf("Timeout = %v, want %v", got.cfg.Timeout, tc.wantTimeout)
			}
		})
	}
}

// TestHeloName pins the EHLO argument derivation. An invalid EHLO name makes
// net/smtp refuse the command outright, so the edge cases matter.
func TestHeloName(t *testing.T) {
	cases := map[string]string{
		"acme@pki.example.com":  "pki.example.com",
		"acme@localhost":        "localhost",
		"no-at-sign":            "localhost",
		"":                      "localhost",
		"trailing@":             "localhost",
		"@leading":              "leading",
		"a@b@c.example":         "c.example",
		"acme+tag@sub.dom.test": "sub.dom.test",
	}
	for in, want := range cases {
		if got := heloName(in); got != want {
			t.Errorf("heloName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSMTPSendDialogue asserts the full plaintext dialogue and, crucially, that
// the DATA payload arrives byte-for-byte: the message is DKIM-signed upstream, so
// any rewriting (line endings, dot-stuffing, 8-bit content) invalidates it.
func TestSMTPSendDialogue(t *testing.T) {
	script := &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"SIZE 10485760", "AUTH PLAIN", "8BITMIME"}}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "none", Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	msg := testOutbound()
	if err := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), msg)
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := script.rec.messages()
	if len(got) != 1 {
		t.Fatalf("server queued %d messages, want 1", len(got))
	}
	if string(got[0]) != testMessage {
		t.Errorf("DATA payload mismatch:\n got %q\nwant %q", got[0], testMessage)
	}
	wire := script.rec.wireString()
	for _, want := range []string{
		"EHLO pki.example.com\r\n",
		"MAIL FROM:<acme@pki.example.com>",
		"RCPT TO:<alice@example.com>",
		"DATA\r\n",
		"QUIT\r\n",
		// Dot-stuffing must happen on the wire, or the body's "." line would end
		// the message early.
		"\r\n..\r\n",
		"\r\n..leading dot\r\n",
	} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire is missing %q; got:\n%s", want, wire)
		}
	}
	// AUTH PLAIN carries \x00user\x00pass base64-encoded.
	wantAuth := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00acme@pki.example.com\x00"+testPassword))
	if !strings.Contains(wire, wantAuth) {
		t.Errorf("wire is missing the expected AUTH PLAIN line %q", wantAuth)
	}
}

// TestSMTPRequiresSTARTTLSByDefault asserts the sender refuses to deliver in the
// clear when the server does not offer STARTTLS, and that it gives up before
// authenticating or handing over the message.
func TestSMTPRequiresSTARTTLSByDefault(t *testing.T) {
	for _, mode := range []string{"", "starttls"} {
		t.Run("mode="+mode, func(t *testing.T) {
			script := &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"SIZE 10485760"}}
			host, port := startSMTPServer(t, script)
			sender, err := NewSMTPSender(SMTPConfig{
				Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
				TLSMode: mode, Timeout: watchdog / 2,
			})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			serr := mustCompleteWithin(t, watchdog, func() error {
				return sender.Send(context.Background(), testOutbound())
			})
			if serr == nil {
				t.Fatal("Send delivered over an unencrypted connection, want a refusal")
			}
			if !strings.Contains(serr.Error(), "STARTTLS") {
				t.Errorf("Send error = %v, want it to mention STARTTLS", serr)
			}
			wire := script.rec.wireString()
			for _, forbidden := range []string{testPassword, "AUTH", "MAIL FROM", "DATA"} {
				if strings.Contains(wire, forbidden) {
					t.Errorf("Send put %q on an unencrypted wire: %q", forbidden, wire)
				}
			}
			if n := len(script.rec.messages()); n != 0 {
				t.Errorf("server received %d messages, want 0", n)
			}
		})
	}
}

// TestSMTPStartTLSUpgrade asserts the STARTTLS path delivers the message and that
// nothing sensitive precedes the upgrade.
func TestSMTPStartTLSUpgrade(t *testing.T) {
	srvTLS := loopbackTLSConfig(t)
	script := &smtpScript{
		greeting:    "220 mail.test ESMTP ready",
		ehloExts:    []string{"STARTTLS", "AUTH PLAIN", "8BITMIME"},
		starttlsCfg: srvTLS,
	}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "starttls", InsecureSkipVerify: true, Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if err := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), testOutbound())
	}); err != nil {
		t.Fatalf("Send over STARTTLS: %v", err)
	}
	got := script.rec.messages()
	if len(got) != 1 || string(got[0]) != testMessage {
		t.Fatalf("server queued %d message(s); payload mismatch", len(got))
	}
	plain := script.rec.plainString()
	for _, forbidden := range []string{testPassword, "AUTH", "MAIL FROM", "DATA", "alice@example.com"} {
		if strings.Contains(plain, forbidden) {
			t.Errorf("%q crossed the wire before the STARTTLS upgrade:\n%s", forbidden, plain)
		}
	}
	if !strings.Contains(plain, "STARTTLS\r\n") {
		t.Errorf("no STARTTLS command in the plaintext phase:\n%s", plain)
	}
}

// TestSMTPImplicitTLS asserts SMTPS delivers with nothing in the clear.
func TestSMTPImplicitTLS(t *testing.T) {
	script := &smtpScript{
		greeting:    "220 mail.test ESMTP ready",
		ehloExts:    []string{"AUTH PLAIN"},
		implicitTLS: loopbackTLSConfig(t),
	}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "implicit", InsecureSkipVerify: true, Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if err := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), testOutbound())
	}); err != nil {
		t.Fatalf("Send over implicit TLS: %v", err)
	}
	if got := script.rec.messages(); len(got) != 1 || string(got[0]) != testMessage {
		t.Fatalf("server queued %d message(s); payload mismatch", len(got))
	}
	if p := script.rec.plainString(); p != "" {
		t.Errorf("implicit TLS sent %q in the clear", p)
	}
}

// TestSMTPImplicitTLSVerifiesCertificate asserts a self-signed certificate is
// rejected when InsecureSkipVerify is off.
func TestSMTPImplicitTLSVerifiesCertificate(t *testing.T) {
	script := &smtpScript{
		greeting:    "220 mail.test ESMTP ready",
		implicitTLS: loopbackTLSConfig(t),
	}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "implicit", Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	serr := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), testOutbound())
	})
	if serr == nil {
		t.Fatal("Send accepted a self-signed certificate with verification enabled")
	}
	if !strings.Contains(serr.Error(), "certificate") {
		t.Errorf("Send error = %v, want a certificate verification failure", serr)
	}
	if strings.Contains(script.rec.wireString(), testPassword) {
		t.Error("password reached the server despite the failed handshake")
	}
}

// TestSMTPHangResistance asserts every stall point fails within the configured
// timeout instead of parking the dispatch goroutine forever.
func TestSMTPHangResistance(t *testing.T) {
	cases := []struct {
		name    string
		script  *smtpScript
		wantErr string
	}{
		{
			name:    "no greeting",
			script:  &smtpScript{},
			wantErr: "smtp: greeting",
		},
		{
			name:    "greeting then no EHLO reply",
			script:  &smtpScript{greeting: "220 mail.test ESMTP ready", stallAt: "EHLO"},
			wantErr: "smtp: EHLO",
		},
		{
			name: "no reply to MAIL FROM",
			script: &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"8BITMIME"},
				stallAt: "MAIL"},
			wantErr: "smtp: MAIL FROM",
		},
		{
			name: "no reply to RCPT TO",
			script: &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"8BITMIME"},
				stallAt: "RCPT"},
			wantErr: "smtp: RCPT TO",
		},
		{
			name: "no reply to DATA",
			script: &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"8BITMIME"},
				stallAt: "DATA"},
			wantErr: "smtp: DATA",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startSMTPServer(t, tc.script)
			// No Username: AUTH would be refused before the stall point is reached.
			sender, err := NewSMTPSender(SMTPConfig{
				Host: host, Port: port, TLSMode: "none", Timeout: shortTimeout,
			})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			start := time.Now()
			serr := mustCompleteWithin(t, watchdog, func() error {
				return sender.Send(context.Background(), testOutbound())
			})
			if serr == nil {
				t.Fatal("Send succeeded against a stalled server")
			}
			if !strings.Contains(serr.Error(), tc.wantErr) {
				t.Errorf("Send error = %v, want it to mention %q", serr, tc.wantErr)
			}
			if !errors.Is(serr, os.ErrDeadlineExceeded) {
				t.Errorf("Send error = %v, want the deadline to bound the call", serr)
			}
			if elapsed := time.Since(start); elapsed > watchdog/2 {
				t.Errorf("Send took %v with a %v timeout", elapsed, shortTimeout)
			}
		})
	}
}

// TestSMTPRejections asserts each rejected step is reported with the step named,
// so an operator can tell a bad recipient from a bad body.
func TestSMTPRejections(t *testing.T) {
	cases := []struct {
		name    string
		reject  map[string]string
		wantErr string
	}{
		{name: "MAIL", reject: map[string]string{"MAIL": "550 5.7.1 Sender rejected"}, wantErr: "smtp: MAIL FROM"},
		{name: "RCPT", reject: map[string]string{"RCPT": "550 5.1.1 No such user"}, wantErr: "smtp: RCPT TO"},
		{name: "DATA", reject: map[string]string{"DATA": "554 5.5.1 No valid recipients"}, wantErr: "smtp: DATA"},
		{name: "end of data", reject: map[string]string{"EOD": "552 5.3.4 Message too big"}, wantErr: "smtp: completing message"},
		{
			// Both greeting verbs refused: net/smtp falls back from EHLO to HELO, so
			// only refusing EHLO is not a handshake failure.
			name:    "greeting handshake",
			reject:  map[string]string{"EHLO": "550 5.7.1 Go away", "HELO": "550 5.7.1 Go away"},
			wantErr: "smtp: EHLO",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := &smtpScript{
				greeting: "220 mail.test ESMTP ready",
				ehloExts: []string{"8BITMIME"},
				reject:   tc.reject,
			}
			host, port := startSMTPServer(t, script)
			sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, TLSMode: "none", Timeout: watchdog / 2})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			serr := mustCompleteWithin(t, watchdog, func() error {
				return sender.Send(context.Background(), testOutbound())
			})
			if serr == nil {
				t.Fatalf("Send succeeded although %s was rejected", tc.name)
			}
			if !strings.Contains(serr.Error(), tc.wantErr) {
				t.Errorf("Send error = %v, want it to mention %q", serr, tc.wantErr)
			}
		})
	}
}

// TestSMTPEnvelopeInjectionRejected asserts a CRLF in the envelope cannot inject
// an SMTP command or extra recipient.
func TestSMTPEnvelopeInjectionRejected(t *testing.T) {
	cases := []acme.OutboundMail{
		{From: "acme@pki.example.com\r\nRCPT TO:<attacker@example.net>", To: "alice@example.com", Raw: []byte(testMessage)},
		{From: "acme@pki.example.com", To: "alice@example.com>\r\nRCPT TO:<attacker@example.net", Raw: []byte(testMessage)},
	}
	for i, msg := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			script := &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"8BITMIME"}}
			host, port := startSMTPServer(t, script)
			sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, TLSMode: "none", Timeout: watchdog / 2})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			serr := mustCompleteWithin(t, watchdog, func() error {
				return sender.Send(context.Background(), msg)
			})
			if serr == nil {
				t.Fatal("Send accepted an envelope address containing CRLF")
			}
			if strings.Contains(script.rec.wireString(), "attacker@example.net") {
				t.Errorf("injected recipient reached the server:\n%s", script.rec.wireString())
			}
			if n := len(script.rec.messages()); n != 0 {
				t.Errorf("server queued %d message(s) for an invalid envelope", n)
			}
		})
	}
}

// TestSMTPDialFailures asserts dial-level failures are reported with the address
// and honour context cancellation.
func TestSMTPDialFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, TLSMode: "none", Timeout: shortTimeout})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	t.Run("closed port", func(t *testing.T) {
		serr := mustCompleteWithin(t, watchdog, func() error {
			return sender.Send(context.Background(), testOutbound())
		})
		if serr == nil {
			t.Fatal("Send succeeded against a closed port")
		}
		if !strings.Contains(serr.Error(), "smtp: dial") || !strings.Contains(serr.Error(), addr) {
			t.Errorf("Send error = %v, want it to name the dialled address %s", serr, addr)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		serr := mustCompleteWithin(t, watchdog, func() error {
			return sender.Send(ctx, testOutbound())
		})
		if !errors.Is(serr, context.Canceled) {
			t.Errorf("Send error = %v, want context.Canceled", serr)
		}
	})
}

// TestSMTPSendIsRepeatable asserts a sender is reusable: each Send opens its own
// connection and delivers exactly one message, so the poll/dispatch loop cannot
// accumulate state across sends.
func TestSMTPSendIsRepeatable(t *testing.T) {
	script := &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"8BITMIME"}}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, TLSMode: "none", Timeout: watchdog / 2})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	for i := 0; i < 3; i++ {
		msg := testOutbound()
		msg.Raw = []byte(fmt.Sprintf("Subject: msg %d\r\n\r\nbody %d\r\n", i, i))
		if err := mustCompleteWithin(t, watchdog, func() error {
			return sender.Send(context.Background(), msg)
		}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	got := script.rec.messages()
	if len(got) != 3 {
		t.Fatalf("server queued %d messages, want 3", len(got))
	}
	for i, m := range got {
		want := fmt.Sprintf("Subject: msg %d\r\n\r\nbody %d\r\n", i, i)
		if string(m) != want {
			t.Errorf("message %d = %q, want %q", i, m, want)
		}
	}
	if n := script.rec.connCount(); n != 3 {
		t.Errorf("server accepted %d connections for 3 sends, want 3", n)
	}
}

// TestSMTPNoESMTPStillRequiresTLS asserts an EHLO-refusing server (net/smtp
// silently falls back to HELO, which advertises no extensions) cannot be used to
// strip the required STARTTLS upgrade.
func TestSMTPNoESMTPStillRequiresTLS(t *testing.T) {
	script := &smtpScript{
		greeting: "220 mail.test SMTP ready",
		reject:   map[string]string{"EHLO": "500 5.5.1 Command unrecognized"},
	}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "starttls", Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	serr := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), testOutbound())
	})
	if serr == nil {
		t.Fatal("Send delivered over a plain-SMTP server although STARTTLS is required")
	}
	if !strings.Contains(serr.Error(), "STARTTLS") {
		t.Errorf("Send error = %v, want it to mention STARTTLS", serr)
	}
	if strings.Contains(script.rec.wireString(), testPassword) {
		t.Errorf("password crossed an unencrypted wire:\n%s", script.rec.wireString())
	}
	if n := len(script.rec.messages()); n != 0 {
		t.Errorf("server queued %d message(s), want 0", n)
	}
}

// TestSMTPAuthRejected asserts a refused AUTH aborts the send before the message
// is handed over and that the error does not carry the password.
func TestSMTPAuthRejected(t *testing.T) {
	script := &smtpScript{
		greeting: "220 mail.test ESMTP ready",
		ehloExts: []string{"AUTH PLAIN"},
		reject:   map[string]string{"AUTH": "535 5.7.8 Authentication credentials invalid"},
	}
	host, port := startSMTPServer(t, script)
	sender, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
		TLSMode: "none", Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	serr := mustCompleteWithin(t, watchdog, func() error {
		return sender.Send(context.Background(), testOutbound())
	})
	if serr == nil {
		t.Fatal("Send succeeded although AUTH was refused")
	}
	if !strings.Contains(serr.Error(), "smtp: AUTH") {
		t.Errorf("Send error = %v, want it to mention AUTH", serr)
	}
	if strings.Contains(serr.Error(), testPassword) {
		t.Errorf("Send error leaks the SMTP password: %v", serr)
	}
	if n := len(script.rec.messages()); n != 0 {
		t.Errorf("server queued %d message(s) after a refused AUTH, want 0", n)
	}
}

// TestSMTPStartTLSUpgradeFails asserts that a server which advertises STARTTLS but
// then refuses (or breaks) the upgrade aborts the send: no AUTH, no envelope, no
// message in the clear.
func TestSMTPStartTLSUpgradeFails(t *testing.T) {
	cases := []struct {
		name   string
		script *smtpScript
	}{
		{
			name: "refused after advertising",
			// starttlsCfg is nil, so the scripted server answers 454.
			script: &smtpScript{greeting: "220 mail.test ESMTP ready", ehloExts: []string{"STARTTLS", "AUTH PLAIN"}},
		},
		{
			name: "handshake fails on an unverifiable certificate",
			script: &smtpScript{
				greeting:    "220 mail.test ESMTP ready",
				ehloExts:    []string{"STARTTLS", "AUTH PLAIN"},
				starttlsCfg: loopbackTLSConfig(t),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startSMTPServer(t, tc.script)
			sender, err := NewSMTPSender(SMTPConfig{
				Host: host, Port: port, Username: "acme@pki.example.com", Password: testPassword,
				TLSMode: "starttls", Timeout: watchdog / 2,
			})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			serr := mustCompleteWithin(t, watchdog, func() error {
				return sender.Send(context.Background(), testOutbound())
			})
			if serr == nil {
				t.Fatal("Send succeeded although the STARTTLS upgrade failed")
			}
			if !strings.Contains(serr.Error(), "STARTTLS") {
				t.Errorf("Send error = %v, want it to mention STARTTLS", serr)
			}
			wire := tc.script.rec.wireString()
			for _, forbidden := range []string{testPassword, "AUTH", "MAIL FROM", "DATA"} {
				if strings.Contains(wire, forbidden) {
					t.Errorf("Send put %q on the wire after a failed upgrade:\n%s", forbidden, wire)
				}
			}
			if n := len(tc.script.rec.messages()); n != 0 {
				t.Errorf("server queued %d message(s), want 0", n)
			}
		})
	}
}
