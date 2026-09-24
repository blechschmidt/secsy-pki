package mailtransport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file exercises the hand-rolled IMAP client in imap.go against a scripted
// fake IMAP server on a loopback TCP listener. Everything here is hermetic: no
// external mail server, no DNS, no real network beyond 127.0.0.1, and no
// time.Sleep — every "must not hang" case pairs a short client timeout with a
// watchdog so a regression fails the test instead of wedging CI.

const (
	// shortTimeout is the IMAPConfig.Timeout used by the hang-resistance tests:
	// short enough to keep the suite fast, long enough that a loopback round trip
	// on a loaded CI box still completes.
	shortTimeout = 400 * time.Millisecond
	// watchdog bounds how long a client call may take before the test declares a
	// hang. It is far larger than shortTimeout so it only fires on a real hang,
	// never on scheduling jitter.
	watchdog = 20 * time.Second
)

// mustCompleteWithin runs fn on its own goroutine and fails the test if fn has
// not returned before limit. Used so a client that hangs on hostile server
// behaviour produces a test failure rather than a stuck test binary.
func mustCompleteWithin(t *testing.T, limit time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		t.Fatalf("call did not return within %v: the client hung", limit)
		return nil
	}
}

// imapRecorder captures what the client sent so tests can assert on the exact
// commands (and on credentials never reaching the plaintext wire).
type imapRecorder struct {
	mu      sync.Mutex
	accepts int
	lines   []string // every command line received, in order
	plain   []string // command lines received before any TLS upgrade
}

func (r *imapRecorder) accept() {
	r.mu.Lock()
	r.accepts++
	r.mu.Unlock()
}

func (r *imapRecorder) record(line string, encrypted bool) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if !encrypted {
		r.plain = append(r.plain, line)
	}
	r.mu.Unlock()
}

func (r *imapRecorder) snapshot() (accepts int, lines, plain []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accepts, append([]string(nil), r.lines...), append([]string(nil), r.plain...)
}

// sent returns every recorded command line joined by newlines, for substring
// assertions.
func (r *imapRecorder) sent() string {
	_, lines, _ := r.snapshot()
	return strings.Join(lines, "\n")
}

// sentPlaintext returns the command lines that crossed the wire unencrypted.
func (r *imapRecorder) sentPlaintext() string {
	_, _, plain := r.snapshot()
	return strings.Join(plain, "\n")
}

// countCommand counts recorded lines whose (upper-cased) text contains want.
func (r *imapRecorder) countCommand(want string) int {
	_, lines, _ := r.snapshot()
	n := 0
	for _, l := range lines {
		if strings.Contains(strings.ToUpper(l), strings.ToUpper(want)) {
			n++
		}
	}
	return n
}

// imapScript describes the server side of one test dialogue.
type imapScript struct {
	// greeting is written (CRLF-appended) as soon as the connection is ready.
	// Empty means the server sends nothing at all — the greeting-timeout case.
	greeting string
	// rawGreeting, when set, is written verbatim (no CRLF appended) instead of
	// greeting, for malformed/unterminated greetings.
	rawGreeting string
	// implicitTLS, when non-nil, makes the listener speak TLS from the first byte.
	implicitTLS *tls.Config
	// starttlsCfg, when non-nil, upgrades the connection to TLS right after the
	// server has answered a STARTTLS command with a tagged OK.
	starttlsCfg *tls.Config
	// reply maps one client command to the raw bytes written back. Returning ""
	// means "stay silent", which models a stalled server. cmd is upper-cased and,
	// for UID commands, includes the sub-command ("UID SEARCH", "UID FETCH").
	reply func(tag, cmd, line string) string
	// afterReply, when non-nil, runs after reply's bytes have been written. It
	// returns false to end the connection. Used for stream-forever and
	// close-mid-response cases.
	afterReply func(conn net.Conn, tag, cmd string) bool
	rec        *imapRecorder
}

// startIMAPServer starts the scripted server on 127.0.0.1:0 and returns the host
// and port to point an IMAPInbox at. The listener and every accepted connection
// are closed on test cleanup, and cleanup waits for the handler goroutines so a
// leaked goroutine cannot bleed into another test.
func startIMAPServer(t *testing.T, s *imapScript) (string, int) {
	t.Helper()
	if s.rec == nil {
		s.rec = &imapRecorder{}
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
			s.rec.accept()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				// Bound the server side too: if the client wedges, the handler must
				// not outlive the test.
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

func (s *imapScript) serve(conn net.Conn) {
	encrypted := false
	if s.implicitTLS != nil {
		tconn := tls.Server(conn, s.implicitTLS)
		if err := tconn.Handshake(); err != nil {
			return
		}
		conn = tconn
		encrypted = true
	}
	switch {
	case s.rawGreeting != "":
		if _, err := io.WriteString(conn, s.rawGreeting); err != nil {
			return
		}
	case s.greeting != "":
		if _, err := io.WriteString(conn, s.greeting+"\r\n"); err != nil {
			return
		}
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.rec.record(line, encrypted)
		tag, cmd := splitIMAPCommand(line)
		var out string
		if s.reply != nil {
			out = s.reply(tag, cmd, line)
		}
		if out != "" {
			if _, err := io.WriteString(conn, out); err != nil {
				return
			}
		}
		if s.afterReply != nil && !s.afterReply(conn, tag, cmd) {
			return
		}
		if s.starttlsCfg != nil && cmd == "STARTTLS" && strings.Contains(out, tag+" OK") {
			tconn := tls.Server(conn, s.starttlsCfg)
			if err := tconn.Handshake(); err != nil {
				return
			}
			conn = tconn
			encrypted = true
			// Anything the client pipelined before the upgrade is deliberately
			// dropped with the old reader (as the client drops its own buffer).
			r = bufio.NewReader(conn)
		}
	}
}

// splitIMAPCommand extracts the tag and the (upper-cased) command name from a
// client line, folding "UID FETCH"/"UID SEARCH"/"UID STORE" into one token.
func splitIMAPCommand(line string) (tag, cmd string) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", ""
	}
	tag = f[0]
	if len(f) > 1 {
		cmd = strings.ToUpper(f[1])
	}
	if cmd == "UID" && len(f) > 2 {
		cmd += " " + strings.ToUpper(f[2])
	}
	return tag, cmd
}

// okReplies returns a reply function for a healthy mailbox: LOGIN/SELECT/STORE
// succeed, UID SEARCH returns uids, and UID FETCH returns message as a literal.
// Any command not named is answered with a bare tagged OK.
func okReplies(uids []string, message string) func(tag, cmd, line string) string {
	return func(tag, cmd, line string) string {
		switch cmd {
		case "SELECT":
			return "* 3 EXISTS\r\n* OK [UIDVALIDITY 1]\r\n" + tag + " OK [READ-WRITE] SELECT completed\r\n"
		case "UID SEARCH":
			return "* SEARCH " + strings.Join(uids, " ") + "\r\n" + tag + " OK SEARCH completed\r\n"
		case "UID FETCH":
			uid := "1"
			if f := strings.Fields(line); len(f) > 3 {
				uid = f[3]
			}
			return "* 1 FETCH (UID " + uid + " BODY[] {" + strconv.Itoa(len(message)) + "}\r\n" +
				message + ")\r\n" + tag + " OK FETCH completed\r\n"
		default:
			return tag + " OK " + cmd + " completed\r\n"
		}
	}
}

// loopbackTLSConfig returns a server TLS config with a fresh self-signed
// certificate valid for 127.0.0.1, generated in-process so the test needs no
// fixture files.
func loopbackTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// testMessage is a challenge-reply-shaped message with content designed to break
// a client that re-parses literal bytes as protocol: embedded CRLFs, a line that
// looks exactly like a tagged completion, a "{n}" literal announcement, a
// leading-dot (SMTP dot-stuffing) line, 8-bit bytes and a NUL.
const testMessage = "From: alice@example.com\r\n" +
	"Subject: Re: ACME: tok\r\n" +
	"In-Reply-To: <mid@pki>\r\n" +
	"Content-Type: text/plain; charset=iso-8859-1\r\n" +
	"\r\n" +
	"a1 OK this line must not be mistaken for a tagged completion\r\n" +
	"* 1 FETCH (BODY[] {99}\r\n" +
	".\r\n" +
	".leading dot\r\n" +
	"8-bit: \xc3\xa4\xc3\xb6\xc3\xbc \xff\xfe and a NUL:\x00\r\n" +
	"-----BEGIN ACME RESPONSE-----\r\n" +
	"AbCd0123_deadbeef {not-a-literal}\r\n" +
	"-----END ACME RESPONSE-----\r\n"

// noneTLSInbox builds an inbox pointed at a plaintext scripted server.
func noneTLSInbox(t *testing.T, host string, port int, timeout time.Duration) *IMAPInbox {
	t.Helper()
	inbox, err := NewIMAPInbox(IMAPConfig{
		Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
		TLSMode: "none", Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("NewIMAPInbox: %v", err)
	}
	return inbox
}

// testPassword is the mailbox password used throughout; tests assert it never
// shows up in an error string or on a plaintext wire.
const testPassword = "s3cr3t-mailbox-pw"

// TestIMAPGreeting covers every greeting shape the client can be handed: the two
// acceptable ones (OK / PREAUTH) and the refusals and malformations it must
// reject with a bounded error instead of proceeding or blocking.
func TestIMAPGreeting(t *testing.T) {
	cases := []struct {
		name    string
		raw     string // written verbatim by the fake server
		wantErr string // "" => greeting must be accepted
	}{
		{name: "ok", raw: "* OK [CAPABILITY IMAP4rev1] server ready\r\n"},
		{name: "ok bare", raw: "* OK\r\n"},
		{name: "preauth", raw: "* PREAUTH IMAP4rev1 already authenticated\r\n"},
		{name: "bye refusal", raw: "* BYE too many connections\r\n", wantErr: "unexpected greeting"},
		{name: "no", raw: "* NO service temporarily unavailable\r\n", wantErr: "unexpected greeting"},
		{name: "pop3 server", raw: "+OK POP3 ready\r\n", wantErr: "unexpected greeting"},
		{name: "http server", raw: "HTTP/1.1 400 Bad Request\r\n", wantErr: "unexpected greeting"},
		{name: "empty line", raw: "\r\n", wantErr: "unexpected greeting"},
		{name: "lf only", raw: "* BYE\n", wantErr: "unexpected greeting"},
		{name: "binary junk", raw: "\x00\x01\x02\xff\r\n", wantErr: "unexpected greeting"},
		// "* OKAY" starts with "* OK" and is therefore accepted by the prefix test.
		// Documented, not a problem: no conformant server sends it and the next
		// command's tagged completion is still required to be OK.
		{name: "ok prefix of longer word", raw: "* OKAY whatever\r\n"},
		{name: "unterminated then close", raw: "* OK no newline", wantErr: "reading greeting"},
		{name: "immediate close", raw: "", wantErr: "reading greeting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()
			_ = clientConn.SetDeadline(time.Now().Add(watchdog))
			go func() {
				defer func() { _ = serverConn.Close() }()
				if tc.raw != "" {
					_, _ = io.WriteString(serverConn, tc.raw)
				}
			}()
			c := newIMAPConn(clientConn)
			err := mustCompleteWithin(t, watchdog, c.greeting)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("greeting(%q) = %v, want nil", tc.raw, err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("greeting(%q) = nil, want error containing %q", tc.raw, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("greeting(%q) = %v, want error containing %q", tc.raw, err, tc.wantErr)
			}
		})
	}
}

// TestNewIMAPInboxValidationAndDefaults pins the constructor's validation and its
// defaulting, including the port default flipping with the TLS mode — getting
// that wrong silently dials the wrong port (or the plaintext port with TLS).
func TestNewIMAPInboxValidationAndDefaults(t *testing.T) {
	cases := []struct {
		name    string
		in      IMAPConfig
		wantErr string
		want    IMAPConfig // checked field by field when wantErr == ""
	}{
		{
			name:    "host required",
			in:      IMAPConfig{Username: "u"},
			wantErr: "host is required",
		},
		{
			name:    "blank host rejected",
			in:      IMAPConfig{Host: "   ", Username: "u"},
			wantErr: "host is required",
		},
		{
			name:    "username required",
			in:      IMAPConfig{Host: "mail.example.com"},
			wantErr: "username is required",
		},
		{
			name:    "blank username rejected",
			in:      IMAPConfig{Host: "mail.example.com", Username: "\t "},
			wantErr: "username is required",
		},
		{
			name: "implicit tls defaults to 993",
			in:   IMAPConfig{Host: "mail.example.com", Username: "u"},
			want: IMAPConfig{Port: 993, Mailbox: "INBOX", Timeout: imapDefaultTimeout, MaxMessages: imapDefaultMaxMessages},
		},
		{
			name: "starttls defaults to 143",
			in:   IMAPConfig{Host: "mail.example.com", Username: "u", TLSMode: "StartTLS"},
			want: IMAPConfig{Port: 143, Mailbox: "INBOX", Timeout: imapDefaultTimeout, MaxMessages: imapDefaultMaxMessages},
		},
		{
			name: "none defaults to 143",
			in:   IMAPConfig{Host: "mail.example.com", Username: "u", TLSMode: "NONE"},
			want: IMAPConfig{Port: 143, Mailbox: "INBOX", Timeout: imapDefaultTimeout, MaxMessages: imapDefaultMaxMessages},
		},
		{
			name: "unknown tls mode falls back to implicit tls",
			in:   IMAPConfig{Host: "mail.example.com", Username: "u", TLSMode: "startls"},
			want: IMAPConfig{Port: 993, Mailbox: "INBOX", Timeout: imapDefaultTimeout, MaxMessages: imapDefaultMaxMessages},
		},
		{
			name: "explicit values preserved",
			in: IMAPConfig{Host: "mail.example.com", Username: "u", Port: 1143, Mailbox: "Replies",
				TLSMode: "none", Timeout: time.Second, MaxMessages: 7},
			want: IMAPConfig{Port: 1143, Mailbox: "Replies", Timeout: time.Second, MaxMessages: 7},
		},
		{
			name: "non-positive timeout and cap defaulted",
			in: IMAPConfig{Host: "mail.example.com", Username: "u", Port: 1143,
				Timeout: -time.Second, MaxMessages: -3},
			want: IMAPConfig{Port: 1143, Mailbox: "INBOX", Timeout: imapDefaultTimeout, MaxMessages: imapDefaultMaxMessages},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewIMAPInbox(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewIMAPInbox = (%v, %v), want error containing %q", got, err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("NewIMAPInbox returned a non-nil inbox alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewIMAPInbox: %v", err)
			}
			if got.cfg.Port != tc.want.Port {
				t.Errorf("Port = %d, want %d", got.cfg.Port, tc.want.Port)
			}
			if got.cfg.Mailbox != tc.want.Mailbox {
				t.Errorf("Mailbox = %q, want %q", got.cfg.Mailbox, tc.want.Mailbox)
			}
			if got.cfg.Timeout != tc.want.Timeout {
				t.Errorf("Timeout = %v, want %v", got.cfg.Timeout, tc.want.Timeout)
			}
			if got.cfg.MaxMessages != tc.want.MaxMessages {
				t.Errorf("MaxMessages = %d, want %d", got.cfg.MaxMessages, tc.want.MaxMessages)
			}
		})
	}
}

// TestIMAPHangResistance is the core stability suite: for each way a server can
// stop making progress, Fetch must return an error bounded by the configured
// timeout. The watchdog turns any regression into a failure instead of a hung
// test binary.
func TestIMAPHangResistance(t *testing.T) {
	const bigMessage = 1 << 20

	cases := []struct {
		name string
		// script builds the server behaviour for this case.
		script func() *imapScript
		// wantErrContains is a substring the returned error must contain, so the
		// failure is attributed to the right protocol step.
		wantErrContains string
		// wantDeadline asserts the failure is the I/O deadline firing (rather than
		// an unrelated error that happens to end the call).
		wantDeadline bool
	}{
		{
			name: "server accepts then sends nothing",
			script: func() *imapScript {
				return &imapScript{} // no greeting, no replies
			},
			wantErrContains: "reading greeting",
			wantDeadline:    true,
		},
		{
			name: "greeting then silence",
			script: func() *imapScript {
				return &imapScript{greeting: "* OK ready"} // never answers LOGIN
			},
			wantErrContains: "LOGIN",
			wantDeadline:    true,
		},
		{
			name: "tagged completion for the wrong tag",
			script: func() *imapScript {
				return &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
					if cmd == "SELECT" {
						// A tag the client never issued: it must not be mistaken for the
						// completion of the in-flight command.
						return "* 3 EXISTS\r\nz99 OK SELECT completed\r\n"
					}
					return tag + " OK completed\r\n"
				}}
			},
			wantErrContains: "SELECT",
			wantDeadline:    true,
		},
		{
			name: "completion tag is a prefix of the real tag",
			script: func() *imapScript {
				return &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
					if cmd == "SELECT" {
						// "a" and "a2x" both share a prefix with the real tag "a2" but are
						// not it.
						return "a OK SELECT completed\r\na2x OK SELECT completed\r\n"
					}
					return tag + " OK completed\r\n"
				}}
			},
			wantErrContains: "SELECT",
			wantDeadline:    true,
		},
		{
			name: "untagged responses forever with no completion",
			script: func() *imapScript {
				return &imapScript{
					greeting: "* OK ready",
					reply: func(tag, cmd, line string) string {
						if cmd == "SELECT" {
							return "" // the flood is written by afterReply
						}
						return tag + " OK completed\r\n"
					},
					afterReply: func(conn net.Conn, tag, cmd string) bool {
						if cmd != "SELECT" {
							return true
						}
						// Stream untagged lines until the client gives up (write fails) or
						// a hard byte cap is hit, then fall silent. Either way the tagged
						// completion never arrives.
						chunk := strings.Repeat("* 1 EXISTS\r\n", 512)
						for written := 0; written < 64<<20; written += len(chunk) {
							if _, err := io.WriteString(conn, chunk); err != nil {
								return false
							}
						}
						return true
					},
				}
			},
			wantErrContains: "SELECT",
			wantDeadline:    true,
		},
		{
			name: "literal shorter than its declared size then silence",
			script: func() *imapScript {
				return &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
					switch cmd {
					case "UID SEARCH":
						return "* SEARCH 5\r\n" + tag + " OK SEARCH completed\r\n"
					case "UID FETCH":
						// Declares 4096 bytes, sends 3, then stalls without closing.
						return "* 1 FETCH (UID 5 BODY[] {4096}\r\nabc"
					default:
						return tag + " OK completed\r\n"
					}
				}}
			},
			wantErrContains: "reading 4096-byte literal",
			wantDeadline:    true,
		},
		{
			name: "single line of megabytes with no CRLF then close",
			script: func() *imapScript {
				return &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
					if cmd == "SELECT" {
						// A never-terminated line: the client must surface an error rather
						// than silently treating the truncated data as a completion.
						return "* " + strings.Repeat("A", bigMessage)
					}
					return tag + " OK completed\r\n"
				}, afterReply: func(conn net.Conn, tag, cmd string) bool {
					return cmd != "SELECT" // close after the unterminated line
				}}
			},
			wantErrContains: "SELECT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startIMAPServer(t, tc.script())
			inbox := noneTLSInbox(t, host, port, shortTimeout)
			start := time.Now()
			err := mustCompleteWithin(t, watchdog, func() error {
				_, err := inbox.Fetch(context.Background())
				return err
			})
			if err == nil {
				t.Fatalf("Fetch succeeded against a stalled/hostile server, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Errorf("Fetch error = %v, want it to mention %q", err, tc.wantErrContains)
			}
			if tc.wantDeadline && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("Fetch error = %v (%T), want an I/O deadline error", err, err)
			}
			// The configured timeout is the bound; allow generous slack for a loaded
			// CI box but still fail if the call ran orders of magnitude too long.
			if elapsed := time.Since(start); elapsed > watchdog/2 {
				t.Errorf("Fetch took %v with a %v timeout: the timeout is not bounding the call", elapsed, shortTimeout)
			}
		})
	}
}

// TestIMAPContextDeadlineBoundsFetch asserts the caller's context deadline wins
// over a huge configured Timeout. Without this, a shutdown or a per-poll context
// could not interrupt a stuck poll.
func TestIMAPContextDeadlineBoundsFetch(t *testing.T) {
	host, port := startIMAPServer(t, &imapScript{}) // accepts, sends nothing
	inbox := noneTLSInbox(t, host, port, time.Hour)
	err := mustCompleteWithin(t, watchdog, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := inbox.Fetch(ctx)
		return err
	})
	if err == nil {
		t.Fatal("Fetch succeeded against a silent server, want a deadline error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Fetch error = %v, want the context deadline to bound the read", err)
	}
}

// TestIMAPCancelledContextFailsFast asserts an already-cancelled context stops
// the poll at the dial instead of opening a connection.
func TestIMAPCancelledContextFailsFast(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: okReplies([]string{"5"}, testMessage)}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := mustCompleteWithin(t, watchdog, func() error {
		_, err := inbox.Fetch(ctx)
		return err
	})
	if err == nil {
		t.Fatal("Fetch with a cancelled context succeeded, want an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch error = %v, want context.Canceled", err)
	}
	if accepts, _, _ := script.rec.snapshot(); accepts != 0 {
		t.Errorf("server accepted %d connection(s) for a cancelled context, want 0", accepts)
	}
}

// fetchBodyOver runs fetchBody against a server that answers the UID FETCH with
// raw verbatim ("{TAG}" is substituted with the real command tag) and then either
// closes the connection or stays open and silent. The client side carries a short
// deadline so a silent server fails the call instead of blocking.
func fetchBodyOver(t *testing.T, raw string, thenClose bool) ([]byte, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	_ = clientConn.SetDeadline(time.Now().Add(shortTimeout))
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = clientConn.Close()
		<-done
	})
	go func() {
		defer close(done)
		defer func() { _ = serverConn.Close() }()
		r := bufio.NewReader(serverConn)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		tag, _ := splitIMAPCommand(strings.TrimRight(line, "\r\n"))
		if _, err := io.WriteString(serverConn, strings.ReplaceAll(raw, "{TAG}", tag)); err != nil {
			return
		}
		if !thenClose {
			// Stay open and silent. This read never yields a line; it returns only
			// when the client (or cleanup) closes the pipe, so the goroutine exits
			// without a sleep.
			_, _ = r.ReadString('\n')
		}
	}()
	c := newIMAPConn(clientConn)
	var (
		body []byte
		err  error
	)
	err = mustCompleteWithin(t, watchdog, func() error {
		var ferr error
		body, ferr = c.fetchBody("5")
		return ferr
	})
	return body, err
}

// TestIMAPFetchBodyResponses drives fetchBody through the malformed, hostile and
// truncated FETCH responses a remote server can produce. Every case must return
// (not panic, not hang) and either yield the exact body or an error.
func TestIMAPFetchBodyResponses(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		thenClose  bool
		wantBody   string // "" => expect an error
		wantErr    string
		wantNoHuge bool // the declared literal must be rejected without being read
	}{
		{
			name:     "body returned byte exactly",
			raw:      "* 1 FETCH (UID 5 BODY[] {" + strconv.Itoa(len(testMessage)) + "}\r\n" + testMessage + ")\r\n{TAG} OK FETCH completed\r\n",
			wantBody: testMessage,
		},
		{
			name: "flags and rfc822.size around the literal",
			raw: "* 1 FETCH (UID 5 FLAGS (\\Recent) RFC822.SIZE 42 BODY[] {" + strconv.Itoa(len(testMessage)) + "}\r\n" +
				testMessage + " FLAGS (\\Recent))\r\n{TAG} OK FETCH completed\r\n",
			wantBody: testMessage,
		},
		{
			name: "largest literal wins when several are returned",
			// A HEADER fetch plus the full body: fetchBody documents that it keeps the
			// largest literal, which is the message.
			raw: "* 1 FETCH (UID 5 BODY[HEADER] {6}\r\nabcdef BODY[] {" + strconv.Itoa(len(testMessage)) + "}\r\n" +
				testMessage + ")\r\n{TAG} OK FETCH completed\r\n",
			wantBody: testMessage,
		},
		{
			name:    "no literal at all",
			raw:     "* 1 FETCH (UID 5 FLAGS (\\Seen))\r\n{TAG} OK FETCH completed\r\n",
			wantErr: "no message body returned",
		},
		{
			name:    "empty literal",
			raw:     "* 1 FETCH (UID 5 BODY[] {0}\r\n)\r\n{TAG} OK FETCH completed\r\n",
			wantErr: "no message body returned",
		},
		{
			name:    "negative literal size is not a literal",
			raw:     "* 1 FETCH (UID 5 BODY[] {-5}\r\nabcde)\r\n{TAG} OK FETCH completed\r\n",
			wantErr: "no message body returned",
		},
		{
			name:    "non-numeric literal size is not a literal",
			raw:     "* 1 FETCH (UID 5 BODY[] {abc}\r\nabcde)\r\n{TAG} OK FETCH completed\r\n",
			wantErr: "no message body returned",
		},
		{
			name:    "tagged BAD completion",
			raw:     "{TAG} BAD Invalid UID set\r\n",
			wantErr: "command failed: BAD Invalid UID set",
		},
		{
			name:    "tagged NO completion",
			raw:     "{TAG} NO Server unavailable\r\n",
			wantErr: "command failed: NO Server unavailable",
		},
		{
			name:      "connection closed before any response",
			raw:       "",
			thenClose: true,
			wantErr:   "EOF",
		},
		{
			name:      "connection closed mid-literal",
			raw:       "* 1 FETCH (UID 5 BODY[] {4096}\r\nonly-a-few-bytes",
			thenClose: true,
			wantErr:   "reading 4096-byte literal: unexpected EOF",
		},
		{
			name:      "connection closed mid-line",
			raw:       "* 1 FETCH (UID 5 BODY[] {4",
			thenClose: true,
			wantErr:   "EOF",
		},
		{
			name: "literal announced mid-line is not consumed as a literal",
			// The announcement is not at end of line, so the bytes that follow are
			// read as protocol lines. That must not wedge or panic the parser.
			raw:     "* 1 FETCH (UID 5 BODY[] {5} trailing\r\nabcde\r\n{TAG} OK FETCH completed\r\n",
			wantErr: "no message body returned",
		},
		{
			name: "declared literal just over the cap is refused",
			raw:  "* 1 FETCH (UID 5 BODY[] {" + strconv.Itoa(imapMaxLiteralSize+1) + "}\r\n",
			// Nothing follows: if the client tried to read it, it would block until
			// its deadline instead of failing on the declared size.
			wantErr:    "literal too large",
			wantNoHuge: true,
		},
		{
			name: "declared literal larger than the address space is refused",
			// An unfixed client calls make([]byte, n) on this, which panics with
			// "makeslice: len out of range" and takes the process down.
			raw:        "* 1 FETCH (UID 5 BODY[] {1125899906842624}\r\n",
			wantErr:    "literal too large",
			wantNoHuge: true,
		},
		{
			name: "declared terabyte literal is refused before allocating",
			// make([]byte, 1<<40) succeeds on an overcommitting host and then
			// io.ReadFull faults in a page per byte the server sends, so the poll's
			// resident set grows without bound until the deadline or the OOM killer.
			raw:        "* 1 FETCH (UID 5 BODY[] {1099511627776}\r\n",
			wantErr:    "literal too large",
			wantNoHuge: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := fetchBodyOver(t, tc.raw, tc.thenClose)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("fetchBody = %q, want error containing %q", body, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("fetchBody error = %v, want it to contain %q", err, tc.wantErr)
				}
				if tc.wantNoHuge && errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("fetchBody error = %v: the oversized literal was read instead of rejected", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fetchBody: %v", err)
			}
			if string(body) != tc.wantBody {
				t.Fatalf("body mismatch:\n got %q\nwant %q", body, tc.wantBody)
			}
		})
	}
}

// commands returns every recorded client command with its leading tag stripped,
// so tests can assert on the exact protocol the client speaks.
func (r *imapRecorder) commands() []string {
	_, lines, _ := r.snapshot()
	return stripTags(lines)
}

// plainCommands is commands() restricted to what crossed the wire unencrypted.
func (r *imapRecorder) plainCommands() []string {
	_, _, plain := r.snapshot()
	return stripTags(plain)
}

func stripTags(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if _, rest, ok := strings.Cut(l, " "); ok {
			out = append(out, rest)
		} else {
			out = append(out, l)
		}
	}
	return out
}

// TestIMAPFetchDialogue pins the exact command sequence a poll issues and checks
// the returned mail. BODY.PEEK[] (not BODY[]) is load-bearing: a plain BODY[]
// fetch sets \Seen server-side, so a crash between fetch and validation would
// lose the challenge reply for good.
func TestIMAPFetchDialogue(t *testing.T) {
	second := "From: bob@example.com\r\nSubject: Re: ACME: tok2\r\n\r\nbody two\r\n"
	script := &imapScript{
		greeting: "* OK [CAPABILITY IMAP4rev1] ready",
		reply: func(tag, cmd, line string) string {
			switch cmd {
			case "SELECT":
				return "* 2 EXISTS\r\n* OK [UIDVALIDITY 1]\r\n" + tag + " OK [READ-WRITE] SELECT completed\r\n"
			case "UID SEARCH":
				return "* SEARCH 5 9\r\n" + tag + " OK SEARCH completed\r\n"
			case "UID FETCH":
				msg := testMessage
				if strings.Contains(line, " 9 ") {
					msg = second
				}
				return "* 1 FETCH (UID 5 BODY[] {" + strconv.Itoa(len(msg)) + "}\r\n" + msg + ")\r\n" +
					tag + " OK FETCH completed\r\n"
			default:
				return tag + " OK completed\r\n"
			}
		},
	}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, watchdog/2)

	var msgs []struct{ ID, Raw string }
	err := mustCompleteWithin(t, watchdog, func() error {
		got, err := inbox.Fetch(context.Background())
		for _, m := range got {
			msgs = append(msgs, struct{ ID, Raw string }{m.ID, string(m.Raw)})
		}
		return err
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("Fetch returned %d messages, want 2: %+v", len(msgs), msgs)
	}
	if msgs[0].ID != "5" || msgs[1].ID != "9" {
		t.Errorf("message IDs = %q/%q, want 5/9", msgs[0].ID, msgs[1].ID)
	}
	if msgs[0].Raw != testMessage {
		t.Errorf("first message body mismatch:\n got %q\nwant %q", msgs[0].Raw, testMessage)
	}
	if msgs[1].Raw != second {
		t.Errorf("second message body mismatch:\n got %q\nwant %q", msgs[1].Raw, second)
	}

	want := []string{
		`LOGIN "acme@example.com" "` + testPassword + `"`,
		`SELECT "INBOX"`,
		`UID SEARCH UNSEEN`,
		`UID FETCH 5 (BODY.PEEK[])`,
		`UID FETCH 9 (BODY.PEEK[])`,
	}
	if got := script.rec.commands(); !equalStrings(got, want) {
		t.Errorf("client dialogue =\n  %q\nwant\n  %q", got, want)
	}
	// A poll must never mutate the mailbox.
	for _, forbidden := range []string{"BODY[]", "STORE", "EXPUNGE", "\\Deleted", "DELETE"} {
		if strings.Contains(script.rec.sent(), forbidden) {
			t.Errorf("Fetch sent %q; a poll must not mutate the mailbox or set \\Seen", forbidden)
		}
	}
}

// TestIMAPFetchEmptyMailbox asserts an empty UID SEARCH result is not an error
// and issues no FETCH — the steady state of a quiet mailbox.
func TestIMAPFetchEmptyMailbox(t *testing.T) {
	for _, searchLine := range []string{"* SEARCH\r\n", "* SEARCH \r\n", ""} {
		t.Run(strconv.Quote(searchLine), func(t *testing.T) {
			script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
				if cmd == "UID SEARCH" {
					return searchLine + tag + " OK SEARCH completed\r\n"
				}
				return tag + " OK completed\r\n"
			}}
			host, port := startIMAPServer(t, script)
			inbox := noneTLSInbox(t, host, port, watchdog/2)
			var n int
			err := mustCompleteWithin(t, watchdog, func() error {
				msgs, err := inbox.Fetch(context.Background())
				n = len(msgs)
				return err
			})
			if err != nil {
				t.Fatalf("Fetch on an empty mailbox: %v", err)
			}
			if n != 0 {
				t.Errorf("Fetch returned %d messages from an empty mailbox", n)
			}
			if c := script.rec.countCommand("FETCH"); c != 0 {
				t.Errorf("Fetch issued %d FETCH command(s) with no search results", c)
			}
		})
	}
}

// TestIMAPFetchCapsAtMaxMessages asserts MaxMessages bounds the work one poll
// does, so a flooded mailbox cannot stall the poll loop indefinitely.
func TestIMAPFetchCapsAtMaxMessages(t *testing.T) {
	uids := make([]string, 0, 50)
	for i := 1; i <= 50; i++ {
		uids = append(uids, strconv.Itoa(i))
	}
	script := &imapScript{greeting: "* OK ready", reply: okReplies(uids, testMessage)}
	host, port := startIMAPServer(t, script)
	inbox, err := NewIMAPInbox(IMAPConfig{
		Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
		TLSMode: "none", Timeout: watchdog / 2, MaxMessages: 3,
	})
	if err != nil {
		t.Fatalf("NewIMAPInbox: %v", err)
	}
	var n int
	ferr := mustCompleteWithin(t, watchdog, func() error {
		msgs, err := inbox.Fetch(context.Background())
		n = len(msgs)
		return err
	})
	if ferr != nil {
		t.Fatalf("Fetch: %v", ferr)
	}
	if n != 3 {
		t.Errorf("Fetch returned %d messages, want MaxMessages=3", n)
	}
	if c := script.rec.countCommand("UID FETCH"); c != 3 {
		t.Errorf("client issued %d UID FETCH commands, want 3", c)
	}
}

// TestIMAPFetchStopsOnSelectFailure asserts a refused SELECT aborts the poll
// before any search or fetch and names the mailbox in the error.
func TestIMAPFetchStopsOnSelectFailure(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
		if cmd == "SELECT" {
			return tag + " NO [NONEXISTENT] Mailbox doesn't exist\r\n"
		}
		return tag + " OK completed\r\n"
	}}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, watchdog/2)
	err := mustCompleteWithin(t, watchdog, func() error {
		_, err := inbox.Fetch(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("Fetch succeeded against a refused SELECT")
	}
	for _, want := range []string{"SELECT", "INBOX", "NONEXISTENT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Fetch error = %v, want it to mention %q", err, want)
		}
	}
	if c := script.rec.countCommand("SEARCH") + script.rec.countCommand("FETCH"); c != 0 {
		t.Errorf("client continued past a failed SELECT (%d search/fetch commands)", c)
	}
}

// TestIMAPAckDialogue asserts Ack marks messages \Seen with the exact STORE the
// mailbox contract needs — and that it never deletes or expunges anything.
func TestIMAPAckDialogue(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: okReplies(nil, "")}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, watchdog/2)
	err := mustCompleteWithin(t, watchdog, func() error {
		return inbox.Ack(context.Background(), []string{"5", "9", "12"})
	})
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	want := []string{
		`LOGIN "acme@example.com" "` + testPassword + `"`,
		`SELECT "INBOX"`,
		`UID STORE 5,9,12 +FLAGS.SILENT (\Seen)`,
	}
	if got := script.rec.commands(); !equalStrings(got, want) {
		t.Errorf("Ack dialogue =\n  %q\nwant\n  %q", got, want)
	}
	for _, forbidden := range []string{"EXPUNGE", "\\Deleted", "DELETE", "-FLAGS"} {
		if strings.Contains(script.rec.sent(), forbidden) {
			t.Errorf("Ack sent %q; it must only add \\Seen", forbidden)
		}
	}
}

// TestIMAPAckWithoutIDsDoesNotConnect asserts an empty ack list is free: no
// connection, no login. The poll loop calls Ack on every cycle.
func TestIMAPAckWithoutIDsDoesNotConnect(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: okReplies(nil, "")}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, watchdog/2)
	if err := inbox.Ack(context.Background(), nil); err != nil {
		t.Fatalf("Ack(nil): %v", err)
	}
	if err := inbox.Ack(context.Background(), []string{}); err != nil {
		t.Fatalf("Ack(empty): %v", err)
	}
	if accepts, _, _ := script.rec.snapshot(); accepts != 0 {
		t.Errorf("Ack with no IDs opened %d connection(s), want 0", accepts)
	}
}

// TestIMAPAckReportsStoreFailure asserts a refused STORE surfaces as an error so
// the caller logs it instead of assuming the messages were marked.
func TestIMAPAckReportsStoreFailure(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
		if cmd == "UID STORE" {
			return tag + " NO [CANNOT] STORE failed\r\n"
		}
		return tag + " OK completed\r\n"
	}}
	host, port := startIMAPServer(t, script)
	inbox := noneTLSInbox(t, host, port, watchdog/2)
	err := mustCompleteWithin(t, watchdog, func() error {
		return inbox.Ack(context.Background(), []string{"5"})
	})
	if err == nil {
		t.Fatal("Ack succeeded against a refused STORE")
	}
	if !strings.Contains(err.Error(), "UID STORE") {
		t.Errorf("Ack error = %v, want it to mention UID STORE", err)
	}
}

// TestIMAPAckRejectsNonNumericUID asserts a UID that is not a plain number never
// reaches the command line. IMAP is line-oriented, so a CRLF inside a UID would
// otherwise inject a second, attacker-chosen command into the authenticated
// session (here: an EXPUNGE that empties the mailbox).
func TestIMAPAckRejectsNonNumericUID(t *testing.T) {
	cases := []string{
		"5\r\nzz STORE 1:* +FLAGS (\\Deleted)",
		"5\r\nzz EXPUNGE",
		"5\nzz EXPUNGE",
		"1:*",
		"",
		"5 9",
		"abc",
	}
	for _, uid := range cases {
		t.Run(strconv.Quote(uid), func(t *testing.T) {
			script := &imapScript{greeting: "* OK ready", reply: okReplies(nil, "")}
			host, port := startIMAPServer(t, script)
			inbox := noneTLSInbox(t, host, port, watchdog/2)
			err := mustCompleteWithin(t, watchdog, func() error {
				return inbox.Ack(context.Background(), []string{uid})
			})
			if err == nil {
				t.Errorf("Ack(%q) succeeded, want a rejected UID", uid)
			}
			sent := script.rec.sent()
			for _, forbidden := range []string{"EXPUNGE", "\\Deleted", "1:*"} {
				if strings.Contains(sent, forbidden) {
					t.Fatalf("Ack(%q) put %q on the wire: %q", uid, forbidden, sent)
				}
			}
			// Only the commands the client itself composes may be sent.
			for _, l := range script.rec.commands() {
				if !strings.HasPrefix(l, "LOGIN ") && !strings.HasPrefix(l, "SELECT ") {
					t.Errorf("Ack(%q) sent unexpected command %q", uid, l)
				}
			}
		})
	}
}

// TestIMAPMailboxNameIsQuoted asserts a mailbox name with IMAP-special characters
// is escaped rather than splitting the SELECT command.
func TestIMAPMailboxNameIsQuoted(t *testing.T) {
	script := &imapScript{greeting: "* OK ready", reply: okReplies(nil, "")}
	host, port := startIMAPServer(t, script)
	inbox, err := NewIMAPInbox(IMAPConfig{
		Host: host, Port: port, Username: `us"er\x`, Password: testPassword,
		Mailbox: `ACME "replies\here`, TLSMode: "none", Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewIMAPInbox: %v", err)
	}
	_ = mustCompleteWithin(t, watchdog, func() error {
		_, ferr := inbox.Fetch(context.Background())
		return ferr
	})
	want := []string{
		`LOGIN "us\"er\\x" "` + testPassword + `"`,
		`SELECT "ACME \"replies\\here"`,
	}
	got := script.rec.commands()
	if len(got) < 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("client dialogue =\n  %q\nwant it to start with\n  %q", got, want)
	}
}

// TestIMAPLoginErrorDoesNotLeakPassword asserts the mailbox password never ends
// up in an error string. The poll loop logs Fetch errors verbatim
// ("acme: email-reply-00 inbox poll: %v"), so a server that echoes the rejected
// command — several do on BAD — would otherwise write the mailbox credential into
// the server log.
func TestIMAPLoginErrorDoesNotLeakPassword(t *testing.T) {
	echoes := []string{
		`{TAG} BAD Error in IMAP command: {TAG} LOGIN "acme@example.com" "` + testPassword + `"`,
		`{TAG} NO [AUTHENTICATIONFAILED] Authentication failed for "acme@example.com"/"` + testPassword + `"`,
		`{TAG} BAD password ` + testPassword + ` rejected`,
	}
	for i, echo := range echoes {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
				if cmd == "LOGIN" {
					return strings.ReplaceAll(echo, "{TAG}", tag) + "\r\n"
				}
				return tag + " OK completed\r\n"
			}}
			host, port := startIMAPServer(t, script)
			inbox := noneTLSInbox(t, host, port, watchdog/2)
			err := mustCompleteWithin(t, watchdog, func() error {
				_, ferr := inbox.Fetch(context.Background())
				return ferr
			})
			if err == nil {
				t.Fatal("Fetch succeeded against a rejected LOGIN")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Errorf("Fetch error leaks the mailbox password:\n%v", err)
			}
			// The error must still say what failed, or the redaction has just
			// destroyed the diagnostic.
			if !strings.Contains(err.Error(), "LOGIN") {
				t.Errorf("Fetch error = %v, want it to mention LOGIN", err)
			}
		})
	}
}

// TestIMAPStartTLSRefusedNeverSendsPassword asserts that when the STARTTLS
// upgrade is refused the client aborts instead of falling back to a plaintext
// LOGIN. A downgrade here hands the mailbox password to anyone on the path.
func TestIMAPStartTLSRefusedNeverSendsPassword(t *testing.T) {
	for _, refusal := range []string{
		"{TAG} NO [PRIVACYREQUIRED] STARTTLS is not available\r\n",
		"{TAG} BAD Unknown command\r\n",
	} {
		t.Run(refusal, func(t *testing.T) {
			script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
				return strings.ReplaceAll(refusal, "{TAG}", tag)
			}}
			host, port := startIMAPServer(t, script)
			inbox, err := NewIMAPInbox(IMAPConfig{
				Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
				TLSMode: "starttls", Timeout: watchdog / 2,
			})
			if err != nil {
				t.Fatalf("NewIMAPInbox: %v", err)
			}
			ferr := mustCompleteWithin(t, watchdog, func() error {
				_, e := inbox.Fetch(context.Background())
				return e
			})
			if ferr == nil {
				t.Fatal("Fetch succeeded although the STARTTLS upgrade was refused")
			}
			if !strings.Contains(ferr.Error(), "STARTTLS") {
				t.Errorf("Fetch error = %v, want it to mention STARTTLS", ferr)
			}
			if got := script.rec.commands(); !equalStrings(got, []string{"STARTTLS"}) {
				t.Errorf("client sent %q after a refused STARTTLS, want only STARTTLS", got)
			}
			if strings.Contains(script.rec.sentPlaintext(), testPassword) {
				t.Errorf("password sent in plaintext after a refused STARTTLS: %q", script.rec.sentPlaintext())
			}
		})
	}
}

// TestIMAPImplicitTLSFetch runs the whole poll over IMAPS against a self-signed
// loopback certificate and asserts nothing crossed the wire in the clear.
func TestIMAPImplicitTLSFetch(t *testing.T) {
	srvTLS := loopbackTLSConfig(t)
	script := &imapScript{
		greeting:    "* OK ready",
		implicitTLS: srvTLS,
		reply:       okReplies([]string{"5"}, testMessage),
	}
	host, port := startIMAPServer(t, script)
	inbox, err := NewIMAPInbox(IMAPConfig{
		Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
		TLSMode: "implicit", InsecureSkipVerify: true, Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewIMAPInbox: %v", err)
	}
	var raw string
	ferr := mustCompleteWithin(t, watchdog, func() error {
		msgs, e := inbox.Fetch(context.Background())
		if len(msgs) == 1 {
			raw = string(msgs[0].Raw)
		}
		return e
	})
	if ferr != nil {
		t.Fatalf("Fetch over implicit TLS: %v", ferr)
	}
	if raw != testMessage {
		t.Errorf("body over TLS mismatch:\n got %q\nwant %q", raw, testMessage)
	}
	if p := script.rec.sentPlaintext(); p != "" {
		t.Errorf("implicit TLS sent %q before the handshake", p)
	}
}

// TestIMAPStartTLSUpgradeFetch asserts the STARTTLS path completes and that the
// credentials are only sent after the upgrade.
func TestIMAPStartTLSUpgradeFetch(t *testing.T) {
	srvTLS := loopbackTLSConfig(t)
	ok := okReplies([]string{"5"}, testMessage)
	script := &imapScript{
		greeting:    "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready",
		starttlsCfg: srvTLS,
		reply: func(tag, cmd, line string) string {
			if cmd == "STARTTLS" {
				return tag + " OK Begin TLS negotiation now\r\n"
			}
			return ok(tag, cmd, line)
		},
	}
	host, port := startIMAPServer(t, script)
	inbox, err := NewIMAPInbox(IMAPConfig{
		Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
		TLSMode: "starttls", InsecureSkipVerify: true, Timeout: watchdog / 2,
	})
	if err != nil {
		t.Fatalf("NewIMAPInbox: %v", err)
	}
	var raw string
	ferr := mustCompleteWithin(t, watchdog, func() error {
		msgs, e := inbox.Fetch(context.Background())
		if len(msgs) == 1 {
			raw = string(msgs[0].Raw)
		}
		return e
	})
	if ferr != nil {
		t.Fatalf("Fetch over STARTTLS: %v", ferr)
	}
	if raw != testMessage {
		t.Errorf("body over STARTTLS mismatch:\n got %q\nwant %q", raw, testMessage)
	}
	if plain := script.rec.plainCommands(); !equalStrings(plain, []string{"STARTTLS"}) {
		t.Errorf("plaintext commands = %q, want only STARTTLS", plain)
	}
	if strings.Contains(script.rec.sentPlaintext(), testPassword) {
		t.Error("password crossed the wire before the STARTTLS upgrade")
	}
	if !strings.Contains(script.rec.sent(), "LOGIN") {
		t.Error("no LOGIN reached the server after the upgrade")
	}
}

// TestIMAPTLSVerificationIsOnByDefault asserts a self-signed server certificate
// is rejected unless InsecureSkipVerify is set, for both TLS modes, and that the
// failure is bounded and leaks nothing.
func TestIMAPTLSVerificationIsOnByDefault(t *testing.T) {
	for _, mode := range []string{"implicit", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			srvTLS := loopbackTLSConfig(t)
			script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
				return tag + " OK Begin TLS negotiation now\r\n"
			}}
			if mode == "implicit" {
				script.implicitTLS = srvTLS
			} else {
				script.starttlsCfg = srvTLS
			}
			host, port := startIMAPServer(t, script)
			inbox, err := NewIMAPInbox(IMAPConfig{
				Host: host, Port: port, Username: "acme@example.com", Password: testPassword,
				TLSMode: mode, Timeout: watchdog / 2,
			})
			if err != nil {
				t.Fatalf("NewIMAPInbox: %v", err)
			}
			ferr := mustCompleteWithin(t, watchdog, func() error {
				_, e := inbox.Fetch(context.Background())
				return e
			})
			if ferr == nil {
				t.Fatal("Fetch accepted a self-signed certificate with verification enabled")
			}
			if !strings.Contains(ferr.Error(), "certificate") {
				t.Errorf("Fetch error = %v, want a certificate verification failure", ferr)
			}
			if strings.Contains(script.rec.sent(), testPassword) {
				t.Errorf("password reached the server despite the failed handshake: %q", script.rec.sent())
			}
		})
	}
}

// TestIMAPServerClosesMidSession asserts a connection dropped at any protocol
// step surfaces as an error rather than a partial success or a hang.
func TestIMAPServerClosesMidSession(t *testing.T) {
	for _, at := range []string{"LOGIN", "SELECT", "UID SEARCH", "UID FETCH"} {
		t.Run(at, func(t *testing.T) {
			ok := okReplies([]string{"5"}, testMessage)
			script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
				if cmd == at {
					// A partial, unterminated untagged response, then the close.
					return "* BYE server shutting down"
				}
				return ok(tag, cmd, line)
			}, afterReply: func(conn net.Conn, tag, cmd string) bool {
				return cmd != at
			}}
			host, port := startIMAPServer(t, script)
			inbox := noneTLSInbox(t, host, port, watchdog/2)
			var n int
			err := mustCompleteWithin(t, watchdog, func() error {
				msgs, e := inbox.Fetch(context.Background())
				n = len(msgs)
				return e
			})
			if err == nil {
				t.Fatalf("Fetch succeeded although the server closed during %s (%d messages)", at, n)
			}
			if !strings.Contains(err.Error(), "EOF") {
				t.Errorf("Fetch error = %v, want it to report the closed connection", err)
			}
		})
	}
}

// TestIMAPDialFailureIsReported asserts a refused connection is reported with the
// address, bounded, and without touching the credentials.
func TestIMAPDialFailureIsReported(t *testing.T) {
	// Bind and immediately close to obtain a port nothing listens on.
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
	inbox := noneTLSInbox(t, host, port, shortTimeout)
	ferr := mustCompleteWithin(t, watchdog, func() error {
		_, e := inbox.Fetch(context.Background())
		return e
	})
	if ferr == nil {
		t.Fatal("Fetch succeeded against a closed port")
	}
	if !strings.Contains(ferr.Error(), "imap: dial") || !strings.Contains(ferr.Error(), addr) {
		t.Errorf("Fetch error = %v, want it to name the dialled address %s", ferr, addr)
	}
	if strings.Contains(ferr.Error(), testPassword) {
		t.Errorf("dial error leaks the password: %v", ferr)
	}
}

// TestIMAPAckReportsConnectAndSelectFailures asserts Ack surfaces failures from
// every step before the STORE, so a caller never believes messages were marked
// \Seen when they were not (which would make the poll re-process them forever).
func TestIMAPAckReportsConnectAndSelectFailures(t *testing.T) {
	t.Run("dial", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)
		if err := ln.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		inbox := noneTLSInbox(t, host, port, shortTimeout)
		err = mustCompleteWithin(t, watchdog, func() error {
			return inbox.Ack(context.Background(), []string{"5"})
		})
		if err == nil || !strings.Contains(err.Error(), "imap: dial") {
			t.Fatalf("Ack = %v, want a dial error", err)
		}
	})
	t.Run("select", func(t *testing.T) {
		script := &imapScript{greeting: "* OK ready", reply: func(tag, cmd, line string) string {
			if cmd == "SELECT" {
				return tag + " NO [NONEXISTENT] no such mailbox\r\n"
			}
			return tag + " OK completed\r\n"
		}}
		host, port := startIMAPServer(t, script)
		inbox := noneTLSInbox(t, host, port, watchdog/2)
		err := mustCompleteWithin(t, watchdog, func() error {
			return inbox.Ack(context.Background(), []string{"5"})
		})
		if err == nil || !strings.Contains(err.Error(), "SELECT") {
			t.Fatalf("Ack = %v, want a SELECT error", err)
		}
		if strings.Contains(script.rec.sent(), "STORE") {
			t.Error("Ack issued a STORE after a failed SELECT")
		}
	})
}

// TestIMAPCommandsOnClosedConnection asserts that once the connection is gone
// every command reports the write failure instead of panicking or reporting
// success. A poll can race a server-side idle timeout at any point.
func TestIMAPCommandsOnClosedConnection(t *testing.T) {
	ops := map[string]func(c *imapConn) error{
		"login":  func(c *imapConn) error { return c.login("u", testPassword) },
		"select": func(c *imapConn) error { return c.selectMailbox("INBOX") },
		"search": func(c *imapConn) error { _, err := c.searchUnseen(); return err },
		"fetch":  func(c *imapConn) error { _, err := c.fetchBody("5"); return err },
		"store":  func(c *imapConn) error { return c.storeSeen([]string{"5"}) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			if err := serverConn.Close(); err != nil {
				t.Fatalf("closing the server side: %v", err)
			}
			c := newIMAPConn(clientConn)
			c.close()
			err := mustCompleteWithin(t, watchdog, func() error { return op(c) })
			if err == nil {
				t.Fatalf("%s on a closed connection returned nil", name)
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Errorf("%s error leaks the password: %v", name, err)
			}
		})
	}
}

// TestRedactPassword covers the redaction helper directly, including that it
// leaves the error chain intact when there is nothing to redact.
func TestRedactPassword(t *testing.T) {
	sentinel := errors.New("sentinel")
	if got := redactPassword(nil, "pw"); got != nil {
		t.Errorf("redactPassword(nil) = %v, want nil", got)
	}
	if got := redactPassword(sentinel, ""); !errors.Is(got, sentinel) {
		t.Errorf("redactPassword with an empty password must return the error unchanged, got %v", got)
	}
	if got := redactPassword(sentinel, "pw"); !errors.Is(got, sentinel) {
		t.Errorf("redactPassword with no match must preserve the error chain, got %v", got)
	}
	wrapped := fmt.Errorf("imap: %w", errors.New(`BAD a1 LOGIN "u" "hunter2" is wrong, hunter2`))
	got := redactPassword(wrapped, "hunter2")
	if strings.Contains(got.Error(), "hunter2") {
		t.Errorf("redactPassword left the password in %q", got)
	}
	for _, want := range []string{"BAD", "LOGIN", "[redacted]"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("redactPassword(%q) = %q, want it to keep %q", wrapped, got, want)
		}
	}
}

// TestNumericUID pins the UID validation that keeps a caller-supplied ID from
// injecting a second IMAP command.
func TestNumericUID(t *testing.T) {
	valid := []string{"1", "5", "0", "4294967295", "007"}
	invalid := []string{"", " ", "5 ", " 5", "5,9", "1:*", "-1", "+1", "5\r\nX", "5\n", "0x5", "abc", "٥"}
	for _, s := range valid {
		if !numericUID(s) {
			t.Errorf("numericUID(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if numericUID(s) {
			t.Errorf("numericUID(%q) = true, want false", s)
		}
	}
}
