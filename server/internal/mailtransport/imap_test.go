package mailtransport

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedIMAPServer drives the server side of a net.Pipe as a minimal IMAP
// server: it reads each client command, echoes the command tag on the tagged
// completion line, and emits the scripted untagged responses (including a
// BODY[] literal for FETCH). It exercises the client's literal + tag handling
// without a live server.
func scriptedIMAPServer(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		tag, cmd := fields[0], strings.ToUpper(fields[1])
		switch {
		case cmd == "SELECT":
			_, _ = conn.Write([]byte("* 3 EXISTS\r\n* OK [UIDVALIDITY 1]\r\n" + tag + " OK [READ-WRITE] SELECT completed\r\n"))
		case cmd == "UID" && strings.Contains(strings.ToUpper(line), "SEARCH"):
			_, _ = conn.Write([]byte("* SEARCH 5 9\r\n" + tag + " OK SEARCH completed\r\n"))
		case cmd == "UID" && strings.Contains(strings.ToUpper(line), "FETCH"):
			resp := "* 1 FETCH (UID 5 BODY[] {" + itoa(len(message)) + "}\r\n" + message + ")\r\n" +
				tag + " OK FETCH completed\r\n"
			_, _ = conn.Write([]byte(resp))
		case cmd == "UID" && strings.Contains(strings.ToUpper(line), "STORE"):
			_, _ = conn.Write([]byte(tag + " OK STORE completed\r\n"))
		default:
			_, _ = conn.Write([]byte(tag + " OK completed\r\n"))
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestIMAPClientFetchParsesLiteral(t *testing.T) {
	// A message body that itself contains a "{n}"-looking token and CRLFs, to
	// confirm the literal is read as raw bytes and not re-parsed line by line.
	message := "From: alice@example.com\r\n" +
		"Subject: Re: ACME: tok\r\n" +
		"In-Reply-To: <mid@pki>\r\n" +
		"\r\n" +
		"-----BEGIN ACME RESPONSE-----\r\n" +
		"AbCd0123_deadbeef {not-a-literal}\r\n" +
		"-----END ACME RESPONSE-----\r\n"

	clientConn, serverConn := net.Pipe()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	go scriptedIMAPServer(t, serverConn, message)

	c := newIMAPConn(clientConn)
	if err := c.selectMailbox("INBOX"); err != nil {
		t.Fatalf("selectMailbox: %v", err)
	}
	uids, err := c.searchUnseen()
	if err != nil {
		t.Fatalf("searchUnseen: %v", err)
	}
	if want := []string{"5", "9"}; !equalStrings(uids, want) {
		t.Fatalf("searchUnseen = %v, want %v", uids, want)
	}
	body, err := c.fetchBody("5")
	if err != nil {
		t.Fatalf("fetchBody: %v", err)
	}
	if string(body) != message {
		t.Fatalf("fetched body mismatch:\n got %q\nwant %q", string(body), message)
	}
	// storeSeen must complete without error against an OK response.
	if err := c.storeSeen([]string{"5", "9"}); err != nil {
		t.Fatalf("storeSeen: %v", err)
	}
	c.close()
}

func TestIMAPClientTaggedError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		line, _ := r.ReadString('\n')
		tag := strings.Fields(strings.TrimRight(line, "\r\n"))[0]
		_, _ = serverConn.Write([]byte(tag + " NO LOGIN failed\r\n"))
	}()
	c := newIMAPConn(clientConn)
	if err := c.login("user", "bad"); err == nil {
		t.Fatal("login against a NO response should error")
	}
	c.close()
}

func TestLiteralSize(t *testing.T) {
	cases := map[string]struct {
		n  int
		ok bool
	}{
		"* 1 FETCH (BODY[] {42}": {42, true},
		"* SEARCH 1 2 3":         {0, false},
		"a1 OK done":             {0, false},
		"trailing {12}":          {12, true},
		"{bad}":                  {0, false},
	}
	for line, want := range cases {
		n, ok := literalSize(line)
		if n != want.n || ok != want.ok {
			t.Errorf("literalSize(%q) = (%d,%v), want (%d,%v)", line, n, ok, want.n, want.ok)
		}
	}
}

func TestQuoteIMAP(t *testing.T) {
	if got := quoteIMAP(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("quoteIMAP = %q", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
