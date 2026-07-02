package siem

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

func twoEvents() []audit.Event {
	base := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	return []audit.Event{
		{Seq: 1, ID: "e1", Timestamp: base, Actor: "root", Action: audit.ActionCAInitRoot, Target: "ca-1", Result: audit.ResultSuccess, Hash: "h1"},
		{Seq: 2, ID: "e2", Timestamp: base.Add(time.Minute), Actor: "alice", Action: audit.ActionCertIssue, Target: "42", Result: audit.ResultSuccess, Hash: "h2"},
	}
}

// TestSyslogSinkOctetCounting delivers a batch to a real TCP listener and checks
// the RFC 6587 octet-counting framing splits the stream into exactly the two
// messages.
func TestSyslogSinkOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var msgs []string
		r := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			msg, err := readOctetFramed(r)
			if err != nil {
				break
			}
			msgs = append(msgs, msg)
		}
		received <- msgs
	}()

	sink, err := NewSyslogSink(SyslogSinkConfig{
		SinkName: "syslog-test",
		Network:  "tcp",
		Address:  ln.Addr().String(),
		Framing:  FramingOctetCounting,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	f, _ := NewFormatter(FormatRFC5424, FormatterOptions{Hostname: "h"})
	if err := sink.Deliver(context.Background(), twoEvents(), f); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	select {
	case msgs := <-received:
		if len(msgs) != 2 {
			t.Fatalf("expected 2 framed messages, got %d: %v", len(msgs), msgs)
		}
		if !strings.Contains(msgs[0], `action="ca.init_root"`) || !strings.Contains(msgs[1], `action="cert.issue"`) {
			t.Errorf("unexpected message content: %v", msgs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for syslog messages")
	}
}

// readOctetFramed reads one RFC 6587 octet-counted frame: "<len> <msg>".
func readOctetFramed(r *bufio.Reader) (string, error) {
	lenField, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenField))
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func TestSyslogSinkLFFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lines []string
		sc := bufio.NewScanner(conn)
		for i := 0; i < 2 && sc.Scan(); i++ {
			lines = append(lines, sc.Text())
		}
		received <- lines
	}()

	sink, err := NewSyslogSink(SyslogSinkConfig{
		SinkName: "syslog-lf",
		Network:  "tcp",
		Address:  ln.Addr().String(),
		Framing:  FramingLF,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	f, _ := NewFormatter(FormatCEF, FormatterOptions{})
	if err := sink.Deliver(context.Background(), twoEvents(), f); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	select {
	case lines := <-received:
		if len(lines) != 2 {
			t.Fatalf("expected 2 LF-delimited lines, got %d: %v", len(lines), lines)
		}
		if !strings.HasPrefix(lines[0], "CEF:0|") {
			t.Errorf("expected CEF line, got %q", lines[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

// TestSyslogSinkDeliverErrorOnClosedCollector verifies Deliver returns an error
// (so the exporter will not advance its cursor) when the collector is gone.
func TestSyslogSinkDeliverErrorOnClosedCollector(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening now

	sink, err := NewSyslogSink(SyslogSinkConfig{
		SinkName: "dead", Network: "tcp", Address: addr, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	f, _ := NewFormatter(FormatRFC5424, FormatterOptions{})
	if err := sink.Deliver(context.Background(), twoEvents(), f); err == nil {
		t.Fatal("expected delivery error against a dead collector")
	}
}

func TestWebhookSinkNDJSON(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("Content-Type = %q", ct)
		}
		if r.Header.Get("X-Token") != "secret" {
			t.Errorf("custom header not forwarded")
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookSinkConfig{
		SinkName: "hook",
		URL:      srv.URL,
		Headers:  map[string]string{"X-Token": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFormatter(FormatJSON, FormatterOptions{})
	if err := sink.Deliver(context.Background(), twoEvents(), f); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(bodies))
	}
	lines := strings.Split(strings.TrimRight(bodies[0], "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %q", len(lines), bodies[0])
	}
}

func TestWebhookSinkErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	sink, _ := NewWebhookSink(WebhookSinkConfig{SinkName: "hook", URL: srv.URL})
	f, _ := NewFormatter(FormatJSON, FormatterOptions{})
	if err := sink.Deliver(context.Background(), twoEvents(), f); err == nil {
		t.Fatal("expected error on 500 response")
	}
}
