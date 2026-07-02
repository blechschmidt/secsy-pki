//go:build sqlite

package siem

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// TestExporterEndToEndSyslog wires the real database (as event source and cursor
// store), the streaming exporter, and a real TCP syslog listener together, to
// prove events written to the hash-chained log are delivered downstream and the
// durable cursor advances — the full "sink delivery" path the task requires.
func TestExporterEndToEndSyslog(t *testing.T) {
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Seal a few real audit events into the chain.
	const n = 5
	for i := 0; i < n; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: "evt", Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A TCP collector that reads octet-counted frames.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		count := 0
		for count < n {
			if _, err := readOctetFramed(r); err != nil {
				break
			}
			count++
		}
		got <- count
	}()

	sink, err := NewSyslogSink(SyslogSinkConfig{
		SinkName: "collector", Network: "tcp", Address: ln.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFormatter(FormatRFC5424, FormatterOptions{Hostname: "pki"})
	exp := NewExporter(db, db, []boundSink{BindSink(sink, f)}, fastOpts())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { exp.Run(ctx); close(done) }()

	select {
	case c := <-got:
		if c != n {
			t.Fatalf("collector received %d frames, want %d", c, n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}

	// The durable cursor must have advanced to the head of the chain.
	waitFor(t, 2*time.Second, func() bool {
		c, _ := db.GetSIEMCursor("collector")
		return c == int64(n)
	})
	cancel()
	<-done

	// A restart must not re-deliver already-acknowledged events.
	c, _ := db.GetSIEMCursor("collector")
	rest, _ := db.ListEventsSince(c, 0)
	if len(rest) != 0 {
		t.Errorf("cursor at %d leaves %d undelivered; expected caught up", c, len(rest))
	}
	if !strings.HasPrefix(f.Name(), "rfc5424") {
		t.Fatalf("unexpected formatter %s", f.Name())
	}
}
