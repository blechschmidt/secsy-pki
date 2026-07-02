package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

func sampleEvent() audit.Event {
	return audit.Event{
		Seq:       7,
		ID:        "evt-7",
		Timestamp: time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC),
		Actor:     "alice",
		ActorName: "Alice Example",
		Action:    audit.ActionCertIssue,
		Target:    "42",
		Result:    audit.ResultSuccess,
		IP:        "10.0.0.1",
		PrevHash:  "aaaa",
		Hash:      "bbbb",
	}
}

func TestRFC5424Format(t *testing.T) {
	f, err := NewFormatter(FormatRFC5424, FormatterOptions{Hostname: "pki-host"})
	if err != nil {
		t.Fatal(err)
	}
	out := string(f.Format(sampleEvent()))

	// Facility 13 (log audit) * 8 + severity 6 (informational for success) = 110.
	if !strings.HasPrefix(out, "<110>1 2026-07-02T10:00:00Z pki-host secsy-pki ") {
		t.Errorf("bad RFC5424 header: %q", out)
	}
	for _, want := range []string{
		`[secsyAudit@32473 seq="7"`,
		`actor="alice"`,
		`action="cert.issue"`,
		`target="42"`,
		`result="success"`,
		`hash="bbbb"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RFC5424 output missing %q\nfull: %s", want, out)
		}
	}
	if strings.Contains(out, "\n") {
		t.Error("RFC5424 record must not contain a newline (framing is the sink's job)")
	}
}

func TestRFC5424SeverityByResult(t *testing.T) {
	f, _ := NewFormatter(FormatRFC5424, FormatterOptions{Hostname: "h"})
	e := sampleEvent()
	e.Result = audit.ResultDenied
	// 13*8 + 4 (warning) = 108.
	if got := string(f.Format(e)); !strings.HasPrefix(got, "<108>1 ") {
		t.Errorf("denied should map to warning severity, got %q", got[:12])
	}
	e.Result = audit.ResultError
	// 13*8 + 3 (error) = 107.
	if got := string(f.Format(e)); !strings.HasPrefix(got, "<107>1 ") {
		t.Errorf("error should map to error severity, got %q", got[:12])
	}
}

func TestRFC5424SDEscaping(t *testing.T) {
	f, _ := NewFormatter(FormatRFC5424, FormatterOptions{Hostname: "h"})
	e := sampleEvent()
	e.Detail = `weird ] " \ chars`
	out := string(f.Format(e))
	if !strings.Contains(out, `detail="weird \] \" \\ chars"`) {
		t.Errorf("SD value not escaped correctly: %s", out)
	}
}

func TestCEFFormat(t *testing.T) {
	f, err := NewFormatter(FormatCEF, FormatterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(f.Format(sampleEvent()))

	if !strings.HasPrefix(out, "CEF:0|secsy|secsy-pki|1.0|cert.issue|cert.issue|3|") {
		t.Errorf("bad CEF header: %q", out)
	}
	for _, want := range []string{"suser=alice", "act=cert.issue", "outcome=success", "cn1=7", "cs1=42"} {
		if !strings.Contains(out, want) {
			t.Errorf("CEF output missing %q\nfull: %s", want, out)
		}
	}
}

func TestCEFEscaping(t *testing.T) {
	f, _ := NewFormatter(FormatCEF, FormatterOptions{})
	e := sampleEvent()
	e.Detail = "a=b|c\\d\nnext"
	out := string(f.Format(e))
	if !strings.Contains(out, `msg=a\=b|c\\d\nnext`) {
		t.Errorf("CEF extension value not escaped correctly: %s", out)
	}
	if strings.Contains(out, "\n") {
		t.Error("CEF record must not contain a raw newline")
	}
}

func TestJSONFormatRoundTrips(t *testing.T) {
	f, err := NewFormatter(FormatJSON, FormatterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	src := sampleEvent()
	out := f.Format(src)
	if strings.Contains(string(out), "\n") {
		t.Error("JSON record must not contain a newline (NDJSON framing is the sink's job)")
	}

	var got audit.Event
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("JSON did not round-trip: %v", err)
	}
	if got.Seq != src.Seq || got.Actor != src.Actor || got.Hash != src.Hash || got.Action != src.Action {
		t.Errorf("round-tripped event differs: %+v", got)
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := NewFormatter(Format("xml"), FormatterOptions{}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
