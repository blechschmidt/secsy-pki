package hsmaudit

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// logFilePath returns a path in a fresh temp dir.
func logFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "hsm-audit.jsonl")
}

// readRecords parses every line of a log file.
func readRecords(t *testing.T, path string) []LogFileRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var out []LogFileRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec LogFileRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %q is not a record: %v", line, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return out
}

func appendAll(t *testing.T, l *LogFile, entries []hsm.AuditLogEntry) {
	t.Helper()
	if err := l.AppendEntries(context.Background(), "31650425", entries); err != nil {
		t.Fatalf("appending %d entr(ies): %v", len(entries), err)
	}
}

// The file is the device's own bytes, not this build's rendering of them. A
// verifier has to be able to hash the raw record and get the digest the device
// reported, using nothing from this package — so the round trip through hex has
// to be exact for every field, including the ones that are always 0xffff.
func TestRawRecordRoundTrip(t *testing.T) {
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0x1939))
	for _, e := range entries {
		raw := RawRecordHex(e)
		if len(raw) != 64 {
			t.Fatalf("entry %d renders as %d hex chars, want 64 (32 bytes)", e.Number, len(raw))
		}
		got, err := DecodeRawRecord(raw)
		if err != nil {
			t.Fatalf("entry %d does not decode: %v", e.Number, err)
		}
		if got != e {
			t.Fatalf("entry %d round-tripped to %+v, want %+v", e.Number, got, e)
		}
	}

	// The digest half of the record is the device's commitment, so a verifier
	// with only the raw bytes must be able to re-derive it.
	prev, err := hex.DecodeString(entries[0].Hash)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRawRecord(RawRecordHex(entries[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got := EntryDigest(decoded, prev); !strings.EqualFold(got, decoded.Hash) {
		t.Fatalf("digest re-derived from the raw record is %s, the record says %s", got, decoded.Hash)
	}
}

func TestDecodeRawRecordRejectsGarbage(t *testing.T) {
	for _, tc := range []string{"", "zz", "055f5600220001fe19ffffd60006bc0c"} {
		if _, err := DecodeRawRecord(tc); err == nil {
			t.Errorf("DecodeRawRecord(%q) accepted a record it should have rejected", tc)
		}
	}
}

// The ordinary case: a file opened on a fresh device holds the sentinel and
// everything after it, and verifies as a complete history.
func TestLogFileRecordsAndVerifiesAWholeHistory(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19), signEntry(0x1939))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	appendAll(t, l, entries)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatalf("VerifyLogFile: %v", err)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("a file this writer just wrote does not verify: %v", err)
	}
	if !res.Continuous {
		t.Errorf("the file reports gaps it does not have: %+v", res.Gaps)
	}
	if !res.FromGenesis {
		t.Error("the file starts at the device-init sentinel but does not report it")
	}
	if res.Entries != len(entries) {
		t.Errorf("verification found %d entries, the file holds %d", res.Entries, len(entries))
	}
	if res.Signatures != 3 {
		t.Errorf("verification counted %d signatures, want 3", res.Signatures)
	}
	if res.Device != "31650425" {
		t.Errorf("verification names device %q, want 31650425", res.Device)
	}
	if res.Tail.Number != entries[len(entries)-1].Number {
		t.Errorf("file tail is entry %d, want %d", res.Tail.Number, entries[len(entries)-1].Number)
	}
	if res.Version != LogFileVersion {
		t.Errorf("file declares format version %d, want %d", res.Version, LogFileVersion)
	}
}

// A record's decoded fields are for people; the raw record is the evidence.
// Editing the readable half — the obvious thing for somebody to "correct" — has
// to be reported rather than believed.
func TestLogFileDetectsAnEditedField(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries)
	_ = l.Close()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the target key in the decoded half of the last line only.
	edited := strings.Replace(string(body), `"target_key":65049`, `"target_key":1`, 1)
	if edited == string(body) {
		t.Fatal("test setup: no decoded target_key field to edit")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("an edited record verified")
	}
	if !hasProblem(res.Problems, ProblemRecordMismatch) {
		t.Fatalf("expected a %s problem, got %+v", ProblemRecordMismatch, res.Problems)
	}
}

// Removing a line is the edit the database copy cannot detect at all when it is
// the newest row. In the file it breaks the numbering, and there is no resume
// record to explain it — which is the point of writing resume records at all.
func TestLogFileDetectsARemovedRecord(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19), signEntry(0xfe19))
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries)
	_ = l.Close()

	lines := strings.Split(strings.TrimRight(mustRead(t, path), "\n"), "\n")
	// Drop the middle entry: header, sentinel, [dropped], entry, entry.
	kept := append(append([]string{}, lines[:3]...), lines[4:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a file with a record cut out of it verified")
	}
	if !hasProblem(res.Problems, ProblemGap) {
		t.Fatalf("expected a %s problem, got %+v", ProblemGap, res.Problems)
	}
}

// Altering the raw record itself breaks the device's digest chain, which is the
// check that does not depend on anything this build wrote alongside it.
func TestLogFileDetectsAnAlteredRawRecord(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries)
	_ = l.Close()

	// Swap the command byte in the raw record of the last entry, and its
	// decoded twin, so only the digest chain can object.
	last := entries[len(entries)-1]
	altered := last
	altered.Command = hsm.CmdSignEdDSA
	altered.Result = hsm.CmdSignEdDSA | 0x80
	body := mustRead(t, path)
	body = strings.Replace(body, RawRecordHex(last), RawRecordHex(altered), 1)
	body = strings.Replace(body,
		`"command":`+itoa(int(last.Command)), `"command":`+itoa(int(altered.Command)), 1)
	body = strings.Replace(body,
		`"result":`+itoa(int(last.Result)), `"result":`+itoa(int(altered.Result)), 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a file whose raw record was rewritten verified")
	}
	if !hasProblem(res.Problems, ProblemDigest) {
		t.Fatalf("expected a %s problem, got %+v", ProblemDigest, res.Problems)
	}
}

// A file switched on midway through a device's life cannot claim the history
// before it. It has to say so, in the file, so that a verifier reading only the
// file is not misled into treating a suffix as a complete account.
func TestLogFileDocumentsAMidLifeStart(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19), signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries[2:]) // start at entry 3, not the sentinel
	_ = l.Close()

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("a documented mid-life start should verify, got: %v", err)
	}
	if res.FromGenesis {
		t.Error("a file starting at entry 3 claims to hold the whole history")
	}
	if res.Continuous {
		t.Error("a file that skipped entries 1-2 reports itself as continuous")
	}
	if len(res.Gaps) != 1 || res.Gaps[0].Before != 3 {
		t.Fatalf("expected one documented gap before entry 3, got %+v", res.Gaps)
	}
}

// The same file must not silently present two disjoint runs as one. A drain
// that could not reach the file for a while resumes with a marker, and
// verification reports the gap without failing: the writer was honest, and the
// database copy may well cover it.
func TestLogFileDocumentsAGapBetweenRuns(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19), signEntry(0xfe19), signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries[:2])
	appendAll(t, l, entries[4:]) // entries 3 and 4 never reached the file
	_ = l.Close()

	recs := readRecords(t, path)
	var resumes int
	for _, r := range recs {
		if r.Type == RecordTypeResume {
			resumes++
			if r.After != 2 {
				t.Errorf("resume record says it follows entry %d, want 2", r.After)
			}
		}
	}
	if resumes != 1 {
		t.Fatalf("the writer recorded %d resume marker(s), want 1", resumes)
	}

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("a documented gap should verify, got: %v", err)
	}
	if res.Continuous {
		t.Error("a file with a documented gap reports itself as continuous")
	}
	if len(res.Gaps) != 1 || res.Gaps[0].After != 2 || res.Gaps[0].Before != 5 {
		t.Fatalf("expected one gap 2 -> 5, got %+v", res.Gaps)
	}
}

// A drain whose store write failed re-fetches the same segment next cycle. The
// file must not grow a second copy of those records: duplicated entry numbers
// would read as a rewind, which is what a tampered file looks like.
func TestLogFileIgnoresReDeliveredEntries(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries)
	appendAll(t, l, entries) // the device re-delivers everything it was not told to forget
	_ = l.Close()

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("re-delivery corrupted the file: %v", err)
	}
	if res.Entries != len(entries) {
		t.Fatalf("the file holds %d entries after a re-delivery of %d, want %d",
			res.Entries, len(entries), len(entries))
	}
}

// A re-delivered entry whose content differs is not a duplicate: the device log
// is immutable, so one of the two copies is not genuine. Appending it would
// leave both in the file for somebody else to puzzle over later.
func TestLogFileRejectsAContradictoryReDelivery(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	appendAll(t, l, entries)

	forged := append([]hsm.AuditLogEntry{}, entries...)
	forged[len(forged)-1].Hash = strings.Repeat("ab", DigestLen)
	err = l.AppendEntries(context.Background(), "31650425", forged)
	if err == nil {
		t.Fatal("a re-delivery contradicting the stored record was accepted")
	}
	if !strings.Contains(err.Error(), "not genuine") {
		t.Fatalf("error does not name the contradiction: %v", err)
	}
}

// Restarting the writer must continue the file rather than start a second run
// in it: an unnecessary resume marker would report a gap that never happened,
// and a verifier that learns to expect spurious gaps stops noticing real ones.
func TestLogFileResumesAcrossAReopen(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19), signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries[:2])
	_ = l.Close()

	l2, err := OpenLogFile(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if n, _, ok := l2.Last(); !ok || n != 2 {
		t.Fatalf("reopened file reports last entry %d (present=%v), want 2", n, ok)
	}
	appendAll(t, l2, entries) // the whole segment, including what is already there
	_ = l2.Close()

	res, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("the file does not verify after a reopen: %v", err)
	}
	if !res.Continuous {
		t.Fatalf("reopening the file introduced a gap: %+v", res.Gaps)
	}
	if res.Entries != len(entries) {
		t.Fatalf("the file holds %d entries, want %d", res.Entries, len(entries))
	}
	// One header only: a second one would mean the writer rewrote a file it is
	// supposed to be able to append to under `chattr +a`.
	headers := 0
	for _, r := range readRecords(t, path) {
		if r.Type == RecordTypeHeader {
			headers++
		}
	}
	if headers != 1 {
		t.Fatalf("the file carries %d header records, want 1", headers)
	}
}

// The writer must only ever append. This is what makes `chattr +a` usable, and
// an accidental O_TRUNC or a seek-and-rewrite would be invisible in every other
// test — they all read the file back through the writer's own eyes.
func TestLogFileOnlyAppends(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))

	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries[:2])
	before := mustRead(t, path)
	appendAll(t, l, entries[2:])
	_ = l.Close()

	after := mustRead(t, path)
	if !strings.HasPrefix(after, before) {
		t.Fatal("appending rewrote bytes that were already in the file")
	}
	if len(after) <= len(before) {
		t.Fatal("the second append did not grow the file")
	}

	// And the same across a reopen, which is where a header rewrite would show.
	l2, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	if got := mustRead(t, path); got != after {
		t.Fatal("reopening the file changed its contents")
	}
}

// A verifier reading a file it does not understand must say so rather than
// interpret the fields it happens to recognise.
func TestVerifyLogFileRejectsUnknownFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json", "this is not a record\n"},
		{"unknown type", `{"type":"summary","at":"2026-01-01T00:00:00Z"}` + "\n"},
		{"future version", `{"type":"header","version":99,"at":"2026-01-01T00:00:00Z"}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := VerifyLogFileReader(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("VerifyLogFileReader: %v", err)
			}
			if res.OK {
				t.Fatal("an unreadable file verified")
			}
			if !hasProblem(res.Problems, ProblemMalformed) {
				t.Fatalf("expected a %s problem, got %+v", ProblemMalformed, res.Problems)
			}
		})
	}
}

// One file, one device. Records from a second device in the same file would
// make its entry numbering meaningless — two devices number from 1
// independently — so it is reported rather than silently merged.
func TestVerifyLogFileRejectsTwoDevices(t *testing.T) {
	path := logFilePath(t)
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, entries)
	_ = l.Close()

	body := strings.Replace(mustRead(t, path), `"device":"31650425"`, `"device":"99999999"`, 1)
	res, err := VerifyLogFileReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a file naming two devices verified")
	}
	if !hasProblem(res.Problems, ProblemDevice) {
		t.Fatalf("expected a %s problem, got %+v", ProblemDevice, res.Problems)
	}
}

func TestOpenLogFileRejectsAnEmptyPath(t *testing.T) {
	if _, err := OpenLogFile("  "); err == nil {
		t.Fatal("an empty path was accepted")
	}
}

func TestVerifyLogFileReportsAMissingFile(t *testing.T) {
	_, err := VerifyLogFile(filepath.Join(t.TempDir(), "absent.jsonl"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verifying a missing file gave %v, want a not-exist error", err)
	}
}

// --- collector integration ------------------------------------------------

// The collector's ordering is the whole guarantee: a sink is written before the
// store and long before the device is acknowledged, so a sink failure leaves
// the entries on the device rather than only in the database.
func TestCollectorWritesSinkBeforeStoreAndDevice(t *testing.T) {
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))
	_, dev, store := provisioned(t, entries)

	path := logFilePath(t)
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	c := NewCollector(dev, store, 0, discardLogger())
	c.AddSink(l)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if res.Collected != 2 {
		t.Fatalf("collected %d entries, want 2", res.Collected)
	}

	got, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Err(); err != nil {
		t.Fatalf("the collected file does not verify: %v", err)
	}
	if got.Entries != 2 {
		t.Fatalf("the file holds %d entries, want the 2 that were collected", got.Entries)
	}
	if got.Tail != res.Tail {
		t.Fatalf("the file's tail is %+v but collection reports %+v", got.Tail, res.Tail)
	}
	if got.Device != "31650425" {
		t.Fatalf("the file names device %q, want the device the state is pinned to", got.Device)
	}
}

// A sink that cannot take the records stops the cycle: nothing is acknowledged,
// the store's tail does not move, and the entries stay on the device where the
// next drain finds them. The alternative — carry on and log it — is how a
// deployment ends up believing it has an append-only copy that is missing the
// entries somebody would most want to see.
func TestCollectorFailsClosedWhenASinkFails(t *testing.T) {
	entries := chain(testAnchor, signEntry(0xfe19), signEntry(0xfe19))
	_, dev, store := provisioned(t, entries)
	before := dev.consumed

	c := NewCollector(dev, store, 0, discardLogger())
	c.AddSink(failingSink{})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("collection succeeded although the sink refused the records")
	}

	if dev.consumed != before {
		t.Fatalf("the device was acknowledged up to %d despite the sink failing (was %d)", dev.consumed, before)
	}
	st, err := store.LoadAuditState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Tail.Number != 1 {
		t.Fatalf("the collection tail advanced to %d despite the sink failing", st.Tail.Number)
	}
	stored, err := store.LogEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("the store holds %d entries; the sink failed, so it should still hold only the sentinel", len(stored))
	}

	// And the retry, with a working sink, still collects them.
	c2 := NewCollector(dev, store, 0, discardLogger())
	path := logFilePath(t)
	l, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	c2.AddSink(l)
	res, err := c2.Collect(context.Background())
	if err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if res.Collected != 2 {
		t.Fatalf("the retry collected %d entries, want the 2 the first attempt left behind", res.Collected)
	}
}

type failingSink struct{}

func (failingSink) AppendEntries(context.Context, string, []hsm.AuditLogEntry) error {
	return errors.New("no space left on device")
}
func (failingSink) Describe() string { return "failing test sink" }

// --- helpers --------------------------------------------------------------

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func hasProblem(problems []Problem, kind string) bool {
	for _, p := range problems {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
