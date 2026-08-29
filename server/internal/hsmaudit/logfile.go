package hsmaudit

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// The append-only log file is a second, independent copy of the device audit
// log, written as one JSON record per line.
//
// The database already holds that copy, and for the running system it is the
// better one: it is transactional, it carries the collection tail, and it is
// what export and reconciliation read. What it is not is *append-only*. Anyone
// who can reach the database can `UPDATE hsm_log_entries` or `DELETE FROM` it,
// and while the device's own digest chain makes an edit detectable, detection
// requires that somebody still holds an unedited copy to compare against. A
// deletion of the newest rows is not detectable at all from the database alone:
// a shorter chain is a perfectly valid chain.
//
// So the file exists for a threat the database cannot address — the operator
// who holds the database credentials — and it is designed for the two
// mechanisms that actually constrain such an operator:
//
//   - `chattr +a` on Linux (or a WORM mount, or a log shipper tailing the file).
//     An append-only inode cannot be rewritten or truncated even by root
//     without first clearing the attribute, which is itself a privileged,
//     auditable act. This writer therefore only ever appends: it opens with
//     O_APPEND, never seeks, never truncates, and never rewrites a byte it has
//     written.
//   - Off-host shipping. One line per record, self-contained and greppable, is
//     what a syslog/filebeat/vector pipeline can forward the moment it lands,
//     which puts a copy beyond the CA host entirely.
//
// Every record carries the device's own 32-byte log record verbatim, in hex, so
// the file is verifiable on its own terms: VerifyLogFile re-derives the digest
// chain from the raw records without consulting the database, the device, or
// the decoded fields that sit alongside them for human legibility.
//
// The file is not a replacement for the database copy and is deliberately not
// offered as one: the collection tail, the anchor, the ledger and the
// reconciliation all live in the store. It is a witness, and its value is
// precisely that it is written by a different mechanism to a different medium.

// LogFileVersion is the format version stamped into each file's header record.
// A verifier refuses a version it does not know rather than guessing at fields.
const LogFileVersion = 1

// Record types written to the file.
const (
	// RecordTypeHeader opens a file: format version, device, and who opened it.
	RecordTypeHeader = "header"
	// RecordTypeEntry carries one device audit log record.
	RecordTypeEntry = "entry"
	// RecordTypeResume documents a discontinuity: the next entry does not
	// directly follow the previous one in this file. It is written by the
	// writer itself, so the file states where it is incomplete instead of
	// presenting a gap as if it were a continuous run.
	RecordTypeResume = "resume"
)

// Additional Problem kinds reported by VerifyLogFile. The kinds shared with
// segment verification (gap, rewind, digest_mismatch) are reused as-is so a
// single alerting rule matches both.
const (
	// ProblemMalformed means a line could not be parsed as a record of a known
	// type and version. An evidence file with unreadable lines is not evidence.
	ProblemMalformed = "malformed"
	// ProblemDevice means records in one file name more than one device serial,
	// so the file does not describe a single device's history.
	ProblemDevice = "device_mismatch"
	// ProblemRecordMismatch means an entry's decoded fields disagree with the
	// raw 32-byte device record on the same line. The raw record is
	// authoritative; a disagreement means the line was edited by something that
	// did not understand it.
	ProblemRecordMismatch = "record_mismatch"
)

// LogFileRecord is one line of the file.
//
// Entry is a pointer and Raw is the device's own bytes: the pointer keeps
// header and resume records from carrying a spurious all-zero entry, and the
// raw record is what verification actually trusts. The decoded Entry, CommandName
// and Success fields are conveniences for an operator reading or grepping the
// file, and VerifyLogFile checks them against Raw rather than believing them.
type LogFileRecord struct {
	Type    string `json:"type"`
	Version int    `json:"version,omitempty"`
	At      string `json:"at"`
	Device  string `json:"device,omitempty"`
	Writer  string `json:"writer,omitempty"`

	// Raw is the 32-byte device log record in lowercase hex: the 16 field bytes
	// exactly as they arrived on the wire, followed by the 16-byte chain digest.
	Raw string `json:"record,omitempty"`
	// Entry is Raw decoded, for reading.
	Entry *hsm.AuditLogEntry `json:"entry,omitempty"`
	// CommandName names Entry.Command where this build knows it.
	CommandName string `json:"command_name,omitempty"`
	// Success reports whether the device accepted the command (result ==
	// command|0x80) as opposed to rejecting it with an error code.
	Success bool `json:"success,omitempty"`

	// After is the last entry number this file held before a resume, 0 when the
	// file held none. Reason says why the writer could not continue from it.
	After  uint16 `json:"after,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// EntrySink is a durable destination for collected device log records other
// than the Store.
//
// The collector writes every sink *before* it writes the store and long before
// it acknowledges anything on the device, and a sink that returns an error
// stops the drain. That is the same fail-closed rule the rest of the subsystem
// follows: acknowledgement is irreversible, so a copy that was supposed to be
// written and was not must stop the cycle rather than be logged and forgotten.
type EntrySink interface {
	// AppendEntries durably stores entries, which are already verified to
	// continue the chain. serial identifies the device they came from.
	AppendEntries(ctx context.Context, serial string, entries []hsm.AuditLogEntry) error
	// Describe names the sink for log messages and errors.
	Describe() string
}

// LogFile is an append-only EntrySink backed by a file.
type LogFile struct {
	mu   sync.Mutex
	f    *os.File
	path string
	sync bool

	// last is the position this file has reached, so a re-delivered segment is
	// not appended twice and a discontinuity can be documented when it is.
	lastNumber uint16
	lastDigest string
	haveLast   bool
}

// OpenLogFile opens (or creates) the append-only device-log file at path.
//
// The file is opened O_APPEND only. It is never truncated, never seeked, and
// never rewritten, so it keeps working after `chattr +a` — which is the whole
// reason to have it, and which a writer that rewrote a header or rewound to
// deduplicate would break at the first attempt.
//
// On an existing file the last entry is read back so this writer continues
// where the file stopped. The read is bounded to the tail of the file rather
// than a full scan: an evidence file grows without limit, and a CA must not pay
// for its whole history at every start.
func OpenLogFile(path string) (*LogFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("hsm audit log file: no path configured")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("creating the directory for the HSM audit log file: %w", err)
		}
	}
	lf := &LogFile{path: path, sync: true}
	if err := lf.readTail(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("opening the HSM audit log file %s for append: %w", path, err)
	}
	lf.f = f
	if err := lf.writeHeaderIfNew(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return lf, nil
}

// Path returns the file's path.
func (l *LogFile) Path() string { return l.path }

// Describe implements EntrySink.
func (l *LogFile) Describe() string { return "append-only file " + l.path }

// Last reports the entry this file has reached, and whether it holds any.
func (l *LogFile) Last() (number uint16, digest string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastNumber, l.lastDigest, l.haveLast
}

// Close flushes and closes the file.
func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return f.Close()
}

// writeHeaderIfNew stamps a header onto a file that has none.
//
// "Has none" is decided by size, because a header cannot be inserted later
// without rewriting the file, which append-only mode forbids by design. A file
// that already holds records keeps the header it was created with.
func (l *LogFile) writeHeaderIfNew() error {
	st, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", l.path, err)
	}
	if st.Size() > 0 {
		return nil
	}
	return l.write([]LogFileRecord{{
		Type:    RecordTypeHeader,
		Version: LogFileVersion,
		At:      nowUTC(),
		Writer:  LeaseOwner(),
	}})
}

// AppendEntries implements EntrySink.
//
// Entries that this file already holds are dropped rather than appended again:
// a drain whose store write failed re-fetches the same segment on its next
// cycle, and duplicating those lines would make the file's own chain look like
// a rewind. Where the incoming segment does not continue this file — a fresh
// file on a long-running device, or entries that reached the database while the
// file was unavailable — a resume record is written first, so the file admits
// the discontinuity instead of presenting the two runs as contiguous.
func (l *LogFile) AppendEntries(ctx context.Context, serial string, entries []hsm.AuditLogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return fmt.Errorf("hsm audit log file %s is closed", l.path)
	}

	fresh, err := l.trimWritten(entries)
	if err != nil || len(fresh) == 0 {
		return err
	}

	recs := make([]LogFileRecord, 0, len(fresh)+1)
	if reason := l.discontinuity(fresh[0]); reason != "" {
		recs = append(recs, LogFileRecord{
			Type:   RecordTypeResume,
			At:     nowUTC(),
			Device: serial,
			Writer: LeaseOwner(),
			After:  l.lastNumber,
			Reason: reason,
		})
	}
	for _, e := range fresh {
		entry := e
		recs = append(recs, LogFileRecord{
			Type:        RecordTypeEntry,
			At:          nowUTC(),
			Device:      serial,
			Raw:         RawRecordHex(e),
			Entry:       &entry,
			CommandName: hsm.AllCommands[e.Command],
			Success:     e.Result == e.Command|0x80,
		})
	}
	if err := l.write(recs); err != nil {
		return err
	}
	last := fresh[len(fresh)-1]
	l.lastNumber, l.lastDigest, l.haveLast = last.Number, strings.ToLower(last.Hash), true
	return nil
}

// trimWritten drops entries at or behind the file's position, checking that a
// re-delivered entry still says what the file recorded.
//
// A device log record is immutable, so a re-delivery whose digest differs from
// the line already on disk is not a duplicate — it is one of the two copies
// being wrong, and appending it would quietly leave both in the file for
// somebody else to notice later.
func (l *LogFile) trimWritten(entries []hsm.AuditLogEntry) ([]hsm.AuditLogEntry, error) {
	if !l.haveLast || len(entries) == 0 {
		return entries, nil
	}
	for i, e := range entries {
		if e.Number == l.lastNumber {
			if !strings.EqualFold(e.Hash, l.lastDigest) {
				return nil, fmt.Errorf(
					"HSM audit log file %s holds entry %d with digest %s but the device re-delivered it with %s: "+
						"one of the two records is not genuine",
					l.path, e.Number, l.lastDigest, strings.ToLower(e.Hash))
			}
			return entries[i+1:], nil
		}
		if isForward(l.lastNumber, e.Number) && e.Number != l.lastNumber {
			return entries[i:], nil
		}
	}
	return nil, nil
}

// discontinuity returns why first does not continue the file, or "" when it does.
func (l *LogFile) discontinuity(first hsm.AuditLogEntry) string {
	if !l.haveLast {
		if first.Number == 1 && hsm.IsBootSentinel(first) {
			return "" // the file starts at the device-init sentinel: a complete history
		}
		return fmt.Sprintf("file opened at entry %d: entries before it, if any, are only in the database", first.Number)
	}
	if first.Number == nextNumber(l.lastNumber) {
		return ""
	}
	if !isForward(l.lastNumber, first.Number) {
		return fmt.Sprintf("next entry %d is at or behind the last entry %d in this file", first.Number, l.lastNumber)
	}
	return fmt.Sprintf("%d entr(ies) between %d and %d never reached this file",
		gapSize(nextNumber(l.lastNumber), first.Number), l.lastNumber, first.Number)
}

// write appends recs as one write, then flushes to stable storage.
//
// One write call rather than one per record, because two processes may append
// to the same file — the server's collector and an operator's `secsy-ca`
// invocation — and O_APPEND makes a single write atomic against the other
// writer's, which is what keeps their lines from interleaving mid-record.
//
// The fsync is not optional bookkeeping. The collector acknowledges device
// entries once the sinks and the store have taken them, and acknowledgement
// frees the device's only copy; a record still sitting in the page cache when
// the host loses power was never written at all.
func (l *LogFile) write(recs []LogFileRecord) error {
	var buf []byte
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encoding an HSM audit log record: %w", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if _, err := l.f.Write(buf); err != nil {
		return fmt.Errorf("appending to the HSM audit log file %s: %w", l.path, err)
	}
	if !l.sync {
		return nil
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("flushing the HSM audit log file %s: %w", l.path, err)
	}
	return nil
}

// readTail recovers the last entry recorded in an existing file.
//
// It reads a bounded window from the end rather than the whole file. The window
// is generous next to a record — a few hundred bytes — so it holds many lines,
// and if it somehow holds no complete entry record the writer starts from
// "unknown" and documents the discontinuity, which is honest and cheap. Growing
// the window until an entry is found would let a file with a long run of
// non-entry records drag the whole history into memory at startup.
func (l *LogFile) readTail() error {
	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading the HSM audit log file %s: %w", l.path, err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", l.path, err)
	}
	const window = 64 << 10
	offset := int64(0)
	size := st.Size()
	if size > window {
		offset = size - window
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seeking in %s: %w", l.path, err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first && offset > 0 {
			first = false // a partial line: the window started mid-record
			continue
		}
		first = false
		var rec LogFileRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.Type != RecordTypeEntry {
			continue
		}
		e, err := DecodeRawRecord(rec.Raw)
		if err != nil {
			continue
		}
		l.lastNumber, l.lastDigest, l.haveLast = e.Number, e.Hash, true
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the tail of %s: %w", l.path, err)
	}
	return nil
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// RawRecordHex renders the device's own 32-byte log record: the 16 field bytes
// as they arrived on the wire, followed by the 16-byte chain digest.
//
// This is what the file stores and what verification hashes. Storing the wire
// bytes rather than only the decoded fields means a verifier never has to trust
// this build's field layout — it can hash the record and compare against the
// device's digest, byte for byte, with any implementation.
func RawRecordHex(e hsm.AuditLogEntry) string {
	digest, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(e.Hash)))
	if err != nil {
		digest = nil
	}
	return hex.EncodeToString(append(hsm.EntryData(e), digest...))
}

// DecodeRawRecord parses a 32-byte device log record from hex.
func DecodeRawRecord(s string) (hsm.AuditLogEntry, error) {
	var e hsm.AuditLogEntry
	b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(s)))
	if err != nil {
		return e, fmt.Errorf("record is not hex: %w", err)
	}
	if len(b) != 16+DigestLen {
		return e, fmt.Errorf("record is %d bytes, want %d", len(b), 16+DigestLen)
	}
	e.Number = uint16(b[0])<<8 | uint16(b[1])
	e.Command = b[2]
	e.Length = uint16(b[3])<<8 | uint16(b[4])
	e.SessionKey = uint16(b[5])<<8 | uint16(b[6])
	e.TargetKey = uint16(b[7])<<8 | uint16(b[8])
	e.SecondKey = uint16(b[9])<<8 | uint16(b[10])
	e.Result = b[11]
	e.Tick = uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	e.Hash = hex.EncodeToString(b[16:])
	return e, nil
}

// LogFileGap is a discontinuity the file documents about itself.
type LogFileGap struct {
	// After is the last entry number before the break, 0 if the file had none.
	After uint16 `json:"after"`
	// Before is the first entry number after it.
	Before uint16 `json:"before"`
	// Reason is what the writer recorded at the time.
	Reason string `json:"reason"`
}

// LogFileResult is the verdict on an append-only device-log file.
type LogFileResult struct {
	// Path is the file verified.
	Path string `json:"path,omitempty"`
	// Version is the format version from the header record, 0 if there is none.
	Version int `json:"version"`
	// Device is the serial the records name.
	Device string `json:"device,omitempty"`
	// Records, Entries and Signatures count what the file holds.
	Records    int `json:"records"`
	Entries    int `json:"entries"`
	Signatures int `json:"signatures"`
	// First and Last bound the entry numbers present.
	First uint16 `json:"first,omitempty"`
	Last  uint16 `json:"last,omitempty"`
	// Tail is the position the file has reached, for comparison against the
	// database's collection tail.
	Tail Tail `json:"tail"`
	// FromGenesis reports whether the file begins at the device-init sentinel,
	// i.e. holds the device's whole history rather than a suffix of it.
	FromGenesis bool `json:"from_genesis"`
	// Anchor is the chain digest the file's device-init sentinel carries, empty
	// unless FromGenesis. It is the value an auditor compares against the anchor
	// pinned at provisioning: the sentinel's own bytes are a constant on every
	// YubiHSM ever made, so this digest is the only thing in the file that
	// distinguishes one device's history from another's, and it is not derivable
	// from the record it accompanies (see genesis.go).
	Anchor string `json:"anchor,omitempty"`
	// Gaps are the discontinuities the file documents about itself. They are not
	// failures — the writer said so at the time, and the database copy may well
	// cover them — but a file with gaps does not on its own account for the
	// entries inside them.
	Gaps []LogFileGap `json:"gaps,omitempty"`
	// Problems are faults in the file itself: unparseable lines, edited records,
	// a digest chain that does not re-derive, an undocumented gap.
	Problems []Problem `json:"problems,omitempty"`
	// OK is true when there are no Problems: every record parses and the digest
	// chain re-derives across every contiguous run.
	OK bool `json:"ok"`
	// Continuous is true when OK holds and the file documents no gaps.
	Continuous bool `json:"continuous"`
}

// Err renders the verdict as an error, or nil when the file verified.
func (r *LogFileResult) Err() error {
	if r.OK {
		return nil
	}
	parts := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		if p.Number != 0 {
			parts = append(parts, fmt.Sprintf("entry %d: %s (%s)", p.Number, p.Detail, p.Kind))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", p.Detail, p.Kind))
	}
	if len(parts) == 0 {
		return fmt.Errorf("hsm audit log file verification failed")
	}
	return fmt.Errorf("hsm audit log file verification failed: %s", strings.Join(parts, "; "))
}

// VerifyLogFile checks an append-only device-log file on its own terms.
//
// It consults nothing else — not the database, not the device, not the decoded
// fields on each line. Every entry's digest is re-derived from the raw 32-byte
// records, so the file stands or falls by the device's own chain, and an
// auditor holding only this file can run the same check with any
// implementation of SHA-256.
//
// What it cannot do alone is establish that the history is *the device's*: the
// chain anchor is a value only a factory reset produces and only the operator
// recorded (see genesis.go), and no YubiHSM log record carries a serial number
// or a signature. Pass the pinned anchor to bind the file to a known
// provisioning, and see the device commitments in an exported bundle to bind it
// to hardware.
func VerifyLogFile(path string) (*LogFileResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the HSM audit log file: %w", err)
	}
	defer func() { _ = f.Close() }()
	res, err := VerifyLogFileReader(f)
	if res != nil {
		res.Path = path
	}
	return res, err
}

// VerifyLogFileReader is VerifyLogFile over an open reader.
func VerifyLogFileReader(r io.Reader) (*LogFileResult, error) {
	res := &LogFileResult{OK: true}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var prevEntry *hsm.AuditLogEntry
	pendingResume := (*LogFileRecord)(nil)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec LogFileRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			res.fail(Problem{Kind: ProblemMalformed, Detail: fmt.Sprintf("line %d is not a JSON record: %v", line, err)})
			continue
		}
		res.Records++

		switch rec.Type {
		case RecordTypeHeader:
			res.Version = rec.Version
			if rec.Version != LogFileVersion {
				res.fail(Problem{Kind: ProblemMalformed, Detail: fmt.Sprintf(
					"line %d declares format version %d, this build understands %d",
					line, rec.Version, LogFileVersion)})
			}
		case RecordTypeResume:
			pendingResume = &rec
		case RecordTypeEntry:
			e, err := DecodeRawRecord(rec.Raw)
			if err != nil {
				res.fail(Problem{Number: rec.entryNumber(), Kind: ProblemMalformed,
					Detail: fmt.Sprintf("line %d: %v", line, err)})
				continue
			}
			if problem := recordAgreesWithFields(rec, e, line); problem != nil {
				res.fail(*problem)
			}
			res.checkDevice(rec.Device, line)
			res.checkEntry(e, prevEntry, pendingResume, line)
			pendingResume = nil
			prevEntry = &e
		default:
			res.fail(Problem{Kind: ProblemMalformed,
				Detail: fmt.Sprintf("line %d has unknown record type %q", line, rec.Type)})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the HSM audit log file: %w", err)
	}
	if prevEntry != nil {
		res.Last = prevEntry.Number
		res.Tail = Tail{Number: prevEntry.Number, Digest: strings.ToLower(prevEntry.Hash)}
	}
	res.Continuous = res.OK && len(res.Gaps) == 0
	return res, nil
}

// entryNumber reports the decoded entry number where one is present, for
// attributing a problem to a position even when the raw record is unusable.
func (r LogFileRecord) entryNumber() uint16 {
	if r.Entry == nil {
		return 0
	}
	return r.Entry.Number
}

func (r *LogFileResult) fail(p Problem) {
	r.OK = false
	r.Problems = append(r.Problems, p)
}

// checkDevice enforces that one file describes one device.
func (r *LogFileResult) checkDevice(serial string, line int) {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return
	}
	if r.Device == "" {
		r.Device = serial
		return
	}
	if !strings.EqualFold(r.Device, serial) {
		r.fail(Problem{Kind: ProblemDevice, Detail: fmt.Sprintf(
			"line %d names device %s but earlier records name %s: one file, two devices",
			line, serial, r.Device)})
	}
}

// checkEntry verifies one entry against its predecessor.
func (r *LogFileResult) checkEntry(e hsm.AuditLogEntry, prev *hsm.AuditLogEntry, resume *LogFileRecord, line int) {
	r.Entries++
	if _, isSign := hsm.SignCommands[e.Command]; isSign && entrySucceeded(e) {
		r.Signatures++
	}
	if r.Entries == 1 {
		r.First = e.Number
		r.FromGenesis = e.Number == 1 && hsm.IsBootSentinel(e)
		if r.FromGenesis {
			r.Anchor = strings.ToLower(e.Hash)
		}
	}

	if prev == nil {
		// The first entry in the file has nothing to chain from. If it is the
		// device-init sentinel the file holds the whole history; otherwise the
		// writer must have said so, and if it did not, the file is claiming a
		// completeness it cannot have.
		if !r.FromGenesis && resume == nil {
			r.fail(Problem{Number: e.Number, Kind: ProblemGap, Detail: fmt.Sprintf(
				"line %d: the file starts at entry %d without a resume record saying why "+
					"(a file that does not start at the device-init sentinel must document it)", line, e.Number)})
			return
		}
		if resume != nil {
			r.Gaps = append(r.Gaps, LogFileGap{After: resume.After, Before: e.Number, Reason: resume.Reason})
		}
		return
	}

	want := nextNumber(prev.Number)
	if e.Number != want {
		if resume == nil {
			kind := ProblemGap
			detail := fmt.Sprintf("expected entry number %d, got %d: %d entr(ies) are missing from this file "+
				"and nothing records why", want, e.Number, gapSize(want, e.Number))
			if !isForward(want, e.Number) {
				kind = ProblemRewind
				detail = fmt.Sprintf("expected entry number %d, got %d: the file goes backwards "+
					"(an appended replay, or records were removed)", want, e.Number)
			}
			r.fail(Problem{Number: e.Number, Kind: kind, Detail: detail})
			return
		}
		r.Gaps = append(r.Gaps, LogFileGap{After: prev.Number, Before: e.Number, Reason: resume.Reason})
		return
	}

	prevDigest, err := decodeDigest(prev.Hash)
	if err != nil {
		r.fail(Problem{Number: prev.Number, Kind: ProblemDigest, Detail: fmt.Sprintf("unusable digest: %v", err)})
		return
	}
	if got := EntryDigest(e, prevDigest); !strings.EqualFold(got, e.Hash) {
		r.fail(Problem{Number: e.Number, Kind: ProblemDigest, Detail: fmt.Sprintf(
			"chain digest %s does not match %s recomputed from the record: the record was altered",
			strings.ToLower(e.Hash), got)})
	}
}

// recordAgreesWithFields checks the human-readable half of a line against the
// authoritative raw record.
//
// The decoded fields exist so an operator can read and grep the file, which
// means they are also the half somebody is most likely to "fix". Checking them
// costs nothing and turns a silently misleading line into a reported one.
func recordAgreesWithFields(rec LogFileRecord, e hsm.AuditLogEntry, line int) *Problem {
	if rec.Entry == nil || *rec.Entry == e {
		return nil
	}
	var diffs []string
	for _, f := range []struct {
		name      string
		raw, said any
	}{
		{"number", e.Number, rec.Entry.Number},
		{"command", e.Command, rec.Entry.Command},
		{"length", e.Length, rec.Entry.Length},
		{"session_key", e.SessionKey, rec.Entry.SessionKey},
		{"target_key", e.TargetKey, rec.Entry.TargetKey},
		{"second_key", e.SecondKey, rec.Entry.SecondKey},
		{"result", e.Result, rec.Entry.Result},
		{"tick", e.Tick, rec.Entry.Tick},
		{"hash", e.Hash, strings.ToLower(rec.Entry.Hash)},
	} {
		if fmt.Sprint(f.raw) != fmt.Sprint(f.said) {
			diffs = append(diffs, fmt.Sprintf("%s (record says %v, the fields say %v)", f.name, f.raw, f.said))
		}
	}
	return &Problem{Number: e.Number, Kind: ProblemRecordMismatch, Detail: fmt.Sprintf(
		"line %d: the decoded fields disagree with the raw device record on %s",
		line, strings.Join(diffs, ", "))}
}
