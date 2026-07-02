// Package siem streams the tamper-evident audit event log to external Security
// Information and Event Management (SIEM) systems. It provides:
//
//   - pluggable wire formats: RFC 5424 syslog, ArcSight CEF, and
//     newline-delimited JSON;
//   - pluggable transports (sinks): a syslog sink over TCP or TLS and a webhook
//     sink that POSTs NDJSON batches;
//   - an Exporter that streams events forward from a durable per-sink cursor with
//     at-least-once delivery, bounded backpressure, retry with backoff, and
//     Prometheus metrics for lag and failures.
//
// The exporter reads the same hash-chained log written by internal/audit and
// persisted by internal/database. It never mutates the log; it only advances a
// cursor after a sink acknowledges a batch, so no event is lost across restarts.
package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// Format selects the wire encoding a sink emits.
type Format string

const (
	// FormatRFC5424 encodes each event as an RFC 5424 syslog message with the
	// event's fields carried in a STRUCTURED-DATA element.
	FormatRFC5424 Format = "rfc5424"
	// FormatCEF encodes each event as an ArcSight Common Event Format record.
	FormatCEF Format = "cef"
	// FormatJSON encodes each event as a single-line JSON object (NDJSON).
	FormatJSON Format = "json"
)

// FormatterOptions carries the static metadata a formatter stamps onto every
// message (host, app/product identity, enterprise number). Zero values fall back
// to sensible defaults so a minimal config still produces valid output.
type FormatterOptions struct {
	// Hostname is the HOSTNAME field of syslog messages. Defaults to os.Hostname.
	Hostname string
	// AppName is the APP-NAME (RFC 5424) / used as the syslog tag. Default "secsy-pki".
	AppName string
	// EnterpriseID is the IANA Private Enterprise Number used to namespace the
	// RFC 5424 STRUCTURED-DATA SD-ID. Default "32473" (the IANA example PEN).
	EnterpriseID string
	// Facility is the syslog facility (0-23). Default 13 (log audit).
	Facility int
	// CEF vendor/product/version identify the source in CEF headers.
	CEFVendor  string
	CEFProduct string
	CEFVersion string
}

func (o FormatterOptions) withDefaults() FormatterOptions {
	if o.Hostname == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			o.Hostname = h
		} else {
			o.Hostname = "-"
		}
	}
	if o.AppName == "" {
		o.AppName = "secsy-pki"
	}
	if o.EnterpriseID == "" {
		o.EnterpriseID = "32473"
	}
	if o.Facility == 0 {
		o.Facility = 13 // log audit
	}
	if o.CEFVendor == "" {
		o.CEFVendor = "secsy"
	}
	if o.CEFProduct == "" {
		o.CEFProduct = "secsy-pki"
	}
	if o.CEFVersion == "" {
		o.CEFVersion = "1.0"
	}
	return o
}

// Formatter renders one audit event into a single wire record (without any
// transport framing — the sink adds framing). Formatters are stateless and safe
// for concurrent use.
type Formatter interface {
	// Format returns the encoded record for e. The returned bytes never contain a
	// trailing newline; sinks add framing as their transport requires.
	Format(e audit.Event) []byte
	// Name identifies the format for logs and metrics.
	Name() string
}

// NewFormatter returns the Formatter for f, or an error for an unknown format.
func NewFormatter(f Format, opts FormatterOptions) (Formatter, error) {
	opts = opts.withDefaults()
	switch f {
	case FormatRFC5424:
		return &rfc5424Formatter{opts: opts}, nil
	case FormatCEF:
		return &cefFormatter{opts: opts}, nil
	case FormatJSON:
		return &jsonFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown audit export format %q (valid: rfc5424, cef, json)", f)
	}
}

// severityForResult maps an audit result to a syslog severity (0=emerg..7=debug)
// and a CEF severity (0..10). A denied authorization is a security-relevant
// warning; an operation error is an error; success is informational.
func severityForResult(result string) (syslogSev int, cefSev int) {
	switch result {
	case audit.ResultDenied:
		return 4, 6 // warning
	case audit.ResultError:
		return 3, 7 // error
	default:
		return 6, 3 // informational
	}
}

// --- RFC 5424 syslog ---------------------------------------------------------

type rfc5424Formatter struct{ opts FormatterOptions }

func (f *rfc5424Formatter) Name() string { return string(FormatRFC5424) }

// nilIfEmpty renders "-" (RFC 5424 NILVALUE) for an empty field.
func nilIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (f *rfc5424Formatter) Format(e audit.Event) []byte {
	sev, _ := severityForResult(e.Result)
	pri := f.opts.Facility*8 + sev

	var b strings.Builder
	// HEADER: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
	fmt.Fprintf(&b, "<%d>1 %s %s %s %s %s",
		pri,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		nilIfEmpty(f.opts.Hostname),
		nilIfEmpty(f.opts.AppName),
		strconv.Itoa(os.Getpid()),
		nilIfEmpty(e.Action), // MSGID = the action
	)

	// STRUCTURED-DATA: [secsyAudit@<PEN> seq="1" id="..." actor="..." ...]
	b.WriteString(" [secsyAudit@")
	b.WriteString(f.opts.EnterpriseID)
	sd := func(key, val string) {
		if val == "" {
			return
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteString(`="`)
		b.WriteString(escapeSDValue(val))
		b.WriteByte('"')
	}
	b.WriteByte(' ')
	b.WriteString(`seq="`)
	b.WriteString(strconv.FormatInt(e.Seq, 10))
	b.WriteByte('"')
	sd("id", e.ID)
	sd("actor", e.Actor)
	sd("actorName", e.ActorName)
	sd("actorRoles", e.ActorRoles)
	sd("action", e.Action)
	sd("target", e.Target)
	sd("targetName", e.TargetName)
	sd("result", e.Result)
	sd("ip", e.IP)
	sd("requestId", e.RequestID)
	sd("prevHash", e.PrevHash)
	sd("hash", e.Hash)
	sd("detail", e.Detail)
	b.WriteByte(']')

	// MSG: a concise human-readable summary.
	fmt.Fprintf(&b, " %s %s on %s -> %s",
		nilIfEmpty(e.Actor), nilIfEmpty(e.Action), nilIfEmpty(e.Target), nilIfEmpty(e.Result))
	return []byte(b.String())
}

// escapeSDValue escapes the three characters that are special inside an RFC 5424
// SD-PARAM value: '"', '\', and ']'.
func escapeSDValue(s string) string {
	if !strings.ContainsAny(s, `"\]`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// --- CEF ---------------------------------------------------------------------

type cefFormatter struct{ opts FormatterOptions }

func (f *cefFormatter) Name() string { return string(FormatCEF) }

func (f *cefFormatter) Format(e audit.Event) []byte {
	_, sev := severityForResult(e.Result)

	var b strings.Builder
	// Header: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
	b.WriteString("CEF:0|")
	b.WriteString(escapeCEFHeader(f.opts.CEFVendor))
	b.WriteByte('|')
	b.WriteString(escapeCEFHeader(f.opts.CEFProduct))
	b.WriteByte('|')
	b.WriteString(escapeCEFHeader(f.opts.CEFVersion))
	b.WriteByte('|')
	b.WriteString(escapeCEFHeader(nilIfEmpty(e.Action))) // SignatureID
	b.WriteByte('|')
	b.WriteString(escapeCEFHeader(nilIfEmpty(e.Action))) // Name
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(sev))
	b.WriteByte('|')

	// Extension: space-separated key=value pairs. Use CEF standard keys where a
	// sensible mapping exists (rt, suser, act, outcome) plus custom cs* labels.
	ext := func(key, val string) {
		if val == "" {
			return
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(escapeCEFValue(val))
	}
	// rt is milliseconds since the epoch per the CEF spec.
	b.WriteString("rt=")
	b.WriteString(strconv.FormatInt(e.Timestamp.UTC().UnixMilli(), 10))
	ext("suser", e.Actor)
	ext("act", e.Action)
	ext("outcome", e.Result)
	ext("src", e.IP)
	ext("cs1Label", "target")
	ext("cs1", e.Target)
	ext("cs2Label", "targetName")
	ext("cs2", e.TargetName)
	ext("cs3Label", "actorRoles")
	ext("cs3", e.ActorRoles)
	ext("cs4Label", "hash")
	ext("cs4", e.Hash)
	ext("cs5Label", "prevHash")
	ext("cs5", e.PrevHash)
	ext("cn1Label", "seq")
	b.WriteString(" cn1=")
	b.WriteString(strconv.FormatInt(e.Seq, 10))
	ext("requestId", e.RequestID)
	ext("msg", e.Detail)
	return []byte(b.String())
}

// escapeCEFHeader escapes '\' and '|' in a CEF header field.
func escapeCEFHeader(s string) string {
	if !strings.ContainsAny(s, `\|`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '\\' || r == '|' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeCEFValue escapes '\' and '=' and collapses newlines in a CEF extension
// value (a bare newline would be read as the end of the record by many parsers).
func escapeCEFValue(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\', '=':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- JSON --------------------------------------------------------------------

type jsonFormatter struct{}

func (f *jsonFormatter) Name() string { return string(FormatJSON) }

func (f *jsonFormatter) Format(e audit.Event) []byte {
	// audit.Event already carries json tags for every field, including the chain
	// links, so a downstream consumer can re-verify integrity. json.Marshal never
	// emits a newline, keeping the NDJSON framing the sink's responsibility.
	data, err := json.Marshal(e)
	if err != nil {
		// Event contains only strings/ints/time; marshal cannot realistically fail.
		// Fall back to a minimal object so a single bad record never wedges the
		// stream.
		return []byte(fmt.Sprintf(`{"seq":%d,"error":"marshal failed"}`, e.Seq))
	}
	return data
}
