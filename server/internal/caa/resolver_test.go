package caa

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// testQName is the (fully qualified) name every wire-format fixture below asks
// about; SystemResolver is called with the dot-less form so the tests also cover
// the FQDN normalization in query().
const testQName = "host.example.com."

// ---------------------------------------------------------------------------
// wire-format fixtures
//
// Responses are packed on the test goroutine (a server goroutine must never
// call t.Fatalf) and replayed by the fake server with only the query ID patched
// in, see echoID.
// ---------------------------------------------------------------------------

func mustPack(tb testing.TB, m dnsmessage.Message) []byte {
	tb.Helper()
	b, err := m.Pack()
	if err != nil {
		tb.Fatalf("packing test response: %v", err)
	}
	return b
}

// response builds a well-formed reply to a qname/qtype question. Its ID is left
// at zero so parseResponse can be called directly with id=0.
func response(tb testing.TB, qname string, qtype uint16, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
	tb.Helper()
	return mustPack(tb, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RecursionAvailable: true, RCode: rcode},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(qname),
			Type:  dnsmessage.Type(qtype),
			Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	})
}

// truncatedResponse is a reply with the TC bit set, which must make the client
// retry the same query over TCP (RFC 1035 §4.2.1).
func truncatedResponse(tb testing.TB, qname string, qtype uint16, answers ...dnsmessage.Resource) []byte {
	tb.Helper()
	return mustPack(tb, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RecursionAvailable: true, Truncated: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(qname),
			Type:  dnsmessage.Type(qtype),
			Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	})
}

// caaRDATA encodes CAA RDATA per RFC 8659 §4.1: flags, tag length, tag, value.
func caaRDATA(flag byte, tag, value string) []byte {
	rd := append([]byte{flag, byte(len(tag))}, tag...)
	return append(rd, value...)
}

func caaAnswer(name string, ttl uint32, flag byte, tag, value string) dnsmessage.Resource {
	return caaRawAnswer(name, ttl, caaRDATA(flag, tag, value))
}

// caaRawAnswer puts arbitrary bytes in the RDATA of a type-257 record so a test
// can ship RDATA no well-behaved server would ever send.
func caaRawAnswer(name string, ttl uint32, rdata []byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.Type(caaRRType),
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.UnknownResource{Type: dnsmessage.Type(caaRRType), Data: rdata},
	}
}

func cnameAnswer(name string, ttl uint32, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func aAnswer(name string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
	}
}

// ---------------------------------------------------------------------------
// hermetic DNS server
// ---------------------------------------------------------------------------

// dnsHandler produces the reply to one query. network is "udp" or "tcp" and
// query is the raw DNS message (any TCP length prefix already stripped).
// Returning nil sends nothing, which drives the client's timeout path.
type dnsHandler func(network string, query []byte) []byte

// echoID replays a pre-packed message with its ID rewritten to the query's,
// because parseResponse rejects a response whose ID does not match.
func echoID(msg []byte) dnsHandler {
	return func(_ string, query []byte) []byte {
		out := slices.Clone(msg)
		if len(out) >= 2 && len(query) >= 2 {
			copy(out[:2], query[:2])
		}
		return out
	}
}

// fakeDNSConfig is fixed at construction time: the serving goroutines read it
// without synchronization, so nothing may be assigned after newFakeDNS returns.
type fakeDNSConfig struct {
	// udp and tcp answer queries on their transport; a nil handler stays silent.
	udp dnsHandler
	tcp dnsHandler
	// tcpRaw, when set, takes over the accepted connection once the query has
	// been read, so a test can abuse the 2-byte length-prefix framing.
	tcpRaw func(c net.Conn, query []byte)
}

// fakeDNS is a hermetic DNS server bound to one 127.0.0.1 port for *both* UDP
// and TCP: the client dials the same "host:port" for its TCP retry, so the
// truncation fallback can only be exercised with a matching port pair.
type fakeDNS struct {
	addr string
	cfg  fakeDNSConfig

	mu       sync.Mutex
	udpCount int
	tcpCount int
}

func newFakeDNS(t *testing.T, cfg fakeDNSConfig) *fakeDNS {
	t.Helper()
	f := &fakeDNS{cfg: cfg}
	var (
		pc net.PacketConn
		ln net.Listener
	)
	// Take an ephemeral UDP port, then claim the same number on TCP. The two
	// port spaces are independent, so retry if the TCP side is already taken.
	for attempt := 0; attempt < 50; attempt++ {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listening on udp: %v", err)
		}
		addr := c.LocalAddr().String()
		l, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			_ = c.Close()
			continue
		}
		pc, ln, f.addr = c, l, addr
		break
	}
	if pc == nil {
		t.Fatal("could not bind a matching udp/tcp port pair on 127.0.0.1")
	}
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
	})
	go f.serveUDP(pc)
	go f.serveTCP(ln)
	return f
}

func (f *fakeDNS) counts() (udp, tcp int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.udpCount, f.tcpCount
}

func (f *fakeDNS) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return // listener closed by t.Cleanup
		}
		query := slices.Clone(buf[:n])
		f.mu.Lock()
		f.udpCount++
		f.mu.Unlock()
		if f.cfg.udp == nil {
			continue
		}
		if resp := f.cfg.udp("udp", query); resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

func (f *fakeDNS) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed by t.Cleanup
		}
		go f.serveTCPConn(c)
	}
}

func (f *fakeDNS) serveTCPConn(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(c, query); err != nil {
		return
	}
	f.mu.Lock()
	f.tcpCount++
	f.mu.Unlock()

	if f.cfg.tcpRaw != nil {
		f.cfg.tcpRaw(c, query)
		return
	}
	if f.cfg.tcp == nil {
		return
	}
	resp := f.cfg.tcp("tcp", query)
	if resp == nil {
		return
	}
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
	_, _ = c.Write(append(out[:], resp...))
}

func requireErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
}

// ---------------------------------------------------------------------------
// LookupCAA over the network
// ---------------------------------------------------------------------------

// TestSystemResolverLookupCAAOverUDP drives the whole client path — pack, UDP
// exchange, header validation, answer walk, CAA RDATA decode — against crafted
// responses. The resolver deliberately leaves Timeout unset so every case also
// proves timeout() substitutes a usable default (a zero deadline would expire
// before the first datagram left).
func TestSystemResolverLookupCAAOverUDP(t *testing.T) {
	// A response big enough that the client's 1232-byte UDP buffer cannot hold
	// it, yet with TC clear: the datagram is silently cut short, which must not
	// yield a partial RRset (a dropped forbidding record would fail *open*).
	bigAnswers := make([]dnsmessage.Resource, 0, 20)
	for i := 0; i < 20; i++ {
		bigAnswers = append(bigAnswers, caaAnswer(testQName, 300, 0, "issue", strings.Repeat("x", 100)))
	}

	tests := []struct {
		name    string
		handler dnsHandler
		want    []Record
		wantErr string // substring; "" means the lookup must succeed
		anyErr  bool   // an error is required but its text is platform-dependent
	}{
		{
			name: "CAA RRset is decoded and tags are lowercased",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaAnswer(testQName, 300, 0, "ISSUE", caID),
				caaAnswer(testQName, 300, 0, "iodef", "mailto:sec@example.com"),
			)),
			want: []Record{
				{Flag: 0, Tag: TagIssue, Value: caID},
				{Flag: 0, Tag: TagIodef, Value: "mailto:sec@example.com"},
			},
		},
		{
			// The issuer-critical bit decides whether an unknown tag forbids
			// issuance, so it has to survive the wire decode intact.
			name: "issuer-critical flag survives decoding",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaAnswer(testQName, 300, criticalFlag, "mustnot", "x"),
			)),
			want: []Record{{Flag: criticalFlag, Tag: "mustnot", Value: "x"}},
		},
		{
			// `issue ""` authorizes nobody; it must decode cleanly so evaluateSet
			// can treat it as forbidding rather than erroring out.
			name: "empty value decodes to an empty-valued record",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaAnswer(testQName, 300, 0, "issue", ""),
			)),
			want: []Record{{Tag: TagIssue, Value: ""}},
		},
		{
			// Resolvers routinely add unrelated records; they must be skipped
			// rather than break the lookup.
			name: "unrelated answer types are skipped",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				aAnswer(testQName, 60),
				caaAnswer(testQName, 300, 0, "issue", caID),
			)),
			want: []Record{{Tag: TagIssue, Value: caID}},
		},
		{
			// A CNAME shares the answer section on an aliased owner; it must not
			// be mistaken for a CAA record.
			name: "CNAME alongside CAA is not decoded as CAA",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				cnameAnswer(testQName, 60, "web.example.net."),
				caaAnswer("web.example.net.", 300, 0, "issue", caID),
			)),
			want: []Record{{Tag: TagIssue, Value: caID}},
		},
		{
			// NODATA: no CAA here, so the caller must keep climbing the tree.
			name:    "NODATA yields no records and no error",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess)),
			want:    nil,
		},
		{
			name:    "NXDOMAIN yields no records and no error",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeNameError)),
			want:    nil,
		},
		{
			// SERVFAIL leaves authorization undetermined: it must surface as an
			// error so ModeEnforce fails closed.
			name:    "SERVFAIL is an error",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeServerFailure)),
			wantErr: "resolver returned RCodeServerFailure",
		},
		{
			name:    "REFUSED is an error",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeRefused)),
			wantErr: "resolver returned RCodeRefused",
		},
		{
			name:    "FORMERR is an error",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeFormatError)),
			wantErr: "resolver returned RCodeFormatError",
		},
		{
			// An unsolicited/off-path answer must be rejected, not merged into the
			// CAA set.
			name: "response with a mismatched ID is rejected",
			handler: func(_ string, query []byte) []byte {
				out := slices.Clone(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
					caaAnswer(testQName, 300, 0, "issue", "attacker.example.net")))
				if len(query) >= 2 {
					out[0] = query[0] ^ 0xff
					out[1] = query[1] ^ 0xff
				}
				return out
			},
			wantErr: "response id mismatch",
		},
		{
			// A tag length past the end of RDATA must fail the lookup instead of
			// being dropped: dropping it could hide a forbidding record.
			name: "malformed CAA RDATA fails the lookup",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaRawAnswer(testQName, 300, []byte{0x00, 0x09, 'x'}),
			)),
			wantErr: "invalid CAA tag length",
		},
		{
			name: "zero-length CAA RDATA fails the lookup",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaRawAnswer(testQName, 300, nil),
			)),
			wantErr: "RDATA too short",
		},
		{
			name: "zero tag length fails the lookup",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaRawAnswer(testQName, 300, []byte{0x00, 0x00}),
			)),
			wantErr: "invalid CAA tag length",
		},
		{
			name: "one malformed record poisons an otherwise valid RRset",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
				caaAnswer(testQName, 300, 0, "issue", caID),
				caaRawAnswer(testQName, 300, []byte{0x00, 0xff}),
			)),
			wantErr: "invalid CAA tag length",
		},
		{
			name:    "oversized datagram without TC does not yield a partial RRset",
			handler: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess, bigAnswers...)),
			anyErr:  true,
		},
		{
			name:    "an empty datagram is an error",
			handler: func(string, []byte) []byte { return []byte{} },
			anyErr:  true, // a zero-length write may or may not reach the client
		},
		{
			name:    "a garbage datagram is an error",
			handler: func(string, []byte) []byte { return []byte("not a dns message") },
			anyErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDNS(t, fakeDNSConfig{udp: tc.handler})
			r := &SystemResolver{Servers: []string{f.addr}}
			got, err := r.LookupCAA(context.Background(), strings.TrimSuffix(testQName, "."))
			switch {
			case tc.wantErr != "":
				requireErr(t, err, tc.wantErr)
			case tc.anyErr:
				requireErr(t, err, "")
			default:
				if err != nil {
					t.Fatalf("LookupCAA: %v", err)
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("records = %+v, want %+v", got, tc.want)
				}
			}
			if udp, _ := f.counts(); udp == 0 {
				t.Fatalf("the resolver never sent a UDP query")
			}
		})
	}
}

// TestSystemResolverFallsBackToTCPOnTruncation proves a TC response is not
// parsed for answers but re-asked over TCP: the UDP datagram carries a
// *different* issuer than TCP, so a client that used the truncated answer would
// authorize the wrong CA.
func TestSystemResolverFallsBackToTCPOnTruncation(t *testing.T) {
	f := newFakeDNS(t, fakeDNSConfig{
		udp: echoID(truncatedResponse(t, testQName, caaRRType,
			caaAnswer(testQName, 60, 0, "issue", "udp-only.example.net"))),
		tcp: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
			caaAnswer(testQName, 60, 0, "issue", caID),
			caaAnswer(testQName, 60, 0, "iodef", "mailto:sec@example.com"))),
	})
	r := &SystemResolver{Servers: []string{f.addr}, Timeout: 5 * time.Second}

	got, err := r.LookupCAA(context.Background(), strings.TrimSuffix(testQName, "."))
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}
	want := []Record{{Tag: TagIssue, Value: caID}, {Tag: TagIodef, Value: "mailto:sec@example.com"}}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %+v, want the TCP answer %+v", got, want)
	}
	udp, tcp := f.counts()
	if udp != 1 || tcp != 1 {
		t.Fatalf("expected exactly one UDP query and one TCP retry, got udp=%d tcp=%d", udp, tcp)
	}
}

// TestSystemResolverTCPFramingFailures abuses the 2-byte length prefix of the
// TCP retry. Every case must surface an error quickly — a client that blocked
// on a prefix promising more data than the server will ever send would stall
// issuance for the whole request timeout.
func TestSystemResolverTCPFramingFailures(t *testing.T) {
	valid := response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
		caaAnswer(testQName, 60, 0, "issue", caID))

	tests := []struct {
		name string
		raw  func(c net.Conn, query []byte)
	}{
		{
			name: "prefix promises more bytes than are sent",
			raw: func(c net.Conn, _ []byte) {
				_, _ = c.Write([]byte{0x01, 0x00, 'p', 'a', 'r', 't'}) // claims 256 bytes, sends 4
			},
		},
		{
			name: "zero-length prefix",
			raw:  func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0x00, 0x00}) },
		},
		{
			name: "a single prefix byte then close",
			raw:  func(c net.Conn, _ []byte) { _, _ = c.Write([]byte{0x00}) },
		},
		{
			name: "prefix matches but the message is garbage",
			raw: func(c net.Conn, _ []byte) {
				_, _ = c.Write([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
			},
		},
		{
			name: "server closes without answering",
			raw:  func(net.Conn, []byte) {},
		},
		{
			// A prefix declaring 64 KiB with a short body must not make the client
			// wait on a read that will never complete.
			name: "prefix declares the maximum message size",
			raw: func(c net.Conn, _ []byte) {
				_, _ = c.Write([]byte{0xff, 0xff, 0x00})
			},
		},
		{
			// Length prefix shorter than the message: the client must parse only
			// the framed bytes, which cuts the answer section short.
			name: "prefix shorter than the message body",
			raw: func(c net.Conn, _ []byte) {
				var hdr [2]byte
				binary.BigEndian.PutUint16(hdr[:], uint16(len(valid)/2))
				_, _ = c.Write(append(hdr[:], valid...))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDNS(t, fakeDNSConfig{
				udp:    echoID(truncatedResponse(t, testQName, caaRRType)),
				tcpRaw: tc.raw,
			})
			// A generous per-exchange timeout: the assertion below proves the
			// failure came from the framing, not from the deadline.
			r := &SystemResolver{Servers: []string{f.addr}, Timeout: 10 * time.Second}
			start := time.Now()
			_, err := r.LookupCAA(context.Background(), strings.TrimSuffix(testQName, "."))
			elapsed := time.Since(start)
			requireErr(t, err, "")
			if elapsed > 2*time.Second {
				t.Fatalf("framing failure took %v; the client waited for its deadline instead of failing fast", elapsed)
			}
			if _, tcp := f.counts(); tcp != 1 {
				t.Fatalf("expected one TCP retry, got %d", tcp)
			}
		})
	}
}

// TestSystemResolverTriesNextServer proves a silent nameserver does not sink the
// lookup: the client must time out on it and ask the next configured server.
func TestSystemResolverTriesNextServer(t *testing.T) {
	silent := newFakeDNS(t, fakeDNSConfig{udp: func(string, []byte) []byte { return nil }})
	live := newFakeDNS(t, fakeDNSConfig{udp: echoID(response(t, testQName, caaRRType,
		dnsmessage.RCodeSuccess, caaAnswer(testQName, 60, 0, "issue", caID)))})

	r := &SystemResolver{Servers: []string{silent.addr, live.addr}, Timeout: 250 * time.Millisecond}
	got, err := r.LookupCAA(context.Background(), strings.TrimSuffix(testQName, "."))
	if err != nil {
		t.Fatalf("LookupCAA: %v", err)
	}
	if want := []Record{{Tag: TagIssue, Value: caID}}; !slices.Equal(got, want) {
		t.Fatalf("records = %+v, want %+v", got, want)
	}
	if udp, _ := silent.counts(); udp != 1 {
		t.Fatalf("expected the silent server to be tried once, got %d queries", udp)
	}
	if udp, _ := live.counts(); udp != 1 {
		t.Fatalf("expected the second server to be queried once, got %d queries", udp)
	}
}

// TestSystemResolverAllServersFail proves an exhausted server list reports a
// wrapped error (authorization undetermined) rather than an empty RRset, which
// evaluateSet would read as "no CAA policy → permitted".
func TestSystemResolverAllServersFail(t *testing.T) {
	a := newFakeDNS(t, fakeDNSConfig{udp: func(string, []byte) []byte { return nil }})
	b := newFakeDNS(t, fakeDNSConfig{udp: echoID(response(t, testQName, caaRRType, dnsmessage.RCodeServerFailure))})

	r := &SystemResolver{Servers: []string{a.addr, b.addr}, Timeout: 200 * time.Millisecond}
	got, err := r.LookupCAA(context.Background(), strings.TrimSuffix(testQName, "."))
	requireErr(t, err, "all nameservers failed")
	if got != nil {
		t.Fatalf("expected no records with the error, got %+v", got)
	}
	// The last server's failure is the one reported.
	requireErr(t, err, "RCodeServerFailure")
}

// TestSystemResolverHonorsCanceledContext proves the caller's context reaches
// the dialer: an already-canceled context must abort at once instead of burning
// the full per-exchange timeout on every configured server.
func TestSystemResolverHonorsCanceledContext(t *testing.T) {
	f := newFakeDNS(t, fakeDNSConfig{udp: func(string, []byte) []byte { return nil }})
	r := &SystemResolver{Servers: []string{f.addr}, Timeout: 30 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := r.LookupCAA(ctx, strings.TrimSuffix(testQName, "."))
	requireErr(t, err, "")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a canceled context took %v to abort the lookup", elapsed)
	}
}

// TestSystemResolverRejectsUnqueryableNames proves a name that cannot be put on
// the wire fails before any packet is sent (the configured "server" is an
// unbound port, so a dial would produce a different error).
func TestSystemResolverRejectsUnqueryableNames(t *testing.T) {
	tests := []struct {
		name    string
		qname   string
		wantErr string
	}{
		{
			name:    "name longer than the 255-byte wire limit",
			qname:   strings.Repeat("a.", 200),
			wantErr: "invalid DNS name",
		},
		{
			name:    "label longer than 63 bytes",
			qname:   strings.Repeat("a", 64) + ".example.com",
			wantErr: "packing query",
		},
		{
			name:    "empty label inside the name",
			qname:   "host..example.com",
			wantErr: "packing query",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &SystemResolver{Servers: []string{"127.0.0.1:1"}, Timeout: time.Second}
			_, err := r.LookupCAA(context.Background(), tc.qname)
			requireErr(t, err, tc.wantErr)
			if _, cerr := r.LookupCNAME(context.Background(), tc.qname); cerr == nil {
				t.Fatalf("LookupCNAME accepted the unqueryable name %q", tc.qname)
			}
		})
	}
}

// TestSystemResolverLookupCNAME covers the alias lookup that decides which tree
// the CAA search climbs.
func TestSystemResolverLookupCNAME(t *testing.T) {
	tests := []struct {
		name    string
		handler dnsHandler
		want    string
		wantErr string
	}{
		{
			// The evaluation logic compares targets against dot-less names, so the
			// trailing dot has to be stripped here.
			name: "alias target is returned without its trailing dot",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeSuccess,
				cnameAnswer(testQName, 60, "web.example.net."))),
			want: "web.example.net",
		},
		{
			name: "first alias in the chain wins",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeSuccess,
				cnameAnswer(testQName, 60, "one.example.net."),
				cnameAnswer("one.example.net.", 60, "two.example.net."))),
			want: "one.example.net",
		},
		{
			name: "a non-alias name reports no target",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeSuccess,
				aAnswer(testQName, 60))),
			want: "",
		},
		{
			name:    "NODATA reports no target",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeSuccess)),
			want:    "",
		},
		{
			name:    "NXDOMAIN reports no target",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeNameError)),
			want:    "",
		},
		{
			// The root is not a usable alias target; it must come back as "no
			// alias" rather than as a "." name the climb would then normalize.
			name: "a root alias target is reported as no target",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeSuccess,
				cnameAnswer(testQName, 60, "."))),
			want: "",
		},
		{
			name:    "SERVFAIL leaves the alias undetermined",
			handler: echoID(response(t, testQName, uint16(dnsmessage.TypeCNAME), dnsmessage.RCodeServerFailure)),
			wantErr: "RCodeServerFailure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDNS(t, fakeDNSConfig{udp: tc.handler})
			r := &SystemResolver{Servers: []string{f.addr}, Timeout: 5 * time.Second}
			got, err := r.LookupCNAME(context.Background(), strings.TrimSuffix(testQName, "."))
			if tc.wantErr != "" {
				requireErr(t, err, tc.wantErr)
				if got != "" {
					t.Fatalf("expected no target with the error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupCNAME: %v", err)
			}
			if got != tc.want {
				t.Fatalf("target = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSystemResolverTimeoutDefault pins the fallback for an unset Timeout. Zero
// must not reach context.WithTimeout: that deadline is already in the past, so
// every lookup would fail closed before a datagram was sent.
func TestSystemResolverTimeoutDefault(t *testing.T) {
	if got := (&SystemResolver{}).timeout(); got != defaultDNSTimeout {
		t.Fatalf("unset Timeout = %v, want %v", got, defaultDNSTimeout)
	}
	if got := (&SystemResolver{Timeout: -time.Second}).timeout(); got != defaultDNSTimeout {
		t.Fatalf("negative Timeout = %v, want %v", got, defaultDNSTimeout)
	}
	if got := (&SystemResolver{Timeout: 42 * time.Millisecond}).timeout(); got != 42*time.Millisecond {
		t.Fatalf("explicit Timeout = %v, want 42ms", got)
	}
}

// ---------------------------------------------------------------------------
// parseResponse: adversarial wire input
// ---------------------------------------------------------------------------

// rawHeader assembles a 12-byte DNS header. flags is the raw second uint16
// (0x8000 = response, low four bits = RCODE).
func rawHeader(id, flags, qd, an, ns, ar uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:], id)
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint16(h[4:], qd)
	binary.BigEndian.PutUint16(h[6:], an)
	binary.BigEndian.PutUint16(h[8:], ns)
	binary.BigEndian.PutUint16(h[10:], ar)
	return h
}

// rawName encodes a dotted name as length-prefixed labels plus the root byte.
func rawName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

// rawQuestion encodes one question-section entry.
func rawQuestion(name string, qtype uint16) []byte {
	q := rawName(name)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1) // class IN
}

// rawRecord assembles one resource record from a pre-encoded owner name (so a
// test can supply a compression pointer) and an explicit RDLENGTH that need not
// agree with len(rdata).
func rawRecord(name []byte, rrtype uint16, ttl uint32, rdlen uint16, rdata []byte) []byte {
	rr := slices.Clone(name)
	rr = binary.BigEndian.AppendUint16(rr, rrtype)
	rr = binary.BigEndian.AppendUint16(rr, 1) // class IN
	rr = binary.BigEndian.AppendUint32(rr, ttl)
	rr = binary.BigEndian.AppendUint16(rr, rdlen)
	return append(rr, rdata...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

const (
	testID      = uint16(0x1234)
	flagsResp   = uint16(0x8000)
	rrTypeCAA   = uint16(caaRRType)
	rrTypeCNAME = uint16(5)
	rrTypeTXT   = uint16(16)
)

// malformedResponses is the shared corpus of hostile/broken wire input: it backs
// both the table test below and the fuzz seed corpus.
func malformedResponses(tb testing.TB) map[string][]byte {
	tb.Helper()
	q := rawQuestion("host.example.com", rrTypeCAA)
	name := rawName("host.example.com")
	goodCAA := rawRecord(name, rrTypeCAA, 300, 21, caaRDATA(0, "issue", "ca.example.com"))

	return map[string][]byte{
		"empty":                    {},
		"single byte":              {0x01},
		"header one byte short":    rawHeader(testID, flagsResp, 0, 0, 0, 0)[:11],
		"question promised absent": rawHeader(testID, flagsResp, 1, 0, 0, 0),
		// A lying QDCOUNT must be caught while skipping, not looped over.
		"65535 questions promised": concat(rawHeader(testID, flagsResp, 0xffff, 0, 0, 0), q),
		"answer promised absent":   concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q),
		"65535 answers promised":   concat(rawHeader(testID, flagsResp, 1, 0xffff, 0, 0), q, goodCAA),
		// RDLENGTH beyond the buffer: the parser pre-allocates from this field, so
		// it must be validated against the message length.
		"rdlength overflows the message": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeCAA, 300, 0xffff, []byte{0x00, 0x05, 'i'})),
		"rdlength one past the end": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeCAA, 300, 22, caaRDATA(0, "issue", "ca.example.com"))),
		// Compression-pointer loops: a name that points at itself, and a pair that
		// point at each other. Both must terminate with an error.
		"self-referential compression pointer": concat(rawHeader(testID, flagsResp, 0, 1, 0, 0),
			rawRecord([]byte{0xc0, 0x0c}, rrTypeCAA, 300, 2, []byte{0x00, 0x00})),
		"two pointers in a loop": concat(rawHeader(testID, flagsResp, 0, 1, 0, 0),
			rawRecord([]byte{0xc0, 0x0e}, 0xc00c, 300, 2, []byte{0x00, 0x00})),
		"pointer past the end of the message": concat(rawHeader(testID, flagsResp, 0, 1, 0, 0),
			rawRecord([]byte{0xc0, 0xfe}, rrTypeCAA, 300, 2, []byte{0x00, 0x00})),
		"reserved label prefix": concat(rawHeader(testID, flagsResp, 0, 1, 0, 0),
			rawRecord([]byte{0x80, 0x00}, rrTypeCAA, 300, 2, []byte{0x00, 0x00})),
		"label length past the end": concat(rawHeader(testID, flagsResp, 0, 1, 0, 0), []byte{0x3f}),
		// Skipping a question never follows its compression pointer, so a
		// self-referential one is inert — but it must still leave the parser
		// positioned correctly for the answer walk.
		"self-pointer in the question name": concat(rawHeader(testID, flagsResp, 1, 0, 0, 0),
			[]byte{0xc0, 0x0c}, []byte{0x01, 0x01, 0x00, 0x01}),
		"cname rdata name runs past the end": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeCNAME, 300, 4, []byte{0x3f, 'a', 'b', 'c'})),
		"cname rdata pointer loop": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeCNAME, 300, 2, []byte{0xc0, byte(12 + len(q) + len(name) + 10)})),
		"servfail":         concat(rawHeader(testID, flagsResp|0x0002, 1, 0, 0, 0), q),
		"refused":          concat(rawHeader(testID, flagsResp|0x0005, 1, 0, 0, 0), q),
		"unassigned rcode": concat(rawHeader(testID, flagsResp|0x000f, 1, 0, 0, 0), q),
		"id mismatch":      concat(rawHeader(testID+1, flagsResp, 1, 0, 0, 0), q),
		// Well-formed shapes worth keeping in the corpus.
		"nodata":              concat(rawHeader(testID, flagsResp, 1, 0, 0, 0), q),
		"nxdomain":            concat(rawHeader(testID, flagsResp|0x0003, 1, 0, 0, 0), q),
		"valid caa":           concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q, goodCAA),
		"zero rdlength caa":   concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q, rawRecord(name, rrTypeCAA, 300, 0, nil)),
		"rdlength under-runs": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q, rawRecord(name, rrTypeCAA, 300, 2, []byte{0x00, 0x05, 'i', 's', 's', 'u', 'e'})),
		// SkipAnswer must not validate the RDATA of a type we ignore, or an
		// unrelated (here: bogus) TXT record would break every CAA lookup.
		"ignored type with bogus rdata": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeTXT, 300, 3, []byte{0xff, 'a', 'b'})),
		// Skipping still has to respect the buffer: an ignored type whose RDLENGTH
		// runs past the end must fail rather than skip out of bounds.
		"ignored type with rdlength past the end": concat(rawHeader(testID, flagsResp, 1, 1, 0, 0), q,
			rawRecord(name, rrTypeTXT, 300, 0xffff, []byte{'a', 'b'})),
		"garbage after a zero answer count": concat(rawHeader(testID, flagsResp, 1, 0, 0, 0), q,
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff}),
	}
}

// TestParseResponseHostileInput drives the response parser with hand-built wire
// bytes. Every case must terminate with either an error or a self-consistent
// answer set; a hang (pointer loop) or panic (length overflow) here would take
// down issuance for every request.
func TestParseResponseHostileInput(t *testing.T) {
	corpus := malformedResponses(t)

	// Cases that must parse, with the number of answers parseResponse keeps.
	wantOK := map[string]int{
		"nodata":                            0,
		"nxdomain":                          0,
		"valid caa":                         1,
		"zero rdlength caa":                 1,
		"rdlength under-runs":               1, // trailing RDATA bytes are simply ignored
		"ignored type with bogus rdata":     0,
		"garbage after a zero answer count": 0,
		"self-pointer in the question name": 0,
	}

	names := make([]string, 0, len(corpus))
	for name := range corpus {
		names = append(names, name)
	}
	slices.Sort(names) // deterministic subtest order

	for _, name := range names {
		msg := corpus[name]
		t.Run(name, func(t *testing.T) {
			answers, _, err := parseResponse(msg, testID, rrTypeCAA)
			wantAnswers, ok := wantOK[name]
			if !ok {
				requireErr(t, err, "")
				if answers != nil {
					t.Fatalf("expected no answers with the error, got %+v", answers)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			if len(answers) != wantAnswers {
				t.Fatalf("parsed %d answers, want %d", len(answers), wantAnswers)
			}
			for i, a := range answers {
				if a.Body == nil {
					t.Fatalf("answer %d has a nil body", i)
				}
			}
		})
	}
}

// TestParseResponseTruncatedAtEveryOffset feeds every prefix of a well-formed
// response — the shape a datagram cut short by the network takes — and requires
// a clean error or a strictly smaller, still-consistent answer set. A prefix
// must never yield the full RRset, because a missing record can be the one that
// forbids issuance.
func TestParseResponseTruncatedAtEveryOffset(t *testing.T) {
	full := response(t, testQName, caaRRType, dnsmessage.RCodeSuccess,
		caaAnswer(testQName, 300, 0, "issue", caID),
		cnameAnswer(testQName, 60, "web.example.net."),
		caaAnswer(testQName, 120, 0, "iodef", "mailto:sec@example.com"),
	)
	want, _, err := parseResponse(full, 0, rrTypeCAA)
	if err != nil {
		t.Fatalf("the unmodified response must parse: %v", err)
	}
	if len(want) != 3 {
		t.Fatalf("fixture parsed %d answers, want 3", len(want))
	}

	for n := 0; n < len(full); n++ {
		answers, _, err := parseResponse(full[:n], 0, rrTypeCAA)
		if err != nil {
			continue // a short message must fail, which it did
		}
		if len(answers) >= len(want) {
			t.Fatalf("prefix of %d/%d bytes yielded %d answers; a truncated message must not look complete",
				n, len(full), len(answers))
		}
		for i, a := range answers {
			if a.Body == nil {
				t.Fatalf("prefix of %d bytes: answer %d has a nil body", n, i)
			}
		}
	}
}

// TestParseResponseMinimumTTL pins the reported TTL to the smallest one in the
// answer set: that value bounds how long the answer may be reused, and a
// legitimate TTL of 0 ("do not cache") must win rather than read as "unset".
func TestParseResponseMinimumTTL(t *testing.T) {
	tests := []struct {
		name    string
		answers []dnsmessage.Resource
		want    uint32
	}{
		{
			name:    "no answers",
			answers: nil,
			want:    0,
		},
		{
			name:    "single answer",
			answers: []dnsmessage.Resource{caaAnswer(testQName, 300, 0, "issue", caID)},
			want:    300,
		},
		{
			name: "smallest of several",
			answers: []dnsmessage.Resource{
				caaAnswer(testQName, 300, 0, "issue", caID),
				caaAnswer(testQName, 60, 0, "iodef", "mailto:sec@example.com"),
				caaAnswer(testQName, 900, 0, "issuewild", caID),
			},
			want: 60,
		},
		{
			name: "a zero TTL is the minimum, not a missing value",
			answers: []dnsmessage.Resource{
				caaAnswer(testQName, 300, 0, "issue", caID),
				caaAnswer(testQName, 0, 0, "iodef", "mailto:sec@example.com"),
			},
			want: 0,
		},
		{
			name:    "a lone zero TTL",
			answers: []dnsmessage.Resource{caaAnswer(testQName, 0, 0, "issue", caID)},
			want:    0,
		},
		{
			// Skipped record types are not part of the answer the caller keeps, so
			// their TTL must not shorten it.
			name: "ignored answer types do not contribute their TTL",
			answers: []dnsmessage.Resource{
				aAnswer(testQName, 5),
				caaAnswer(testQName, 300, 0, "issue", caID),
			},
			want: 300,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := response(t, testQName, caaRRType, dnsmessage.RCodeSuccess, tc.answers...)
			_, ttl, err := parseResponse(msg, 0, rrTypeCAA)
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			if ttl != tc.want {
				t.Fatalf("minimum TTL = %d, want %d", ttl, tc.want)
			}
		})
	}
}

// FuzzParseResponse drives the response parser with arbitrary bytes. DNS
// responses are unauthenticated network input on the pre-issuance path, so the
// parser must never panic or hang, and anything it hands back must be safe to
// walk: LookupCAA type-asserts the body and slices the RDATA of every answer it
// keeps.
func FuzzParseResponse(f *testing.F) {
	for _, msg := range malformedResponses(f) {
		f.Add(msg)
	}
	f.Add(mustPack(f, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(testQName),
			Type:  dnsmessage.Type(caaRRType),
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{
			caaAnswer(testQName, 300, 0, "issue", caID),
			cnameAnswer(testQName, 60, "web.example.net."),
			aAnswer(testQName, 60),
		},
	}))
	f.Add([]byte(nil))
	f.Add([]byte("not a dns message at all"))

	f.Fuzz(func(t *testing.T, msg []byte) {
		answers, ttl, err := parseResponse(msg, testID, rrTypeCAA)
		if err != nil {
			if answers != nil || ttl != 0 {
				t.Fatalf("parseResponse returned %d answers and ttl=%d alongside an error: %v", len(answers), ttl, err)
			}
			return
		}
		for i, a := range answers {
			if a.Body == nil {
				t.Fatalf("answer %d has a nil body", i)
			}
			// parseResponse must only keep the two types its callers know how to
			// interpret; anything else would reach a caller unprepared for it.
			switch a.Header.Type {
			case dnsmessage.Type(caaRRType):
				u, ok := a.Body.(*dnsmessage.UnknownResource)
				if !ok {
					t.Fatalf("answer %d is typed CAA but carries %T", i, a.Body)
				}
				// The same call LookupCAA makes: it must not panic on any RDATA.
				if rec, derr := decodeCAARDATA(u.Data); derr == nil && rec.Tag == "" {
					t.Fatalf("answer %d decoded to a record with no tag: %+v", i, rec)
				}
			case dnsmessage.TypeCNAME:
				c, ok := a.Body.(*dnsmessage.CNAMEResource)
				if !ok {
					t.Fatalf("answer %d is typed CNAME but carries %T", i, a.Body)
				}
				_ = c.CNAME.String()
			default:
				t.Fatalf("answer %d has unexpected type %v", i, a.Header.Type)
			}
		}
	})
}

// FuzzDecodeCAARDATA drives the CAA RDATA decoder directly: it slices the buffer
// using a length byte taken straight off the wire.
func FuzzDecodeCAARDATA(f *testing.F) {
	f.Add(caaRDATA(0, "issue", "ca.example.com"))
	f.Add(caaRDATA(criticalFlag, "issuewild", ""))
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0xff, 'x'})
	f.Add([]byte{0xff, 0x01, 'a', 'b', 'c'})

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := decodeCAARDATA(data)
		if err != nil {
			return
		}
		if rec.Tag == "" {
			t.Fatalf("decoded an empty tag from %v", data)
		}
		// Tags are matched against lowercase constants (knownTag), so an uppercase
		// letter surviving the decode would make a known tag look unknown.
		if strings.IndexFunc(rec.Tag, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 {
			t.Fatalf("tag %q was not lowercased for case-insensitive matching", rec.Tag)
		}
		// The value must be the exact RDATA tail after flags, tag length and tag.
		// Losing bytes here could strip an RFC 8657 parameter and turn a record
		// that forbids issuance into one that authorizes it.
		if want := string(data[2+int(data[1]):]); rec.Value != want {
			t.Fatalf("value = %q, want the RDATA tail %q", rec.Value, want)
		}
		if rec.Flag != data[0] {
			t.Fatalf("flags = %#x, want %#x (the issuer-critical bit decides whether an unknown tag forbids issuance)", rec.Flag, data[0])
		}
	})
}

// ---------------------------------------------------------------------------
// resolv.conf parsing
// ---------------------------------------------------------------------------

// TestResolvConfServers covers the nameserver extraction that decides whether
// the CAA gate has anywhere to ask. A file it cannot read fully must produce an
// error rather than a short server list, because an empty list would silently
// leave every lookup undetermined.
func TestResolvConfServers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{
			name: "nameservers in order, other directives ignored",
			content: "# managed file\n" +
				"; another comment style\n" +
				"search example.com\n" +
				"nameserver 192.0.2.1\n" +
				"options edns0 trust-ad\n" +
				"nameserver 192.0.2.2\n",
			want: []string{"192.0.2.1:53", "192.0.2.2:53"},
		},
		{
			// An IPv6 nameserver must come back bracketed, or the dial would fail.
			name:    "IPv6 nameserver is bracketed",
			content: "nameserver ::1\nnameserver fe80::1\n",
			want:    []string{"[::1]:53", "[fe80::1]:53"},
		},
		{
			name:    "tabs and trailing whitespace are tolerated",
			content: "\tnameserver\t192.0.2.3   \n",
			want:    []string{"192.0.2.3:53"},
		},
		{
			// resolv.conf files written with CRLF endings appear in containers and
			// VPN-managed setups; a stray \r would break the dial address.
			name:    "CRLF line endings",
			content: "nameserver 192.0.2.4\r\nnameserver 192.0.2.5\r\n",
			want:    []string{"192.0.2.4:53", "192.0.2.5:53"},
		},
		{
			name:    "a nameserver directive with no address is skipped",
			content: "nameserver\nnameserver 192.0.2.6\n",
			want:    []string{"192.0.2.6:53"},
		},
		{
			name:    "a commented-out nameserver is not used",
			content: "#nameserver 192.0.2.7\n; nameserver 192.0.2.8\n",
			want:    nil,
		},
		{
			name:    "no nameserver at all",
			content: "search example.com\noptions ndots:1\n",
			want:    nil,
		},
		{
			name:    "empty file",
			content: "",
			want:    nil,
		},
		{
			// bufio.Scanner refuses tokens over 64 KiB; that error must not be
			// swallowed into a truncated (here: empty) server list.
			name:    "a line beyond the scanner limit is an error",
			content: "nameserver 192.0.2.9\n" + strings.Repeat("x", 70000) + "\nnameserver 192.0.2.10\n",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("writing fixture: %v", err)
			}
			got, err := resolvConfServers(path)
			if tc.wantErr {
				requireErr(t, err, "")
				if got != nil {
					t.Fatalf("expected no servers with the error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvConfServers: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("servers = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		got, err := resolvConfServers(filepath.Join(t.TempDir(), "absent"))
		requireErr(t, err, "")
		if got != nil {
			t.Fatalf("expected no servers, got %v", got)
		}
	})

	t.Run("path is a directory", func(t *testing.T) {
		// os.Open succeeds on a directory, so only the scanner's error keeps this
		// from looking like "a valid file with no nameservers".
		got, err := resolvConfServers(t.TempDir())
		requireErr(t, err, "")
		if got != nil {
			t.Fatalf("expected no servers, got %v", got)
		}
	})
}

// TestNewSystemResolverUsesResolvConf pins the constructor to the system file
// without touching the network: either it agrees with the parsed file, or — when
// there is nothing usable to parse — it fails instead of handing back a resolver
// that would never dial anything. servers() must reach the same conclusion for a
// resolver with no explicit list.
func TestNewSystemResolverUsesResolvConf(t *testing.T) {
	want, parseErr := resolvConfServers("/etc/resolv.conf")

	r, err := NewSystemResolver()
	fromEmpty, emptyErr := (&SystemResolver{}).servers()

	if parseErr != nil || len(want) == 0 {
		if err == nil {
			t.Fatalf("expected an error with no usable /etc/resolv.conf, got servers %v", r.Servers)
		}
		if emptyErr == nil {
			t.Fatalf("servers() returned %v with no usable /etc/resolv.conf", fromEmpty)
		}
		return
	}

	if err != nil {
		t.Fatalf("NewSystemResolver: %v", err)
	}
	if !slices.Equal(r.Servers, want) {
		t.Fatalf("servers = %v, want %v", r.Servers, want)
	}
	if emptyErr != nil {
		t.Fatalf("servers(): %v", emptyErr)
	}
	if !slices.Equal(fromEmpty, want) {
		t.Fatalf("servers() = %v, want %v", fromEmpty, want)
	}
	for _, s := range r.Servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			t.Fatalf("server %q is not a dialable host:port: %v", s, err)
		}
	}
}

// TestSystemResolverServersPrefersExplicitList proves an explicit list short-
// circuits /etc/resolv.conf, so a configured resolver cannot be overridden by
// the host's DNS settings.
func TestSystemResolverServersPrefersExplicitList(t *testing.T) {
	r := &SystemResolver{Servers: []string{"192.0.2.53:53"}}
	got, err := r.servers()
	if err != nil {
		t.Fatalf("servers(): %v", err)
	}
	if !slices.Equal(got, r.Servers) {
		t.Fatalf("servers() = %v, want the configured %v", got, r.Servers)
	}
}
