package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS is a minimal authoritative nameserver for tests: it answers SOA
// queries (so zone discovery works) and applies TSIG-authenticated RFC 2136
// UPDATE messages to an in-memory record set. Crucially, its TSIG verification
// is an INDEPENDENT re-implementation of the wire format — it does not call the
// provider's signing helpers — so a bug in the provider's UPDATE/TSIG encoding
// surfaces as a MAC mismatch here.
type fakeDNS struct {
	zone    string // apex, e.g. "example.com."
	keyName string // canonical TSIG key name
	secret  []byte

	conn *net.UDPConn

	mu       sync.Mutex
	records  map[string]int // "name|value" -> count present
	updates  int            // successfully applied UPDATEs
	authFail int            // UPDATEs rejected for a bad TSIG
}

func newFakeDNS(t *testing.T, zone, keyName string, secret []byte) *fakeDNS {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	f := &fakeDNS{
		zone:    canonicalDNSName(zone),
		keyName: canonicalDNSName(keyName),
		secret:  secret,
		conn:    pc,
		records: make(map[string]int),
	}
	go f.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return f
}

func (f *fakeDNS) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeDNS) has(name, value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[canonicalDNSName(name)+"|"+value] > 0
}

func (f *fakeDNS) authFailures() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authFail
}

func (f *fakeDNS) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

func (f *fakeDNS) serve() {
	buf := make([]byte, 4096)
	for {
		n, src, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		if resp := f.handle(req); resp != nil {
			_, _ = f.conn.WriteToUDP(resp, src)
		}
	}
}

func (f *fakeDNS) handle(req []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	switch h.OpCode {
	case dnsmessage.OpCode(opcodeUpdate):
		return f.handleUpdate(req, h.ID)
	case 0:
		return f.handleQuery(&p, h.ID)
	default:
		return nil
	}
}

func (f *fakeDNS) handleUpdate(req []byte, id uint16) []byte {
	if !f.verifyTSIG(req) {
		f.mu.Lock()
		f.authFail++
		f.mu.Unlock()
		return responseHeaderRcode(id, 9) // NOTAUTH
	}
	var p dnsmessage.Parser
	if _, err := p.Start(req); err != nil {
		return responseHeaderRcode(id, 1)
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers() // prerequisites (none)
	for {
		ah, err := p.AuthorityHeader()
		if err != nil {
			break // ErrSectionDone
		}
		if ah.Type != dnsmessage.TypeTXT {
			_ = p.SkipAuthority()
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			break
		}
		key := canonicalDNSName(ah.Name.String()) + "|" + strings.Join(txt.TXT, "")
		f.mu.Lock()
		if ah.Class == dnsmessage.Class(classNone) {
			delete(f.records, key)
		} else {
			f.records[key]++
		}
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.updates++
	f.mu.Unlock()
	return responseHeaderRcode(id, 0)
}

func (f *fakeDNS) handleQuery(p *dnsmessage.Parser, id uint16) []byte {
	q, err := p.Question()
	if err != nil {
		return responseHeaderRcode(id, 0)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess})
	_ = b.StartQuestions()
	_ = b.Question(q)
	if q.Type == dnsmessage.TypeSOA && canonicalDNSName(q.Name.String()) == f.zone {
		_ = b.StartAnswers()
		zoneName, _ := dnsmessage.NewName(f.zone)
		ns, _ := dnsmessage.NewName("ns1." + f.zone)
		mbox, _ := dnsmessage.NewName("hostmaster." + f.zone)
		_ = b.SOAResource(
			dnsmessage.ResourceHeader{Name: zoneName, Class: dnsmessage.ClassINET, TTL: 3600},
			dnsmessage.SOAResource{NS: ns, MBox: mbox, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: 60},
		)
	}
	msg, _ := b.Finish()
	return msg
}

// verifyTSIG independently re-derives and checks the request MAC.
func (f *fakeDNS) verifyTSIG(req []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(req); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	if err := p.SkipAllAnswers(); err != nil {
		return false
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return false
	}
	ah, err := p.AdditionalHeader()
	if err != nil || ah.Type != dnsmessage.Type(tsigRRType) {
		return false
	}
	u, err := p.UnknownResource()
	if err != nil {
		return false
	}
	rdata := u.Data

	// Locate the TSIG RR in the raw message: it is the last record, and carries
	// no compression, so its wire length is deterministic.
	tsigWireLen := len(indepEncodeName(ah.Name.String())) + 10 + len(rdata)
	if tsigWireLen > len(req) {
		return false
	}
	tsigStart := len(req) - tsigWireLen
	signed := append([]byte(nil), req[:tsigStart]...)
	binary.BigEndian.PutUint16(signed[10:12], binary.BigEndian.Uint16(signed[10:12])-1)

	algo, timeSigned, fudge, mac, _, errCode, other, ok := indepParseTSIGRData(rdata)
	if !ok {
		return false
	}
	if canonicalDNSName(ah.Name.String()) != f.keyName {
		return false
	}
	newHash := indepHashFor(algo)
	if newHash == nil {
		return false
	}
	m := hmac.New(newHash, f.secret)
	m.Write(signed)
	m.Write(indepTSIGVariables(ah.Name.String(), algo, timeSigned, fudge, errCode, other))
	return hmac.Equal(m.Sum(nil), mac)
}

// responseHeaderRcode builds a header-only UPDATE response with the given rcode.
func responseHeaderRcode(id uint16, rcode uint16) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:       id,
		Response: true,
		OpCode:   dnsmessage.OpCode(opcodeUpdate),
		RCode:    dnsmessage.RCode(rcode),
	})
	msg, _ := b.Finish()
	return msg
}

// ---- independent TSIG wire helpers (do not call production code) ----

func indepEncodeName(name string) []byte {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []byte{0}
	}
	var b []byte
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func indepTSIGVariables(keyName, algo string, timeSigned uint64, fudge, errCode uint16, other []byte) []byte {
	var b []byte
	b = append(b, indepEncodeName(keyName)...)
	b = append(b, 0x00, 0xFF) // CLASS ANY
	b = append(b, 0, 0, 0, 0) // TTL 0
	b = append(b, indepEncodeName(algo)...)
	b = append(b, byte(timeSigned>>40), byte(timeSigned>>32), byte(timeSigned>>24), byte(timeSigned>>16), byte(timeSigned>>8), byte(timeSigned))
	b = append(b, byte(fudge>>8), byte(fudge))
	b = append(b, byte(errCode>>8), byte(errCode))
	b = append(b, byte(len(other)>>8), byte(len(other)))
	return append(b, other...)
}

func indepParseTSIGRData(rd []byte) (algo string, timeSigned uint64, fudge uint16, mac []byte, origID, errCode uint16, other []byte, ok bool) {
	name, off, ok := indepReadName(rd, 0)
	if !ok || off+12 > len(rd) {
		return "", 0, 0, nil, 0, 0, nil, false
	}
	for i := 0; i < 6; i++ {
		timeSigned = timeSigned<<8 | uint64(rd[off+i])
	}
	off += 6
	fudge = binary.BigEndian.Uint16(rd[off:])
	off += 2
	macSize := int(binary.BigEndian.Uint16(rd[off:]))
	off += 2
	if off+macSize+6 > len(rd) {
		return "", 0, 0, nil, 0, 0, nil, false
	}
	mac = rd[off : off+macSize]
	off += macSize
	origID = binary.BigEndian.Uint16(rd[off:])
	off += 2
	errCode = binary.BigEndian.Uint16(rd[off:])
	off += 2
	otherLen := int(binary.BigEndian.Uint16(rd[off:]))
	off += 2
	if off+otherLen > len(rd) {
		return "", 0, 0, nil, 0, 0, nil, false
	}
	other = rd[off : off+otherLen]
	return name, timeSigned, fudge, mac, origID, errCode, other, true
}

func indepReadName(b []byte, off int) (string, int, bool) {
	var labels []string
	for {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		off++
		if l == 0 {
			break
		}
		if l > 63 || off+l > len(b) {
			return "", 0, false
		}
		labels = append(labels, string(b[off:off+l]))
		off += l
	}
	if len(labels) == 0 {
		return ".", off, true
	}
	return strings.Join(labels, ".") + ".", off, true
}

func indepHashFor(algo string) func() hash.Hash {
	switch strings.TrimSuffix(algo, ".") {
	case "hmac-sha256":
		return sha256.New
	case "hmac-sha384":
		return sha512.New384
	case "hmac-sha512":
		return sha512.New
	}
	return nil
}

// ---- tests ----

func testRFC2136Provider(t *testing.T, fake *fakeDNS, zone, algorithm string) *rfc2136Provider {
	t.Helper()
	p, err := newRFC2136Provider(&RFC2136Config{
		Server:        fake.addr(),
		Zone:          zone,
		TSIGName:      "acme-key.",
		TSIGSecret:    base64.StdEncoding.EncodeToString(fake.secret),
		TSIGAlgorithm: algorithm,
	})
	if err != nil {
		t.Fatalf("newRFC2136Provider: %v", err)
	}
	return p
}

func TestRFC2136PresentCleanUp(t *testing.T) {
	for _, algo := range []string{"hmac-sha256", "hmac-sha512"} {
		t.Run(algo, func(t *testing.T) {
			secret := []byte("0123456789abcdef0123456789abcdef")
			fake := newFakeDNS(t, "example.com.", "acme-key.", secret)
			p := testRFC2136Provider(t, fake, "example.com.", algo)

			fqdn := "_acme-challenge.host.example.com."
			value := "Zm9vYmFyLWRuczAxLXZhbHVl"
			ctx := context.Background()

			if err := p.Present(ctx, fqdn, value); err != nil {
				t.Fatalf("Present: %v", err)
			}
			if !fake.has(fqdn, value) {
				t.Fatal("record was not published")
			}
			if err := p.CleanUp(ctx, fqdn, value); err != nil {
				t.Fatalf("CleanUp: %v", err)
			}
			if fake.has(fqdn, value) {
				t.Fatal("record was not withdrawn")
			}
			if fake.authFailures() != 0 {
				t.Fatalf("TSIG unexpectedly rejected %d update(s)", fake.authFailures())
			}
			if fake.updateCount() != 2 {
				t.Fatalf("applied %d updates, want 2 (present + cleanup)", fake.updateCount())
			}
		})
	}
}

func TestRFC2136TSIGRejected(t *testing.T) {
	fake := newFakeDNS(t, "example.com.", "acme-key.", []byte("the-server-side-shared-secret!!!"))
	// The provider is configured with a different secret; the server must reject
	// the UPDATE with NOTAUTH and the provider must surface an error.
	p, err := newRFC2136Provider(&RFC2136Config{
		Server:        fake.addr(),
		Zone:          "example.com.",
		TSIGName:      "acme-key.",
		TSIGSecret:    base64.StdEncoding.EncodeToString([]byte("a-completely-different-secret!!!")),
		TSIGAlgorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("newRFC2136Provider: %v", err)
	}
	err = p.Present(context.Background(), "_acme-challenge.host.example.com.", "value")
	if err == nil {
		t.Fatal("Present succeeded despite a bad TSIG secret")
	}
	if !strings.Contains(err.Error(), "NOTAUTH") {
		t.Fatalf("error = %v, want a NOTAUTH rejection", err)
	}
	if fake.authFailures() != 1 {
		t.Fatalf("server recorded %d auth failures, want 1", fake.authFailures())
	}
}

func TestRFC2136ZoneDiscovery(t *testing.T) {
	fake := newFakeDNS(t, "example.com.", "acme-key.", []byte("0123456789abcdef0123456789abcdef"))
	p := testRFC2136Provider(t, fake, "" /* discover */, "hmac-sha256")

	zone, err := p.resolveZone(context.Background(), "_acme-challenge.host.example.com.")
	if err != nil {
		t.Fatalf("resolveZone: %v", err)
	}
	if zone != "example.com." {
		t.Fatalf("discovered zone = %q, want example.com.", zone)
	}

	// A full Present must also work end-to-end when the zone is auto-discovered.
	if err := p.Present(context.Background(), "_acme-challenge.host.example.com.", "v"); err != nil {
		t.Fatalf("Present with discovered zone: %v", err)
	}
	if !fake.has("_acme-challenge.host.example.com.", "v") {
		t.Fatal("record not published after discovery")
	}
}

func TestTSIGAlgorithmName(t *testing.T) {
	cases := map[string]string{
		"":             "hmac-sha256.",
		"hmac-sha256":  "hmac-sha256.",
		"HMAC-SHA256":  "hmac-sha256.",
		"hmac-sha512.": "hmac-sha512.",
		"hmac-sha1":    "hmac-sha1.",
	}
	for in, want := range cases {
		got, err := tsigAlgorithmName(in)
		if err != nil {
			t.Errorf("tsigAlgorithmName(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("tsigAlgorithmName(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := tsigAlgorithmName("hmac-md5"); err == nil {
		t.Error("hmac-md5 should be rejected")
	}
}

func TestEncodeDNSName(t *testing.T) {
	got := encodeDNSName("Acme-Key.Example.COM.")
	want := []byte{8, 'a', 'c', 'm', 'e', '-', 'k', 'e', 'y', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if string(got) != string(want) {
		t.Errorf("encodeDNSName = %v, want %v", got, want)
	}
	if string(encodeDNSName(".")) != string([]byte{0}) {
		t.Error("root name should encode to a single zero octet")
	}
}
