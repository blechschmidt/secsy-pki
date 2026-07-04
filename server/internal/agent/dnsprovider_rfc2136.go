package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // hmac-sha1 is a TSIG algorithm (RFC 4635); selected only when explicitly configured.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS opcodes and record/class constants used by the RFC 2136 provider that the
// x/net dnsmessage package does not name.
const (
	opcodeUpdate = 5   // RFC 2136 §2.1 DNS OPCODE UPDATE
	tsigRRType   = 250 // RFC 8945 TSIG meta-RR
	classNone    = 254 // RFC 2136 §2.4 "delete an RR from an RRset"

	// tsigFudge is the permitted clock skew (seconds) advertised in the TSIG RR.
	tsigFudge = uint16(300)
)

// rfc2136Provider publishes dns-01 records via RFC 2136 dynamic DNS UPDATE
// messages authenticated with TSIG (RFC 8945). It speaks the wire protocol
// directly on top of golang.org/x/net/dns/dnsmessage, so it pulls in no DNS
// library dependency.
type rfc2136Provider struct {
	server   string // authoritative nameserver, host:port
	zone     string // explicit zone override (fqdn with trailing dot) or ""
	keyName  string // canonical TSIG key name (lowercase, trailing dot)
	algoName string // canonical TSIG algorithm name (lowercase, trailing dot)
	secret   []byte
	ttl      uint32
	timeout  time.Duration
	tcp      bool

	// now and newID are injectable for deterministic tests.
	now   func() time.Time
	newID func() uint16
}

// newRFC2136Provider builds the provider from its (already defaulted and
// validated) configuration.
func newRFC2136Provider(cfg *RFC2136Config) (*rfc2136Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rfc2136: configuration is missing")
	}
	algo, err := tsigAlgorithmName(cfg.TSIGAlgorithm)
	if err != nil {
		return nil, err
	}
	secret, err := loadTSIGSecret(cfg)
	if err != nil {
		return nil, err
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultRFC2136TTL
	}
	timeout := cfg.Timeout.Std()
	if timeout <= 0 {
		timeout = defaultRFC2136Timeout
	}
	p := &rfc2136Provider{
		server:   withDefaultPort(cfg.Server, "53"),
		keyName:  canonicalDNSName(cfg.TSIGName),
		algoName: algo,
		secret:   secret,
		ttl:      ttl,
		timeout:  timeout,
		tcp:      cfg.TCP,
		now:      time.Now,
		newID:    randomDNSID,
	}
	if z := strings.TrimSpace(cfg.Zone); z != "" {
		p.zone = ensureTrailingDot(z)
	}
	return p, nil
}

// Present adds the challenge TXT record to the zone's RRset.
func (p *rfc2136Provider) Present(ctx context.Context, fqdn, value string) error {
	return p.update(ctx, fqdn, value, true)
}

// CleanUp deletes exactly the challenge TXT record (leaving any other
// _acme-challenge records for the same name untouched).
func (p *rfc2136Provider) CleanUp(ctx context.Context, fqdn, value string) error {
	return p.update(ctx, fqdn, value, false)
}

// update sends a single signed UPDATE that adds (add=true) or deletes the TXT
// record, then checks the response RCODE.
func (p *rfc2136Provider) update(ctx context.Context, fqdn, value string, add bool) error {
	zone, err := p.resolveZone(ctx, fqdn)
	if err != nil {
		return err
	}
	msg, err := p.buildUpdate(fqdn, zone, value, add)
	if err != nil {
		return err
	}
	resp, err := p.exchange(ctx, msg)
	if err != nil {
		return err
	}
	return checkResponseRcode(resp, "UPDATE")
}

// buildUpdate constructs the TSIG-signed UPDATE message. An add uses the zone
// class (IN) and the configured TTL; a delete uses class NONE / TTL 0 to remove
// just this RR from the RRset (RFC 2136 §2.5.4).
func (p *rfc2136Provider) buildUpdate(fqdn, zone, value string, add bool) ([]byte, error) {
	zoneName, err := dnsmessage.NewName(ensureTrailingDot(zone))
	if err != nil {
		return nil, fmt.Errorf("rfc2136: invalid zone %q: %w", zone, err)
	}
	rrName, err := dnsmessage.NewName(ensureTrailingDot(fqdn))
	if err != nil {
		return nil, fmt.Errorf("rfc2136: invalid record name %q: %w", fqdn, err)
	}

	class := dnsmessage.ClassINET
	ttl := p.ttl
	if !add {
		class = dnsmessage.Class(classNone)
		ttl = 0
	}

	id := p.newID()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, OpCode: dnsmessage.OpCode(opcodeUpdate)})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	// Zone section: a single SOA-type question naming the zone.
	if err := b.Question(dnsmessage.Question{Name: zoneName, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	// Update section (carried in the Authority section of the message).
	if err := b.StartAuthorities(); err != nil {
		return nil, err
	}
	if err := b.TXTResource(dnsmessage.ResourceHeader{Name: rrName, Class: class, TTL: ttl}, dnsmessage.TXTResource{TXT: []string{value}}); err != nil {
		return nil, fmt.Errorf("rfc2136: encoding TXT record: %w", err)
	}
	unsigned, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return p.signTSIG(unsigned, id)
}

// signTSIG appends a TSIG RR authenticating the message and bumps ARCOUNT. The
// MAC covers the unsigned message (ARCOUNT excluding the TSIG) followed by the
// canonical TSIG variables, per RFC 8945 §4.3.3.
func (p *rfc2136Provider) signTSIG(unsigned []byte, id uint16) ([]byte, error) {
	timeSigned := uint64(p.now().Unix())

	newHash, err := tsigHash(p.algoName)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newHash, p.secret)
	mac.Write(unsigned)
	mac.Write(tsigVariables(p.keyName, p.algoName, timeSigned, tsigFudge, 0, nil))
	digest := mac.Sum(nil)

	rr, err := packTSIGRecord(p.keyName, p.algoName, timeSigned, tsigFudge, digest, id, 0, nil)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(unsigned)+len(rr))
	out = append(out, unsigned...)
	out = append(out, rr...)
	// The TSIG RR is the only additional; ARCOUNT was 0 in the unsigned message.
	binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(out[10:12])+1)
	return out, nil
}

// resolveZone returns the zone the record belongs to: the explicit override
// when configured, otherwise the closest enclosing apex found via SOA queries.
func (p *rfc2136Provider) resolveZone(ctx context.Context, fqdn string) (string, error) {
	if p.zone != "" {
		return p.zone, nil
	}
	labels := dnsLabels(fqdn)
	// Start one label in (the record name itself is never a zone apex) and walk
	// up to, but not including, the root.
	for i := 1; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".") + "."
		apex, err := p.isZoneApex(ctx, candidate)
		if err != nil {
			return "", err
		}
		if apex {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("rfc2136: could not determine the DNS zone for %s; set acme.dns01.rfc2136.zone", fqdn)
}

// isZoneApex reports whether name is a zone apex, i.e. the authoritative server
// answers an SOA query for it with an SOA record owned by name.
func (p *rfc2136Provider) isZoneApex(ctx context.Context, name string) (bool, error) {
	qName, err := dnsmessage.NewName(name)
	if err != nil {
		return false, fmt.Errorf("rfc2136: invalid name %q: %w", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: p.newID()})
	if err := b.StartQuestions(); err != nil {
		return false, err
	}
	if err := b.Question(dnsmessage.Question{Name: qName, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}); err != nil {
		return false, err
	}
	query, err := b.Finish()
	if err != nil {
		return false, err
	}
	resp, err := p.exchange(ctx, query)
	if err != nil {
		return false, err
	}
	return answerHasSOA(resp, name), nil
}

// exchange sends packed to the server and returns the response, using UDP with
// a TCP retry on truncation (or TCP directly when forced).
func (p *rfc2136Provider) exchange(ctx context.Context, packed []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	network := "udp"
	if p.tcp {
		network = "tcp"
	}
	resp, truncated, err := p.roundTrip(ctx, network, packed)
	if err != nil {
		return nil, err
	}
	if truncated {
		resp, _, err = p.roundTrip(ctx, "tcp", packed)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// roundTrip performs one DNS exchange. For UDP it reports whether the response
// set the TC (truncated) bit so the caller can retry over TCP.
func (p *rfc2136Provider) roundTrip(ctx context.Context, network string, packed []byte) (resp []byte, truncated bool, err error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, p.server)
	if err != nil {
		return nil, false, fmt.Errorf("rfc2136: dialing %s/%s: %w", p.server, network, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if network == "tcp" {
		var lenPrefix [2]byte
		binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(packed)))
		if _, err := conn.Write(append(lenPrefix[:], packed...)); err != nil {
			return nil, false, fmt.Errorf("rfc2136: writing UPDATE: %w", err)
		}
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, false, fmt.Errorf("rfc2136: reading response length: %w", err)
		}
		buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, false, fmt.Errorf("rfc2136: reading response: %w", err)
		}
		return buf, false, nil
	}

	if _, err := conn.Write(packed); err != nil {
		return nil, false, fmt.Errorf("rfc2136: writing UPDATE: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, fmt.Errorf("rfc2136: reading response: %w", err)
	}
	buf = buf[:n]
	var parser dnsmessage.Parser
	h, err := parser.Start(buf)
	if err != nil {
		return nil, false, fmt.Errorf("rfc2136: parsing response header: %w", err)
	}
	return buf, h.Truncated, nil
}

// ---- TSIG / DNS wire helpers ----

// tsigVariables serializes the canonical TSIG variables covered by the MAC
// (RFC 8945 §4.3.3): key name, class (ANY), TTL (0), algorithm name, time
// signed, fudge, error, and other data.
func tsigVariables(keyName, algoName string, timeSigned uint64, fudge, errCode uint16, otherData []byte) []byte {
	var b []byte
	b = append(b, encodeDNSName(keyName)...)       // NAME (canonical)
	b = appendUint16Raw(b, 255)                    // CLASS = ANY
	b = appendUint32Raw(b, 0)                      // TTL = 0
	b = append(b, encodeDNSName(algoName)...)      // Algorithm Name (canonical)
	b = appendUint48Raw(b, timeSigned)             // Time Signed
	b = appendUint16Raw(b, fudge)                  // Fudge
	b = appendUint16Raw(b, errCode)                // Error
	b = appendUint16Raw(b, uint16(len(otherData))) // Other Len
	b = append(b, otherData...)                    // Other Data
	return b
}

// packTSIGRecord builds the wire-format TSIG resource record.
func packTSIGRecord(keyName, algoName string, timeSigned uint64, fudge uint16, mac []byte, originalID, errCode uint16, otherData []byte) ([]byte, error) {
	rdata := packTSIGRData(algoName, timeSigned, fudge, mac, originalID, errCode, otherData)
	var b []byte
	b = append(b, encodeDNSName(keyName)...)
	b = appendUint16Raw(b, tsigRRType) // TYPE
	b = appendUint16Raw(b, 255)        // CLASS = ANY
	b = appendUint32Raw(b, 0)          // TTL = 0
	if len(rdata) > 0xFFFF {
		return nil, fmt.Errorf("rfc2136: TSIG rdata too large (%d bytes)", len(rdata))
	}
	b = appendUint16Raw(b, uint16(len(rdata))) // RDLENGTH
	b = append(b, rdata...)
	return b, nil
}

// packTSIGRData serializes the TSIG RDATA (RFC 8945 §4.2).
func packTSIGRData(algoName string, timeSigned uint64, fudge uint16, mac []byte, originalID, errCode uint16, otherData []byte) []byte {
	var b []byte
	b = append(b, encodeDNSName(algoName)...)
	b = appendUint48Raw(b, timeSigned)
	b = appendUint16Raw(b, fudge)
	b = appendUint16Raw(b, uint16(len(mac)))
	b = append(b, mac...)
	b = appendUint16Raw(b, originalID)
	b = appendUint16Raw(b, errCode)
	b = appendUint16Raw(b, uint16(len(otherData)))
	b = append(b, otherData...)
	return b
}

// encodeDNSName returns the canonical (lowercase, uncompressed) wire encoding of
// a domain name: a sequence of length-prefixed labels terminated by a zero
// octet. Inputs are validated key/algorithm/record names, so empty interior
// labels are simply skipped.
func encodeDNSName(name string) []byte {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []byte{0}
	}
	var b []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// canonicalDNSName lowercases and appends a trailing dot.
func canonicalDNSName(name string) string {
	return ensureTrailingDot(strings.ToLower(strings.TrimSpace(name)))
}

// ensureTrailingDot appends a dot to a non-empty name that lacks one.
func ensureTrailingDot(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// dnsLabels splits a name into its labels, dropping the trailing empty label
// from a fully-qualified name.
func dnsLabels(name string) []string {
	return strings.Split(strings.TrimSuffix(strings.TrimSpace(name), "."), ".")
}

func appendUint16Raw(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32Raw(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendUint48Raw appends the low 48 bits of v (the TSIG time-signed field).
func appendUint48Raw(b []byte, v uint64) []byte {
	return append(b, byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// answerHasSOA reports whether the response's answer section carries an SOA
// record owned by name (case-insensitive), i.e. name is a zone apex.
func answerHasSOA(resp []byte, name string) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	want := canonicalDNSName(name)
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return false
		}
		if h.Type == dnsmessage.TypeSOA && canonicalDNSName(h.Name.String()) == want {
			return true
		}
		if err := p.SkipAnswer(); err != nil {
			return false
		}
	}
}

// updateRcodeNames names the RFC 2136 / RFC 8945 response codes most useful for
// diagnosing a failed UPDATE beyond what dnsmessage.RCode renders.
var updateRcodeNames = map[uint16]string{
	6:  "YXDOMAIN",
	7:  "YXRRSET",
	8:  "NXRRSET",
	9:  "NOTAUTH (TSIG/authorization failure)",
	10: "NOTZONE",
}

// checkResponseRcode parses a response header and turns a non-success RCODE into
// an error.
func checkResponseRcode(resp []byte, op string) error {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return fmt.Errorf("rfc2136: parsing %s response: %w", op, err)
	}
	if h.RCode == dnsmessage.RCodeSuccess {
		return nil
	}
	code := uint16(h.RCode)
	if name, ok := updateRcodeNames[code]; ok {
		return fmt.Errorf("rfc2136: %s rejected with rcode %d %s", op, code, name)
	}
	return fmt.Errorf("rfc2136: %s rejected with rcode %s", op, h.RCode)
}

// tsigAlgorithmName normalizes a configured TSIG algorithm to its canonical
// lowercase, trailing-dot form and rejects unsupported algorithms. Empty
// defaults to hmac-sha256.
func tsigAlgorithmName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	switch n {
	case "":
		return canonicalDNSName(defaultTSIGAlgorithm), nil
	case "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512":
		return n + ".", nil
	default:
		return "", fmt.Errorf("rfc2136: unsupported tsig_algorithm %q (want hmac-sha1/224/256/384/512)", name)
	}
}

// tsigHash returns the HMAC hash constructor for a canonical algorithm name.
func tsigHash(algo string) (func() hash.Hash, error) {
	switch strings.TrimSuffix(algo, ".") {
	case "hmac-sha1":
		return sha1.New, nil
	case "hmac-sha224":
		return sha256.New224, nil
	case "hmac-sha256":
		return sha256.New, nil
	case "hmac-sha384":
		return sha512.New384, nil
	case "hmac-sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("rfc2136: unsupported tsig algorithm %q", algo)
	}
}

// loadTSIGSecret resolves and base64-decodes the TSIG shared secret, tolerating
// the standard and URL base64 variants (padded or raw), as BIND/knsupdate emit.
func loadTSIGSecret(cfg *RFC2136Config) ([]byte, error) {
	raw := cfg.TSIGSecret
	if cfg.TSIGSecretFile != "" {
		data, err := os.ReadFile(cfg.TSIGSecretFile)
		if err != nil {
			return nil, fmt.Errorf("rfc2136: reading tsig_secret_file: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("rfc2136: tsig secret is empty")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(raw); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("rfc2136: tsig secret is not valid base64")
}

// randomDNSID returns a random DNS message ID.
func randomDNSID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}
