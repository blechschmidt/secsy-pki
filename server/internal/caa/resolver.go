package caa

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// caaRRType is the DNS resource-record type code for CAA (RFC 8659 §4.1). The
// dnsmessage package has no typed CAA resource, so CAA answers are read as
// UnknownResource and their RDATA decoded here.
const caaRRType = 257

// defaultDNSTimeout bounds a single UDP/TCP exchange with a resolver.
const defaultDNSTimeout = 5 * time.Second

// SystemResolver resolves CAA and CNAME records by querying the recursive DNS
// servers listed in /etc/resolv.conf (or an explicit server list) over UDP with
// TCP fallback on truncation. It implements Resolver.
type SystemResolver struct {
	// Servers is the ordered list of "host:port" resolvers to try. When empty it
	// is populated from /etc/resolv.conf at first use.
	Servers []string
	// Timeout bounds each individual UDP/TCP exchange. Zero uses defaultDNSTimeout.
	Timeout time.Duration
}

// NewSystemResolver builds a resolver from /etc/resolv.conf. It returns an error
// only if no nameservers can be determined.
func NewSystemResolver() (*SystemResolver, error) {
	servers, err := resolvConfServers("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("caa: no nameservers configured in /etc/resolv.conf")
	}
	return &SystemResolver{Servers: servers}, nil
}

func (s *SystemResolver) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return defaultDNSTimeout
}

func (s *SystemResolver) servers() ([]string, error) {
	if len(s.Servers) > 0 {
		return s.Servers, nil
	}
	servers, err := resolvConfServers("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("caa: no nameservers available")
	}
	return servers, nil
}

// LookupCAA queries the CAA RRset at name and decodes each record's RDATA.
func (s *SystemResolver) LookupCAA(ctx context.Context, name string) ([]Record, error) {
	answers, _, err := s.query(ctx, name, caaRRType)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, a := range answers {
		if a.Header.Type != dnsmessage.Type(caaRRType) {
			continue
		}
		u, ok := a.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		rec, err := decodeCAARDATA(u.Data)
		if err != nil {
			// A malformed CAA record in an otherwise valid response is treated as a
			// hard error: it leaves authorization undetermined (fail-closed under
			// enforce) rather than silently ignoring a possibly-forbidding record.
			return nil, fmt.Errorf("caa: decoding CAA record for %q: %w", name, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// LookupCNAME returns the canonical target of name, or "" when name is not an
// alias.
func (s *SystemResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	answers, _, err := s.query(ctx, name, uint16(dnsmessage.TypeCNAME))
	if err != nil {
		return "", err
	}
	for _, a := range answers {
		if c, ok := a.Body.(*dnsmessage.CNAMEResource); ok {
			return strings.TrimSuffix(c.CNAME.String(), "."), nil
		}
	}
	return "", nil
}

// query sends a single question and returns the answer records and the smallest
// TTL seen. A NODATA/NXDOMAIN response yields (nil, 0, nil); a SERVFAIL/refused
// or transport failure yields an error (authorization undetermined).
func (s *SystemResolver) query(ctx context.Context, name string, qtype uint16) ([]dnsmessage.Resource, uint32, error) { //nolint:unparam // the minimum-TTL return is part of the resolver's DNS answer surface; current CAA callers don't cache it.
	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	dnsName, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, 0, fmt.Errorf("caa: invalid DNS name %q: %w", name, err)
	}

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("caa: generating query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  dnsmessage.Type(qtype),
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("caa: packing query: %w", err)
	}

	servers, err := s.servers()
	if err != nil {
		return nil, 0, err
	}

	var lastErr error
	for _, srv := range servers {
		answers, ttl, err := s.exchange(ctx, srv, packed, id, qtype)
		if err == nil {
			return answers, ttl, nil
		}
		lastErr = err
	}
	return nil, 0, fmt.Errorf("caa: all nameservers failed for %q: %w", name, lastErr)
}

// exchange performs one UDP exchange with a server, retrying over TCP if the
// response is truncated.
func (s *SystemResolver) exchange(ctx context.Context, server string, packed []byte, id uint16, qtype uint16) ([]dnsmessage.Resource, uint32, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	resp, truncated, err := s.roundTrip(ctx, "udp", server, packed)
	if err != nil {
		return nil, 0, err
	}
	if truncated {
		resp, _, err = s.roundTrip(ctx, "tcp", server, packed)
		if err != nil {
			return nil, 0, err
		}
	}
	return parseResponse(resp, id, qtype)
}

// roundTrip sends a query over the given network and returns the raw response.
// For UDP it also reports whether the (header-only) response was truncated so
// the caller can retry over TCP.
func (s *SystemResolver) roundTrip(ctx context.Context, network, server string, packed []byte) (resp []byte, truncated bool, err error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if network == "tcp" {
		var lenPrefix [2]byte
		binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(packed)))
		if _, err := conn.Write(append(lenPrefix[:], packed...)); err != nil {
			return nil, false, err
		}
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, false, err
		}
		n := binary.BigEndian.Uint16(hdr[:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, false, err
		}
		return buf, false, nil
	}

	if _, err := conn.Write(packed); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 1232) // EDNS-sized UDP buffer is ample for CAA/CNAME
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	buf = buf[:n]
	// Peek the header to detect truncation without a full parse.
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil {
		return nil, false, err
	}
	return buf, h.Truncated, nil
}

// parseResponse validates the response header (ID match, RCODE) and returns the
// answer resources plus the minimum TTL. NXDOMAIN and NODATA are non-errors that
// return no records; SERVFAIL/refused are errors.
func parseResponse(resp []byte, id uint16, _ uint16) ([]dnsmessage.Resource, uint32, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("caa: parsing response: %w", err)
	}
	if h.ID != id {
		return nil, 0, errors.New("caa: response id mismatch")
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		// Success (possibly NODATA) or NXDOMAIN: both mean "no forbidding record",
		// so processing continues (climb the tree / allow).
	default:
		return nil, 0, fmt.Errorf("caa: resolver returned %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}

	var answers []dnsmessage.Resource
	minTTL := uint32(0)
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		var body dnsmessage.ResourceBody
		switch ah.Type {
		case dnsmessage.Type(caaRRType):
			u, err := p.UnknownResource()
			if err != nil {
				return nil, 0, err
			}
			body = &u
		case dnsmessage.TypeCNAME:
			c, err := p.CNAMEResource()
			if err != nil {
				return nil, 0, err
			}
			body = &c
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, err
			}
			continue
		}
		if minTTL == 0 || (ah.TTL > 0 && ah.TTL < minTTL) {
			minTTL = ah.TTL
		}
		answers = append(answers, dnsmessage.Resource{Header: ah, Body: body})
	}
	return answers, minTTL, nil
}

// decodeCAARDATA decodes the wire RDATA of a CAA record (RFC 8659 §4.1):
// 1-octet flags, 1-octet tag length, the tag, then the value (rest of RDATA).
func decodeCAARDATA(data []byte) (Record, error) {
	if len(data) < 2 {
		return Record{}, errors.New("caa: RDATA too short")
	}
	flag := data[0]
	tagLen := int(data[1])
	if tagLen == 0 || 2+tagLen > len(data) {
		return Record{}, errors.New("caa: invalid CAA tag length")
	}
	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])
	return Record{Flag: flag, Tag: strings.ToLower(tag), Value: value}, nil
}

// resolvConfServers extracts "host:53" nameserver entries from a resolv.conf.
func resolvConfServers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, net.JoinHostPort(fields[1], "53"))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}
