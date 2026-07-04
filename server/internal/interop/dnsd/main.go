// Command dnsd is a tiny authoritative DNS server used only by the external-
// client interop suite (scripts/interop-test.sh). It answers just enough to let
// a real ACME client (acme.sh) satisfy dns-01 challenges against a live server:
//
//   - A/AAAA queries resolve every name to a fixed address (default 127.0.0.1),
//     so the ACME server's http-01 / tls-alpn-01 fetches reach the client's
//     local challenge responder without touching /etc/hosts.
//   - TXT queries are answered from a zone directory: one file per (lower-cased,
//     trailing-dot-stripped) query name, each non-empty line becoming one TXT
//     string. The acme.sh dns hook simply writes _acme-challenge.<domain> files
//     into that directory; because the file is read fresh on every query, no
//     reload/signal is needed and there is no race with the validating server.
//
// It is deliberately not a general-purpose resolver: unknown types return an
// empty NOERROR, and it never recurses. It is not part of the shipped product;
// the interop suite runs it with `go run`.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5354", "UDP+TCP listen address")
	zone := flag.String("zone", "", "directory holding TXT record files (one file per query name)")
	answerA := flag.String("a", "127.0.0.1", "IPv4 address returned for every A query")
	verbose := flag.Bool("v", false, "log every query")
	flag.Parse()

	if *zone == "" {
		log.Fatal("dnsd: -zone is required")
	}
	ip := net.ParseIP(*answerA).To4()
	if ip == nil {
		log.Fatalf("dnsd: -a %q is not a valid IPv4 address", *answerA)
	}
	var a4 [4]byte
	copy(a4[:], ip)

	srv := &server{zone: *zone, a4: a4, verbose: *verbose}

	udp, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("dnsd: listen udp %s: %v", *listen, err)
	}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("dnsd: listen tcp %s: %v", *listen, err)
	}
	log.Printf("dnsd: listening on %s (zone=%s, A=%s)", *listen, *zone, *answerA)

	go srv.serveTCP(tcp)
	srv.serveUDP(udp)
}

type server struct {
	zone    string
	a4      [4]byte
	verbose bool
}

func (s *server) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("dnsd: udp read: %v", err)
			continue
		}
		resp, err := s.respond(buf[:n])
		if err != nil {
			continue
		}
		if _, err := pc.WriteTo(resp, addr); err != nil {
			log.Printf("dnsd: udp write: %v", err)
		}
	}
}

func (s *server) serveTCP(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("dnsd: tcp accept: %v", err)
			return
		}
		go s.handleTCP(conn)
	}
}

func (s *server) handleTCP(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// DNS-over-TCP frames each message with a 2-byte big-endian length prefix.
	var lenBuf [2]byte
	if err := readFull(conn, lenBuf[:]); err != nil {
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	msg := make([]byte, msgLen)
	if err := readFull(conn, msg); err != nil {
		return
	}
	resp, err := s.respond(msg)
	if err != nil {
		return
	}
	out := make([]byte, 2+len(resp))
	out[0] = byte(len(resp) >> 8)
	out[1] = byte(len(resp))
	copy(out[2:], resp)
	_, _ = conn.Write(out)
}

func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}

// respond parses a single query and builds an authoritative answer.
func (s *server) respond(req []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 hdr.ID,
			Response:           true,
			Authoritative:      true,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{q},
	}

	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if s.verbose {
		log.Printf("dnsd: query %s %v", name, q.Type)
	}

	switch q.Type {
	case dnsmessage.TypeA:
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
			Body:   &dnsmessage.AResource{A: s.a4},
		})
	case dnsmessage.TypeTXT:
		if txts := s.txtRecords(name); len(txts) > 0 {
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.TXTResource{TXT: txts},
			})
		}
	}
	// Unknown types and missing TXT files fall through to an empty NOERROR, which
	// is all the ACME dns-01 validator needs to distinguish "not yet published".
	return resp.Pack()
}

// txtRecords reads the TXT strings for name from <zone>/<name>. Each non-empty,
// non-comment line is one TXT string. A missing file yields no records.
func (s *server) txtRecords(name string) []string {
	data, err := os.ReadFile(filepath.Join(s.zone, name))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
