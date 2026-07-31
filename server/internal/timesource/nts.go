package timesource

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// NTS (Network Time Security, RFC 8915) authenticates NTPv4. A query has two
// phases: an NTS-KE (key establishment) handshake over TLS that yields cookies
// and, via RFC 5705 key export, the client-to-server (C2S) and server-to-client
// (S2C) AEAD keys; and the NTPv4 exchange itself over UDP, where the request
// carries a Unique Identifier, a cookie, and an authenticator (AES-SIV over the
// packet), and the response is rejected unless its authenticator verifies under
// the S2C key and it echoes the unique identifier. This makes the returned time
// unforgeable by an on-path attacker — the property a trust anchor needs.

// NTS protocol constants.
const (
	ntsKEALPN        = "ntske/1"
	ntsKEDefaultPort = 4460
	ntpDefaultPort   = 123

	// NTS-KE record types (RFC 8915 §4).
	ntsRecEndOfMessage = 0
	ntsRecNextProto    = 1
	ntsRecError        = 2
	ntsRecWarning      = 3
	ntsRecAEAD         = 4
	ntsRecCookie       = 5
	ntsRecServer       = 6
	ntsRecPort         = 7

	ntsNextProtoNTPv4 = 0
	// AEAD_AES_SIV_CMAC_256 (RFC 8915 §5.1, IANA AEAD id 15) is the
	// mandatory-to-implement algorithm; its key length is 32 bytes.
	ntsAEADAesSivCmac256 = 15
	ntsSIVKeyLen         = 32

	ntsExporterLabel = "EXPORTER-network-time-security"

	// NTP extension-field types (RFC 8915 §5.x).
	efUniqueIdentifier = 0x0104
	efNTSCookie        = 0x0204
	efNTSAuthenticator = 0x0404

	// NTP timestamp epoch offset: seconds between 1900-01-01 and 1970-01-01.
	ntpUnixEpochOffset = 2208988800
)

// NTSServer configures one NTS server.
type NTSServer struct {
	Name    string        // label for metrics/audit; defaults to Address
	Address string        // NTS-KE endpoint (host or host:port; KE port defaults to 4460)
	Timeout time.Duration // per-query timeout; defaults to 5s
}

// ntsProvider queries one NTS server.
type ntsProvider struct {
	name    string
	keHost  string
	kePort  int
	timeout time.Duration
	tlsConf *tls.Config
}

// NewNTSProvider builds an NTS Provider for one server.
func NewNTSProvider(s NTSServer) (Provider, error) {
	host, port, err := splitHostPortDefault(s.Address, ntsKEDefaultPort)
	if err != nil {
		return nil, fmt.Errorf("nts: %w", err)
	}
	name := s.Name
	if name == "" {
		name = s.Address
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &ntsProvider{
		name:    name,
		keHost:  host,
		kePort:  port,
		timeout: timeout,
		tlsConf: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{ntsKEALPN},
			ServerName: host,
		},
	}, nil
}

func (p *ntsProvider) Name() string { return p.name }

// Now performs the NTS-KE handshake followed by the authenticated NTP exchange
// and returns the measured offset.
func (p *ntsProvider) Now(ctx context.Context) (Reading, error) {
	ke, err := p.keyExchange(ctx)
	if err != nil {
		return Reading{}, fmt.Errorf("nts: key establishment: %w", err)
	}
	return p.ntpQuery(ctx, ke)
}

// ntsKEResult carries the NTS-KE outputs needed for the NTP exchange.
type ntsKEResult struct {
	c2sKey    []byte
	s2cKey    []byte
	cookies   [][]byte
	ntpServer string // negotiated NTP host (defaults to the KE host)
	ntpPort   int
}

// keyExchange runs the NTS-KE TLS handshake and extracts the cookies and the
// C2S/S2C keys.
func (p *ntsProvider) keyExchange(ctx context.Context) (*ntsKEResult, error) {
	dctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	dialer := &tls.Dialer{Config: p.tlsConf}
	conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(p.keHost, strconv.Itoa(p.kePort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)
	if deadline, ok := dctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}

	if state := tlsConn.ConnectionState(); state.NegotiatedProtocol != ntsKEALPN {
		return nil, fmt.Errorf("server did not negotiate the %q ALPN protocol", ntsKEALPN)
	}

	if _, err := tlsConn.Write(buildKERequest()); err != nil {
		return nil, fmt.Errorf("writing NTS-KE request: %w", err)
	}

	res, err := readKEResponse(tlsConn)
	if err != nil {
		return nil, err
	}
	if res.ntpServer == "" {
		res.ntpServer = p.keHost
	}
	if res.ntpPort == 0 {
		res.ntpPort = ntpDefaultPort
	}

	// Export the C2S/S2C keys per RFC 8915 §5.1 (RFC 5705 exporters).
	state := tlsConn.ConnectionState()
	res.c2sKey, err = state.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x00), ntsSIVKeyLen)
	if err != nil {
		return nil, fmt.Errorf("exporting C2S key: %w", err)
	}
	res.s2cKey, err = state.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x01), ntsSIVKeyLen)
	if err != nil {
		return nil, fmt.Errorf("exporting S2C key: %w", err)
	}
	if len(res.cookies) == 0 {
		return nil, errors.New("server returned no NTS cookies")
	}
	return res, nil
}

// exporterContext builds the per-direction RFC 5705 exporter context: the
// next-protocol id, the AEAD id, and the key-type byte (0=C2S, 1=S2C).
func exporterContext(keyType byte) []byte {
	ctx := make([]byte, 5)
	binary.BigEndian.PutUint16(ctx[0:2], ntsNextProtoNTPv4)
	binary.BigEndian.PutUint16(ctx[2:4], ntsAEADAesSivCmac256)
	ctx[4] = keyType
	return ctx
}

// buildKERequest builds the NTS-KE request: negotiate NTPv4 and AES-SIV-CMAC-256.
func buildKERequest() []byte {
	var b []byte
	b = appendKERecord(b, true, ntsRecNextProto, be16(ntsNextProtoNTPv4))
	b = appendKERecord(b, true, ntsRecAEAD, be16(ntsAEADAesSivCmac256))
	b = appendKERecord(b, true, ntsRecEndOfMessage, nil)
	return b
}

// appendKERecord appends one NTS-KE record (critical bit, 15-bit type, 16-bit
// length, body).
func appendKERecord(dst []byte, critical bool, recType uint16, body []byte) []byte {
	t := recType & 0x7fff
	if critical {
		t |= 0x8000
	}
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], t)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	dst = append(dst, hdr[:]...)
	return append(dst, body...)
}

// readKEResponse reads and parses NTS-KE records until End of Message.
func readKEResponse(conn *tls.Conn) (*ntsKEResult, error) {
	res := &ntsKEResult{}
	buf := make([]byte, 4)
	for {
		if _, err := readFull(conn, buf); err != nil {
			return nil, fmt.Errorf("reading NTS-KE record header: %w", err)
		}
		typ := binary.BigEndian.Uint16(buf[0:2]) & 0x7fff
		bodyLen := int(binary.BigEndian.Uint16(buf[2:4]))
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := readFull(conn, body); err != nil {
				return nil, fmt.Errorf("reading NTS-KE record body: %w", err)
			}
		}
		switch typ {
		case ntsRecEndOfMessage:
			return res, nil
		case ntsRecError:
			code := uint16(0)
			if len(body) >= 2 {
				code = binary.BigEndian.Uint16(body)
			}
			return nil, fmt.Errorf("NTS-KE error record (code %d)", code)
		case ntsRecNextProto:
			if len(body) < 2 || binary.BigEndian.Uint16(body) != ntsNextProtoNTPv4 {
				return nil, errors.New("NTS-KE server did not select NTPv4")
			}
		case ntsRecAEAD:
			if len(body) < 2 || binary.BigEndian.Uint16(body) != ntsAEADAesSivCmac256 {
				return nil, errors.New("NTS-KE server did not select AES-SIV-CMAC-256")
			}
		case ntsRecCookie:
			cookie := make([]byte, len(body))
			copy(cookie, body)
			res.cookies = append(res.cookies, cookie)
		case ntsRecServer:
			res.ntpServer = string(body)
		case ntsRecPort:
			if len(body) >= 2 {
				res.ntpPort = int(binary.BigEndian.Uint16(body))
			}
		}
	}
}

// ntpQuery sends one authenticated NTP request and validates the response.
func (p *ntsProvider) ntpQuery(ctx context.Context, ke *ntsKEResult) (Reading, error) {
	c2s, err := newAESSIV(ke.c2sKey)
	if err != nil {
		return Reading{}, fmt.Errorf("nts: C2S key: %w", err)
	}
	s2c, err := newAESSIV(ke.s2cKey)
	if err != nil {
		return Reading{}, fmt.Errorf("nts: S2C key: %w", err)
	}

	uniqueID := make([]byte, 32)
	if _, err := rand.Read(uniqueID); err != nil {
		return Reading{}, err
	}
	request, err := buildNTPRequest(c2s, uniqueID, ke.cookies[0])
	if err != nil {
		return Reading{}, err
	}

	addr := net.JoinHostPort(ke.ntpServer, strconv.Itoa(ke.ntpPort))
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return Reading{}, fmt.Errorf("nts: dialing NTP server: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(p.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	t1 := time.Now()
	if _, err := conn.Write(request); err != nil {
		return Reading{}, fmt.Errorf("nts: sending NTP request: %w", err)
	}
	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	t4 := time.Now()
	if err != nil {
		return Reading{}, fmt.Errorf("nts: reading NTP response: %w", err)
	}
	resp = resp[:n]

	serverXmit, err := validateNTPResponse(resp, uniqueID, s2c)
	if err != nil {
		return Reading{}, fmt.Errorf("nts: %w", err)
	}

	rtt := t4.Sub(t1)
	if rtt < 0 {
		rtt = 0
	}
	midpoint := t1.Add(rtt / 2)
	return Reading{Time: serverXmit, Offset: midpoint.Sub(serverXmit), RTT: rtt}, nil
}

// buildNTPRequest builds an NTS-protected NTPv4 client request: the header, a
// Unique Identifier EF, a NTS Cookie EF, and the NTS Authenticator EF (an
// AES-SIV tag over the preceding bytes, with an empty encrypted payload).
func buildNTPRequest(c2s *aesSIV, uniqueID, cookie []byte) ([]byte, error) {
	pkt := make([]byte, 48)
	pkt[0] = 0x23 // LI=0, VN=4, Mode=3 (client)

	pkt = appendExtensionField(pkt, efUniqueIdentifier, uniqueID)
	pkt = appendExtensionField(pkt, efNTSCookie, cookie)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// AES-SIV over an empty plaintext, authenticating the packet-so-far and the
	// nonce. The output is the 16-byte synthetic tag (no ciphertext bytes).
	ct, err := c2s.Seal(nil, pkt, nonce)
	if err != nil {
		return nil, err
	}
	pkt = append(pkt, buildAuthenticatorEF(nonce, ct)...)
	return pkt, nil
}

// validateNTPResponse authenticates an NTS NTP response and returns the server's
// transmit timestamp. It fails closed unless the Unique Identifier is echoed and
// the NTS Authenticator verifies under the S2C key over the exact response bytes.
func validateNTPResponse(resp, sentUniqueID []byte, s2c *aesSIV) (time.Time, error) {
	if len(resp) < 48 {
		return time.Time{}, errors.New("NTP response too short")
	}
	if resp[0]&0x07 != 4 { // Mode 4 (server)
		return time.Time{}, fmt.Errorf("NTP response mode is %d, want 4 (server)", resp[0]&0x07)
	}

	efs, err := parseExtensionFields(resp[48:])
	if err != nil {
		return time.Time{}, err
	}

	var gotUnique, gotAuth bool
	var authStart int
	for _, ef := range efs {
		switch ef.typ {
		case efUniqueIdentifier:
			if !constantTimeEqual(ef.body, sentUniqueID) {
				return time.Time{}, errors.New("response Unique Identifier does not match the request")
			}
			gotUnique = true
		case efNTSAuthenticator:
			authStart = 48 + ef.offset
			nonce, ciphertext, perr := parseAuthenticatorEF(ef.body)
			if perr != nil {
				return time.Time{}, perr
			}
			// Associated data is the packet from the start up to the authenticator EF.
			if _, oerr := s2c.Open(ciphertext, resp[:authStart], nonce); oerr != nil {
				return time.Time{}, fmt.Errorf("NTS authenticator verification failed: %w", oerr)
			}
			gotAuth = true
		}
	}
	if !gotUnique {
		return time.Time{}, errors.New("response is missing the Unique Identifier extension field")
	}
	if !gotAuth {
		return time.Time{}, errors.New("response is missing the NTS Authenticator extension field")
	}

	// Transmit timestamp: NTP header bytes 40..48.
	xmit := be64(resp[40:48])
	return ntpToTime(xmit), nil
}

// extensionField is a parsed EF with its byte offset within the EF region.
type extensionField struct {
	typ    uint16
	body   []byte
	offset int
}

// appendExtensionField appends an EF (RFC 7822): 2-byte type, 2-byte total
// length, body, zero-padded so the total length is a multiple of 4 and at least
// 16 octets.
func appendExtensionField(pkt []byte, typ uint16, value []byte) []byte {
	total := 4 + len(value)
	if pad := total % 4; pad != 0 {
		total += 4 - pad
	}
	if total < 16 {
		total = 16
	}
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	pkt = append(pkt, hdr[:]...)
	pkt = append(pkt, value...)
	for pad := total - 4 - len(value); pad > 0; pad-- {
		pkt = append(pkt, 0)
	}
	return pkt
}

// buildAuthenticatorEF builds the NTS Authenticator and Encrypted EF body.
func buildAuthenticatorEF(nonce, ciphertext []byte) []byte {
	nonceLen := len(nonce)
	ctLen := len(ciphertext)
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], uint16(nonceLen))
	binary.BigEndian.PutUint16(body[2:4], uint16(ctLen))
	body = append(body, nonce...)
	body = append(body, pad4(nonceLen)...)
	body = append(body, ciphertext...)
	body = append(body, pad4(ctLen)...)

	total := 4 + len(body)
	if pad := total % 4; pad != 0 {
		total += 4 - pad
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint16(out[0:2], efNTSAuthenticator)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out = append(out, body...)
	for len(out) < total {
		out = append(out, 0)
	}
	return out
}

// parseExtensionFields parses the EF region into fields, tracking each field's
// offset for the authenticator's associated-data computation.
func parseExtensionFields(region []byte) ([]extensionField, error) {
	var fields []extensionField
	off := 0
	for off+4 <= len(region) {
		typ := binary.BigEndian.Uint16(region[off : off+2])
		length := int(binary.BigEndian.Uint16(region[off+2 : off+4]))
		if length < 4 || off+length > len(region) {
			return nil, errors.New("malformed extension field")
		}
		fields = append(fields, extensionField{
			typ:    typ,
			body:   region[off+4 : off+length],
			offset: off,
		})
		off += length
	}
	return fields, nil
}

// parseAuthenticatorEF extracts the nonce and ciphertext from an NTS
// Authenticator EF body.
func parseAuthenticatorEF(body []byte) (nonce, ciphertext []byte, err error) {
	if len(body) < 4 {
		return nil, nil, errors.New("authenticator EF too short")
	}
	nonceLen := int(binary.BigEndian.Uint16(body[0:2]))
	ctLen := int(binary.BigEndian.Uint16(body[2:4]))
	noncePadded := roundUp4(nonceLen)
	ctPadded := roundUp4(ctLen)
	if 4+noncePadded+ctPadded > len(body) {
		return nil, nil, errors.New("authenticator EF length mismatch")
	}
	nonce = body[4 : 4+nonceLen]
	ciphertext = body[4+noncePadded : 4+noncePadded+ctLen]
	return nonce, ciphertext, nil
}

// ntpToTime converts a 64-bit NTP timestamp (era 0) to a time.Time.
func ntpToTime(ts uint64) time.Time {
	sec := ts >> 32
	frac := ts & 0xffffffff
	nsec := (frac * 1_000_000_000) >> 32
	return time.Unix(int64(sec)-ntpUnixEpochOffset, int64(nsec)).UTC()
}

// --- small byte helpers ------------------------------------------------------

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func pad4(n int) []byte {
	if r := n % 4; r != 0 {
		return make([]byte, 4-r)
	}
	return nil
}

func roundUp4(n int) int {
	if r := n % 4; r != 0 {
		return n + 4 - r
	}
	return n
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// splitHostPortDefault splits host:port, applying defaultPort when the port is
// absent. A bare host (no colon) is accepted.
func splitHostPortDefault(addr string, defaultPort int) (host string, port int, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, errors.New("empty address")
	}
	if !strings.Contains(addr, ":") || (strings.Count(addr, ":") > 1 && !strings.Contains(addr, "]")) {
		// bare host or bracketless IPv6
		return addr, defaultPort, nil
	}
	h, p, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return addr, defaultPort, nil
	}
	pn, convErr := strconv.Atoi(p)
	if convErr != nil {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, pn, nil
}

// readFull reads len(buf) bytes or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
