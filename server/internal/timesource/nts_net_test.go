package timesource

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The exchanges below run against listeners bound to 127.0.0.1:0 inside the test
// process: a TLS server with a certificate generated per test for the NTS-KE
// phase, and a UDP socket implementing the server half of the NTS/NTP and
// Roughtime protocols. Nothing leaves the loopback interface and no public time
// server is contacted, but the full client path — handshake, ALPN check, RFC 5705
// key export, record parsing, request construction, response authentication — is
// exercised end to end.

// --- TLS test plumbing -------------------------------------------------------

// loopbackCert generates a fresh self-signed certificate for 127.0.0.1 and the
// pool that trusts it, so the client can verify the server properly instead of
// disabling verification (which would stop exercising the real TLS path).
func loopbackCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nts-ke-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// startKEServer starts a TLS listener on 127.0.0.1:0 offering the given ALPN
// protocols and hands each accepted connection to handle. The listener and all
// handler goroutines are shut down when the test finishes.
func startKEServer(t *testing.T, alpn []string, handle func(conn *tls.Conn)) (host string, port int, roots *x509.CertPool) {
	t.Helper()
	cert, pool := loopbackCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	var wg sync.WaitGroup
	// Cleanups run last-registered-first, so the listener is closed before the
	// wait — otherwise the accept loop would never return.
	t.Cleanup(wg.Wait)
	t.Cleanup(func() { _ = ln.Close() })

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Safe with wg.Wait: the accept loop's own count is still held.
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				handle(conn.(*tls.Conn))
			}()
		}
	}()

	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing listener address: %v", err)
	}
	pn, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("parsing listener port: %v", err)
	}
	return h, pn, pool
}

// testNTSProvider builds an ntsProvider aimed at a test listener, trusting only
// the per-test certificate.
func testNTSProvider(host string, port int, roots *x509.CertPool, timeout time.Duration) *ntsProvider {
	return &ntsProvider{
		name:    "nts-test",
		keHost:  host,
		kePort:  port,
		timeout: timeout,
		tlsConf: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{ntsKEALPN},
			ServerName: host,
			RootCAs:    roots,
		},
	}
}

// keRec is one NTS-KE record to emit.
type keRec struct {
	critical bool
	typ      uint16
	body     []byte
}

// keHandler returns a handler that consumes the client's NTS-KE request and
// replies with the given records.
func keHandler(recs ...keRec) func(*tls.Conn) {
	return func(conn *tls.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, len(buildKERequest()))); err != nil {
			return
		}
		var out []byte
		for _, r := range recs {
			out = appendKERecord(out, r.critical, r.typ, r.body)
		}
		_, _ = conn.Write(out)
	}
}

// keRawHandler replies with arbitrary (possibly truncated) bytes and then closes,
// so the record reader's framing can be attacked.
func keRawHandler(raw []byte) func(*tls.Conn) {
	return func(conn *tls.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, len(buildKERequest()))); err != nil {
			return
		}
		_, _ = conn.Write(raw)
	}
}

// --- NTS-KE -------------------------------------------------------------------

// TestKeyExchangeHappyPath drives the whole NTS-KE phase against a local TLS
// server and asserts the two things that make the following NTP exchange
// possible: the negotiated endpoint/cookies are parsed out of the record stream,
// and the RFC 5705 exported keys match what the server derives independently. If
// the exporter label or context were wrong the keys would differ and every
// response would fail authentication — a permanently fail-closed TSA.
func TestKeyExchangeHappyPath(t *testing.T) {
	cookie1 := bytes.Repeat([]byte{0xc1}, 100)
	cookie2 := bytes.Repeat([]byte{0xc2}, 104)

	gotRequest := make(chan []byte, 1)
	serverKeys := make(chan [2][]byte, 1)

	handle := func(conn *tls.Conn) {
		req := make([]byte, len(buildKERequest()))
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		gotRequest <- req

		// Export the same keying material from the server side.
		st := conn.ConnectionState()
		c2s, err1 := st.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x00), ntsSIVKeyLen)
		s2c, err2 := st.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x01), ntsSIVKeyLen)
		if err1 == nil && err2 == nil {
			serverKeys <- [2][]byte{c2s, s2c}
		}

		var out []byte
		out = appendKERecord(out, true, ntsRecNextProto, be16(ntsNextProtoNTPv4))
		out = appendKERecord(out, true, ntsRecAEAD, be16(ntsAEADAesSivCmac256))
		out = appendKERecord(out, true, ntsRecCookie, cookie1)
		out = appendKERecord(out, true, ntsRecCookie, cookie2)
		// A non-critical record this client does not implement must be skipped.
		out = appendKERecord(out, false, 0x002a, []byte("ignore me"))
		out = appendKERecord(out, true, ntsRecServer, []byte("127.0.0.1"))
		out = appendKERecord(out, true, ntsRecPort, be16(4567))
		out = appendKERecord(out, true, ntsRecEndOfMessage, nil)
		_, _ = conn.Write(out)
	}

	host, port, roots := startKEServer(t, []string{ntsKEALPN}, handle)
	p := testNTSProvider(host, port, roots, 5*time.Second)

	res, err := p.keyExchange(context.Background())
	if err != nil {
		t.Fatalf("keyExchange: %v", err)
	}

	if len(res.cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(res.cookies))
	}
	if !bytes.Equal(res.cookies[0], cookie1) || !bytes.Equal(res.cookies[1], cookie2) {
		t.Fatal("cookies were not carried through verbatim")
	}
	if res.ntpServer != "127.0.0.1" {
		t.Fatalf("negotiated NTP server = %q, want 127.0.0.1", res.ntpServer)
	}
	if res.ntpPort != 4567 {
		t.Fatalf("negotiated NTP port = %d, want 4567", res.ntpPort)
	}
	if len(res.c2sKey) != ntsSIVKeyLen || len(res.s2cKey) != ntsSIVKeyLen {
		t.Fatalf("key lengths = %d/%d, want %d", len(res.c2sKey), len(res.s2cKey), ntsSIVKeyLen)
	}
	if bytes.Equal(res.c2sKey, res.s2cKey) {
		t.Fatal("the C2S and S2C keys are identical, so a reflected request would authenticate as a response")
	}

	select {
	case req := <-gotRequest:
		if !bytes.Equal(req, buildKERequest()) {
			t.Fatalf("server received %x, want %x", req, buildKERequest())
		}
	default:
		t.Fatal("the server never received an NTS-KE request")
	}
	select {
	case k := <-serverKeys:
		if !bytes.Equal(k[0], res.c2sKey) {
			t.Fatal("the C2S key exported by the server differs from the client's")
		}
		if !bytes.Equal(k[1], res.s2cKey) {
			t.Fatal("the S2C key exported by the server differs from the client's")
		}
	default:
		t.Fatal("the server did not export keying material")
	}
}

// TestKeyExchangeAppliesDefaults checks the fallbacks used when the server names
// no NTP endpoint: the KE host and the IANA NTP port.
func TestKeyExchangeAppliesDefaults(t *testing.T) {
	host, port, roots := startKEServer(t, []string{ntsKEALPN}, keHandler(
		keRec{critical: true, typ: ntsRecNextProto, body: be16(ntsNextProtoNTPv4)},
		keRec{critical: true, typ: ntsRecAEAD, body: be16(ntsAEADAesSivCmac256)},
		keRec{critical: true, typ: ntsRecCookie, body: bytes.Repeat([]byte{0x01}, 100)},
		keRec{critical: true, typ: ntsRecEndOfMessage},
	))
	p := testNTSProvider(host, port, roots, 5*time.Second)

	res, err := p.keyExchange(context.Background())
	if err != nil {
		t.Fatalf("keyExchange: %v", err)
	}
	if res.ntpServer != p.keHost {
		t.Fatalf("ntpServer = %q, want the KE host %q", res.ntpServer, p.keHost)
	}
	if res.ntpPort != ntpDefaultPort {
		t.Fatalf("ntpPort = %d, want the default %d", res.ntpPort, ntpDefaultPort)
	}
}

// TestKeyExchangeRejects covers every way the NTS-KE phase must refuse to
// continue. Each failure has to surface as an error rather than as a half-built
// ntsKEResult, because the caller would otherwise query NTP with garbage keys (or
// panic on ke.cookies[0]).
func TestKeyExchangeRejects(t *testing.T) {
	okRecs := []keRec{
		{critical: true, typ: ntsRecNextProto, body: be16(ntsNextProtoNTPv4)},
		{critical: true, typ: ntsRecAEAD, body: be16(ntsAEADAesSivCmac256)},
	}
	withOK := func(extra ...keRec) []keRec {
		return append(append([]keRec(nil), okRecs...), extra...)
	}

	cases := []struct {
		name            string
		alpn            []string
		handle          func(*tls.Conn)
		wantErrContains string
	}{
		{
			// Without cookies the NTP phase would index ke.cookies[0] and panic,
			// so this must be caught here.
			name:            "no cookies",
			handle:          keHandler(withOK(keRec{critical: true, typ: ntsRecEndOfMessage})...),
			wantErrContains: "no NTS cookies",
		},
		{
			name: "server error record",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecError, body: be16(1)},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "error record (code 1)",
		},
		{
			name: "server error record with an empty body",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecError},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "error record (code 0)",
		},
		{
			// A server selecting another next protocol is not speaking NTPv4, so
			// the exported keys would be meaningless.
			name: "next protocol is not NTPv4",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecNextProto, body: be16(1)},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "did not select NTPv4",
		},
		{
			name: "next protocol record is truncated",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecNextProto, body: []byte{0x00}},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "did not select NTPv4",
		},
		{
			// Downgrading the AEAD would silently change the key length and the
			// authenticator construction.
			name: "AEAD is not AES-SIV-CMAC-256",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecNextProto, body: be16(ntsNextProtoNTPv4)},
				keRec{critical: true, typ: ntsRecAEAD, body: be16(17)},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "did not select AES-SIV-CMAC-256",
		},
		{
			name: "AEAD record is empty",
			handle: keHandler(
				keRec{critical: true, typ: ntsRecNextProto, body: be16(ntsNextProtoNTPv4)},
				keRec{critical: true, typ: ntsRecAEAD},
				keRec{critical: true, typ: ntsRecEndOfMessage},
			),
			wantErrContains: "did not select AES-SIV-CMAC-256",
		},
		{
			name:            "record header truncated mid-stream",
			handle:          keRawHandler([]byte{0x80, 0x01}),
			wantErrContains: "reading NTS-KE record header",
		},
		{
			// A header promising eight body bytes followed by three: the reader
			// must not hand a partially-filled buffer to the record switch.
			name:            "record body shorter than its declared length",
			handle:          keRawHandler([]byte{0x80, 0x05, 0x00, 0x08, 0x01, 0x02, 0x03}),
			wantErrContains: "reading NTS-KE record body",
		},
		{
			name:            "stream ends without End of Message",
			handle:          keRawHandler(appendKERecord(nil, true, ntsRecCookie, bytes.Repeat([]byte{0x01}, 100))),
			wantErrContains: "reading NTS-KE record header",
		},
		{
			// Reads the request, then closes without a single record. The client
			// must report the truncated stream rather than proceeding with an
			// empty ntsKEResult.
			name: "server closes after reading the request",
			handle: func(conn *tls.Conn) {
				_, _ = io.ReadFull(conn, make([]byte, len(buildKERequest())))
			},
			wantErrContains: "reading NTS-KE record header",
		},
		{
			// Closes before the handshake finishes. The exact transport error is
			// timing-dependent (EOF or a reset), so only the failure itself is
			// asserted.
			name:   "server closes before the TLS handshake completes",
			handle: func(conn *tls.Conn) {},
		},
		{
			// RFC 8915 requires the ntske/1 ALPN. A server that does not negotiate
			// it is not an NTS-KE server, so the handshake must not be trusted.
			name:            "ALPN not negotiated",
			alpn:            []string{},
			handle:          keHandler(withOK(keRec{critical: true, typ: ntsRecEndOfMessage})...),
			wantErrContains: "ALPN",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alpn := tc.alpn
			if alpn == nil {
				alpn = []string{ntsKEALPN}
			}
			host, port, roots := startKEServer(t, alpn, tc.handle)
			p := testNTSProvider(host, port, roots, 5*time.Second)

			res, err := p.keyExchange(context.Background())
			if err == nil {
				t.Fatalf("keyExchange accepted a bad NTS-KE exchange: %+v", res)
			}
			if res != nil {
				t.Fatalf("a failed key exchange must not return a result, got %+v", res)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// TestKeyExchangeHonoursTimeout checks the handshake deadline: a server that
// completes TLS and then stalls must not wedge the caller, because Checker.Now
// runs on the TSA's request path.
func TestKeyExchangeHonoursTimeout(t *testing.T) {
	stall := func(conn *tls.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, len(buildKERequest()))); err != nil {
			return
		}
		// Block until the client gives up and closes the connection.
		_, _ = io.Copy(io.Discard, conn)
	}
	host, port, roots := startKEServer(t, []string{ntsKEALPN}, stall)
	p := testNTSProvider(host, port, roots, 250*time.Millisecond)

	start := time.Now()
	_, err := p.keyExchange(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("keyExchange must fail when the server never sends records")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("keyExchange took %v to honour a 250ms timeout", elapsed)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

// --- NTP over UDP ------------------------------------------------------------

// startUDPResponder starts a UDP socket on 127.0.0.1:0 and answers each datagram
// with respond's return value; a nil return stays silent.
func startUDPResponder(t *testing.T, respond func(req []byte) []byte) (host string, port int) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("net.ListenUDP: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	t.Cleanup(func() { _ = conn.Close() })

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := respond(append([]byte(nil), buf[:n]...)); out != nil {
				_, _ = conn.WriteTo(out, from)
			}
		}
	}()

	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

// ntsServerRole implements the server half of the NTS-protected NTP exchange: it
// authenticates the client's request under the C2S key, echoes the unique
// identifier, and seals its reply under the S2C key. Being an independent
// implementation of the peer role, it is what makes the client round-trip below a
// real interoperability check rather than a self-consistency check.
//
// mutate, when non-nil, is applied to the finished response so a test can inject
// an attacker's version of it.
func ntsServerRole(c2s, s2c *aesSIV, xmit uint64, mutate func([]byte) []byte) func([]byte) []byte {
	return func(req []byte) []byte {
		if len(req) < 48 || req[0]&0x07 != 3 {
			return nil // not a client-mode NTP packet
		}
		fields, err := parseExtensionFields(req[48:])
		if err != nil {
			return nil
		}
		var uid []byte
		authenticated := false
		for _, ef := range fields {
			switch ef.typ {
			case efUniqueIdentifier:
				uid = append([]byte(nil), ef.body...)
			case efNTSAuthenticator:
				nonce, ct, perr := parseAuthenticatorEF(ef.body)
				if perr != nil {
					return nil
				}
				if _, oerr := c2s.Open(ct, req[:48+ef.offset], nonce); oerr == nil {
					authenticated = true
				}
			}
		}
		if uid == nil || !authenticated {
			return nil
		}

		pkt := make([]byte, 48)
		pkt[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
		pkt[1] = 1    // stratum
		binary.BigEndian.PutUint64(pkt[40:48], xmit)
		pkt = appendExtensionField(pkt, efUniqueIdentifier, uid)
		nonce := bytes.Repeat([]byte{0x77}, 16)
		ct, serr := s2c.Seal(nil, pkt, nonce)
		if serr != nil {
			return nil
		}
		pkt = append(pkt, buildAuthenticatorEF(nonce, ct)...)
		if mutate != nil {
			pkt = mutate(pkt)
		}
		return pkt
	}
}

// fixedKey returns a deterministic AES-SIV key.
func fixedKey(seed byte) []byte {
	key := make([]byte, ntsSIVKeyLen)
	for i := range key {
		key[i] = seed ^ byte(i)
	}
	return key
}

// TestNTPQueryRoundTrip runs the authenticated NTP exchange against a local
// responder and checks the derived Reading: the trusted time must be exactly the
// server's transmit timestamp, and the offset must be the host-minus-source
// difference measured inside the exchange (bracketed here by the host clock
// samples taken either side of the call, so no absolute wall-clock value is
// assumed).
func TestNTPQueryRoundTrip(t *testing.T) {
	c2sKey, s2cKey := fixedKey(0x10), fixedKey(0x20)
	c2s, err := newAESSIV(c2sKey)
	if err != nil {
		t.Fatalf("newAESSIV: %v", err)
	}
	s2c, err := newAESSIV(s2cKey)
	if err != nil {
		t.Fatalf("newAESSIV: %v", err)
	}
	// A fixed server time in the past, so the expected offset is large and
	// unambiguous.
	xmit := ntpTimestamp(1_700_000_000, 0x8000_0000)
	serverTime := ntpToTime(xmit)

	host, port := startUDPResponder(t, ntsServerRole(c2s, s2c, xmit, nil))
	p := testNTSProvider("127.0.0.1", 0, nil, 3*time.Second)
	ke := &ntsKEResult{
		c2sKey:    c2sKey,
		s2cKey:    s2cKey,
		cookies:   [][]byte{bytes.Repeat([]byte{0xcc}, 100)},
		ntpServer: host,
		ntpPort:   port,
	}

	before := time.Now()
	reading, err := p.ntpQuery(context.Background(), ke)
	after := time.Now()
	if err != nil {
		t.Fatalf("ntpQuery: %v", err)
	}

	if !reading.Time.Equal(serverTime) {
		t.Fatalf("Reading.Time = %s, want the server transmit timestamp %s",
			reading.Time.Format(time.RFC3339Nano), serverTime.Format(time.RFC3339Nano))
	}
	if reading.RTT < 0 || reading.RTT > after.Sub(before) {
		t.Fatalf("Reading.RTT = %v, want it within the observed [0, %v]", reading.RTT, after.Sub(before))
	}
	// Offset is host-minus-source, measured at the midpoint of the exchange.
	lo, hi := before.Sub(serverTime), after.Sub(serverTime)
	if reading.Offset < lo || reading.Offset > hi {
		t.Fatalf("Reading.Offset = %v, want it within [%v, %v]", reading.Offset, lo, hi)
	}
}

// TestNTPQueryRejects covers the failure modes of the UDP phase. Each one must
// return an error so the Checker records an unreachable source instead of
// trusting an unauthenticated datagram.
func TestNTPQueryRejects(t *testing.T) {
	c2sKey, s2cKey := fixedKey(0x30), fixedKey(0x40)
	c2s, _ := newAESSIV(c2sKey)
	s2c, _ := newAESSIV(s2cKey)
	attacker, _ := newAESSIV(fixedKey(0x50))
	xmit := ntpTimestamp(1_700_000_000, 0)

	cases := []struct {
		name            string
		c2sKey, s2cKey  []byte
		respond         func([]byte) []byte
		wantErrContains string
	}{
		{
			name:            "C2S key of the wrong length",
			c2sKey:          make([]byte, 31),
			s2cKey:          s2cKey,
			respond:         ntsServerRole(c2s, s2c, xmit, nil),
			wantErrContains: "C2S key",
		},
		{
			name:            "S2C key of the wrong length",
			c2sKey:          c2sKey,
			s2cKey:          make([]byte, 16),
			respond:         ntsServerRole(c2s, s2c, xmit, nil),
			wantErrContains: "S2C key",
		},
		{
			// A silent server (or a dropped datagram) must time out, not hang.
			name:            "server never answers",
			respond:         func([]byte) []byte { return nil },
			wantErrContains: "reading NTP response",
		},
		{
			// An off-path spoofer that guesses the source port can only produce
			// unauthenticated bytes.
			name:            "unauthenticated reply",
			respond:         func([]byte) []byte { return make([]byte, 48) },
			wantErrContains: "mode",
		},
		{
			name: "reply sealed with an attacker key",
			respond: func(req []byte) []byte {
				return ntsServerRole(c2s, attacker, xmit, nil)(req)
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			// Replay of a correctly-signed response for a different query: the
			// unique identifier no longer matches.
			name: "reply echoing a different unique identifier",
			respond: ntsServerRole(c2s, s2c, xmit, func(pkt []byte) []byte {
				pkt[48+4] ^= 0xff // flip a byte of the echoed identifier
				return pkt
			}),
			wantErrContains: "Unique Identifier does not match",
		},
		{
			name: "reply truncated below the NTP header",
			respond: ntsServerRole(c2s, s2c, xmit, func(pkt []byte) []byte {
				return pkt[:40]
			}),
			wantErrContains: "too short",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startUDPResponder(t, tc.respond)
			p := testNTSProvider("127.0.0.1", 0, nil, 300*time.Millisecond)
			ck, sk := tc.c2sKey, tc.s2cKey
			if ck == nil {
				ck = c2sKey
			}
			if sk == nil {
				sk = s2cKey
			}
			ke := &ntsKEResult{
				c2sKey:    ck,
				s2cKey:    sk,
				cookies:   [][]byte{bytes.Repeat([]byte{0xcc}, 100)},
				ntpServer: host,
				ntpPort:   port,
			}

			start := time.Now()
			reading, err := p.ntpQuery(context.Background(), ke)
			if err == nil {
				t.Fatalf("ntpQuery accepted a bad exchange: %+v", reading)
			}
			if !reading.Time.IsZero() {
				t.Fatalf("a failed query must return the zero Reading, got %+v", reading)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("ntpQuery took %v despite a 300ms timeout", elapsed)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// TestNTSProviderNowEndToEnd exercises ntsProvider.Now across both phases: the
// TLS key establishment (whose exported keys the test server derives itself) and
// the authenticated UDP exchange that uses them. It is the only test that proves
// the two halves agree on the keys, the negotiated endpoint, and the cookie.
func TestNTSProviderNowEndToEnd(t *testing.T) {
	xmit := ntpTimestamp(1_700_000_500, 0x4000_0000)
	serverTime := ntpToTime(xmit)

	keyCh := make(chan [2][]byte, 1)
	var once sync.Once
	var c2s, s2c *aesSIV

	udpHost, udpPort := startUDPResponder(t, func(req []byte) []byte {
		once.Do(func() {
			select {
			case k := <-keyCh:
				c2s, _ = newAESSIV(k[0])
				s2c, _ = newAESSIV(k[1])
			case <-time.After(5 * time.Second):
			}
		})
		if c2s == nil || s2c == nil {
			return nil
		}
		return ntsServerRole(c2s, s2c, xmit, nil)(req)
	})

	handle := func(conn *tls.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, len(buildKERequest()))); err != nil {
			return
		}
		st := conn.ConnectionState()
		ck, err1 := st.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x00), ntsSIVKeyLen)
		sk, err2 := st.ExportKeyingMaterial(ntsExporterLabel, exporterContext(0x01), ntsSIVKeyLen)
		if err1 != nil || err2 != nil {
			return
		}
		keyCh <- [2][]byte{ck, sk}

		var out []byte
		out = appendKERecord(out, true, ntsRecNextProto, be16(ntsNextProtoNTPv4))
		out = appendKERecord(out, true, ntsRecAEAD, be16(ntsAEADAesSivCmac256))
		out = appendKERecord(out, true, ntsRecCookie, bytes.Repeat([]byte{0xab}, 100))
		out = appendKERecord(out, true, ntsRecServer, []byte(udpHost))
		out = appendKERecord(out, true, ntsRecPort, be16(uint16(udpPort))) //nolint:gosec // a loopback port always fits
		out = appendKERecord(out, true, ntsRecEndOfMessage, nil)
		_, _ = conn.Write(out)
	}

	keHost, kePort, roots := startKEServer(t, []string{ntsKEALPN}, handle)
	p := testNTSProvider(keHost, kePort, roots, 5*time.Second)

	if p.Name() != "nts-test" {
		t.Fatalf("Name() = %q, want nts-test", p.Name())
	}

	before := time.Now()
	reading, err := p.Now(context.Background())
	after := time.Now()
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	if !reading.Time.Equal(serverTime) {
		t.Fatalf("Reading.Time = %s, want %s", reading.Time.Format(time.RFC3339Nano), serverTime.Format(time.RFC3339Nano))
	}
	if lo, hi := before.Sub(serverTime), after.Sub(serverTime); reading.Offset < lo || reading.Offset > hi {
		t.Fatalf("Reading.Offset = %v, want it within [%v, %v]", reading.Offset, lo, hi)
	}
}

// TestNTSProviderNowReportsKeyExchangeFailure checks the error wrapping on the
// path the Checker sees: a failed KE must be attributed to key establishment, so
// the audit detail names the real cause.
func TestNTSProviderNowReportsKeyExchangeFailure(t *testing.T) {
	host, port, roots := startKEServer(t, []string{ntsKEALPN}, keHandler(
		keRec{critical: true, typ: ntsRecError, body: be16(2)},
		keRec{critical: true, typ: ntsRecEndOfMessage},
	))
	p := testNTSProvider(host, port, roots, 3*time.Second)

	reading, err := p.Now(context.Background())
	if err == nil {
		t.Fatalf("Now must fail when key establishment fails, got %+v", reading)
	}
	if !strings.Contains(err.Error(), "key establishment") {
		t.Fatalf("error = %q, want it to mention key establishment", err.Error())
	}
	if !strings.Contains(err.Error(), "code 2") {
		t.Fatalf("error = %q, want it to carry the server's error code", err.Error())
	}
}

// --- Roughtime over UDP -------------------------------------------------------

// TestRoughtimeProviderNowOverLoopback drives roughtimeProvider.Now against the
// signing responder already used by roughtime_test.go, over a real UDP socket.
// This is the only test that covers the request the client actually emits, so it
// also asserts the anti-amplification padding survives to the wire.
func TestRoughtimeProviderNowOverLoopback(t *testing.T) {
	const mid = uint64(1_700_000_000_000_000)
	const radius = uint32(1_500)
	responder := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	reqLens := make(chan int, 4)

	host, port := startUDPResponder(t, func(req []byte) []byte {
		reqLens <- len(req)
		fields, err := decodeRoughtimeMessage(req)
		if err != nil {
			return nil
		}
		nonce, ok := fields[tagNONC]
		if !ok || len(nonce) != roughtimeNonceLen {
			return nil
		}
		return responder.respond(nonce, mid, radius, nil)
	})

	p := &roughtimeProvider{
		name:      "rt-loopback",
		address:   net.JoinHostPort(host, strconv.Itoa(port)),
		publicKey: responder.rootPub,
		timeout:   3 * time.Second,
	}
	if p.Name() != "rt-loopback" {
		t.Fatalf("Name() = %q, want rt-loopback", p.Name())
	}

	want := microsToTime(mid)
	before := time.Now()
	reading, err := p.Now(context.Background())
	after := time.Now()
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	if !reading.Time.Equal(want) {
		t.Fatalf("Reading.Time = %s, want the signed midpoint %s", reading.Time.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	if reading.Uncertainty != time.Duration(radius)*time.Microsecond {
		t.Fatalf("Reading.Uncertainty = %v, want %v", reading.Uncertainty, time.Duration(radius)*time.Microsecond)
	}
	if lo, hi := before.Sub(want), after.Sub(want); reading.Offset < lo || reading.Offset > hi {
		t.Fatalf("Reading.Offset = %v, want it within [%v, %v]", reading.Offset, lo, hi)
	}
	if reading.RTT < 0 || reading.RTT > after.Sub(before) {
		t.Fatalf("Reading.RTT = %v, want it within [0, %v]", reading.RTT, after.Sub(before))
	}

	select {
	case n := <-reqLens:
		if n < roughtimeMinRequestLen {
			t.Fatalf("the server received a %d-byte request, below the %d-byte anti-amplification minimum", n, roughtimeMinRequestLen)
		}
	default:
		t.Fatal("the responder never saw a request")
	}
}

// TestRoughtimeProviderNowRejects covers the UDP-phase failures: a response
// signed by the wrong long-term key (an impostor server) and a silent server.
func TestRoughtimeProviderNowRejects(t *testing.T) {
	const mid = uint64(1_700_000_000_000_000)
	legit := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)
	impostor := newRoughtimeResponder(t, mid-1_000_000, mid+1_000_000)

	cases := []struct {
		name            string
		respond         func([]byte) []byte
		wantErrContains string
	}{
		{
			name: "response signed by an impostor",
			respond: func(req []byte) []byte {
				fields, err := decodeRoughtimeMessage(req)
				if err != nil {
					return nil
				}
				return impostor.respond(fields[tagNONC], mid, 0, nil)
			},
			wantErrContains: "delegation signature does not verify",
		},
		{
			name:            "server never answers",
			respond:         func([]byte) []byte { return nil },
			wantErrContains: "reading response",
		},
		{
			name:            "server returns garbage",
			respond:         func([]byte) []byte { return []byte{0x01, 0x02} },
			wantErrContains: "parsing response",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startUDPResponder(t, tc.respond)
			p := &roughtimeProvider{
				name:      "rt-test",
				address:   net.JoinHostPort(host, strconv.Itoa(port)),
				publicKey: legit.rootPub,
				timeout:   300 * time.Millisecond,
			}
			reading, err := p.Now(context.Background())
			if err == nil {
				t.Fatalf("Now accepted a bad response: %+v", reading)
			}
			if !reading.Time.IsZero() {
				t.Fatalf("a failed query must return the zero Reading, got %+v", reading)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}
