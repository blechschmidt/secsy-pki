package timesource

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// validateNTPResponse is the single security boundary of the NTS provider: the
// datagram it inspects arrives over unauthenticated UDP, so anything it accepts
// becomes the "trusted" time the TSA stamps into signed tokens. Every rejection
// asserted below is therefore a security property, not a nicety.

// --- helpers -----------------------------------------------------------------

// testSIV builds a deterministic AES-SIV instance. seed distinguishes the
// legitimate server key from an attacker's key.
func testSIV(tb testing.TB, seed byte) *aesSIV {
	tb.Helper()
	key := make([]byte, ntsSIVKeyLen)
	for i := range key {
		key[i] = seed ^ byte(i)
	}
	s, err := newAESSIV(key)
	if err != nil {
		tb.Fatalf("newAESSIV: %v", err)
	}
	return s
}

// ntpTimestamp encodes a Unix second plus an NTP fraction as a 64-bit era-0 NTP
// timestamp, the form the server writes into bytes 40..48 of the header.
func ntpTimestamp(unixSec int64, frac uint32) uint64 {
	return uint64(unixSec+ntpUnixEpochOffset)<<32 | uint64(frac)
}

// testNTSResponseOpts tweaks the response the fake server produces so a specific
// validation rule can be probed in isolation.
type testNTSResponseOpts struct {
	firstByte      *byte    // override the LI/VN/Mode byte
	echoUniqueID   []byte   // unique identifier to echo (defaults to the one asked for)
	omitUniqueID   bool     // leave out the unique-identifier extension field
	omitAuth       bool     // leave out the authenticator extension field
	sealKey        *aesSIV  // key used for the authenticator (defaults to s2c)
	plaintext      []byte   // encrypted payload (real servers put fresh cookies here)
	extraEFs       []uint16 // unknown extension-field types inserted before the authenticator
	trailingEFType *uint16  // an extension field appended *after* the authenticator
}

// buildTestNTSResponse assembles a mode-4 NTS response the way a correct server
// would: header, echoed unique identifier, then an AES-SIV authenticator over
// everything preceding it.
func buildTestNTSResponse(tb testing.TB, s2c *aesSIV, uniqueID []byte, xmit uint64, opts *testNTSResponseOpts) []byte {
	tb.Helper()
	if opts == nil {
		opts = &testNTSResponseOpts{}
	}

	pkt := make([]byte, 48)
	pkt[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
	if opts.firstByte != nil {
		pkt[0] = *opts.firstByte
	}
	pkt[1] = 2                                       // stratum
	binary.BigEndian.PutUint64(pkt[40:48], xmit)     // transmit timestamp
	binary.BigEndian.PutUint32(pkt[24:28], 0xdeadbe) // reference timestamp filler

	if !opts.omitUniqueID {
		echo := opts.echoUniqueID
		if echo == nil {
			echo = uniqueID
		}
		pkt = appendExtensionField(pkt, efUniqueIdentifier, echo)
	}
	for _, typ := range opts.extraEFs {
		pkt = appendExtensionField(pkt, typ, []byte("forward-compat"))
	}

	if !opts.omitAuth {
		key := opts.sealKey
		if key == nil {
			key = s2c
		}
		nonce := bytes.Repeat([]byte{0x3c}, 16)
		ct, err := key.Seal(opts.plaintext, pkt, nonce)
		if err != nil {
			tb.Fatalf("sealing the authenticator: %v", err)
		}
		pkt = append(pkt, buildAuthenticatorEF(nonce, ct)...)
	}
	if opts.trailingEFType != nil {
		pkt = appendExtensionField(pkt, *opts.trailingEFType, []byte("appended after the authenticator"))
	}
	return pkt
}

// --- acceptance --------------------------------------------------------------

// TestValidateNTPResponseAcceptsWellFormed proves the validator accepts a
// correct response and returns exactly the server's transmit timestamp (not the
// host clock, and not a rounded value).
func TestValidateNTPResponseAcceptsWellFormed(t *testing.T) {
	s2c := testSIV(t, 0x11)
	uniqueID := bytes.Repeat([]byte{0x7e}, 32)

	cases := []struct {
		name string
		xmit uint64
		want time.Time
	}{
		{name: "whole second", xmit: ntpTimestamp(1_700_000_000, 0), want: time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)},
		{name: "half second", xmit: ntpTimestamp(1_700_000_000, 0x8000_0000), want: time.Date(2023, 11, 14, 22, 13, 20, 500_000_000, time.UTC)},
		{name: "unix epoch", xmit: ntpTimestamp(0, 0), want: time.Unix(0, 0).UTC()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := buildTestNTSResponse(t, s2c, uniqueID, tc.xmit, nil)
			got, err := validateNTPResponse(resp, uniqueID, s2c)
			if err != nil {
				t.Fatalf("validateNTPResponse rejected a well-formed response: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("transmit timestamp = %s, want %s", got.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
		})
	}
}

// TestValidateNTPResponseAcceptsEncryptedPayload covers the shape real NTS
// servers send: fresh cookies inside the authenticator's encrypted payload. The
// client does not need them (it re-runs key establishment per query) but it must
// not choke on them, or every production server would look unreachable.
func TestValidateNTPResponseAcceptsEncryptedPayload(t *testing.T) {
	s2c := testSIV(t, 0x22)
	uniqueID := bytes.Repeat([]byte{0x01}, 32)
	// Two 100-byte cookies wrapped in cookie extension fields, as RFC 8915 does.
	var payload []byte
	payload = appendExtensionField(payload, efNTSCookie, bytes.Repeat([]byte{0xc1}, 100))
	payload = appendExtensionField(payload, efNTSCookie, bytes.Repeat([]byte{0xc2}, 100))

	resp := buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{plaintext: payload})
	if _, err := validateNTPResponse(resp, uniqueID, s2c); err != nil {
		t.Fatalf("a response carrying encrypted cookies must be accepted: %v", err)
	}
}

// TestValidateNTPResponseAcceptsUnknownExtensionFields checks forward
// compatibility: an unrecognized extension field between the identifier and the
// authenticator is part of the authenticated prefix, so it must be tolerated.
func TestValidateNTPResponseAcceptsUnknownExtensionFields(t *testing.T) {
	s2c := testSIV(t, 0x33)
	uniqueID := bytes.Repeat([]byte{0x02}, 32)
	resp := buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0),
		&testNTSResponseOpts{extraEFs: []uint16{0x0304, 0xbeef}})
	if _, err := validateNTPResponse(resp, uniqueID, s2c); err != nil {
		t.Fatalf("unknown extension fields must not break validation: %v", err)
	}
}

// --- rejection ---------------------------------------------------------------

// TestValidateNTPResponseRejects enumerates the ways a response must be refused.
// Each case is an attack an off-path or on-path adversary can actually mount
// against a UDP time query.
func TestValidateNTPResponseRejects(t *testing.T) {
	s2c := testSIV(t, 0x44)
	attacker := testSIV(t, 0x55)
	uniqueID := bytes.Repeat([]byte{0x7e}, 32)
	const xmit = 0xE7C0_0000_0000_0000 // some far-future era-0 timestamp

	// good is the response every mutator below starts from.
	good := func() []byte {
		return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), nil)
	}

	cases := []struct {
		name string
		// resp builds the response to validate.
		resp func() []byte
		// wantErrContains, when set, pins the rejection reason so a case cannot
		// silently start failing for an unrelated reason.
		wantErrContains string
	}{
		{
			name:            "empty datagram",
			resp:            func() []byte { return nil },
			wantErrContains: "too short",
		},
		{
			name:            "47-byte datagram is shorter than the NTP header",
			resp:            func() []byte { return make([]byte, 47) },
			wantErrContains: "too short",
		},
		{
			// A bare, unauthenticated NTP header is exactly what an off-path
			// spoofer can blast at the client.
			name: "plain NTP header with no extension fields",
			resp: func() []byte {
				pkt := make([]byte, 48)
				pkt[0] = 0x24
				binary.BigEndian.PutUint64(pkt[40:48], ntpTimestamp(1_700_000_000, 0))
				return pkt
			},
			wantErrContains: "Unique Identifier",
		},
		{
			// Mode 3 is a client packet: accepting one would let an attacker
			// reflect our own request back at us.
			name: "client mode instead of server mode",
			resp: func() []byte {
				b := byte(0x23)
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{firstByte: &b})
			},
			wantErrContains: "mode",
		},
		{
			name: "broadcast mode",
			resp: func() []byte {
				b := byte(0x25)
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{firstByte: &b})
			},
			wantErrContains: "mode",
		},
		{
			// Replay / off-path injection: a correctly-signed response for a
			// different query must not satisfy this query.
			name: "unique identifier from a different query",
			resp: func() []byte {
				other := bytes.Repeat([]byte{0x7f}, 32)
				return buildTestNTSResponse(t, s2c, other, ntpTimestamp(1_700_000_000, 0), nil)
			},
			wantErrContains: "Unique Identifier does not match",
		},
		{
			name: "unique identifier differing in one byte",
			resp: func() []byte {
				echo := append([]byte(nil), uniqueID...)
				echo[31] ^= 0x01
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{echoUniqueID: echo})
			},
			wantErrContains: "Unique Identifier does not match",
		},
		{
			name: "truncated unique identifier",
			resp: func() []byte {
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0),
					&testNTSResponseOpts{echoUniqueID: uniqueID[:16]})
			},
			wantErrContains: "Unique Identifier does not match",
		},
		{
			name: "missing unique identifier",
			resp: func() []byte {
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{omitUniqueID: true})
			},
			wantErrContains: "missing the Unique Identifier",
		},
		{
			name: "missing authenticator",
			resp: func() []byte {
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{omitAuth: true})
			},
			wantErrContains: "missing the NTS Authenticator",
		},
		{
			// The attacker knows the unique identifier (it is sent in the clear)
			// but not the S2C key, so a response sealed under any other key is
			// the canonical forgery attempt.
			name: "authenticator sealed with the wrong key",
			resp: func() []byte {
				return buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), &testNTSResponseOpts{sealKey: attacker})
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			// The whole point: the transmit timestamp is covered by the
			// authenticator, so rewriting the time invalidates the packet.
			name: "transmit timestamp rewritten after signing",
			resp: func() []byte {
				r := good()
				binary.BigEndian.PutUint64(r[40:48], xmit)
				return r
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			// The version/leap bits live in the same byte as the mode and are
			// also authenticated, so they cannot be rewritten either.
			name: "version downgraded to NTPv3 after signing",
			resp: func() []byte {
				r := good()
				r[0] = 0x1c // LI=0, VN=3, Mode=4 — still mode 4, so it passes the mode check
				return r
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			name: "stratum rewritten after signing",
			resp: func() []byte {
				r := good()
				r[1] ^= 0xff
				return r
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			name: "authenticator nonce tampered",
			resp: func() []byte {
				r := good()
				// The authenticator EF starts after the 48-byte header and the
				// 36-byte unique-identifier EF; its nonce begins 8 bytes in.
				r[48+36+8] ^= 0x01
				return r
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			name: "authenticator tag tampered",
			resp: func() []byte {
				r := good()
				r[len(r)-1] ^= 0x01
				return r
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			name: "authenticator truncated to nothing",
			resp: func() []byte {
				r := good()
				// Declare an authenticator EF with zero-length nonce and
				// ciphertext: AES-SIV has no tag to check.
				authOff := 48 + 36
				trimmed := append([]byte(nil), r[:authOff]...)
				trimmed = append(trimmed, 0x04, 0x04, 0x00, 0x10)
				trimmed = append(trimmed, make([]byte, 12)...)
				return trimmed
			},
			wantErrContains: "authenticator verification failed",
		},
		{
			name: "authenticator EF body shorter than its declared sections",
			resp: func() []byte {
				r := good()
				authOff := 48 + 36
				trimmed := append([]byte(nil), r[:authOff]...)
				// Declare a 16-byte nonce and 16-byte ciphertext in a 12-byte body.
				trimmed = append(trimmed, 0x04, 0x04, 0x00, 0x10)
				trimmed = append(trimmed, 0x00, 0x10, 0x00, 0x10)
				trimmed = append(trimmed, make([]byte, 8)...)
				return trimmed
			},
			wantErrContains: "authenticator EF length mismatch",
		},
		{
			name: "datagram truncated inside the authenticator",
			resp: func() []byte {
				r := good()
				return r[:len(r)-4]
			},
			wantErrContains: "malformed extension field",
		},
		{
			name: "extension field claiming a zero length",
			resp: func() []byte {
				pkt := make([]byte, 48)
				pkt[0] = 0x24
				return append(pkt, 0x01, 0x04, 0x00, 0x00)
			},
			wantErrContains: "malformed extension field",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateNTPResponse(tc.resp(), uniqueID, s2c)
			if err == nil {
				t.Fatalf("validateNTPResponse ACCEPTED a response it must reject, returning %s", got)
			}
			if !got.IsZero() {
				t.Fatalf("a rejected response must yield the zero time, got %s", got)
			}
			if tc.wantErrContains != "" && !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// TestValidateNTPResponseRejectsMisalignedExtensionField pins the consequence of
// the extension-field parser tolerating a length that is not a multiple of four:
// the offsets it derives no longer match the prefix the server authenticated, so
// the packet is rejected. The leniency therefore cannot be turned into an
// accepted forgery.
func TestValidateNTPResponseRejectsMisalignedExtensionField(t *testing.T) {
	s2c := testSIV(t, 0x66)
	uniqueID := bytes.Repeat([]byte{0x09}, 32)
	resp := buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), nil)

	// Shrink the unique-identifier EF's declared length from 36 to 35, shifting
	// every later offset by one byte.
	if got := binary.BigEndian.Uint16(resp[50:52]); got != 36 {
		t.Fatalf("precondition: unique-identifier EF length = %d, want 36", got)
	}
	binary.BigEndian.PutUint16(resp[50:52], 35)

	if _, err := validateNTPResponse(resp, uniqueID, s2c); err == nil {
		t.Fatal("a misaligned extension-field length must not produce an accepted response")
	}
}

// TestValidateNTPResponseRejectsAppendedExtensionField checks that bytes an
// attacker staples onto the end of a captured, validly-authenticated response
// cannot change the outcome in the attacker's favour: either they parse as an
// extension field the validator ignores (and the returned time is still the
// authenticated one) or the packet is rejected outright. What must never happen
// is a *different* time coming back.
func TestValidateNTPResponseRejectsAppendedExtensionField(t *testing.T) {
	s2c := testSIV(t, 0x77)
	uniqueID := bytes.Repeat([]byte{0x0a}, 32)
	want := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)

	trailing := uint16(0x0304)
	resp := buildTestNTSResponse(t, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0),
		&testNTSResponseOpts{trailingEFType: &trailing})

	// Either outcome is safe; a *different* time is not.
	if got, err := validateNTPResponse(resp, uniqueID, s2c); err == nil && !got.Equal(want) {
		t.Fatalf("appended bytes changed the validated time to %s, want %s", got, want)
	}

	// Appending a second unique identifier that does *not* match must never be
	// accepted, even though it sits outside the authenticated prefix: every
	// identifier field in the datagram has to match the one we sent.
	forged := append([]byte(nil), resp...)
	forged = appendExtensionField(forged, efUniqueIdentifier, bytes.Repeat([]byte{0xff}, 32))
	if _, err := validateNTPResponse(forged, uniqueID, s2c); err == nil {
		t.Fatal("an appended mismatching unique identifier must be rejected")
	}
}

// --- request construction ----------------------------------------------------

// TestBuildNTPRequestStructure verifies the client request is exactly what the
// server (and, symmetrically, validateNTPResponse) expects: a mode-3 NTPv4
// header, the unique identifier verbatim, the cookie, and an AES-SIV
// authenticator over everything preceding it.
func TestBuildNTPRequestStructure(t *testing.T) {
	c2s := testSIV(t, 0x88)
	uniqueID := bytes.Repeat([]byte{0xa1}, 32)
	cookie := bytes.Repeat([]byte{0xb2}, 100)

	req, err := buildNTPRequest(c2s, uniqueID, cookie)
	if err != nil {
		t.Fatalf("buildNTPRequest: %v", err)
	}
	if len(req) < 48 {
		t.Fatalf("request is %d bytes, shorter than the NTP header", len(req))
	}
	// LI=0, VN=4, Mode=3 (client).
	if req[0] != 0x23 {
		t.Fatalf("first byte = %#02x, want 0x23 (LI=0, VN=4, Mode=3)", req[0])
	}
	if vn := (req[0] >> 3) & 0x07; vn != 4 {
		t.Fatalf("version = %d, want 4", vn)
	}
	if mode := req[0] & 0x07; mode != 3 {
		t.Fatalf("mode = %d, want 3 (client)", mode)
	}
	// The client deliberately sends an all-zero transmit timestamp: RFC 8915
	// replaces the origin-timestamp echo check with the unique identifier, and
	// the offset is measured from local clock samples instead.
	for i, b := range req[1:48] {
		if b != 0 {
			t.Fatalf("NTP header byte %d = %#02x, want the header to be otherwise zero", i+1, b)
		}
	}

	fields, err := parseExtensionFields(req[48:])
	if err != nil {
		t.Fatalf("our own request does not parse: %v", err)
	}
	if len(fields) != 3 {
		t.Fatalf("request carries %d extension fields, want 3 (identifier, cookie, authenticator)", len(fields))
	}
	wantOrder := []uint16{efUniqueIdentifier, efNTSCookie, efNTSAuthenticator}
	for i, w := range wantOrder {
		if fields[i].typ != w {
			t.Fatalf("extension field %d type = %#04x, want %#04x", i, fields[i].typ, w)
		}
	}
	// The identifier must be byte-identical, because validateNTPResponse compares
	// the echoed field against these exact bytes.
	if !bytes.Equal(fields[0].body, uniqueID) {
		t.Fatalf("unique identifier on the wire = %x, want %x", fields[0].body, uniqueID)
	}
	if !bytes.HasPrefix(fields[1].body, cookie) {
		t.Fatalf("cookie on the wire = %x, want it to start with %x", fields[1].body, cookie)
	}

	// Server-side check: the authenticator must verify over the packet prefix.
	authStart := 48 + fields[2].offset
	nonce, ct, err := parseAuthenticatorEF(fields[2].body)
	if err != nil {
		t.Fatalf("parseAuthenticatorEF of our own authenticator: %v", err)
	}
	if len(nonce) != 16 {
		t.Fatalf("nonce length = %d, want 16", len(nonce))
	}
	if len(ct) != sivTagSize {
		t.Fatalf("ciphertext length = %d, want the %d-byte tag with no payload", len(ct), sivTagSize)
	}
	plaintext, err := c2s.Open(ct, req[:authStart], nonce)
	if err != nil {
		t.Fatalf("the server could not verify our request authenticator: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("request carries a %d-byte encrypted payload, want none", len(plaintext))
	}
	// Flipping any byte of the authenticated prefix must break verification.
	tampered := append([]byte(nil), req...)
	tampered[0] ^= 0x01
	if _, err := c2s.Open(ct, tampered[:authStart], nonce); err == nil {
		t.Fatal("the request authenticator does not actually cover the NTP header")
	}
}

// TestBuildNTPRequestUsesAFreshNonce guards against a deterministic nonce: two
// requests with identical inputs must differ, otherwise an on-path attacker
// could recognize and correlate queries (AES-SIV survives nonce reuse, but the
// nonce is also the only per-message variation in the packet).
func TestBuildNTPRequestUsesAFreshNonce(t *testing.T) {
	c2s := testSIV(t, 0x99)
	uniqueID := bytes.Repeat([]byte{0x01}, 32)
	cookie := bytes.Repeat([]byte{0x02}, 100)

	first, err := buildNTPRequest(c2s, uniqueID, cookie)
	if err != nil {
		t.Fatalf("buildNTPRequest: %v", err)
	}
	second, err := buildNTPRequest(c2s, uniqueID, cookie)
	if err != nil {
		t.Fatalf("buildNTPRequest: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("identical inputs produced different lengths: %d and %d", len(first), len(second))
	}
	if bytes.Equal(first, second) {
		t.Fatal("two requests with identical inputs are byte-identical: the authenticator nonce is not random")
	}
	// Only the authenticator (nonce and tag) may differ.
	if !bytes.Equal(first[:48+36+104], second[:48+36+104]) {
		t.Fatal("the header, identifier, and cookie must be identical across requests")
	}
}

// TestBuildNTPRequestRoundTripsThroughTheValidator closes the loop: a packet
// built by buildNTPRequest, re-emitted by a server as a mode-4 response with the
// same extension-field layout, must satisfy validateNTPResponse. This is the
// property that guarantees the builder and the validator agree on where the
// unique identifier lives and which prefix the authenticator covers.
func TestBuildNTPRequestRoundTripsThroughTheValidator(t *testing.T) {
	c2s := testSIV(t, 0xa1)
	s2c := testSIV(t, 0xa2)
	uniqueID := bytes.Repeat([]byte{0xcd}, 32)
	cookie := bytes.Repeat([]byte{0xef}, 100)

	req, err := buildNTPRequest(c2s, uniqueID, cookie)
	if err != nil {
		t.Fatalf("buildNTPRequest: %v", err)
	}
	// Read the identifier back out of the request exactly as a server would, then
	// echo it in a response. Nothing in this path re-uses the local uniqueID
	// variable, so a mis-encoded identifier would surface as a rejection.
	fields, err := parseExtensionFields(req[48:])
	if err != nil {
		t.Fatalf("parseExtensionFields: %v", err)
	}
	echoed := append([]byte(nil), fields[0].body...)

	xmit := ntpTimestamp(1_700_000_123, 0x4000_0000)
	resp := buildTestNTSResponse(t, s2c, echoed, xmit, nil)

	got, err := validateNTPResponse(resp, uniqueID, s2c)
	if err != nil {
		t.Fatalf("a response echoing the identifier from our own request was rejected: %v", err)
	}
	if want := time.Unix(1_700_000_123, 250_000_000).UTC(); !got.Equal(want) {
		t.Fatalf("validated time = %s, want %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// TestBuildNTPRequestRejectsUnencodableCookie checks that a cookie too large for
// the 16-bit extension-field length is refused instead of being silently
// truncated into a corrupt packet. Cookie bodies come from the NTS-KE server and
// are only bounded by that protocol's own 16-bit record length, so an oversized
// one is reachable from the wire.
func TestBuildNTPRequestRejectsUnencodableCookie(t *testing.T) {
	c2s := testSIV(t, 0xa3)
	uniqueID := bytes.Repeat([]byte{0x01}, 32)

	// 65535 is the largest body an NTS-KE cookie record can carry; with the
	// 4-byte extension-field header it cannot be expressed in 16 bits.
	_, err := buildNTPRequest(c2s, uniqueID, bytes.Repeat([]byte{0xaa}, 65535))
	if err == nil {
		t.Fatal("buildNTPRequest accepted a cookie that cannot be length-encoded")
	}
	if !strings.Contains(err.Error(), "cookie") {
		t.Fatalf("error = %q, want it to name the cookie", err.Error())
	}

	// The largest cookie that still fits must be accepted, and its encoded
	// length field must match the bytes emitted.
	maxCookie := bytes.Repeat([]byte{0xbb}, 65528)
	req, err := buildNTPRequest(c2s, uniqueID, maxCookie)
	if err != nil {
		t.Fatalf("buildNTPRequest rejected the largest encodable cookie: %v", err)
	}
	fields, err := parseExtensionFields(req[48:])
	if err != nil {
		t.Fatalf("parseExtensionFields: %v", err)
	}
	if len(fields) != 3 || fields[1].typ != efNTSCookie {
		t.Fatalf("expected 3 extension fields with a cookie second, got %d", len(fields))
	}
	if !bytes.HasPrefix(fields[1].body, maxCookie) {
		t.Fatal("the largest encodable cookie was not emitted intact")
	}
}
