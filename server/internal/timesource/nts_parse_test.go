package timesource

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Everything in this file parses bytes that arrive off the network from an
// unauthenticated UDP source (the NTP response) or from a TLS peer whose records
// are not otherwise validated (the NTS-KE stream). A panic in any of them takes
// down the process that is supposed to be gating the TSA, so the contract is:
// return an error, never panic, never loop forever, never hand back a slice that
// points outside the input.

// --- parseExtensionFields ----------------------------------------------------

// efRecord describes one extension field to synthesize with an arbitrary (and
// possibly lying) length field, which appendExtensionField cannot produce.
type efRecord struct {
	typ    uint16
	length uint16 // the value written into the wire length field
	body   []byte // the bytes actually emitted after the header
}

// buildEFRegion concatenates raw extension fields, writing each declared length
// verbatim so a test can claim a length that does not match the bytes present.
func buildEFRegion(recs ...efRecord) []byte {
	var out []byte
	for _, r := range recs {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], r.typ)
		binary.BigEndian.PutUint16(hdr[2:4], r.length)
		out = append(out, hdr[:]...)
		out = append(out, r.body...)
	}
	return out
}

// parseEFsBounded runs parseExtensionFields with a hard wall-clock bound so a
// length field that fails to advance the cursor shows up as a fast, readable
// failure instead of hanging the whole package until the go test timeout.
func parseEFsBounded(t *testing.T, region []byte) ([]extensionField, error) {
	t.Helper()
	type result struct {
		fields []extensionField
		err    error
	}
	done := make(chan result, 1)
	go func() {
		fields, err := parseExtensionFields(region)
		done <- result{fields, err}
	}()
	select {
	case r := <-done:
		return r.fields, r.err
	case <-time.After(5 * time.Second):
		t.Fatalf("parseExtensionFields did not return for %x — the cursor is not advancing", region)
		return nil, nil
	}
}

func TestParseExtensionFieldsUntrustedInput(t *testing.T) {
	cases := []struct {
		name       string
		region     []byte
		wantErr    bool
		wantFields int
		// wantBodyLens, when non-nil, pins each accepted field's body length.
		wantBodyLens []int
	}{
		{
			// No extension fields at all is a structurally valid (if useless)
			// region; validateNTPResponse rejects it later for the missing
			// unique identifier, which is where that policy belongs.
			name:   "empty region",
			region: nil,
		},
		{
			// Fewer than four bytes cannot hold a header. The parser stops and
			// ignores the tail rather than reading out of bounds.
			name:   "three trailing bytes cannot hold a header",
			region: []byte{0x01, 0x04, 0x00},
		},
		{
			// THE critical case: a declared length of zero would leave the cursor
			// where it is and spin forever. It must be rejected.
			name:    "zero length would not advance the cursor",
			region:  buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 0, body: bytes.Repeat([]byte{0}, 32)}),
			wantErr: true,
		},
		{
			name:    "length 1 is below the header size",
			region:  buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 1, body: bytes.Repeat([]byte{0}, 32)}),
			wantErr: true,
		},
		{
			name:    "length 3 is below the header size",
			region:  buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 3, body: bytes.Repeat([]byte{0}, 32)}),
			wantErr: true,
		},
		{
			// A length of exactly 4 is a header with an empty body. It advances
			// the cursor, so it is accepted even though RFC 7822 sets the minimum
			// at 16; the packet is rejected downstream because the authenticator
			// cannot cover a prefix the server did not authenticate.
			name:         "length 4 is an empty body",
			region:       buildEFRegion(efRecord{typ: 0x1234, length: 4}),
			wantFields:   1,
			wantBodyLens: []int{0},
		},
		{
			name:    "declared length exceeds the remaining bytes",
			region:  buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 64, body: bytes.Repeat([]byte{0xaa}, 8)}),
			wantErr: true,
		},
		{
			name:    "declared length 0xffff on a short region",
			region:  buildEFRegion(efRecord{typ: efNTSAuthenticator, length: 0xffff}),
			wantErr: true,
		},
		{
			name:    "second field overruns the region",
			region:  append(buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 16, body: bytes.Repeat([]byte{1}, 12)}), buildEFRegion(efRecord{typ: efNTSCookie, length: 128, body: bytes.Repeat([]byte{2}, 8)})...),
			wantErr: true,
		},
		{
			name:         "declared length exactly consumes the region",
			region:       buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 36, body: bytes.Repeat([]byte{0xaa}, 32)}),
			wantFields:   1,
			wantBodyLens: []int{32},
		},
		{
			// A non-multiple-of-4 length violates RFC 7822 and is accepted here.
			// That leniency cannot be turned into an accepted forgery: the
			// authenticator's associated data is derived from these offsets, so a
			// misaligned parse computes a different prefix than the server signed
			// and the packet is rejected (asserted in
			// TestValidateNTPResponseRejectsMisalignedExtensionField).
			name:         "unaligned length is tolerated but shifts later offsets",
			region:       buildEFRegion(efRecord{typ: 0x1234, length: 5, body: bytes.Repeat([]byte{0xaa}, 1)}),
			wantFields:   1,
			wantBodyLens: []int{1},
		},
		{
			// Unknown types must be skipped, not rejected: NTS servers are
			// allowed to include extension fields this client does not implement.
			name: "unknown types are skipped",
			region: append(
				buildEFRegion(efRecord{typ: 0xbeef, length: 16, body: bytes.Repeat([]byte{7}, 12)}),
				buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 36, body: bytes.Repeat([]byte{8}, 32)})...),
			wantFields:   2,
			wantBodyLens: []int{12, 32},
		},
		{
			// Duplicates are structurally fine here; validateNTPResponse checks
			// every unique-identifier field it finds, so a second, mismatching
			// copy cannot slip past.
			name: "duplicate unique identifiers both surface",
			region: append(
				buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 36, body: bytes.Repeat([]byte{1}, 32)}),
				buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 36, body: bytes.Repeat([]byte{2}, 32)})...),
			wantFields:   2,
			wantBodyLens: []int{32, 32},
		},
		{
			// A trailing partial header after a valid field is silently dropped.
			name:         "valid field followed by a two-byte stub",
			region:       append(buildEFRegion(efRecord{typ: efUniqueIdentifier, length: 36, body: bytes.Repeat([]byte{1}, 32)}), 0x01, 0x04),
			wantFields:   1,
			wantBodyLens: []int{32},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields, err := parseEFsBounded(t, tc.region)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseExtensionFields(%x) accepted a malformed region (%d fields)", tc.region, len(fields))
				}
				if fields != nil {
					t.Fatalf("a failed parse must not return fields, got %d", len(fields))
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExtensionFields(%x): unexpected error %v", tc.region, err)
			}
			if len(fields) != tc.wantFields {
				t.Fatalf("parsed %d fields, want %d", len(fields), tc.wantFields)
			}
			for i, f := range fields {
				if tc.wantBodyLens != nil && len(f.body) != tc.wantBodyLens[i] {
					t.Fatalf("field %d body length = %d, want %d", i, len(f.body), tc.wantBodyLens[i])
				}
				// Every returned body must be an in-bounds view of the input.
				end := f.offset + 4 + len(f.body)
				if f.offset < 0 || end > len(tc.region) {
					t.Fatalf("field %d spans [%d,%d) outside the %d-byte region", i, f.offset, end, len(tc.region))
				}
			}
		})
	}
}

// --- parseAuthenticatorEF ----------------------------------------------------

// authEFBody assembles an authenticator EF body with arbitrary declared lengths
// so the parser's bounds arithmetic can be probed directly.
func authEFBody(nonceLen, ctLen uint16, tail []byte) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], nonceLen)
	binary.BigEndian.PutUint16(body[2:4], ctLen)
	return append(body, tail...)
}

func TestParseAuthenticatorEFUntrustedInput(t *testing.T) {
	// A recognizable filler so the extracted slices can be checked by position.
	filler := make([]byte, 256)
	for i := range filler {
		filler[i] = byte(i)
	}

	cases := []struct {
		name      string
		body      []byte
		wantErr   bool
		wantNonce []byte
		wantCT    []byte
	}{
		{name: "empty body", body: nil, wantErr: true},
		{name: "one byte body", body: []byte{0x00}, wantErr: true},
		{name: "three byte body (header truncated)", body: []byte{0x00, 0x10, 0x00}, wantErr: true},
		{
			// The lengths a real NTS response carries: a 16-byte nonce and the
			// 16-byte AES-SIV tag with no ciphertext.
			name:      "nts shape",
			body:      authEFBody(16, 16, filler[:32]),
			wantNonce: filler[0:16],
			wantCT:    filler[16:32],
		},
		{
			name:    "body one byte short of the declared sections",
			body:    authEFBody(16, 16, filler[:31]),
			wantErr: true,
		},
		{
			// The dangerous case: 0xffff/0xffff would index far outside a short
			// body. It must be caught by the length check, not by a panic.
			name:    "maximum declared lengths on a 4-byte body",
			body:    authEFBody(0xffff, 0xffff, nil),
			wantErr: true,
		},
		{
			name:    "maximum nonce length with a plausible body",
			body:    authEFBody(0xffff, 0, filler),
			wantErr: true,
		},
		{
			// Zero lengths parse to empty slices. The packet is still rejected
			// downstream: AES-SIV Open needs at least a 16-byte tag.
			name:      "zero lengths",
			body:      authEFBody(0, 0, nil),
			wantNonce: []byte{},
			wantCT:    []byte{},
		},
		{
			// An unaligned nonce length must not shift the ciphertext: the
			// ciphertext starts after the *padded* nonce.
			name:      "unaligned nonce length pads before the ciphertext",
			body:      authEFBody(13, 16, filler[:32]),
			wantNonce: filler[0:13],
			wantCT:    filler[16:32],
		},
		{
			name:      "unaligned ciphertext length",
			body:      authEFBody(16, 17, filler[:36]),
			wantNonce: filler[0:16],
			wantCT:    filler[16:33],
		},
		{
			name:      "both lengths unaligned",
			body:      authEFBody(5, 3, filler[:12]),
			wantNonce: filler[0:5],
			wantCT:    filler[8:11],
		},
		{
			// Extra trailing bytes (the EF's own padding) are ignored.
			name:      "trailing padding is ignored",
			body:      authEFBody(16, 16, filler[:64]),
			wantNonce: filler[0:16],
			wantCT:    filler[16:32],
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce, ct, err := parseAuthenticatorEF(tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAuthenticatorEF(%x) accepted a malformed body (nonce %d, ct %d bytes)", tc.body, len(nonce), len(ct))
				}
				if nonce != nil || ct != nil {
					t.Fatal("a failed parse must not return a nonce or ciphertext")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAuthenticatorEF(%x): unexpected error %v", tc.body, err)
			}
			if !bytes.Equal(nonce, tc.wantNonce) {
				t.Fatalf("nonce = %x, want %x", nonce, tc.wantNonce)
			}
			if !bytes.Equal(ct, tc.wantCT) {
				t.Fatalf("ciphertext = %x, want %x", ct, tc.wantCT)
			}
		})
	}
}

// --- readFull ----------------------------------------------------------------

// scriptedConn is a net.Conn whose Read returns a pre-programmed sequence of
// chunks, optionally delivering the terminal error alongside the final chunk.
// Returning n > 0 together with io.EOF in one call is explicitly permitted by the
// io.Reader contract, so readFull has to cope with it.
type scriptedConn struct {
	net.Conn
	chunks    [][]byte
	finalErr  error
	eofOnLast bool // attach finalErr to the last chunk instead of a later call
	reads     int
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.chunks) == 0 {
		if c.finalErr != nil {
			return 0, c.finalErr
		}
		return 0, io.EOF
	}
	chunk := c.chunks[0]
	n := copy(p, chunk)
	if n < len(chunk) {
		c.chunks[0] = chunk[n:]
		return n, nil
	}
	c.chunks = c.chunks[1:]
	if len(c.chunks) == 0 && c.eofOnLast {
		err := c.finalErr
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	return n, nil
}

func TestReadFull(t *testing.T) {
	t.Run("assembles a short-read stream", func(t *testing.T) {
		// A TLS record boundary can split an NTS-KE header across Read calls;
		// readFull must keep going until the buffer is full.
		conn := &scriptedConn{chunks: [][]byte{{0x80}, {0x01, 0x00}, {0x02}}}
		buf := make([]byte, 4)
		if err := readFull(conn, buf); err != nil {
			t.Fatalf("readFull over a chunked stream: %v", err)
		}
		if !bytes.Equal(buf, []byte{0x80, 0x01, 0x00, 0x02}) {
			t.Fatalf("buffer = %x, want 80010002", buf)
		}
		if conn.reads < 3 {
			t.Fatalf("expected at least 3 reads to assemble the buffer, got %d", conn.reads)
		}
	})

	t.Run("data delivered with EOF in one call still succeeds", func(t *testing.T) {
		// io.Reader permits returning the last bytes together with io.EOF. A peer
		// that writes its NTS-KE response and closes immediately can surface
		// exactly this, and treating it as a failure would abort a handshake
		// whose bytes all arrived — the checker would then fail closed and the
		// TSA would refuse to sign for no reason.
		conn := &scriptedConn{chunks: [][]byte{{0x80, 0x00, 0x00, 0x00}}, eofOnLast: true}
		buf := make([]byte, 4)
		if err := readFull(conn, buf); err != nil {
			t.Fatalf("readFull returned %v even though the buffer was filled completely", err)
		}
		if !bytes.Equal(buf, []byte{0x80, 0x00, 0x00, 0x00}) {
			t.Fatalf("buffer = %x, want 80000000", buf)
		}
	})

	t.Run("short stream reports an error", func(t *testing.T) {
		conn := &scriptedConn{chunks: [][]byte{{0x80, 0x00}}, eofOnLast: true}
		buf := make([]byte, 4)
		err := readFull(conn, buf)
		if err == nil {
			t.Fatal("readFull must report an error when the stream ends early")
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected an EOF-flavoured error, got %v", err)
		}
	})

	t.Run("propagates a transport error", func(t *testing.T) {
		want := errors.New("connection reset")
		conn := &scriptedConn{finalErr: want}
		if err := readFull(conn, make([]byte, 4)); !errors.Is(err, want) {
			t.Fatalf("readFull error = %v, want %v", err, want)
		}
	})

	t.Run("empty buffer does not touch the conn", func(t *testing.T) {
		// readKEResponse skips the body read for a zero-length record; that must
		// not consume a read (nor surface a spurious EOF).
		conn := &scriptedConn{finalErr: errors.New("must not be read")}
		if err := readFull(conn, nil); err != nil {
			t.Fatalf("readFull with an empty buffer: %v", err)
		}
		if conn.reads != 0 {
			t.Fatalf("readFull read from the conn %d times for an empty buffer", conn.reads)
		}
	})
}

// --- address parsing ---------------------------------------------------------

// TestSplitHostPortDefault covers the address forms an operator can put in
// time.source.servers[].address. The result is fed straight to net.JoinHostPort,
// so the returned host must be the bare host — a form JoinHostPort can re-bracket
// — or the provider dials a syntactically invalid address and the time check
// fails closed for the lifetime of the process.
func TestSplitHostPortDefault(t *testing.T) {
	const defPort = ntsKEDefaultPort

	cases := []struct {
		name     string
		addr     string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "bare hostname takes the default port", addr: "time.cloudflare.com", wantHost: "time.cloudflare.com", wantPort: defPort},
		{name: "host with explicit port", addr: "time.nist.gov:4460", wantHost: "time.nist.gov", wantPort: 4460},
		{name: "host with a non-default port", addr: "ntp.example:1234", wantHost: "ntp.example", wantPort: 1234},
		{name: "surrounding whitespace is trimmed", addr: "  time.example  ", wantHost: "time.example", wantPort: defPort},
		{name: "bare IPv4", addr: "192.0.2.10", wantHost: "192.0.2.10", wantPort: defPort},
		{name: "IPv4 with port", addr: "192.0.2.10:4460", wantHost: "192.0.2.10", wantPort: 4460},
		{name: "bracketless IPv6 is a bare host", addr: "2001:db8::1", wantHost: "2001:db8::1", wantPort: defPort},
		{name: "bracketed IPv6 with port", addr: "[2001:db8::1]:4460", wantHost: "2001:db8::1", wantPort: 4460},
		{name: "bracketed IPv6 without a port", addr: "[2001:db8::1]", wantHost: "2001:db8::1", wantPort: defPort},
		{name: "bracketed loopback without a port", addr: "[::1]", wantHost: "::1", wantPort: defPort},
		{name: "empty address", addr: "", wantErr: true},
		{name: "whitespace-only address", addr: "   ", wantErr: true},
		{name: "non-numeric port", addr: "host:https", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := splitHostPortDefault(tc.addr, defPort)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitHostPortDefault(%q) = (%q, %d), want an error", tc.addr, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitHostPortDefault(%q): %v", tc.addr, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("splitHostPortDefault(%q) = (%q, %d), want (%q, %d)", tc.addr, host, port, tc.wantHost, tc.wantPort)
			}
			// The whole point of the split is to rebuild a dialable address.
			joined := net.JoinHostPort(host, "4460")
			if _, _, err := net.SplitHostPort(joined); err != nil {
				t.Fatalf("net.JoinHostPort(%q, \"4460\") = %q, which is not a valid address: %v", host, joined, err)
			}
			if strings.Contains(joined, "[[") || strings.Contains(joined, "]]") {
				t.Fatalf("host %q produced a double-bracketed address %q", host, joined)
			}
		})
	}
}

// --- fuzzing -----------------------------------------------------------------

// FuzzParseExtensionFields drives the NTP extension-field parser with arbitrary
// bytes. The region comes from an unauthenticated UDP datagram and is parsed
// *before* the authenticator is verified, so it is the most exposed parser in the
// package: it must never panic, never fail to terminate, and never return a field
// that points outside the input.
func FuzzParseExtensionFields(f *testing.F) {
	// Well-formed seeds.
	f.Add(appendExtensionField(nil, efUniqueIdentifier, bytes.Repeat([]byte{0xaa}, 32)))
	f.Add(appendExtensionField(appendExtensionField(nil, efUniqueIdentifier, bytes.Repeat([]byte{1}, 32)), efNTSCookie, bytes.Repeat([]byte{2}, 100)))
	f.Add(buildAuthenticatorEF(bytes.Repeat([]byte{0xa5}, 16), bytes.Repeat([]byte{0x5a}, 16)))
	// Edge and malformed seeds.
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x04, 0x00})
	f.Add([]byte{0x01, 0x04, 0x00, 0x00})             // length 0: must not spin
	f.Add([]byte{0x01, 0x04, 0x00, 0x03})             // length below the header size
	f.Add([]byte{0x01, 0x04, 0xff, 0xff})             // length far beyond the region
	f.Add([]byte{0x01, 0x04, 0x00, 0x05, 0x00})       // unaligned length
	f.Add([]byte{0x00, 0x00, 0x00, 0x04, 0x04, 0x04}) // empty body plus a stub

	f.Fuzz(func(t *testing.T, region []byte) {
		fields, err := parseExtensionFields(region)
		if err != nil {
			if fields != nil {
				t.Fatalf("error return must not also yield %d fields", len(fields))
			}
			return
		}
		prevEnd := 0
		for i, ef := range fields {
			if ef.offset != prevEnd {
				t.Fatalf("field %d starts at %d but the previous field ended at %d (gap or overlap)", i, ef.offset, prevEnd)
			}
			total := 4 + len(ef.body)
			if total < 4 {
				t.Fatalf("field %d has a total length of %d", i, total)
			}
			if ef.offset+total > len(region) {
				t.Fatalf("field %d spans [%d,%d) outside the %d-byte region", i, ef.offset, ef.offset+total, len(region))
			}
			// The parsed type and length must match what is on the wire.
			if got := binary.BigEndian.Uint16(region[ef.offset : ef.offset+2]); got != ef.typ {
				t.Fatalf("field %d type = %#04x, wire says %#04x", i, ef.typ, got)
			}
			if got := int(binary.BigEndian.Uint16(region[ef.offset+2 : ef.offset+4])); got != total {
				t.Fatalf("field %d total = %d, wire says %d", i, total, got)
			}
			prevEnd = ef.offset + total
		}
		// Whatever is left must be too small to hold another header, otherwise the
		// parser stopped early and silently ignored data.
		if rem := len(region) - prevEnd; rem >= 4 {
			t.Fatalf("parser stopped with %d unconsumed bytes", rem)
		}
	})
}

// FuzzValidateNTPResponse drives the whole response validator (header checks,
// extension-field parsing, authenticator parsing, AES-SIV verification) with
// arbitrary bytes under a fixed key. The invariant is fail-closed: a validated
// time is returned if and only if no error is returned, so no malformed datagram
// can ever yield a usable timestamp.
func FuzzValidateNTPResponse(f *testing.F) {
	key := make([]byte, ntsSIVKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	s2c, err := newAESSIV(key)
	if err != nil {
		f.Fatalf("newAESSIV: %v", err)
	}
	uniqueID := bytes.Repeat([]byte{0x42}, 32)

	valid := buildTestNTSResponse(f, s2c, uniqueID, ntpTimestamp(1_700_000_000, 0), nil)
	f.Add(valid)
	// A single flipped bit anywhere in a valid response.
	flipped := append([]byte(nil), valid...)
	flipped[50] ^= 0x01
	f.Add(flipped)
	f.Add(valid[:48])                           // header only, no extension fields
	f.Add(valid[:len(valid)-1])                 // truncated authenticator
	f.Add(make([]byte, 48))                     // all-zero header (mode 0)
	f.Add(append(make([]byte, 48), 0, 0, 0, 0)) // header plus a zero-length EF
	f.Add([]byte(nil))
	f.Add([]byte{0x24})

	f.Fuzz(func(t *testing.T, resp []byte) {
		got, err := validateNTPResponse(resp, uniqueID, s2c)
		if err != nil {
			if !got.IsZero() {
				t.Fatalf("rejected response still returned the time %s", got)
			}
			return
		}
		if got.IsZero() {
			t.Fatal("accepted a response but returned the zero time")
		}
		// An accepted response must carry the echoed unique identifier, and the
		// time must be the header's transmit timestamp — nothing else.
		if want := ntpToTime(be64(resp[40:48])); !got.Equal(want) {
			t.Fatalf("returned %s but the header transmit timestamp is %s", got, want)
		}
	})
}
