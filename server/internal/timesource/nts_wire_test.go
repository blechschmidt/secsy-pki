package timesource

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// These tests pin the exact wire encoding and the padding/epoch arithmetic that
// every NTS packet depends on. They are deliberately expressed as literal byte
// strings and literal calendar dates rather than by re-deriving the value from
// the code under test: an off-by-one in the padding math or a wrong epoch
// constant would otherwise be invisible (the TSA would happily sign a timestamp
// that is decades wrong, or the NTP server would silently drop every request and
// the checker would fail closed forever).

// --- NTP timestamp conversion ------------------------------------------------

// TestNTPToTimeKnownInstants checks the era-0 NTP timestamp conversion against
// externally-known instants. ntpToTime feeds Reading.Time, which the audit log
// records as the trusted time, so a wrong epoch offset or a wrong fraction scale
// is a silent multi-decade (or sub-second) time error.
func TestNTPToTimeKnownInstants(t *testing.T) {
	// The epoch offset itself is a protocol constant; pin it so a typo cannot
	// slip through unnoticed.
	if ntpUnixEpochOffset != 2208988800 {
		t.Fatalf("ntpUnixEpochOffset = %d, want 2208988800 (seconds between 1900-01-01 and 1970-01-01)", ntpUnixEpochOffset)
	}

	const unixEpochNTPSeconds = 2208988800

	cases := []struct {
		name string
		ts   uint64
		want time.Time
	}{
		{
			// The NTP epoch itself. Pins the epoch offset from the 1900 side.
			name: "ntp epoch 1900-01-01",
			ts:   0,
			want: time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			// Pins the epoch offset from the Unix side: 2208988800 NTP seconds
			// must be exactly Unix time 0.
			name: "unix epoch 1970-01-01",
			ts:   unixEpochNTPSeconds << 32,
			want: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "one second after the unix epoch",
			ts:   (unixEpochNTPSeconds + 1) << 32,
			want: time.Unix(1, 0).UTC(),
		},
		{
			// A concrete modern instant (the timestamp used across this package's
			// tests): Unix 1700000000 == 2023-11-14T22:13:20Z.
			name: "2023-11-14T22:13:20Z",
			ts:   (unixEpochNTPSeconds + 1_700_000_000) << 32,
			want: time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC),
		},
		{
			// Fraction 0x80000000 is exactly one half second.
			name: "half second fraction",
			ts:   (unixEpochNTPSeconds << 32) | 0x8000_0000,
			want: time.Unix(0, 500_000_000).UTC(),
		},
		{
			name: "quarter second fraction",
			ts:   (unixEpochNTPSeconds << 32) | 0x4000_0000,
			want: time.Unix(0, 250_000_000).UTC(),
		},
		{
			// The largest representable fraction must stay strictly below one
			// second: truncation, never a carry into the next second.
			name: "maximum fraction stays below one second",
			ts:   (unixEpochNTPSeconds << 32) | 0xffff_ffff,
			want: time.Unix(0, 999_999_999).UTC(),
		},
		{
			// The last instant of NTP era 0. The well-known rollover is
			// 2036-02-07T06:28:16Z, so the maximum era-0 second is one earlier.
			name: "last second of NTP era 0",
			ts:   0xffff_ffff_0000_0000,
			want: time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ntpToTime(tc.ts)
			if !got.Equal(tc.want) {
				t.Fatalf("ntpToTime(%#016x) = %s, want %s", tc.ts, got.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
			if loc := got.Location(); loc != time.UTC {
				t.Fatalf("ntpToTime must return a UTC time, got location %v", loc)
			}
		})
	}
}

// TestNTPToTimeIsMonotonicInTheFraction guards the fraction scaling: consecutive
// fraction values must map to non-decreasing nanoseconds and never leak into the
// seconds field.
func TestNTPToTimeIsMonotonicInTheFraction(t *testing.T) {
	const sec = uint64(2208988800) // Unix epoch, so the expected second is 0
	prev := int64(-1)
	for _, frac := range []uint64{0, 1, 0x1000, 0x4000_0000, 0x8000_0000, 0xc000_0000, 0xffff_fffe, 0xffff_ffff} {
		got := ntpToTime(sec<<32 | frac)
		if got.Unix() != 0 {
			t.Fatalf("fraction %#08x leaked into the seconds field: %s", frac, got.Format(time.RFC3339Nano))
		}
		ns := int64(got.Nanosecond())
		if ns < prev {
			t.Fatalf("fraction %#08x produced %d ns, which is below the previous %d ns", frac, ns, prev)
		}
		prev = ns
	}
}

// --- byte helpers ------------------------------------------------------------

// TestBE16 pins the big-endian encoding used for every NTS-KE record body.
func TestBE16(t *testing.T) {
	cases := []struct {
		in   uint16
		want string
	}{
		{0, "0000"},
		{1, "0001"},
		{ntsNextProtoNTPv4, "0000"},
		{ntsAEADAesSivCmac256, "000f"},
		{efUniqueIdentifier, "0104"},
		{0x1234, "1234"},
		{0xffff, "ffff"},
	}
	for _, tc := range cases {
		got := be16(tc.in)
		if len(got) != 2 {
			t.Fatalf("be16(%d) returned %d bytes, want 2", tc.in, len(got))
		}
		if hex.EncodeToString(got) != tc.want {
			t.Fatalf("be16(%d) = %x, want %s", tc.in, got, tc.want)
		}
	}
}

// TestBE64 pins the big-endian 64-bit read used to lift the NTP transmit
// timestamp out of the response header. A byte-order mistake here would yield a
// nonsense time that still parses.
func TestBE64(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"0000000000000000", 0},
		{"0000000000000001", 1},
		{"0100000000000000", 1 << 56},
		{"ffffffffffffffff", ^uint64(0)},
		{"83aa7e8000000000", 2208988800 << 32}, // the Unix epoch as an NTP timestamp
	}
	for _, tc := range cases {
		if got := be64(mustHex(t, tc.in)); got != tc.want {
			t.Fatalf("be64(%s) = %#x, want %#x", tc.in, got, tc.want)
		}
	}

	// be64 must read the first eight bytes and ignore any tail, because it is
	// applied to a sub-slice of a larger packet.
	long := append(mustHex(t, "0000000000000001"), 0xff, 0xff)
	if got := be64(long); got != 1 {
		t.Fatalf("be64 of an over-long slice = %#x, want 1", got)
	}

	// Round-trip against the standard library encoder.
	for _, v := range []uint64{0, 1, 42, 1 << 31, 1 << 63, ^uint64(0)} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		if got := be64(b[:]); got != v {
			t.Fatalf("be64 round-trip for %#x gave %#x", v, got)
		}
	}
}

// --- padding / alignment arithmetic ------------------------------------------

// TestPad4AndRoundUp4 walks the exact 4-octet alignment boundaries. Every NTS
// extension field and the authenticator's nonce/ciphertext sections are padded
// with these two helpers; an off-by-one corrupts every packet the client sends
// and misplaces every field it parses.
func TestPad4AndRoundUp4(t *testing.T) {
	cases := []struct {
		n       int
		wantPad int
		wantUp  int
	}{
		{n: 0, wantPad: 0, wantUp: 0}, // already aligned: no padding at all
		{n: 1, wantPad: 3, wantUp: 4},
		{n: 2, wantPad: 2, wantUp: 4},
		{n: 3, wantPad: 1, wantUp: 4},
		{n: 4, wantPad: 0, wantUp: 4}, // exact boundary must not add a whole extra word
		{n: 5, wantPad: 3, wantUp: 8},
		{n: 7, wantPad: 1, wantUp: 8},
		{n: 8, wantPad: 0, wantUp: 8},
		{n: 15, wantPad: 1, wantUp: 16},
		{n: 16, wantPad: 0, wantUp: 16}, // the AES-SIV tag and nonce length: must never be padded
		{n: 17, wantPad: 3, wantUp: 20},
		{n: 32, wantPad: 0, wantUp: 32}, // the unique-identifier length
		{n: 1024, wantPad: 0, wantUp: 1024},
		{n: 1025, wantPad: 3, wantUp: 1028},
		{n: 65535, wantPad: 1, wantUp: 65536}, // the largest length a 16-bit wire field can claim
	}
	for _, tc := range cases {
		pad := pad4(tc.n)
		if len(pad) != tc.wantPad {
			t.Fatalf("len(pad4(%d)) = %d, want %d", tc.n, len(pad), tc.wantPad)
		}
		for i, b := range pad {
			if b != 0 {
				t.Fatalf("pad4(%d) byte %d = %#x, want a zero byte", tc.n, i, b)
			}
		}
		if got := roundUp4(tc.n); got != tc.wantUp {
			t.Fatalf("roundUp4(%d) = %d, want %d", tc.n, got, tc.wantUp)
		}
		// The two helpers must agree: the padded total is the rounded-up length.
		if tc.n+len(pad) != roundUp4(tc.n) {
			t.Fatalf("pad4/roundUp4 disagree for %d: %d+%d != %d", tc.n, tc.n, len(pad), roundUp4(tc.n))
		}
		if roundUp4(tc.n)%4 != 0 {
			t.Fatalf("roundUp4(%d) = %d is not 4-octet aligned", tc.n, roundUp4(tc.n))
		}
		if up := roundUp4(tc.n); up < tc.n || up >= tc.n+4 {
			t.Fatalf("roundUp4(%d) = %d must be in [%d, %d)", tc.n, up, tc.n, tc.n+4)
		}
	}
	// Both helpers are only ever called with a slice length, so negative inputs
	// are unreachable and deliberately not specified here.
}

// --- extension-field encoding ------------------------------------------------

// TestAppendExtensionFieldEncoding pins the RFC 7822 extension-field layout and
// proves appendExtensionField round-trips through parseExtensionFields — the two
// halves of the wire format the NTS exchange stands on.
func TestAppendExtensionFieldEncoding(t *testing.T) {
	cases := []struct {
		name      string
		valueLen  int
		wantTotal int
	}{
		// Below the RFC 7822 minimum the field is padded out to 16 octets.
		{name: "empty value pads to the 16-octet minimum", valueLen: 0, wantTotal: 16},
		{name: "one byte pads to the minimum", valueLen: 1, wantTotal: 16},
		{name: "eleven bytes still fit the minimum", valueLen: 11, wantTotal: 16},
		{name: "twelve bytes exactly fill the minimum", valueLen: 12, wantTotal: 16},
		{name: "thirteen bytes cross the minimum", valueLen: 13, wantTotal: 20},
		{name: "unique identifier", valueLen: 32, wantTotal: 36},
		{name: "aligned cookie", valueLen: 100, wantTotal: 104},
		{name: "unaligned cookie rounds up", valueLen: 99, wantTotal: 104},
		{name: "unaligned cookie rounds up by one", valueLen: 97, wantTotal: 104},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := make([]byte, tc.valueLen)
			for i := range value {
				value[i] = byte(i%251 + 1) // non-zero, so padding is distinguishable
			}
			// A non-empty prefix stands in for the 48-byte NTP header: the helper
			// must append, never overwrite.
			prefix := []byte{0xde, 0xad, 0xbe, 0xef}
			pkt := appendExtensionField(append([]byte(nil), prefix...), efNTSCookie, value)

			if !bytes.Equal(pkt[:len(prefix)], prefix) {
				t.Fatalf("appendExtensionField clobbered the packet prefix: %x", pkt[:len(prefix)])
			}
			region := pkt[len(prefix):]
			if len(region) != tc.wantTotal {
				t.Fatalf("appended %d bytes, want %d", len(region), tc.wantTotal)
			}
			if typ := binary.BigEndian.Uint16(region[0:2]); typ != efNTSCookie {
				t.Fatalf("encoded type = %#04x, want %#04x", typ, efNTSCookie)
			}
			// The length field must describe the bytes actually appended,
			// otherwise the server parses a different packet than we sent.
			if declared := int(binary.BigEndian.Uint16(region[2:4])); declared != len(region) {
				t.Fatalf("declared length %d does not match the %d bytes appended", declared, len(region))
			}
			if len(region)%4 != 0 {
				t.Fatalf("extension field length %d is not 4-octet aligned", len(region))
			}
			if len(region) < 16 {
				t.Fatalf("extension field length %d is below the RFC 7822 minimum of 16", len(region))
			}
			if !bytes.Equal(region[4:4+tc.valueLen], value) {
				t.Fatalf("value not preserved: got %x want %x", region[4:4+tc.valueLen], value)
			}
			for i, b := range region[4+tc.valueLen:] {
				if b != 0 {
					t.Fatalf("padding byte %d = %#x, want zero", i, b)
				}
			}

			// Round-trip: the parser must recover the field at offset 0 with the
			// value as the body prefix.
			fields, err := parseExtensionFields(region)
			if err != nil {
				t.Fatalf("parseExtensionFields of our own encoding failed: %v", err)
			}
			if len(fields) != 1 {
				t.Fatalf("parsed %d fields, want 1", len(fields))
			}
			if fields[0].typ != efNTSCookie || fields[0].offset != 0 {
				t.Fatalf("parsed field = {typ:%#04x offset:%d}, want {typ:%#04x offset:0}", fields[0].typ, fields[0].offset, efNTSCookie)
			}
			if len(fields[0].body) != tc.wantTotal-4 {
				t.Fatalf("parsed body length %d, want %d", len(fields[0].body), tc.wantTotal-4)
			}
			if !bytes.HasPrefix(fields[0].body, value) {
				t.Fatalf("parsed body %x does not start with the value %x", fields[0].body, value)
			}
		})
	}
}

// TestAppendExtensionFieldSequenceOffsets checks that a chain of appended fields
// parses back with the exact byte offsets the authenticator's associated-data
// computation relies on (authStart = 48 + offset). A wrong offset makes the
// client authenticate a different prefix than the server did, so every response
// would be rejected and the TSA would stall.
func TestAppendExtensionFieldSequenceOffsets(t *testing.T) {
	uniqueID := bytes.Repeat([]byte{0x11}, 32)
	cookie := bytes.Repeat([]byte{0x22}, 100)
	trailer := bytes.Repeat([]byte{0x33}, 5)

	var region []byte
	region = appendExtensionField(region, efUniqueIdentifier, uniqueID)
	region = appendExtensionField(region, efNTSCookie, cookie)
	region = appendExtensionField(region, 0x0999, trailer)

	fields, err := parseExtensionFields(region)
	if err != nil {
		t.Fatalf("parseExtensionFields: %v", err)
	}
	want := []struct {
		typ    uint16
		offset int
		total  int
	}{
		{efUniqueIdentifier, 0, 36},
		{efNTSCookie, 36, 104},
		{0x0999, 140, 16},
	}
	if len(fields) != len(want) {
		t.Fatalf("parsed %d fields, want %d", len(fields), len(want))
	}
	for i, w := range want {
		if fields[i].typ != w.typ {
			t.Fatalf("field %d type = %#04x, want %#04x", i, fields[i].typ, w.typ)
		}
		if fields[i].offset != w.offset {
			t.Fatalf("field %d offset = %d, want %d", i, fields[i].offset, w.offset)
		}
		if got := 4 + len(fields[i].body); got != w.total {
			t.Fatalf("field %d total length = %d, want %d", i, got, w.total)
		}
		// The recorded offset must point at this field's header in the region.
		if typ := binary.BigEndian.Uint16(region[fields[i].offset : fields[i].offset+2]); typ != w.typ {
			t.Fatalf("offset %d does not point at field %d's header", fields[i].offset, i)
		}
	}
	if total := want[2].offset + want[2].total; total != len(region) {
		t.Fatalf("fields cover %d bytes but the region is %d bytes", total, len(region))
	}
}

// TestBuildAuthenticatorEFRoundTrip proves the authenticator EF builder and
// parser agree on the nonce/ciphertext split, including the unaligned nonce
// lengths where the padding arithmetic actually bites.
func TestBuildAuthenticatorEFRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		nonceLen int
		ctLen    int
	}{
		{name: "NTS shape: 16-byte nonce, tag-only ciphertext", nonceLen: 16, ctLen: 16},
		{name: "tag plus encrypted cookies", nonceLen: 16, ctLen: 16 + 104},
		{name: "unaligned nonce", nonceLen: 13, ctLen: 16},
		{name: "unaligned ciphertext", nonceLen: 16, ctLen: 17},
		{name: "both unaligned", nonceLen: 15, ctLen: 15},
		{name: "empty ciphertext", nonceLen: 16, ctLen: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := bytes.Repeat([]byte{0xa5}, tc.nonceLen)
			ct := bytes.Repeat([]byte{0x5a}, tc.ctLen)

			ef := buildAuthenticatorEF(nonce, ct)
			if len(ef)%4 != 0 {
				t.Fatalf("authenticator EF length %d is not 4-octet aligned", len(ef))
			}
			if typ := binary.BigEndian.Uint16(ef[0:2]); typ != efNTSAuthenticator {
				t.Fatalf("EF type = %#04x, want %#04x", typ, efNTSAuthenticator)
			}
			if declared := int(binary.BigEndian.Uint16(ef[2:4])); declared != len(ef) {
				t.Fatalf("declared length %d does not match the %d bytes emitted", declared, len(ef))
			}

			gotNonce, gotCT, err := parseAuthenticatorEF(ef[4:])
			if err != nil {
				t.Fatalf("parseAuthenticatorEF of our own encoding: %v", err)
			}
			if !bytes.Equal(gotNonce, nonce) {
				t.Fatalf("nonce round-trip: got %x want %x", gotNonce, nonce)
			}
			if !bytes.Equal(gotCT, ct) {
				t.Fatalf("ciphertext round-trip: got %x want %x", gotCT, ct)
			}

			// It must also survive the generic EF parser, which is how
			// validateNTPResponse actually reaches it.
			fields, err := parseExtensionFields(ef)
			if err != nil {
				t.Fatalf("parseExtensionFields: %v", err)
			}
			if len(fields) != 1 || fields[0].typ != efNTSAuthenticator {
				t.Fatalf("generic parse produced %d fields (first type %#04x)", len(fields), fields[0].typ)
			}
			n2, c2, err := parseAuthenticatorEF(fields[0].body)
			if err != nil {
				t.Fatalf("parseAuthenticatorEF via the generic parser: %v", err)
			}
			if !bytes.Equal(n2, nonce) || !bytes.Equal(c2, ct) {
				t.Fatal("nonce/ciphertext differ when reached through parseExtensionFields")
			}
		})
	}
}

// --- NTS-KE request encoding -------------------------------------------------

// TestBuildKERequestExactBytes pins the NTS-KE request byte for byte. The
// request is fixed (negotiate NTPv4 + AES-SIV-CMAC-256, then End of Message), so
// a literal comparison is the strongest possible check: a server that cannot
// parse it leaves the checker permanently unable to reach a trusted source.
func TestBuildKERequestExactBytes(t *testing.T) {
	// 8001 0002 0000 : critical, Next Protocol Negotiation, body = NTPv4 (0)
	// 8004 0002 000f : critical, AEAD Algorithm Negotiation, body = AES-SIV-CMAC-256 (15)
	// 8000 0000      : critical, End of Message, empty body
	const want = "80010002000080040002000f80000000"
	got := buildKERequest()
	if hex.EncodeToString(got) != want {
		t.Fatalf("buildKERequest() = %x, want %s", got, want)
	}
	// End of Message must be last, or the server waits for more records forever.
	if typ := binary.BigEndian.Uint16(got[len(got)-4:len(got)-2]) & 0x7fff; typ != ntsRecEndOfMessage {
		t.Fatalf("last record type = %d, want End of Message (%d)", typ, ntsRecEndOfMessage)
	}
}

// TestAppendKERecord covers the record header: the critical bit, the 15-bit type
// masking, the body length, and appending to a non-empty buffer.
func TestAppendKERecord(t *testing.T) {
	cases := []struct {
		name     string
		critical bool
		recType  uint16
		body     []byte
		want     string
	}{
		{name: "critical empty body", critical: true, recType: ntsRecEndOfMessage, body: nil, want: "80000000"},
		{name: "non-critical empty body", critical: false, recType: ntsRecEndOfMessage, body: nil, want: "00000000"},
		{name: "critical with body", critical: true, recType: ntsRecAEAD, body: be16(ntsAEADAesSivCmac256), want: "80040002000f"},
		{name: "non-critical with body", critical: false, recType: ntsRecCookie, body: []byte{1, 2, 3}, want: "000500030102 03"},
		{
			// The type is a 15-bit field: the high bit belongs to the critical
			// flag and must be masked off rather than corrupting the type.
			name: "high bit in the type is masked off", critical: false, recType: 0x8007, body: nil, want: "00070000",
		},
		{name: "high bit masked with critical set", critical: true, recType: 0x8007, body: nil, want: "80070000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(t, stripSpaces(tc.want))
			prefix := []byte{0xaa, 0xbb}
			got := appendKERecord(append([]byte(nil), prefix...), tc.critical, tc.recType, tc.body)
			if !bytes.Equal(got[:len(prefix)], prefix) {
				t.Fatalf("appendKERecord clobbered the prefix: %x", got[:len(prefix)])
			}
			if !bytes.Equal(got[len(prefix):], want) {
				t.Fatalf("record = %x, want %x", got[len(prefix):], want)
			}
			if declared := int(binary.BigEndian.Uint16(got[len(prefix)+2 : len(prefix)+4])); declared != len(tc.body) {
				t.Fatalf("declared body length %d, want %d", declared, len(tc.body))
			}
		})
	}
}

// TestExporterContextSeparatesDirections pins the RFC 5705 exporter context and,
// crucially, that the two directions differ. If C2S and S2C derived the same key
// an attacker could reflect the client's own request back as a "response" and it
// would authenticate — a trivial time-forgery.
func TestExporterContextSeparatesDirections(t *testing.T) {
	c2s := exporterContext(0x00)
	s2c := exporterContext(0x01)

	// next protocol (NTPv4 = 0) || AEAD id (AES-SIV-CMAC-256 = 15) || key type
	if got, want := hex.EncodeToString(c2s), "0000000f00"; got != want {
		t.Fatalf("exporterContext(0x00) = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(s2c), "0000000f01"; got != want {
		t.Fatalf("exporterContext(0x01) = %s, want %s", got, want)
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("the C2S and S2C exporter contexts must differ, otherwise the two directions share a key")
	}
	if len(c2s) != 5 {
		t.Fatalf("exporter context length = %d, want 5", len(c2s))
	}
	if ntsExporterLabel != "EXPORTER-network-time-security" {
		t.Fatalf("exporter label = %q, want the RFC 8915 label", ntsExporterLabel)
	}
}

// --- Roughtime request encoding ----------------------------------------------

// TestBuildRoughtimeRequest checks the two properties the request must have: the
// nonce is carried verbatim (otherwise the Merkle check can never succeed) and
// the datagram is padded past the minimum size so the server cannot be used as a
// UDP amplifier.
func TestBuildRoughtimeRequest(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5a}, roughtimeNonceLen)
	req := buildRoughtimeRequest(nonce)

	if len(req) < roughtimeMinRequestLen {
		t.Fatalf("request is %d bytes, below the %d-byte minimum (amplification guard)", len(req), roughtimeMinRequestLen)
	}
	fields, err := decodeRoughtimeMessage(req)
	if err != nil {
		t.Fatalf("our own request does not decode: %v", err)
	}
	gotNonce, ok := fields[tagNONC]
	if !ok {
		t.Fatal("request is missing the NONC tag")
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Fatalf("NONC = %x, want %x", gotNonce, nonce)
	}
	pad, ok := fields[tagPAD]
	if !ok {
		t.Fatal("request is missing the PAD tag, so it is below the minimum size")
	}
	if len(pad) == 0 {
		t.Fatal("PAD is present but empty")
	}
	if n := binary.LittleEndian.Uint32(req[0:4]); n != 2 {
		t.Fatalf("request declares %d tags, want 2 (NONC and PAD)", n)
	}
	// Tags must be in ascending order and value offsets must be multiples of 4.
	first := binary.LittleEndian.Uint32(req[8:12])
	second := binary.LittleEndian.Uint32(req[12:16])
	if first >= second {
		t.Fatalf("tags are not in ascending order: %#08x then %#08x", first, second)
	}
	if first != tagNONC || second != tagPAD {
		t.Fatalf("tags = %#08x, %#08x; want NONC %#08x then PAD %#08x", first, second, tagNONC, tagPAD)
	}
	if off := binary.LittleEndian.Uint32(req[4:8]); off%4 != 0 || int(off) != roughtimeNonceLen {
		t.Fatalf("value offset = %d, want %d and 4-octet aligned", off, roughtimeNonceLen)
	}
}

// stripSpaces removes the readability spaces from the hex literals above.
func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
