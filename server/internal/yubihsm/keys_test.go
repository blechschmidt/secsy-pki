package yubihsm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Wire-encoding tests for the object-lifecycle and signing commands, driven
// through the fake device in fakedevice_test.go.
//
// These commands are the ones with no reply to check them against: the device
// answers GENERATE ASYMMETRIC KEY with an object id and nothing else, so a
// field written at the wrong offset does not fail — it creates a key with the
// wrong capabilities, or in the wrong domain, and reports success. The audit
// and attestation subsystems then make claims about that key. Asserting the
// exact bytes is therefore the only place the encoding is checked at all.
//
// The offsets are Yubico's, confirmed against the device by the hardware tier
// (scripts/yubihsm-test.sh); pinning them here means a refactor cannot move a
// field without a test failing on a machine with no HSM attached.

// captureCommand registers a handler that records the request body for cmd and
// answers with reply.
func captureCommand(d *fakeDevice, cmd byte, reply []byte) *[]byte {
	var got []byte
	d.handlers[cmd] = func(data []byte) ([]byte, error) {
		got = append([]byte(nil), data...)
		return reply, nil
	}
	return &got
}

// refuseCommand registers a handler that fails with the given device error.
func refuseCommand(d *fakeDevice, cmd byte, e DeviceError) {
	d.handlers[cmd] = func([]byte) ([]byte, error) { return nil, e }
}

func TestKeySpecEncodeHeaderLayout(t *testing.T) {
	spec := KeySpec{
		ID:           0x1234,
		Label:        "ledger-head",
		Domains:      0x0001,
		Capabilities: 0x0000000000000104,
		Algorithm:    AlgorithmECP256,
	}
	got, err := spec.encodeHeader()
	if err != nil {
		t.Fatalf("encoding a valid key spec: %v", err)
	}

	// id (2) | label (40, NUL padded) | domains (2) | capabilities (8) | algorithm (1)
	if len(got) != 2+labelLen+2+8+1 {
		t.Fatalf("header is %d bytes, want %d", len(got), 2+labelLen+2+8+1)
	}
	if id := binary.BigEndian.Uint16(got[:2]); id != 0x1234 {
		t.Fatalf("id encoded as 0x%04x", id)
	}
	label := got[2 : 2+labelLen]
	if string(label[:len(spec.Label)]) != spec.Label {
		t.Fatalf("label encoded as %q", label)
	}
	// The label field is fixed width: everything after the text must be NUL, or
	// the device stores whatever followed it in memory as part of the name.
	if !bytes.Equal(label[len(spec.Label):], make([]byte, labelLen-len(spec.Label))) {
		t.Fatalf("label field is not NUL padded: %x", label)
	}
	if dom := binary.BigEndian.Uint16(got[2+labelLen : 4+labelLen]); dom != spec.Domains {
		t.Fatalf("domains encoded as 0x%04x", dom)
	}
	if caps := binary.BigEndian.Uint64(got[4+labelLen : 12+labelLen]); caps != spec.Capabilities {
		t.Fatalf("capabilities encoded as 0x%016x", caps)
	}
	if got[12+labelLen] != AlgorithmECP256 {
		t.Fatalf("algorithm encoded as %d", got[12+labelLen])
	}
}

// A label exactly at the limit must still encode — internal/hsmaudit's serial
// binding fills the field to its last byte on purpose, so an off-by-one here
// would break the commitment scheme rather than a cosmetic name.
func TestKeySpecEncodeHeaderAcceptsAFullLabel(t *testing.T) {
	spec := KeySpec{Label: strings.Repeat("x", labelLen), Domains: 1, Algorithm: AlgorithmECP256}
	got, err := spec.encodeHeader()
	if err != nil {
		t.Fatalf("a %d-byte label was rejected: %v", labelLen, err)
	}
	if string(got[2:2+labelLen]) != spec.Label {
		t.Fatalf("full-width label encoded as %q", got[2:2+labelLen])
	}
}

func TestKeySpecEncodeHeaderRejectsUnusableSpecs(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec KeySpec
		want string
	}{
		{
			// Silently truncating would name the key something other than what
			// the caller asked for, which for an attested key is the claim.
			name: "over-long label",
			spec: KeySpec{Label: strings.Repeat("x", labelLen+1), Domains: 1, Algorithm: AlgorithmECP256},
			want: "above the device limit",
		},
		{
			// The device rejects domain 0; catching it here names the key.
			name: "no domain",
			spec: KeySpec{Label: "k", Domains: 0, Algorithm: AlgorithmECP256},
			want: "at least one domain",
		},
		{
			name: "no algorithm",
			spec: KeySpec{Label: "k", Domains: 1},
			want: "no algorithm",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.spec.encodeHeader(); err == nil {
				t.Fatal("an unusable key spec encoded cleanly")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGenerateAsymmetricKeySendsTheHeaderAndReturnsTheID(t *testing.T) {
	d := newFakeDevice("password")
	got := captureCommand(d, cmdGenerateAsymmetricKey, []byte{0x5a, 0xa3})
	c, ctx := testClient(t, d)

	spec := KeySpec{ID: 0, Label: "attest-witness", Domains: 1, Capabilities: 0x04, Algorithm: AlgorithmECP256}
	id, err := c.GenerateAsymmetricKey(ctx, spec)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if id != 0x5aa3 {
		t.Fatalf("device allocated 0x%04x, client reported 0x%04x", 0x5aa3, id)
	}
	want, err := spec.encodeHeader()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(*got, want) {
		t.Fatalf("generate sent %x, want %x", *got, want)
	}
}

// The reply is the whole result — there is no other way to address the key that
// was just created — so a wrong-length one has to fail rather than be padded or
// truncated into a plausible id.
func TestGenerateAsymmetricKeyRejectsAMalformedReply(t *testing.T) {
	d := newFakeDevice("password")
	captureCommand(d, cmdGenerateAsymmetricKey, []byte{0x5a})
	c, ctx := testClient(t, d)

	if _, err := c.GenerateAsymmetricKey(ctx, KeySpec{Label: "k", Domains: 1, Algorithm: AlgorithmECP256}); err == nil {
		t.Fatal("a one-byte object id was accepted")
	} else if !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("expected a length complaint, got %v", err)
	}
}

func TestGenerateAsymmetricKeyReportsADeviceRefusal(t *testing.T) {
	d := newFakeDevice("password")
	refuseCommand(d, cmdGenerateAsymmetricKey, ErrInsufficientPermissions)
	c, ctx := testClient(t, d)

	_, err := c.GenerateAsymmetricKey(ctx, KeySpec{Label: "k", Domains: 1, Algorithm: AlgorithmECP256})
	var devErr DeviceError
	if !errors.As(err, &devErr) || devErr != ErrInsufficientPermissions {
		t.Fatalf("expected a typed permissions error, got %v", err)
	}
	// The label has to survive into the message: an operator provisioning several
	// keys needs to know which one the device refused.
	if !strings.Contains(err.Error(), `"k"`) {
		t.Fatalf("the refusal does not name the key: %v", err)
	}
}

// An imported key is exactly the case where the private half did exist outside
// the HSM, so the material must be appended verbatim after the header and
// nowhere else.
func TestPutAsymmetricKeyAppendsTheMaterialAfterTheHeader(t *testing.T) {
	d := newFakeDevice("password")
	got := captureCommand(d, cmdPutAsymmetricKey, []byte{0x00, 0x07})
	c, ctx := testClient(t, d)

	spec := KeySpec{ID: 7, Label: "imported", Domains: 3, Capabilities: 0x04, Algorithm: AlgorithmECP256}
	material := bytes.Repeat([]byte{0xab}, 32)
	id, err := c.PutAsymmetricKey(ctx, spec, material)
	if err != nil {
		t.Fatalf("importing a key: %v", err)
	}
	if id != 7 {
		t.Fatalf("import reported id 0x%04x", id)
	}
	header, err := spec.encodeHeader()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(*got, append(header, material...)) {
		t.Fatalf("import sent %x", *got)
	}
}

func TestPutAsymmetricKeyRejectsAMalformedReply(t *testing.T) {
	d := newFakeDevice("password")
	captureCommand(d, cmdPutAsymmetricKey, nil)
	c, ctx := testClient(t, d)

	_, err := c.PutAsymmetricKey(ctx, KeySpec{Label: "k", Domains: 1, Algorithm: AlgorithmECP256}, []byte{1})
	if err == nil {
		t.Fatal("an empty object id was accepted")
	} else if !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("expected a length complaint, got %v", err)
	}
}

// Both commands refuse to send a spec that cannot encode, so a bad label never
// reaches the device.
func TestKeyCommandsRefuseAnUnencodableSpec(t *testing.T) {
	d := newFakeDevice("password")
	captureCommand(d, cmdGenerateAsymmetricKey, []byte{0x00, 0x01})
	captureCommand(d, cmdPutAsymmetricKey, []byte{0x00, 0x01})
	c, ctx := testClient(t, d)

	bad := KeySpec{Label: "no-domain", Algorithm: AlgorithmECP256}
	if _, err := c.GenerateAsymmetricKey(ctx, bad); err == nil {
		t.Fatal("generate accepted a spec with no domain")
	}
	if _, err := c.PutAsymmetricKey(ctx, bad, []byte{1}); err == nil {
		t.Fatal("import accepted a spec with no domain")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Nothing beyond session setup may have gone out.
	for _, msg := range d.Sent {
		if msg[0] == cmdSessionMessage {
			t.Fatal("an unencodable key spec was sent to the device anyway")
		}
	}
}

func TestDeleteObjectEncodesIDAndType(t *testing.T) {
	d := newFakeDevice("password")
	got := captureCommand(d, cmdDeleteObject, nil)
	c, ctx := testClient(t, d)

	if err := c.DeleteObject(ctx, 0xfb01, ObjectTypeAsymmetricKey); err != nil {
		t.Fatalf("deleting an object: %v", err)
	}
	if want := []byte{0xfb, 0x01, ObjectTypeAsymmetricKey}; !bytes.Equal(*got, want) {
		t.Fatalf("delete sent %x, want %x", *got, want)
	}
}

// A delete that did not happen has to be visible as such: the serial-binding
// flow generates a key, attests it and deletes it, and a silently-surviving
// witness key is a capability left on the device.
func TestDeleteObjectReportsARefusalWithTheObjectIdentified(t *testing.T) {
	d := newFakeDevice("password")
	refuseCommand(d, cmdDeleteObject, ErrObjectNotFound)
	c, ctx := testClient(t, d)

	err := c.DeleteObject(ctx, 0xfb01, ObjectTypeAsymmetricKey)
	var devErr DeviceError
	if !errors.As(err, &devErr) || devErr != ErrObjectNotFound {
		t.Fatalf("expected a typed not-found error, got %v", err)
	}
	if !strings.Contains(err.Error(), "0xfb01") || !strings.Contains(err.Error(), "asymmetric-key") {
		t.Fatalf("the refusal does not identify the object: %v", err)
	}
}

// ECDSA is fed a digest and EdDSA a whole message; both put the key id first and
// the payload straight after, with no length prefix.
func TestSigningCommandsPrefixTheKeyID(t *testing.T) {
	d := newFakeDevice("password")
	ecdsa := captureCommand(d, cmdSignECDSA, []byte("der-sig"))
	eddsa := captureCommand(d, cmdSignEdDSA, []byte("ed-sig"))
	c, ctx := testClient(t, d)

	digest := bytes.Repeat([]byte{0x9f}, 32)
	sig, err := c.SignECDSA(ctx, 0x0100, digest)
	if err != nil {
		t.Fatalf("ECDSA sign: %v", err)
	}
	if string(sig) != "der-sig" {
		t.Fatalf("ECDSA signature = %q", sig)
	}
	if !bytes.Equal(*ecdsa, append([]byte{0x01, 0x00}, digest...)) {
		t.Fatalf("ECDSA sign sent %x", *ecdsa)
	}

	msg := []byte("a whole message, not a digest")
	sig, err = c.SignEdDSA(ctx, 0x0200, msg)
	if err != nil {
		t.Fatalf("EdDSA sign: %v", err)
	}
	if string(sig) != "ed-sig" {
		t.Fatalf("EdDSA signature = %q", sig)
	}
	if !bytes.Equal(*eddsa, append([]byte{0x02, 0x00}, msg...)) {
		t.Fatalf("EdDSA sign sent %x", *eddsa)
	}
}

func TestSigningCommandsReportRefusalsWithTheKeyID(t *testing.T) {
	d := newFakeDevice("password")
	refuseCommand(d, cmdSignECDSA, ErrInsufficientPermissions)
	refuseCommand(d, cmdSignEdDSA, ErrObjectNotFound)
	c, ctx := testClient(t, d)

	if _, err := c.SignECDSA(ctx, 0x0100, []byte("d")); err == nil || !strings.Contains(err.Error(), "0x0100") {
		t.Fatalf("ECDSA refusal does not name the key: %v", err)
	}
	if _, err := c.SignEdDSA(ctx, 0x0200, []byte("m")); err == nil || !strings.Contains(err.Error(), "0x0200") {
		t.Fatalf("EdDSA refusal does not name the key: %v", err)
	}
}

func TestGetPublicKeySplitsAlgorithmFromKeyMaterial(t *testing.T) {
	d := newFakeDevice("password")
	// An uncompressed P-256 point without its 0x04 prefix: 64 bytes.
	point := bytes.Repeat([]byte{0x2b}, 64)
	got := captureCommand(d, cmdGetPublicKey, append([]byte{AlgorithmECP256}, point...))
	c, ctx := testClient(t, d)

	alg, key, err := c.GetPublicKey(ctx, 0x0abc)
	if err != nil {
		t.Fatalf("reading a public key: %v", err)
	}
	if alg != AlgorithmECP256 {
		t.Fatalf("algorithm = %d, want %d", alg, AlgorithmECP256)
	}
	if !bytes.Equal(key, point) {
		t.Fatalf("key material = %x", key)
	}
	if !bytes.Equal(*got, []byte{0x0a, 0xbc}) {
		t.Fatalf("get-public-key sent %x", *got)
	}
}

// A reply too short to hold both fields would otherwise index out of range, or
// worse, be read as an empty key under a valid algorithm.
func TestGetPublicKeyRejectsAShortReply(t *testing.T) {
	d := newFakeDevice("password")
	captureCommand(d, cmdGetPublicKey, []byte{AlgorithmEd25519})
	c, ctx := testClient(t, d)

	if _, _, err := c.GetPublicKey(ctx, 1); err == nil {
		t.Fatal("a public-key reply with no key in it was accepted")
	} else if !strings.Contains(err.Error(), "at least 2") {
		t.Fatalf("expected a length complaint, got %v", err)
	}
}

func TestGetPublicKeyReportsARefusal(t *testing.T) {
	d := newFakeDevice("password")
	refuseCommand(d, cmdGetPublicKey, ErrObjectNotFound)
	c, ctx := testClient(t, d)

	if _, _, err := c.GetPublicKey(ctx, 0x0abc); err == nil || !strings.Contains(err.Error(), "0x0abc") {
		t.Fatalf("the refusal does not name the key: %v", err)
	}
}

// Opaque object 0 is the factory device attestation certificate, which anchors
// every per-key attestation to Yubico's PKI (see internal/hsmattest).
func TestGetOpaqueReturnsTheObjectVerbatim(t *testing.T) {
	d := newFakeDevice("password")
	der := bytes.Repeat([]byte{0x30, 0x82}, 8)
	got := captureCommand(d, cmdGetOpaque, der)
	c, ctx := testClient(t, d)

	body, err := c.GetOpaque(ctx, 0)
	if err != nil {
		t.Fatalf("reading an opaque object: %v", err)
	}
	if !bytes.Equal(body, der) {
		t.Fatalf("opaque object came back as %x", body)
	}
	if !bytes.Equal(*got, []byte{0x00, 0x00}) {
		t.Fatalf("get-opaque sent %x", *got)
	}
}

func TestGetOpaqueReportsARefusal(t *testing.T) {
	d := newFakeDevice("password")
	refuseCommand(d, cmdGetOpaque, ErrObjectNotFound)
	c, ctx := testClient(t, d)

	if _, err := c.GetOpaque(ctx, 0x0002); err == nil || !strings.Contains(err.Error(), "0x0002") {
		t.Fatalf("the refusal does not name the object: %v", err)
	}
}

func TestGetPseudoRandomEncodesTheByteCount(t *testing.T) {
	d := newFakeDevice("password")
	got := captureCommand(d, cmdGetPseudoRandom, bytes.Repeat([]byte{0x7c}, 32))
	c, ctx := testClient(t, d)

	out, err := c.GetPseudoRandom(ctx, 32)
	if err != nil {
		t.Fatalf("drawing random bytes: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("got %d bytes, want 32", len(out))
	}
	if !bytes.Equal(*got, []byte{0x00, 0x20}) {
		t.Fatalf("get-pseudo-random sent %x, want the count big-endian", *got)
	}
}

// Diagnostics name the endpoint the client is actually talking to, not the URL
// that was requested — with a connector in the path those differ.
func TestDescribeNamesTheTransport(t *testing.T) {
	d := newFakeDevice("password")
	c, _ := testClient(t, d)
	if c.Describe() != d.Describe() {
		t.Fatalf("client describes itself as %q, transport as %q", c.Describe(), d.Describe())
	}
}

func TestAlgorithmNameFallsBackToTheNumber(t *testing.T) {
	if got := AlgorithmName(AlgorithmECP256); got != "ecp256" {
		t.Fatalf("AlgorithmName(%d) = %q", AlgorithmECP256, got)
	}
	// An id from newer firmware must still identify the key in an inventory
	// listing rather than render as an empty string.
	if got := AlgorithmName(0xff); got != "algorithm-255" {
		t.Fatalf("unknown algorithm rendered as %q", got)
	}
}

func TestObjectTypeNameCoversEveryType(t *testing.T) {
	for _, tc := range []struct {
		t    byte
		want string
	}{
		{ObjectTypeOpaque, "opaque"},
		{ObjectTypeAuthenticationKey, "authentication-key"},
		{ObjectTypeAsymmetricKey, "asymmetric-key"},
		{ObjectTypeWrapKey, "wrap-key"},
		{ObjectTypeHMACKey, "hmac-key"},
		{ObjectTypeTemplate, "template"},
		{ObjectTypeOTPAEADKey, "otp-aead-key"},
		{ObjectTypeSymmetricKey, "symmetric-key"},
		{0x7f, "unknown(0x7f)"},
	} {
		if got := ObjectTypeName(tc.t); got != tc.want {
			t.Fatalf("ObjectTypeName(0x%02x) = %q, want %q", tc.t, got, tc.want)
		}
	}
}

func TestUSBSerialFromURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"serial=0123456789", "0123456789"},
		// yubihsm-shell's own spelling is serial=; a bare authority is accepted
		// too because it is what an operator types.
		{"0123456789", "0123456789"},
		{"serial=0123456789/", "0123456789"},
	} {
		if got := usbSerialFromURL(tc.in); got != tc.want {
			t.Fatalf("usbSerialFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An unrecognised scheme must be refused rather than silently falling through to
// direct USB, which would reach for whatever device is plugged into the host
// when the operator asked for a specific remote one.
func TestOpenTransportRejectsAnUnsupportedURL(t *testing.T) {
	_, err := OpenTransport(context.Background(), "tcp://hsm.internal:12345")
	if err == nil {
		t.Fatal("an unsupported connector URL was accepted")
	}
	if !strings.Contains(err.Error(), "unsupported YubiHSM connector URL") {
		t.Fatalf("expected an unsupported-URL error, got %v", err)
	}
}
