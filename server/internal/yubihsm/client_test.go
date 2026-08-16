package yubihsm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testClient(t *testing.T, d *fakeDevice) (*Client, context.Context) {
	t.Helper()
	ctx := context.Background()
	c, err := OpenOver(ctx, d, Config{AuthKeyID: 1, Password: "password"})
	if err != nil {
		t.Fatalf("opening a session against the fake device: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, ctx
}

func TestSecureChannelRoundTrip(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	// Sizes chosen to straddle the AES block boundary, since a padding mistake
	// only shows on an exact multiple.
	for _, n := range []int{0, 1, 12, 13, 16, 17, 100} {
		payload := bytes.Repeat([]byte{byte(n)}, n)
		got, err := c.Echo(ctx, payload)
		if err != nil {
			t.Fatalf("echo of %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo of %d bytes returned %x", n, got)
		}
	}
}

func TestWrongPasswordFailsMutualAuthentication(t *testing.T) {
	d := newFakeDevice("the-real-password")
	_, err := OpenOver(context.Background(), d, Config{AuthKeyID: 1, Password: "a-guess"})
	if err == nil {
		t.Fatal("a session opened with the wrong password")
	}
	// The client must reject the device before sending its own cryptogram: the
	// card cryptogram is what proves the peer holds the key, and checking it
	// second would leak an authentication attempt to an impostor.
	if !strings.Contains(err.Error(), "card cryptogram") {
		t.Fatalf("expected card-cryptogram rejection, got %v", err)
	}
	for _, msg := range d.Sent {
		if msg[0] == cmdAuthenticateSession {
			t.Fatal("the client sent its host cryptogram to a device that failed to authenticate")
		}
	}
}

func TestUnknownAuthenticationKeyIsReported(t *testing.T) {
	d := newFakeDevice("password")
	d.expectKeySetID = 42
	_, err := OpenOver(context.Background(), d, Config{AuthKeyID: 1, Password: "password"})
	var devErr DeviceError
	if !errors.As(err, &devErr) || devErr != ErrObjectNotFound {
		t.Fatalf("expected a typed object-not-found device error, got %v", err)
	}
}

func TestTamperedResponseIsRejected(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	// Flip a ciphertext bit on the way back. Without the response MAC this would
	// surface as a corrupt value rather than an error, which for an audit-log
	// read means fabricated evidence.
	d.mu.Lock()
	d.tamper = func(resp []byte) []byte {
		out := append([]byte(nil), resp...)
		out[5] ^= 0x01
		return out
	}
	d.mu.Unlock()

	if _, err := c.Echo(ctx, []byte("audit evidence")); err == nil {
		t.Fatal("a tampered response was accepted")
	} else if !strings.Contains(err.Error(), "MAC verification failed") {
		t.Fatalf("expected a MAC failure, got %v", err)
	}
}

func TestReplayedResponseIsRejected(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	if _, err := c.Echo(ctx, []byte("first")); err != nil {
		t.Fatal(err)
	}
	var captured []byte
	d.mu.Lock()
	d.tamper = func(resp []byte) []byte {
		if captured == nil {
			captured = append([]byte(nil), resp...)
		}
		return append([]byte(nil), captured...)
	}
	d.mu.Unlock()

	if _, err := c.Echo(ctx, []byte("second")); err != nil {
		t.Fatal(err)
	}
	// The MAC chains, so re-serving the previous reply must not verify.
	if _, err := c.Echo(ctx, []byte("third")); err == nil {
		t.Fatal("a replayed response was accepted")
	}
}

func TestDeviceErrorsSurfaceTyped(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdGetOption] = func([]byte) ([]byte, error) { return nil, ErrInsufficientPermissions }
	c, ctx := testClient(t, d)

	_, err := c.GetOption(ctx, OptionForceAudit)
	var devErr DeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("expected a DeviceError, got %T: %v", err, err)
	}
	if devErr != ErrInsufficientPermissions {
		t.Fatalf("got %v, want insufficient permissions", devErr)
	}
	// A rejected command must not be mistakable for success — the failure mode
	// the shell-scraping predecessor had.
	if !strings.Contains(err.Error(), "insufficient permissions") {
		t.Fatalf("error text does not name the failure: %v", err)
	}
}

// Golden responses captured from a YubiHSM 2 (firmware 2.4.0, serial 31650425),
// so the wire-format parsers are pinned to bytes a real device produced.
const (
	goldenDeviceInfo = "02040001e2f2793e01" +
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f3031323334353637"
	goldenObjectInfo = "ffffffffffffffff00010028ffff0226000244454641554c542041555448" +
		"4b4559204348414e4745205448495320415341500000000000000000ffffffffffffffff"
)

func TestParseDeviceInfoGolden(t *testing.T) {
	raw, err := hex.DecodeString(goldenDeviceInfo)
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseDeviceInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "2.4.0" {
		t.Errorf("version = %q, want 2.4.0", info.Version)
	}
	if info.Serial != "31650425" {
		t.Errorf("serial = %q, want 31650425", info.Serial)
	}
	if info.LogCapacity() != "1/62" {
		t.Errorf("log capacity = %q, want 1/62", info.LogCapacity())
	}
	if len(info.Algorithms) != 55 {
		t.Errorf("algorithms = %d, want 55", len(info.Algorithms))
	}
}

func TestDeviceInfoIncludesPartNumber(t *testing.T) {
	base, _ := hex.DecodeString(goldenDeviceInfo)
	d := newFakeDevice("password")
	d.handlers[cmdGetDeviceInfo] = func(data []byte) ([]byte, error) {
		if len(data) == 1 && data[0] == deviceInfoPartNumber {
			return []byte("78CLUFX5000P"), nil
		}
		return base, nil
	}
	c, ctx := testClient(t, d)

	info, err := c.DeviceInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.PartNumber != "78CLUFX5000P" {
		t.Errorf("part number = %q", info.PartNumber)
	}
}

// Firmware before 2.4 rejects the part-number selector. Device info must still
// come back, because it carries the log occupancy the audit collector needs.
func TestDeviceInfoToleratesMissingPartNumber(t *testing.T) {
	base, _ := hex.DecodeString(goldenDeviceInfo)
	d := newFakeDevice("password")
	d.handlers[cmdGetDeviceInfo] = func(data []byte) ([]byte, error) {
		if len(data) > 0 {
			return nil, ErrInvalidData
		}
		return base, nil
	}
	c, ctx := testClient(t, d)

	info, err := c.DeviceInfo(ctx)
	if err != nil {
		t.Fatalf("device info: %v", err)
	}
	if info.PartNumber != "" {
		t.Errorf("part number = %q, want empty", info.PartNumber)
	}
	if info.Serial != "31650425" {
		t.Errorf("serial = %q", info.Serial)
	}
}

func TestGetObjectInfoGolden(t *testing.T) {
	raw, err := hex.DecodeString(strings.ReplaceAll(goldenObjectInfo, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	d := newFakeDevice("password")
	d.handlers[cmdGetObjectInfo] = func([]byte) ([]byte, error) { return raw, nil }
	c, ctx := testClient(t, d)

	info, err := c.GetObjectInfo(ctx, 1, ObjectTypeAuthenticationKey)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != 1 {
		t.Errorf("id = %d", info.ID)
	}
	if info.Type != ObjectTypeAuthenticationKey {
		t.Errorf("type = 0x%02x", info.Type)
	}
	// The label is a fixed-width NUL-padded field; reading it from the wrong
	// offset silently truncates the name an operator identifies a key by.
	if info.Label != "DEFAULT AUTHKEY CHANGE THIS ASAP" {
		t.Errorf("label = %q", info.Label)
	}
	if info.Capabilities != ^uint64(0) {
		t.Errorf("capabilities = %#x", info.Capabilities)
	}
	if info.DelegatedCapabilities != ^uint64(0) {
		t.Errorf("delegated capabilities = %#x", info.DelegatedCapabilities)
	}
}

func TestGetLogEntriesParsesEntriesAndUnloggedCounters(t *testing.T) {
	entry := func(number uint16, cmd byte, target uint16, digest byte) []byte {
		b := make([]byte, logEntryLen)
		binary.BigEndian.PutUint16(b[0:2], number)
		b[2] = cmd
		binary.BigEndian.PutUint16(b[3:5], 3)
		binary.BigEndian.PutUint16(b[5:7], 1)
		binary.BigEndian.PutUint16(b[7:9], target)
		binary.BigEndian.PutUint16(b[9:11], 0xffff)
		b[11] = 0x83
		binary.BigEndian.PutUint32(b[12:16], 4242)
		for i := 16; i < logEntryLen; i++ {
			b[i] = digest
		}
		return b
	}
	body := []byte{0x00, 0x02, 0x00, 0x07, 0x02}
	body = append(body, entry(35, 0x58, 0x5aa3, 0xab)...)
	body = append(body, entry(36, 0x56, 0x1234, 0xcd)...)

	d := newFakeDevice("password")
	d.handlers[cmdGetLogEntries] = func([]byte) ([]byte, error) { return body, nil }
	c, ctx := testClient(t, d)

	log, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The unlogged counters are the device admitting its log is incomplete;
	// dropping them would let operations that were never recorded pass as a
	// clean log.
	if log.UnloggedBoots != 2 || log.UnloggedAuthentications != 7 {
		t.Fatalf("unlogged = %d boots / %d auths, want 2/7", log.UnloggedBoots, log.UnloggedAuthentications)
	}
	if len(log.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(log.Entries))
	}
	e := log.Entries[0]
	if e.Number != 35 || e.Command != 0x58 || e.TargetKey != 0x5aa3 || e.Result != 0x83 || e.Tick != 4242 {
		t.Fatalf("first entry mis-parsed: %+v", e)
	}
	if e.Digest != [16]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab} {
		t.Fatalf("digest mis-parsed: %x", e.Digest)
	}
}

func TestGetLogEntriesRejectsShortPayload(t *testing.T) {
	d := newFakeDevice("password")
	// Announces two entries but carries one: accepting this would silently drop
	// an audit record.
	d.handlers[cmdGetLogEntries] = func([]byte) ([]byte, error) {
		return append([]byte{0, 0, 0, 0, 2}, make([]byte, logEntryLen)...), nil
	}
	c, ctx := testClient(t, d)

	if _, err := c.GetLogEntries(ctx); err == nil {
		t.Fatal("a truncated log response was accepted")
	}
}

func TestListObjectsParsesHandles(t *testing.T) {
	d := newFakeDevice("password")
	var gotFilter []byte
	d.handlers[cmdListObjects] = func(data []byte) ([]byte, error) {
		gotFilter = append([]byte(nil), data...)
		return []byte{0x00, 0x01, ObjectTypeAuthenticationKey, 0x00, 0x5a, 0xa3, ObjectTypeAsymmetricKey, 0x02}, nil
	}
	c, ctx := testClient(t, d)

	objs, err := c.ListObjects(ctx, ObjectTypeAsymmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotFilter, []byte{listFilterType, ObjectTypeAsymmetricKey}) {
		t.Fatalf("filter sent = %x", gotFilter)
	}
	if len(objs) != 2 || objs[1].ID != 0x5aa3 || objs[1].Type != ObjectTypeAsymmetricKey || objs[1].Sequence != 2 {
		t.Fatalf("objects mis-parsed: %+v", objs)
	}
}

func TestPutOptionEncodesLengthPrefix(t *testing.T) {
	d := newFakeDevice("password")
	var got []byte
	d.handlers[cmdPutOption] = func(data []byte) ([]byte, error) {
		got = append([]byte(nil), data...)
		return nil, nil
	}
	c, ctx := testClient(t, d)

	if err := c.PutOption(ctx, OptionCommandAudit, []byte{0x56, 0x02}); err != nil {
		t.Fatal(err)
	}
	want := []byte{OptionCommandAudit, 0x00, 0x02, 0x56, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("put option sent %x, want %x", got, want)
	}
}

func TestSetLogIndexEncodesIndex(t *testing.T) {
	d := newFakeDevice("password")
	var got []byte
	d.handlers[cmdSetLogIndex] = func(data []byte) ([]byte, error) {
		got = append([]byte(nil), data...)
		return nil, nil
	}
	c, ctx := testClient(t, d)

	if err := c.SetLogIndex(ctx, 0x0123); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x01, 0x23}) {
		t.Fatalf("set log index sent %x", got)
	}
}

func TestAttestAsymmetricKeySendsBothKeyIDs(t *testing.T) {
	d := newFakeDevice("password")
	var got []byte
	d.handlers[cmdSignAttestationCert] = func(data []byte) ([]byte, error) {
		got = append([]byte(nil), data...)
		return []byte("der"), nil
	}
	c, ctx := testClient(t, d)

	der, err := c.AttestAsymmetricKey(ctx, 0x5aa3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x5a, 0xa3, 0x00, 0x00}) {
		t.Fatalf("attest sent %x", got)
	}
	if string(der) != "der" {
		t.Fatalf("der = %q", der)
	}
}

func TestClosedClientRefusesCommands(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Echo(ctx, []byte("x")); err == nil {
		t.Fatal("a closed client accepted a command")
	}
}

func TestWithSessionClosesTheClient(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }

	var inner *Client
	err := withSessionOver(context.Background(), d, Config{Password: "password"}, func(c *Client) error {
		inner = c
		_, err := c.Echo(context.Background(), []byte("hi"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Echo(context.Background(), []byte("hi")); err == nil {
		t.Fatal("the client outlived WithSession")
	}
}

// withSessionOver mirrors WithSession for an already-open transport.
func withSessionOver(ctx context.Context, t Transport, cfg Config, fn func(*Client) error) error {
	c, err := OpenOver(ctx, t, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return fn(c)
}

// An unencrypted error frame is something anything on the transport can write,
// so only the session-level codes — the ones the device really does report
// outside the secure channel — may be honoured. Anything else must fail MAC
// verification instead of being taken as the command's outcome.
func TestUnauthenticatedErrorFrameIsNotACommandResult(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdListObjects] = func([]byte) ([]byte, error) {
		return []byte{0x00, 0x01, ObjectTypeAsymmetricKey, 0x00}, nil
	}
	c, ctx := testClient(t, d)

	d.mu.Lock()
	d.tamper = func([]byte) []byte { return errorFrame(ErrObjectNotFound) }
	d.mu.Unlock()

	_, err := c.ListObjects(ctx, ObjectTypeAsymmetricKey)
	if err == nil {
		t.Fatal("an injected error frame was accepted as the command's result")
	}
	var devErr DeviceError
	if errors.As(err, &devErr) && devErr == ErrObjectNotFound {
		t.Fatalf("an injected error frame was reported as a device verdict: %v", err)
	}
}

// A session the device tore down is reported as such, and ends the client: the
// remaining messages would be MACed against a chain the device no longer holds.
func TestSessionLevelErrorEndsTheClient(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	d.mu.Lock()
	d.tamper = func([]byte) []byte { return errorFrame(ErrInvalidSession) }
	d.mu.Unlock()

	_, err := c.Echo(ctx, []byte("x"))
	var devErr DeviceError
	if !errors.As(err, &devErr) || devErr != ErrInvalidSession {
		t.Fatalf("expected an invalid-session device error, got %v", err)
	}

	d.mu.Lock()
	d.tamper = nil
	d.mu.Unlock()
	if _, err := c.Echo(ctx, []byte("x")); err == nil {
		t.Fatal("the client kept using a session the device had torn down")
	}
}

// A MAC failure is unambiguous evidence the channel is no longer carrying this
// session's traffic, so the client must not be reusable afterwards — otherwise
// each later reply is a fresh decision about whether to believe it.
func TestMACFailureEndsTheClient(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)

	d.mu.Lock()
	d.tamper = func(resp []byte) []byte {
		out := append([]byte(nil), resp...)
		out[len(out)-1] ^= 0x01
		return out
	}
	d.mu.Unlock()
	if _, err := c.Echo(ctx, []byte("x")); err == nil {
		t.Fatal("a tampered response was accepted")
	}

	d.mu.Lock()
	d.tamper = nil
	d.mu.Unlock()
	if _, err := c.Echo(ctx, []byte("x")); err == nil {
		t.Fatal("the client kept using a channel whose reply had failed its MAC")
	}
}

// A reset that never reached the device must not be reported as a wipe: the
// operator's next step is to provision audit logging believing the history
// before it is gone.
func TestResetReportsFailuresThatAreNotTheDeviceRebooting(t *testing.T) {
	d := newFakeDevice("password")
	c, ctx := testClient(t, d)

	d.mu.Lock()
	d.tamper = func(resp []byte) []byte {
		out := append([]byte(nil), resp...)
		out[len(out)-1] ^= 0x01
		return out
	}
	d.mu.Unlock()

	if err := c.Reset(ctx); err == nil {
		t.Fatal("Reset reported success after a response that failed its MAC")
	}
}

// The disconnect a successful reset causes is not a failure.
func TestResetToleratesTheDeviceDisconnecting(t *testing.T) {
	d := newFakeDevice("password")
	c, ctx := testClient(t, d)

	d.mu.Lock()
	d.transactErr = fmt.Errorf("reading from the YubiHSM: %w: device went away", errTransportRead)
	d.mu.Unlock()

	if err := c.Reset(ctx); err != nil {
		t.Fatalf("Reset reported the post-reset disconnect as a failure: %v", err)
	}
}
