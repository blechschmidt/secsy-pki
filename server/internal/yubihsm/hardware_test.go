package yubihsm

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

// Read-only exercise of the native driver against an attached YubiHSM 2.
//
// It skips unless a device is actually reachable, so it is harmless in CI, and
// it issues nothing that mutates the device: no key generation, no option
// writes, no log acknowledgement. Read-only matters here because the device's
// audit log is append-only evidence — a test that consumed entries would destroy
// the very record the audit subsystem depends on.
func hwConfig(t *testing.T) Config {
	t.Helper()
	connector := os.Getenv("YUBIHSM_CONNECTOR")
	if connector == "" {
		connector = "yhusb://"
	}
	password := os.Getenv("YUBIHSM_PASSWORD")
	if password == "" {
		password = "password"
	}
	return Config{ConnectorURL: connector, AuthKeyID: 1, Password: password}
}

func hwClient(t *testing.T) (*Client, context.Context) {
	t.Helper()
	cfg := hwConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if _, err := TransportDeviceInfo(ctx, cfg); err != nil {
		t.Skipf("no YubiHSM reachable: %v", err)
	}
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Skipf("no YubiHSM session: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, ctx
}

func TestHardwareDeviceInfoWithoutSession(t *testing.T) {
	cfg := hwConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := TransportDeviceInfo(ctx, cfg)
	if err != nil {
		t.Skipf("no YubiHSM reachable: %v", err)
	}
	if info.Serial == "" || info.Version == "" {
		t.Fatalf("device info is missing identity: %+v", info)
	}
	if info.LogTotal == 0 {
		t.Fatalf("device reports a zero-capacity audit log: %+v", info)
	}
	if info.LogUsed > info.LogTotal {
		t.Fatalf("device reports %d used of %d log slots", info.LogUsed, info.LogTotal)
	}
	if len(info.Algorithms) == 0 {
		t.Fatal("device reports no supported algorithms")
	}
	t.Logf("device %s firmware %s part %q log %s", info.Serial, info.Version, info.PartNumber, info.LogCapacity())
}

func TestHardwareSecureChannelRoundTrip(t *testing.T) {
	c, ctx := hwClient(t)

	// Several echoes in a row: the SCP03 counter and MAC chaining advance per
	// message, so a mistake in either shows up on the second exchange, not the
	// first.
	for i := 0; i < 3; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 20+i)
		got, err := c.Echo(ctx, payload)
		if err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo %d returned %x, want %x", i, got, payload)
		}
	}

	// A payload that makes the outer USB message an exact multiple of the 64-byte
	// packet size exercises the zero-length-packet terminator, which the device
	// otherwise waits for forever.
	for _, n := range []int{27, 43, 59, 91} {
		got, err := c.Echo(ctx, bytes.Repeat([]byte{0x5a}, n))
		if err != nil {
			t.Fatalf("echo of %d bytes: %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("echo of %d bytes returned %d", n, len(got))
		}
	}
}

func TestHardwareReadAuditState(t *testing.T) {
	c, ctx := hwClient(t)

	force, err := c.GetOption(ctx, OptionForceAudit)
	if err != nil {
		t.Fatalf("force-audit: %v", err)
	}
	if len(force) != 1 {
		t.Fatalf("force-audit is %d bytes, want 1", len(force))
	}

	cmdAudit, err := c.GetOption(ctx, OptionCommandAudit)
	if err != nil {
		t.Fatalf("command-audit: %v", err)
	}
	if len(cmdAudit) == 0 || len(cmdAudit)%2 != 0 {
		t.Fatalf("command-audit is %d bytes, want a positive multiple of 2", len(cmdAudit))
	}
	t.Logf("force-audit=0x%02x, %d command-audit entries", force[0], len(cmdAudit)/2)

	// GetLogEntries must not acknowledge: reading twice must return the same
	// entries, or a crash between read and persist would lose evidence.
	first, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("get log entries: %v", err)
	}
	second, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("get log entries again: %v", err)
	}
	if len(first.Entries) != len(second.Entries) {
		t.Fatalf("reading the log consumed entries: %d then %d", len(first.Entries), len(second.Entries))
	}
	for i := range first.Entries {
		if first.Entries[i] != second.Entries[i] {
			t.Fatalf("entry %d differs between reads: %+v vs %+v", i, first.Entries[i], second.Entries[i])
		}
	}
	t.Logf("%d log entries, unlogged boots=%d auths=%d",
		len(first.Entries), first.UnloggedBoots, first.UnloggedAuthentications)
}

func TestHardwareObjectInventory(t *testing.T) {
	c, ctx := hwClient(t)

	objs, err := c.ListObjects(ctx, 0)
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	if len(objs) == 0 {
		t.Fatal("device reports no objects, but the session's own authentication key must be visible")
	}
	var sawAuthKey bool
	for _, o := range objs {
		info, err := c.GetObjectInfo(ctx, o.ID, o.Type)
		if err != nil {
			t.Fatalf("object info 0x%04x: %v", o.ID, err)
		}
		if info.ID != o.ID || info.Type != o.Type {
			t.Fatalf("object info describes 0x%04x/%d, asked for 0x%04x/%d", info.ID, info.Type, o.ID, o.Type)
		}
		if o.Type == ObjectTypeAuthenticationKey {
			sawAuthKey = true
		}
		t.Logf("0x%04x %-20s %q", o.ID, ObjectTypeName(o.Type), info.Label)
	}
	if !sawAuthKey {
		t.Fatal("no authentication key in the object list")
	}
}

func TestHardwareDeviceAttestationCertificate(t *testing.T) {
	c, ctx := hwClient(t)

	der, err := c.GetOpaque(ctx, 0)
	if err != nil {
		t.Fatalf("reading the factory device attestation certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the device attestation certificate (%d bytes): %v", len(der), err)
	}
	t.Logf("device attestation certificate subject %q issuer %q", cert.Subject, cert.Issuer)
}

func TestHardwareRandomIsNotConstant(t *testing.T) {
	c, ctx := hwClient(t)

	a, err := c.GetPseudoRandom(ctx, 32)
	if err != nil {
		t.Fatalf("get pseudo random: %v", err)
	}
	b, err := c.GetPseudoRandom(ctx, 32)
	if err != nil {
		t.Fatalf("get pseudo random: %v", err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("expected 32 bytes each, got %d and %d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two random draws are identical")
	}
}

func TestHardwareWrongPasswordIsRejected(t *testing.T) {
	cfg := hwConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := TransportDeviceInfo(ctx, cfg); err != nil {
		t.Skipf("no YubiHSM reachable: %v", err)
	}
	cfg.Password = "definitely-not-the-password"
	c, err := Open(ctx, cfg)
	if err == nil {
		_ = c.Close()
		t.Fatal("a session opened with the wrong password")
	}
	t.Logf("rejected as expected: %v", err)
}
