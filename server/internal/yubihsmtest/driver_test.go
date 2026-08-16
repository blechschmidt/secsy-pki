package yubihsmtest

// Tier 1: the transport and the SCP03 secure channel.
//
// Everything above this file assumes a byte-exact request/response channel to
// the device. These tests are the ones that decide whether that assumption
// holds, so when a higher tier fails, start here: a green tier 1 means the wire
// is sound and the fault is in the layer that failed.

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// TestDeviceIdentity reads the device's self-description over the bare
// transport, with no session. This is the only device call that works before
// authentication, so it is what every "is the HSM there" probe in the product
// ultimately calls.
func TestDeviceIdentity(t *testing.T) {
	requireDevice(t)
	ctx := testContext(t)

	info, err := yubihsm.TransportDeviceInfo(ctx, driverConfig())
	if err != nil {
		t.Fatalf("reading device info: %v", err)
	}
	if info.Serial == "" {
		t.Error("device reports no serial number; audit bundles are bound to it")
	}
	if info.Version == "" {
		t.Error("device reports no firmware version; the required forced-audit set is derived from it")
	}
	if info.LogTotal == 0 {
		t.Error("device reports a zero-capacity audit log")
	}
	if info.LogUsed > info.LogTotal {
		t.Errorf("device reports %d used of %d audit log slots", info.LogUsed, info.LogTotal)
	}
	if len(info.Algorithms) == 0 {
		t.Error("device reports no supported algorithms")
	}
	t.Logf("serial %s firmware %s part %q, audit log %d/%d, %d algorithms",
		info.Serial, info.Version, info.PartNumber, info.LogUsed, info.LogTotal, len(info.Algorithms))

	// Identity has to be stable across connections: the audit subsystem pins a
	// bundle to a serial, so a serial that changed between reads would silently
	// invalidate every continuation check.
	again, err := yubihsm.TransportDeviceInfo(ctx, driverConfig())
	if err != nil {
		t.Fatalf("re-reading device info: %v", err)
	}
	if again.Serial != info.Serial || again.Version != info.Version {
		t.Errorf("device identity changed between reads: %s/%s then %s/%s",
			info.Serial, info.Version, again.Serial, again.Version)
	}
}

// TestSecureChannelPayloadSizes sweeps echo payloads across the sizes where the
// secure channel's framing decisions change.
//
// SCP03 pads every command to an AES block, and the USB transport splits on a
// 64-byte packet boundary and must emit a zero-length packet when a message is
// an exact multiple of it. Both are off-by-one machines: a payload one byte
// either side of a boundary takes a different path through the code, and a
// suite that only echoes "hello" exercises exactly one of those paths.
func TestSecureChannelPayloadSizes(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	// Around the AES block size (16), the USB packet size (64), and their
	// multiples, plus the largest payload the echo command accepts.
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 55, 56, 57, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 2021}
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i % 251) // 251 is prime: no alignment with any block size
		}
		got, err := c.Echo(ctx, payload)
		if err != nil {
			t.Fatalf("echo of %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo of %d bytes came back changed:\n got %x\nwant %x", n, got, payload)
		}
	}
}

// TestSecureChannelCounterChaining runs many commands over one session.
//
// Each SCP03 message advances an encryption counter and chains its MAC to the
// previous one. A mistake in either is invisible on the first exchange and
// fatal on the second, so the count matters: this is the test that would catch
// a counter that stops incrementing or a chaining value that is not carried.
func TestSecureChannelCounterChaining(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	const exchanges = 200
	for i := 0; i < exchanges; i++ {
		payload := []byte(strings.Repeat("x", i%64) + "|" + time.Now().Format(time.RFC3339Nano))
		got, err := c.Echo(ctx, payload)
		if err != nil {
			t.Fatalf("echo %d of %d: %v", i+1, exchanges, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo %d of %d came back changed", i+1, exchanges)
		}
	}
}

// TestConcurrentCommandsOnOneSession drives one session from many goroutines.
//
// The device answers one command at a time and the SCP03 counter is shared
// mutable state, so the Client has to serialise. If it does not, the failure is
// a MAC mismatch or a response delivered to the wrong caller — and the product
// does exactly this, because the audit collector and the signing path share a
// session.
func TestConcurrentCommandsOnOneSession(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	const goroutines, each = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*each)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// A payload unique per goroutine catches a response routed to
				// the wrong caller, which an identical payload would hide.
				want := []byte(strings.Repeat(string(rune('a'+g)), 8+i))
				got, err := c.Echo(ctx, want)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, want) {
					errs <- errors.New("goroutine " + string(rune('a'+g)) + " got another caller's response")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent echo: %v", err)
	}
}

// TestWrongPasswordIsRejected checks that authentication actually authenticates.
//
// SCP03 authenticates mutually, so a wrong password must fail during channel
// establishment rather than at first use. Getting a session here would mean the
// derived keys are not being checked — the whole secure channel would be
// decorative.
func TestWrongPasswordIsRejected(t *testing.T) {
	requireDevice(t)
	ctx := testContext(t)

	cfg := driverConfig()
	cfg.Password = password() + "-wrong"
	c, err := yubihsm.Open(ctx, cfg)
	if err == nil {
		_ = c.Close()
		t.Fatal("a session opened with the wrong password")
	}
	t.Logf("rejected as expected: %v", err)
}

// TestWrongAuthKeyIDIsRejected asks for a session under an authentication key
// that does not exist. It is the companion to the wrong-password case: that one
// proves the key material is checked, this one proves the key *identity* is,
// and a device that answered here would let any caller pick a key id until one
// happened to work.
func TestWrongAuthKeyIDIsRejected(t *testing.T) {
	requireDevice(t)
	ctx := testContext(t)

	cfg := driverConfig()
	cfg.AuthKeyID = 0xfeed // outside any sane provisioning scheme
	c, err := yubihsm.Open(ctx, cfg)
	if err == nil {
		_ = c.Close()
		t.Fatal("a session opened under a nonexistent authentication key")
	}
	t.Logf("rejected as expected: %v", err)
}

// TestDeviceErrorsAreTyped checks that a device refusal arrives as a
// yubihsm.DeviceError rather than a generic transport failure.
//
// This is load-bearing for the layers above: the audit code distinguishes
// "the device says no" from "the wire broke", and it can only do that if the
// refusal keeps its status byte. A refusal flattened into a string would make
// an unreachable device and a rejected command indistinguishable.
func TestDeviceErrorsAreTyped(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	t.Run("unknown command", func(t *testing.T) {
		// 0x7e is not in the device's command set.
		_, err := c.Command(ctx, 0x7e, nil)
		if err == nil {
			t.Fatal("the device accepted an unknown command")
		}
		var devErr yubihsm.DeviceError
		if !errors.As(err, &devErr) {
			t.Fatalf("want a yubihsm.DeviceError, got %T: %v", err, err)
		}
		t.Logf("unknown command rejected: %v (0x%02x)", devErr, byte(devErr))
	})

	t.Run("missing object", func(t *testing.T) {
		// Nothing is provisioned at the top of the scratch range.
		_, err := c.GetObjectInfo(ctx, scratchTop, yubihsm.ObjectTypeAsymmetricKey)
		if err == nil {
			t.Fatalf("the device described object 0x%04x, which should not exist", scratchTop)
		}
		var devErr yubihsm.DeviceError
		if !errors.As(err, &devErr) {
			t.Fatalf("want a yubihsm.DeviceError, got %T: %v", err, err)
		}
		t.Logf("missing object rejected: %v (0x%02x)", devErr, byte(devErr))
	})
}

// TestSessionSurvivesRefusedCommand checks that a refusal does not poison the
// channel. A device error is an application-level answer, not a transport
// fault, so the SCP03 counter must still advance and the next command must
// work — otherwise every recoverable "no" from the device would cost a
// reconnect, and the audit collector would drop entries around one.
func TestSessionSurvivesRefusedCommand(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	if _, err := c.Command(ctx, 0x7e, nil); err == nil {
		t.Fatal("the device accepted an unknown command")
	}
	payload := []byte("still alive")
	got, err := c.Echo(ctx, payload)
	if err != nil {
		t.Fatalf("the session did not survive a refused command: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the session answered a refused command with a corrupted echo")
	}
}

// TestRandomIsFromTheDevice draws from the hardware RNG. The crypto service
// exposes this generator to callers (Task 138), so "it returns bytes" is not
// enough: the bytes have to differ between draws and not be trivially
// degenerate.
func TestRandomIsFromTheDevice(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	const n = 32
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		b, err := c.GetPseudoRandom(ctx, n)
		if err != nil {
			t.Fatalf("drawing %d random bytes: %v", n, err)
		}
		if len(b) != n {
			t.Fatalf("asked for %d random bytes, got %d", n, len(b))
		}
		if allSame(b) {
			t.Fatalf("the device returned %d identical bytes: %x", n, b)
		}
		if seen[string(b)] {
			t.Fatalf("the device repeated a %d-byte draw: %x", n, b)
		}
		seen[string(b)] = true
	}
}

func allSame(b []byte) bool {
	for _, x := range b[1:] {
		if x != b[0] {
			return false
		}
	}
	return len(b) > 0
}

// TestDeviceAttestationCertificate reads the factory attestation certificate
// from opaque object 0. Every per-key attestation is signed by the key this
// certificate belongs to, so if it cannot be read and parsed, the whole
// attestation tier has no anchor.
func TestDeviceAttestationCertificate(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	der, err := c.GetOpaque(ctx, 0)
	if err != nil {
		t.Fatalf("reading the device attestation certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the device attestation certificate: %v", err)
	}
	t.Logf("device certificate subject %q, issuer %q, %s .. %s",
		cert.Subject, cert.Issuer,
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if time.Now().After(cert.NotAfter) {
		t.Errorf("the device attestation certificate expired on %s; attestations will not verify",
			cert.NotAfter.Format(time.RFC3339))
	}
	if cert.PublicKey == nil {
		t.Error("the device attestation certificate carries no public key")
	}
}

// TestObjectInventoryIsConsistent walks every object the session can see and
// checks that the listing and the per-object detail agree.
//
// A disagreement here is not cosmetic: hsm.FindAsymmetricKey resolves a label
// to a handle by listing objects and then describing each one, so a mismatch
// between the two views would mean the product signs with a key other than the
// one it named.
func TestObjectInventoryIsConsistent(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	types := []byte{
		yubihsm.ObjectTypeAsymmetricKey,
		yubihsm.ObjectTypeAuthenticationKey,
		yubihsm.ObjectTypeOpaque,
		yubihsm.ObjectTypeWrapKey,
		yubihsm.ObjectTypeHMACKey,
	}
	sawAuthKey := false
	for _, ot := range types {
		objs, err := c.ListObjects(ctx, ot)
		if err != nil {
			t.Fatalf("listing %s objects: %v", yubihsm.ObjectTypeName(ot), err)
		}
		for _, o := range objs {
			if o.Type != ot {
				t.Errorf("listing %s returned an object of type %s", yubihsm.ObjectTypeName(ot), yubihsm.ObjectTypeName(o.Type))
			}
			info, err := c.GetObjectInfo(ctx, o.ID, o.Type)
			if err != nil {
				t.Errorf("describing 0x%04x (%s): %v", o.ID, yubihsm.ObjectTypeName(o.Type), err)
				continue
			}
			if info.ID != o.ID || info.Type != o.Type {
				t.Errorf("listing said 0x%04x/%s but the detail says 0x%04x/%s",
					o.ID, yubihsm.ObjectTypeName(o.Type), info.ID, yubihsm.ObjectTypeName(info.Type))
			}
			if info.Domains == 0 {
				t.Errorf("object 0x%04x belongs to no domain, which the device should not allow", info.ID)
			}
			if ot == yubihsm.ObjectTypeAuthenticationKey && info.ID == uint16(authKeyID()) {
				sawAuthKey = true
			}
			t.Logf("0x%04x %-20s alg=%-12s label=%q domains=0x%04x", info.ID,
				yubihsm.ObjectTypeName(info.Type), yubihsm.AlgorithmName(info.Algorithm), info.Label, info.Domains)
		}
	}
	// The key this very session authenticated with must be in the inventory; if
	// it is not, the listing is filtering or the session is not what it claims.
	if !sawAuthKey {
		t.Errorf("the authentication key 0x%04x this session used is not in the inventory", authKeyID())
	}
}

// TestLogReadsDoNotConsume reads the audit log twice and checks that the second
// read returns what the first did.
//
// This is the single most important read-only property of the device. The audit
// log is append-only evidence with 62 slots; entries are removed only by an
// explicit SET LOG INDEX. If a plain read consumed entries, then every
// diagnostic that looked at the log would destroy the evidence it was
// inspecting, and no bundle exported afterwards could be verified.
func TestLogReadsDoNotConsume(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	first, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	second, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("re-reading the audit log: %v", err)
	}

	// Reading the log is itself an audited command on a device with forced
	// audit, so the second read legitimately sees the first read's own entry.
	// What must not happen is entries disappearing.
	if len(second.Entries) < len(first.Entries) {
		t.Fatalf("reading the audit log consumed entries: %d then %d", len(first.Entries), len(second.Entries))
	}
	for i := range first.Entries {
		if first.Entries[i].Number != second.Entries[i].Number {
			t.Fatalf("entry %d changed number between reads: %d then %d",
				i, first.Entries[i].Number, second.Entries[i].Number)
		}
	}
	t.Logf("audit log holds %d entries and stayed put across two reads", len(first.Entries))
}

// TestContextCancellationIsHonoured checks that an expired context aborts a
// device call instead of blocking on USB.
//
// The product calls the device from request handlers and from background jobs
// under a shutdown context. A driver that ignored cancellation would turn a
// device that stopped answering into a hung server rather than a failed
// request.
func TestContextCancellationIsHonoured(t *testing.T) {
	requireDevice(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead before the call starts

	_, err := yubihsm.TransportDeviceInfo(ctx, driverConfig())
	if err == nil {
		t.Fatal("a cancelled context still produced a device answer")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want a context.Canceled error, got %v", err)
	}
}
