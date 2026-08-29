package yubihsm

import (
	"errors"
	"sync"
	"testing"
)

// installObserver registers fn for the duration of one test and returns a
// collector for what it saw. Restoring the previous hook matters because it is
// process-wide: a test that left one installed would have every later test in
// this package feeding a stale closure.
func installObserver(t *testing.T) *observed {
	t.Helper()
	o := &observed{}
	SetCommandObserver(o.record)
	t.Cleanup(func() { SetCommandObserver(nil) })
	return o
}

type observed struct {
	mu   sync.Mutex
	cmds []byte
}

func (o *observed) record(cmd byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cmds = append(o.cmds, cmd)
}

func (o *observed) seen() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte{}, o.cmds...)
}

func (o *observed) count(cmd byte) int {
	n := 0
	for _, c := range o.seen() {
		if c == cmd {
			n++
		}
	}
	return n
}

// Every command that reaches the device is announced. This is what covers the
// paths that never touch a key provider — key and device attestation, audit-head
// commitments, option changes — each of which writes device log entries that
// something has to drain.
func TestCommandObserverSeesEveryDeviceCommand(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	d.handlers[cmdGenerateAsymmetricKey] = func([]byte) ([]byte, error) { return []byte{0x7f, 0x00}, nil }
	d.handlers[cmdSignAttestationCert] = func([]byte) ([]byte, error) { return []byte("cert"), nil }

	o := installObserver(t)
	c, ctx := testClient(t, d)

	if _, err := c.Echo(ctx, []byte("hello")); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if _, err := c.GenerateAsymmetricKey(ctx, KeySpec{ID: 0x7f00, Label: "k", Domains: 1, Algorithm: AlgorithmECP256}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := c.AttestAsymmetricKey(ctx, 0x7f00, 0); err != nil {
		t.Fatalf("attest: %v", err)
	}

	for _, cmd := range []byte{cmdEcho, cmdGenerateAsymmetricKey, cmdSignAttestationCert} {
		if o.count(cmd) != 1 {
			t.Errorf("command 0x%02x was announced %d time(s), want 1 (seen: %x)", cmd, o.count(cmd), o.seen())
		}
	}
}

// A rejected command is announced too. The device logs the rejection, and an
// entry nobody collects is one a later fetch reports as a gap in the chain —
// which reads as tampering rather than as the failed operation it was.
func TestCommandObserverSeesRejectedCommands(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdDeleteObject] = func([]byte) ([]byte, error) { return nil, ErrObjectNotFound }

	o := installObserver(t)
	c, ctx := testClient(t, d)

	err := c.DeleteObject(ctx, 0x7f00, ObjectTypeAsymmetricKey)
	if err == nil {
		t.Fatal("the fake device accepted a delete it was told to reject")
	}
	var devErr DeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("expected a device error, got %v", err)
	}
	if o.count(cmdDeleteObject) != 1 {
		t.Fatalf("a rejected DELETE OBJECT was announced %d time(s), want 1", o.count(cmdDeleteObject))
	}
}

// The drain's own commands must not be announced, or every drain cycle would
// signal the need for another one. None of the three is audited, so nothing is
// lost by staying quiet about them.
func TestCommandObserverIgnoresTheDrainsOwnCommands(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdGetLogEntries] = func([]byte) ([]byte, error) {
		return make([]byte, 5), nil // no unlogged counters, no entries
	}
	d.handlers[cmdSetLogIndex] = func([]byte) ([]byte, error) { return nil, nil }
	// version 2.4.0, serial 31650425, 62-slot log with 4 used.
	d.handlers[cmdGetDeviceInfo] = func([]byte) ([]byte, error) {
		return []byte{2, 4, 0, 0x01, 0xe2, 0x0b, 0x39, 62, 4}, nil
	}

	o := installObserver(t)
	c, ctx := testClient(t, d)

	if _, err := c.GetLogEntries(ctx); err != nil {
		t.Fatalf("get log entries: %v", err)
	}
	if err := c.SetLogIndex(ctx, 12); err != nil {
		t.Fatalf("set log index: %v", err)
	}
	if _, err := c.DeviceInfo(ctx); err != nil {
		t.Fatalf("device info: %v", err)
	}
	// Closing the session is the fourth: it is not audited either, and firing on
	// it would have every short-lived CLI client request a drain on the way out.
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := o.seen(); len(got) != 0 {
		t.Fatalf("the drain's own commands were announced back to it: %x", got)
	}
}

// Removing the hook has to actually remove it: the CLI installs one only when
// the device is provisioned, and a leftover closure would outlive the collector
// it points at.
func TestCommandObserverCanBeRemoved(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }

	o := installObserver(t)
	c, ctx := testClient(t, d)
	if _, err := c.Echo(ctx, []byte("one")); err != nil {
		t.Fatalf("echo: %v", err)
	}
	SetCommandObserver(nil)
	if _, err := c.Echo(ctx, []byte("two")); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if got := o.count(cmdEcho); got != 1 {
		t.Fatalf("the removed observer saw %d echo(es), want the 1 sent before removal", got)
	}
}

// With no observer installed — the default, and what every deployment that
// never commissioned a device runs — the command path must not touch the hook
// at all.
func TestCommandsWorkWithoutAnObserver(t *testing.T) {
	SetCommandObserver(nil)
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	c, ctx := testClient(t, d)
	if _, err := c.Echo(ctx, []byte("hello")); err != nil {
		t.Fatalf("echo without an observer: %v", err)
	}
}
