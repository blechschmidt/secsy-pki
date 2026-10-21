package hsmaudit

// A factory reset replaces the device's history, and the collector has to notice.
//
// The device numbers its log from 1 again after a reset, so every entry it then
// offers sits *behind* a stored tail that belongs to the erased history. That is
// indistinguishable, by entry number alone, from the device re-delivering
// records we already hold — and the collector treated it as exactly that: it
// trimmed the whole segment as stale, stored nothing, and acknowledged the
// device anyway. Acknowledgement frees the ring slots, so the device-init
// sentinel — the one entry that cannot be recovered, and the one `provision`
// requires — was destroyed by the first HSM operation after a reset, silently.
//
// Found against a YubiHSM 2: a device reset while its database still held the
// pinned state of the previous commissioning could not be commissioned again
// without a second reset, and nothing said why.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// sentinelDevice is a freshly factory-reset device: entry 1 is the all-0xff
// device-init sentinel, entry 2 the boot record that follows it.
func sentinelDevice(serial string) *fakeDevice {
	// A real device seeds the sentinel's digest randomly at each reset (see
	// genesis.go), so any value stands in for it here.
	sentinel := Sentinel()
	sentinel.Hash = strings.Repeat("7e", 16)
	d := &fakeDevice{
		info:    DeviceInfo{Serial: serial, Version: "2.4.0", LogUsed: "2/62"},
		entries: []hsm.AuditLogEntry{sentinel},
	}
	d.appendEntry(hsm.AuditLogEntry{Command: 0x00})
	return d
}

func TestCollectorRefusesToAcknowledgeARestartedLog(t *testing.T) {
	dev := sentinelDevice("31650425")
	store := NewMemStore()
	ctx := context.Background()

	// The state a deployment still holds after someone factory-resets its
	// device: same serial, an anchor and a tail from the history just erased.
	if err := store.SaveAuditState(ctx, &AuditState{
		DeviceSerial: "31650425",
		Anchor:       "68e1e0fa1015e282f5ab2e9b7a539e32",
		Tail:         Tail{Number: 31, Digest: "6faa7cb2d6cf8e2200000000000000ff"},
	}); err != nil {
		t.Fatal(err)
	}

	_, err := NewCollector(dev, store, 0, discardLogger()).Collect(ctx)
	if err == nil {
		t.Fatal("the collector accepted a device whose log had restarted, so the entries it did not " +
			"store were acknowledged off the device")
	}
	for _, want := range []string{"device-init sentinel", "factory reset", "Refusing to acknowledge"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// The point of the refusal: the sentinel is still on the device, so the
	// operator can clear the stale state and provision.
	if got := dev.consumedUpTo(); got != 0 {
		t.Fatalf("the device was acknowledged up to entry %d; the sentinel is gone and the device can "+
			"no longer be provisioned without another factory reset", got)
	}
	resp, err := dev.FetchLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) == 0 || !hsm.IsBootSentinel(resp.Entries[0]) {
		t.Fatal("the device no longer offers its device-init sentinel")
	}
}

// The same shape with no sentinel — a log whose numbering simply bears no
// relation to the pinned tail — is refused too, because those entries also exist
// in exactly one copy.
func TestCollectorRefusesEntriesThatMatchNoStoredTail(t *testing.T) {
	dev := &fakeDevice{
		info:    DeviceInfo{Serial: "31650425", Version: "2.4.0", LogUsed: "2/62"},
		entries: []hsm.AuditLogEntry{{Number: 4, Command: 0x56, Hash: strings.Repeat("ab", 16)}},
	}
	store := NewMemStore()
	ctx := context.Background()
	if err := store.SaveAuditState(ctx, &AuditState{
		DeviceSerial: "31650425",
		Anchor:       "68e1e0fa1015e282f5ab2e9b7a539e32",
		Tail:         Tail{Number: 900, Digest: strings.Repeat("cd", 16)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(ctx); err == nil {
		t.Fatal("entries belonging to no known history were accepted")
	} else if !strings.Contains(err.Error(), "no record of") {
		t.Errorf("unexpected refusal: %v", err)
	}
	if got := dev.consumedUpTo(); got != 0 {
		t.Fatalf("the device was acknowledged up to entry %d, destroying records nothing stored", got)
	}
}

// And the genuine re-delivery this must not break: a cycle that persisted
// entries and then failed to acknowledge them. The device re-offers everything
// from the tail onward, the tail entry itself matches what is stored, and the
// cycle acknowledges — which is what frees the ring.
func TestCollectorStillAcknowledgesAGenuineRedelivery(t *testing.T) {
	dev := sentinelDevice("31650425")
	store := NewMemStore()
	ctx := context.Background()

	// Commission, so the stored tail and the device's log are the same history.
	svc := NewService(dev, store)
	svc.SetAuditor(&MemAuditor{})
	if _, err := svc.Provision(ctx); err != nil {
		t.Fatalf("provisioning the fake device: %v", err)
	}
	// Put the device back to delivering the entries it has already handed over:
	// a persisted-but-unacknowledged cycle.
	st, err := store.LoadAuditState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dev.mu.Lock()
	dev.consumed = st.Tail.Number - 1
	dev.mu.Unlock()

	res, err := NewCollector(dev, store, 0, discardLogger()).Collect(ctx)
	if err != nil {
		t.Fatalf("a re-delivery of stored entries must still be acknowledged: %v", err)
	}
	if res.Collected != 0 {
		t.Errorf("re-delivered entries were counted as newly collected: %d", res.Collected)
	}
	if got := dev.consumedUpTo(); got != st.Tail.Number {
		t.Errorf("the device was left unacknowledged at entry %d (tail %d), so its ring never frees",
			got, st.Tail.Number)
	}
}
