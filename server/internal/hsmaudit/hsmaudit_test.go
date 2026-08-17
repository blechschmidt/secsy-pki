package hsmaudit

import (
	"context"
	"encoding/hex"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// fakeDevice is a scripted Device. Its log is built with real chain digests so
// the tests exercise the same re-derivation production does, rather than a
// weakened one that would let a broken verifier pass.
//
// The log-facing methods take mu because collection is now concurrent by
// design: operation-driven drains, the backstop sweep and the export path can
// all reach one device at once, and the tests that check they are serialized
// correctly would otherwise trip the race detector on this double rather than
// on the code under test. Tests that stay single-threaded may still touch the
// fields directly.
type fakeDevice struct {
	mu       sync.Mutex
	info     DeviceInfo
	opts     Options
	entries  []hsm.AuditLogEntry
	consumed uint16
	unlogged Unlogged

	fetchErr     error
	consumeErr   error
	provisionErr error
	fetches      int
	provisioned  []uint8

	// beforeFetch, when set, runs at the top of FetchLog. It lets a test hold a
	// drain cycle open at the one point where a concurrent drain would collide.
	beforeFetch func()
}

func (d *fakeDevice) Info(ctx context.Context) (*DeviceInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := d.info
	return &cp, nil
}

func (d *fakeDevice) FetchLog(ctx context.Context) (*hsm.LogResponse, error) {
	d.mu.Lock()
	hook := d.beforeFetch
	d.mu.Unlock()
	if hook != nil {
		hook()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.fetches++
	if d.fetchErr != nil {
		return nil, d.fetchErr
	}
	var out []hsm.AuditLogEntry
	for _, e := range d.entries {
		if e.Number > d.consumed {
			out = append(out, e)
		}
	}
	return &hsm.LogResponse{
		Entries:                 out,
		UnloggedBoots:           d.unlogged.Boots,
		UnloggedAuthentications: d.unlogged.Authentications,
	}, nil
}

func (d *fakeDevice) ConsumeLog(ctx context.Context, upTo uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.consumeErr != nil {
		return d.consumeErr
	}
	d.consumed = upTo
	return nil
}

// appendEntry adds one entry to the device log, chained onto the last, the way
// a real operation would. It returns the new entry number.
func (d *fakeDevice) appendEntry(e hsm.AuditLogEntry) uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	last := d.entries[len(d.entries)-1]
	prev, err := hex.DecodeString(last.Hash)
	if err != nil {
		panic(err)
	}
	e.Number = last.Number + 1
	e.Hash = hsm.ComputeEntryHash(e, prev)
	d.entries = append(d.entries, e)
	return e.Number
}

// consumedUpTo reports the acknowledgement point under the lock.
func (d *fakeDevice) consumedUpTo() uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.consumed
}

// fetchCount reports how many drain cycles reached the device.
func (d *fakeDevice) fetchCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fetches
}

func (d *fakeDevice) Options(ctx context.Context) (*Options, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := d.opts
	return &cp, nil
}

// ProvisionAudit records what would have been force-audited and raises the
// fake's own options. It reaches no hardware — which is the point of having it
// on the Device interface: before that, provisioning a fake reached for a zero
// hsm.Config, whose empty connector URL is the real direct-USB default, and
// silently force-audited any YubiHSM plugged into the machine running the test.
func (d *fakeDevice) ProvisionAudit(ctx context.Context, forced []uint8) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.provisionErr != nil {
		return "", d.provisionErr
	}
	d.provisioned = append(d.provisioned, forced...)
	if d.opts.CommandAudit == nil {
		d.opts.CommandAudit = map[uint8]AuditLevel{}
	}
	d.opts.ForceAudit = AuditFixed
	for _, c := range forced {
		d.opts.CommandAudit[c] = AuditFixed
	}
	return "fake: force-audited " + strconv.Itoa(len(forced)) + " command(s)", nil
}

// forcedOptions returns a device configuration that satisfies Options.Verify.
func forcedOptions() Options {
	o := Options{ForceAudit: AuditFixed, CommandAudit: map[uint8]AuditLevel{}}
	for _, c := range BaselineForcedCommands {
		o.CommandAudit[c] = AuditFixed
	}
	return o
}

// sentinel returns the device-init entry a factory reset writes. The digest is
// arbitrary because the device seeds it randomly per reset — which is exactly
// why it has to be pinned rather than recomputed.
func sentinel(anchor string) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Number: 1, Command: 0xff, Length: 0xffff,
		SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff,
		Result: 0xff, Tick: 0xffffffff, Hash: anchor,
	}
}

// chain appends entries after the sentinel, computing each real chain digest.
func chain(anchor string, rest ...hsm.AuditLogEntry) []hsm.AuditLogEntry {
	out := []hsm.AuditLogEntry{sentinel(anchor)}
	prev, err := hex.DecodeString(anchor)
	if err != nil {
		panic(err)
	}
	for i, e := range rest {
		e.Number = uint16(i + 2)
		e.Hash = hsm.ComputeEntryHash(e, prev)
		prev, _ = hex.DecodeString(e.Hash)
		out = append(out, e)
	}
	return out
}

// signEntry builds a successful signing entry for key id.
func signEntry(key uint16) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Command: hsm.CmdSignECDSA, Length: 64, SessionKey: 1,
		TargetKey: key, Result: hsm.CmdSignECDSA | 0x80, Tick: 100,
	}
}

const testAnchor = "369a47bf3d7353d627b7ce4e9c117fba"

func newFake(entries []hsm.AuditLogEntry) *fakeDevice {
	return &fakeDevice{
		info:    DeviceInfo{Serial: "31650425", Version: "2.4.0", LogUsed: "2/62"},
		opts:    forcedOptions(),
		entries: entries,
	}
}

// provisioned returns a Service, device and store already through provisioning,
// so tests can start from a commissioned device.
//
// It wires no Committer, so bundles exported from it carry no device commitment
// and every VerifyBundle call outside commitment_test.go passes
// AllowUnboundLog. That is deliberate rather than an oversight: a commitment
// costs three device log entries, which would shift every entry number these
// tests assert on, and none of them are about where the log came from.
// commitment_test.go builds on this helper and adds the committer.
func provisioned(t *testing.T, entries []hsm.AuditLogEntry) (*Service, *fakeDevice, *MemStore) {
	t.Helper()
	dev := newFake(entries)
	store := NewMemStore()
	// Provision would shell out to the real device to set options; the fake
	// already reports them forced, so pin the state directly the way Provision
	// does and collect.
	st := &AuditState{DeviceSerial: dev.info.Serial, Anchor: testAnchor, ProvisionedAt: time.Now().UTC()}
	if err := store.AppendLogEntries(context.Background(), entries[:1]); err != nil {
		t.Fatalf("seeding sentinel: %v", err)
	}
	st.Tail = Tail{Number: 1, Digest: testAnchor}
	if err := store.SaveAuditState(context.Background(), st); err != nil {
		t.Fatalf("pinning state: %v", err)
	}
	dev.consumed = 1
	svc := NewService(dev, store)
	// Production wires an attester from the device; the fake device is not a
	// HardwareDevice, so give it the captured one. Without it every exported bundle
	// would be unattested and every verification would fail on coverage, which
	// would say nothing about the property each test is actually checking.
	svc.SetAttester(&fakeAttester{})
	svc.SetAuditor(&MemAuditor{})
	return svc, dev, store
}

func TestCollectPersistsThenConsumes(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)

	res, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if res.Collected != 2 || res.Signatures != 2 {
		t.Fatalf("collected %d entries / %d signatures, want 2/2", res.Collected, res.Signatures)
	}
	if dev.consumed != 3 {
		t.Fatalf("device consumed up to %d, want 3", dev.consumed)
	}
	got, _ := store.LogEntries(context.Background())
	if len(got) != 3 {
		t.Fatalf("stored %d entries, want 3", len(got))
	}
	_ = svc
}

// A persist failure must leave the device log unacknowledged, so the entries
// survive to the next cycle. This is the specific bug in the pre-existing
// fetch-and-consume-then-store implementation.
func TestCollectDoesNotConsumeWhenPersistFails(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)

	failing := &failingStore{Store: store}
	res, err := NewCollector(dev, failing, 0, discardLogger()).Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error when persistence fails")
	}
	if dev.consumed != 1 {
		t.Fatalf("device log was acknowledged (consumed up to %d) despite the persist failure: "+
			"the only copy of entry 2 would have been destroyed", dev.consumed)
	}
	if res.Collected != 0 {
		t.Fatalf("reported %d collected entries after a failure", res.Collected)
	}
}

type failingStore struct {
	Store
}

func (f *failingStore) AppendLogEntries(ctx context.Context, entries []hsm.AuditLogEntry) error {
	return context.DeadlineExceeded
}

// A gap in device entry numbers means entries exist that were never collected.
// On a force-audited device those may be signatures, so the collector must
// refuse to acknowledge rather than skip over them.
func TestCollectFailsClosedOnGap(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	// Drop entry 2, leaving 1 and 3.
	gapped := []hsm.AuditLogEntry{entries[0], entries[2]}
	_, dev, store := provisioned(t, gapped)
	dev.entries = gapped

	_, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background())
	if err == nil {
		t.Fatal("expected a gap to fail collection")
	}
	if !strings.Contains(err.Error(), "never collected") {
		t.Fatalf("error does not name the gap: %v", err)
	}
	if dev.consumed != 1 {
		t.Fatalf("entries were acknowledged despite an unverifiable gap (consumed %d)", dev.consumed)
	}
}

// The device's own unlogged-operation counters mean the log overflowed and
// operations went unrecorded. That is the device admitting incompleteness.
func TestCollectFailsOnUnloggedOperations(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)
	dev.unlogged = Unlogged{Boots: 1}

	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err == nil {
		t.Fatal("expected unlogged operations to fail collection")
	}
}

// After a cycle that stored entries but failed to acknowledge them, the device
// re-delivers what we already hold. That must be tolerated, not reported as a
// rewind.
func TestCollectToleratesReDeliveryAfterConsumeFailure(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)
	dev.consumeErr = context.DeadlineExceeded

	c := NewCollector(dev, store, 0, discardLogger())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("first collect: %v", err)
	}
	dev.consumeErr = nil

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("second collect after re-delivery: %v", err)
	}
	if res.Collected != 0 {
		t.Fatalf("re-delivered entries were collected twice (%d)", res.Collected)
	}
	if dev.consumed != 3 {
		t.Fatalf("device consumed up to %d, want 3", dev.consumed)
	}
}

// A device that re-delivers an entry whose content differs from the stored copy
// is not describing an immutable log.
func TestCollectRejectsAlteredReDelivery(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	_, dev, store := provisioned(t, entries)
	dev.consumeErr = context.DeadlineExceeded
	c := NewCollector(dev, store, 0, discardLogger())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("first collect: %v", err)
	}
	dev.consumeErr = nil

	// Tamper with the digest of the entry the store already holds.
	dev.entries[1].Hash = strings.Repeat("ab", DigestLen)

	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected an altered re-delivery to be rejected")
	}
}

func TestVerifyBundleAcceptsBalancedHistory(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	if _, err := svc.Export(context.Background()); err != nil {
		t.Fatalf("priming export: %v", err)
	}
	// Two device signatures, two ledger rows.
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{AllowUnboundLog: true, ExpectedAnchor: testAnchor, ExpectedSerial: "31650425", SkipFreshness: true})
	if !res.OK {
		t.Fatalf("balanced history rejected: %v", res.Err())
	}
	if res.Reconciliation.TotalDeviceSignatures != 2 {
		t.Fatalf("counted %d device signatures, want 2", res.Reconciliation.TotalDeviceSignatures)
	}
}

// The headline property: a signature the device performed that the CA cannot
// account for must be reported as key abuse.
func TestVerifyBundleDetectsKeyAbuse(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	// The CA only accounts for two of the three device signatures.
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{AllowUnboundLog: true, ExpectedAnchor: testAnchor, ExpectedSerial: "31650425", SkipFreshness: true})
	if res.OK {
		t.Fatal("a surplus device signature was not detected as key abuse")
	}
	if !strings.Contains(res.Err().Error(), "KEY ABUSE") {
		t.Fatalf("finding does not identify key abuse: %v", res.Err())
	}
	if res.Reconciliation.Keys[0].Surplus != 1 {
		t.Fatalf("surplus %d, want 1", res.Reconciliation.Keys[0].Surplus)
	}
}

// An anchor that does not match the one the auditor pinned means the bundle
// describes a different history, however internally consistent it is.
func TestVerifyBundleRejectsUnpinnedAnchor(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{AllowUnboundLog: true, ExpectedAnchor: strings.Repeat("11", DigestLen), SkipFreshness: true})
	if res.OK {
		t.Fatal("a bundle with a foreign anchor verified")
	}
	if !strings.Contains(res.Err().Error(), "different device history") {
		t.Fatalf("finding does not explain the anchor mismatch: %v", res.Err())
	}
}

// Without force-audit fixed the device would overwrite log entries instead of
// refusing to operate, so the completeness argument collapses.
func TestVerifyBundleRejectsWeakDeviceOptions(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	dev.opts.ForceAudit = AuditOn // merely on: an operator can turn it off again

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{AllowUnboundLog: true, ExpectedAnchor: testAnchor, SkipFreshness: true})
	if res.OK {
		t.Fatal("a device without fixed force-audit verified")
	}
	if !strings.Contains(res.DeviceOptionsErr, "force-audit is on, want fixed") {
		t.Fatalf("options error does not name the weakness: %q", res.DeviceOptionsErr)
	}
}

// A command the device supports but this build does not recognise must be
// force-audited, because nothing here can rule out that it signs or exports a
// key. Real hardware made this concrete: a YubiHSM 2 on firmware 2.4.0 reports
// audit settings for commands 0x07 and 0x09, neither of which appears in
// Yubico's published command reference or their SDK's yh_cmd enum.
func TestUndocumentedDeviceCommandMustBeForced(t *testing.T) {
	const undocumented = 0x09
	if _, known := hsm.AllCommands[undocumented]; known {
		t.Skipf("0x%02x is now a known command; pick another unknown byte", undocumented)
	}

	o := forcedOptions()
	o.CommandAudit[undocumented] = AuditOff

	var inRequired bool
	for _, c := range o.RequiredForced() {
		if c == undocumented {
			inRequired = true
		}
	}
	if !inRequired {
		t.Fatalf("RequiredForced omitted undocumented command 0x%02x", undocumented)
	}

	err := o.Verify()
	if err == nil {
		t.Fatal("a device with an unaudited undocumented command verified as sufficient")
	}
	if !strings.Contains(err.Error(), "0x09") || !strings.Contains(err.Error(), "UNDOCUMENTED") {
		t.Fatalf("error does not identify the undocumented command: %v", err)
	}

	// Fixing it must satisfy the check.
	o.CommandAudit[undocumented] = AuditFixed
	if err := o.Verify(); err != nil {
		t.Fatalf("options with the undocumented command fixed still rejected: %v", err)
	}
}

// A bundle that simply omits an awkward command from the device's option set
// must not thereby dodge the requirement that it be force-audited.
func TestVerifyRejectsOptionsMissingBaselineCommand(t *testing.T) {
	o := forcedOptions()
	delete(o.CommandAudit, hsm.CmdSignECDSA)

	err := o.Verify()
	if err == nil {
		t.Fatal("options with SIGN ECDSA removed verified as sufficient")
	}
	if !strings.Contains(err.Error(), "no audit setting for commands it must support") {
		t.Fatalf("error does not name the omission: %v", err)
	}
}

// A deleted ledger row must break the chain rather than merely shorten the list,
// otherwise an operator could sign a rogue certificate and delete its row to
// make reconciliation balance.
func TestLedgerDeletionBreaksChain(t *testing.T) {
	store := NewMemStore()
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")
	addLedger(t, store, attestedKeyID, "cc")

	full, _ := store.Ledger(context.Background())
	if res := VerifyLedger(full); !res.Valid {
		t.Fatalf("intact ledger rejected: %s", res.Reason)
	}
	pruned := []LedgerEntry{full[0], full[2]}
	res := VerifyLedger(pruned)
	if res.Valid {
		t.Fatal("a ledger with a deleted row verified")
	}
	if !strings.Contains(res.Reason, "deleted") {
		t.Fatalf("reason does not name the deletion: %s", res.Reason)
	}
}

// Chaining exports is what bounds "what happened since the last export".
func TestVerifyContinuation(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	first, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("first export: %v", err)
	}

	// One more signature happens, and is accounted for.
	dev.entries = keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID), signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "cc")
	second, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("second export: %v", err)
	}

	cont := VerifyContinuation(first, second)
	if !cont.OK {
		t.Fatalf("legitimate continuation rejected: %v", cont.Err())
	}
	if cont.NewSignatures != 1 {
		t.Fatalf("reported %d new signatures, want 1", cont.NewSignatures)
	}
	if res := VerifyBundle(second, VerifyOptions{AllowUnboundLog: true, ExpectedAnchor: testAnchor, SkipFreshness: true}); !res.OK {
		t.Fatalf("second bundle rejected: %v", res.Err())
	}
}

// A factory reset between exports erases history. The anchor change makes that
// undeniable, which is the point: a reset cannot be used to launder a log.
func TestVerifyContinuationDetectsResetBetweenExports(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	first, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("first export: %v", err)
	}

	newAnchor := "225212b1e76170fed634a755a92a389f"
	second := *first
	second.Anchor = newAnchor
	second.LogEntries = chain(newAnchor, signEntry(attestedKeyID))

	cont := VerifyContinuation(first, &second)
	if cont.OK {
		t.Fatal("a post-reset bundle was accepted as a continuation")
	}
	if !strings.Contains(cont.Err().Error(), "factory reset") {
		t.Fatalf("finding does not name the reset: %v", cont.Err())
	}
}

// History that was already exported cannot be rewritten later.
func TestVerifyContinuationDetectsRewrittenHistory(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")
	first, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	second := *first
	second.LogEntries = append([]hsm.AuditLogEntry(nil), first.LogEntries...)
	// Drop the surplus signature from the previously exported history.
	second.LogEntries = second.LogEntries[:len(second.LogEntries)-1]

	cont := VerifyContinuation(first, &second)
	if cont.OK {
		t.Fatal("a truncated history was accepted as a continuation")
	}
	if !strings.Contains(cont.Err().Error(), "deleted") {
		t.Fatalf("finding does not name the deletion: %v", cont.Err())
	}
}

// Matching ledger digests against independently obtained artifacts is what
// turns "the HSM signed N times" into "the HSM signed exactly these N things".
func TestMatchPublishedDetectsUnpublishedSignature(t *testing.T) {
	store := NewMemStore()
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")
	ledger, _ := store.Ledger(context.Background())

	// The auditor only found one of the two signed artifacts published.
	res := MatchPublished(ledger, []string{digestOf("aa")})
	if res.OK {
		t.Fatal("an unpublished signature was not detected")
	}
	if len(res.Unpublished) != 1 {
		t.Fatalf("reported %d unpublished rows, want 1", len(res.Unpublished))
	}
}

func TestProvisionRefusesUnresetDevice(t *testing.T) {
	// A log that does not begin with the device-init sentinel means the device
	// has prior, unaudited history.
	used := []hsm.AuditLogEntry{signEntry(attestedKeyID)}
	used[0].Number = 1
	dev := newFake(used)
	svc := NewService(dev, NewMemStore())
	svc.SetAuditor(&MemAuditor{})

	if _, err := svc.Provision(context.Background()); err == nil {
		t.Fatal("provisioning succeeded on a device that was not factory reset")
	}
}

func TestProvisionRefusesToRePin(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, _ := provisioned(t, entries)
	if _, err := svc.Provision(context.Background()); err == nil {
		t.Fatal("re-provisioning replaced a pinned anchor")
	} else if !strings.Contains(err.Error(), "already provisioned") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseKeyID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint16
	}{
		{"1939", 0x1939},
		{"0a", 0x0a},
		{"", 0},
		{"6425", 0x6425},
		// Longer CKA_IDs come from tokens that do not use the YubiHSM's
		// two-byte object IDs; joining them onto a real key would be wrong.
		{"00112233", 0},
	} {
		if got := parseKeyID(tc.in); got != tc.want {
			t.Errorf("parseKeyID(%q) = 0x%04x, want 0x%04x", tc.in, got, tc.want)
		}
	}
}

func addLedger(t *testing.T, store Store, keyID uint16, seed string) {
	t.Helper()
	e := &LedgerEntry{
		Timestamp: time.Now().UTC(),
		KeyLabel:  "test-ca",
		KeyID:     keyID,
		Digest:    digestOf(seed),
		Algorithm: "SHA-256",
		Purpose:   PurposeCertificate,
	}
	if err := store.AppendLedger(context.Background(), e); err != nil {
		t.Fatalf("appending ledger entry: %v", err)
	}
}

func digestOf(seed string) string {
	return strings.Repeat(seed, 32)[:64]
}

// discardLogger keeps expected-failure tests from spamming the test output.
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
