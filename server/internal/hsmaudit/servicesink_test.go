package hsmaudit

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// The append-only file is documented as "the copy that survives whoever holds
// the database". It was not: four of the six drains in the system — the ones
// inside provisioning, export, freshness attestation and the device commitment
// — built their collector without sinks, so the entries they stored reached the
// database alone.
//
// What that cost is worse than a few missing rows. Provisioning collects the
// device-init sentinel and everything the commissioning itself produced, so a
// file written by a deployment that provisioned through this software never
// started at the sentinel — and a file that does not start there cannot be
// pinned to the chain anchor at all, which is the one check that distinguishes
// a genuine device history from a fabricated one. `verify-file -anchor` refused
// such a file outright. Meanwhile a server with a TSA configured ran the
// freshness and commitment jobs on a timer, each punching one more documented
// gap into the file it was supposed to be filling.
//
// So the sinks belong to the Service, and every collector the package builds
// carries them. These tests are per operation on purpose: a single "the Service
// has sinks" test would pass again the moment one of the four grew its own
// collector.

// recordingSink captures what the collector hands a sink.
type recordingSink struct {
	serial  string
	entries []uint16
	batches int
}

func (r *recordingSink) AppendEntries(_ context.Context, serial string, entries []hsm.AuditLogEntry) error {
	r.serial = serial
	r.batches++
	for _, e := range entries {
		r.entries = append(r.entries, e.Number)
	}
	return nil
}

func (r *recordingSink) Describe() string { return "recording test sink" }

func (r *recordingSink) has(n uint16) bool {
	for _, got := range r.entries {
		if got == n {
			return true
		}
	}
	return false
}

// Provisioning is the important one: it collects the sentinel, and a file that
// starts anywhere else can never be checked against the pinned anchor.
func TestProvisionWritesEveryCollectedEntryToTheConfiguredFile(t *testing.T) {
	dev := newFake(chain(testAnchor, genEntry(attestedKeyID)))
	store := NewMemStore()
	svc := NewService(dev, store)
	svc.SetAuditor(&MemAuditor{})

	path := logFilePath(t)
	file, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	svc.AddSink(file)

	if _, err := svc.Provision(context.Background()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	got, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Err(); err != nil {
		t.Fatalf("the provisioned file does not verify: %v", err)
	}
	if got.First != 1 {
		t.Fatalf("the file starts at entry %d, want the device-init sentinel at 1: "+
			"a file that does not start there cannot be pinned to the chain anchor", got.First)
	}
	if !got.FromGenesis {
		t.Fatal("the file does not claim to start at a factory reset, so -anchor can never check it")
	}
	if len(got.Problems) != 0 {
		t.Fatalf("the file documents %d problem(s): %+v", len(got.Problems), got.Problems)
	}
}

// Export drains twice — once for the log, once for the entries the key
// attestations themselves produce — and both belong in the file.
func TestExportWritesTheDrainedEntriesToTheConfiguredFile(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	sink := &recordingSink{}
	svc.AddSink(sink)

	// A signature the collector has not seen yet, exactly as an export taken
	// after a busy hour would find.
	n := dev.appendEntry(signEntry(attestedKeyID))
	if _, err := svc.Export(context.Background()); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !sink.has(n) {
		t.Fatalf("export collected entries %v but not %d, which it drained to build the bundle",
			sink.entries, n)
	}
	if sink.serial != dev.info.Serial {
		t.Fatalf("the sink was handed serial %q, want %q", sink.serial, dev.info.Serial)
	}
}

// Freshness attestation drains before it dates the head, so the server's own
// interval job is a writer of the device log.
func TestTimestampWritesTheDrainedEntriesToTheConfiguredFile(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	sink := &recordingSink{}
	svc.AddSink(sink)

	n := dev.appendEntry(signEntry(attestedKeyID))
	if _, err := svc.Timestamp(context.Background(), newTestTSA(t, "https://tsa.example/tsr")); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if !sink.has(n) {
		t.Fatalf("the freshness drain collected %v but not %d", sink.entries, n)
	}
}

// And so is the device commitment.
func TestCommitWritesTheDrainedEntriesToTheConfiguredFile(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	sink := &recordingSink{}
	svc.AddSink(sink)

	n := dev.appendEntry(signEntry(attestedKeyID))
	if _, err := svc.Commit(context.Background(), newTestTSA(t, "https://tsa.example/tsr")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !sink.has(n) {
		t.Fatalf("the commitment drain collected %v but not %d", sink.entries, n)
	}
}

// A sink the deployment did not configure must not be invented: AddSink(nil) is
// how every caller spells "no file is configured".
func TestAddSinkIgnoresNil(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, _ := provisioned(t, entries)
	svc.AddSink(nil)
	if _, err := svc.Export(context.Background()); err != nil {
		t.Fatalf("export with no sink configured: %v", err)
	}
}

// The file's own verifier must still describe a Service-written file the way an
// auditor reads it: whole history, no gaps, pinned to the anchor.
func TestProvisionedFilePinsToTheAnchor(t *testing.T) {
	dev := newFake(chain(testAnchor, genEntry(attestedKeyID)))
	store := NewMemStore()
	svc := NewService(dev, store)
	svc.SetAuditor(&MemAuditor{})

	path := logFilePath(t)
	file, err := OpenLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	svc.AddSink(file)
	if _, err := svc.Provision(context.Background()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	got, err := VerifyLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got.Anchor, testAnchor) {
		t.Fatalf("the file's anchor is %q, want the pinned %q", got.Anchor, testAnchor)
	}
}

// Provisioning writes the sentinel to the file before it pins anything, and a
// file that will not take it stops the commissioning. The device is still
// factory-reset at that point, so the operator fixes the path and runs it again
// — which is a far better place to be than holding a force-audited device whose
// append-only file is missing the only entry that can anchor it.
func TestProvisionFailsClosedWhenTheConfiguredFileRefuses(t *testing.T) {
	dev := newFake(chain(testAnchor, genEntry(attestedKeyID)))
	store := NewMemStore()
	svc := NewService(dev, store)
	svc.SetAuditor(&MemAuditor{})
	svc.AddSink(failingSink{})

	if _, err := svc.Provision(context.Background()); err == nil {
		t.Fatal("provisioning succeeded although its append-only file refused the records")
	}
	st, err := store.LoadAuditState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Fatal("an anchor was pinned even though the configured file never received the sentinel")
	}
	if len(dev.provisioned) != 0 {
		t.Fatal("the device was irreversibly force-audited before its sentinel reached the file")
	}
}
