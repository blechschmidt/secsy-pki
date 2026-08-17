package hsmaudit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
)

// The commitment tests are structured around one question: what, exactly, does
// a bundle stop proving when each piece is removed?
//
// That shape matters more here than anywhere else in the package, because the
// property being added is not "another check passed". It is the only check whose
// subject is where the evidence came from. Every other check in VerifyBundle
// reasons about a log that carries no device identity and no signature, so all
// of them hold just as well over a fabrication — which is what
// TestFabricatedLogPassesEveryCheckExceptTheDeviceBinding demonstrates
// end-to-end rather than by assertion.

// --- fixtures -------------------------------------------------------------

// attestEntry builds the SIGN ATTESTATION CERTIFICATE entry a device writes when
// a key is attested: the attested object in target_key and the attesting key in
// second_key. Command 0x64 is not in hsm.SignCommands, so these do not count as
// signatures needing a ledger row — which is correct, and is why a commitment
// does not unbalance reconciliation.
func attestEntry(key, attestingKey uint16) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Command: cmdSignAttestationCertificate, Length: 4, SessionKey: 1,
		TargetKey: key, SecondKey: attestingKey, Result: cmdSignAttestationCertificate | 0x80, Tick: 80,
	}
}

const cmdSignAttestationCertificate uint8 = 0x64

// appendChain continues an existing chain, numbering and hashing each new entry
// from the last one. chain() rebuilds from the anchor, which cannot express "the
// device logged three more things while the test was running".
func appendChain(entries []hsm.AuditLogEntry, rest ...hsm.AuditLogEntry) []hsm.AuditLogEntry {
	out := append([]hsm.AuditLogEntry(nil), entries...)
	last := out[len(out)-1]
	prev, err := hex.DecodeString(last.Hash)
	if err != nil {
		panic(err)
	}
	next := last.Number
	for _, e := range rest {
		next++
		e.Number = next
		e.Hash = hsm.ComputeEntryHash(e, prev)
		prev, _ = hex.DecodeString(e.Hash)
		out = append(out, e)
	}
	return out
}

// fakeCommitter stands in for the device half of a commitment: it mints an
// attestation over the requested label and — because generating, attesting and
// deleting the throwaway key are force-audited commands — writes the three log
// entries a real device would.
//
// Its knobs are the ways a device or an adversary could deviate, one per test.
type fakeCommitter struct {
	ca  *fakeDeviceCA
	dev *fakeDevice

	calls []string
	err   error
	// tweak adjusts what the device asserts, for the tests where the certificate
	// and the request disagree.
	tweak func(*attestClaims)
	// silent suppresses the log entries, modelling a certificate produced against
	// some other device — or by an adversary holding one — and filed against this
	// log.
	silent bool
	// omitDeviceCert models a device whose factory certificate could not be read,
	// leaving the assertions unauthenticated.
	omitDeviceCert bool
}

func (f *fakeCommitter) CommitHead(ctx context.Context, objectID uint16, label string) (*hsmattest.Attestation, error) {
	f.calls = append(f.calls, label)
	if f.err != nil {
		return nil, f.err
	}
	claims := commitmentClaims(f.ca.serial, objectID, label)
	if f.tweak != nil {
		f.tweak(&claims)
	}
	att := &hsmattest.Attestation{
		KeyLabel:       label,
		CertificatePEM: f.ca.attest(nil2t(ctx), claims),
		ProducedAt:     time.Now().UTC(),
	}
	if !f.omitDeviceCert {
		att.DeviceCertificatePEM = f.ca.deviceCertPEM()
	}
	if !f.silent && f.dev != nil {
		f.dev.entries = appendChain(f.dev.entries,
			genEntry(objectID),
			attestEntry(objectID, 0),
			deleteEntry(objectID))
	}
	return att, nil
}

// nil2t lets the fake CA's t.Fatalf-based helpers be called from a Committer,
// which has no *testing.T. A failure inside the synthesizer is a bug in the test
// harness, so panicking is the right shape — it names the line either way.
func nil2t(context.Context) *testing.T { return harnessT }

// harnessT is set by newCommitter for the duration of a test.
var harnessT *testing.T

func newCommitter(t *testing.T, ca *fakeDeviceCA, dev *fakeDevice) *fakeCommitter {
	t.Helper()
	harnessT = t
	t.Cleanup(func() { harnessT = nil })
	return &fakeCommitter{ca: ca, dev: dev}
}

// committed builds a provisioned, collected, ledgered service with a synthetic
// device attestation CA and committer wired in — the starting point for almost
// every test below.
func committed(t *testing.T, entries []hsm.AuditLogEntry) (*Service, *fakeDevice, *MemStore, *fakeDeviceCA, *fakeCommitter) {
	t.Helper()
	svc, dev, store := provisioned(t, entries)
	ca := newFakeDeviceCA(t, dev.info.Serial)
	com := newCommitter(t, ca, dev)
	svc.SetCommitter(com)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return svc, dev, store, ca, com
}

// boundBundle is the canonical subject: two signatures, both published, a
// freshness proof and a device commitment. tweak, when non-nil, adjusts the test
// TSA before either is taken.
func boundBundle(t *testing.T, tweak func(*testTSA)) (*Bundle, *testTSA, *fakeDeviceCA) {
	t.Helper()
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	if tweak != nil {
		tweak(ts)
	}
	ctx := context.Background()
	if _, err := svc.Timestamp(ctx, ts); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return b, ts, ca
}

// boundOptions is the verification an auditor with everything would run.
func boundOptions(ts *testTSA, ca *fakeDeviceCA) VerifyOptions {
	return VerifyOptions{
		ExpectedAnchor:    testAnchor,
		ExpectedSerial:    "31650425",
		AttestationPolicy: ca.policy(),
		Freshness:         FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	}
}

// --- the label ------------------------------------------------------------

// The label is the entire channel between the audit head and the device's
// signature, and its width is fixed by the device: 40 bytes, no more and — since
// a shorter label would be NUL-padded on the way in and stripped on the way out
// — preferably no less.
func TestCommitmentLabelFillsTheDeviceLabelField(t *testing.T) {
	label := CommitmentLabel(Head{DeviceSerial: "31650425", Anchor: testAnchor, DeviceNumber: 7})
	if len(label) != CommitmentLabelLen {
		t.Fatalf("label %q is %d bytes, want exactly %d (the YubiHSM label width)",
			label, len(label), CommitmentLabelLen)
	}
	if !strings.HasPrefix(label, CommitmentLabelPrefix) {
		t.Fatalf("label %q does not carry the commitment prefix %q", label, CommitmentLabelPrefix)
	}
	payload := strings.TrimPrefix(label, CommitmentLabelPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("label payload %q is not base64url: %v", payload, err)
	}
	if len(raw) != CommitmentDigestBytes {
		t.Fatalf("label carries %d digest bytes, want %d", len(raw), CommitmentDigestBytes)
	}
}

// The point of committing to the head rather than to the log tail alone: every
// field an auditor reasons about has to be inside the digest, or an operator
// could swap the part that is not.
func TestCommitmentLabelCoversEveryHeadField(t *testing.T) {
	base := Head{
		DeviceSerial: "31650425", Anchor: testAnchor,
		DeviceNumber: 4, DeviceDigest: strings.Repeat("ab", DigestLen),
		Signatures: 2, LedgerSeq: 2, LedgerHash: strings.Repeat("cd", sha256.Size),
	}
	want := CommitmentLabel(base)
	for _, tc := range []struct {
		name string
		edit func(*Head)
	}{
		{"device serial", func(h *Head) { h.DeviceSerial = "99999999" }},
		{"anchor", func(h *Head) { h.Anchor = strings.Repeat("11", DigestLen) }},
		{"device entry number", func(h *Head) { h.DeviceNumber = 5 }},
		{"device chain digest", func(h *Head) { h.DeviceDigest = strings.Repeat("ba", DigestLen) }},
		{"signature count", func(h *Head) { h.Signatures = 3 }},
		{"ledger sequence", func(h *Head) { h.LedgerSeq = 3 }},
		{"ledger chain hash", func(h *Head) { h.LedgerHash = strings.Repeat("dc", sha256.Size) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			tc.edit(&h)
			if got := CommitmentLabel(h); got == want {
				t.Fatalf("changing the %s did not change the commitment label (%s)", tc.name, got)
			}
		})
	}
	if CommitmentLabel(base) != want {
		t.Fatal("the label is not deterministic for a fixed head")
	}
}

// The composition this feature exists for: the label carries a prefix of exactly
// the digest the timestamp token is taken over, so a commitment and a freshness
// proof over the same head are demonstrably about the same state rather than two
// adjacent claims that happen to look alike.
func TestCommitmentLabelIsAPrefixOfTheTimestampedDigest(t *testing.T) {
	h := Head{DeviceSerial: "31650425", Anchor: testAnchor, DeviceNumber: 4, Signatures: 2}
	full, err := hex.DecodeString(h.Digest())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(CommitmentLabel(h), CommitmentLabelPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(full[:CommitmentDigestBytes]) {
		t.Fatalf("the label commits to %x but the TSA signs over %x: the two mechanisms would attest to different values",
			payload, full[:CommitmentDigestBytes])
	}
}

// --- the commit path ------------------------------------------------------

// The happy path: the device signs a label derived from the head the CA actually
// holds, and a TSA dates that signature.
func TestCommitBindsCurrentHeadToDeviceSerial(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	com, err := svc.Commit(context.Background(), ts)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Entry 1 is the sentinel, 2 the key's creation, 3 and 4 the two signatures.
	if com.Head.DeviceNumber != 4 || com.Head.Signatures != 2 || com.Head.LedgerSeq != 2 {
		t.Fatalf("committed head is entry %d/%d signature(s)/ledger %d, want 4/2/2",
			com.Head.DeviceNumber, com.Head.Signatures, com.Head.LedgerSeq)
	}
	if com.Label != CommitmentLabel(com.Head) {
		t.Fatalf("stored label %q is not the head's %q", com.Label, CommitmentLabel(com.Head))
	}
	if com.ObjectID != DefaultCommitmentKeyID {
		t.Fatalf("commitment used object 0x%04x, want the reserved 0x%04x", com.ObjectID, DefaultCommitmentKeyID)
	}
	if len(com.Token) == 0 || com.GenTime.IsZero() {
		t.Fatal("the commitment was not dated")
	}
	if com.Source != "https://tsa.example/tsr" {
		t.Fatalf("commitment source %q, want the external TSA", com.Source)
	}

	// The device's own assertions, re-derived from the certificate rather than
	// read off the record.
	cert, err := com.Certificate()
	if err != nil {
		t.Fatalf("parsing commitment certificate: %v", err)
	}
	claims, err := hsmattest.ParseClaims(cert)
	if err != nil {
		t.Fatalf("parsing commitment claims: %v", err)
	}
	if claims.Label != com.Label {
		t.Fatalf("the device attested %q, not the commitment %q", claims.Label, com.Label)
	}
	if claims.DeviceSerial != "31650425" {
		t.Fatalf("the device attested serial %q, want 31650425", claims.DeviceSerial)
	}

	stored, err := store.Commitments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Seq != 1 {
		t.Fatalf("stored %d commitment(s) at seq %v, want one at seq 1", len(stored), stored)
	}
}

// A commitment is three force-audited device operations. Committing without
// collecting them would leave the export trailing entries it cannot explain into
// the next one — and would break the marker check that welds commitments into
// the chain.
func TestCommitCollectsTheEntriesItProduced(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	before, _ := store.LogEntries(context.Background())
	if _, err := svc.Commit(context.Background(), newTestTSA(t, "https://tsa.example/tsr")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	after, _ := store.LogEntries(context.Background())
	if len(after) != len(before)+3 {
		t.Fatalf("the commitment added %d stored log entr(ies), want 3 (generate, attest, delete)",
			len(after)-len(before))
	}
	var gen, attest, del bool
	for _, e := range after[len(before):] {
		if e.TargetKey != DefaultCommitmentKeyID {
			t.Fatalf("commitment entry %d targets 0x%04x, want the reserved 0x%04x",
				e.Number, e.TargetKey, DefaultCommitmentKeyID)
		}
		switch e.Command {
		case hsm.CmdGenerateAsymmetricKey:
			gen = true
		case cmdSignAttestationCertificate:
			attest = true
		case hsm.CmdDeleteObject:
			del = true
		}
	}
	if !gen || !attest || !del {
		t.Fatalf("commitment left generate=%v attest=%v delete=%v in the log", gen, attest, del)
	}
}

// A commitment must not unbalance reconciliation. SIGN ATTESTATION CERTIFICATE
// is not a signing command, so the three entries add no device signature that the
// ledger would then owe a row for.
func TestCommitDoesNotUnbalanceReconciliation(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	res := VerifyBundle(b, boundOptions(ts, ca))
	if !res.OK {
		t.Fatalf("a committed bundle was rejected: %v", res.Err())
	}
	if !res.Reconciliation.OK || res.Reconciliation.TotalDeviceSignatures != 2 {
		t.Fatalf("reconciliation counted %d device signature(s), want 2: %v",
			res.Reconciliation.TotalDeviceSignatures, res.Reconciliation.Findings)
	}
	// The throwaway key must not be treated as a signing key needing attestation.
	for _, id := range SigningKeyIDs(b.LogEntries, b.Ledger) {
		if id >= CommitmentKeyIDMin && id <= CommitmentKeyIDMax {
			t.Fatalf("the commitment handle 0x%04x was counted as a signing key", id)
		}
	}
}

func TestCommitRefusesWithoutACommitter(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, _ := provisioned(t, entries)
	svc.SetCommitter(nil)
	if _, err := svc.Commit(context.Background(), newTestTSA(t, "x")); err == nil {
		t.Fatal("a service with no committer produced a commitment")
	}
}

// The reserved range is what keeps a commitment's log entries distinguishable
// from work done with a production key. A configuration outside it is refused
// where it would be used rather than silently accepted and rejected at audit.
func TestCommitRefusesKeyIDOutsideTheReservedRange(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, _, _, _ := committed(t, entries)
	svc.SetCommitmentKeyID(attestedKeyID)
	_, err := svc.Commit(context.Background(), newTestTSA(t, "x"))
	if err == nil {
		t.Fatal("a commitment key id outside the reserved range was accepted")
	}
	if !strings.Contains(err.Error(), "reserved range") {
		t.Fatalf("error does not name the range: %v", err)
	}
}

// A device that attests something other than what it was asked to is not a
// record to keep for later analysis. Catching it at commit time is what stops a
// useless commitment entering the record with no way to tell whether the device
// or the row was at fault.
func TestCommitRejectsADeviceThatAttestsTheWrongLabel(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, com := committed(t, entries)
	com.tweak = func(c *attestClaims) { c.Label = CommitmentLabelPrefix + strings.Repeat("A", 36) }

	if _, err := svc.Commit(context.Background(), newTestTSA(t, "x")); err == nil {
		t.Fatal("a certificate over the wrong label was accepted")
	} else if !strings.Contains(err.Error(), "does not bind the audit head") {
		t.Fatalf("error does not explain the mismatch: %v", err)
	}
	if stored, _ := store.Commitments(context.Background()); len(stored) != 0 {
		t.Fatalf("a rejected commitment was stored anyway (%d row(s))", len(stored))
	}
}

func TestCommitRejectsAForeignDeviceSerial(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, com := committed(t, entries)
	com.tweak = func(c *attestClaims) { c.Serial = "99999999" }

	_, err := svc.Commit(context.Background(), newTestTSA(t, "x"))
	if err == nil {
		t.Fatal("a commitment signed by a different HSM was accepted")
	}
	if !strings.Contains(err.Error(), "different HSM") {
		t.Fatalf("error does not name the device mismatch: %v", err)
	}
	if stored, _ := store.Commitments(context.Background()); len(stored) != 0 {
		t.Fatal("a commitment from a foreign device was stored")
	}
}

// A TSA that returns a token over something else leaves the commitment undated.
// The token itself is discarded — keeping one that does not cover the
// certificate would leave a row that fails verification later with no way to tell
// whether the authority misbehaved or the row was edited — but the binding is
// still recorded, because the device has already written its log entries.
func TestCommitDiscardsAnUnusableTokenButKeepsTheBinding(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, _ := committed(t, entries)

	ts := newTestTSA(t, "https://tsa.example/tsr")
	com, err := svc.Commit(context.Background(), &lyingTSA{testTSA: ts})
	if err == nil {
		t.Fatal("a token over an unrelated digest was accepted silently")
	}
	if !strings.Contains(err.Error(), "unusable token") {
		t.Fatalf("error does not name the token: %v", err)
	}
	if com == nil {
		t.Fatal("the binding was discarded along with the bad token")
	}
	if len(com.Token) != 0 || !com.GenTime.IsZero() {
		t.Fatal("a token that does not cover the certificate was kept")
	}
	stored, _ := store.Commitments(context.Background())
	if len(stored) != 1 {
		t.Fatalf("stored %d commitment(s), want the undated binding to be recorded", len(stored))
	}
}

// lyingTSA returns a genuine token over a digest of its own choosing, which is
// what a compromised or misconfigured authority looks like from here.
type lyingTSA struct{ *testTSA }

func (l *lyingTSA) Timestamp(ctx context.Context, digest []byte) ([]byte, time.Time, error) {
	other := sha256.Sum256([]byte("something else entirely"))
	return l.testTSA.Timestamp(ctx, other[:])
}

// A deployment with no reachable TSA still gets the serial binding — throwing it
// away would also throw away the log markers the device has already written, and
// those cannot be retracted. The verifier is where the missing date becomes a
// failure, and the commit path reports it as a warning rather than swallowing it.
func TestCommitWithoutATSAProducesAnUndatedCommitment(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	com, err := svc.Commit(context.Background(), nil)
	if com == nil {
		t.Fatalf("commit without a TSA discarded the binding: %v", err)
	}
	if err == nil {
		t.Fatal("an undated binding was reported as a clean success")
	}
	if !strings.Contains(err.Error(), "could not be dated") {
		t.Fatalf("warning does not name the missing date: %v", err)
	}
	if len(com.Token) != 0 || !com.GenTime.IsZero() {
		t.Fatal("a commitment taken without a TSA carries a date")
	}
	if stored, _ := store.Commitments(context.Background()); len(stored) != 1 {
		t.Fatalf("stored %d commitment(s), want the undated binding to be recorded", len(stored))
	}

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyCommitments(b, CommitmentOptions{AttestationPolicy: ca.policy()})
	if res.OK {
		t.Fatal("a bundle whose only binding is undated verified")
	}
	if res.Undated != 1 {
		t.Fatalf("reported %d undated binding(s), want 1", res.Undated)
	}
	if !strings.Contains(res.Err().Error(), "2017..2071") {
		t.Fatalf("finding does not explain why an undated attestation proves nothing about time: %v", res.Err())
	}
}

// The bug that made undated bindings and orphaned markers notes rather than
// failures: a device's log entries are append-only, so anything that goes wrong
// *after* the device has signed leaves a trace that no later work can retract.
// If that trace were fatal, a single unreachable timestamp authority would
// permanently convert every future export into a tampering accusation.
func TestATransientTSAOutageDoesNotPoisonLaterBundles(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	ctx := context.Background()
	ts := newTestTSA(t, "https://tsa.example/tsr")

	// The outage: the authority is unreachable, but the device has already
	// generated, attested and deleted the commitment key.
	if _, err := svc.Commit(ctx, nil); err == nil {
		t.Fatal("the undated commitment was reported as a clean success")
	}

	// The recovery: the authority comes back and the next cycle succeeds.
	dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "bb")
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("the commitment after the outage failed: %v", err)
	}

	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor:    testAnchor,
		ExpectedSerial:    "31650425",
		AttestationPolicy: ca.policy(),
		SkipFreshness:     true,
		Commitments:       CommitmentOptions{TSARoots: []*x509.Certificate{ts.root}},
	})
	if !res.OK {
		t.Fatalf("one TSA outage made a later, correctly bound export unverifiable: %v", res.Err())
	}
	c := res.Commitments
	if c.Verified != 1 || c.Undated != 1 {
		t.Fatalf("verdict counted %d verified / %d undated of %d, want 1/1 of 2",
			c.Verified, c.Undated, c.Commitments)
	}
	// The outage is reported, just not as tampering.
	if len(c.Notes) == 0 || !strings.Contains(strings.Join(c.Notes, "; "), "carries no timestamp") {
		t.Fatalf("the undated binding was not reported at all: %v", c.Notes)
	}
}

// --- verification ---------------------------------------------------------

// The composed claim: a device asserted this state, and an authority dated the
// assertion. The summary has to say both, because either alone overstates.
func TestVerifyBundleAcceptsASerialBoundLog(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	res := VerifyBundle(b, boundOptions(ts, ca))
	if !res.OK {
		t.Fatalf("a serial-bound bundle was rejected: %v", res.Err())
	}
	c := res.Commitments
	if c == nil || !c.OK || c.Verified != 1 {
		t.Fatalf("commitment verdict: %+v", c)
	}
	if !c.SerialBound || c.DeviceSerial != "31650425" {
		t.Fatalf("the log was not bound to the device: serial=%q bound=%v", c.DeviceSerial, c.SerialBound)
	}
	if c.TrustAnchor == "" {
		t.Fatal("the commitment did not report the attestation root it reached")
	}
	if c.Stale {
		t.Fatal("a just-made commitment was reported stale")
	}
	if !strings.Contains(res.Summary, "signed a commitment to this log") {
		t.Fatalf("summary does not state the provenance: %q", res.Summary)
	}
	if !strings.Contains(res.Summary, "current as of") {
		t.Fatalf("summary lost the freshness clause: %q", res.Summary)
	}
	if b.Version != BundleVersion {
		t.Fatalf("bundle version %d, want %d", b.Version, BundleVersion)
	}
}

// A bundle with no commitment is the default state of every deployment before
// this feature. It must fail rather than report a confident OK over a log whose
// origin nothing establishes.
func TestVerifyRejectsAnUnboundLog(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	ts := newTestTSA(t, "https://tsa.example/tsr")
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(b.Commitments) != 0 {
		t.Fatal("a service with no committer produced commitments")
	}

	opts := VerifyOptions{ExpectedAnchor: testAnchor, Freshness: FreshnessOptions{Roots: []*x509.Certificate{ts.root}}}
	res := VerifyBundle(b, opts)
	if res.OK {
		t.Fatal("a log no device ever signed for verified")
	}
	if !strings.Contains(res.Err().Error(), "fabricated offline") {
		t.Fatalf("finding does not explain what is missing: %v", res.Err())
	}

	// The escape hatch reports rather than fails, and says so.
	opts.AllowUnboundLog = true
	relaxed := VerifyBundle(b, opts)
	if !relaxed.OK {
		t.Fatalf("-allow-unbound-log did not downgrade the failure: %v", relaxed.Err())
	}
	if len(relaxed.Findings) == 0 || !strings.Contains(strings.Join(relaxed.Findings, "; "), "IGNORED") {
		t.Fatalf("the downgrade was silent: %v", relaxed.Findings)
	}
	// And the summary must stop claiming provenance it no longer has.
	if strings.Contains(relaxed.Summary, "signed a commitment") {
		t.Fatalf("summary claims a binding the bundle does not carry: %q", relaxed.Summary)
	}
	if !strings.Contains(relaxed.Summary, "carries no device identity") {
		t.Fatalf("summary does not disclaim the provenance: %q", relaxed.Summary)
	}
}

// The headline demonstration. Everything except the device binding is
// reconstructible by anyone who has seen one genuine export: the log chain is
// unkeyed, the ledger chain is unkeyed, the key attestations are public
// certificates, and a real TSA will timestamp any digest it is handed. So a
// wholly invented history passes every other check — including the pinned anchor,
// if the auditor's copy came from the same forger.
//
// This test builds exactly that bundle and asserts that the commitment check is
// the one thing that catches it.
func TestFabricatedLogPassesEveryCheckExceptTheDeviceBinding(t *testing.T) {
	// An invented anchor, a hand-built log with correct chain digests, a
	// hand-built ledger, and the key attestation copied out of a real export.
	const forgedAnchor = "00112233445566778899aabbccddeeff"
	entries := keyChain(forgedAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))

	store := NewMemStore()
	ctx := context.Background()
	if err := store.SaveAuditState(ctx, &AuditState{
		DeviceSerial: "31650425", Anchor: forgedAnchor, ProvisionedAt: time.Now().UTC(),
		Tail: Tail{Number: entries[len(entries)-1].Number, Digest: entries[len(entries)-1].Hash},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendLogEntries(ctx, entries); err != nil {
		t.Fatal(err)
	}
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	svc := NewService(&fakeDevice{
		info: DeviceInfo{Serial: "31650425", Version: "2.4.0", LogUsed: "4/62"},
		opts: forcedOptions(), entries: entries, consumed: entries[len(entries)-1].Number,
	}, store)
	svc.SetAttester(&fakeAttester{})
	svc.SetAuditor(&MemAuditor{})

	// A genuine timestamp over the invented head. The TSA has never seen a
	// YubiHSM and signs what it is given.
	ts := newTestTSA(t, "https://tsa.example/tsr")
	if _, err := svc.Timestamp(ctx, ts); err != nil {
		t.Fatalf("timestamping the forged head: %v", err)
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// With the device binding waived, the forgery is indistinguishable from a
	// genuine history. That is the state of the art this task changes, and
	// asserting it is what makes the next assertion meaningful.
	lenient := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor:  forgedAnchor,
		ExpectedSerial:  "31650425",
		AllowUnboundLog: true,
		Freshness:       FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if !lenient.OK {
		t.Fatalf("the forgery failed a check other than the device binding, which would make this test "+
			"prove the wrong thing: %v", lenient.Err())
	}

	// With it required, it fails — and on exactly that check.
	strict := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: forgedAnchor,
		ExpectedSerial: "31650425",
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if strict.OK {
		t.Fatal("a wholly fabricated log verified")
	}
	if len(strict.Findings) != 1 {
		t.Fatalf("the forgery failed %d checks, want exactly the device binding: %v", len(strict.Findings), strict.Findings)
	}
	if !strings.Contains(strict.Findings[0], "no device-signed commitments") {
		t.Fatalf("the failing check is not the device binding: %v", strict.Findings[0])
	}
}

// The forger's obvious next move: mint a "device attestation certificate" of
// their own asserting the serial they want and sign a commitment with it. The
// chain anchoring to Yubico's published roots is what makes that fail.
func TestVerifyRejectsACommitmentFromAnUnanchoredDevice(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	// The auditor uses Yubico's roots, which the synthetic device CA is not in.
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor:      testAnchor,
		AllowUnattestedKeys: true, // isolate the commitment check from the key one
		Freshness:           FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a commitment from a device that does not chain to a trusted attestation root verified")
	}
	if !strings.Contains(res.Err().Error(), "does not chain to a trusted attestation root") {
		t.Fatalf("finding does not name the unanchored chain: %v", res.Err())
	}
	_ = ca
}

// A self-signed certificate carrying the right label and the right serial, with
// no device certificate behind it: the cheapest possible forgery.
func TestVerifyRejectsASelfSignedCommitment(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	com := &b.Commitments[0]
	com.CertificatePEM = selfSignedAttestation(t, commitmentClaims("31650425", com.ObjectID, com.Label))
	com.DeviceCertificatePEM = ""
	// Re-date it so the token still covers the certificate; the point is the
	// missing device binding, not a stale imprint.
	redate(t, com, ts)

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a self-signed commitment verified")
	}
	if !strings.Contains(res.Err().Error(), "device attestation certificate") {
		t.Fatalf("finding does not name the missing device binding: %v", res.Err())
	}
}

// selfSignedAttestation mints a certificate carrying genuine-looking YubiHSM
// extensions but signed by nothing in particular.
func selfSignedAttestation(t *testing.T, c attestClaims) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: fmt.Sprintf("YubiHSM Attestation id:0x%04x", c.ObjectID)},
		NotBefore:       time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:        time.Date(2071, 10, 5, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: yubicoExtensions(t, c),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// redate re-obtains a token over a commitment's current certificate, so a test
// that replaced the certificate is not caught by the imprint check when it means
// to exercise something else.
func redate(t *testing.T, com *Commitment, ts *testTSA) {
	t.Helper()
	der, err := com.CertificateDER()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	token, genTime, err := ts.Timestamp(context.Background(), sum[:])
	if err != nil {
		t.Fatal(err)
	}
	com.Token, com.GenTime = token, genTime.UTC()
}

// A commitment whose head does not describe the bundle's log is a device
// signature over a state that never existed. The device will sign any label it
// is handed, so this is the check that keeps the binding honest.
func TestVerifyRejectsACommitmentToAHeadTheLogDoesNotContain(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	b.Commitments[0].Head.Signatures = 99

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a commitment to an invented head verified")
	}
	// Editing the head changes the label the verifier recomputes, so the
	// certificate no longer matches it — either finding is the correct rejection.
	if e := res.Err().Error(); !strings.Contains(e, "commits to a different audit state") &&
		!strings.Contains(e, "does not match the exported one") {
		t.Fatalf("finding does not explain the head mismatch: %v", res.Err())
	}
}

// Rewriting a log entry the device already signed for must be detected: the
// committed label folds in that entry's chain digest.
func TestVerifyDetectsALogRewriteBehindACommitment(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	for i := range b.LogEntries {
		if b.LogEntries[i].Number == 4 {
			b.LogEntries[i].Hash = strings.Repeat("cc", DigestLen)
		}
	}
	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a log rewritten behind a device commitment verified")
	}
	if !strings.Contains(res.Err().Error(), "rewritten after it was attested") {
		t.Fatalf("finding does not name the rewrite: %v", res.Err())
	}
}

// A commitment signed by a genuine YubiHSM that is not the one the bundle names
// proves the wrong thing entirely: some device exists, not that this log came
// from the device the CA claims.
func TestVerifyRejectsACommitmentFromAnotherDevice(t *testing.T) {
	b, ts, _ := boundBundle(t, nil)
	other := newFakeDeviceCA(t, "99999999")
	com := &b.Commitments[0]
	com.CertificatePEM = other.attest(t, commitmentClaims("99999999", com.ObjectID, com.Label))
	com.DeviceCertificatePEM = other.deviceCertPEM()
	redate(t, com, ts)

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: other.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a commitment from a different HSM verified for this log")
	}
	if !strings.Contains(res.Err().Error(), "serial") {
		t.Fatalf("finding does not name the serial mismatch: %v", res.Err())
	}
}

// The ratchet. Generating the commitment key is force-audited, so a genuine
// commitment leaves an entry naming its reserved handle right after the head it
// bound. A certificate obtained against some other device — or minted while this
// one was disconnected — leaves no such entry.
func TestVerifyRejectsACommitmentWithNoTraceInTheLog(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, ca, com := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	com.silent = true // the device signs, but this log does not record it

	ts := newTestTSA(t, "https://tsa.example/tsr")
	if _, err := svc.Commit(context.Background(), ts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a commitment the log has no record of verified")
	}
	if !strings.Contains(res.Err().Error(), "no creation of the commitment key") {
		t.Fatalf("finding does not name the missing marker: %v", res.Err())
	}
}

// Dropping the commitment's log entries from an export is the same move seen
// from the other side, and must fail the same way.
func TestVerifyRejectsALogWithTheCommitmentMarkerRemoved(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	kept := b.LogEntries[:0:0]
	for _, e := range b.LogEntries {
		if e.TargetKey == DefaultCommitmentKeyID && e.Command == hsm.CmdGenerateAsymmetricKey {
			continue
		}
		kept = append(kept, e)
	}
	b.LogEntries = kept

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("an export that deleted the commitment's own log entry verified")
	}
	if !strings.Contains(res.Err().Error(), "commitment key") {
		t.Fatalf("finding does not name the missing entry: %v", res.Err())
	}
}

// The converse of the marker check: drop a binding from the middle of the
// sequence and every surviving commitment still finds a marker of its own, while
// the log is left with a commitment key nothing accounts for.
//
// It is reported rather than failed, and the asymmetry is deliberate — see
// VerifyCommitments. A dropped binding removes evidence in the CA's favour,
// while failing on the orphan would make one crashed commitment permanently
// fatal. TestATransientTSAOutageDoesNotPoisonLaterBundles is the other side of
// that trade; VerifyContinuation is what catches the drop as tampering, because
// it compares against a bundle the auditor already held.
func TestVerifyReportsACommitmentDroppedFromTheMiddle(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Commit(ctx, ts); err != nil {
			t.Fatalf("commit %d: %v", i+1, err)
		}
		dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
		addLedger(t, store, attestedKeyID, fmt.Sprintf("%02x", i))
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(b.Commitments) != 3 {
		t.Fatalf("exported %d commitment(s), want 3", len(b.Commitments))
	}

	// The log is untouched; only the middle binding is gone from the record.
	full := append([]Commitment(nil), b.Commitments...)
	b.Commitments = []Commitment{full[0], full[2]}

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if !res.OK {
		t.Fatalf("dropping a binding was treated as tampering rather than reported: %v", res.Err())
	}
	if !strings.Contains(strings.Join(res.Notes, "; "), "no commitment in this bundle accounts for") {
		t.Fatalf("the orphaned marker was not reported at all: %v", res.Notes)
	}

	// With all three present there is nothing to report, which is what makes the
	// note above about the drop rather than about the log's shape.
	b.Commitments = full
	if quiet := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	}); strings.Contains(strings.Join(quiet.Notes, "; "), "no commitment in this bundle accounts for") {
		t.Fatalf("a complete sequence still reported an orphaned marker: %v", quiet.Notes)
	}
}

// A commitment made with a production key's handle would make every log entry
// against that handle ambiguous — was that a signature or a commitment?
func TestVerifyRejectsACommitmentOutsideTheReservedRange(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	b.Commitments[0].ObjectID = attestedKeyID

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a commitment made with a production key handle verified")
	}
	if !strings.Contains(res.Err().Error(), "reserved commitment range") {
		t.Fatalf("finding does not name the range: %v", res.Err())
	}
}

// An attestation certificate carries a fixed 2017..2071 validity, so nothing in
// it dates the commitment. Without a token an operator could mint a batch in
// advance and file them against whatever history they later invented.
func TestVerifyRejectsAnUndatedCommitment(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	b.Commitments[0].Token = nil
	b.Commitments[0].GenTime = time.Time{}

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a bundle whose only binding is undated verified")
	}
	if res.Undated != 1 || res.Verified != 0 {
		t.Fatalf("counted %d verified / %d undated, want 0/1", res.Verified, res.Undated)
	}
	if !strings.Contains(res.Err().Error(), "none of those bindings is dated") {
		t.Fatalf("finding does not name the missing date: %v", res.Err())
	}
	if !strings.Contains(strings.Join(res.Notes, "; "), "carries no timestamp") {
		t.Fatalf("the undated binding was not identified: %v", res.Notes)
	}
}

// Trust anchors are what separate "some authority dated this" from "an authority
// you trust dated this".
func TestVerifyRejectsACommitmentDatedByAnUntrustedTSA(t *testing.T) {
	b, _, ca := boundBundle(t, nil)
	other := newTestTSA(t, "https://other.example/tsr")

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{other.root},
	})
	if res.OK {
		t.Fatal("a commitment dated by an untrusted authority verified against pinned roots")
	}
	if !strings.Contains(res.Err().Error(), "TSA certificate chain") {
		t.Fatalf("finding does not name the chain failure: %v", res.Err())
	}
}

// Moving a token between commitments must not work: the imprint is over the
// certificate's own DER, not over the head.
func TestVerifyRejectsATransplantedToken(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	ctx := context.Background()
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "bb")
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(b.Commitments) != 2 {
		t.Fatalf("exported %d commitment(s), want 2", len(b.Commitments))
	}

	b.Commitments[0].Token = b.Commitments[1].Token
	b.Commitments[0].GenTime = b.Commitments[1].GenTime
	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a token moved from one commitment to another verified")
	}
	if !strings.Contains(res.Err().Error(), "does not cover this commitment's certificate") {
		t.Fatalf("finding does not name the imprint mismatch: %v", res.Err())
	}
}

// A record whose stored genTime disagrees with the token's is an edited row.
func TestVerifyDetectsAnEditedCommitmentDate(t *testing.T) {
	b, ts, ca := boundBundle(t, nil)
	b.Commitments[0].GenTime = b.Commitments[0].GenTime.Add(-48 * time.Hour)

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a commitment whose recorded date contradicts its token verified")
	}
	if !strings.Contains(res.Err().Error(), "the record was altered") {
		t.Fatalf("finding does not name the alteration: %v", res.Err())
	}
}

// A month-old binding leaves every signature since connected to the device by
// the CA's word alone, which is exactly the state the check exists to surface.
func TestVerifyRejectsAStaleBinding(t *testing.T) {
	b, ts, ca := boundBundle(t, func(tsa *testTSA) {
		tsa.now = func() time.Time { return time.Now().Add(-30 * 24 * time.Hour) }
	})
	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a month-old device binding passed")
	}
	if !res.Stale {
		t.Fatal("result does not report the binding as stale")
	}
	if !strings.Contains(res.Err().Error(), "the CA's word alone") {
		t.Fatalf("finding does not explain the consequence: %v", res.Err())
	}

	// A negative threshold reports the age without failing on it, for an auditor
	// deliberately examining an archived bundle.
	archived := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
		MaxAge:            -1,
	})
	if !archived.OK {
		t.Fatalf("a negative max-age did not disable the staleness check: %v", archived.Err())
	}
	if archived.Age < 29*24*time.Hour {
		t.Fatalf("reported age %s, want about 30 days", archived.Age)
	}
}

// The in-process TSA signs with the HSM under audit, so it cannot date a
// commitment against an operator holding that HSM. The binding still holds; only
// its date does not.
func TestInternalTSACommitmentIsFlaggedAndRejectable(t *testing.T) {
	b, ts, ca := boundBundle(t, func(tsa *testTSA) { tsa.source = "" })

	lenient := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if !lenient.OK {
		t.Fatalf("an internally dated commitment was rejected by default: %v", lenient.Err())
	}
	if lenient.IndependentTSA {
		t.Fatal("an in-process date was reported as independent")
	}
	if len(lenient.Notes) == 0 {
		t.Fatal("no note warns that the date is not independent")
	}

	strict := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy:     ca.policy(),
		TSARoots:              []*x509.Certificate{ts.root},
		RequireIndependentTSA: true,
	})
	if strict.OK {
		t.Fatal("-require-external-tsa accepted an in-process date")
	}
}

// Replaying an older binding at a later date would let an abandoned log look
// maintained, so the sequence must move forward on both chains and the clock.
func TestVerifyRejectsAReBoundEarlierHead(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	ctx := context.Background()
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "bb")
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Swap the two, so the later sequence number carries the earlier head. Both
	// certificates are genuine and both tokens are genuine; only the order they
	// are presented in is a lie, which is what a replay looks like.
	b.Commitments[0], b.Commitments[1] = b.Commitments[1], b.Commitments[0]
	b.Commitments[0].Seq, b.Commitments[1].Seq = 1, 2

	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if res.OK {
		t.Fatal("a re-bound earlier head verified")
	}
	if !strings.Contains(res.Err().Error(), "covers less history") {
		t.Fatalf("finding does not name the rewind: %v", res.Err())
	}
}

// A run of commitments over a growing history is the normal case and must not
// trip the sequence checks.
func TestVerifyAcceptsASequenceOfCommitments(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, ca, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Commit(ctx, ts); err != nil {
			t.Fatalf("commit %d: %v", i+1, err)
		}
		dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
		addLedger(t, store, attestedKeyID, fmt.Sprintf("%02x", i))
	}
	b, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyCommitments(b, CommitmentOptions{
		AttestationPolicy: ca.policy(),
		TSARoots:          []*x509.Certificate{ts.root},
	})
	if !res.OK {
		t.Fatalf("a genuine sequence of commitments was rejected: %v", res.Err())
	}
	if res.Verified != 3 {
		t.Fatalf("verified %d of %d commitments, want 3", res.Verified, res.Commitments)
	}
	// Signatures made after the newest binding are accounted for but not yet
	// bound, and the result has to say so rather than imply full coverage.
	if res.SignaturesSinceCommitment == 0 || len(res.Notes) == 0 {
		t.Fatalf("the trailing unbound signatures were not reported: since=%d notes=%v",
			res.SignaturesSinceCommitment, res.Notes)
	}
}

// --- continuation ---------------------------------------------------------

// Dropping a binding the CA already published would let it disown a stretch of
// history the device signed for.
func TestContinuationDetectsADroppedCommitment(t *testing.T) {
	first, _, _ := boundBundle(t, nil)
	second := *first
	second.Commitments = nil

	cont := VerifyContinuation(first, &second)
	if cont.OK {
		t.Fatal("an export that dropped a published commitment was accepted")
	}
	if !strings.Contains(cont.Err().Error(), "bindings were deleted") {
		t.Fatalf("finding does not name the deletion: %v", cont.Err())
	}
}

func TestContinuationDetectsAReplacedCommitment(t *testing.T) {
	first, ts, _ := boundBundle(t, nil)
	second := *first
	second.Commitments = append([]Commitment(nil), first.Commitments...)
	other := newFakeDeviceCA(t, "31650425")
	second.Commitments[0].CertificatePEM = other.attest(t,
		commitmentClaims("31650425", second.Commitments[0].ObjectID, second.Commitments[0].Label))
	redate(t, &second.Commitments[0], ts)

	cont := VerifyContinuation(first, &second)
	if cont.OK {
		t.Fatal("an export that replaced a published commitment was accepted")
	}
	if !strings.Contains(cont.Err().Error(), "a binding was replaced") {
		t.Fatalf("finding does not name the replacement: %v", cont.Err())
	}
}

// The normal case: a later export extends an earlier one and carries more
// bindings than it did.
func TestContinuationAcceptsAGrowingCommitmentSequence(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	ts := newTestTSA(t, "https://tsa.example/tsr")
	ctx := context.Background()

	if _, err := svc.Timestamp(ctx, ts); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	first, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}

	dev.entries = appendChain(dev.entries, signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "bb")
	if _, err := svc.Timestamp(ctx, ts); err != nil {
		t.Fatalf("second timestamp: %v", err)
	}
	if _, err := svc.Commit(ctx, ts); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	second, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}

	cont := VerifyContinuation(first, second)
	if !cont.OK {
		t.Fatalf("a genuine continuation was rejected: %v", cont.Err())
	}
	if cont.NewSignatures != 1 {
		t.Fatalf("reported %d new signature(s), want 1", cont.NewSignatures)
	}
}

// --- status and the runner ------------------------------------------------

func TestStatusReportsTheDeviceBinding(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	st, err := svc.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.CanCommit {
		t.Fatal("a service with a committer reports it cannot commit")
	}
	if st.Commitments != 0 || st.LastCommittedAt != nil {
		t.Fatal("status reports a binding before one was made")
	}

	ts := newTestTSA(t, "https://tsa.example/tsr")
	if _, err := svc.Commit(context.Background(), ts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	st, err = svc.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Commitments != 1 || st.LastCommittedAt == nil {
		t.Fatalf("status reports %d binding(s) at %v, want 1", st.Commitments, st.LastCommittedAt)
	}
}

// The runner has to commit at startup rather than waiting out the interval: a
// process restarting more often than the interval would otherwise never bind at
// all, while every other check kept reporting OK.
func TestCommitmentRunnerBindsAtStartup(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, _ := committed(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	ctx, cancel := context.WithCancel(context.Background())
	r := NewCommitmentRunner(svc, newTestTSA(t, "https://tsa.example/tsr"), time.Hour, discardLogger())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for {
		stored, err := store.Commitments(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) > 0 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("the runner made no commitment at startup")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// A failing device must not stop the loop: neither a TSA outage nor a busy HSM
// may take the CA down, and the staleness gauge plus the fail-closed verifier
// are what turn a persistent failure into a visible one.
func TestCommitmentRunnerSurvivesAFailingDevice(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store, _, com := committed(t, entries)
	com.err = errors.New("device busy")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	NewCommitmentRunner(svc, newTestTSA(t, "x"), 20*time.Millisecond, discardLogger()).Run(ctx)

	stored, err := store.Commitments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("a failing committer produced %d stored commitment(s)", len(stored))
	}
}
