package yubihsmtest

// Tier 4: the device audit log.
//
// The audit subsystem claims that a bundle exported from this device accounts
// for every signature the device produced. That claim has two halves, and only
// one of them is about software: the collector has to store what the device
// reports, and the device has to report everything. This tier is where the
// second half is checked, because it depends on device behaviour that no
// software token has — a 62-entry ring, a per-command audit configuration that
// can be made irreversible, and a refusal to operate once the ring is full.
//
// The 62-entry ring is the interesting constraint. It is small enough that a
// busy CA laps it in minutes, so "collect often enough" is not a tuning
// preference but the difference between a complete audit trail and a broken
// one.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// TestAuditConfigurationMeetsTheBaseline checks that this device is configured
// so that a complete audit trail is even possible.
//
// It is a readiness check rather than a code test: a device whose signing
// commands are not force-audited will happily sign without recording it, and
// every bundle exported from it would be honest about a log that was never
// written. Running it here means an operator learns that from the test suite
// rather than from an auditor.
func TestAuditConfigurationMeetsTheBaseline(t *testing.T) {
	requireDevice(t)
	ctx := testContext(t)

	dev := hsmaudit.NewHardwareDevice(hsmConfig())
	opts, err := dev.Options(ctx)
	if err != nil {
		t.Fatalf("reading audit options: %v", err)
	}

	t.Logf("force-audit = %s", opts.ForceAudit)
	required := opts.RequiredForced()
	var missing []uint8
	for _, cmd := range required {
		if opts.CommandAudit[cmd] != hsmaudit.AuditFixed {
			missing = append(missing, cmd)
		}
	}
	if err := opts.Verify(); err != nil {
		t.Errorf("this device cannot guarantee a complete audit trail: %v", err)
		for _, cmd := range missing {
			t.Errorf("  command 0x%02x (%s) is at audit level %s, want fixed",
				cmd, hsm.AllCommands[cmd], opts.CommandAudit[cmd])
		}
		t.Log("run: secsy-ca hsm-audit provision")
		return
	}
	t.Logf("all %d required commands are force-audited at level fixed", len(required))
}

// TestProvisionForcedAudit commissions a device that has not been provisioned.
//
// It is the one operation in this suite that cannot be undone: setting the
// per-command audit levels to "fixed" survives every power cycle, and the only
// way back is a factory reset that destroys every key on the device. Hence the
// separate gate — an operator who said "run the hardware tests" has not thereby
// said "permanently reconfigure this HSM".
//
// On an already-provisioned device it skips, which is the common case; it exists
// so that a fresh device can be taken from factory state to audit-complete and
// checked, rather than that path being exercised only in production.
func TestProvisionForcedAudit(t *testing.T) {
	requireDestructive(t)
	ctx := testContext(t)

	dev := hsmaudit.NewHardwareDevice(hsmConfig())
	before, err := dev.Options(ctx)
	if err != nil {
		t.Fatalf("reading audit options: %v", err)
	}
	if before.Verify() == nil {
		t.Skip("this device is already provisioned for complete auditing; nothing to do")
	}

	// Provision exactly the set this firmware requires, which is what
	// `secsy-ca hsm-audit provision` does; hard-coding a list would silently
	// under-provision a newer device.
	report, err := hsm.ProvisionAuditLogging(ctx, hsmConfig(), before.RequiredForced())
	if err != nil {
		t.Fatalf("provisioning audit logging: %v", err)
	}
	t.Logf("provisioned: %s", report)

	after, err := dev.Options(ctx)
	if err != nil {
		t.Fatalf("re-reading audit options: %v", err)
	}
	if err := after.Verify(); err != nil {
		t.Fatalf("the device still cannot guarantee a complete audit trail after provisioning: %v", err)
	}
	if after.ForceAudit != hsmaudit.AuditFixed {
		t.Errorf("force-audit is %s after provisioning, want fixed", after.ForceAudit)
	}
	t.Log("device is now audit-complete, irreversibly")
}

// TestForcedAuditCannotBeDowngraded tries to lower an audit setting the device
// has fixed.
//
// "Fixed" is the whole point of the provisioning step: it means an operator who
// later gains full access to the device still cannot turn logging off and sign
// unobserved. If the device accepted the downgrade, every audit bundle would be
// worth exactly as much as the honesty of whoever holds the authentication key.
//
// The attempt is safe to make unconditionally: it must fail, and a device that
// accepted it was never protecting anything.
func TestForcedAuditCannotBeDowngraded(t *testing.T) {
	requireDevice(t)
	c, ctx := client(t)

	before, err := c.GetOption(ctx, yubihsm.OptionForceAudit)
	if err != nil {
		t.Fatalf("reading the force-audit option: %v", err)
	}
	if len(before) != 1 || before[0] != byte(hsmaudit.AuditFixed) {
		t.Skipf("force-audit is %x, not fixed; nothing to downgrade (run: secsy-ca hsm-audit provision)", before)
	}

	// Ask for "on", a strictly weaker setting than "fixed".
	err = c.PutOption(ctx, yubihsm.OptionForceAudit, []byte{byte(hsmaudit.AuditOn)})
	if err == nil {
		t.Fatal("the device downgraded force-audit from fixed to on; the irreversibility guarantee does not hold")
	}
	var devErr yubihsm.DeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("want a device refusal, got %T: %v", err, err)
	}
	t.Logf("downgrade refused as expected: %v", devErr)

	after, err := c.GetOption(ctx, yubihsm.OptionForceAudit)
	if err != nil {
		t.Fatalf("re-reading the force-audit option: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the refused write still changed the option: %x then %x", before, after)
	}
}

// TestSignaturesAppearInTheLogAgainstTheirKey checks that a signature is
// recorded against the handle that made it.
//
// The audit subsystem attributes signatures to keys through the target_key
// field, and the attestation tier binds a handle to a public key. If the device
// recorded signatures without naming the key, an auditor could count operations
// but never say *which* key performed them — which is the difference between
// Task 167's claim and Task 170's.
func TestSignaturesAppearInTheLogAgainstTheirKey(t *testing.T) {
	// On an uncommissioned device every audit level is off and nothing at all is
	// logged, so without this the test would report that the device records no
	// signatures — which says nothing about the device and everything about how
	// it was configured. See requireAuditedCommands.
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA, hsm.CmdDeleteObject)
	keepLogSpace(t, 20)
	c, ctx := client(t)

	// Start from a known position so only this test's operations are in view.
	tail := drainToTail(t, ctx, c)

	id := generateScratch(t, c, ctx, scratchID(0), "audit-sign", algECP256, "sign-ecdsa")

	const signatures = 5
	digest := sha256.Sum256([]byte("audited signature"))
	for i := 0; i < signatures; i++ {
		if _, err := c.SignECDSA(ctx, id, digest[:]); err != nil {
			t.Fatalf("signature %d: %v", i+1, err)
		}
	}

	log, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	entries := convertEntries(log.Entries)

	// The segment must continue the chain from where the drain left it.
	seg := hsmaudit.VerifySegment(entries, &tail, hsmaudit.Unlogged{
		Boots: log.UnloggedBoots, Authentications: log.UnloggedAuthentications})
	if !seg.OK {
		t.Fatalf("the segment does not verify: %v", seg.Problems)
	}

	var signed, generated int
	for _, e := range entries {
		if e.TargetKey != id {
			continue
		}
		switch e.Command {
		case hsm.CmdSignECDSA:
			signed++
		case hsm.CmdGenerateAsymmetricKey:
			generated++
		}
	}
	if signed != signatures {
		t.Errorf("the log records %d signatures against key 0x%04x, want %d", signed, id, signatures)
	}
	if generated != 1 {
		t.Errorf("the log records %d generate operations for key 0x%04x, want 1", generated, id)
	}
	t.Logf("segment of %d entries verified; %d signatures attributed to key 0x%04x",
		seg.Count, signed, id)
}

// TestCollectionSurvivesMoreEntriesThanTheLogHolds is the ring-buffer test.
//
// The device log holds 62 entries. A collector that drains it must produce one
// continuous chain across many drains, and the seam between drains is where a
// mistake lives: an off-by-one in the acknowledged index either skips an entry
// (a gap, which breaks the chain) or re-reads one (a duplicate, which breaks
// the digest). Neither shows up in a run that never fills the ring, which is
// why this test deliberately produces more than 62 audited operations.
func TestCollectionSurvivesMoreEntriesThanTheLogHolds(t *testing.T) {
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA, hsm.CmdDeleteObject)
	keepLogSpace(t, 10)

	store := hsmaudit.NewMemStore()
	dev := hsmaudit.NewHardwareDevice(hsmConfig())
	collector := hsmaudit.NewCollector(dev, store, 0, nil)
	ctx := testContext(t)

	// Anchor the store at the device's current position: this test verifies
	// continuity of what it collects, not the device's whole history.
	var tail hsmaudit.Tail
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		tail = drainToTail(t, ctx, c)
	})
	info, err := dev.Info(ctx)
	if err != nil {
		t.Fatalf("reading device info: %v", err)
	}
	if err := store.SaveAuditState(ctx, &hsmaudit.AuditState{
		DeviceSerial: info.Serial, Anchor: tail.Digest, Tail: tail,
	}); err != nil {
		t.Fatalf("seeding the audit state: %v", err)
	}

	// Produce well over one ring's worth of audited operations in batches, with
	// a collection between each. The batch size stays under the ring depth so
	// that nothing is lost to overflow: the point is the seam between drains,
	// not the overflow behaviour, which TestFullLogStopsTheDevice covers.
	//
	// Signing and collecting take turns rather than interleaving because the
	// device admits one session at a time over direct USB — which is also why a
	// deployment that signs through PKCS#11 collects through a connector.
	const (
		batches   = 3
		perBatch  = hsmaudit.MaxLogEntries / 2
		wantTotal = batches * perBatch
	)
	var collected, signaturesSeen int
	digest := sha256.Sum256([]byte("ring buffer"))
	keyID := scratchID(1)

	withClient(t, func(sctx context.Context, c *yubihsm.Client) {
		deleteScratch(sctx, c, keyID)
		if _, err := c.GenerateAsymmetricKey(sctx, yubihsm.KeySpec{
			ID: keyID, Label: label("audit-ring"), Domains: 1,
			Capabilities: capabilities(t, "sign-ecdsa"), Algorithm: algECP256,
		}); err != nil {
			t.Fatalf("generating the signing key: %v", err)
		}
	})
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) { deleteScratch(ctx, c, keyID) })
	})

	for b := 0; b < batches; b++ {
		withClient(t, func(sctx context.Context, c *yubihsm.Client) {
			for i := 0; i < perBatch; i++ {
				if _, err := c.SignECDSA(sctx, keyID, digest[:]); err != nil {
					t.Fatalf("batch %d signature %d: %v", b+1, i+1, err)
				}
			}
		})
		res, err := collector.Collect(ctx)
		if err != nil {
			t.Fatalf("collecting after batch %d: %v", b+1, err)
		}
		assertCollected(t, res)
		collected += res.Collected
		signaturesSeen += res.Signatures
		t.Logf("batch %d: collected %d entries (%d signatures), log at %s",
			b+1, res.Collected, res.Signatures, res.LogUsed)
	}

	if signaturesSeen < wantTotal {
		t.Errorf("collected %d signatures across the run, want at least %d — entries were lost at a drain seam",
			signaturesSeen, wantTotal)
	}
	if collected <= hsmaudit.MaxLogEntries {
		t.Errorf("collected only %d entries, which fits in one %d-entry ring; "+
			"the test did not exercise a drain seam", collected, hsmaudit.MaxLogEntries)
	}

	// The stored entries must form one unbroken chain from the seed tail: this
	// is the property the seams could have broken.
	stored, err := store.LogEntries(ctx)
	if err != nil {
		t.Fatalf("reading stored entries: %v", err)
	}
	seg := hsmaudit.VerifySegment(stored, &tail, hsmaudit.Unlogged{})
	if !seg.OK {
		t.Fatalf("the %d collected entries do not form a continuous chain: %v", len(stored), seg.Problems)
	}
	t.Logf("collected %d entries (%d signatures) across %d drains; chain continuous from #%d to #%d",
		collected, signaturesSeen, batches, seg.First, seg.Last)
}

// assertCollected fails on a collection cycle that reported a broken segment.
func assertCollected(t *testing.T, res *hsmaudit.CollectResult) {
	t.Helper()
	if res.Segment != nil && !res.Segment.OK {
		t.Fatalf("collection cycle reported a broken segment: %v", res.Segment.Problems)
	}
}

// TestFullLogStopsTheDevice is the fail-closed property, and it is the reason
// forced audit is worth configuring at all.
//
// With force-audit set, a device whose log is full must refuse audited
// operations rather than continue and drop the records. The alternative — sign
// now, log later, never — would mean an attacker could fill the log with noise
// and then sign invisibly. This test fills the ring deliberately and checks the
// device stops.
func TestFullLogStopsTheDevice(t *testing.T) {
	// The fill has to be made of audited operations, and force-audit has to be
	// on for a full log to block rather than overwrite — neither of which is
	// true of a device out of the box.
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA, hsm.CmdDeleteObject)
	c, ctx := client(t)

	force, err := c.GetOption(ctx, yubihsm.OptionForceAudit)
	if err != nil {
		t.Fatalf("reading the force-audit option: %v", err)
	}
	if len(force) != 1 || force[0] == byte(hsmaudit.AuditOff) {
		t.Skip("force-audit is off, so a full log is expected to overwrite rather than block")
	}

	// Whatever happens below, leave the device usable.
	t.Cleanup(func() {
		log, err := c.GetLogEntries(ctx)
		if err != nil || len(log.Entries) == 0 {
			return
		}
		last := log.Entries[len(log.Entries)-1].Number
		if err := c.SetLogIndex(ctx, last); err != nil {
			t.Errorf("could not drain the audit log afterwards; the device may refuse "+
				"audited operations until it is drained: %v", err)
			return
		}
		t.Logf("drained the log up to #%d, device usable again", last)
	})

	drainToTail(t, ctx, c)
	id := generateScratch(t, c, ctx, scratchID(2), "audit-full", algECP256, "sign-ecdsa")

	// Sign until the device refuses. It must refuse before unboundedly many
	// signatures: the ring is 62 deep and the key generation already used one.
	digest := sha256.Sum256([]byte("filling the log"))
	limit := hsmaudit.MaxLogEntries * 2
	var made int
	var refusal error
	for i := 0; i < limit; i++ {
		if _, err := c.SignECDSA(ctx, id, digest[:]); err != nil {
			refusal = err
			break
		}
		made++
	}
	if refusal == nil {
		t.Fatalf("the device produced %d signatures without ever filling its %d-entry log; "+
			"entries are being dropped rather than blocking", made, hsmaudit.MaxLogEntries)
	}
	var devErr yubihsm.DeviceError
	if !errors.As(refusal, &devErr) {
		t.Fatalf("want a device refusal once the log filled, got %T: %v", refusal, refusal)
	}
	if made >= hsmaudit.MaxLogEntries {
		t.Errorf("the device accepted %d signatures before refusing, more than its %d-entry log holds",
			made, hsmaudit.MaxLogEntries)
	}
	t.Logf("device refused after %d signatures with %v — audited operations fail closed on a full log",
		made, devErr)
}

// drainToTail acknowledges everything pending and returns the resulting
// position, so a test can reason about a window it fully controls.
//
// A drained log holds no entries, and an entry is exactly what a tail is: a
// number and the device's chain digest at that point. So the drain is preceded
// by one deliberately failing signature against a handle this suite reserves
// and never provisions. The device logs attempted operations, not just
// successful ones — which is itself a property worth asserting, since an audit
// trail that recorded only successes would hide every probe of a key an
// attacker does not have — so that failure leaves exactly one entry to anchor
// on and nothing else behind.
func drainToTail(t *testing.T, ctx context.Context, c *yubihsm.Client) hsmaudit.Tail {
	t.Helper()

	if log, err := c.GetLogEntries(ctx); err == nil && len(log.Entries) > 0 {
		if err := c.SetLogIndex(ctx, log.Entries[len(log.Entries)-1].Number); err != nil {
			t.Fatalf("draining the audit log: %v", err)
		}
	}

	digest := sha256.Sum256([]byte("audit anchor"))
	if _, err := c.SignECDSA(ctx, scratchTop, digest[:]); err == nil {
		t.Fatalf("signing with handle 0x%04x succeeded; the suite reserves it as unprovisioned", scratchTop)
	}

	log, err := c.GetLogEntries(ctx)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	if len(log.Entries) == 0 {
		t.Fatal("the device did not log a failed signing attempt; " +
			"an audit trail that records only successes cannot be complete")
	}
	entries := convertEntries(log.Entries)
	last := entries[len(entries)-1]
	if err := c.SetLogIndex(ctx, last.Number); err != nil {
		t.Fatalf("acknowledging entries up to #%d: %v", last.Number, err)
	}
	return hsmaudit.Tail{Number: last.Number, Digest: last.Hash}
}

// convertEntries maps driver records to the audit package's representation.
// The digest is the device's own chain value, carried as lowercase hex.
func convertEntries(in []yubihsm.LogEntry) []hsm.AuditLogEntry {
	out := make([]hsm.AuditLogEntry, 0, len(in))
	for _, e := range in {
		out = append(out, hsm.AuditLogEntry{
			Number:     e.Number,
			Command:    e.Command,
			Length:     e.Length,
			SessionKey: e.SessionKey,
			TargetKey:  e.TargetKey,
			SecondKey:  e.SecondKey,
			Result:     e.Result,
			Tick:       e.Tick,
			Hash:       hex.EncodeToString(e.Digest[:]),
		})
	}
	return out
}
