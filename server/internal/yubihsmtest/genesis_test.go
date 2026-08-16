package yubihsmtest

// The genesis tier: what a factory reset actually writes, and what that means
// for the chain anchor an auditor is asked to pin.
//
// This is the hardware half of the evaluation in internal/hsmaudit/genesis.go.
// The question it answers is one every operator eventually asks — "why do I have
// to record this hash by hand; why can't the verifier just check the sentinel?"
// — and it can only be answered on a device, because it turns on where the
// digest of entry 1 comes from. That is not documented by Yubico, and their own
// SDK sidesteps it by starting verification at entry 2.
//
// These tests factory-reset the device repeatedly, so they are behind their own
// gate (SECSY_YUBIHSM_RESET=1) on top of the destructive one.

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// genesisResets is how many factory resets the observation runs over.
//
// Two would technically settle "the digest is not a function of the record".
// Three is the standing value because each reset is a real USB re-enumeration
// and that is the part of this test that can go wrong: on a host that reaches
// the device over USB/IP, a run of four resets in quick succession left the
// device failing to re-enumerate and the kernel's hub workqueue stuck, which no
// amount of care in Go can recover from. The recorded corpus in
// internal/hsmaudit/genesis.go is seven observations across two sittings; this
// adds to it rather than having to establish it alone.
const genesisResets = 3

// resetSettle is how long to leave the device alone after a reset before
// reaching for it again.
//
// Polling immediately is what a careful implementation would do, and it is
// wrong here: the device drops off the bus as it reboots, and probing during the
// window in which the host has not yet noticed produces a usbfs wait the kernel
// will not interrupt — at which point the test's context deadline is decoration.
// Waiting first, then polling, is what a hand-run reset loop does successfully.
const resetSettle = 5 * time.Second

// TestFactoryResetSentinelIsConstantButItsDigestIsNot is the measurement the
// whole anchor design rests on.
//
// It establishes two things that pull in opposite directions:
//
//   - The sentinel record is a *constant*. Every factory reset writes the same
//     sixteen hashed bytes, 0x0001 followed by fourteen 0xff. So publishing the
//     sentinel and hashing it could only ever produce one value, shared by every
//     YubiHSM on earth — which identifies nothing.
//   - The digest the device reports for those constant bytes is *different every
//     time*. So the digest is not a function of the record; the device folds in
//     something it chooses at reset and never discloses.
//
// Together they say the chain anchor cannot be made self-verifying: there is
// nothing to verify it against. It has to be pinned out of band, which is why
// `hsm-audit provision` prints it and tells the operator to write it down.
func TestFactoryResetSentinelIsConstantButItsDigestIsNot(t *testing.T) {
	requireReset(t)

	type observation struct {
		data   string
		digest string
		serial string
	}
	var seen []observation

	for i := 0; i < genesisResets; i++ {
		factoryReset(t)

		entry, serial := firstLogEntry(t)
		if !hsm.IsBootSentinel(entry) {
			t.Fatalf("reset %d: entry 1 is not a device-init sentinel: %+v", i+1, entry)
		}
		obs := observation{
			data:   hex.EncodeToString(hsm.EntryData(entry)),
			digest: strings.ToLower(entry.Hash),
			serial: serial,
		}
		t.Logf("reset %d: sentinel data %s, digest %s", i+1, obs.data, obs.digest)
		seen = append(seen, obs)
	}

	// 1. The record is a constant, and it is the one this build hard-codes.
	for i, obs := range seen {
		if obs.data != hsmaudit.SentinelPreimageHex {
			t.Errorf("reset %d wrote sentinel data %s, but this build expects %s",
				i+1, obs.data, hsmaudit.SentinelPreimageHex)
		}
		if obs.data != seen[0].data {
			t.Errorf("reset %d wrote sentinel data %s, reset 1 wrote %s: the record is not constant after all",
				i+1, obs.data, seen[0].data)
		}
	}

	// 2. The digest is not. If two resets ever agreed, the device would be
	// seeding its chain deterministically and every anchor would be a shared
	// constant — pinning one would prove nothing, and this test is the alarm.
	for i := range seen {
		for j := i + 1; j < len(seen); j++ {
			if seen[i].digest == seen[j].digest {
				t.Errorf("resets %d and %d produced the same anchor %s from identical records: "+
					"the genesis digest is deterministic, so it identifies no reset and pinning it is worthless",
					i+1, j+1, seen[i].digest)
			}
		}
	}

	// 3. And it is not reproducible from any predecessor an auditor could guess.
	// This is the check that would fire if a firmware started seeding from a
	// public value, which is the only way the "just hash the sentinel" idea
	// could ever become implementable — and the moment it would stop being
	// worth implementing.
	for i, obs := range seen {
		if name := hsmaudit.DerivableAnchor(obs.digest, obs.serial); name != "" {
			t.Errorf("reset %d's anchor %s is reproducible from public data (the %s seed): "+
				"this device's anchor carries no entropy", i+1, obs.digest, name)
		}
	}

	t.Logf("%d resets: one constant record, %d distinct anchors, none derivable — "+
		"the anchor must be pinned out of band", len(seen), len(seen))
}

// TestFactoryResetRestartsTheLog checks the other half of the genesis claim:
// that a reset really does clear the ring and restart the numbering, so a
// provisioned device's history genuinely begins at entry 1 with nothing before
// it. A reset that left older entries in place would mean the "no prior use"
// precondition `hsm-audit provision` enforces was checking the wrong thing.
func TestFactoryResetRestartsTheLog(t *testing.T) {
	requireReset(t)
	factoryReset(t)

	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			t.Fatalf("reading the log after a factory reset: %v", err)
		}
		if len(log.Entries) == 0 {
			t.Fatal("a factory reset left the log empty; it must write the device-init sentinel")
		}
		if log.Entries[0].Number != 1 {
			t.Errorf("the first entry after a reset is number %d, want 1: the counter did not restart",
				log.Entries[0].Number)
		}
		if log.UnloggedBoots != 0 || log.UnloggedAuthentications != 0 {
			t.Errorf("a freshly reset device already reports %d unlogged boot(s) and %d unlogged "+
				"authentication(s), so its log has holes before anything happened",
				log.UnloggedBoots, log.UnloggedAuthentications)
		}

		// Every entry must chain forward from the sentinel — the digest of entry
		// 1 excepted, which is the whole point of the test above.
		prev := append([]byte(nil), log.Entries[0].Digest[:]...)
		for _, e := range log.Entries[1:] {
			entry := toAuditEntry(e)
			want := hsm.ComputeEntryHash(entry, prev)
			if !strings.EqualFold(want, entry.Hash) {
				t.Fatalf("entry %d digest %s does not chain from its predecessor (computed %s)",
					e.Number, entry.Hash, want)
			}
			prev, _ = hex.DecodeString(strings.ToLower(entry.Hash))
		}
		t.Logf("reset left %d entr(ies), starting at the sentinel and chaining forward", len(log.Entries))
	})
}

// factoryReset wipes the device and waits for it to come back.
//
// The reset takes the USB connection down with it, so the reply is normally lost
// and the driver reports success on that specific transport failure; what
// follows is a re-enumeration the host needs a moment to notice. It settles
// first (see resetSettle) and only then polls for a session, rather than
// sleeping one fixed interval and hoping, so the wait adapts to the machine's
// USB stack without ever probing a device that is still off the bus.
func factoryReset(t *testing.T) {
	t.Helper()
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		if err := c.Reset(ctx); err != nil {
			t.Fatalf("factory-resetting the device: %v", err)
		}
	})

	// Let the reboot and the host's re-enumeration finish before probing; see
	// resetSettle.
	time.Sleep(resetSettle)

	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := yubihsm.Open(ctx, driverConfig())
		cancel()
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the device did not come back after a factory reset: %v\n"+
				"It may need a physical replug (or a USB/IP re-attach), and its authentication "+
				"key is now the factory default (id 1, password \"password\").", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// firstLogEntry reads entry 1 and the device serial without acknowledging
// anything, so the sentinel stays on the device.
func firstLogEntry(t *testing.T) (hsm.AuditLogEntry, string) {
	t.Helper()
	var entry hsm.AuditLogEntry
	var serial string
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			t.Fatalf("reading device info: %v", err)
		}
		serial = info.Serial
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			t.Fatalf("reading the device log: %v", err)
		}
		if len(log.Entries) == 0 {
			t.Fatal("the device log is empty right after a factory reset")
		}
		entry = toAuditEntry(log.Entries[0])
	})
	return entry, serial
}

// toAuditEntry converts a driver log record into the representation the audit
// package verifies, keeping the digest as lowercase hex the way the rest of the
// subsystem stores and transports it.
func toAuditEntry(e yubihsm.LogEntry) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Number: e.Number, Command: e.Command, Length: e.Length,
		SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
		Result: e.Result, Tick: e.Tick, Hash: hex.EncodeToString(e.Digest[:]),
	}
}
