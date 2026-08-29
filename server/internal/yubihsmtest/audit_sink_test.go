package yubihsmtest

// Tier 4b: where the drained entries end up.
//
// audit_test.go establishes that the device records what it does and that the
// collector can follow the ring across drains. This file asks the next
// question, which is the one an auditor actually asks: after the ring has been
// acknowledged — irreversibly, the device keeping no copy — who still holds
// those records, and can they be shown to be unaltered?
//
// Two answers have to hold at once. The database is the copy the running system
// uses, and the append-only file is the copy the operator of the database
// cannot quietly shorten. Both are written before the device is acknowledged,
// so this tier checks the same operations against both, and then verifies the
// file with nothing but the file.
//
// It also checks the half that no software-only test can: that *every* kind of
// operation prompts a drain. Signing goes through the key provider, which
// announces itself. Attestation, key generation on the native path, option
// changes and the audit-head commitments do not — they reach the device through
// the driver, and on a force-audited device each of them writes a log entry
// that something has to collect before the ring fills and the HSM stops.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// auditedForThisTier are the commands these tests need the device to record.
//
// They are exactly the commands the tests issue and nothing more: turning on
// auditing for a command the test does not use would add entries from whatever
// else touches the device during the run, and the assertions here are about
// entry-for-operation correspondence.
var auditedForThisTier = []byte{
	hsm.CmdGenerateAsymmetricKey,
	hsm.CmdSignECDSA,
	hsm.CmdSignEdDSA,
	hsm.CmdDeleteObject,
	0x64, // SIGN ATTESTATION CERTIFICATE
}

// requireAuditedCommands makes sure the device records cmds, and restores
// whatever it changed when the test ends.
//
// A YubiHSM leaves the factory with force-audit off and every per-command audit
// level off, so on an uncommissioned device nothing at all is logged and a test
// about the audit log has nothing to look at. `hsm-audit provision` fixes that
// permanently — level 0x02, irreversible until a factory reset — which is right
// for a production device and much too strong for a test run.
//
// Level 0x01 ("on") produces the same log entries and can be set back, so that
// is what this uses. The difference is only whether an operator holding the
// authentication key could turn it off again, which is a property of a
// production device rather than of the code under test. Anything already at
// "fixed" is left alone: it is already stronger than what is being asked for,
// and it could not be restored afterwards anyway.
func requireAuditedCommands(t *testing.T, cmds ...byte) {
	t.Helper()
	requireDevice(t)

	type change struct {
		cmd, previous byte
	}
	var (
		changes      []change
		prevForce    byte
		forceChanged bool
	)

	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		force, err := c.GetOption(ctx, yubihsm.OptionForceAudit)
		if err != nil || len(force) != 1 {
			t.Fatalf("reading the force-audit option: %v", err)
		}
		levels, err := c.GetOption(ctx, yubihsm.OptionCommandAudit)
		if err != nil {
			t.Fatalf("reading the command-audit option: %v", err)
		}
		current := map[byte]byte{}
		for i := 0; i+1 < len(levels); i += 2 {
			current[levels[i]] = levels[i+1]
		}

		for _, cmd := range cmds {
			level, present := current[cmd]
			if !present {
				t.Fatalf("the device reports no audit setting for command 0x%02x (%s)", cmd, hsm.AllCommands[cmd])
			}
			if level != 0x00 {
				continue // already on or fixed
			}
			if err := c.PutOption(ctx, yubihsm.OptionCommandAudit, []byte{cmd, 0x01}); err != nil {
				t.Fatalf("enabling auditing for command 0x%02x: %v", cmd, err)
			}
			changes = append(changes, change{cmd: cmd, previous: level})
		}

		if force[0] == 0x00 {
			if err := c.PutOption(ctx, yubihsm.OptionForceAudit, []byte{0x01}); err != nil {
				t.Fatalf("enabling force-audit: %v", err)
			}
			prevForce, forceChanged = force[0], true
		}
	})

	if len(changes) == 0 && !forceChanged {
		t.Log("the device already audits every command this tier uses; nothing to change")
		return
	}
	t.Logf("temporarily enabled auditing for %d command(s)%s; it will be restored when this test ends",
		len(changes), map[bool]string{true: " and force-audit", false: ""}[forceChanged])

	t.Cleanup(func() {
		// A fresh session: the test's own may be long gone, and leaving the
		// device force-auditing commands nobody drains would eventually stop it
		// serving anything at all.
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		c, err := yubihsm.Open(ctx, driverConfig())
		if err != nil {
			t.Errorf("could not restore the device audit options (%v); "+
				"force-audit and %d command level(s) are still raised — "+
				"run `secsy-ca hsm-audit status` and set them back", err, len(changes))
			return
		}
		defer func() { _ = c.Close() }()
		if forceChanged {
			if err := c.PutOption(ctx, yubihsm.OptionForceAudit, []byte{prevForce}); err != nil {
				t.Errorf("restoring force-audit to 0x%02x: %v", prevForce, err)
			}
		}
		for _, ch := range changes {
			if err := c.PutOption(ctx, yubihsm.OptionCommandAudit, []byte{ch.cmd, ch.previous}); err != nil {
				t.Errorf("restoring the audit level of command 0x%02x to 0x%02x: %v", ch.cmd, ch.previous, err)
			}
		}
	})
}

// auditSinks is a collector wired to both durable destinations, anchored at the
// device's current position.
type auditSinks struct {
	collector *hsmaudit.Collector
	db        *database.DB
	filePath  string
	serial    string
	start     hsmaudit.Tail
}

// newAuditSinks drains the device to a known position and pins a collection
// state there, then returns a collector writing to a real database and a real
// append-only file.
//
// It anchors at "now" rather than at the device-init sentinel because this tier
// is about what happens to entries after they are drained, not about the
// device's whole history — genesis_test.go covers that, and it needs a factory
// reset to do it.
func newAuditSinks(t *testing.T) *auditSinks {
	t.Helper()
	ctx := testContext(t)

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Skipf("this tier needs a database; build with -tags sqlite (%v)", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	dev := hsmaudit.NewHardwareDevice(hsmConfig())
	info, err := dev.Info(ctx)
	if err != nil {
		t.Fatalf("reading device info: %v", err)
	}

	var tail hsmaudit.Tail
	withClient(t, func(sctx context.Context, c *yubihsm.Client) {
		tail = drainToTail(t, sctx, c)
	})
	if err := db.SaveAuditState(ctx, &hsmaudit.AuditState{
		DeviceSerial:  info.Serial,
		Anchor:        tail.Digest,
		ProvisionedAt: time.Now().UTC(),
		Tail:          tail,
	}); err != nil {
		t.Fatalf("pinning the audit state: %v", err)
	}

	path := filepath.Join(t.TempDir(), "hsm-audit.jsonl")
	f, err := hsmaudit.OpenLogFile(path)
	if err != nil {
		t.Fatalf("opening the append-only log file: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	collector := hsmaudit.NewCollector(dev, db, time.Minute, nil)
	collector.AddSink(f)
	return &auditSinks{collector: collector, db: db, filePath: path, serial: info.Serial, start: tail}
}

// collect runs one drain cycle and fails the test on a broken segment.
func (s *auditSinks) collect(t *testing.T, why string) *hsmaudit.CollectResult {
	t.Helper()
	res, err := s.collector.Collect(testContext(t))
	if err != nil {
		t.Fatalf("collecting after %s: %v", why, err)
	}
	assertCollected(t, res)
	return res
}

// entries returns what the database holds beyond the anchor position.
func (s *auditSinks) entries(t *testing.T) []hsm.AuditLogEntry {
	t.Helper()
	all, err := s.db.LogEntries(testContext(t))
	if err != nil {
		t.Fatalf("reading stored entries: %v", err)
	}
	return all
}

// commandCounts tallies successful entries by command byte.
func commandCounts(entries []hsm.AuditLogEntry) map[byte]int {
	out := map[byte]int{}
	for _, e := range entries {
		if e.Result == e.Command|0x80 {
			out[e.Command]++
		}
	}
	return out
}

// TestOperationsReachBothTheDatabaseAndTheAppendOnlyFile runs a spread of
// device operations and checks that each one's log entry ends up in both
// durable copies, and that the file verifies on its own.
//
// The operations are deliberately varied. A test that only signs would pass
// against a collector wired to the signing path alone — which is precisely the
// gap this task closes, since key generation, attestation and deletion are all
// force-audited and none of them is a signature.
func TestOperationsReachBothTheDatabaseAndTheAppendOnlyFile(t *testing.T) {
	requireAuditedCommands(t, auditedForThisTier...)
	keepLogSpace(t, 20)

	sinks := newAuditSinks(t)
	keyID := scratchID(2)
	edID := scratchID(3)
	digest := sha256.Sum256([]byte("audit sink tier"))

	// Each step runs its device work in a session of its own and then drains,
	// because over direct USB the device admits one session at a time — the
	// collector cannot open its own while the test holds one. A deployment that
	// signs through PKCS#11 and collects through the driver reaches the device
	// through a connector for exactly this reason.
	steps := []struct {
		name string
		want byte
		run  func(ctx context.Context, c *yubihsm.Client)
	}{
		{
			name: "generate an ECDSA key",
			want: hsm.CmdGenerateAsymmetricKey,
			run: func(ctx context.Context, c *yubihsm.Client) {
				deleteScratch(ctx, c, keyID)
				if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
					ID: keyID, Label: label("sink-ec"), Domains: 1,
					Capabilities: capabilities(t, "sign-ecdsa", "exportable-under-wrap"),
					Algorithm:    algECP256,
				}); err != nil {
					t.Fatalf("generating the ECDSA key: %v", err)
				}
			},
		},
		{
			name: "sign with it",
			want: hsm.CmdSignECDSA,
			run: func(ctx context.Context, c *yubihsm.Client) {
				if _, err := c.SignECDSA(ctx, keyID, digest[:]); err != nil {
					t.Fatalf("signing: %v", err)
				}
			},
		},
		{
			name: "attest it",
			want: 0x64,
			run: func(ctx context.Context, c *yubihsm.Client) {
				if _, err := c.AttestAsymmetricKey(ctx, keyID, 0); err != nil {
					t.Fatalf("attesting the key: %v", err)
				}
			},
		},
		{
			name: "generate an Ed25519 key",
			want: hsm.CmdGenerateAsymmetricKey,
			run: func(ctx context.Context, c *yubihsm.Client) {
				deleteScratch(ctx, c, edID)
				if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
					ID: edID, Label: label("sink-ed"), Domains: 1,
					Capabilities: capabilities(t, "sign-eddsa"), Algorithm: algEd25519,
				}); err != nil {
					t.Fatalf("generating the Ed25519 key: %v", err)
				}
			},
		},
		{
			name: "sign with EdDSA",
			want: hsm.CmdSignEdDSA,
			run: func(ctx context.Context, c *yubihsm.Client) {
				if _, err := c.SignEdDSA(ctx, edID, []byte("audit sink tier")); err != nil {
					t.Fatalf("signing with EdDSA: %v", err)
				}
			},
		},
		{
			name: "delete a key",
			want: hsm.CmdDeleteObject,
			run: func(ctx context.Context, c *yubihsm.Client) {
				if err := c.DeleteObject(ctx, edID, yubihsm.ObjectTypeAsymmetricKey); err != nil {
					t.Fatalf("deleting the Ed25519 key: %v", err)
				}
			},
		},
	}
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) {
			deleteScratch(ctx, c, keyID)
			deleteScratch(ctx, c, edID)
		})
	})

	for _, step := range steps {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) { step.run(ctx, c) })

		before := len(sinks.entries(t))
		res := sinks.collect(t, step.name)
		stored := sinks.entries(t)
		if len(stored) <= before {
			t.Fatalf("%s: the drain stored nothing, so the entry it produced is only on the device", step.name)
		}
		if counts := commandCounts(stored[before:]); counts[step.want] == 0 {
			t.Errorf("%s: no successful 0x%02x (%s) entry among the %d newly stored, got %v",
				step.name, step.want, hsm.AllCommands[step.want], len(stored)-before, counts)
		}
		t.Logf("%-24s collected %d entr(ies), device log %s", step.name+":", res.Collected, res.LogUsed)
	}

	// Both copies, same records. This is the property the whole tier exists for:
	// the append-only file is only worth having if it holds what the database
	// holds, entry for entry and digest for digest.
	stored := sinks.entries(t)
	fileRes, err := hsmaudit.VerifyLogFile(sinks.filePath)
	if err != nil {
		t.Fatalf("verifying the append-only file: %v", err)
	}
	if err := fileRes.Err(); err != nil {
		t.Fatalf("the append-only file does not verify: %v", err)
	}
	if fileRes.Device != sinks.serial {
		t.Errorf("the file names device %q, the device is %q", fileRes.Device, sinks.serial)
	}
	if fileRes.Entries != len(stored) {
		t.Errorf("the file holds %d entries and the database %d: the two copies disagree",
			fileRes.Entries, len(stored))
	}
	if last := stored[len(stored)-1]; fileRes.Tail.Number != last.Number ||
		!strings.EqualFold(fileRes.Tail.Digest, last.Hash) {
		t.Errorf("the file ends at entry %d (%s), the database at %d (%s)",
			fileRes.Tail.Number, fileRes.Tail.Digest, last.Number, last.Hash)
	}
	// One documented gap: this file was opened partway through the device's
	// life, and it says so rather than presenting a suffix as a whole history.
	if fileRes.FromGenesis {
		t.Error("the file claims to start at a factory reset; it was anchored at the device's current position")
	}
	if len(fileRes.Gaps) != 1 || fileRes.Gaps[0].Before != sinks.start.Number+1 {
		t.Errorf("expected exactly one documented gap at entry %d, got %+v", sinks.start.Number+1, fileRes.Gaps)
	}
	t.Logf("%d entries in both the database and %s; file verified independently (%d signature(s))",
		fileRes.Entries, filepath.Base(sinks.filePath), fileRes.Signatures)
}

// TestEveryDriverCommandPromptsADrain checks the notification half.
//
// The collector cannot drain after an operation it never hears about, and the
// operations most likely to go unheard are the ones that do not pass a key
// provider: attestation, key generation on the native path, deletions. This
// asserts the driver announces each of them — and stays quiet about the three
// commands the drain itself issues, which would otherwise have every drain ask
// for another drain.
func TestEveryDriverCommandPromptsADrain(t *testing.T) {
	requireDevice(t)

	var (
		mu       sync.Mutex
		announce []byte
	)
	yubihsm.SetCommandObserver(func(cmd byte) {
		mu.Lock()
		defer mu.Unlock()
		announce = append(announce, cmd)
	})
	t.Cleanup(func() { yubihsm.SetCommandObserver(nil) })

	keyID := scratchID(4)
	digest := sha256.Sum256([]byte("drain prompt"))
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		deleteScratch(ctx, c, keyID)
		if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
			ID: keyID, Label: label("drain-prompt"), Domains: 1,
			Capabilities: capabilities(t, "sign-ecdsa", "exportable-under-wrap"), Algorithm: algECP256,
		}); err != nil {
			t.Fatalf("generating: %v", err)
		}
		if _, err := c.SignECDSA(ctx, keyID, digest[:]); err != nil {
			t.Fatalf("signing: %v", err)
		}
		if _, err := c.AttestAsymmetricKey(ctx, keyID, 0); err != nil {
			t.Fatalf("attesting: %v", err)
		}
		if _, err := c.GetPseudoRandom(ctx, 16); err != nil {
			t.Fatalf("random: %v", err)
		}
		if err := c.DeleteObject(ctx, keyID, yubihsm.ObjectTypeAsymmetricKey); err != nil {
			t.Fatalf("deleting: %v", err)
		}
		// The drain's own commands, which must not be announced back to it.
		if _, err := c.DeviceInfo(ctx); err != nil {
			t.Fatalf("device info: %v", err)
		}
		if _, err := c.GetLogEntries(ctx); err != nil {
			t.Fatalf("get log entries: %v", err)
		}
	})

	mu.Lock()
	seen := append([]byte{}, announce...)
	mu.Unlock()

	count := func(cmd byte) int {
		n := 0
		for _, c := range seen {
			if c == cmd {
				n++
			}
		}
		return n
	}
	for _, cmd := range []byte{
		hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA, 0x64, 0x51, hsm.CmdDeleteObject,
	} {
		if count(cmd) == 0 {
			t.Errorf("command 0x%02x (%s) reached the device without prompting a drain; "+
				"on a force-audited device its log entry would sit in the volatile ring",
				cmd, hsm.AllCommands[cmd])
		}
	}
	for _, cmd := range []byte{0x06 /* GET DEVICE INFO */, 0x4d /* GET LOG ENTRIES */, 0x67 /* SET LOG INDEX */} {
		if count(cmd) != 0 {
			t.Errorf("the drain's own command 0x%02x (%s) was announced back to it, which would drain in a loop",
				cmd, hsm.AllCommands[cmd])
		}
	}
	t.Logf("%d device command(s) announced: %x", len(seen), seen)
}

// TestProviderOperationsAreDrainedToBothSinks runs the product's own signing
// path — PKCS#11 through keyprovider — and checks that what it does reaches
// both copies.
//
// The tier above uses the native driver, which is not how the CA signs. The
// module is a separate implementation with its own session handling, and the
// recording wrapper that announces its operations sits at a different layer, so
// neither the entries nor the notifications are covered by testing the driver.
func TestProviderOperationsAreDrainedToBothSinks(t *testing.T) {
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA)
	keepLogSpace(t, 12)

	sinks := newAuditSinks(t)
	ctx := testContext(t)

	recorder, err := hsmaudit.EnableRecording(ctx, sinks.db)
	if err != nil {
		t.Fatalf("enabling signature-ledger recording: %v", err)
	}
	if recorder == nil {
		t.Fatal("recording is off although the audit state was just pinned")
	}

	var drains atomic.Int64
	lbl := label("sink-p11")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	// The provider is closed before the drain: the module holds the USB
	// interface for as long as it has a session, and the collector reaches the
	// same device through the native driver.
	func() {
		p := keyprovider.Record(provider(t), recorder, keyprovider.OnOperation(func() { drains.Add(1) }))
		defer func() { _ = p.Close() }()

		if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyprovider.KeyTypeECDSAP256}); err != nil {
			t.Fatalf("generating a key through the provider: %v", err)
		}
		signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
		if err != nil {
			t.Fatalf("opening a signer: %v", err)
		}
		defer func() { _ = signer.Close() }()
		digest := sha256.Sum256([]byte("provider sink"))
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatalf("signing through the provider: %v", err)
		}
	}()

	if got := drains.Load(); got < 2 {
		t.Errorf("the provider announced %d operation(s) for a generate and a signature; "+
			"an unannounced operation is one whose log entry nothing collects", got)
	}

	res := sinks.collect(t, "provider generate and sign")
	if res.Collected == 0 {
		t.Fatal("the drain stored nothing after a generate and a signature through the provider")
	}
	counts := commandCounts(sinks.entries(t))
	if counts[hsm.CmdGenerateAsymmetricKey] == 0 {
		t.Errorf("no GENERATE ASYMMETRIC KEY entry was collected; stored commands: %s", describeCounts(counts))
	}
	if counts[hsm.CmdSignECDSA] == 0 {
		t.Errorf("no SIGN ECDSA entry was collected; stored commands: %s", describeCounts(counts))
	}

	// The ledger is the other half of reconciliation: the device log says a key
	// signed, the ledger says what it signed.
	ledger, err := sinks.db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading the signature ledger: %v", err)
	}
	if len(ledger) == 0 {
		t.Error("the signature reached the device but no ledger row was written")
	}

	fileRes, err := hsmaudit.VerifyLogFile(sinks.filePath)
	if err != nil {
		t.Fatalf("verifying the append-only file: %v", err)
	}
	if err := fileRes.Err(); err != nil {
		t.Fatalf("the append-only file does not verify: %v", err)
	}
	if fileRes.Entries != len(sinks.entries(t)) {
		t.Errorf("the file holds %d entries and the database %d", fileRes.Entries, len(sinks.entries(t)))
	}
	t.Logf("provider operations: %d entr(ies) in both copies, %d ledger row(s), file verified",
		fileRes.Entries, len(ledger))
}

// TestDrainingAfterEveryOperationOutlastsTheRing is the liveness claim.
//
// With force-audit on, a device whose 62 slots fill stops serving audited
// commands — it does not overwrite. So "drain after every operation" is not a
// tuning preference: it is what lets a CA perform more than 62 operations. This
// runs comfortably more than one ring's worth with a drain following each
// operation, and checks that the device never refuses, the ring never
// approaches full, and every entry is in both durable copies afterwards.
func TestDrainingAfterEveryOperationOutlastsTheRing(t *testing.T) {
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA)
	keepLogSpace(t, 10)

	sinks := newAuditSinks(t)
	keyID := scratchID(5)
	digest := sha256.Sum256([]byte("outlast the ring"))

	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		deleteScratch(ctx, c, keyID)
		if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
			ID: keyID, Label: label("sink-ring"), Domains: 1,
			Capabilities: capabilities(t, "sign-ecdsa"), Algorithm: algECP256,
		}); err != nil {
			t.Fatalf("generating the signing key: %v", err)
		}
	})
	t.Cleanup(func() {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) { deleteScratch(ctx, c, keyID) })
	})
	sinks.collect(t, "the setup key generation")

	// Batches rather than one-at-a-time: each drain is three device round trips
	// and a session, so a per-signature drain would spend most of the test in
	// session setup while proving the same thing. The batch stays well under the
	// ring depth, which is what makes the run depend on draining.
	const (
		batches  = 5
		perBatch = 20
	)
	worst := 0
	for b := 0; b < batches; b++ {
		withClient(t, func(ctx context.Context, c *yubihsm.Client) {
			for i := 0; i < perBatch; i++ {
				if _, err := c.SignECDSA(ctx, keyID, digest[:]); err != nil {
					t.Fatalf("batch %d signature %d failed after %d total operations "+
						"(a full log stops a force-audited device): %v", b+1, i+1, b*perBatch+i, err)
				}
			}
		})
		res := sinks.collect(t, fmt.Sprintf("batch %d", b+1))
		if used, _, ok := parseUsed(res.LogUsed); ok && used > worst {
			worst = used
		}
	}

	total := batches * perBatch
	if total <= hsmaudit.MaxLogEntries {
		t.Fatalf("this test ran %d operations, which fits in one %d-entry ring; it proves nothing about draining",
			total, hsmaudit.MaxLogEntries)
	}
	if worst >= hsmaudit.MaxLogEntries {
		t.Errorf("the device log reached %d/%d entries: draining is not keeping up", worst, hsmaudit.MaxLogEntries)
	}

	stored := sinks.entries(t)
	if got := commandCounts(stored)[hsm.CmdSignECDSA]; got < total {
		t.Errorf("the database holds %d signature entries after %d signatures: entries were lost", got, total)
	}
	seg := hsmaudit.VerifySegment(stored, &sinks.start, hsmaudit.Unlogged{})
	if !seg.OK {
		t.Fatalf("the collected entries do not form a continuous chain: %v", seg.Problems)
	}

	fileRes, err := hsmaudit.VerifyLogFile(sinks.filePath)
	if err != nil {
		t.Fatalf("verifying the append-only file: %v", err)
	}
	if err := fileRes.Err(); err != nil {
		t.Fatalf("the append-only file does not verify after %d operations: %v", total, err)
	}
	if fileRes.Entries != len(stored) {
		t.Errorf("after %d operations the file holds %d entries and the database %d",
			total, fileRes.Entries, len(stored))
	}
	if fileRes.Signatures < total {
		t.Errorf("the file records %d signatures, want at least %d", fileRes.Signatures, total)
	}
	if st, err := os.Stat(sinks.filePath); err == nil {
		t.Logf("%d operations across %d drains: %d entries in both copies, %d bytes of append-only file, "+
			"device log peaked at %d/%d", total, batches+1, fileRes.Entries, st.Size(), worst, hsmaudit.MaxLogEntries)
	}
}

// parseUsed reads the device's "used/total" log occupancy report.
func parseUsed(s string) (used, total int, ok bool) {
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d/%d", &used, &total); err != nil {
		return 0, 0, false
	}
	return used, total, true
}

// describeCounts renders a command tally for an error message.
func describeCounts(counts map[byte]int) string {
	if len(counts) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(counts))
	for cmd, n := range counts {
		parts = append(parts, fmt.Sprintf("0x%02x %s x%d", cmd, hsm.AllCommands[cmd], n))
	}
	return strings.Join(parts, ", ")
}
