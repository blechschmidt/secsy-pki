//go:build sqlite

package yubihsmtest

// Tier 4c: steady-state signing, audited end to end.
//
// audit_test.go proves the device records what it does. audit_sink_test.go
// proves drained entries reach both durable copies. Both drive the device
// directly, which leaves the question an auditor actually asks unanswered: when
// the *product* signs — a CA issuing certificates hour after hour — does the
// evidence still add up?
//
// It is a different question because reconciliation is a two-sided claim. The
// device log says key 0x1939 produced 64 signatures; the signature ledger says
// which 64 they were. A surplus on the device side is key abuse by definition,
// and the way a real deployment manufactures a false one is not by being
// attacked but by signing through a path nobody wired the ledger into. Only a
// test that issues through ca.Manager, with the collector running after every
// operation exactly as the server configures it, can show that the two sides
// agree.
//
// It is also where the one hardware fact that invalidates the whole arrangement
// shows up, which is that a YubiHSM's USB interface belongs to one process at a
// time. See TestDirectUSBCannotBeDrainedWhileTheModuleHoldsIt.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// requireShareableConnector skips a test that needs the device through two
// routes at once unless the connector can multiplex it.
//
// Direct USB cannot: the test below pins that. Rather than silently testing
// something weaker on a `yhusb://` run, the skip names the daemon that makes
// the real configuration reachable.
func requireShareableConnector(t *testing.T) {
	t.Helper()
	requireDevice(t)
	if url := connectorURL(); yubihsm.IsDirectUSB(url) {
		t.Skipf("this test needs the device through the PKCS#11 module and the native driver at the same "+
			"time, which %s cannot do (see TestDirectUSBCannotBeDrainedWhileTheModuleHoldsIt). "+
			"Run `yubihsm-connector -l 127.0.0.1:12345` and set SECSY_YUBIHSM_CONNECTOR to it.", url)
	}
}

// TestDirectUSBCannotBeDrainedWhileTheModuleHoldsIt pins the hardware fact the
// rest of this file is arranged around.
//
// Exactly one process may claim a YubiHSM's USB interface, and Yubico's PKCS#11
// module claims it for as long as it holds a session — which, behind the key
// provider's session pool, is the life of the process. So a deployment that
// signs through PKCS#11 and drains the device log through the native driver
// over `yhusb://` never drains anything: every cycle fails here.
//
// This is a measurement, not a design preference, and it is the reason the
// server refuses to start in that configuration (hsmaudit.DrainContention) and
// the reason `secsy-ca doctor` reports it. If a firmware or module release ever
// made the device shareable over direct USB, this test would start failing,
// which is precisely when that refusal should be revisited.
func TestDirectUSBCannotBeDrainedWhileTheModuleHoldsIt(t *testing.T) {
	requireDevice(t)
	if !yubihsm.IsDirectUSB(connectorURL()) {
		t.Skipf("this test is about the direct-USB transport; this run uses %s", connectorURL())
	}
	ctx := testContext(t)
	dev := hsmaudit.NewHardwareDevice(hsmConfig())

	// With nothing else holding the device the same call has to succeed, or the
	// failure below would prove nothing about contention.
	if _, err := dev.FetchLog(ctx); err != nil {
		t.Fatalf("reading the device log with no module session open: %v", err)
	}

	p := provider(t)
	// A real round trip, so the module has certainly opened its session rather
	// than merely been initialised.
	if _, err := p.FindKey(ctx, keyprovider.KeyRef{Label: label("no-such-key")}); err == nil {
		t.Fatal("a key that was never created was found")
	}

	_, err := dev.FetchLog(ctx)
	if err == nil {
		t.Fatal("the device log was drained while the PKCS#11 module held the USB interface. " +
			"If that is now genuinely possible, hsmaudit.DrainContention and the server's startup " +
			"refusal are obsolete and should be removed — but check first that the module had a " +
			"session open.")
	}
	if !errors.Is(err, yubihsm.ErrDeviceBusy) {
		t.Fatalf("the drain failed, but not as a recognised device-busy condition, so neither the "+
			"startup check nor the collector's diagnosis would classify it: %v", err)
	}
	// The error is what an operator sees first, so it has to carry the fix.
	if !strings.Contains(err.Error(), "yubihsm-connector") {
		t.Errorf("the contention error does not name the daemon that resolves it: %v", err)
	}
	t.Logf("direct USB is exclusive, as expected: %v", err)
}

// TestSteadyStateSigningIsAuditedAndExtracted runs the product's own issuance
// path against the device with the audit subsystem wired exactly as the server
// wires it, then checks that the evidence balances.
//
// Three claims, in the order they have to hold:
//
//  1. Extraction keeps up. More operations than the 62-entry ring holds, with a
//     drain after each one, and the device never refuses and never approaches
//     full. This is the liveness half: on a force-audited device it is what
//     lets a CA issue more than five dozen certificates at all.
//  2. Both durable copies agree. Every entry is in the database and in the
//     append-only file, the file verifies standalone, and the collected run
//     forms one unbroken chain from the pinned position.
//  3. The two sides reconcile. Every signature the device recorded has exactly
//     one ledger row — no surplus, which would read as key abuse, and no
//     deficit, which would mean entries went missing.
func TestSteadyStateSigningIsAuditedAndExtracted(t *testing.T) {
	requireShareableConnector(t)
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA)
	keepLogSpace(t, 20)
	t.Cleanup(func() { sweepPrefix(t) })

	sinks := newAuditSinks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	recorder, err := hsmaudit.EnableRecording(ctx, sinks.db)
	if err != nil {
		t.Fatalf("enabling signature-ledger recording: %v", err)
	}
	if recorder == nil {
		t.Fatal("recording is off although the audit state was just pinned")
	}

	// The server's wiring, verbatim: one chokepoint that both records the
	// signature and drains the entry it produced (cmd/server/hsmaudit.go's
	// recordHSMSignatures). Draining inline is the point — a per-phase drain
	// would prove the sinks work without proving the deployment can run.
	drain := newInlineDrain(sinks)
	p := keyprovider.Record(provider(t), recorder, keyprovider.OnOperation(drain.run))

	mgr := ca.NewManager(sinks.db, p)
	const keyType = keyprovider.KeyTypeECDSAP256

	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    label("ss-root"),
		KeyType:  keyType,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy Steady State Root", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("creating the root CA on the device: %v", err)
	}
	zero := 0
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      label("ss-inter"),
		KeyType:    keyType,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy Steady State Intermediate"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: &zero,
	})
	if err != nil {
		t.Fatalf("issuing the intermediate on the device: %v", err)
	}

	// More leaves than the ring holds entries, so the run cannot complete unless
	// extraction is keeping pace with issuance.
	const leaves = hsmaudit.MaxLogEntries + 8
	var lastSerial *big.Int
	for i := 0; i < leaves; i++ {
		dns := fmt.Sprintf("steady-%02d.example.test", i)
		res, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
			CAID:    inter.ID,
			CSRPEM:  makeCSR(t, dns),
			Profile: "server",
		})
		if err != nil {
			t.Fatalf("issuing leaf %d of %d (a full device log stops a force-audited device): %v",
				i+1, leaves, err)
		}
		lastSerial = res.Certificate.SerialNumber
	}

	// A revocation and a CRL, because the steady state of a CA is not only
	// issuance and because the CRL is signed by a different key than the leaves
	// are — so reconciliation has two keys to balance, not one.
	if _, err := mgr.RevokeCertificate(ctx, inter.ID, lastSerial.String(), "keyCompromise"); err != nil {
		t.Fatalf("revoking the last leaf: %v", err)
	}
	crlDER, err := mgr.GenerateCRL(ctx, inter.ID)
	if err != nil {
		t.Fatalf("generating the CRL on the device: %v", err)
	}
	if _, err := x509.ParseRevocationList(crlDER); err != nil {
		t.Fatalf("parsing the CRL: %v", err)
	}

	// Close the provider before the final drain and the device reads below: the
	// module and the driver share the device through the connector, but there is
	// no reason to keep a session open once the signing is done.
	if err := p.Close(); err != nil {
		t.Errorf("closing the key provider: %v", err)
	}

	// --- 1. extraction kept up -------------------------------------------
	if err := drain.err(); err != nil {
		t.Fatalf("a drain failed during steady-state issuance, so the device log was not being "+
			"extracted while the CA was signing: %v", err)
	}
	if got, want := drain.count(), leaves; got < want {
		t.Errorf("%d drain(s) for %d leaf signatures: operations are reaching the device without "+
			"prompting a drain", got, want)
	}
	if worst := drain.worstUsed(); worst >= hsmaudit.MaxLogEntries {
		t.Errorf("the device log reached %d/%d entries: extraction is not keeping up with issuance",
			worst, hsmaudit.MaxLogEntries)
	}

	// --- 2. both durable copies agree ------------------------------------
	stored := sinks.entries(t)
	if seg := hsmaudit.VerifySegment(stored, &sinks.start, hsmaudit.Unlogged{}); !seg.OK {
		t.Fatalf("the collected entries do not form a continuous chain from the pinned position: %v", seg.Problems)
	}
	fileRes, err := hsmaudit.VerifyLogFile(sinks.filePath)
	if err != nil {
		t.Fatalf("verifying the append-only file: %v", err)
	}
	if err := fileRes.Err(); err != nil {
		t.Fatalf("the append-only file does not verify after steady-state issuance: %v", err)
	}
	if fileRes.Entries != len(stored) {
		t.Errorf("the file holds %d entries and the database %d: the two copies have diverged",
			fileRes.Entries, len(stored))
	}

	// --- 3. the two sides reconcile --------------------------------------
	ledger, err := sinks.db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading the signature ledger: %v", err)
	}
	rec := hsmaudit.Reconcile(stored, ledger)
	if err := rec.Err(); err != nil {
		t.Fatalf("the device log and the signature ledger do not reconcile after ordinary issuance, "+
			"which an auditor reads as key abuse:\n%v", err)
	}
	// Reconcile is vacuously OK over an empty log, so state what it weighed.
	if rec.TotalDeviceSignatures < leaves {
		t.Fatalf("reconciliation balanced, but over only %d device signature(s) for %d leaves: "+
			"the entries that matter were never collected", rec.TotalDeviceSignatures, leaves)
	}
	if len(rec.Keys) < 2 {
		t.Errorf("reconciliation covered %d key(s); the root and the intermediate both signed, "+
			"so a single key means one of them was not attributed", len(rec.Keys))
	}
	t.Logf("%d leaves + 1 CRL through ca.Manager: %d device signature(s) across %d key(s) balanced "+
		"against %d ledger row(s); %d entries in both copies; device log peaked at %d/%d",
		leaves, rec.TotalDeviceSignatures, len(rec.Keys), rec.TotalLedgerSignatures,
		fileRes.Entries, drain.worstUsed(), hsmaudit.MaxLogEntries)
}

// inlineDrain is the collector running on the signing path, as the server runs
// it: one cycle per completed HSM operation.
//
// It collects failures instead of calling t.Fatalf, because the hook fires from
// inside ca.Manager — failing the test from there would abandon a half-finished
// issuance and leave the device holding entries nobody acknowledged, which looks
// exactly like the fault being tested for.
type inlineDrain struct {
	sinks *auditSinks

	mu    sync.Mutex
	first error
	worst int

	drains atomic.Int64
}

func newInlineDrain(s *auditSinks) *inlineDrain { return &inlineDrain{sinks: s} }

func (d *inlineDrain) run() {
	d.drains.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	res, err := d.sinks.collector.Collect(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		if d.first == nil {
			d.first = err
		}
		return
	}
	if used, _, ok := parseUsed(res.LogUsed); ok && used > d.worst {
		d.worst = used
	}
	if res.Segment != nil && !res.Segment.OK && d.first == nil {
		d.first = fmt.Errorf("collected segment is not continuous: %v", res.Segment.Problems)
	}
}

func (d *inlineDrain) err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.first
}

func (d *inlineDrain) worstUsed() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.worst
}

func (d *inlineDrain) count() int { return int(d.drains.Load()) }

// TestSecretLayerSigningIsAuditedAndExtracted covers the signing path that was
// missing from the audit subsystem entirely until Task 202.
//
// `secsy-secret sign` asks the device for the same SIGN ECDSA command the CA
// does, and for a long time it asked anonymously: no ledger row, and — worse
// for a deployment — no drain. The consequence was not a gap in the evidence
// but a false accusation in it. Reconcile counts a device signature with no
// ledger row as key abuse, correctly, because that is exactly what an abused
// key looks like; so an operator signing a release artifact with the secret
// layer would have made their own HSM look compromised.
//
// Running it here rather than only in cmd/secsy-secret's unit tests is what
// makes the claim about the device: the ledger joins on the two-byte on-device
// object id that the module reports as CKA_ID and the device reports as
// target_key, and only hardware can show those are the same number.
func TestSecretLayerSigningIsAuditedAndExtracted(t *testing.T) {
	requireShareableConnector(t)
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA)
	keepLogSpace(t, 20)

	sinks := newAuditSinks(t)
	ctx := testContext(t)

	recorder, err := hsmaudit.EnableRecording(ctx, sinks.db)
	if err != nil {
		t.Fatalf("enabling signature-ledger recording: %v", err)
	}
	if recorder == nil {
		t.Fatal("recording is off although the audit state was just pinned")
	}

	drain := newInlineDrain(sinks)
	p := keyprovider.Record(provider(t), recorder, keyprovider.OnOperation(drain.run))

	// The secret layer names its HSM objects "secsy-sig-<id>", which carries
	// none of this suite's label prefix, so the sweep has to be told the label.
	var keyLabel string
	t.Cleanup(func() {
		if keyLabel != "" {
			sweepLabel(t, keyLabel)
		}
	})

	row, err := secret.CreateSigningKey(ctx, p, sinks.db, secret.CreateSigningKeySpec{
		TenantID:  models.DefaultTenantID,
		Name:      "t202-" + runID,
		Algorithm: secret.AlgECDSAP256,
		CreatedBy: "yubihsmtest",
	})
	if err != nil {
		t.Fatalf("creating a secret-layer signing key on the device: %v", err)
	}
	keyLabel = "secsy-sig-" + row.ID

	const signatures = 6
	for i := 0; i < signatures; i++ {
		res, err := secret.Sign(ctx, p, row, []byte(fmt.Sprintf("release-artifact-%d", i)), "sha256", false)
		if err != nil {
			t.Fatalf("secret-layer signature %d of %d: %v", i+1, signatures, err)
		}
		// Verification uses the stored public half, so a device signature that
		// did not come from this key would not validate.
		ok, err := secret.Verify(row, []byte(fmt.Sprintf("release-artifact-%d", i)), res.Signature, "sha256", false)
		if err != nil || !ok {
			t.Fatalf("signature %d does not verify against the key's public half (ok=%v): %v", i+1, ok, err)
		}
	}
	if err := p.Close(); err != nil {
		t.Errorf("closing the key provider: %v", err)
	}

	if err := drain.err(); err != nil {
		t.Fatalf("a drain failed during secret-layer signing: %v", err)
	}
	stored := sinks.entries(t)
	ledger, err := sinks.db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading the signature ledger: %v", err)
	}
	rec := hsmaudit.Reconcile(stored, ledger)
	if err := rec.Err(); err != nil {
		t.Fatalf("secret-layer signatures do not reconcile against the device log, which an auditor "+
			"reads as key abuse:\n%v", err)
	}
	if rec.TotalDeviceSignatures < signatures {
		t.Fatalf("reconciliation balanced over only %d device signature(s) for %d secret-layer "+
			"signatures: the entries that matter were never collected", rec.TotalDeviceSignatures, signatures)
	}
	// The join is on the on-device object id, and a mis-parsed CKA_ID would show
	// up as an unattributed key 0 that happens to balance against nothing.
	for _, k := range rec.Keys {
		if k.KeyID == 0 {
			t.Errorf("a reconciled key has on-device id 0, so its CKA_ID was not understood: %+v", k)
		}
	}
	fileRes, err := hsmaudit.VerifyLogFile(sinks.filePath)
	if err != nil {
		t.Fatalf("verifying the append-only file: %v", err)
	}
	if err := fileRes.Err(); err != nil {
		t.Fatalf("the append-only file does not verify after secret-layer signing: %v", err)
	}
	t.Logf("%d secret-layer signatures: %d device signature(s) balanced against %d ledger row(s); "+
		"%d entries in both copies", signatures, rec.TotalDeviceSignatures, rec.TotalLedgerSignatures,
		fileRes.Entries)
}
