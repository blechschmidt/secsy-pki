package yubihsmtest

// Tier 10: one process, one container.
//
// Every other tier here takes the deployment shape for granted: the native
// driver talks to the device, or the PKCS#11 module does, and whichever is
// running has the USB interface to itself. A real deployment has both at once
// — the module signs, the driver collects the device audit log, because PKCS#11
// cannot express GET LOG ENTRIES — and the kernel grants that interface to one
// claim. The module takes it for the life of its session pool, so the drain
// never runs: a force-audited device then fills its 62-entry log and stops
// signing, having looked healthy the whole way down.
//
// The answer used to be a second process, Yubico's yubihsm-connector, which in
// a container deployment meant a second container with the device node passed
// to it. This tier is the evidence that it no longer has to be: the embedded
// connector (internal/yubihsm.StartEmbedded) holds the device inside the CA's
// own process, the real Yubico module signs through it over loopback HTTP, and
// the device audit log is drained *while that module's session pool is open* —
// the exact combination hsmaudit.DrainContention exists to refuse.
//
// It has to be hardware. A fake device proves the relay's framing (see
// internal/yubihsm/embedded_test.go) but says nothing about the thing in doubt:
// whether Yubico's closed-source module accepts this relay's status document
// and will carry a signature over it.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// startRelay brings up the embedded connector against the attached device and
// points the PKCS#11 module at it for the duration of the test.
//
// The module reads its connector from the file named by YUBIHSM_PKCS11_CONF at
// C_Initialize, so the file has to be in place before any provider is built —
// and restored afterwards, because the other tiers in this package share the
// one TestMain wrote.
func startRelay(t *testing.T, onOp func()) *yubihsm.Embedded {
	t.Helper()
	if !yubihsm.IsDirectUSB(connectorURL()) {
		t.Skipf("the embedded connector holds a USB device; this run is configured for %s", connectorURL())
	}

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	// Port 0: the kernel picks, so a run cannot collide with a
	// yubihsm-connector daemon on 12345 or with another test run.
	e, err := yubihsm.StartEmbedded(ctx, yubihsm.EmbeddedConfig{
		DeviceURL:   connectorURL(),
		Listen:      "127.0.0.1:0",
		Logger:      log.New(os.Stderr, "relay: ", 0),
		OnOperation: onOp,
	})
	if err != nil {
		t.Fatalf("starting the embedded connector against %s: %v\n"+
			"Another process (yubihsm-connector, yubihsm-shell, or a PKCS#11 module left "+
			"initialised by an earlier test) may still hold the device.", connectorURL(), err)
	}
	t.Cleanup(func() { _ = e.Close() })

	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "yubihsm_pkcs11.conf")
	if err := os.WriteFile(confPath, []byte("connector = "+e.URL()+"\n"), 0o600); err != nil {
		t.Fatalf("writing the module config: %v", err)
	}
	// t.Setenv restores the suite's own value when the test ends, which matters:
	// every other tier shares the file TestMain wrote.
	t.Setenv("YUBIHSM_PKCS11_CONF", confPath)
	t.Logf("embedded connector on %s, device %s; module config %s", e.URL(), e.Serial(), confPath)
	return e
}

// TestEmbeddedConnectorStatusDescribesTheAttachedDevice checks the one document
// Yubico's module reads before it will open a session.
func TestEmbeddedConnectorStatusDescribesTheAttachedDevice(t *testing.T) {
	requireDevice(t)
	e := startRelay(t, nil)

	req, err := http.NewRequestWithContext(testContext(t), http.MethodGet, e.URL()+"/connector/status", nil)
	if err != nil {
		t.Fatalf("building the status request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reading the relay's status: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the status body: %v", err)
	}
	got := string(body)
	t.Logf("connector status:\n%s", strings.TrimSpace(got))
	if !strings.Contains(got, "status=OK") {
		t.Fatalf("the relay does not report a device: %q", got)
	}
	// The serial has to be the device's own, read from the hardware rather than
	// echoed from configuration: everything the audit subsystem claims is about
	// a specific device, and a relay that reported "*" would make the one
	// identifying field in its status document worthless.
	if e.Serial() == "" || !strings.Contains(got, "serial="+e.Serial()) {
		t.Fatalf("the relay's status does not name the attached device (serial %q): %q", e.Serial(), got)
	}
}

// TestEmbeddedConnectorCarriesTheNativeDriver proves the in-process half: code
// that asks for the device by its yhusb:// URL is handed the relay's claim
// instead of attempting a second one.
func TestEmbeddedConnectorCarriesTheNativeDriver(t *testing.T) {
	requireDevice(t)
	e := startRelay(t, nil)
	ctx := testContext(t)

	// driverConfig() carries the plain yhusb:// URL — exactly what every audit,
	// attestation and provisioning path in the product carries when no
	// connector is configured. Opening it must work while the relay holds the
	// device, which before the relay existed it could not.
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		t.Fatalf("opening a native session while the relay holds the device: %v", err)
	}
	defer func() { _ = c.Close() }()
	info, err := c.DeviceInfo(ctx)
	if err != nil {
		t.Fatalf("reading device info over the shared claim: %v", err)
	}
	if info.Serial != e.Serial() {
		t.Fatalf("the shared claim reached device %s, but the relay holds %s", info.Serial, e.Serial())
	}
	t.Logf("native driver over the shared claim: device %s, firmware %s, log %s",
		info.Serial, info.Version, info.LogCapacity())
}

// TestEmbeddedConnectorCarriesPKCS11 drives Yubico's own module through the
// relay, end to end: key generation, signing, and a signature that verifies.
//
// This is the claim that cannot be made against a fake. The module is closed
// source; whether it accepts this relay's status document and will carry a
// secure channel over it is a fact about Yubico's implementation, not about
// ours.
func TestEmbeddedConnectorCarriesPKCS11(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 10)
	startRelay(t, nil)

	p := provider(t)
	lbl := label("relay-sign")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	ctx := testContext(t)
	if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyprovider.KeyTypeECDSAP256}); err != nil {
		t.Fatalf("generating a key through the module over the relay: %v", err)
	}
	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("finding the key through the module over the relay: %v", err)
	}
	defer signer.Close()
	digest := sha256.Sum256([]byte("signed through the embedded connector"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing through the module over the relay: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the module returned a %T public key", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("a signature produced through the relay does not verify against the reported public key")
	}
	t.Logf("Yubico's PKCS#11 module generated and signed with %s over the embedded connector", lbl)
}

// TestEmbeddedConnectorCarriesAnRSAKeyGeneration covers the one device
// operation slow enough to be cut off by a timeout rather than by a bug.
//
// RSA-3072 generation takes about 75 seconds on this device, and relayed
// traffic passes through the native USB transport, whose per-transfer bound is
// 30 seconds by default. A relay that did not let the caller's own deadline
// extend that bound would work perfectly for signatures and ECDSA keys and then
// fail the first time an operator generated an RSA CA key — with a timeout
// nothing in the audit or signing path would explain.
//
// It costs most of two minutes, which is why it is a test of its own rather
// than another case in the matrix above.
func TestEmbeddedConnectorCarriesAnRSAKeyGeneration(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 10)
	startRelay(t, nil)

	p := provider(t)
	lbl := label("relay-rsa")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	started := time.Now()
	gen, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyprovider.KeyTypeRSA3072})
	if err != nil {
		t.Fatalf("generating an RSA-3072 key through the relay: %v\n"+
			"A deadline-shaped failure here means the relay is capping a device operation that was "+
			"about to succeed; see maxUSBTimeout in internal/yubihsm.", err)
	}
	elapsed := time.Since(started)
	if gen.PublicKey == nil {
		t.Fatal("the generated key carries no public key")
	}
	pub, ok := gen.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the module returned a %T public key", gen.PublicKey)
	}
	if bits := pub.N.BitLen(); bits != 3072 {
		t.Fatalf("the generated key is %d bits, want 3072", bits)
	}
	t.Logf("RSA-3072 generated through the relay in %s", elapsed.Round(time.Second))

	// And it signs, because a key that exists but cannot be used would pass
	// every check above.
	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("opening a signer for the relayed RSA key: %v", err)
	}
	defer signer.Close()
	digest := sha256.Sum256([]byte("RSA through the embedded connector"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing with the relayed RSA key: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the signature does not verify under the generated key: %v", err)
	}
}

// TestEmbeddedConnectorDrainsWhileTheModuleHoldsASession is the whole point of
// the tier.
//
// It holds an open PKCS#11 session pool — the module's USB claim, in a
// deployment without the relay — and drains the device audit log through the
// native driver at the same time, in the same process. On direct USB that
// combination is impossible: the drain fails with EBUSY every cycle while
// signing carries on, which is why hsmaudit.DrainContention refuses to start
// such a deployment at all. Here it succeeds, and the entry the signature left
// is in durable storage before the test ends.
func TestEmbeddedConnectorDrainsWhileTheModuleHoldsASession(t *testing.T) {
	requireAuditedCommands(t, hsm.CmdGenerateAsymmetricKey, hsm.CmdSignECDSA)
	keepLogSpace(t, 20)

	var ops atomic.Int64
	startRelay(t, func() { ops.Add(1) })

	// Anchor an in-memory store at the device's current position: this tier is
	// about whether the drain can run at all, not about the chain a provisioned
	// deployment pins — audit_test.go covers that.
	store := hsmaudit.NewMemStore()
	dev := hsmaudit.NewHardwareDevice(hsmConfig())
	collector := hsmaudit.NewCollector(dev, store, 0, log.New(io.Discard, "", 0))
	ctx := testContext(t)

	var tail hsmaudit.Tail
	withClient(t, func(sctx context.Context, c *yubihsm.Client) { tail = drainToTail(t, sctx, c) })
	info, err := dev.Info(ctx)
	if err != nil {
		t.Fatalf("reading device info: %v", err)
	}
	if err := store.SaveAuditState(ctx, &hsmaudit.AuditState{
		DeviceSerial: info.Serial, Anchor: tail.Digest, Tail: tail,
	}); err != nil {
		t.Fatalf("seeding the audit state: %v", err)
	}

	// The provider stays open for the rest of the test: its session pool is the
	// thing that used to lock the drain out.
	p := provider(t)
	lbl := label("relay-drain")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyprovider.KeyTypeECDSAP256}); err != nil {
		t.Fatalf("generating a key through the module: %v", err)
	}
	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("finding the key: %v", err)
	}
	defer signer.Close()

	// One drain with the module's pool already open, before any signature: this
	// is the call that used to fail with EBUSY every single cycle.
	if _, err := collector.Collect(ctx); err != nil {
		t.Fatalf("draining while the module's session pool is open: %v\n"+
			"This is the failure the embedded connector exists to remove.", err)
	}

	const signatures = 5
	for i := 0; i < signatures; i++ {
		digest := sha256.Sum256([]byte(fmt.Sprintf("audited signature %d", i)))
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatalf("signature %d through the module: %v", i, err)
		}
	}

	// Drain again, with the module's pool still open. The signatures must be
	// there: a drain that returned nothing would mean the relay carried the
	// signing traffic but the device log was never reachable, which is the
	// silent half of the original failure.
	res, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("draining the device log while the module's session pool is open: %v", err)
	}
	if res.Signatures < signatures {
		t.Fatalf("the drain found %d signature entries for %d signatures (collected %d entries, log %s)",
			res.Signatures, signatures, res.Collected, res.LogUsed)
	}
	t.Logf("drained %d device log entries (%d signatures) with the module's session pool open; device log %s",
		res.Collected, res.Signatures, res.LogUsed)

	// And the relay signalled those operations, which is what makes collection
	// follow the operations of a client this process has no other view of: the
	// module's traffic is opaque to the key provider, so without the relay's
	// hook nothing in-process would know a signature had happened.
	if n := ops.Load(); n < signatures {
		t.Fatalf("the relay signalled %d operations for %d module signatures", n, signatures)
	}
	t.Logf("the relay signalled %d operations, so the drain follows the module's work", ops.Load())
}

// TestEmbeddedConnectorRemovesTheDrainContentionDiagnosis ties the runtime
// behaviour above to the configuration check that gates startup, so the two
// cannot drift: a deployment the relay makes work must not still be refused.
func TestEmbeddedConnectorRemovesTheDrainContentionDiagnosis(t *testing.T) {
	requireDevice(t)
	module := pkcs11ModulePath(t)

	// Without the relay this configuration is exactly the one that cannot work.
	if err := hsmaudit.DrainContention("yhusb://", module, false); err == nil {
		t.Fatal("direct USB plus a PKCS#11 signing module was accepted without an embedded connector")
	}
	// With it, the same configuration is the single-container deployment.
	if err := hsmaudit.DrainContention("yhusb://", module, true); err != nil {
		t.Fatalf("the embedded connector did not clear the drain-contention diagnosis: %v", err)
	}
	// And the planner agrees it is what should happen by default.
	plan := hsm.PlanEmbeddedConnector(hsm.EmbeddedConnectorOptions{
		ConnectorURL: "",
		PKCS11Module: module,
	})
	if !plan.Start {
		t.Fatalf("the planner would not start a relay for direct USB plus %s: %s", module, plan.Reason)
	}
	if plan.Listen != yubihsm.DefaultEmbeddedListen {
		t.Errorf("the planner chose %s, want %s", plan.Listen, yubihsm.DefaultEmbeddedListen)
	}
	t.Logf("single-container plan: %s", plan.Reason)
}
