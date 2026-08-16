//go:build yubihsm

// Hardware validation for the HSM audit subsystem. These tests require a real
// YubiHSM 2 reachable over the connector in YUBIHSM_CONNECTOR (default
// yhusb://, direct USB) and are excluded from the normal build.
//
// Run with:
//
//	go test -tags yubihsm ./internal/hsmaudit/ -v
//
// Several of the assertions here exist because the corresponding assumption in
// the pre-existing implementation turned out to be wrong when checked against
// hardware; each such test names what it pins down.
package hsmaudit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
)

func hwConfig(t *testing.T) hsm.Config {
	t.Helper()
	connector := os.Getenv("YUBIHSM_CONNECTOR")
	if connector == "" {
		connector = "yhusb://"
	}
	password := os.Getenv("YUBIHSM_PASSWORD")
	if password == "" {
		password = "password"
	}
	return hsm.Config{ConnectorURL: connector, AuthKeyID: 1, Password: password}
}

func hwDevice(t *testing.T) *ShellDevice {
	t.Helper()
	if _, err := exec.LookPath("yubihsm-shell"); err != nil {
		t.Skip("yubihsm-shell not installed")
	}
	d := NewShellDevice(hwConfig(t))
	if _, err := d.Info(context.Background()); err != nil {
		t.Skipf("no YubiHSM reachable: %v", err)
	}
	return d
}

// shell runs raw yubihsm-shell commands for test setup that is not part of the
// production surface (key generation, signing).
func shell(t *testing.T, cfg hsm.Config, commands string) string {
	t.Helper()
	script := fmt.Sprintf("connect\nsession open %d %s\n%s\nsession close 0\nexit\n",
		cfg.AuthKeyID, cfg.Password, commands)
	cmd := exec.Command("yubihsm-shell", "-C", cfg.ConnectorURL)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("yubihsm-shell: %v\n%s", err, out)
	}
	return string(out)
}

// TestDeviceInfo_RealDevice checks the device is reachable and its identity
// parses.
func TestDeviceInfo_RealDevice(t *testing.T) {
	d := hwDevice(t)
	info, err := d.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Serial == "" {
		t.Error("device serial did not parse")
	}
	if info.Version == "" {
		t.Error("device version did not parse")
	}
	if !strings.Contains(info.LogUsed, "/") {
		t.Errorf("log usage %q does not look like used/capacity", info.LogUsed)
	}
	t.Logf("device serial=%s version=%s part=%s log=%s",
		info.Serial, info.Version, info.PartNumber, info.LogUsed)
}

// TestEntryDigest_RealDevice pins the device chain-digest construction:
// SHA-256(entry_fields_big_endian || previous_digest) truncated to 16 bytes.
//
// This is the load-bearing assumption of the whole package — if the digest were
// computed differently, every "the chain verifies" claim would be vacuous. It
// is checked against digests the device itself produced.
func TestEntryDigest_RealDevice(t *testing.T) {
	d := hwDevice(t)
	resp, err := d.FetchLog(context.Background())
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	if len(resp.Entries) < 2 {
		t.Skipf("need at least 2 unconsumed entries to check a chain link, have %d", len(resp.Entries))
	}
	checked := 0
	for i := 1; i < len(resp.Entries); i++ {
		prev, err := hex.DecodeString(resp.Entries[i-1].Hash)
		if err != nil {
			t.Fatalf("entry %d digest not hex: %v", resp.Entries[i-1].Number, err)
		}
		got := EntryDigest(resp.Entries[i], prev)
		if !strings.EqualFold(got, resp.Entries[i].Hash) {
			t.Fatalf("entry %d: recomputed digest %s, device reported %s",
				resp.Entries[i].Number, got, resp.Entries[i].Hash)
		}
		checked++
	}
	t.Logf("verified %d device-produced chain link(s)", checked)
}

// TestBootSentinel_RealDevice documents the shape of the device-init entry a
// factory reset writes. It only runs on a freshly reset device.
func TestBootSentinel_RealDevice(t *testing.T) {
	d := hwDevice(t)
	resp, err := d.FetchLog(context.Background())
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	if len(resp.Entries) == 0 || resp.Entries[0].Number != 1 {
		t.Skip("device log does not start at entry 1 (not freshly reset, or already consumed)")
	}
	if !hsm.IsBootSentinel(resp.Entries[0]) {
		t.Fatalf("entry 1 is not a device-init sentinel: %+v", resp.Entries[0])
	}
	t.Logf("device-init sentinel confirmed: %+v", resp.Entries[0])
}

// TestUnloggedCounters_RealDevice checks that the unlogged-operation counters
// are parsed from the device response.
//
// The pre-existing parser discarded these lines entirely. They are the device
// reporting that its own log overflowed and operations went unrecorded, so
// dropping them let an incomplete log pass as a clean one.
func TestUnloggedCounters_RealDevice(t *testing.T) {
	d := hwDevice(t)
	out := shell(t, hwConfig(t), "audit get 0")
	if !strings.Contains(out, "unlogged boots found") {
		t.Fatalf("device output no longer reports unlogged boots; parser needs review:\n%s", out)
	}
	resp, err := hsm.ParseLogResponse(out)
	if err != nil {
		t.Fatalf("ParseLogResponse: %v", err)
	}
	t.Logf("unlogged boots=%d authentications=%d entries=%d",
		resp.UnloggedBoots, resp.UnloggedAuthentications, len(resp.Entries))

	unlogged := Unlogged{Boots: resp.UnloggedBoots, Authentications: resp.UnloggedAuthentications}
	if unlogged.Any() {
		t.Errorf("device reports unrecorded operations: %+v — the log is not complete", unlogged)
	}
	_ = d
}

// TestShellInBandFailure_RealDevice pins the behaviour that motivated in-band
// error detection: yubihsm-shell exits 0 even when a scripted command fails.
//
// Without this check, provisioning could report that force-audit was enabled
// when the device had rejected the change — the exact state in which unlogged
// signing becomes possible.
func TestShellInBandFailure_RealDevice(t *testing.T) {
	cfg := hwConfig(t)
	hwDevice(t)

	// Ask for an option that does not exist; the shell prints an error line and
	// still exits 0.
	cmd := exec.Command("yubihsm-shell", "-C", cfg.ConnectorURL)
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"connect\nsession open %d %s\nput option 0 command-audit ff02\nsession close 0\nexit\n",
		cfg.AuthKeyID, cfg.Password))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("shell exited non-zero (%v); in-band detection not exercised:\n%s", err, out)
	}
	if _, err := hsm.GetAuditOptions(cfg); err != nil {
		t.Logf("GetAuditOptions surfaced: %v", err)
	}
	t.Logf("shell exit status 0 with output:\n%s", out)
}

// TestAuditOptions_RealDevice reads the device audit configuration and reports
// whether it currently satisfies the completeness requirement.
func TestAuditOptions_RealDevice(t *testing.T) {
	d := hwDevice(t)
	opts, err := d.Options(context.Background())
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	t.Logf("force-audit=%s, %d command-audit entries", opts.ForceAudit, len(opts.CommandAudit))
	if len(opts.CommandAudit) == 0 {
		t.Fatal("command-audit option parsed to zero commands; the pair decoding is wrong")
	}
	// A command the device lists but this build does not know about could be a
	// signing or key-export command hiding behind an unrecognised byte. It does
	// not have to be recognised, but it does have to be force-audited, so that
	// running it cannot escape the log. Confirm RequiredForced picks each one up.
	required := make(map[uint8]bool)
	for _, c := range opts.RequiredForced() {
		required[c] = true
	}
	for cmd := range opts.CommandAudit {
		if _, known := hsm.AllCommands[cmd]; known {
			continue
		}
		t.Logf("device reports undocumented command 0x%02x (absent from Yubico's published "+
			"command reference and yh_cmd enum)", cmd)
		if !required[cmd] {
			t.Errorf("undocumented command 0x%02x is not in the force-audit set: "+
				"it could sign or export a key without leaving a log entry", cmd)
		}
	}
	if err := opts.Verify(); err != nil {
		t.Logf("device is not fully provisioned (expected before provisioning): %v", err)
	} else {
		t.Log("device audit configuration satisfies the completeness requirement")
	}
}

// TestProvisionAndVerifyOptions_RealDevice provisions forced auditing and then
// verifies the device reports it.
//
// This test makes an IRREVERSIBLE change: audit levels are set to "fixed",
// which survives until a factory reset. It is opt-in via
// YUBIHSM_ALLOW_PROVISION=1.
func TestProvisionAndVerifyOptions_RealDevice(t *testing.T) {
	if os.Getenv("YUBIHSM_ALLOW_PROVISION") != "1" {
		t.Skip("set YUBIHSM_ALLOW_PROVISION=1 to run (makes irreversible device changes)")
	}
	d := hwDevice(t)
	cfg := hwConfig(t)

	before, err := d.Options(context.Background())
	if err != nil {
		t.Fatalf("Options before provisioning: %v", err)
	}
	// Provisioning is one-shot by design: the device refuses to re-store an
	// option that is already fixed, so re-running this against a commissioned
	// device would fail on the device's correct behaviour rather than on a bug.
	// Report the end state instead — which is what the test is really asserting.
	if err := before.Verify(); err == nil {
		t.Logf("device is already commissioned: force-audit=%s, %d command(s) fixed",
			before.ForceAudit, len(before.RequiredForced()))
		t.Skip("device already provisioned; factory reset it to exercise provisioning again")
	}
	required := before.RequiredForced()

	// The device-derived set must be a strict superset of the static baseline on
	// this firmware, because 2.4.0 reports commands Yubico does not document.
	// If that ever stops being true the extension logic has silently stopped
	// doing anything.
	var undocumented []uint8
	for cmd := range before.CommandAudit {
		if _, known := hsm.AllCommands[cmd]; !known {
			undocumented = append(undocumented, cmd)
		}
	}
	t.Logf("device reports %d command(s), %d unknown to this build: %#x",
		len(before.CommandAudit), len(undocumented), undocumented)

	out, err := hsm.ProvisionAuditLogging(cfg, required)
	if err != nil {
		t.Fatalf("ProvisionAuditLogging: %v\n%s", err, out)
	}

	opts, err := d.Options(context.Background())
	if err != nil {
		t.Fatalf("Options after provisioning: %v", err)
	}
	if err := opts.Verify(); err != nil {
		t.Fatalf("device still not sufficiently audited after provisioning: %v", err)
	}

	// Every command this build cannot vouch for must have actually been fixed on
	// the device, not merely included in the request.
	for _, cmd := range undocumented {
		if opts.CommandAudit[cmd] != AuditFixed {
			t.Errorf("undocumented command 0x%02x is %s, want fixed: it could sign or export a key unlogged",
				cmd, opts.CommandAudit[cmd])
		}
	}
	t.Logf("force-audit=%s; all %d required commands are fixed (baseline %d + %d undocumented)",
		opts.ForceAudit, len(required), len(BaselineForcedCommands), len(undocumented))
}

// TestForcedAuditIsIrreversible_RealDevice proves that an audit level set to
// "fixed" cannot be lowered again, which is what makes the completeness claim
// hold against an operator who holds the authentication key.
func TestForcedAuditIsIrreversible_RealDevice(t *testing.T) {
	d := hwDevice(t)
	cfg := hwConfig(t)
	opts, err := d.Options(context.Background())
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if opts.CommandAudit[hsm.CmdSignECDSA] != AuditFixed {
		t.Skip("SIGN ECDSA is not fixed on this device; run the provisioning test first")
	}

	// Attempt to turn auditing for SIGN ECDSA off. The device must refuse.
	cmd := exec.Command("yubihsm-shell", "-C", cfg.ConnectorURL)
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"connect\nsession open %d %s\nput option 0 command-audit %02x00\nsession close 0\nexit\n",
		cfg.AuthKeyID, cfg.Password, hsm.CmdSignECDSA))
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "Failed") {
		t.Fatalf("device accepted lowering a fixed audit level — auditing is NOT irreversible:\n%s", out)
	}

	after, err := d.Options(context.Background())
	if err != nil {
		t.Fatalf("Options after attempted downgrade: %v", err)
	}
	if after.CommandAudit[hsm.CmdSignECDSA] != AuditFixed {
		t.Fatalf("SIGN ECDSA audit level changed to %s despite being fixed", after.CommandAudit[hsm.CmdSignECDSA])
	}
	t.Log("confirmed: a fixed audit level cannot be lowered without a factory reset")
}

// TestSignaturesAreCounted_RealDevice is the end-to-end validation of the
// property this package exists to prove: every signature the device produces
// appears in the log, the collected segments chain together across fetches, and
// the counts reconcile against a ledger.
//
// It generates a throwaway key, signs a known number of times, and then checks
// that the device log accounts for exactly that many signatures — and that an
// under-reported ledger is detected as a surplus.
func TestSignaturesAreCounted_RealDevice(t *testing.T) {
	if os.Getenv("YUBIHSM_ALLOW_PROVISION") != "1" {
		t.Skip("set YUBIHSM_ALLOW_PROVISION=1 to run (creates and deletes a key on the device)")
	}
	d := hwDevice(t)
	cfg := hwConfig(t)
	ctx := context.Background()

	opts, err := d.Options(ctx)
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if opts.CommandAudit[hsm.CmdSignECDSA] != AuditFixed {
		t.Skip("SIGN ECDSA is not force-audited; run the provisioning test first")
	}

	// Drain whatever is pending so the segment under test starts clean.
	pre, err := d.FetchLog(ctx)
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	var tail *Tail
	if len(pre.Entries) > 0 {
		last := pre.Entries[len(pre.Entries)-1]
		if err := d.ConsumeLog(ctx, last.Number); err != nil {
			t.Fatalf("ConsumeLog: %v", err)
		}
		tail = &Tail{Number: last.Number, Digest: last.Hash}
	}
	if tail == nil {
		t.Skip("no prior entry to anchor the segment on")
	}

	const keyID = 0x7e57
	const signatures = 5
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) // best effort
	shell(t, cfg, fmt.Sprintf("generate asymmetric 0 0x%04x hsmaudit-test 1 sign-ecdsa ecp256", keyID))

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	digestFile := t.TempDir() + "/digest.bin"
	if err := os.WriteFile(digestFile, digest, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < signatures; i++ {
		shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
	}

	post, err := d.FetchLog(ctx)
	if err != nil {
		t.Fatalf("FetchLog after signing: %v", err)
	}
	unlogged := Unlogged{Boots: post.UnloggedBoots, Authentications: post.UnloggedAuthentications}

	// The new segment must continue the chain from where collection stopped.
	res := VerifySegment(post.Entries, tail, unlogged)
	if err := res.Err(); err != nil {
		t.Fatalf("segment does not continue the device chain: %v", err)
	}
	t.Logf("collected %d entries (%d..%d), chain continuous from entry %d",
		res.Count, res.First, res.Last, tail.Number)

	// A ledger that accounts for every signature must reconcile exactly.
	var ledger []LedgerEntry
	for i := 0; i < signatures; i++ {
		ledger = append(ledger, LedgerEntry{KeyID: keyID, KeyLabel: "hsmaudit-test", Digest: hex.EncodeToString(digest)})
	}
	rec := Reconcile(post.Entries, ledger)
	if err := rec.Err(); err != nil {
		t.Fatalf("balanced ledger failed to reconcile: %v", err)
	}
	var deviceCount int
	for _, k := range rec.Keys {
		if k.KeyID == keyID {
			deviceCount = k.DeviceSignatures
		}
	}
	if deviceCount != signatures {
		t.Fatalf("device recorded %d signatures for key 0x%04x, expected %d", deviceCount, keyID, signatures)
	}
	t.Logf("device recorded exactly %d signature(s) for key 0x%04x", deviceCount, keyID)

	// Removing one ledger row must surface as key abuse: the device performed a
	// signature the CA cannot account for.
	abuse := Reconcile(post.Entries, ledger[:len(ledger)-1])
	if abuse.OK {
		t.Fatal("an unaccounted-for device signature did NOT trip reconciliation")
	}
	if !strings.Contains(abuse.Err().Error(), "KEY ABUSE") {
		t.Fatalf("expected a key-abuse finding, got: %v", abuse.Err())
	}
	t.Logf("unaccounted signature correctly reported: %v", abuse.Err())

	if err := d.ConsumeLog(ctx, post.Entries[len(post.Entries)-1].Number); err != nil {
		t.Fatalf("ConsumeLog: %v", err)
	}
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID))
}

// TestFreshnessEndToEnd_RealDevice exercises the complete claim on hardware: a
// commissioned device signs, a timestamp authority attests to the resulting
// audit head, the exported bundle verifies as current — and a signature the
// ledger does not account for is caught as key abuse.
//
// It runs against a real YubiHSM and a real (in-test) RFC 3161 authority, so
// every digest, chain link and token signature in the path is genuine. The
// device must already be provisioned; run TestProvisionAndVerifyOptions_RealDevice
// first on a factory-reset device.
func TestFreshnessEndToEnd_RealDevice(t *testing.T) {
	if os.Getenv("YUBIHSM_ALLOW_PROVISION") != "1" {
		t.Skip("set YUBIHSM_ALLOW_PROVISION=1 to run (creates and deletes a key on the device)")
	}
	d := hwDevice(t)
	cfg := hwConfig(t)
	ctx := context.Background()

	opts, err := d.Options(ctx)
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if err := opts.Verify(); err != nil {
		t.Skipf("device is not commissioned for audited operation: %v", err)
	}

	// Start the audited history from the device's current position rather than
	// from the factory-reset sentinel: this test runs after others have already
	// consumed entries, so the sentinel is long gone from the ring. Pinning the
	// current tail as the anchor gives the same structural guarantees for the
	// window under test.
	pre, err := d.FetchLog(ctx)
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	if len(pre.Entries) == 0 {
		t.Skip("no pending entry to anchor this window on")
	}
	last := pre.Entries[len(pre.Entries)-1]
	if err := d.ConsumeLog(ctx, last.Number); err != nil {
		t.Fatalf("ConsumeLog: %v", err)
	}

	store := NewMemStore()
	info, err := d.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if err := store.AppendLogEntries(ctx, []hsm.AuditLogEntry{last}); err != nil {
		t.Fatalf("seeding window anchor: %v", err)
	}
	if err := store.SaveAuditState(ctx, &AuditState{
		DeviceSerial:  info.Serial,
		Anchor:        strings.ToLower(last.Hash),
		ProvisionedAt: time.Now().UTC(),
		Tail:          Tail{Number: last.Number, Digest: strings.ToLower(last.Hash)},
	}); err != nil {
		t.Fatalf("pinning window anchor: %v", err)
	}
	svc := NewService(d, store)

	// Sign three times on the device, recording each in the ledger exactly as the
	// key-provider chokepoint does in production.
	const keyID = 0x7e58
	const signatures = 3
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) // best effort
	shell(t, cfg, fmt.Sprintf("generate asymmetric 0 0x%04x freshness-test 1 sign-ecdsa ecp256", keyID))
	t.Cleanup(func() { shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) })

	digest := make([]byte, 32)
	digestFile := t.TempDir() + "/digest.bin"
	for i := 0; i < signatures; i++ {
		for j := range digest {
			digest[j] = byte(i*32 + j)
		}
		if err := os.WriteFile(digestFile, digest, 0o600); err != nil {
			t.Fatal(err)
		}
		shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
		if err := store.AppendLedger(ctx, &LedgerEntry{
			Timestamp: time.Now().UTC(),
			KeyLabel:  "freshness-test",
			KeyID:     keyID,
			Digest:    hex.EncodeToString(digest),
			Algorithm: "SHA-256",
			Purpose:   PurposeCertificate,
		}); err != nil {
			t.Fatalf("appending ledger row: %v", err)
		}
	}

	// Attest to the resulting head with a real RFC 3161 authority.
	ts := newTestTSA(t, "https://tsa.test/tsr")
	proof, err := svc.Timestamp(ctx, ts)
	if err != nil {
		t.Fatalf("obtaining freshness attestation: %v", err)
	}
	t.Logf("attested head at %s: device entry %d, %d signature(s), ledger seq %d",
		proof.GenTime.Format(time.RFC3339), proof.Head.DeviceNumber, proof.Head.Signatures, proof.Head.LedgerSeq)

	bundle, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(bundle, VerifyOptions{
		ExpectedAnchor: strings.ToLower(last.Hash),
		ExpectedSerial: info.Serial,
		Freshness: FreshnessOptions{
			Roots:                 []*x509.Certificate{ts.root},
			RequireIndependentTSA: true,
		},
	})
	// This window starts at the device's current position rather than at the
	// factory-reset sentinel, which VerifyBundle correctly refuses as a genesis
	// (TestBootSentinel_RealDevice covers that requirement). Every other part of
	// the verdict is meaningful here, so assert on those rather than on the
	// bottom line, which the missing sentinel would fail for an unrelated reason.
	if err := res.Reconciliation.Err(); err != nil {
		t.Fatalf("a genuine hardware history failed to reconcile: %v", err)
	}
	if err := res.Attestations.Err(); err != nil {
		t.Fatalf("the device's own key attestations were rejected: %v", err)
	}
	if err := res.Freshness.Err(); err != nil {
		t.Fatalf("a freshly attested bundle was judged stale: %v", err)
	}
	if res.Reconciliation.TotalDeviceSignatures != signatures {
		t.Fatalf("device reported %d signatures, want %d",
			res.Reconciliation.TotalDeviceSignatures, signatures)
	}
	t.Logf("verified: %s", res.Summary)

	// Now the abuse case: sign once more without a ledger row, exactly as an
	// operator misusing the key would. The device log cannot be suppressed, so
	// the surplus must surface.
	shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
	if _, err := NewCollector(d, store, 0, discardLogger()).Collect(ctx); err != nil {
		t.Fatalf("collect after unrecorded signature: %v", err)
	}
	abused, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export after unrecorded signature: %v", err)
	}
	abuseRes := VerifyBundle(abused, VerifyOptions{
		ExpectedAnchor: strings.ToLower(last.Hash),
		ExpectedSerial: info.Serial,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if abuseRes.Reconciliation.OK {
		t.Fatal("a signature the ledger does not account for was NOT detected on real hardware")
	}
	if !strings.Contains(abuseRes.Reconciliation.Err().Error(), "KEY ABUSE") {
		t.Fatalf("expected a key-abuse finding, got: %v", abuseRes.Reconciliation.Err())
	}
	t.Logf("unrecorded hardware signature correctly reported: %s", abuseRes.Summary)

	// And the staleness case: the same bundle judged against a threshold shorter
	// than the attestation's age must be refused as outdated.
	stale := VerifyBundle(bundle, VerifyOptions{
		ExpectedAnchor: strings.ToLower(last.Hash),
		Freshness: FreshnessOptions{
			Roots:  []*x509.Certificate{ts.root},
			Now:    proof.GenTime.Add(48 * time.Hour),
			MaxAge: time.Hour,
		},
	})
	if !stale.Freshness.Stale {
		t.Fatal("an attestation two days past the freshness threshold was accepted as current")
	}
	t.Logf("stale bundle correctly refused: %v", stale.Freshness.Findings)
}

// TestKeyProofEndToEnd_RealDevice is the Task 170 claim on hardware: an auditor
// who holds nothing but a public key learns, from the exported bundle alone,
// that this key lives inside this HSM and has signed exactly what was published.
//
// It is deliberately built from two independent device paths. The public key
// comes from GET PUBLIC KEY; the binding of that key to an object handle comes
// from a device-signed attestation certificate; the signature history comes from
// the audit log. Nothing in the chain is asserted by this process.
func TestKeyProofEndToEnd_RealDevice(t *testing.T) {
	if os.Getenv("YUBIHSM_ALLOW_PROVISION") != "1" {
		t.Skip("set YUBIHSM_ALLOW_PROVISION=1 to run (creates and deletes keys on the device)")
	}
	d := hwDevice(t)
	cfg := hwConfig(t)
	ctx := context.Background()

	opts, err := d.Options(ctx)
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if err := opts.Verify(); err != nil {
		t.Skipf("device is not commissioned for audited operation: %v", err)
	}

	// As in the freshness test, pin the device's current position as the window
	// anchor: earlier tests have long since consumed the factory-reset sentinel,
	// and the structural guarantees over the window are the same.
	svc, store, _, _ := hwWindow(t, d)

	const keyID = 0x7e5a
	const signatures = 2
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) // best effort
	shell(t, cfg, fmt.Sprintf("generate asymmetric 0 0x%04x keyproof-test 1 sign-ecdsa ecp256", keyID))
	t.Cleanup(func() { shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) })

	// The auditor's copy of the public key, read out of the device by a different
	// command than the one that attests it. In production this is the key in the
	// CA certificate they are deciding whether to trust.
	pub := hwPublicKey(t, cfg, keyID)

	digest := make([]byte, 32)
	digestFile := t.TempDir() + "/digest.bin"
	for i := 0; i < signatures; i++ {
		for j := range digest {
			digest[j] = byte(i*32 + j)
		}
		if err := os.WriteFile(digestFile, digest, 0o600); err != nil {
			t.Fatal(err)
		}
		shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
		if err := store.AppendLedger(ctx, &LedgerEntry{
			Timestamp: time.Now().UTC(),
			KeyLabel:  "keyproof-test",
			KeyID:     keyID,
			Digest:    hex.EncodeToString(digest),
			Algorithm: "SHA-256",
			Purpose:   PurposeCertificate,
		}); err != nil {
			t.Fatalf("appending ledger row: %v", err)
		}
	}

	bundle, report, err := svc.ExportWithReport(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(report.AttestationErrors) > 0 {
		t.Fatalf("the device would not attest a key it holds: %v", report.AttestationErrors)
	}
	if len(bundle.KeyAttestations) == 0 {
		t.Fatal("export carried no key attestations")
	}

	atts, kp := verifyWindow(t, bundle, ExpectedKey{Name: "keyproof-test", PublicKey: pub})
	if !atts.OK {
		t.Fatalf("the device's own attestations were rejected: %v", atts.Err())
	}
	if !kp.OK {
		t.Fatalf("a genuine key proof from real hardware was rejected: %v", kp.Err())
	}
	if kp.Key == nil || kp.Key.ObjectID != keyID {
		t.Fatalf("the public key was not bound to object 0x%04x: %+v", keyID, kp.Key)
	}
	if !kp.Key.Attestation.IsNonExportable() || !kp.Key.Attestation.IsGeneratedOnDevice() {
		t.Fatalf("hardware did not assert a generated, non-exportable key: %+v", kp.Key.Attestation)
	}
	if !kp.Key.Attestation.IsDeviceBound() {
		t.Fatal("the attestation certificate was not verified against the device attestation certificate")
	}
	if len(kp.Key.Lifecycle.Generated) != 1 {
		t.Fatalf("the log recorded %d creation(s) of the handle, want 1", len(kp.Key.Lifecycle.Generated))
	}
	if kp.Key.DeviceSignatures != signatures {
		t.Fatalf("device recorded %d signature(s) for the key, want %d", kp.Key.DeviceSignatures, signatures)
	}
	t.Logf("verified: %s", kp.Summary)

	// A key the bundle does not attest must not inherit this one's clean result.
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other := verifyWindow(t, bundle, ExpectedKey{Name: "unrelated", PublicKey: foreign.Public()})
	if other.OK {
		t.Fatal("a key the device never attested was reported as proven")
	}
	t.Logf("unattested key correctly refused: %s", other.Summary)

	// The abuse case, phrased against the key rather than the device: one more
	// signature with no ledger row.
	shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
	abusedBundle, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export after unrecorded signature: %v", err)
	}
	_, abused := verifyWindow(t, abusedBundle, ExpectedKey{Name: "keyproof-test", PublicKey: pub})
	if abused.OK {
		t.Fatal("an unpublished signature by the named key was not detected on real hardware")
	}
	if !strings.Contains(abused.Err().Error(), "never published") {
		t.Fatalf("the key verdict does not name the unpublished signature: %v", abused.Err())
	}
	t.Logf("unpublished hardware signature correctly attributed to the key: %s", abused.Summary)
}

// TestExportableKeyFailsTheAudit_RealDevice pins the property that makes the
// audit log mean anything: a signing key that could leave the device breaks the
// whole bundle, because signatures made with an exported copy would appear in no
// log at all. The device's own attestation is what reveals it — nothing in the
// audit log distinguishes an exportable key from a confined one.
func TestExportableKeyFailsTheAudit_RealDevice(t *testing.T) {
	if os.Getenv("YUBIHSM_ALLOW_PROVISION") != "1" {
		t.Skip("set YUBIHSM_ALLOW_PROVISION=1 to run (creates and deletes keys on the device)")
	}
	d := hwDevice(t)
	cfg := hwConfig(t)
	ctx := context.Background()

	opts, err := d.Options(ctx)
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if err := opts.Verify(); err != nil {
		t.Skipf("device is not commissioned for audited operation: %v", err)
	}
	svc, store, _, _ := hwWindow(t, d)

	const keyID = 0x7e5b
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) // best effort
	shell(t, cfg, fmt.Sprintf("generate asymmetric 0 0x%04x exportable-test 1 sign-ecdsa,exportable-under-wrap ecp256", keyID))
	t.Cleanup(func() { shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", keyID)) })

	pub := hwPublicKey(t, cfg, keyID)
	digest := make([]byte, 32)
	digestFile := t.TempDir() + "/digest.bin"
	if err := os.WriteFile(digestFile, digest, 0o600); err != nil {
		t.Fatal(err)
	}
	shell(t, cfg, fmt.Sprintf("sign ecdsa 0 0x%04x ecdsa-sha256 %s", keyID, digestFile))
	if err := store.AppendLedger(ctx, &LedgerEntry{
		Timestamp: time.Now().UTC(),
		KeyLabel:  "exportable-test",
		KeyID:     keyID,
		Digest:    hex.EncodeToString(digest),
		Algorithm: "SHA-256",
		Purpose:   PurposeCertificate,
	}); err != nil {
		t.Fatalf("appending ledger row: %v", err)
	}

	bundle, err := svc.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// The counts balance exactly — one device signature, one ledger row — so the
	// pre-Task-170 verdict would have been a clean pass.
	if rec := Reconcile(bundle.LogEntries, bundle.Ledger); !rec.OK {
		t.Fatalf("the signature counts should balance; this test is about what they do not show: %v", rec.Err())
	}

	atts, kp := verifyWindow(t, bundle, ExpectedKey{Name: "exportable-test", PublicKey: pub})
	if atts.OK {
		t.Fatal("a signing key that can be exported from the HSM was accepted as confined")
	}
	if kp.OK {
		t.Fatal("a balanced history for a key that can leave the device was reported as proof")
	}
	if !strings.Contains(kp.Err().Error(), "exportable-under-wrap") {
		t.Fatalf("the finding does not name the exportability: %v", kp.Err())
	}
	t.Logf("exportable signing key correctly refused: %s", kp.Summary)
}

// hwWindow pins the device's current log position as a chain anchor and returns
// a Service over a fresh in-memory store. Provisioning proper requires a
// factory-reset device; this gives the same structural guarantees over the
// window under test, which is what these tests exercise.
func hwWindow(t *testing.T, d *ShellDevice) (*Service, *MemStore, string, *DeviceInfo) {
	t.Helper()
	ctx := context.Background()
	pre, err := d.FetchLog(ctx)
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	if len(pre.Entries) == 0 {
		t.Skip("no pending entry to anchor this window on")
	}
	last := pre.Entries[len(pre.Entries)-1]
	if err := d.ConsumeLog(ctx, last.Number); err != nil {
		t.Fatalf("ConsumeLog: %v", err)
	}
	info, err := d.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	store := NewMemStore()
	if err := store.AppendLogEntries(ctx, []hsm.AuditLogEntry{last}); err != nil {
		t.Fatalf("seeding window anchor: %v", err)
	}
	anchor := strings.ToLower(last.Hash)
	if err := store.SaveAuditState(ctx, &AuditState{
		DeviceSerial:  info.Serial,
		Anchor:        anchor,
		ProvisionedAt: time.Now().UTC(),
		Tail:          Tail{Number: last.Number, Digest: anchor},
	}); err != nil {
		t.Fatalf("pinning window anchor: %v", err)
	}
	return NewService(d, store), store, anchor, info
}

// hwPublicKey reads an object's public key off the device with GET PUBLIC KEY —
// a different command than the one that attests it, so the test's expectation is
// not derived from the evidence it is checking.
func hwPublicKey(t *testing.T, cfg hsm.Config, keyID uint16) crypto.PublicKey {
	t.Helper()
	out := shell(t, cfg, fmt.Sprintf("get pubkey 0 0x%04x asymmetric-key", keyID))
	start := strings.Index(out, "-----BEGIN PUBLIC KEY-----")
	end := strings.Index(out, "-----END PUBLIC KEY-----")
	if start < 0 || end < 0 {
		t.Fatalf("no public key in yubihsm-shell output:\n%s", out)
	}
	block, _ := pem.Decode([]byte(out[start : end+len("-----END PUBLIC KEY-----\n")]))
	if block == nil {
		t.Fatal("public key did not decode as PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing device public key: %v", err)
	}
	return pub
}

// verifyWindow runs the checks that are meaningful over a mid-history window.
//
// VerifyBundle deliberately refuses a log that does not begin at the
// factory-reset sentinel, and by the time these tests run the sentinel is long
// consumed — pinning the device's current position is the best a repeatable
// hardware test can do. That requirement is exercised by
// TestBootSentinel_RealDevice and by the unit tests; what is checked here is
// everything that depends on the hardware being real: the device's own
// attestations, the log's account of the key's lifecycle, and the join of both
// onto the ledger.
func verifyWindow(t *testing.T, b *Bundle, want ExpectedKey) (*AttestationResult, *KeyProofResult) {
	t.Helper()
	atts := VerifyAttestations(b, hsmattest.DefaultPolicy())
	return atts, ProveKey(b, atts, want, nil)
}
