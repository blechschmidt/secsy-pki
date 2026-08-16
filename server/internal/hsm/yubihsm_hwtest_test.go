//go:build yubihsm

package hsm

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var hwCfg Config

func TestMain(m *testing.M) {
	// Write yubihsm_pkcs11.conf so the connector-resolution path this package
	// shares with the PKCS#11 module is exercised as deployed.
	confDir, err := os.MkdirTemp("", "yubihsm-hwtest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(confDir)

	confPath := filepath.Join(confDir, "yubihsm_pkcs11.conf")
	if err := os.WriteFile(confPath, []byte("connector = yhusb://\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write conf: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("YUBIHSM_PKCS11_CONF", confPath)

	hwCfg = Config{
		ConnectorURL: "yhusb://",
		AuthKeyID:    1,
		Password:     "password",
	}

	os.Exit(m.Run())
}

func hwContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// GetDeviceInfo
// ---------------------------------------------------------------------------

func TestGetDeviceInfo(t *testing.T) {
	info, err := GetDeviceInfo(hwContext(t), hwCfg)
	if err != nil {
		t.Fatalf("GetDeviceInfo: %v", err)
	}

	if info.Version == "" {
		t.Error("Version is empty")
	}
	if info.Serial == "" {
		t.Error("Serial is empty")
	}
	// Log occupancy is reported as used/capacity and is what the collector
	// watches to drain before a force-audit device wedges.
	if !strings.Contains(info.LogUsed, "/") {
		t.Errorf("LogUsed = %q, want used/capacity", info.LogUsed)
	}
	t.Logf("version %s serial %s part %q log %s force-audit=%v provisioned=%v",
		info.Version, info.Serial, info.PartNumber, info.LogUsed, info.ForceAudit, info.AuditProvisioned)
}

// ---------------------------------------------------------------------------
// GetAuditOptions
// ---------------------------------------------------------------------------

func TestGetAuditOptionsFromDevice(t *testing.T) {
	opts, err := GetAuditOptions(hwContext(t), hwCfg)
	if err != nil {
		t.Fatalf("GetAuditOptions: %v", err)
	}
	if len(opts.CommandAudit) == 0 {
		t.Fatal("device reported no command-audit settings")
	}
	// The device enumerates its whole command set here, so a settings map far
	// smaller than the command table means the response was mis-parsed.
	if len(opts.CommandAudit) < 50 {
		t.Errorf("only %d command-audit entries; the option was likely mis-parsed", len(opts.CommandAudit))
	}
	t.Logf("force-audit=0x%02x over %d commands", opts.ForceAudit, len(opts.CommandAudit))
}

// ---------------------------------------------------------------------------
// GetAuditLog / hash chain
// ---------------------------------------------------------------------------

func TestGetAuditLog(t *testing.T) {
	log, err := GetAuditLog(hwContext(t), hwCfg)
	if err != nil {
		t.Skipf("GetAuditLog: %v (the log may have been consumed)", err)
	}
	if log.DeviceSerial == "" {
		t.Error("DeviceSerial is empty")
	}
	if len(log.Entries) == 0 {
		t.Skip("no audit log entries (may have been consumed)")
	}

	for i, e := range log.Entries {
		// The digest is a 16-byte value carried as hex; a length other than 32
		// means the wire record was mis-sliced.
		if len(e.Hash) != 32 {
			t.Errorf("entry %d: hash length = %d, want 32 hex chars", i, len(e.Hash))
		}
		if _, err := hex.DecodeString(e.Hash); err != nil {
			t.Errorf("entry %d: invalid hash hex: %v", i, err)
		}
		if _, ok := AllCommands[e.Command]; !ok {
			t.Errorf("entry %d: unknown command 0x%02x", i, e.Command)
		}
	}
	t.Logf("%d entries from device %s", len(log.Entries), log.DeviceSerial)
}

func TestVerifyHashChainRealDevice(t *testing.T) {
	log, err := GetAuditLog(hwContext(t), hwCfg)
	if err != nil {
		t.Skipf("GetAuditLog: %v", err)
	}
	if len(log.Entries) < 2 {
		t.Skip("need at least 2 entries to verify a chain")
	}

	results, err := VerifyHashChain(log.Entries)
	if err != nil {
		t.Fatalf("VerifyHashChain: %v", err)
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("entry %d (number %d, command 0x%02x) failed hash-chain verification",
				i, log.Entries[i].Number, log.Entries[i].Command)
		}
	}

	// The device computes these digests itself, so a match proves this package's
	// entry encoding matches the firmware's byte for byte.
	prevHash, err := hex.DecodeString(log.Entries[0].Hash)
	if err != nil {
		t.Fatalf("decode prev hash: %v", err)
	}
	if computed := ComputeEntryHash(log.Entries[1], prevHash); computed != log.Entries[1].Hash {
		t.Errorf("ComputeEntryHash = %s, device reported %s", computed, log.Entries[1].Hash)
	}
}

// ---------------------------------------------------------------------------
// FetchLog does not consume
// ---------------------------------------------------------------------------

func TestFetchLogDoesNotConsume(t *testing.T) {
	ctx := hwContext(t)
	first, err := FetchLog(ctx, hwCfg)
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	second, err := FetchLog(ctx, hwCfg)
	if err != nil {
		t.Fatalf("FetchLog (second): %v", err)
	}
	// Fetch and consume are separate calls precisely so a caller that dies while
	// persisting can retry; a fetch that consumed would lose the only copy.
	if len(first.Entries) != len(second.Entries) {
		t.Fatalf("fetching consumed entries: %d then %d", len(first.Entries), len(second.Entries))
	}
	if first.UnloggedBoots != 0 || first.UnloggedAuthentications != 0 {
		t.Logf("device reports unlogged operations: %d boots, %d authentications",
			first.UnloggedBoots, first.UnloggedAuthentications)
	}
}

// ---------------------------------------------------------------------------
// ListObjects
// ---------------------------------------------------------------------------

func TestListObjectsRealDevice(t *testing.T) {
	objs, err := ListObjects(hwContext(t), hwCfg)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(objs) == 0 {
		t.Fatal("no objects; the session's own authentication key must be visible")
	}
	var sawAuthKey bool
	for _, o := range objs {
		if o.Type == "" || strings.HasPrefix(o.Type, "unknown(") {
			t.Errorf("object 0x%04x has an unrecognised type %q", o.ID, o.Type)
		}
		if o.Type == "authentication-key" {
			sawAuthKey = true
		}
		t.Logf("0x%04x %-20s %-30s %q", o.ID, o.Type, o.Algo, o.Label)
	}
	if !sawAuthKey {
		t.Error("no authentication key in the inventory")
	}
}

func TestFindAsymmetricKeyRejectsUnknownLabel(t *testing.T) {
	_, err := FindAsymmetricKey(hwContext(t), hwCfg, "no-such-key-label-t171")
	if err == nil {
		t.Fatal("resolving an absent label succeeded")
	}
	if !strings.Contains(err.Error(), "no asymmetric key labelled") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetDeviceAttestation / GetDeviceSerial
// ---------------------------------------------------------------------------

func TestGetDeviceAttestationRealDevice(t *testing.T) {
	der, err := GetDeviceAttestation(hwContext(t), hwCfg)
	if err != nil {
		t.Fatalf("GetDeviceAttestation: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("device attestation certificate is empty")
	}
	t.Logf("device attestation certificate: %d DER bytes", len(der))
}

func TestGetDeviceSerial(t *testing.T) {
	serial, err := GetDeviceSerial(hwContext(t), hwCfg)
	if err != nil {
		t.Fatalf("GetDeviceSerial: %v", err)
	}
	if serial == "" {
		t.Fatal("serial is empty")
	}
	for _, c := range serial {
		if c < '0' || c > '9' {
			t.Fatalf("serial contains a non-digit: %q", serial)
		}
	}
	// The serial must be readable without a session: it is the identity check
	// for a device whose authentication key is unknown to this process.
	t.Logf("device serial: %s", serial)
}

// ---------------------------------------------------------------------------
// Connector resolution
// ---------------------------------------------------------------------------

func TestConnectorArgWithEnv(t *testing.T) {
	if got := connectorArg(Config{}); got != "yhusb://" {
		t.Errorf("connectorArg with env conf = %q, want yhusb://", got)
	}
	if got := connectorArg(Config{ConnectorURL: "http://explicit:12345"}); got != "http://explicit:12345" {
		t.Errorf("connectorArg with explicit URL = %q", got)
	}
}
