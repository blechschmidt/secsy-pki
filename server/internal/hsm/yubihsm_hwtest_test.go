//go:build yubihsm

package hsm

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var hwCfg Config

func TestMain(m *testing.M) {
	// Write yubihsm_pkcs11.conf so the PKCS#11 module knows how to reach the device.
	confDir, err := os.MkdirTemp("", "yubihsm-hwtest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(confDir)

	confPath := filepath.Join(confDir, "yubihsm_pkcs11.conf")
	confContent := "connector = yhusb://\n"
	if err := os.WriteFile(confPath, []byte(confContent), 0644); err != nil {
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

// retryRunShell retries a runShell call up to 3 times with a short delay,
// working around transient USB contention with the YubiHSM.
func retryRunShell(cfg Config, commands string) (string, error) {
	var out string
	var err error
	for i := 0; i < 3; i++ {
		out, err = runShell(cfg, commands)
		if err == nil {
			return out, nil
		}
		if !strings.Contains(out, "Connector operation failed") {
			return out, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return out, err
}

// ---------------------------------------------------------------------------
// GetDeviceInfo
// ---------------------------------------------------------------------------

func TestGetDeviceInfo(t *testing.T) {
	info, err := GetDeviceInfo(hwCfg)
	if err != nil {
		t.Fatalf("GetDeviceInfo: %v", err)
	}

	if info.Version == "" {
		t.Error("Version is empty")
	}
	t.Logf("Version: %s", info.Version)

	if info.Serial == "" {
		t.Error("Serial is empty")
	}
	t.Logf("Serial: %s", info.Serial)

	if info.LogUsed == "" {
		t.Error("LogUsed is empty")
	}
	t.Logf("LogUsed: %s", info.LogUsed)

	t.Logf("ForceAudit: %v, AuditProvisioned: %v", info.ForceAudit, info.AuditProvisioned)
}

// ---------------------------------------------------------------------------
// GetAuditLog
// ---------------------------------------------------------------------------

func TestGetAuditLog(t *testing.T) {
	// Generate some activity to ensure there are log entries
	_, _ = retryRunShell(hwCfg, "list objects 0")
	_, _ = retryRunShell(hwCfg, "get deviceinfo")

	log, err := GetAuditLog(hwCfg)
	if err != nil {
		t.Skipf("GetAuditLog: %v (audit log may be empty after consumption)", err)
	}

	if log.DeviceSerial == "" {
		t.Error("DeviceSerial is empty")
	}

	if len(log.Entries) == 0 {
		t.Skip("no audit log entries returned (may have been consumed)")
	}

	t.Logf("Got %d audit log entries from device %s", len(log.Entries), log.DeviceSerial)

	// Verify structure of each entry
	for i, e := range log.Entries {
		if e.Hash == "" {
			t.Errorf("entry %d: hash is empty", i)
		}
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
}

// ---------------------------------------------------------------------------
// FetchAndConsumeAuditLog
// ---------------------------------------------------------------------------

func TestFetchAndConsumeAuditLog(t *testing.T) {
	// Generate some activity first
	_, _ = retryRunShell(hwCfg, "list objects 0")

	entries, err := FetchAndConsumeAuditLog(hwCfg)
	if err != nil {
		t.Fatalf("FetchAndConsumeAuditLog: %v", err)
	}

	t.Logf("FetchAndConsumeAuditLog returned %d entries", len(entries))

	if entries != nil {
		for i, e := range entries {
			if e.Hash == "" {
				t.Errorf("entry %d: hash is empty", i)
			}
			if _, err := hex.DecodeString(e.Hash); err != nil {
				t.Errorf("entry %d: invalid hash hex: %v", i, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// ParseAuditLogOutput - with real output format
// ---------------------------------------------------------------------------

func TestParseAuditLogOutput_RealDevice(t *testing.T) {
	// Generate some activity first
	_, _ = retryRunShell(hwCfg, "list objects 0")
	_, _ = retryRunShell(hwCfg, "get deviceinfo")

	out, err := retryRunShell(hwCfg, "audit get 0")
	if err != nil {
		t.Fatalf("runShell audit get: %v", err)
	}
	t.Logf("Raw audit output:\n%s", out)

	entries, err := ParseAuditLogOutput(out)
	if err != nil {
		t.Skipf("no entries in audit output (may have been consumed): %v", err)
	}

	if len(entries) == 0 {
		t.Skip("no entries from real device (log may be empty)")
	}

	t.Logf("Parsed %d entries from real device output", len(entries))

	// Verify entries are numbered sequentially (may not start at 1 if consumed)
	for i := 1; i < len(entries); i++ {
		if entries[i].Number != entries[i-1].Number+1 {
			t.Errorf("entries not sequential: entry[%d].Number=%d, entry[%d].Number=%d",
				i-1, entries[i-1].Number, i, entries[i].Number)
		}
	}
}

// ---------------------------------------------------------------------------
// ComputeEntryHash / VerifyHashChain - with entries from real device
// ---------------------------------------------------------------------------

func TestVerifyHashChain_RealDevice(t *testing.T) {
	// Generate activity to ensure entries exist
	_, _ = retryRunShell(hwCfg, "list objects 0")
	_, _ = retryRunShell(hwCfg, "get deviceinfo")

	log, err := GetAuditLog(hwCfg)
	if err != nil {
		t.Skipf("GetAuditLog: %v (audit log may be empty)", err)
	}

	if len(log.Entries) < 2 {
		t.Skip("need at least 2 entries to verify hash chain")
	}

	results, err := VerifyHashChain(log.Entries)
	if err != nil {
		t.Fatalf("VerifyHashChain: %v", err)
	}

	allPass := true
	for i, ok := range results {
		if !ok {
			t.Errorf("entry %d (Number=%d, Command=0x%02x): hash chain verification FAILED",
				i, log.Entries[i].Number, log.Entries[i].Command)
			allPass = false
		}
	}
	if allPass {
		t.Logf("all %d entries passed hash chain verification", len(results))
	}

	// Also test ComputeEntryHash individually for a non-anchor entry
	prevHash, err := hex.DecodeString(log.Entries[0].Hash)
	if err != nil {
		t.Fatalf("decode prev hash: %v", err)
	}
	computed := ComputeEntryHash(log.Entries[1], prevHash)
	if computed != log.Entries[1].Hash {
		t.Errorf("ComputeEntryHash mismatch: computed=%s actual=%s", computed, log.Entries[1].Hash)
	} else {
		t.Logf("ComputeEntryHash matched for entry %d", log.Entries[1].Number)
	}
}

// ---------------------------------------------------------------------------
// GetKeyAttestationCert
// ---------------------------------------------------------------------------

func TestGetKeyAttestationCert(t *testing.T) {
	out, err := retryRunShell(hwCfg, "list objects 0")
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}

	// Find an asymmetric key with a unique label (appears only once).
	// The regex used by GetKeyAttestationCert matches labels in the listing,
	// so we need a label that uniquely identifies one key.
	re := regexp.MustCompile(`id:\s+0x([0-9a-fA-F]+),\s+type:\s+asymmetric-key,.*label:\s+(.+)`)
	matches := re.FindAllStringSubmatch(out, -1)

	// Count label occurrences and prefer short, unique labels
	labelCount := make(map[string]int)
	for _, m := range matches {
		label := strings.TrimSpace(m[2])
		labelCount[label]++
	}

	var keyLabel string
	// First pass: prefer unique, short labels without test prefixes
	for _, m := range matches {
		candidate := strings.TrimSpace(m[2])
		if labelCount[candidate] == 1 && !strings.HasPrefix(candidate, "Test") &&
			!strings.HasPrefix(candidate, "t_") && len(candidate) < 30 {
			keyLabel = candidate
			break
		}
	}
	// Second pass: any unique label
	if keyLabel == "" {
		for _, m := range matches {
			candidate := strings.TrimSpace(m[2])
			if labelCount[candidate] == 1 {
				keyLabel = candidate
				break
			}
		}
	}

	if keyLabel == "" {
		t.Skip("no asymmetric key with unique label found on HSM for attestation test")
	}

	t.Logf("Testing attestation for key label: %q", keyLabel)

	cert, err := GetKeyAttestationCert(hwCfg, keyLabel)
	if err != nil {
		t.Fatalf("GetKeyAttestationCert(%q): %v", keyLabel, err)
	}

	if !strings.Contains(cert, "-----BEGIN CERTIFICATE-----") {
		t.Error("attestation cert missing PEM header")
	}
	if !strings.Contains(cert, "-----END CERTIFICATE-----") {
		t.Error("attestation cert missing PEM footer")
	}
	t.Logf("Got attestation cert (%d bytes) for key %q", len(cert), keyLabel)
}

// ---------------------------------------------------------------------------
// GetDeviceSerial
// ---------------------------------------------------------------------------

func TestGetDeviceSerial(t *testing.T) {
	var serial string
	var err error
	for i := 0; i < 5; i++ {
		serial, err = GetDeviceSerial(hwCfg)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GetDeviceSerial: %v", err)
	}
	if serial == "" {
		t.Error("serial is empty")
	}
	for _, c := range serial {
		if c < '0' || c > '9' {
			t.Errorf("serial contains non-digit: %q", serial)
			break
		}
	}
	t.Logf("Device serial: %s", serial)
}

// ---------------------------------------------------------------------------
// TestConnectorArg_WithEnv verifies the env-based connector lookup that
// is active when TestMain sets YUBIHSM_PKCS11_CONF.
// ---------------------------------------------------------------------------

func TestConnectorArg_WithEnv(t *testing.T) {
	// The conf file set by TestMain has "connector = yhusb://"
	got := connectorArg(Config{})
	if got != "yhusb://" {
		t.Errorf("connectorArg with env conf = %q, want yhusb://", got)
	}

	// With explicit ConnectorURL, it should take priority
	got = connectorArg(Config{ConnectorURL: "http://explicit:12345"})
	if got != "http://explicit:12345" {
		t.Errorf("connectorArg with explicit URL = %q", got)
	}
}
