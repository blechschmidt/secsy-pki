package hsm

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestComputeEntryHash(t *testing.T) {
	// From the YubiHSM gist — verified against real hardware
	prevHash, _ := hex.DecodeString("fc153091560e18bca82621522c85bdba")
	e := AuditLogEntry{
		Number: 3, Command: 0x4f, Length: 5,
		SessionKey: 0x0001, TargetKey: 0xffff, SecondKey: 0xffff,
		Result: 0xcf, Tick: 1987,
	}
	computed := ComputeEntryHash(e, prevHash)
	expected := "3d9380a76ae41826d90daa44c1085a62"
	if computed != expected {
		t.Errorf("hash = %s, want %s", computed, expected)
	}
}

func TestVerifyHashChain(t *testing.T) {
	entries := []AuditLogEntry{
		{Number: 1, Command: 0xff, Length: 0xffff, SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xff, Tick: 0xffffffff, Hash: "33012657537e4842f57fa6ed3b09b25b"},
		{Number: 2, Command: 0x00, Length: 0, SessionKey: 0xffff, TargetKey: 0x0000, SecondKey: 0x0000, Result: 0x00, Tick: 0, Hash: "fc153091560e18bca82621522c85bdba"},
		{Number: 3, Command: 0x4f, Length: 5, SessionKey: 0x0001, TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xcf, Tick: 1987, Hash: "3d9380a76ae41826d90daa44c1085a62"},
		{Number: 4, Command: 0x4f, Length: 4, SessionKey: 0x0001, TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xcf, Tick: 3479, Hash: "43d063d6f0d67b43b87cd67df2f6c2bc"},
	}

	results, err := VerifyHashChain(entries)
	if err != nil {
		t.Fatal(err)
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("entry %d: hash verification failed", i)
		}
	}
}

func TestVerifyHashChainBroken(t *testing.T) {
	entries := []AuditLogEntry{
		{Number: 1, Command: 0xff, Length: 0xffff, SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xff, Tick: 0xffffffff, Hash: "33012657537e4842f57fa6ed3b09b25b"},
		{Number: 2, Command: 0x00, Length: 0, SessionKey: 0xffff, TargetKey: 0x0000, SecondKey: 0x0000, Result: 0x00, Tick: 0, Hash: "0000000000000000aaaaaaaaaaaaaaaa"},
	}
	results, err := VerifyHashChain(entries)
	if err != nil {
		t.Fatal(err)
	}
	if results[1] {
		t.Error("expected entry 1 to fail")
	}
}

func TestVerifyHashChainEmpty(t *testing.T) {
	_, err := VerifyHashChain(nil)
	if err == nil {
		t.Fatal("expected error for empty entries")
	}
}

func TestIsBootSentinel(t *testing.T) {
	boot := AuditLogEntry{
		Number: 1, Command: 0xff, Length: 0xffff,
		SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff,
		Result: 0xff, Tick: 0xffffffff,
	}
	if !IsBootSentinel(boot) {
		t.Error("should be boot sentinel")
	}

	notBoot := boot
	notBoot.Number = 2
	if IsBootSentinel(notBoot) {
		t.Error("number 2 should not be boot sentinel")
	}

	notBoot2 := boot
	notBoot2.Command = 0x00
	if IsBootSentinel(notBoot2) {
		t.Error("cmd 0x00 should not be boot sentinel")
	}
}

func TestCheckDeviceInitEntry(t *testing.T) {
	boot := AuditLogEntry{
		Number: 1, Command: 0xff, Length: 0xffff,
		SessionKey: 0xffff, TargetKey: 0xffff, SecondKey: 0xffff,
		Result: 0xff, Tick: 0xffffffff,
	}
	if err := CheckDeviceInitEntry([]AuditLogEntry{boot}); err != nil {
		t.Errorf("should pass: %v", err)
	}
	if err := CheckDeviceInitEntry(nil); err == nil {
		t.Error("should fail for empty")
	}
	if err := CheckDeviceInitEntry([]AuditLogEntry{{Number: 5}}); err == nil {
		t.Error("should fail for non-boot entry")
	}
}

func TestSignCommandsFixed(t *testing.T) {
	fixed := &AuditOptions{CommandAudit: map[uint8]uint8{
		CmdSignECDSA:             0x02,
		CmdSignEdDSA:             0x02,
		CmdSignRSAPKCS1:          0x02,
		CmdSignRSAPSS:            0x02,
		CmdGenerateAsymmetricKey: 0x02,
	}}
	if !fixed.signCommandsFixed() {
		t.Error("all signing commands at level fixed should pass")
	}

	// A command merely "on" can be switched off again by anyone holding the
	// authentication key, so it must not count as provisioned.
	on := &AuditOptions{CommandAudit: map[uint8]uint8{}}
	for cmd, level := range fixed.CommandAudit {
		on.CommandAudit[cmd] = level
	}
	on.CommandAudit[CmdSignECDSA] = 0x01
	if on.signCommandsFixed() {
		t.Error("a signing command at level on should fail")
	}

	missing := &AuditOptions{CommandAudit: map[uint8]uint8{CmdSignECDSA: 0x02}}
	if missing.signCommandsFixed() {
		t.Error("an options set missing signing commands should fail")
	}
}

func TestAuditOptionsReportNamesUnfixedCommands(t *testing.T) {
	opts := &AuditOptions{
		ForceAudit: 0x01,
		CommandAudit: map[uint8]uint8{
			CmdSignECDSA: 0x02,
			CmdSignEdDSA: 0x00,
			0x07:         0x01, // undocumented on firmware 2.4.0
		},
	}
	report := opts.Report()
	for _, want := range []string{"force-audit: on", "0x6a SIGN EDDSA=off", "0x07 UNDOCUMENTED COMMAND=on"} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not mention %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "0x56") {
		t.Errorf("report should not list the command that is already fixed:\n%s", report)
	}
}

func TestAllCommandsComplete(t *testing.T) {
	// Every command in CryptoCommands must be in AllCommands
	for cmd, name := range CryptoCommands {
		if _, ok := AllCommands[cmd]; !ok {
			t.Errorf("CryptoCommands has %s (0x%02x) but AllCommands does not", name, cmd)
		}
	}
	for cmd, name := range SignCommands {
		if _, ok := CryptoCommands[cmd]; !ok {
			t.Errorf("SignCommands has %s (0x%02x) but CryptoCommands does not", name, cmd)
		}
	}
}

func TestConnectorArg(t *testing.T) {
	cfg := Config{ConnectorURL: "http://test:12345"}
	if got := connectorArg(cfg); got != "http://test:12345" {
		t.Errorf("connectorArg = %q", got)
	}
	// Temporarily unset the env var so the default fallback is tested correctly
	// (TestMain in the yubihsm-tagged file may have set it).
	prev, hadPrev := os.LookupEnv("YUBIHSM_PKCS11_CONF")
	os.Unsetenv("YUBIHSM_PKCS11_CONF")
	defer func() {
		if hadPrev {
			os.Setenv("YUBIHSM_PKCS11_CONF", prev)
		}
	}()
	if got := connectorArg(Config{}); got != "yhusb://" {
		t.Errorf("default connectorArg = %q", got)
	}
}
