package hsm

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestParseAuditLogOutput(t *testing.T) {
	output := `Session keepalive set up to run every 15 seconds
Created session 0
0 unlogged boots found
0 unlogged authentications found
Found 3 items
item:     1 -- cmd: 0xff -- length: 65535 -- session key: 0xffff -- target key: 0xffff -- second key: 0xffff -- result: 0xff -- tick: 4294967295 -- hash: 33012657537e4842f57fa6ed3b09b25b
item:     2 -- cmd: 0x00 -- length:    0 -- session key: 0xffff -- target key: 0x0000 -- second key: 0x0000 -- result: 0x00 -- tick: 0 -- hash: fc153091560e18bca82621522c85bdba
item:     3 -- cmd: 0x4f -- length:    5 -- session key: 0x0001 -- target key: 0xffff -- second key: 0xffff -- result: 0xcf -- tick: 1987 -- hash: 3d9380a76ae41826d90daa44c1085a62`

	entries, err := ParseAuditLogOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	e := entries[0]
	if e.Number != 1 || e.Command != 0xff || e.Length != 65535 || e.SessionKey != 0xffff {
		t.Errorf("entry 0: %+v", e)
	}
	if e.Hash != "33012657537e4842f57fa6ed3b09b25b" {
		t.Errorf("entry 0 hash: %s", e.Hash)
	}

	e = entries[2]
	if e.Number != 3 || e.Command != 0x4f || e.Length != 5 || e.Tick != 1987 {
		t.Errorf("entry 2: %+v", e)
	}
}

func TestParseAuditLogOutputEmpty(t *testing.T) {
	_, err := ParseAuditLogOutput("No logs to extract")
	if err == nil {
		t.Fatal("expected error")
	}
}

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

func TestCheckSignCommandsAudited(t *testing.T) {
	// Build a hex string with all required commands set to 0x02
	required := []byte{
		CmdSignECDSA, 0x02,
		CmdSignEdDSA, 0x02,
		CmdSignRSAPKCS1, 0x02,
		CmdSignRSAPSS, 0x02,
		CmdGenerateAsymmetricKey, 0x02,
	}
	if !checkSignCommandsAudited(hex.EncodeToString(required)) {
		t.Error("should pass with all required commands audited")
	}

	// Missing one
	partial := []byte{
		CmdSignECDSA, 0x02,
		CmdSignEdDSA, 0x02,
	}
	if checkSignCommandsAudited(hex.EncodeToString(partial)) {
		t.Error("should fail with missing commands")
	}

	// Invalid hex
	if checkSignCommandsAudited("zzzz") {
		t.Error("should fail for invalid hex")
	}

	// Odd length
	if checkSignCommandsAudited("abc") {
		t.Error("should fail for odd length")
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

func TestExtractPEM(t *testing.T) {
	input := `some output
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
more output`
	result := extractPEM(input)
	if result != "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----" {
		t.Errorf("extractPEM = %q", result)
	}
	if extractPEM("no cert here") != "" {
		t.Error("should return empty for no PEM")
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
	if got := connectorArg(Config{}); got != "http://localhost:12345" {
		t.Errorf("default connectorArg = %q", got)
	}
}
