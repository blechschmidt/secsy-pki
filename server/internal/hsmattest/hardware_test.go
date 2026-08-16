//go:build yubihsm

// Hardware validation for YubiHSM key attestation (Task 168). These tests
// require a real YubiHSM 2 reachable over the connector in YUBIHSM_CONNECTOR
// (default yhusb://, direct USB) and are excluded from the normal build.
//
// Run with:
//
//	go test -tags yubihsm ./internal/hsmattest/ -v
//
// They create and delete scratch objects at 0x7e5a..0x7e5c. Nothing else on the
// device is touched, but do not point them at a production HSM.
//
// The two negative cases are the reason this file exists. Everything about the
// exportability verdict rests on one capability bit and one origin bit, and
// neither can be exercised by a fixture that was captured from a well-behaved
// key — the encoding has to be observed on a key that really is exportable, and
// on one that really was imported, or the test only proves the parser agrees
// with itself.
package hsmattest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

const (
	scratchGenerated  = 0x7e5a
	scratchExportable = 0x7e5b
	scratchImported   = 0x7e5c
)

func hwConfig(t *testing.T) hsm.Config {
	t.Helper()
	if _, err := exec.LookPath("yubihsm-shell"); err != nil {
		t.Skip("yubihsm-shell not installed")
	}
	connector := os.Getenv("YUBIHSM_CONNECTOR")
	if connector == "" {
		connector = "yhusb://"
	}
	cfg := hsm.Config{ConnectorURL: connector, AuthKeyID: 1, Password: "password"}
	if pw := os.Getenv("YUBIHSM_PASSWORD"); pw != "" {
		cfg.Password = pw
	}
	if _, err := hsm.GetDeviceInfo(cfg); err != nil {
		t.Skipf("no YubiHSM reachable at %s: %v", connector, err)
	}
	return cfg
}

// shell runs one yubihsm-shell script against the device.
func shell(t *testing.T, cfg hsm.Config, command string) string {
	t.Helper()
	script := fmt.Sprintf("connect\nsession open %d %s\n%s\nsession close 0\nexit\n",
		cfg.AuthKeyID, cfg.Password, command)
	cmd := exec.Command("yubihsm-shell", "-C", cfg.ConnectorURL)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("yubihsm-shell %q: %v\n%s", command, err, out)
	}
	return string(out)
}

// generateScratch creates a scratch asymmetric key with the given capabilities
// and removes it when the test ends.
func generateScratch(t *testing.T, cfg hsm.Config, id int, label, capabilities string) {
	t.Helper()
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", id)) // best effort
	shell(t, cfg, fmt.Sprintf("generate asymmetric 0 0x%04x %s 1 %s ecp256", id, label, capabilities))
	t.Cleanup(func() {
		shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", id))
	})
}

// TestHardwareAttestGeneratedKey pins the happy path: a key generated on the
// device with only a signing capability attests as non-exportable and
// on-device-generated, and its attestation is signed by the device certificate.
func TestHardwareAttestGeneratedKey(t *testing.T) {
	cfg := hwConfig(t)
	generateScratch(t, cfg, scratchGenerated, "t168-hw-generated", "sign-ecdsa")

	att, err := NewShellAttester(cfg).AttestKey(context.Background(), "t168-hw-generated")
	if err != nil {
		t.Fatalf("AttestKey: %v", err)
	}
	if att.DeviceCertificatePEM == "" {
		t.Error("attestation carries no device certificate; offline verification would be impossible")
	}

	// Device binding is required; chain anchoring is not, because Yubico does
	// not publish the per-batch sub-CA for every device generation.
	res := Verify(att, DefaultPolicy())
	if !res.Verified {
		t.Fatalf("Verified = false: %v", res.Problems)
	}
	if !res.NonExportable {
		t.Error("NonExportable = false for a key without exportable-under-wrap")
	}
	if !res.GeneratedOnDevice {
		t.Errorf("GeneratedOnDevice = false; origin was %q", res.Origin)
	}
	if !res.DeviceBound {
		t.Error("DeviceBound = false; the device certificate should issue the attestation")
	}
	if !res.CanSign {
		t.Error("CanSign = false for a sign-ecdsa key")
	}
	if got := strings.Join(res.Capabilities, ","); got != "sign-ecdsa" {
		t.Errorf("capabilities = %q, want sign-ecdsa", got)
	}
	if res.ObjectID != scratchGenerated {
		t.Errorf("ObjectID = 0x%04x, want 0x%04x", res.ObjectID, scratchGenerated)
	}
	if res.DeviceSerial == "" || res.FirmwareVersion == "" {
		t.Errorf("device identity incomplete: serial=%q firmware=%q", res.DeviceSerial, res.FirmwareVersion)
	}
}

// TestHardwareAttestExportableKey is the case the feature exists to catch: a
// key that really can be exported from the device must not verify.
func TestHardwareAttestExportableKey(t *testing.T) {
	cfg := hwConfig(t)
	generateScratch(t, cfg, scratchExportable, "t168-hw-exportable", "sign-ecdsa:exportable-under-wrap")

	att, err := NewShellAttester(cfg).AttestKey(context.Background(), "t168-hw-exportable")
	if err != nil {
		t.Fatalf("AttestKey: %v", err)
	}
	res := Verify(att, DefaultPolicy())

	if res.Verified {
		t.Fatal("Verified = true for a key holding exportable-under-wrap")
	}
	if res.NonExportable {
		t.Error("NonExportable = true for a key holding exportable-under-wrap")
	}
	if !containsSubstr(res.Problems, "exportable-under-wrap") {
		t.Errorf("problems = %v, want the exportability failure", res.Problems)
	}
	// The capability must be named, not merely counted: an operator reading the
	// report needs to know which capability made the key extractable.
	found := false
	for _, c := range res.Capabilities {
		if c == "exportable-under-wrap" {
			found = true
		}
	}
	if !found {
		t.Errorf("capabilities = %v, want exportable-under-wrap listed", res.Capabilities)
	}
}

// TestHardwareAttestImportedKey pins the origin bit. Non-exportability alone is
// not enough: a key that was imported existed outside the device first, so the
// attestation must say so.
func TestHardwareAttestImportedKey(t *testing.T) {
	cfg := hwConfig(t)

	keyPath := t.TempDir() + "/imported.pem"
	gen := exec.Command("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", keyPath)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("openssl unavailable: %v\n%s", err, out)
	}
	shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", scratchImported))
	shell(t, cfg, fmt.Sprintf("put asymmetric 0 0x%04x t168-hw-imported 1 sign-ecdsa %s", scratchImported, keyPath))
	t.Cleanup(func() {
		shell(t, cfg, fmt.Sprintf("delete 0 0x%04x asymmetric-key", scratchImported))
	})

	att, err := NewShellAttester(cfg).AttestKey(context.Background(), "t168-hw-imported")
	if err != nil {
		t.Fatalf("AttestKey: %v", err)
	}
	res := Verify(att, DefaultPolicy())

	if res.Verified {
		t.Fatal("Verified = true for an imported key")
	}
	if res.GeneratedOnDevice {
		t.Error("GeneratedOnDevice = true for an imported key")
	}
	if got := res.Origin; got != "imported" {
		t.Errorf("Origin = %q, want %q", got, "imported")
	}
	// It is still non-exportable, which is precisely why the origin check has to
	// be separate: reporting only exportability would call this key safe.
	if !res.NonExportable {
		t.Error("NonExportable = false; the imported key was given no export capability")
	}
}

// TestHardwareExactLabelResolution pins the fix for prefix matching: a label
// that is a prefix of another must resolve to its own key, not the other one.
func TestHardwareExactLabelResolution(t *testing.T) {
	cfg := hwConfig(t)
	generateScratch(t, cfg, scratchGenerated, "t168-hw-pref", "sign-ecdsa")
	generateScratch(t, cfg, scratchExportable, "t168-hw-pref-longer", "sign-ecdsa")

	id, err := hsm.FindAsymmetricKey(cfg, "t168-hw-pref")
	if err != nil {
		t.Fatalf("FindAsymmetricKey: %v", err)
	}
	if id != scratchGenerated {
		t.Errorf("resolved 0x%04x, want 0x%04x — a prefix match picked the wrong key", id, scratchGenerated)
	}

	if _, err := hsm.FindAsymmetricKey(cfg, "t168-hw-nonexistent"); err == nil {
		t.Error("FindAsymmetricKey accepted a label no object carries")
	}
}
