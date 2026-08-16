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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

const (
	scratchGenerated  = 0x7e5a
	scratchExportable = 0x7e5b
	scratchImported   = 0x7e5c
)

func hwConfig(t *testing.T) hsm.Config {
	t.Helper()
	connector := os.Getenv("YUBIHSM_CONNECTOR")
	if connector == "" {
		connector = "yhusb://"
	}
	cfg := hsm.Config{ConnectorURL: connector, AuthKeyID: 1, Password: "password"}
	if pw := os.Getenv("YUBIHSM_PASSWORD"); pw != "" {
		cfg.Password = pw
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := hsm.GetDeviceInfo(ctx, cfg); err != nil {
		t.Skipf("no YubiHSM reachable at %s: %v", connector, err)
	}
	return cfg
}

// onDevice runs fn against an authenticated session, using the same native
// driver the production code path uses rather than a second mechanism whose
// disagreement with it would be invisible.
func onDevice(t *testing.T, cfg hsm.Config, fn func(ctx context.Context, c *yubihsm.Client)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := yubihsm.Open(ctx, yubihsm.Config{
		ConnectorURL: cfg.ConnectorURL,
		AuthKeyID:    uint16(cfg.AuthKeyID),
		Password:     cfg.Password,
	})
	if err != nil {
		t.Fatalf("opening a YubiHSM session: %v", err)
	}
	defer func() { _ = c.Close() }()
	fn(ctx, c)
}

func capabilityMask(t *testing.T, names ...string) uint64 {
	t.Helper()
	mask, err := ParseCapabilityNames(names)
	if err != nil {
		t.Fatalf("capability names %v: %v", names, err)
	}
	return uint64(mask)
}

func deleteScratch(t *testing.T, cfg hsm.Config, id uint16) {
	t.Helper()
	onDevice(t, cfg, func(ctx context.Context, c *yubihsm.Client) {
		// Best effort: the object usually does not exist yet.
		_ = c.DeleteObject(ctx, id, yubihsm.ObjectTypeAsymmetricKey)
	})
}

// generateScratch creates a scratch asymmetric key with the given capabilities
// and removes it when the test ends.
func generateScratch(t *testing.T, cfg hsm.Config, id uint16, label string, capabilities ...string) {
	t.Helper()
	mask := capabilityMask(t, capabilities...)
	deleteScratch(t, cfg, id)
	onDevice(t, cfg, func(ctx context.Context, c *yubihsm.Client) {
		if _, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
			ID:           id,
			Label:        label,
			Domains:      1,
			Capabilities: mask,
			Algorithm:    yubihsm.AlgorithmECP256,
		}); err != nil {
			t.Fatalf("generating scratch key %q: %v", label, err)
		}
	})
	t.Cleanup(func() { deleteScratch(t, cfg, id) })
}

// importScratch imports a P-256 key generated on this host, so the device
// records its origin as imported.
func importScratch(t *testing.T, cfg hsm.Config, id uint16, label string, capabilities ...string) {
	t.Helper()
	mask := capabilityMask(t, capabilities...)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a host key: %v", err)
	}
	// The device expects the raw private scalar, left-padded to the curve length.
	scalar := make([]byte, 32)
	key.D.FillBytes(scalar)

	deleteScratch(t, cfg, id)
	onDevice(t, cfg, func(ctx context.Context, c *yubihsm.Client) {
		if _, err := c.PutAsymmetricKey(ctx, yubihsm.KeySpec{
			ID:           id,
			Label:        label,
			Domains:      1,
			Capabilities: mask,
			Algorithm:    yubihsm.AlgorithmECP256,
		}, scalar); err != nil {
			t.Fatalf("importing scratch key %q: %v", label, err)
		}
	})
	t.Cleanup(func() { deleteScratch(t, cfg, id) })
}

// TestHardwareAttestGeneratedKey pins the happy path: a key generated on the
// device with only a signing capability attests as non-exportable and
// on-device-generated, and its attestation is signed by the device certificate.
func TestHardwareAttestGeneratedKey(t *testing.T) {
	cfg := hwConfig(t)
	generateScratch(t, cfg, scratchGenerated, "t168-hw-generated", "sign-ecdsa")

	att, err := NewDeviceAttester(cfg).AttestKey(context.Background(), "t168-hw-generated")
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
	generateScratch(t, cfg, scratchExportable, "t168-hw-exportable", "sign-ecdsa", "exportable-under-wrap")

	att, err := NewDeviceAttester(cfg).AttestKey(context.Background(), "t168-hw-exportable")
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

	importScratch(t, cfg, scratchImported, "t168-hw-imported", "sign-ecdsa")

	att, err := NewDeviceAttester(cfg).AttestKey(context.Background(), "t168-hw-imported")
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

	id, err := hsm.FindAsymmetricKey(context.Background(), cfg, "t168-hw-pref")
	if err != nil {
		t.Fatalf("FindAsymmetricKey: %v", err)
	}
	if id != scratchGenerated {
		t.Errorf("resolved 0x%04x, want 0x%04x — a prefix match picked the wrong key", id, scratchGenerated)
	}

	if _, err := hsm.FindAsymmetricKey(context.Background(), cfg, "t168-hw-nonexistent"); err == nil {
		t.Error("FindAsymmetricKey accepted a label no object carries")
	}
}
