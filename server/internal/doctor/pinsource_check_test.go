package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

func findResult(t *testing.T, r *Report, name string) Result {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %+v", name, r.Checks)
	return Result{}
}

// pkcs11Cfg is a minimal config whose CA role uses the PKCS#11 backend, enough to
// make the pin.source check apply. It configures the given pin_source.
func pkcs11Cfg(ps config.PinSourceConfig) *config.Config {
	return &config.Config{
		KeyProvider: config.KeyProviderConfig{Type: "pkcs11"},
		PKCS11:      config.PKCS11Config{ModulePath: "/x/module.so", PinSource: ps},
	}
}

// buildFrom mirrors what the command injects: map the config pin_source onto
// keyprovider settings and construct the named sources.
func buildFrom(cfg *config.Config) ([]keyprovider.NamedPinSource, error) {
	p := cfg.PKCS11.PinSource
	return keyprovider.BuildNamedPinSources(keyprovider.PKCS11Settings{
		ModulePath: cfg.PKCS11.ModulePath,
		Pin:        cfg.PKCS11.Pin,
		PinSource: keyprovider.PinSourceSettings{
			Type: p.Type,
			File: keyprovider.FilePinSourceSettings{Path: p.File.Path, AllowInsecurePerms: p.File.AllowInsecurePerms},
		},
	})
}

func writeSecurePin(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	return p
}

func TestCheckPinSourceReachable(t *testing.T) {
	cfg := pkcs11Cfg(config.PinSourceConfig{Type: "file", File: config.FilePinSourceConfig{Path: writeSecurePin(t, "1234")}})
	r := &Report{OK: true}
	checkPinSources(context.Background(), r, cfg, Options{BuildPinSources: buildFrom})

	res := findResult(t, r, "pin.source")
	if res.Status != StatusPass {
		t.Fatalf("want pass, got %s: %s", res.Status, res.Detail)
	}
	// The detail must describe the source but never leak the PIN.
	if strings.Contains(res.Detail, "1234") {
		t.Errorf("pin.source detail leaks the PIN: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "file ") {
		t.Errorf("pin.source detail lacks source description: %s", res.Detail)
	}
}

func TestCheckPinSourceUnreachableFailsClosed(t *testing.T) {
	// A file source pointing at a missing file resolves to an error → FAIL.
	cfg := pkcs11Cfg(config.PinSourceConfig{Type: "file", File: config.FilePinSourceConfig{Path: filepath.Join(t.TempDir(), "absent")}})
	r := &Report{OK: true}
	checkPinSources(context.Background(), r, cfg, Options{BuildPinSources: buildFrom})

	res := findResult(t, r, "pin.source")
	if res.Status != StatusFail {
		t.Fatalf("want fail, got %s: %s", res.Status, res.Detail)
	}
	if r.OK {
		t.Error("a failed check must clear Report.OK")
	}
}

func TestCheckPinSourceInsecurePermsFailsClosed(t *testing.T) {
	p := writeSecurePin(t, "1234")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := pkcs11Cfg(config.PinSourceConfig{Type: "file", File: config.FilePinSourceConfig{Path: p}})
	r := &Report{OK: true}
	checkPinSources(context.Background(), r, cfg, Options{BuildPinSources: buildFrom})

	res := findResult(t, r, "pin.source")
	if res.Status != StatusFail || !strings.Contains(res.Detail, "insecure permissions") {
		t.Fatalf("want fail on insecure perms, got %s: %s", res.Status, res.Detail)
	}
}

func TestCheckPinSourceInlineSkips(t *testing.T) {
	cfg := pkcs11Cfg(config.PinSourceConfig{}) // inline (no external source)
	cfg.PKCS11.Pin = "inlinepin"
	r := &Report{OK: true}
	checkPinSources(context.Background(), r, cfg, Options{BuildPinSources: buildFrom})

	res := findResult(t, r, "pin.source")
	if res.Status != StatusSkip {
		t.Fatalf("want skip for inline PIN, got %s: %s", res.Status, res.Detail)
	}
}

func TestCheckPinSourceNonPKCS11Skips(t *testing.T) {
	cfg := &config.Config{KeyProvider: config.KeyProviderConfig{Type: "software"}}
	r := &Report{OK: true}
	checkPinSources(context.Background(), r, cfg, Options{BuildPinSources: buildFrom})

	res := findResult(t, r, "pin.source")
	if res.Status != StatusSkip {
		t.Fatalf("want skip for non-pkcs11 backend, got %s: %s", res.Status, res.Detail)
	}
}
