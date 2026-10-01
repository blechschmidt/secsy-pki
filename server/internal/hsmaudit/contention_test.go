package hsmaudit

import (
	"errors"
	"strings"
	"testing"
)

// The contention check decides whether a server starts, so both directions of
// the verdict matter equally: a missed conflict ships a deployment that cannot
// drain, and a spurious one refuses to boot a deployment that can.
//
// The cases are the configurations hardware actually distinguishes. A direct-USB
// drain alongside Yubico's PKCS#11 module was measured to fail with EBUSY on
// the attached device; the same pair over an http:// connector was measured to
// succeed with a module session open. See
// internal/yubihsmtest/steady_state_test.go, which pins both on hardware.
func TestDrainContention(t *testing.T) {
	const module = "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
	for _, tc := range []struct {
		name     string
		url      string
		module   string
		conflict bool
	}{
		{
			name:     "an unset connector is direct USB and conflicts",
			url:      "",
			module:   module,
			conflict: true,
		},
		{
			name:     "bare yhusb conflicts",
			url:      "yhusb://",
			module:   module,
			conflict: true,
		},
		{
			name:     "a serial-qualified yhusb conflicts too",
			url:      "yhusb://serial=31650425",
			module:   module,
			conflict: true,
		},
		{
			name:   "an http connector multiplexes the device",
			url:    "http://127.0.0.1:12345",
			module: module,
		},
		{
			name:   "an https connector likewise",
			url:    "https://hsm.internal:12345",
			module: module,
		},
		{
			// A cloud-KMS or software-backed signing path claims no USB
			// interface, so direct USB is the right transport for it.
			name:   "direct USB with no PKCS#11 signing path is fine",
			url:    "yhusb://",
			module: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := DrainContention(tc.url, tc.module)
			if tc.conflict != (err != nil) {
				t.Fatalf("DrainContention(%q, %q) = %v, want conflict=%v", tc.url, tc.module, err, tc.conflict)
			}
			if !tc.conflict {
				return
			}
			if !errors.Is(err, ErrDrainContention) {
				t.Errorf("the diagnosis does not unwrap to ErrDrainContention, so callers cannot "+
					"distinguish it from an unreachable device: %v", err)
			}
			// The whole point of detecting this at startup is that the operator
			// learns what to do. A diagnosis that does not name the remedy is
			// no better than the EBUSY it replaces.
			for _, want := range []string{"yubihsm-connector", "connector_url", tc.module} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the diagnosis never mentions %q:\n%v", want, err)
				}
			}
		})
	}
}

// An unset connector URL has to be reported as what it resolves to, not as an
// empty string: "the audit driver addresses the device over """ tells an
// operator nothing about why their configuration is wrong.
func TestDrainContentionNamesTheDefaultTransport(t *testing.T) {
	err := DrainContention("", "/usr/lib/pkcs11/yubihsm_pkcs11.so")
	if err == nil {
		t.Fatal("an unset connector URL with the YubiHSM module is the conflicting case")
	}
	if !strings.Contains(err.Error(), "yhusb://") {
		t.Errorf("the diagnosis does not say that an unset connector URL means direct USB:\n%v", err)
	}
}
