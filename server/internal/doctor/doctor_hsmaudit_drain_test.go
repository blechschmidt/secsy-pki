//go:build sqlite

// HSM audit-drain diagnostics.
//
// Every other HSM-audit check in the preflight reads state that only exists if
// collection already worked: the pinned anchor, the stored chain, the signature
// ledger, the freshness token. A deployment where collection can *never* work
// therefore shows no symptom in any of them — it simply has nothing yet — and
// the first sign of trouble is a device that stops signing once its 62-entry
// log fills. This check is the one that can see that coming, from the
// configuration alone.
package doctor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
)

// yubiHSMRoleConfig puts the TSA signing role on Yubico's PKCS#11 module.
//
// The leading indentation continues the fixture's own key_provider mapping,
// which is where a per-role override has to live.
//
// The module path deliberately does not exist. The check under test reasons
// about the filename — that is the evidence available for which device a module
// drives — and a path to the real module would have the fixture's provider
// check load it and claim the USB interface of whatever YubiHSM is plugged into
// the machine running the unit suite.
const yubiHSMRoleConfig = `  roles:
    tsa: pkcs11
pkcs11:
  module_path: /nonexistent/pkcs11/yubihsm_pkcs11.so
  token_label: YubiHSM
`

// commissionDevice pins an audit state, which is what makes an undrainable
// device consequential rather than merely theoretical.
func commissionDevice(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.db.SaveAuditState(context.Background(), &hsmaudit.AuditState{
		DeviceSerial:  "31650425",
		Anchor:        "27caf4edc279c4b514bfc61fc6638677",
		ProvisionedAt: time.Now().UTC(),
		Tail:          hsmaudit.Tail{Number: 1, Digest: "27caf4edc279c4b514bfc61fc6638677"},
	}); err != nil {
		t.Fatalf("pinning the audit state: %v", err)
	}
}

// The default deployment has no commissioned device, so the check must report
// "not applicable" rather than a finding: there is no device log to lose.
func TestDoctorHSMAuditDrainSkippedWithoutACommissionedDevice(t *testing.T) {
	f := newFixture(t, "")
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusSkip)
	if !strings.Contains(res.Detail, "hsm-audit provision") {
		t.Errorf("the skip reason does not say how a device is commissioned: %q", res.Detail)
	}
}

// A software-backed signing path claims no USB interface, so direct USB is the
// right transport for it and the check must not manufacture a finding.
func TestDoctorHSMAuditDrainPassesWithNoCompetingSigningPath(t *testing.T) {
	f := newFixture(t, "")
	commissionDevice(t, f)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusPass)
	if !strings.Contains(res.Detail, "31650425") {
		t.Errorf("the detail does not name the commissioned device: %q", res.Detail)
	}
}

// The finding itself: a commissioned device reached over direct USB while the
// signing path drives it through Yubico's PKCS#11 module, with the in-process
// relay explicitly turned off. Nothing in this deployment can ever drain the
// device log.
//
// The relay has to be turned off for the finding to exist, because this is the
// configuration it is on by default for — which is the point of it. An operator
// who disabled it is running Yubico's daemon, and if they have not pointed
// connector_url at one, this is the check that says so.
func TestDoctorHSMAuditDrainFailsOnUSBContention(t *testing.T) {
	f := newFixture(t, yubiHSMRoleConfig+`yubihsm:
  embedded_connector:
    enabled: false
`)
	commissionDevice(t, f)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusFail)
	// Both remedies and the module at fault: a finding that does not name what
	// to do is no better than the EBUSY it replaces.
	for _, want := range []string{"embedded_connector", "yubihsm-connector", "yubihsm_pkcs11.so"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("the finding does not mention %q, so it does not tell the operator what to do: %q", want, res.Detail)
		}
	}
}

// The same deployment with the relay left at its default: the server will
// multiplex the device itself, so there is nothing to report.
//
// The doctor runs in the operator's own process, where no relay is listening,
// so this verdict can only come from the configuration — and it has to match
// the one the server will reach from the same configuration, or a preflight
// check is worse than none.
func TestDoctorHSMAuditDrainPassesWithTheEmbeddedConnector(t *testing.T) {
	f := newFixture(t, yubiHSMRoleConfig)
	commissionDevice(t, f)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusPass)
	for _, want := range []string{"multiplexes", "http://127.0.0.1:12345"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("the detail does not say the device is multiplexed in-process (%q): %q", want, res.Detail)
		}
	}
}

// And a configuration that asks for a relay it cannot have is a finding too: a
// relay can only serve the host its USB device is attached to, so naming
// another host is a mistake that would otherwise silently leave the device
// undrainable.
func TestDoctorHSMAuditDrainFailsOnAnImpossibleRelay(t *testing.T) {
	f := newFixture(t, yubiHSMRoleConfig+`yubihsm:
  connector_url: http://hsm.example.internal:12345
  embedded_connector:
    enabled: true
`)
	commissionDevice(t, f)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusFail)
	if !strings.Contains(res.Detail, "can only serve a local address") {
		t.Errorf("the finding does not explain why the relay cannot serve that URL: %q", res.Detail)
	}
}

// With Yubico's daemon in front of the device both paths reach it over HTTP,
// which is the other supported configuration and must report clean.
func TestDoctorHSMAuditDrainPassesThroughAConnector(t *testing.T) {
	f := newFixture(t, yubiHSMRoleConfig+`yubihsm:
  connector_url: http://127.0.0.1:12345
`)
	commissionDevice(t, f)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "hsmaudit.drain", doctor.StatusPass)
	if !strings.Contains(res.Detail, "http://127.0.0.1:12345") {
		t.Errorf("the detail does not name the shared connector: %q", res.Detail)
	}
}
