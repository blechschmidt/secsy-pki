//go:build sqlite

package doctor_test

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
)

// TestDoctorTrustedTimeSkippedByDefault confirms the time.trusted check is a
// no-op skip when no external time source is configured (the zero-config
// host-clock default), so it never affects existing deployments.
func TestDoctorTrustedTimeSkippedByDefault(t *testing.T) {
	f := newFixture(t, "")
	r := f.run(t, doctor.Options{})
	assertStatus(t, r, "time.trusted", doctor.StatusSkip)
}

// TestDoctorTrustedTimeUnreachableFails wires an NTS source at a loopback port
// with nothing listening: the live probe cannot reach it, and under the default
// fail-closed policy the check fails — the same condition that would make the
// TSA refuse to sign, surfaced before the first rejected timestamp.
func TestDoctorTrustedTimeUnreachableFails(t *testing.T) {
	f := newFixture(t, "time:\n  source:\n    type: nts\n    timeout: 300ms\n    servers:\n      - address: 127.0.0.1:4460\n")
	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "time.trusted", doctor.StatusFail)
	if c.Detail == "" {
		t.Fatal("expected a detail explaining the unreachable time source")
	}
}
