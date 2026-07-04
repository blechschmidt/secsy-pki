//go:build !zlint

package certlint

import "testing"

// In the default build the zlint backend is not compiled in: it must report
// unavailable and produce no findings, so the fail-closed gate relies solely on
// the hand-rolled checks and no zlint dependency is linked.

func TestZLintUnavailableInDefaultBuild(t *testing.T) {
	if ZLintAvailable() {
		t.Fatal("ZLintAvailable() = true in the default build; expected false (build with -tags zlint to enable)")
	}
	// A DER that would trip many lints still yields nothing without the backend.
	findings := ZLintFindings([]byte{0x30, 0x00}, ZLintPolicy{})
	if len(findings) != 0 {
		t.Fatalf("ZLintFindings returned %d findings without the backend; want 0", len(findings))
	}
}
