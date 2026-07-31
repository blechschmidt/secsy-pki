package ratelimit

import (
	"net/http/httptest"
	"testing"
)

// TestClassifyMSWSTEP verifies the Microsoft autoenrollment endpoints are
// classified for metering: the CES enrollment endpoint is HSM-bound and
// tenant-scoped (it signs), while the CEP policy endpoint is metered and
// tenant-scoped but not HSM-bound (it never signs).
func TestClassifyMSWSTEP(t *testing.T) {
	m := New(Options{Prefixes: Prefixes{
		MSXCEP:  "/mswstep/policy",
		MSWSTEP: "/mswstep/enroll",
	}})

	enroll := m.classify(httptest.NewRequest("POST", "/mswstep/enroll", nil))
	if enroll == nil {
		t.Fatal("enroll endpoint was not classified")
	}
	if enroll.name != "mswstep_enroll" || !enroll.hsmBound || !enroll.tenantScoped {
		t.Errorf("enroll class = %+v, want name=mswstep_enroll hsmBound=true tenantScoped=true", *enroll)
	}

	policy := m.classify(httptest.NewRequest("POST", "/mswstep/policy", nil))
	if policy == nil {
		t.Fatal("policy endpoint was not classified")
	}
	if policy.name != "mswstep_policy" || policy.hsmBound || !policy.tenantScoped {
		t.Errorf("policy class = %+v, want name=mswstep_policy hsmBound=false tenantScoped=true", *policy)
	}

	// A path outside both prefixes is not a metered public endpoint.
	if c := m.classify(httptest.NewRequest("POST", "/mswstep/other", nil)); c != nil {
		t.Errorf("unexpected classification for /mswstep/other: %+v", *c)
	}
}
