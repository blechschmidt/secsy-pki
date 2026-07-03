//go:build sqlite

package cmp

import (
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 61: the tenant gate on the CMP (RFC 9483) enrollment path. A suspended
// tenant's ir is answered with an error PKIBody carrying notAuthorized and a
// "suspended" status text — no certificate is issued — and reactivation
// restores enrollment.
func TestCMP_SuspendedTenantIRRejected(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t))

	// Baseline: enrollment works.
	env.enroll(t, "cmp-baseline.example.test")

	if err := env.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspending: %v", err)
	}

	key := newKey(t)
	reqDER, err := BuildInitializationRequest(testReference, testSecret,
		pkix.Name{CommonName: "cmp-susp.example.test"}, key,
		RequestOptions{DNSNames: []string{"cmp-susp.example.test"}})
	if err != nil {
		t.Fatalf("BuildInitializationRequest: %v", err)
	}
	res, err := ParseResponse(env.post(t, reqDER))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.BodyTag != bodyError {
		t.Fatalf("response body tag = %d, want error (%d); status=%q", res.BodyTag, bodyError, res.StatusText)
	}
	if res.Accepted() || res.Certificate != nil {
		t.Fatal("a certificate was issued for a suspended tenant")
	}
	if !strings.Contains(res.StatusText, "suspended") {
		t.Errorf("error status text = %q, want it to name the suspension", res.StatusText)
	}

	// Reactivation restores enrollment end-to-end.
	if err := env.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusActive); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
	env.enroll(t, "cmp-reactivated.example.test")
}
