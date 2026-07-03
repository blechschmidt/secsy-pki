//go:build sqlite

package scep

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// httpGet fetches a URL and returns just the status code.
func httpGet(url string) (int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// Task 61: the tenant gate on the SCEP enrollment path. SCEP reports issuance
// refusals as a CertRep with pkiStatus FAILURE (its failInfo vocabulary has no
// throttling value), so both suspension and quota exhaustion surface as
// failures rather than certificates — and GetCACert (distribution) keeps
// serving while suspended.
func TestSCEP_SuspendedTenantEnrollmentFails(t *testing.T) {
	srv, ts, caCert := newTestServer(t, Config{Profile: "client"})

	// Baseline: enrollment works in the active default tenant.
	c := newSCEPClient(t, ts, caCert, "device-base")
	if _, status, err := c.enroll("device-base", ""); err != nil || status != pkiStatusSuccess {
		t.Fatalf("baseline enroll: status=%q err=%v", status, err)
	}

	if err := srv.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspending: %v", err)
	}

	// Enrollment now fails (CertRep FAILURE, no certificate).
	c2 := newSCEPClient(t, ts, caCert, "device-susp")
	issued, status, err := c2.enroll("device-susp", "")
	if err != nil {
		t.Fatalf("enroll transport error: %v", err)
	}
	if status != pkiStatusFailure {
		t.Fatalf("pkiStatus under suspension = %q, want failure", status)
	}
	if issued != nil {
		t.Fatal("a certificate was issued for a suspended tenant")
	}

	// GetCACert (CA certificate distribution) keeps working while suspended.
	resp, err := httpGet(ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	if resp != 200 {
		t.Errorf("GetCACert under suspension = %d, want 200 (distribution must keep working)", resp)
	}

	// Reactivation restores enrollment.
	if err := srv.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusActive); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
	c3 := newSCEPClient(t, ts, caCert, "device-back")
	if _, status, err := c3.enroll("device-back", ""); err != nil || status != pkiStatusSuccess {
		t.Fatalf("enroll after reactivation: status=%q err=%v", status, err)
	}
}
