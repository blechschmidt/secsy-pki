//go:build sqlite

package est

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 61: the tenant gate on the EST enrollment path. The test root lives in
// the default tenant; suspending it must refuse simpleenroll with 403 while
// /cacerts (pure distribution, like CRL/OCSP) keeps serving, and an exhausted
// daily quota answers 429 with Retry-After.
func TestEST_TenantSuspensionAndQuota(t *testing.T) {
	srv, ts, _ := newTestEST(t, Config{
		Users: map[string]User{"device": {Password: "pw", Profile: "client"}},
	}, false)

	enroll := func(cn string) *http.Response {
		t.Helper()
		_, csrDER := makeCSR(t, cn)
		req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
			strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.SetBasicAuth("device", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// Baseline: enrollment works.
	if resp := enroll("dev-baseline"); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("baseline enroll = %d: %s", resp.StatusCode, body)
	}

	// Suspension refuses enrollment with 403…
	if err := srv.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	if resp := enroll("dev-suspended"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enroll under suspension = %d, want 403", resp.StatusCode)
	}
	// …while /cacerts (certificate distribution) keeps working.
	caResp, err := http.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	defer caResp.Body.Close()
	if caResp.StatusCode != http.StatusOK {
		t.Errorf("cacerts under suspension = %d, want 200 (distribution must keep working)", caResp.StatusCode)
	}

	// Reactivate, then exhaust the daily quota: 429 + Retry-After.
	if err := srv.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusActive); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
	tn, err := srv.db.GetTenant(models.DefaultTenantID)
	if err != nil || tn == nil {
		t.Fatalf("GetTenant: %v", err)
	}
	tn.Quotas.MaxCertsPerDay = 1
	if err := srv.db.UpdateTenant(tn); err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	// One unit was already consumed by the baseline enrollment... top the
	// counter up to the ceiling regardless of prior state.
	day := database.UsageDay(time.Now())
	usage, err := srv.db.GetTenantUsageDay(models.DefaultTenantID, day)
	if err != nil {
		t.Fatalf("GetTenantUsageDay: %v", err)
	}
	if usage.CertsIssued < 1 {
		if err := srv.db.AddTenantUsage(models.DefaultTenantID, day, database.UsageCertsIssued, 1); err != nil {
			t.Fatalf("AddTenantUsage: %v", err)
		}
	}

	resp := enroll("dev-overquota")
	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll over quota = %d, want 429: %s", resp.StatusCode, body)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 missing positive Retry-After (got %q)", ra)
	}
}
