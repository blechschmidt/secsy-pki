//go:build sqlite

package handlers

// Tests for POST /api/ct/verify-inclusion (Task 198).
//
// The scan itself is exercised end to end against the real ctmonitor over a
// configured log; what these assert is the endpoint contract around it — the gate
// (an active third-party probe that writes cross-tenant state, so cert:issue, not
// read standing), the two "this deployment cannot do that" 503s, and that a
// completed scan reports its tallies as data rather than as an error.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ctLogPublicKeyPEM returns a fresh P-256 SubjectPublicKeyInfo PEM block, the
// form a CT log's public key is configured in.
func ctLogPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// ctMonitorAPI builds an API whose ops bundle configures one CT log. Nothing in
// the store carries an unresolved SCT, so a scan completes without contacting the
// log — the endpoint's own behavior is what is under test, not RFC 6962 plumbing
// (which internal/ctmonitor covers against a fake log).
func ctMonitorAPI(t *testing.T) (*API, *database.DB) {
	t.Helper()
	return ctMonitorAPIWithBound(t, 0)
}

// ctMonitorAPIWithBound is ctMonitorAPI with an explicit
// inclusion_monitor.max_certs_per_run, for the clamp assertions.
func ctMonitorAPIWithBound(t *testing.T, maxCertsPerRun int) (*API, *database.DB) {
	t.Helper()
	api, db := tenantAPI(t)
	api.SetOps(&OpsDeps{Config: &config.Config{
		CertificateTransparency: config.CTConfig{
			Logs: []config.CTLogConfig{{
				Name:      "test-log",
				URL:       "https://ct.example.invalid/log",
				PublicKey: ctLogPublicKeyPEM(t),
				MMDHours:  24,
			}},
			InclusionMonitor: config.CTInclusionMonitorConfig{MaxCertsPerRun: maxCertsPerRun},
		},
	}})
	return api, db
}

// seedPendingInclusion records n certificates that carry an unresolved SCT, which
// is what puts them in the monitor's per-scan candidate set. The stored PEM is
// deliberately unparseable: the scan then counts the certificate and moves on
// without any network I/O, so what the test observes is exactly how many
// candidates the run was allowed to take.
func seedPendingInclusion(t *testing.T, db *database.DB, n int) {
	t.Helper()
	const caID = "ct-clamp-ca"
	if err := db.CreateCA(&models.CA{
		ID: caID, Label: caID, PKCS11URI: "pkcs11:" + caID,
		KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	for i := 0; i < n; i++ {
		serial := fmt.Sprintf("%04d", i+1)
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: caID + "-" + serial, CAID: caID, Serial: serial,
			CommonName: serial + ".example.com", Profile: "server",
			Certificate: "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n",
			NotBefore:   time.Now().Add(-time.Duration(n-i) * time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
			Status:      models.CertStatusValid,
			SCTCount:    1,
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%s): %v", serial, err)
		}
	}
}

// postCTVerify drives the handler as the given principal.
func postCTVerify(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	return postAs(api.VerifyCTInclusion, user, "/api/ct/verify-inclusion", body)
}

// TestCTVerifyInclusionAuthz: the run actively reaches out to third-party logs and
// writes inclusion state across every tenant's certificates, so it is gated on the
// PLATFORM issue capability — exactly like POST /api/discovery/scan — and sits
// above the read standing that views the recorded result (GET /api/ct/inclusion).
func TestCTVerifyInclusionAuthz(t *testing.T) {
	api, db := ctMonitorAPI(t)

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, http.StatusForbidden},
		{"tenant issuer", tenantUser("alice", models.DefaultTenantID, "issuer"), http.StatusForbidden},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, http.StatusOK},
		{"platform admin", platAdminUser(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postCTVerify(api, tc.user, `{}`)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	if log := eventDetails(t, db); !strings.Contains(log,
		audit.ActionCTInclusion+"||CT inclusion verification requires the platform issue capability") {
		t.Errorf("denied scan attempts must be audited:\n%s", log)
	}
}

// TestCTVerifyInclusionUnavailable: the two configurations under which the CLI
// refuses as well — no operations bundle at all, and a bundle with no CT logs —
// are reported as 503 with a reason, not as an empty success.
func TestCTVerifyInclusionUnavailable(t *testing.T) {
	noOps, _ := tenantAPI(t)
	if rec := postCTVerify(noOps, platAdminUser(), `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no ops deps: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}

	noLogs, _ := tenantAPI(t)
	noLogs.SetOps(&OpsDeps{Config: &config.Config{}})
	rec := postCTVerify(noLogs, platAdminUser(), `{}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no CT logs: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "no CT logs are configured") {
		t.Errorf("error should name the missing log configuration, got %s", body)
	}

	// A log whose public key cannot be parsed is a configuration fault, not a
	// verification result: the monitor could not verify a signed tree head with it.
	badKey, _ := tenantAPI(t)
	badKey.SetOps(&OpsDeps{Config: &config.Config{
		CertificateTransparency: config.CTConfig{Logs: []config.CTLogConfig{{
			Name: "broken", URL: "https://ct.example.invalid/log", PublicKey: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n",
		}}},
	}})
	if rec := postCTVerify(badKey, platAdminUser(), `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unparseable log key: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

// TestCTVerifyInclusionBadInput: a malformed body is a request error; an absent
// body is not (a scan needs no parameters).
func TestCTVerifyInclusionBadInput(t *testing.T) {
	api, _ := ctMonitorAPI(t)
	if rec := postCTVerify(api, platAdminUser(), `{"max":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := postCTVerify(api, platAdminUser(), ``); rec.Code != http.StatusOK {
		t.Fatalf("empty body: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestCTVerifyInclusionScanReportsTallies: a completed scan is a 200 carrying the
// per-outcome tallies and the standing backlog counts — the shape the console
// renders. A clean store yields zeros rather than an error, and the run is
// attributed to the operator on top of the monitor's own ct.inclusion event.
func TestCTVerifyInclusionScanReportsTallies(t *testing.T) {
	api, db := ctMonitorAPI(t)

	rec := postCTVerify(api, platAdminUser(), `{"max":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp CTVerifyInclusionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("scan reported an error on a clean store: %s", resp.Error)
	}
	if resp.StartedAt.IsZero() {
		t.Error("started_at must be set so the console can show when the scan ran")
	}
	if resp.Certs != 0 || resp.Checked != 0 || resp.Failed != 0 || resp.NewMisbehavior != 0 {
		t.Errorf("tallies = %+v, want all zero with nothing pending inclusion", resp.ScanResult)
	}

	log := eventDetails(t, db)
	if !strings.Contains(log, audit.ActionCTInclusion+"||certs=0 checked=0") || !strings.Contains(log, "via=api") {
		t.Errorf("audit log lacks the operator-attributed ct.inclusion event:\n%s", log)
	}
}

// TestCTVerifyInclusionMaxOnlyNarrows is the bound invariant: the request's `max`
// may shrink the configured per-run bound and must never be able to raise it.
//
// config's MaxCerts() hands back any positive value unchanged, so treating the
// body as authoritative made max_certs_per_run advisory: {"max":2000000000} loaded
// every certificate with an unresolved SCT and hit third-party CT logs once per
// SCT, and N concurrent callers could each start a full scan. The scan's candidate
// count (certs) is what the bound governs, so that is what is asserted.
func TestCTVerifyInclusionMaxOnlyNarrows(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		body       string
		wantCerts  int
	}{
		// The whole finding: a huge request max cannot escape the configured bound.
		{"huge max cannot widen", 1, `{"max":2000000000}`, 1},
		{"a max above the bound cannot widen", 1, `{"max":3}`, 1},
		{"no max uses the configured bound", 1, `{}`, 1},
		// …and narrowing, which is what the field exists for, still works.
		{"max narrows", 3, `{"max":1}`, 1},
		{"max at the bound is the bound", 3, `{"max":3}`, 3},
		// An unset bound falls back to the package default (500), which 3 is under.
		{"unconfigured bound scans the seeded set", 0, `{"max":2000000000}`, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, _ := ctMonitorAPIWithBound(t, tc.configured)
			seedPendingInclusion(t, api.db, 3)

			rec := postCTVerify(api, platAdminUser(), tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			var resp CTVerifyInclusionResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Certs != tc.wantCerts {
				t.Errorf("scan examined %d certificates, want %d (configured bound %d, body %s)",
					resp.Certs, tc.wantCerts, tc.configured, tc.body)
			}
		})
	}
}
