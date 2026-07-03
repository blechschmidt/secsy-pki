//go:build sqlite

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// newObsAPI builds an API backed by an in-memory DB and a software key provider
// for exercising the observability endpoints.
func newObsAPI(t *testing.T) (*API, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, false, "")
	return api, db
}

func TestHealthz(t *testing.T) {
	api, db := newObsAPI(t)
	defer db.Close()

	rec := httptest.NewRecorder()
	api.Healthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status string            `json:"status"`
		Build  map[string]string `json:"build"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	// The build block must identify the binary and its FIPS 140-3 posture.
	if body.Build["version"] == "" || !strings.HasPrefix(body.Build["go"], "go") {
		t.Errorf("build block missing version/go: %v", body.Build)
	}
	if v := body.Build["fips140"]; v != "on" && v != "off" {
		t.Errorf("build.fips140 = %q, want on|off", v)
	}
	if v := body.Build["fips140_policy"]; v != "enforced" && v != "off" {
		t.Errorf("build.fips140_policy = %q, want enforced|off", v)
	}
}

func TestReadyzHealthy(t *testing.T) {
	api, db := newObsAPI(t)
	defer db.Close()

	rec := httptest.NewRecorder()
	api.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status     string `json:"status"`
		Components map[string]struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("overall status = %q, want ready", body.Status)
	}
	if body.Components["database"].Status != "up" {
		t.Errorf("database status = %q, want up", body.Components["database"].Status)
	}
	// The software provider implements Prober and its keystore dir exists, so it
	// must report up.
	if body.Components["hsm"].Status != "up" {
		t.Errorf("hsm status = %q, want up", body.Components["hsm"].Status)
	}
}

func TestReadyzDatabaseDown(t *testing.T) {
	api, db := newObsAPI(t)
	db.Close() // sever the DB so the readiness probe fails

	rec := httptest.NewRecorder()
	api.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"not_ready"`) {
		t.Errorf("expected not_ready in body: %s", rec.Body.String())
	}
}

func TestMetricsEndpoint(t *testing.T) {
	api, db := newObsAPI(t)
	defer db.Close()

	// Record something so a known series is present.
	metrics.RecordCertificate("issue", nil)

	rec := httptest.NewRecorder()
	api.Metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain...", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "secsy_certificates_total") {
		t.Errorf("metrics output missing secsy_certificates_total:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE secsy_hsm_operation_duration_seconds histogram") {
		t.Errorf("metrics output missing HSM histogram TYPE line")
	}
}

// readyzProbeUsesKeyProvider confirms the readiness probe actually calls through
// the (instrumented) key provider's Prober capability and records the HSM up
// gauge.
func TestReadyzRecordsHSMUpGauge(t *testing.T) {
	api, db := newObsAPI(t)
	defer db.Close()

	rec := httptest.NewRecorder()
	api.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	mrec := httptest.NewRecorder()
	api.Metrics(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(mrec.Body.String(), `secsy_component_up{component="hsm"} 1`) {
		t.Errorf("hsm up gauge not set to 1 after readyz:\n%s", mrec.Body.String())
	}
}
