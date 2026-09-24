//go:build sqlite

package handlers

// Tests for the preflight-diagnostics REST surface (Task 198). The load-bearing
// invariant is that a FAILING CHECK IS DATA: the console's health page must still
// render — with the failure visible — when the deployment is broken, so a failed
// check yields HTTP 200 with a `fail` entry rather than an error status.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// doctorIsolateEnv clears the SECSY_* variables config.Load would otherwise apply
// as overrides, so the config file written by a test is the whole truth.
func doctorIsolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECSY_KEY_PROVIDER", "SECSY_KEY_PROVIDER_CA", "SECSY_KEY_PROVIDER_TSA", "SECSY_KEY_PROVIDER_SIGNING",
		"SECSY_PKCS11_MODULE", "SECSY_TOKEN_LABEL", "SECSY_TOKEN_SERIAL", "SECSY_USER_PIN",
		"SECSY_DATABASE_DRIVER", "SECSY_DATABASE_DSN",
		"SECSY_SOFTWARE_KEYSTORE_DIR", "SECSY_SECRET_KEK_LABEL",
		"SECSY_ROOT_PASSWORD", "SECSY_ALLOW_INSECURE_HTTP",
	} {
		t.Setenv(k, "")
	}
}

// doctorAPI builds an API whose operations dependencies point at cfgPath, with a
// software key provider factory standing in for the HSM.
func doctorAPI(t *testing.T, cfgPath string) *API {
	t.Helper()
	api, _ := tenantAPI(t)
	keystore := t.TempDir()
	api.SetOps(&OpsDeps{
		Config:     &config.Config{},
		ConfigPath: cfgPath,
		ProviderFor: func(string) (keyprovider.Provider, error) {
			return keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: keystore})
		},
	})
	return api
}

// doctorRun drives GET /api/doctor with an optional query string.
func doctorRun(api *API, user *models.UserInfo, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.Doctor(rec, reqAs(http.MethodGet, "/api/doctor"+query, user, "", ""))
	return rec
}

// doctorDecode decodes a 200 report.
func doctorDecode(t *testing.T, rec *httptest.ResponseRecorder) DoctorResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("doctor: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp DoctorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	return resp
}

// doctorFindCheck returns the named check from a report.
func doctorFindCheck(t *testing.T, resp DoctorResponse, name string) DoctorCheck {
	t.Helper()
	for _, c := range resp.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing from the report (%d checks)", name, len(resp.Checks))
	return DoctorCheck{}
}

// doctorWriteConfig writes a minimal but valid single-node configuration and
// returns its path.
func doctorWriteConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "doctor.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: 8443
root_user:
  password: doctor-endpoint-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: software
  software:
    keystore_dir: %s
`, dbPath, filepath.Join(dir, "keystore"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return cfgPath
}

// TestDoctorAuthz pins the gate: diagnostics are a PLATFORM-wide read. The report
// is node-level infrastructure truth (config path, provider backends, listener,
// FIPS posture), not one tenant's data, so a tenant-scoped auditor is denied even
// though it can read its own tenant's inventory.
func TestDoctorAuthz(t *testing.T) {
	api := doctorAPI(t, doctorWriteConfig(t))

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant auditor", tenantUser("taud", "a", "auditor"), http.StatusForbidden},
		{"tenant admin", tenantUser("tadmin", "a", "admin"), http.StatusForbidden},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, http.StatusOK},
		{"platform admin", platformAdmin(), http.StatusOK},
		{"root", rootUser(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doctorIsolateEnv(t)
			if rec := doctorRun(api, tc.user, "?no_listener=true"); rec.Code != tc.want {
				t.Errorf("got %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestDoctorWithoutOpsDeps proves the endpoint degrades to 503 rather than
// panicking when the server was started without the operations dependencies, and
// that authorization is decided first so a roleless caller cannot probe the wiring.
func TestDoctorWithoutOpsDeps(t *testing.T) {
	api, _ := tenantAPI(t) // no SetOps

	if rec := doctorRun(api, rootUser(), ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("capable caller: got %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if rec := doctorRun(api, &models.UserInfo{Subject: "nobody"}, ""); rec.Code != http.StatusForbidden {
		t.Errorf("roleless caller: got %d, want 403 (authz before wiring); body=%s", rec.Code, rec.Body.String())
	}
}

// TestDoctorFailingCheckIs200 is the headline invariant: the diagnosis of a broken
// deployment is a successful response. An unloadable config file fails the
// config.parse check and skips the rest — and the request still answers 200 with
// the whole report, because a health page that 500s when the node is unhealthy is
// useless exactly when it is needed.
func TestDoctorFailingCheckIs200(t *testing.T) {
	doctorIsolateEnv(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	api := doctorAPI(t, missing)

	resp := doctorDecode(t, doctorRun(api, rootUser(), ""))
	if resp.Verdict != "fail" || resp.OK {
		t.Errorf("verdict=%q ok=%v, want fail/false", resp.Verdict, resp.OK)
	}
	if resp.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1 (the CLI's failure code)", resp.ExitCode)
	}
	if resp.ConfigPath != missing {
		t.Errorf("config_path = %q, want %q — an operator must be able to tell which file was diagnosed", resp.ConfigPath, missing)
	}
	parse := doctorFindCheck(t, resp, "config.parse")
	if parse.Status != "fail" {
		t.Errorf("config.parse = %q, want fail; message=%q", parse.Status, parse.Message)
	}
	if !strings.Contains(parse.Message, missing) {
		t.Errorf("config.parse message %q does not name the file", parse.Message)
	}
	if parse.Hint == "" {
		t.Error("a failing check carries no remediation hint")
	}
	if resp.Summary.Fail == 0 || resp.Summary.Skip == 0 {
		t.Errorf("summary = %+v, want at least one fail and the remaining checks skipped", resp.Summary)
	}
	// The report shape stays stable for CI: every check is accounted for.
	if n := resp.Summary.Pass + resp.Summary.Warn + resp.Summary.Fail + resp.Summary.Skip; n != len(resp.Checks) {
		t.Errorf("summary totals %d but the report has %d checks", n, len(resp.Checks))
	}
}

// TestDoctorReportsStructuredChecks runs the suite over a real config file and
// asserts the structure the console renders: a verdict consistent with the
// summary, per-check name/status/message, and hints only where there is something
// to remediate.
func TestDoctorReportsStructuredChecks(t *testing.T) {
	doctorIsolateEnv(t)
	cfgPath := doctorWriteConfig(t)
	api := doctorAPI(t, cfgPath)

	resp := doctorDecode(t, doctorRun(api, rootUser(), "?no_listener=true&timeout=30"))
	if resp.ConfigPath != cfgPath {
		t.Errorf("config_path = %q, want %q", resp.ConfigPath, cfgPath)
	}
	if resp.TimeoutSeconds != 30 {
		t.Errorf("timeout_seconds = %d, want the requested 30", resp.TimeoutSeconds)
	}
	if resp.Deep {
		t.Error("deep = true without the deep parameter")
	}
	if len(resp.Checks) < 10 {
		t.Fatalf("report has only %d checks, want the full suite", len(resp.Checks))
	}
	if parse := doctorFindCheck(t, resp, "config.parse"); parse.Status != "pass" {
		t.Errorf("config.parse = %q (%s), want pass for a valid config", parse.Status, parse.Message)
	}
	// The verdict, OK flag, and exit code are all derived from the same summary.
	wantVerdict, wantExit := "ok", 0
	switch {
	case resp.Summary.Fail > 0:
		wantVerdict, wantExit = "fail", 1
	case resp.Summary.Warn > 0:
		wantVerdict, wantExit = "warn", 2
	}
	if resp.Verdict != wantVerdict || resp.ExitCode != wantExit || resp.OK != (resp.Summary.Fail == 0) {
		t.Errorf("verdict=%q exit=%d ok=%v, want %q/%d/%v for summary %+v",
			resp.Verdict, resp.ExitCode, resp.OK, wantVerdict, wantExit, resp.Summary.Fail == 0, resp.Summary)
	}
	for _, c := range resp.Checks {
		switch c.Status {
		case "pass", "warn", "fail", "skip":
		default:
			t.Errorf("check %q has status %q, outside the pass/warn/fail/skip vocabulary", c.Name, c.Status)
		}
		if c.Name == "" || c.Message == "" {
			t.Errorf("check %+v is missing a name or message", c)
		}
		if c.Hint != "" && c.Status != "warn" && c.Status != "fail" {
			t.Errorf("check %q (%s) carries a remediation hint it does not need", c.Name, c.Status)
		}
	}
	// The listener probe was skipped as requested rather than dialing the address.
	if lis := doctorFindCheck(t, resp, "listener.tls"); strings.Contains(lis.Message, "handshake") {
		t.Errorf("listener.tls probed the live listener despite no_listener=true: %q", lis.Message)
	}
}

// TestDoctorRejectsBadParameters refuses a malformed knob instead of silently
// diagnosing something other than what was asked for.
func TestDoctorRejectsBadParameters(t *testing.T) {
	doctorIsolateEnv(t)
	api := doctorAPI(t, doctorWriteConfig(t))

	for _, q := range []string{"?deep=maybe", "?timeout=soon", "?audit_sample=-5", "?expiry_warn_days=x", "?no_listener=1.5"} {
		t.Run(q, func(t *testing.T) {
			if rec := doctorRun(api, rootUser(), q); rec.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestDoctorClampsHugeTimeBudgets is the overflow invariant: a caller-supplied
// budget is clamped in integer seconds/days BEFORE it becomes a time.Duration.
//
// time.Duration is an int64 of nanoseconds, so time.Duration(secs) * time.Second
// wraps for secs above ~9.2e9 — and it wraps NEGATIVE, which is below any ceiling
// and so passed a clamp applied after the multiplication. The result was a
// context.WithTimeout deadline already in the past: ?timeout=10000000000 answered
// 200 with verdict "fail", ok=false, exit_code 1 and a NEGATIVE timeout_seconds,
// i.e. any platform auditor could make the console show a totally broken PKI and
// trip a pipeline keyed off exit_code. The same wrap in expiry_warn_days /
// expiry_fail_days (* 24 * time.Hour, so it wraps 24x sooner) inverted the expiry
// thresholds instead.
func TestDoctorClampsHugeTimeBudgets(t *testing.T) {
	// 1e10 seconds is 1e19 nanoseconds, past int64: the multiplication wraps.
	const overflows = "10000000000"
	maxSeconds := int(doctorMaxTimeout / time.Second)

	// The two helpers, directly: every parameter has to come back POSITIVE, because
	// a negative Duration is what turns into an already-expired deadline (timeout) or
	// an inverted threshold that every certificate looks past (expiry days).
	param := func(query string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/doctor?"+query, nil)
	}
	for _, tc := range []struct {
		name string
		got  func() (time.Duration, error)
		want time.Duration
	}{
		{"timeout overflows", func() (time.Duration, error) {
			return doctorTimeoutParam(param("timeout=" + overflows))
		}, doctorMaxTimeout},
		{"timeout at the ceiling", func() (time.Duration, error) {
			return doctorTimeoutParam(param("timeout=300"))
		}, doctorMaxTimeout},
		{"timeout in range", func() (time.Duration, error) {
			return doctorTimeoutParam(param("timeout=30"))
		}, 30 * time.Second},
		{"timeout unset", func() (time.Duration, error) {
			return doctorTimeoutParam(param(""))
		}, doctorDefaultTimeout},
		// * 24 * time.Hour wraps 24x sooner than * time.Second does, so the day
		// parameters overflow on much smaller inputs than the timeout.
		{"expiry days overflow", func() (time.Duration, error) {
			return doctorDaysParam(param("expiry_warn_days="+overflows), "expiry_warn_days")
		}, maxDoctorDays * 24 * time.Hour},
		{"expiry days just past the cap", func() (time.Duration, error) {
			return doctorDaysParam(param("expiry_fail_days=107000000"), "expiry_fail_days")
		}, maxDoctorDays * 24 * time.Hour},
		{"expiry days in range", func() (time.Duration, error) {
			return doctorDaysParam(param("expiry_warn_days=30"), "expiry_warn_days")
		}, 30 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.got()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got <= 0 {
				t.Fatalf("got %v; a wrapped budget is worse than a rejected one", got)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	// End to end: the report a huge timeout produces is a real diagnosis with a
	// positive budget, not the "everything is broken" report an expired deadline
	// produced — verdict "fail", ok=false, exit_code 1 and a negative
	// timeout_seconds, from any principal holding platform audit:read.
	doctorIsolateEnv(t)
	api := doctorAPI(t, doctorWriteConfig(t))
	resp := doctorDecode(t, doctorRun(api, rootUser(), "?no_listener=true&timeout="+overflows+
		"&expiry_warn_days="+overflows+"&expiry_fail_days="+overflows))
	if resp.TimeoutSeconds != maxSeconds {
		t.Errorf("timeout_seconds = %d, want the %ds ceiling exactly", resp.TimeoutSeconds, maxSeconds)
	}
	if parse := doctorFindCheck(t, resp, "config.parse"); parse.Status != "pass" {
		t.Errorf("config.parse = %q (%s) — the run started on an expired deadline",
			parse.Status, parse.Message)
	}
	for _, c := range resp.Checks {
		if c.Status == "fail" && strings.Contains(c.Message, "context deadline exceeded") {
			t.Errorf("check %q failed on the deadline rather than on its dependency: %s", c.Name, c.Message)
		}
	}
}

// TestPublishTimeoutClampsBeforeConverting is publishTimeout's half of the same
// overflow: the requested seconds are compared against the ceiling as integers, so
// a huge value yields the ceiling instead of a wrapped negative duration — which
// context.WithTimeout would treat as already expired, turning a publish into an
// instant "context deadline exceeded" and a 500.
func TestPublishTimeoutClampsBeforeConverting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested int
		want      time.Duration
	}{
		{"unset uses the default", 0, publishVerifyTimeout},
		{"negative uses the default", -1, publishVerifyTimeout},
		{"in range is honored", 30, 30 * time.Second},
		{"at the ceiling", int(publishMaxTimeout / time.Second), publishMaxTimeout},
		{"above the ceiling", int(publishMaxTimeout/time.Second) + 1, publishMaxTimeout},
		// 1e10 seconds is 1e19 nanoseconds: time.Duration(1e10) * time.Second wraps.
		{"overflows a Duration", 10_000_000_000, publishMaxTimeout},
		{"the largest int32 a client could send", 2_147_483_647, publishMaxTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := publishTimeout(tc.requested, publishVerifyTimeout)
			if got != tc.want {
				t.Errorf("publishTimeout(%d) = %v, want %v", tc.requested, got, tc.want)
			}
			if got <= 0 {
				t.Errorf("publishTimeout(%d) = %v; a non-positive deadline is already expired", tc.requested, got)
			}
		})
	}
}

// TestDoctorWithoutProviderFactorySkipsKeyChecks proves the endpoint is safe to
// call when no role-scoped provider factory is installed: the key-provider checks
// degrade to skips and the report still answers 200 — the same degradation an HSM
// outage produces.
func TestDoctorWithoutProviderFactory(t *testing.T) {
	doctorIsolateEnv(t)
	cfgPath := doctorWriteConfig(t)
	api, _ := tenantAPI(t)
	api.SetOps(&OpsDeps{Config: &config.Config{}, ConfigPath: cfgPath}) // no ProviderFor

	resp := doctorDecode(t, doctorRun(api, rootUser(), "?no_listener=true"))
	if kp := doctorFindCheck(t, resp, "keyprovider.ca"); kp.Status != "skip" {
		t.Errorf("keyprovider.ca = %q (%s), want skip without a provider factory", kp.Status, kp.Message)
	}
}
