package handlers

// REST surface for the preflight diagnostic suite (`secsy-ca doctor`) — Task 198.
//
// The suite already exists in internal/doctor and is the single place that knows
// how to interrogate a node's effective configuration and every dependency it
// stands on (key providers, the store, the audit chain, expiry headroom, CRL
// freshness, backup/retention/ERS freshness, clock and trusted time, listener
// TLS, FIPS posture). What was missing was a way to READ it without shell access
// to the CA host, which is exactly what an operator needs first during an
// incident. This endpoint runs the same doctor.Run the CLI runs, over the same
// configuration file, and returns the report structured rather than rendered, so
// the console can present per-check state instead of parsing a table.
//
// Two properties are load-bearing:
//
//   - A failing check is DATA, not an error. The request answers 200 with the
//     full report whatever the checks find; only an unauthorized caller or an
//     unwired server changes the status. A diagnostic endpoint that 500s when the
//     deployment is broken is useless precisely when it is needed.
//   - It is safe to call while the HSM is down. doctor.Run degrades every
//     unreachable dependency to a fail/skip result and closes everything it
//     opened before returning, so the report always covers the full check list.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Time budget for one diagnostic run. The default matches the CLI's -timeout
// default; the ceiling exists because this one is a request: -deep walks the
// entire audit chain, and an operator must not be able to pin a server worker
// for an unbounded time from the console.
const (
	doctorDefaultTimeout = 60 * time.Second
	doctorMaxTimeout     = 5 * time.Minute
)

// DoctorCheck is one diagnostic result. Name, Status, Message and ElapsedMS are
// doctor.Result field-for-field (the same shape `secsy-ca doctor -json` emits);
// Hint is added for the console.
type DoctorCheck struct {
	// Name identifies the check, dotted by area (e.g. "keyprovider.ca").
	Name string `json:"name"`
	// Status is "pass", "warn", "fail", or "skip" — the doctor package's
	// vocabulary, kept verbatim so the console and `secsy-ca doctor -json` can
	// never disagree about what a check reported.
	Status string `json:"status"`
	// Message is the one-line human explanation of the outcome.
	Message string `json:"message"`
	// ElapsedMS is how long the check took, for spotting slow dependencies.
	ElapsedMS int64 `json:"elapsed_ms"`
	// Hint points at the configuration block, command, or runbook area that
	// remediation starts from. It is present only for warn/fail (a passing check
	// needs no remediation) and is deliberately scoped to the check's AREA rather
	// than to the individual failure: the diagnosis is Message, which comes from
	// the check itself and cannot drift, while this only says where to go next.
	Hint string `json:"hint,omitempty"`
}

// DoctorResponse is the body of GET /api/doctor: the structured report plus the
// overall verdict.
type DoctorResponse struct {
	// CheckedAt is when the run started (UTC).
	CheckedAt time.Time `json:"checked_at"`
	// ConfigPath is the configuration file this process answers for — reported so
	// an operator reading the console knows WHICH file the diagnosis is about
	// before changing anything. Empty when the server was started without one.
	ConfigPath string `json:"config_path"`
	// Verdict is the overall outcome: "ok" (nothing to do), "warn" (operational,
	// needs attention) or "fail" (broken or will refuse to serve).
	Verdict string `json:"verdict"`
	// OK is true when no check failed; warnings do not clear it (doctor.Report.OK).
	OK bool `json:"ok"`
	// ExitCode is the tri-state code `secsy-ca doctor` would exit with for this
	// report (0 pass, 1 failure(s), 2 warning(s) only), so a pipeline driving the
	// API keys off the same number as one driving the CLI.
	ExitCode int `json:"exit_code"`
	// Deep reports whether the full store-integrity gate ran.
	Deep bool `json:"deep"`
	// TimeoutSeconds is the time budget the run was given.
	TimeoutSeconds int `json:"timeout_seconds"`
	// Summary counts the results by status.
	Summary doctor.Summary `json:"summary"`
	// Checks are the individual results in execution order. Never null.
	Checks []DoctorCheck `json:"checks"`
}

// Doctor handles GET /api/doctor — the REST form of `secsy-ca doctor`.
//
// Gated on the PLATFORM-wide audit:read capability (a.can, which consults
// platform roles only), like the other cross-tenant operational reads
// (/api/events/export, /api/hsm/audit-bundle). The report is infrastructure
// truth about the whole node — config path, key-provider backends and slots,
// store schema, listener addresses, FIPS posture — not one tenant's data, so a
// tenant-scoped auditor must not be able to read it. It stays a READ capability
// because the suite is read-only by construction: it never generates keys,
// issues, writes rows, or migrates (see the doctor package's invariants).
func (a *API) Doctor(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "platform-wide audit:read capability required (admin or auditor role)")
		return
	}
	deps, ok := a.requireOps(w, "preflight diagnostics")
	if !ok {
		return
	}

	// doctor loads the config file itself (a broken config is its first finding,
	// not a precondition), then asks for a provider per signing role. Delegating to
	// the installed factory means the diagnosis is made with the exact provider
	// construction this server runs with, rather than a second implementation of
	// the config→provider mapping; doctor.Run closes every provider it obtains this
	// way before returning. With no factory installed the keyprovider.* checks
	// report a skip rather than the suite failing.
	opts := doctor.Options{ConfigPath: deps.ConfigPath}
	if deps.ProviderFor != nil {
		opts.BuildProvider = func(_ *config.Config, role string) (keyprovider.Provider, error) {
			return deps.ProviderFor(role)
		}
	}

	timeout, err := doctorTimeoutParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if opts.ExpiryWarn, err = doctorDaysParam(r, "expiry_warn_days"); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if opts.ExpiryFail, err = doctorDaysParam(r, "expiry_fail_days"); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if opts.AuditSample, err = doctorIntParam(r, "audit_sample"); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if opts.Deep, err = doctorBoolParam(r, "deep"); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if opts.SkipListener, err = doctorBoolParam(r, "no_listener"); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Bound the run: a hung dependency must not hold a server worker open
	// indefinitely. The request context is the parent, so a caller that hangs up
	// also stops the probing — safe here because the suite is read-only and
	// doctor.Run releases everything it opened on the way out.
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	report := doctor.Run(ctx, opts)

	resp := DoctorResponse{
		CheckedAt:      report.CheckedAt,
		ConfigPath:     report.ConfigPath,
		Verdict:        doctorVerdict(report),
		OK:             report.OK,
		ExitCode:       report.ExitCode(),
		Deep:           opts.Deep,
		TimeoutSeconds: int(timeout / time.Second),
		Summary:        report.Summary,
		Checks:         make([]DoctorCheck, 0, len(report.Checks)),
	}
	for _, c := range report.Checks {
		resp.Checks = append(resp.Checks, DoctorCheck{
			Name:      c.Name,
			Status:    string(c.Status),
			Message:   c.Detail,
			ElapsedMS: c.ElapsedMS,
			Hint:      doctorHint(c.Name, c.Status),
		})
	}
	// 200 regardless of the verdict: the report is the answer.
	writeJSON(w, http.StatusOK, resp)
}

// doctorVerdict collapses the summary into the CLI's three-way result line.
func doctorVerdict(r *doctor.Report) string {
	switch {
	case r.Summary.Fail > 0:
		return "fail"
	case r.Summary.Warn > 0:
		return "warn"
	default:
		return "ok"
	}
}

// doctorHints maps a check's area (the part before the first dot in its name) to
// where remediation starts. Keyed by area on purpose: individual checks come and
// go inside the doctor package, and an area-scoped pointer cannot rot into a
// confident lie about a specific failure the way a per-check script would.
var doctorHints = map[string]string{
	"config":      "fix the configuration file named in config_path; `secsy-ca -config <path> doctor` reproduces this offline",
	"db":          "check database.dsn reachability, then apply pending migrations (the server migrates on start; `secsy-ca db verify` checks integrity)",
	"keyprovider": "check the key_provider block for this role: backend type, PKCS#11 module/token, or KMS credentials",
	"pin":         "check pkcs11.pin_source — the external credential store must be reachable and return the user PIN",
	"pkcs11":      "check the pkcs11: URIs (config module/token and each CA's stored key URI) resolve on the token; `secsy-ca inventory` lists what it holds",
	"hsm":         "check every member of the HA token set individually; a dead backup token is invisible while the primary carries traffic",
	"keys":        "the key must exist on the configured provider under the label the runtime uses; `secsy-ca inventory` lists the labels it holds",
	"audit":       "a broken hash chain is an integrity incident, not a misconfiguration: preserve the store and run `secsy-ca db verify` before writing anything",
	"certs":       "renew or re-issue the certificate before the fail threshold (`secsy-ca rotation` for CA keys, re-issue for TSA/code-signing certificates)",
	"crl":         "regenerate and republish the revocation artifacts (`secsy-ca publish` / POST /api/publish) and check crl.validity against the publish interval",
	"canary":      "the issuance canary has not reported recently: check the canary schedule and the CA it probes",
	"backup":      "check the backup.* destination and KEK, then prove recovery with `secsy-ca backup verify-restore` (POST /api/backup/verify-restore)",
	"retention":   "the inventory-retention job has not run recently: check retention.* and the leader-elected loop",
	"ers":         "the evidence-record preservation cycle has stalled: check ers.* and its archive-timestamp material",
	"ct":          "check the configured CT logs and the inclusion monitor's schedule; unincluded precertificates need operator attention",
	"webhook":     "triage the dead-lettered deliveries: a paused endpoint, a wrong URL, or a rotated shared secret",
	"keychecks":   "the pre-issuance key-quality gate is weakened or unloadable: check the blocklist source and any profile overriding it",
	"pqc":         "provision ML-KEM material for every KEK family, or turn secret.pqc_hybrid off until it is provisioned",
	"clock":       "synchronize the host clock (NTP/NTS); TSA signing and audit anchoring fail closed on drift",
	"time":        "check the configured NTS/Roughtime sources; the trusted-time gate fails closed when they cannot be reached",
	"serving":     "renew the self-managed serving-TLS certificate — it is inside its renew_before window",
	"listener":    "check server.tls certificate/key material, the listener address, and the socket path/permissions",
	"fips":        "check security.fips: the module must be active and the store/key material must conform to the policy it enforces",
	"auth":        "check auth.ldap: URL, TLS trust material, and the bind credential source",
}

// doctorHint returns the remediation pointer for a check, if any. Only warn and
// fail carry one: a pass needs no action, and a skip means the check did not
// apply (or its prerequisite already failed and reported its own hint).
func doctorHint(name string, status doctor.Status) string {
	if status != doctor.StatusWarn && status != doctor.StatusFail {
		return ""
	}
	area, _, _ := strings.Cut(name, ".")
	return doctorHints[area]
}

// doctorTimeoutParam reads the second-valued ?timeout parameter: absent or zero
// yields doctorDefaultTimeout, and anything larger is clamped to
// doctorMaxTimeout.
//
// The clamp is applied in SECONDS, before the multiplication. time.Duration is an
// int64 of nanoseconds, so time.Duration(secs) * time.Second wraps once secs
// exceeds ~9.2e9 — and it wraps NEGATIVE, which compares below any ceiling and so
// would sail through a clamp applied afterwards. A negative duration handed to
// context.WithTimeout is an already-expired deadline: ?timeout=10000000000 would
// answer 200 with verdict "fail", ok=false and exit_code 1, i.e. a console showing
// a totally broken PKI and a pipeline tripping on a number nothing measured.
func doctorTimeoutParam(r *http.Request) (time.Duration, error) {
	secs, err := doctorIntParam(r, "timeout")
	if err != nil || secs == 0 {
		return doctorDefaultTimeout, err
	}
	if maxSecs := int(doctorMaxTimeout / time.Second); secs >= maxSecs {
		return doctorMaxTimeout, nil
	}
	return time.Duration(secs) * time.Second, nil
}

// maxDoctorDays caps an expiry threshold. A century is far past the lifetime of
// any credential this PKI issues, so clamping there changes no real answer; it
// exists to keep the day count from overflowing the Duration it becomes.
const maxDoctorDays = 100 * 365

// doctorDaysParam reads a day-valued query parameter (0 = the suite's default).
// Clamped in DAYS before the conversion, for the overflow reason
// doctorTimeoutParam documents: * 24 * time.Hour wraps ~24x sooner than
// * time.Second does, and a negative expiry threshold silently inverts the gate —
// every certificate would look beyond it.
func doctorDaysParam(r *http.Request, name string) (time.Duration, error) {
	days, err := doctorIntParam(r, name)
	if err != nil {
		return 0, err
	}
	if days > maxDoctorDays {
		days = maxDoctorDays
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// doctorIntParam reads a non-negative integer query parameter; absent or empty
// yields 0, which every caller maps onto the suite's own default.
func doctorIntParam(r *http.Request, name string) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, newDoctorParamError(name, raw)
	}
	return n, nil
}

// doctorBoolParam reads a boolean query parameter, accepting the usual forms.
func doctorBoolParam(r *http.Request, name string) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, newDoctorParamError(name, raw)
	}
	return v, nil
}

// doctorParamError is the 400 for a malformed diagnostic parameter.
type doctorParamError struct{ name, value string }

func newDoctorParamError(name, value string) error { return &doctorParamError{name, value} }

func (e *doctorParamError) Error() string {
	return "invalid " + e.name + " parameter " + strconv.Quote(e.value)
}
