package handlers

// REST surface for on-demand Certificate Transparency inclusion verification —
// the counterpart of `secsy-ca ct verify-inclusion` (Task 198).
// POST /api/ct/verify-inclusion.
//
// GET /api/ct/inclusion (ct.go) shows what the background monitor last recorded;
// this triggers the check. An SCT is a log's signed promise to merge a
// certificate into its append-only tree within its Maximum Merge Delay, and the
// only way to learn whether the log kept that promise was to wait for the
// leader-elected monitor's next tick — which a console operator can neither see
// nor hasten. Now they can ask, and read the answer in the same page.
//
// It drives the SAME ctmonitor.Monitor the background job and the CLI use, over
// the same configured logs, so the console can never report a different inclusion
// posture than `secsy-ca` does. Like the CLI it passes no notifier: the operator
// is looking at the result, so a duplicate alert fan-out would be noise. The scan
// is HSM-free — it reads certificates from the store, fetches over HTTP, and
// verifies Merkle proofs with the logs' public keys.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/ctmonitor"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ctVerifyTimeout bounds one on-demand scan. A scan is a request, and every
// certificate it examines costs a get-sth and a get-proof-by-hash round trip to a
// third-party log, so it must not be able to hold a server worker open for as
// long as those logs feel like taking. Generous, because a full configured run
// genuinely takes minutes against a slow log — the per-request bound inside the
// monitor is the finer-grained one.
const ctVerifyTimeout = 10 * time.Minute

// CTVerifyInclusionRequest is the body of POST /api/ct/verify-inclusion. The body
// is optional; omitting it scans with the configured per-run bound.
type CTVerifyInclusionRequest struct {
	// Max bounds how many certificates this run examines, NARROWING
	// certificate_transparency.inclusion_monitor.max_certs_per_run (the CLI's
	// -max). Zero, negative, or a value at or above the configured bound uses the
	// configured bound — a request cannot raise it.
	Max int `json:"max,omitempty"`
}

// CTVerifyInclusionResponse is the outcome of one scan: the shared
// ctmonitor.ScanResult (started_at, certs, checked, included, pending, failed,
// unknown_log, errors, new_misbehavior) plus the standing backlog counts, so the
// console can render the run and the overall state from one call.
type CTVerifyInclusionResponse struct {
	ctmonitor.ScanResult
	// Counts is the standing per-status SCT tally after the scan, keyed exactly as
	// GET /api/ct/inclusion reports it (included|pending|failed|unknown_log).
	Counts map[string]int `json:"counts,omitempty"`
	// Error is set, with HTTP 500, when the scan itself failed (e.g. enumerating
	// the store). Per-SCT failures are not errors — they are the "failed" tally,
	// which is the log-misbehavior signal.
	Error string `json:"error,omitempty"`
}

// VerifyCTInclusion handles POST /api/ct/verify-inclusion — the REST form of
// `secsy-ca ct verify-inclusion`.
//
// Gated on the PLATFORM-wide cert:issue capability, exactly like
// POST /api/discovery/scan: the run actively reaches out to third-party CT logs
// and writes inclusion state across every tenant's certificates, so it is held
// above the read standing that views the recorded result. A tenant-scoped issuer
// is denied — the scan is not scopable to one tenant.
func (a *API) VerifyCTInclusion(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionIssue) {
		a.recordEvent(r, audit.ActionCTInclusion, "", "", audit.ResultDenied,
			"CT inclusion verification requires the platform issue capability")
		writeError(w, http.StatusForbidden, "CT inclusion verification requires the issue capability (admin or issuer role)")
		return
	}

	var req CTVerifyInclusionRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	deps, ok := a.requireOps(w, "CT inclusion verification")
	if !ok {
		return
	}
	submitter, err := ctSubmitterForMonitor(deps.Config.CertificateTransparency)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the configured CT logs are unusable: %v", err)
		return
	}
	if submitter == nil {
		writeError(w, http.StatusServiceUnavailable,
			"no CT logs are configured (certificate_transparency.logs); there is nothing to verify inclusion against")
		return
	}

	// The request's max may only NARROW the configured per-run bound, never widen
	// it. config's MaxCerts() hands back any positive number unchanged, so treating
	// the body as authoritative would make max_certs_per_run advisory: one caller
	// could load every pending certificate and hit third-party CT logs once per
	// SCT, and N concurrent callers could each start a full scan. The configured
	// value is the deployment's bound on outbound CT traffic; a console operator
	// asking for "just a quick look" is the only thing this field is for.
	imCfg := deps.Config.CertificateTransparency.InclusionMonitor
	if req.Max > 0 && req.Max < imCfg.MaxCerts() {
		imCfg.MaxCertsPerRun = req.Max
	}
	// No notifier: the operator triggered this and is reading the result, so the
	// misbehavior fan-out stays the background job's job (the monitor still
	// records, audits, and counts every finding).
	mon, err := ctmonitor.New(a.db, submitter, imCfg, nil, log.Default())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "building the CT inclusion monitor: %v", err)
		return
	}

	// A scan WRITES inclusion state (and appends misbehavior findings), so a client
	// that hangs up must not abandon it half-applied: the run is detached from the
	// request's cancellation — keeping its values, so the actor and request id still
	// reach the audit event — and bounded on its own, the same shape the publish and
	// backup-drill endpoints use.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), ctVerifyTimeout)
	defer cancel()

	// RunOnce records the shared ct.inclusion audit event (actor "ct-monitor") with
	// the per-status tallies, exactly as the background job and the CLI do; the
	// event below adds what that path cannot know — which operator asked.
	res := mon.RunOnce(ctx)
	resp := CTVerifyInclusionResponse{ScanResult: *res}
	if counts, cerr := a.db.CountSCTInclusionByStatus(); cerr == nil {
		resp.Counts = counts
	}

	if res.Err != nil {
		resp.Error = res.Err.Error()
		a.recordEvent(r, audit.ActionCTInclusion, "", "", audit.ResultError, "error="+res.Err.Error()+" via=api")
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}

	// A completed scan is a success even when it found misbehavior: the finding is
	// the point of running it. It is audited as an error result (matching the
	// monitor's own convention) and surfaced in failed / new_misbehavior, which is
	// what the console alarms on.
	result := audit.ResultSuccess
	if res.NewMisbehavior > 0 {
		result = audit.ResultError
	}
	a.recordEvent(r, audit.ActionCTInclusion, "", "", result, ctScanDetail(res)+" via=api")
	writeJSON(w, http.StatusOK, resp)
}

// ctScanDetail renders one scan in the same key=value shape the monitor's own
// ct.inclusion event uses, so both read alike in the log.
func ctScanDetail(res *ctmonitor.ScanResult) string {
	return fmt.Sprintf("certs=%d checked=%d included=%d pending=%d failed=%d unknown_log=%d errors=%d new_misbehavior=%d",
		res.Certs, res.Checked, res.Included, res.Pending, res.Failed, res.UnknownLog, res.Errors, res.NewMisbehavior)
}

// ctSubmitterForMonitor builds the CT log registry the inclusion monitor resolves
// an SCT's log id against, from the same certificate_transparency.logs block the
// server and the CLI read. It returns (nil, nil) when no logs are configured.
//
// Only what inclusion verification needs is wired: each log's URL, public key
// (inline or from public_key_file), and MMD. Operator attribution
// (known_logs_file) is deliberately left out — it exists for the issuance-time
// operator-diversity policy and has no bearing on whether a log honored an SCT.
func ctSubmitterForMonitor(cfg config.CTConfig) (*ct.Submitter, error) {
	if len(cfg.Logs) == 0 {
		return nil, nil
	}
	logs := make([]ct.LogConfig, 0, len(cfg.Logs))
	for _, l := range cfg.Logs {
		pubPEM := l.PublicKey
		if pubPEM == "" && l.PublicKeyFile != "" {
			data, err := os.ReadFile(l.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("reading public_key_file for CT log %q: %w", l.Name, err)
			}
			pubPEM = string(data)
		}
		logs = append(logs, ct.LogConfig{Name: l.Name, URL: l.URL, PublicKeyPEM: pubPEM, MMD: l.MMD()})
	}
	// A conservative whole-exchange bound, matching the server's and the CLI's
	// submitter client; the monitor additionally applies its configured per-request
	// timeout to each get-sth / get-proof-by-hash call.
	return ct.NewSubmitter(logs, &http.Client{Timeout: 30 * time.Second})
}
