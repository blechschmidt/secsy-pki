package handlers

// REST surface for the certificate-inventory retention/archival job (Task 157) —
// the counterpart of `secsy-ca inventory retention status|dry-run|run`
// (Task 198). The background loop is leader-elected and silent, and the only way
// to inspect its policy or trigger a pass was shell access to the CA host, so the
// console could not show an operator why the hot inventory was (or was not)
// shrinking.
//
// Both endpoints drive the SAME retention.Runner the background loop and the CLI
// use, over the SAME configured policy, so the console can never report a
// different retention posture than `secsy-ca` does: only long-expired, terminal,
// non-held, non-approval-pinned rows are eligible, and the authoritative
// revoked_certificates table is never touched (OCSP/CRL for every retained
// serial is unaffected).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/retention"
)

// retentionRunTimeout bounds one API-triggered pass. A pass walks the whole
// eligible set in bounded batched transactions, so on a large inventory it
// genuinely takes many minutes — but it is still a request, and a mutating pass
// must not be able to run without a deadline at all.
const retentionRunTimeout = 30 * time.Minute

// retentionMu serializes real retention passes across everything in this process,
// the same way publishMu serializes publishes (see publish.go for why a guard over
// a process-wide resource is package-level rather than per-API).
//
// It protects a different resource, hence a separate guard: the leader-elected
// background loop is gated "so replicas do not race each other's archive/prune
// transactions" (cmd/server/retention.go), and internal/retention holds no lock of
// its own — so within one process this endpoint could otherwise start a pass
// against the leader's, with both hard-deleting from the same archive. The
// background loop takes this guard through TryRetentionLock for exactly that
// reason.
//
// Only the MUTATING pass takes it. A dry run reads counts and touches nothing, so
// making it contend would only hide the preview an operator wants precisely while
// a pass is running.
var retentionMu sync.Mutex

// TryRetentionLock acquires the process-wide retention single-flight, reporting
// false when a pass is already running. The caller must call release exactly once
// on every path when ok is true.
//
// Exported for cmd/server's leader-elected retention loop, which archives and
// prunes the same rows POST /api/inventory/retention/run does. A loser does not
// queue: retention is idempotent and periodic, so the work the contended pass is
// already doing is the work the loser would have done.
func TryRetentionLock() (release func(), ok bool) {
	if !retentionMu.TryLock() {
		return nil, false
	}
	return retentionMu.Unlock, true
}

// RetentionStatusResponse is the body of GET /api/inventory/retention: the
// resolved policy, how much is eligible right now, and the newest recorded run.
// It is field-for-field what `secsy-ca inventory retention status -json` prints.
type RetentionStatusResponse struct {
	// Enabled reports whether the leader-elected background loop runs. It is
	// independent of these endpoints, which work either way.
	Enabled bool `json:"enabled"`
	// Interval is the resolved background-loop period (e.g. "24h0m0s").
	Interval string `json:"interval"`
	// Snapshot carries mode, window, cutoff, prune_cutoff, eligible, prunable and
	// archive_size inline.
	retention.Snapshot
	// LastRun is the newest inventory.retention audit event — the same offline
	// source of truth doctor's retention.freshness check reads. Absent when no run
	// has ever been recorded.
	LastRun *audit.Event `json:"last_run,omitempty"`
}

// RetentionRunRequest is the body of POST /api/inventory/retention/run. One
// endpoint serves both CLI subcommands: dry_run=true is `inventory retention
// dry-run` (reports exactly what would happen, mutating nothing) and the default
// is `inventory retention run`.
type RetentionRunRequest struct {
	DryRun bool `json:"dry_run,omitempty"`
}

// RetentionRunResponse is the outcome of one pass. It embeds the shared
// retention.Result so the payload matches `secsy-ca inventory retention run
// -json` exactly (mode, dry_run, window, cutoff, eligible, archived, pruned,
// backlog, archive_size, protected_by_approvals, digest, started, duration_ms).
type RetentionRunResponse struct {
	retention.Result
	// Error is set, with HTTP 500, when the pass failed part-way. The counts above
	// still report the work that committed before the failure — batches are
	// independent transactions, so a partial pass is a real, durable outcome
	// rather than something to hide behind a bare error.
	Error string `json:"error,omitempty"`
}

// retentionRunner builds the runner for one request over the configured policy.
// The logger is the process logger (not discarded as in the CLI): a retention
// pass triggered through the API is a server-side event and belongs in the
// server log next to the background loop's passes.
func (a *API) retentionRunner(w http.ResponseWriter) (*retention.Runner, bool) {
	deps, ok := a.requireOps(w, "inventory retention")
	if !ok {
		return nil, false
	}
	runner, err := retention.New(a.db, deps.Config.Retention, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the configured retention policy is invalid: %v", err)
		return nil, false
	}
	return runner, true
}

// InventoryRetentionStatus handles GET /api/inventory/retention — the REST form
// of `secsy-ca inventory retention status`.
//
// Gated on the PLATFORM-wide audit:read capability, like the other cross-tenant
// reads (event export, HSM audit views): the eligibility and archive counts span
// every tenant's inventory, so a tenant-scoped auditor must not be able to read
// them. It is a pure read — cheap counts, no scan, no mutation.
func (a *API) InventoryRetentionStatus(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	// a.can consults PLATFORM roles only (never a tenant-scoped grant), which is
	// precisely the standing this cross-tenant view requires.
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "platform-wide audit:read capability required (admin or auditor role)")
		return
	}
	runner, ok := a.retentionRunner(w)
	if !ok {
		return
	}
	snap, err := runner.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading retention state: %v", err)
		return
	}
	deps := a.opsDeps()
	resp := RetentionStatusResponse{
		Enabled:  deps.Config.Retention.Enabled,
		Interval: deps.Config.Retention.Interval().String(),
		Snapshot: snap,
	}
	// The newest recorded run, exactly as the CLI resolves it.
	if events, _, lerr := a.db.ListEvents(audit.ActionInventoryRetention, "", "", 1, 0); lerr == nil && len(events) > 0 {
		resp.LastRun = &events[0]
	}
	writeJSON(w, http.StatusOK, resp)
}

// RunInventoryRetention handles POST /api/inventory/retention/run — the REST
// form of `secsy-ca inventory retention run` and `... dry-run`, selected by the
// dry_run flag.
//
// Gated on the platform-wide ca:configure capability. A real pass archives and
// (in prune mode) hard-deletes inventory rows across every tenant: it is the
// execution of deployment-wide data-retention policy, so it is held at the same
// level as the policy itself and is deliberately not reachable with cert:issue
// or a tenant-scoped role. The dry-run shares that gate on purpose — previewing
// a destructive pass is an operator action, and one gate cannot be talked into
// running the wrong half.
func (a *API) RunInventoryRetention(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionInventoryRetention, "", "", audit.ResultDenied,
			"ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}

	var req RetentionRunRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}
	}

	runner, ok := a.retentionRunner(w)
	if !ok {
		return
	}

	// Dry run: report what a pass would do, touching nothing. No audit event — it
	// mutates nothing, and the CLI's dry-run records none either.
	if req.DryRun {
		res, err := runner.Plan(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, RetentionRunResponse{Result: res, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, RetentionRunResponse{Result: res})
		return
	}

	// One real pass at a time in this process — including the leader-elected loop's,
	// which takes the same guard. Two passes over one archive would interleave their
	// prune transactions, and in prune mode those are hard deletes.
	release, free := TryRetentionLock()
	if !free {
		writeError(w, http.StatusConflict,
			"a retention pass is already running; retry when it completes")
		return
	}
	defer release()

	// A pass hard-deletes rows in prune mode, in a sequence of independent
	// transactions. A client hanging up between batches must not stop it half-way —
	// that leaves the archive and the hot table in a state no audit event describes —
	// so the run is detached from the request's cancellation (values, and therefore
	// the actor and request id, are kept) and bounded on its own. This is the shape
	// POST /api/publish and POST /api/backup/verify-restore already use.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), retentionRunTimeout)
	defer cancel()

	// Real pass. RunNow records the shared, tamper-evident inventory.retention
	// event (actor "retention") carrying the manifest digest, exactly as the CLI
	// and the background loop do; the event recorded below adds the one thing that
	// path cannot know — which operator asked for it.
	res, runErr := runner.RunNow(ctx)
	result, detail := audit.ResultSuccess, retentionDetail(res)
	if runErr != nil {
		result, detail = audit.ResultError, "error="+runErr.Error()+" "+retentionDetail(res)
	}
	a.recordEvent(r, audit.ActionInventoryRetention, "", "", result, detail+" via=api")
	if runErr != nil {
		writeJSON(w, http.StatusInternalServerError, RetentionRunResponse{Result: res, Error: runErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, RetentionRunResponse{Result: res})
}

// retentionDetail renders the operator-attributed audit detail for one pass,
// following the runner's own key=value shape so both events read alike.
func retentionDetail(res retention.Result) string {
	return fmt.Sprintf("mode=%s archived=%d pruned=%d eligible=%d backlog=%d archive_size=%d window=%s digest=%s",
		res.Mode, res.Archived, res.Pruned, res.Eligible, res.Backlog, res.ArchiveSize, res.Window, res.Digest)
}
