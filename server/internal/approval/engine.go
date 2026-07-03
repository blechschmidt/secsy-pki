package approval

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Engine owns the approval state machine. It is safe for concurrent use: all
// mutating steps are optimistic conditional updates in the store, so racing
// callers converge without clobbering each other.
type Engine struct {
	store Store
	audit Auditor
	pol   Policy
	// clock is injectable so tests can drive expiry deterministically.
	clock func() time.Time
	// onTerminal, when set, is invoked after a request reaches a NEGATIVE
	// terminal state (rejected or expired) with the outcome string
	// OutcomeDenied or OutcomeExpired. The wiring layer uses it to emit
	// operation-class-specific audit events and metrics (e.g. cert.issue.denied,
	// Task 84) for classes that need them, without coupling this package to those
	// domains. It runs synchronously after the transition is durably recorded and
	// must not block. The positive terminal (executed) is owned by the caller that
	// completes the operation, so it is deliberately not reported here.
	onTerminal func(pa *models.PendingApproval, outcome string)
}

// NewEngine builds an Engine. A nil store or auditor is tolerated only for a
// disabled policy (the zero Engine acts as a no-op gate); a guarded policy
// requires both.
func NewEngine(store Store, aud Auditor, pol Policy) *Engine {
	return &Engine{store: store, audit: aud, pol: pol, clock: time.Now}
}

// SetTerminalHook installs a callback invoked when a request reaches a negative
// terminal state (rejected or expired). See Engine.onTerminal. Passing nil
// clears it. It is safe to call once during wiring, before the engine serves.
func (e *Engine) SetTerminalHook(fn func(pa *models.PendingApproval, outcome string)) {
	if e == nil {
		return
	}
	e.onTerminal = fn
}

// fireTerminal invokes the terminal hook, if installed, tolerating a nil engine.
func (e *Engine) fireTerminal(pa *models.PendingApproval, outcome string) {
	if e != nil && e.onTerminal != nil && pa != nil {
		e.onTerminal(pa, outcome)
	}
}

// Policy returns the engine's effective policy.
func (e *Engine) Policy() Policy {
	if e == nil {
		return Policy{}
	}
	return e.pol
}

// now returns the engine clock (defaulting to time.Now for a zero Engine).
func (e *Engine) now() time.Time {
	if e.clock != nil {
		return e.clock()
	}
	return time.Now()
}

// GuardRequest describes the operation a caller is about to perform. ResourceKey
// is a stable, human-meaningful target id (e.g. "ca:<id>"); Params is the
// canonical serialization of the operation's inputs used to pin the approval to
// exactly these parameters (falling back to ResourceKey when empty).
type GuardRequest struct {
	Class        string
	ResourceKey  string
	ResourceName string
	Summary      string
	Details      string
	Params       string
	Actor        string
	ActorName    string
	Tenant       string
	IP           string
	// Payload is an opaque, class-specific serialization of the operation stored
	// on a freshly created request so it can be completed after approval without
	// the requester resubmitting it (Task 84's cert.issue parks the CSR and
	// issuance parameters here). It is used only on the create path.
	Payload string
	// ParkOnly makes Guard never consume an approved request inline: it always
	// reports the operation as blocked (Allowed=false), returning the pending or
	// approved request so the caller can direct the requester to fetch the
	// completed result separately. It is used by classes whose completion is a
	// distinct, server-side step rather than a re-run of the original call
	// (cert.issue). Admin-op classes leave it false to keep the re-run-consumes
	// semantics.
	ParkOnly bool
}

func (r GuardRequest) tenant() string {
	if r.Tenant == "" {
		return models.DefaultTenantID
	}
	return r.Tenant
}

func (r GuardRequest) params() string {
	if r.Params != "" {
		return r.Params
	}
	return r.ResourceKey
}

// GuardResult reports the gate decision. When Allowed is false the caller must
// NOT execute the operation; Approval names the pending (or freshly created)
// request the operator and approvers act on.
type GuardResult struct {
	Allowed  bool
	Approval *models.PendingApproval
	Reason   string
	// Created is true only when this call recorded a brand-new pending request
	// (rather than reusing an already-open one), so the caller can emit a
	// "request parked" domain event exactly once instead of on every re-attempt.
	Created bool
}

// Guard is the fail-closed pre-execution chokepoint. For an unguarded class it
// allows immediately. For a guarded class it:
//
//   - consumes an existing approved request matching the operation fingerprint
//     (marking it executed) and allows the operation exactly once; or
//   - reports the still-pending request blocking the operation; or
//   - creates a fresh pending request and blocks, so the very first attempt
//     records what needs approving.
//
// A store error blocks (returns a non-nil error): the gate never fails open.
func (e *Engine) Guard(ctx context.Context, req GuardRequest) (GuardResult, error) {
	if e == nil || !e.pol.Guarded(req.Class) {
		return GuardResult{Allowed: true, Reason: "not guarded"}, nil
	}
	tenant := req.tenant()
	fp := Fingerprint(req.Class, req.ResourceKey, req.params())
	now := e.now()

	existing, err := e.store.FindOpenApproval(tenant, req.Class, fp)
	if err != nil {
		return GuardResult{}, fmt.Errorf("approval: looking up open request: %w", err)
	}
	if existing != nil && existing.Expired(now) {
		// Retire the stale request before creating a fresh one, so the operator
		// isn't blocked forever on a request nobody can act on anymore.
		if ok, _ := e.store.SetApprovalStatus(existing.ID, existing.Status, StatusExpired, now); ok {
			e.record(existing, audit.ActionApprovalExpire, req.Actor, req.ActorName, req.IP,
				audit.ResultSuccess, "expired before execution")
			e.fireTerminal(existing, OutcomeExpired)
		}
		existing = nil
	}
	if existing != nil {
		switch existing.Status {
		case StatusApproved:
			// ParkOnly classes complete via a separate server-side step (e.g.
			// cert.issue's fetch/deliver), so never consume inline: report the
			// approved request as ready-to-fetch while still blocking this call path.
			if req.ParkOnly {
				return GuardResult{Allowed: false, Approval: existing, Reason: "approved; awaiting completion"}, nil
			}
			// Atomically consume: approved -> executed. Only one racing caller wins.
			ok, err := e.store.SetApprovalStatus(existing.ID, StatusApproved, StatusExecuted, now)
			if err != nil {
				return GuardResult{}, fmt.Errorf("approval: consuming approved request: %w", err)
			}
			if ok {
				existing.Status = StatusExecuted
				existing.ExecutedAt = &now
				e.record(existing, audit.ActionApprovalExecute, req.Actor, req.ActorName, req.IP,
					audit.ResultSuccess, "threshold met; operation authorized")
				return GuardResult{Allowed: true, Approval: existing, Reason: "approved"}, nil
			}
			// Lost the race (already consumed/expired). Reload and block.
			reloaded, _ := e.store.GetPendingApproval(existing.ID)
			return GuardResult{Allowed: false, Approval: reloaded, Reason: "request already consumed"}, nil
		case StatusPending:
			return GuardResult{Allowed: false, Approval: existing, Reason: "awaiting approvals"}, nil
		}
	}

	pa := &models.PendingApproval{
		ID:                newID(),
		TenantID:          tenant,
		OperationClass:    req.Class,
		ResourceKey:       req.ResourceKey,
		ResourceName:      req.ResourceName,
		Fingerprint:       fp,
		Summary:           req.Summary,
		Details:           req.Details,
		RequestedBy:       req.Actor,
		RequestedByName:   req.ActorName,
		RequiredApprovals: e.pol.Required(req.Class),
		Status:            StatusPending,
		CreatedAt:         now,
		ExpiresAt:         now.Add(e.pol.ttl()),
		Payload:           req.Payload,
	}
	if err := e.store.CreatePendingApproval(pa); err != nil {
		return GuardResult{}, fmt.Errorf("approval: recording request: %w", err)
	}
	e.record(pa, audit.ActionApprovalRequest, req.Actor, req.ActorName, req.IP, audit.ResultSuccess,
		fmt.Sprintf("requires %d distinct approver(s)", pa.RequiredApprovals))
	return GuardResult{Allowed: false, Approval: pa, Reason: "approval required", Created: true}, nil
}

// Approve records one approver's sign-off. It denies self-approval (approver ==
// requester) and rejects a repeat vote by the same approver. When the count of
// distinct approvers reaches the required threshold the request transitions to
// approved and the guarded operation may then execute.
func (e *Engine) Approve(ctx context.Context, id, approver, approverName, comment, ip string) (*models.PendingApproval, error) {
	pa, err := e.load(id)
	if err != nil {
		return nil, err
	}
	now := e.now()
	if pa.Status != StatusPending {
		return nil, &StateError{Status: pa.Status}
	}
	if pa.Expired(now) {
		e.expire(pa, approver, approverName, ip)
		return nil, ErrExpired
	}
	if approver == pa.RequestedBy {
		e.record(pa, audit.ActionApprovalApprove, approver, approverName, ip, audit.ResultDenied,
			"self-approval denied")
		return nil, ErrSelfApproval
	}
	inserted, err := e.store.AddApprovalDecision(&models.ApprovalDecision{
		ApprovalID:   id,
		Approver:     approver,
		ApproverName: approverName,
		Decision:     DecisionApprove,
		Comment:      comment,
		CreatedAt:    now,
	})
	if err != nil {
		return nil, fmt.Errorf("approval: recording decision: %w", err)
	}
	if !inserted {
		return nil, ErrAlreadyDecided
	}
	count, err := e.store.CountApprovalDecisions(id, DecisionApprove)
	if err != nil {
		return nil, fmt.Errorf("approval: counting approvals: %w", err)
	}
	detail := fmt.Sprintf("%d of %d approval(s)", count, pa.RequiredApprovals)
	if count >= pa.RequiredApprovals {
		if ok, err := e.store.SetApprovalStatus(id, StatusPending, StatusApproved, now); err != nil {
			return nil, fmt.Errorf("approval: marking approved: %w", err)
		} else if ok {
			detail += "; threshold met — operation authorized"
		}
	}
	e.record(pa, audit.ActionApprovalApprove, approver, approverName, ip, audit.ResultSuccess, detail)
	return e.load(id)
}

// Claim atomically transitions an approved request to executed so a ParkOnly
// class (Task 84's cert.issue) can complete the guarded operation exactly once.
// It returns claimed=true to the single caller that won the transition; racing
// callers get claimed=false and the current request state, and must NOT perform
// the operation. On a win it appends the approval.execute lifecycle event; the
// caller records the operation's own outcome via RecordResult and audits the
// domain event. A request that is not currently approved yields a StateError
// (pending) or is returned as-is when already executed (idempotent completion).
func (e *Engine) Claim(ctx context.Context, id, actor, actorName, ip string) (pa *models.PendingApproval, claimed bool, err error) {
	pa, err = e.load(id)
	if err != nil {
		return nil, false, err
	}
	switch pa.Status {
	case StatusExecuted:
		// Already completed by an earlier claim; the caller delivers the stored
		// Result rather than re-running the operation.
		return pa, false, nil
	case StatusApproved:
		// fall through to the atomic claim below.
	default:
		return pa, false, &StateError{Status: pa.Status}
	}
	now := e.now()
	ok, err := e.store.SetApprovalStatus(id, StatusApproved, StatusExecuted, now)
	if err != nil {
		return nil, false, fmt.Errorf("approval: claiming approved request: %w", err)
	}
	if !ok {
		// Lost the race (another caller consumed it, or it expired). Reload so the
		// caller sees the authoritative state.
		reloaded, _ := e.load(id)
		return reloaded, false, nil
	}
	pa.Status = StatusExecuted
	pa.ExecutedAt = &now
	e.record(pa, audit.ActionApprovalExecute, actor, actorName, ip, audit.ResultSuccess,
		"threshold met; operation completed")
	return pa, true, nil
}

// RecordResult stores an opaque outcome blob against a request (e.g. the issued
// certificate's serial for cert.issue), so the completed operation's artifact
// can be delivered on later fetches. It is a plain update, independent of the
// state machine; call it after Claim has authorized completion.
func (e *Engine) RecordResult(ctx context.Context, id, result string) error {
	if err := e.store.SetApprovalResult(id, result); err != nil {
		return fmt.Errorf("approval: recording result: %w", err)
	}
	return nil
}

// Reject vetoes a pending request. A single rejection is terminal (four-eyes:
// any approver may block). The requester may also reject to withdraw their own
// request.
func (e *Engine) Reject(ctx context.Context, id, approver, approverName, comment, ip string) (*models.PendingApproval, error) {
	pa, err := e.load(id)
	if err != nil {
		return nil, err
	}
	now := e.now()
	if pa.Status != StatusPending {
		return nil, &StateError{Status: pa.Status}
	}
	if pa.Expired(now) {
		e.expire(pa, approver, approverName, ip)
		return nil, ErrExpired
	}
	// Record the veto decision (best-effort: a duplicate from an approver who
	// already voted must not stop the rejection from taking effect).
	_, _ = e.store.AddApprovalDecision(&models.ApprovalDecision{
		ApprovalID:   id,
		Approver:     approver,
		ApproverName: approverName,
		Decision:     DecisionReject,
		Comment:      comment,
		CreatedAt:    now,
	})
	rejected, err := e.store.SetApprovalStatus(id, StatusPending, StatusRejected, now)
	if err != nil {
		return nil, fmt.Errorf("approval: marking rejected: %w", err)
	}
	detail := "rejected"
	if comment != "" {
		detail += ": " + comment
	}
	e.record(pa, audit.ActionApprovalReject, approver, approverName, ip, audit.ResultSuccess, detail)
	if rejected {
		e.fireTerminal(pa, OutcomeDenied)
	}
	return e.load(id)
}

// Get returns one request with its decisions, or ErrNotFound.
func (e *Engine) Get(id string) (*models.PendingApproval, error) {
	return e.load(id)
}

// List returns requests matching the query (defaults the tenant filter to
// caller-supplied). Newest first.
func (e *Engine) List(q Query) ([]models.PendingApproval, error) {
	return e.store.ListPendingApprovals(q.TenantID, q.Status, q.Class, q.Limit)
}

// SweepExpired flips every open request past its window to expired, auditing
// each. It is idempotent and safe to run from a periodic job. Returns the count
// of requests expired.
func (e *Engine) SweepExpired(ctx context.Context) (int, error) {
	if e == nil || !e.pol.Enabled {
		return 0, nil
	}
	now := e.now()
	list, err := e.store.ListExpirableApprovals(now)
	if err != nil {
		return 0, fmt.Errorf("approval: listing expirable requests: %w", err)
	}
	n := 0
	for i := range list {
		pa := &list[i]
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if ok, _ := e.store.SetApprovalStatus(pa.ID, pa.Status, StatusExpired, now); ok {
			e.record(pa, audit.ActionApprovalExpire, "system", "", "", audit.ResultSuccess, "expired (swept)")
			e.fireTerminal(pa, OutcomeExpired)
			n++
		}
	}
	return n, nil
}

// load fetches a request, translating absence into ErrNotFound.
func (e *Engine) load(id string) (*models.PendingApproval, error) {
	pa, err := e.store.GetPendingApproval(id)
	if err != nil {
		return nil, fmt.Errorf("approval: loading request: %w", err)
	}
	if pa == nil {
		return nil, ErrNotFound
	}
	return pa, nil
}

// expire best-effort flips a request to expired and audits it.
func (e *Engine) expire(pa *models.PendingApproval, actor, actorName, ip string) {
	if ok, _ := e.store.SetApprovalStatus(pa.ID, pa.Status, StatusExpired, e.now()); ok {
		e.record(pa, audit.ActionApprovalExpire, actor, actorName, ip, audit.ResultSuccess, "expired")
		e.fireTerminal(pa, OutcomeExpired)
	}
}

// record appends one approval-lifecycle event to the audit chain. Audit is
// best-effort here: a transient append failure must not wedge the workflow, and
// the guarded operation's own success/denial is audited separately by the
// caller. The approval id is the Target so a request and every decision on it
// share a stable correlation key.
func (e *Engine) record(pa *models.PendingApproval, action, actor, actorName, ip, result, detail string) {
	if e.audit == nil {
		return
	}
	_ = e.audit.AppendEvent(&audit.Event{
		Timestamp:  e.now(),
		Actor:      actor,
		ActorName:  actorName,
		Action:     action,
		Tenant:     pa.TenantID,
		Target:     pa.ID,
		TargetName: pa.OperationClass + ":" + pa.ResourceKey,
		Result:     result,
		Detail:     detail,
		IP:         ip,
	})
}

// newID mints a request identifier with a readable prefix.
func newID() string {
	return "apr_" + uuid.New().String()
}
