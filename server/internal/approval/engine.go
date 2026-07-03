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
}

// NewEngine builds an Engine. A nil store or auditor is tolerated only for a
// disabled policy (the zero Engine acts as a no-op gate); a guarded policy
// requires both.
func NewEngine(store Store, aud Auditor, pol Policy) *Engine {
	return &Engine{store: store, audit: aud, pol: pol, clock: time.Now}
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
		}
		existing = nil
	}
	if existing != nil {
		switch existing.Status {
		case StatusApproved:
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
	}
	if err := e.store.CreatePendingApproval(pa); err != nil {
		return GuardResult{}, fmt.Errorf("approval: recording request: %w", err)
	}
	e.record(pa, audit.ActionApprovalRequest, req.Actor, req.ActorName, req.IP, audit.ResultSuccess,
		fmt.Sprintf("requires %d distinct approver(s)", pa.RequiredApprovals))
	return GuardResult{Allowed: false, Approval: pa, Reason: "approval required"}, nil
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
	if _, err := e.store.SetApprovalStatus(id, StatusPending, StatusRejected, now); err != nil {
		return nil, fmt.Errorf("approval: marking rejected: %w", err)
	}
	detail := "rejected"
	if comment != "" {
		detail += ": " + comment
	}
	e.record(pa, audit.ActionApprovalReject, approver, approverName, ip, audit.ResultSuccess, detail)
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
