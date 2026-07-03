package approval

// Unit tests for the four-eyes / maker-checker state machine (Task 81) against
// an in-memory store faithful to the SQL implementation's semantics (distinct
// approvers via a unique (approval, approver) key; optimistic status
// transitions). White-box (package approval) so the engine clock can be driven
// for deterministic expiry.

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// memStore is an in-memory approval.Store + Auditor for tests.
type memStore struct {
	approvals map[string]*models.PendingApproval
	decisions map[string][]models.ApprovalDecision
	events    []*audit.Event
}

func newMemStore() *memStore {
	return &memStore{
		approvals: map[string]*models.PendingApproval{},
		decisions: map[string][]models.ApprovalDecision{},
	}
}

func (m *memStore) clone(pa *models.PendingApproval) *models.PendingApproval {
	cp := *pa
	cp.ApprovalsCount = m.count(pa.ID, DecisionApprove)
	cp.Decisions = append([]models.ApprovalDecision(nil), m.decisions[pa.ID]...)
	return &cp
}

func (m *memStore) count(id, decision string) int {
	n := 0
	for _, d := range m.decisions[id] {
		if d.Decision == decision {
			n++
		}
	}
	return n
}

func (m *memStore) CreatePendingApproval(a *models.PendingApproval) error {
	cp := *a
	m.approvals[a.ID] = &cp
	return nil
}

func (m *memStore) GetPendingApproval(id string) (*models.PendingApproval, error) {
	pa, ok := m.approvals[id]
	if !ok {
		return nil, nil
	}
	return m.clone(pa), nil
}

func (m *memStore) FindOpenApproval(tenantID, class, fingerprint string) (*models.PendingApproval, error) {
	var newest *models.PendingApproval
	for _, pa := range m.approvals {
		if pa.TenantID == tenantID && pa.OperationClass == class && pa.Fingerprint == fingerprint &&
			(pa.Status == StatusPending || pa.Status == StatusApproved) {
			if newest == nil || pa.CreatedAt.After(newest.CreatedAt) {
				newest = pa
			}
		}
	}
	if newest == nil {
		return nil, nil
	}
	return m.clone(newest), nil
}

func (m *memStore) ListPendingApprovals(tenantID, status, class string, limit int) ([]models.PendingApproval, error) {
	var out []models.PendingApproval
	for _, pa := range m.approvals {
		if tenantID != "" && pa.TenantID != tenantID {
			continue
		}
		if status != "" && pa.Status != status {
			continue
		}
		if class != "" && pa.OperationClass != class {
			continue
		}
		out = append(out, *m.clone(pa))
	}
	return out, nil
}

func (m *memStore) ListApprovalDecisions(id string) ([]models.ApprovalDecision, error) {
	return append([]models.ApprovalDecision(nil), m.decisions[id]...), nil
}

func (m *memStore) AddApprovalDecision(d *models.ApprovalDecision) (bool, error) {
	for _, ex := range m.decisions[d.ApprovalID] {
		if ex.Approver == d.Approver {
			return false, nil // UNIQUE(approval_id, approver)
		}
	}
	cp := *d
	cp.ID = int64(len(m.decisions[d.ApprovalID]) + 1)
	m.decisions[d.ApprovalID] = append(m.decisions[d.ApprovalID], cp)
	return true, nil
}

func (m *memStore) CountApprovalDecisions(id, decision string) (int, error) {
	return m.count(id, decision), nil
}

func (m *memStore) SetApprovalStatus(id, from, to string, at time.Time) (bool, error) {
	pa, ok := m.approvals[id]
	if !ok || pa.Status != from {
		return false, nil // optimistic: the row already moved on
	}
	pa.Status = to
	switch to {
	case StatusApproved, StatusRejected, StatusExpired:
		t := at
		pa.DecidedAt = &t
	case StatusExecuted:
		t := at
		pa.ExecutedAt = &t
	}
	return true, nil
}

func (m *memStore) ListExpirableApprovals(now time.Time) ([]models.PendingApproval, error) {
	var out []models.PendingApproval
	for _, pa := range m.approvals {
		if (pa.Status == StatusPending || pa.Status == StatusApproved) && pa.Expired(now) {
			out = append(out, *m.clone(pa))
		}
	}
	return out, nil
}

func (m *memStore) AppendEvent(e *audit.Event) error {
	m.events = append(m.events, e)
	return nil
}

func (m *memStore) eventCount(action, result string) int {
	n := 0
	for _, e := range m.events {
		if e.Action == action && (result == "" || e.Result == result) {
			n++
		}
	}
	return n
}

// testEngine builds an engine with a driven clock and a threshold-2 policy on
// ca.rotate.
func testEngine(t *testing.T) (*Engine, *memStore, *time.Time) {
	t.Helper()
	st := newMemStore()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	clock := &now
	eng := NewEngine(st, st, Policy{
		Enabled:          true,
		DefaultThreshold: 2,
		TTL:              72 * time.Hour,
	})
	eng.clock = func() time.Time { return *clock }
	return eng, st, clock
}

func guardRotate(t *testing.T, eng *Engine, actor string) GuardResult {
	t.Helper()
	res, err := eng.Guard(context.Background(), GuardRequest{
		Class:       ClassCARotate,
		ResourceKey: "ca:1",
		Summary:     "rotate ca:1",
		Params:      "ca=1;key_type=rsa-4096",
		Actor:       actor,
		Tenant:      models.DefaultTenantID,
	})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	return res
}

// TestUnapprovedGuardedOpBlocked: the first attempt records a pending request
// and blocks; a repeat attempt reuses that request rather than creating another,
// and never executes while unapproved.
func TestUnapprovedGuardedOpBlocked(t *testing.T) {
	eng, st, _ := testEngine(t)

	res := guardRotate(t, eng, "alice")
	if res.Allowed {
		t.Fatal("unapproved guarded operation must be blocked")
	}
	if res.Approval == nil || res.Approval.Status != StatusPending || res.Approval.RequiredApprovals != 2 {
		t.Fatalf("expected a pending request needing 2 approvers, got %+v", res.Approval)
	}
	firstID := res.Approval.ID

	// A second attempt must reuse the same open request, not spawn a duplicate.
	res2 := guardRotate(t, eng, "alice")
	if res2.Allowed || res2.Approval.ID != firstID {
		t.Fatalf("second attempt should reuse request %s, got %+v", firstID, res2.Approval)
	}
	if got := len(st.approvals); got != 1 {
		t.Fatalf("expected exactly 1 stored request, got %d", got)
	}
	if st.eventCount(audit.ActionApprovalRequest, audit.ResultSuccess) != 1 {
		t.Fatalf("expected exactly one approval.request audit event, got %d",
			st.eventCount(audit.ActionApprovalRequest, audit.ResultSuccess))
	}
}

// TestSelfApprovalDenied: the requester cannot approve their own request.
func TestSelfApprovalDenied(t *testing.T) {
	eng, st, _ := testEngine(t)
	id := guardRotate(t, eng, "alice").Approval.ID

	if _, err := eng.Approve(context.Background(), id, "alice", "Alice", "looks fine to me", ""); err != ErrSelfApproval {
		t.Fatalf("self-approval must be denied, got %v", err)
	}
	// The denial is audited, and the request is untouched (still 0 approvals).
	if st.eventCount(audit.ActionApprovalApprove, audit.ResultDenied) != 1 {
		t.Fatal("self-approval denial must be audited")
	}
	pa, _ := eng.Get(id)
	if pa.ApprovalsCount != 0 || pa.Status != StatusPending {
		t.Fatalf("self-approval must not count: %+v", pa)
	}
}

// TestThresholdEnforcement: N DISTINCT approvers are required; one approver
// voting twice does not advance the count, and the operation only executes once
// the threshold is met.
func TestThresholdEnforcement(t *testing.T) {
	eng, _, _ := testEngine(t)
	id := guardRotate(t, eng, "alice").Approval.ID

	// One approval: still short of the threshold, still blocked.
	if pa, err := eng.Approve(context.Background(), id, "bob", "Bob", "", ""); err != nil || pa.Status != StatusPending {
		t.Fatalf("after 1/2 approvals expected pending, got %+v err=%v", pa, err)
	}
	if guardRotate(t, eng, "alice").Allowed {
		t.Fatal("operation must remain blocked at 1 of 2 approvals")
	}

	// The same approver again does not count (distinct-approver constraint).
	if _, err := eng.Approve(context.Background(), id, "bob", "Bob", "", ""); err != ErrAlreadyDecided {
		t.Fatalf("a repeat vote by the same approver must be refused, got %v", err)
	}
	if guardRotate(t, eng, "alice").Allowed {
		t.Fatal("a repeat vote must not satisfy the threshold")
	}

	// A distinct second approver meets the threshold.
	pa, err := eng.Approve(context.Background(), id, "carol", "Carol", "approved", "")
	if err != nil || pa.Status != StatusApproved || pa.ApprovalsCount != 2 {
		t.Fatalf("after 2 distinct approvals expected approved 2/2, got %+v err=%v", pa, err)
	}

	// Now the operation may execute — exactly once (the approval is consumed).
	res := guardRotate(t, eng, "alice")
	if !res.Allowed || res.Approval.Status != StatusExecuted {
		t.Fatalf("approved operation must execute and be consumed, got %+v", res)
	}
	res2 := guardRotate(t, eng, "alice")
	if res2.Allowed {
		t.Fatal("a consumed approval must not authorize a second execution")
	}
	if res2.Approval.ID == id {
		t.Fatal("a fresh attempt after execution must open a NEW request, not reuse the executed one")
	}
}

// TestExpiry: a request past its window cannot be approved and is swept to
// expired; a new attempt opens a fresh request.
func TestExpiry(t *testing.T) {
	eng, st, clock := testEngine(t)
	id := guardRotate(t, eng, "alice").Approval.ID

	// Advance past the 72h TTL.
	*clock = clock.Add(73 * time.Hour)

	if _, err := eng.Approve(context.Background(), id, "bob", "Bob", "", ""); err != ErrExpired {
		t.Fatalf("approving an expired request must fail, got %v", err)
	}
	pa, _ := eng.Get(id)
	if pa.Status != StatusExpired {
		t.Fatalf("expired request must be flipped to expired, got %s", pa.Status)
	}

	// A fresh guard opens a new request (the expired one no longer blocks).
	res := guardRotate(t, eng, "alice")
	if res.Allowed || res.Approval.ID == id || res.Approval.Status != StatusPending {
		t.Fatalf("a new attempt after expiry must open a fresh pending request, got %+v", res.Approval)
	}

	// SweepExpired retires the new one too once it lapses.
	*clock = clock.Add(100 * time.Hour)
	n, err := eng.SweepExpired(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("SweepExpired expected to expire 1 request, got %d err=%v", n, err)
	}
	if st.eventCount(audit.ActionApprovalExpire, audit.ResultSuccess) < 2 {
		t.Fatalf("each expiry must be audited, got %d", st.eventCount(audit.ActionApprovalExpire, audit.ResultSuccess))
	}
}

// TestRejectIsTerminal: a single rejection kills the request; it cannot then be
// approved, and a new attempt opens a fresh request.
func TestRejectIsTerminal(t *testing.T) {
	eng, _, _ := testEngine(t)
	id := guardRotate(t, eng, "alice").Approval.ID

	pa, err := eng.Reject(context.Background(), id, "bob", "Bob", "not now", "")
	if err != nil || pa.Status != StatusRejected {
		t.Fatalf("reject expected terminal rejected, got %+v err=%v", pa, err)
	}
	if _, err := eng.Approve(context.Background(), id, "carol", "Carol", "", ""); err == nil {
		t.Fatal("approving a rejected request must fail")
	}
	res := guardRotate(t, eng, "alice")
	if res.Allowed || res.Approval.ID == id {
		t.Fatalf("after rejection a new attempt must open a fresh request, got %+v", res.Approval)
	}
}

// TestFingerprintPinsParams: an approval granted for one parameter set cannot
// authorize an operation with different parameters.
func TestFingerprintPinsParams(t *testing.T) {
	eng, _, _ := testEngine(t)

	guard := func(params, actor string) GuardResult {
		res, err := eng.Guard(context.Background(), GuardRequest{
			Class: ClassBulkRevoke, ResourceKey: "ca:1", Params: params, Actor: actor, Tenant: models.DefaultTenantID,
		})
		if err != nil {
			t.Fatalf("Guard: %v", err)
		}
		return res
	}

	idA := guard("serials=1,2,3", "alice").Approval.ID
	if _, err := eng.Approve(context.Background(), idA, "bob", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Approve(context.Background(), idA, "carol", "", "", ""); err != nil {
		t.Fatal(err)
	}

	// A different selection must NOT be authorized by the approval of {1,2,3}.
	resB := guard("serials=4,5,6", "alice")
	if resB.Allowed {
		t.Fatal("approval for one selection must not authorize a different selection")
	}
	if resB.Approval.ID == idA {
		t.Fatal("a different parameter set must open its own request")
	}

	// The originally-approved selection still executes.
	resA := guard("serials=1,2,3", "alice")
	if !resA.Allowed {
		t.Fatal("the approved selection must execute")
	}
}

// TestDisabledAndUnguarded: a disabled policy, or a class with a zero threshold,
// allows the operation immediately without recording anything.
func TestDisabledAndUnguarded(t *testing.T) {
	st := newMemStore()
	// Disabled policy.
	off := NewEngine(st, st, Policy{Enabled: false, DefaultThreshold: 2})
	if res, err := off.Guard(context.Background(), GuardRequest{Class: ClassCARotate, ResourceKey: "ca:1", Actor: "a"}); err != nil || !res.Allowed {
		t.Fatalf("disabled gate must allow, got %+v err=%v", res, err)
	}
	// Enabled but this class explicitly unguarded (threshold 0).
	partial := NewEngine(st, st, Policy{Enabled: true, DefaultThreshold: 2, Thresholds: map[string]int{ClassCARotate: 0}})
	if res, err := partial.Guard(context.Background(), GuardRequest{Class: ClassCARotate, ResourceKey: "ca:1", Actor: "a"}); err != nil || !res.Allowed {
		t.Fatalf("unguarded class must allow, got %+v err=%v", res, err)
	}
	if len(st.approvals) != 0 {
		t.Fatal("an allowed (ungated) operation must not record a request")
	}
	// But a guarded class in the same policy still blocks.
	if res, _ := partial.Guard(context.Background(), GuardRequest{Class: ClassBulkRevoke, ResourceKey: "ca:1", Actor: "a"}); res.Allowed {
		t.Fatal("a guarded class must still block")
	}
}
