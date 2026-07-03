// Package approval implements a four-eyes / maker-checker approval workflow for
// high-risk administrative operations (Task 81).
//
// It adds a request -> approve -> execute state machine, backed by a
// pending_approvals store, that guards operations which today execute
// immediately: CA creation, CA key rotation and retirement, bulk certificate
// revocation, secret-layer KEK rotation, and (reserved) issuance-profile and
// escrow-policy changes. The gate is a fail-closed chokepoint: when a class is
// guarded, the operation cannot execute until a configurable number of DISTINCT
// approvers (none of them the requester) have signed off.
//
// The design has three moving parts:
//
//   - A Policy (built from configuration) declaring which operation classes are
//     guarded and how many distinct approvals each needs.
//   - An Engine that owns the state machine: Guard (the pre-execution
//     chokepoint), Approve, Reject, and SweepExpired. Every transition is
//     appended to the tamper-evident audit log.
//   - A Store (satisfied by *database.DB) persisting the requests and the
//     per-approver decisions, whose UNIQUE(approval_id, approver) constraint is
//     what makes "N DISTINCT approvers" enforceable.
//
// Enforcement is inert unless approvals.enabled is set, so existing deployments
// are unaffected until an operator opts in.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Operation classes. Each names a family of high-risk operations guarded by the
// approval gate. Thresholds are configured per class.
const (
	// ClassCACreate guards creating a new CA (root or intermediate).
	ClassCACreate = "ca.create"
	// ClassCARotate guards intermediate-CA key rotation (Task 24).
	ClassCARotate = "ca.rotate"
	// ClassCARetire guards retiring a superseded intermediate CA (Task 24).
	ClassCARetire = "ca.retire"
	// ClassProfileChange guards issuance-profile changes. Profiles are currently
	// configuration-managed (edited in config + reload), so this class has no
	// runtime chokepoint today; it is reserved so a future profile-mutation
	// endpoint is guarded by construction and so operators can set its threshold.
	ClassProfileChange = "profile.change"
	// ClassBulkRevoke guards bulk certificate revocation (Task 70).
	ClassBulkRevoke = "revocation.bulk"
	// ClassEscrowPolicy guards key-escrow-policy changes. Like profiles, escrow
	// policy is configuration-managed today, so this class is reserved.
	ClassEscrowPolicy = "escrow.policy"
	// ClassKEKRotate guards secret-layer KEK rotation (Task 63).
	ClassKEKRotate = "secret.kek_rotate"
)

// Classes is the set of recognized operation classes, in a stable order for
// listing/validation and configuration documentation.
var Classes = []string{
	ClassCACreate, ClassCARotate, ClassCARetire, ClassProfileChange,
	ClassBulkRevoke, ClassEscrowPolicy, ClassKEKRotate,
}

var classTitles = map[string]string{
	ClassCACreate:      "CA creation",
	ClassCARotate:      "CA key rotation",
	ClassCARetire:      "CA retirement",
	ClassProfileChange: "issuance-profile change",
	ClassBulkRevoke:    "bulk revocation",
	ClassEscrowPolicy:  "escrow-policy change",
	ClassKEKRotate:     "secret KEK rotation",
}

// ValidClass reports whether c names a recognized operation class.
func ValidClass(c string) bool {
	_, ok := classTitles[c]
	return ok
}

// ClassTitle returns a human-readable label for an operation class (the class
// id itself when unknown).
func ClassTitle(c string) string {
	if t, ok := classTitles[c]; ok {
		return t
	}
	return c
}

// Request statuses. A request starts pending, becomes approved once the
// threshold of distinct approvers is met, and is finally consumed (executed) by
// the guarded operation. Rejected and expired are terminal too.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusExecuted = "executed"
	StatusExpired  = "expired"
)

// Decision values recorded per approver.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// DefaultTTL bounds how long a request may sit pending before it is treated as
// expired when the policy sets no explicit TTL.
const DefaultTTL = 72 * time.Hour

// Sentinel errors returned by the Engine. Callers map these to protocol status
// codes and CLI messages.
var (
	// ErrNotFound is returned when no request has the given id.
	ErrNotFound = errors.New("approval: request not found")
	// ErrSelfApproval is returned when an approver tries to approve their own
	// request — the core four-eyes guarantee.
	ErrSelfApproval = errors.New("approval: self-approval denied; a different approver must sign off")
	// ErrAlreadyDecided is returned when an approver has already voted on a
	// request (the distinct-approver constraint).
	ErrAlreadyDecided = errors.New("approval: this approver has already decided on the request")
	// ErrExpired is returned when acting on a request whose window has elapsed.
	ErrExpired = errors.New("approval: request has expired")
)

// StateError is returned when a request is not in a state that permits the
// requested transition (e.g. approving an already-executed request).
type StateError struct{ Status string }

func (e *StateError) Error() string {
	return "approval: request is " + e.Status + "; only pending requests can be decided"
}

// Policy declares which operation classes are guarded and how strong each gate
// is. It is built from configuration at the edges (server/CLI) so this package
// stays decoupled from the config schema.
type Policy struct {
	// Enabled turns the whole gate on. When false every Guard call is a no-op
	// allow, so existing deployments are unaffected until they opt in.
	Enabled bool
	// DefaultThreshold is the number of distinct approvers required for any
	// guarded class without its own explicit threshold.
	DefaultThreshold int
	// Thresholds overrides the required approver count per operation class. A
	// value of 0 for a class leaves that class unguarded even when Enabled.
	Thresholds map[string]int
	// TTL bounds how long a request stays actionable. Zero uses DefaultTTL.
	TTL time.Duration
}

// Required returns the number of distinct approvers required for a class: its
// explicit threshold when set, otherwise the policy default.
func (p Policy) Required(class string) int {
	if p.Thresholds != nil {
		if n, ok := p.Thresholds[class]; ok {
			return n
		}
	}
	return p.DefaultThreshold
}

// Guarded reports whether the gate must intercept operations of a class: the
// policy is enabled and the class requires at least one approver.
func (p Policy) Guarded(class string) bool {
	return p.Enabled && p.Required(class) > 0
}

// ttl returns the effective request lifetime.
func (p Policy) ttl() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	return DefaultTTL
}

// Store persists approval requests and their per-approver decisions. It is
// satisfied structurally by *database.DB, so the approval package does not
// import the database package (avoiding a dependency cycle) and tests can
// substitute an in-memory implementation.
type Store interface {
	// CreatePendingApproval inserts a new request (status pending).
	CreatePendingApproval(a *models.PendingApproval) error
	// GetPendingApproval loads one request by id with its decisions and the
	// running distinct-approver count populated; returns (nil, nil) when absent.
	GetPendingApproval(id string) (*models.PendingApproval, error)
	// FindOpenApproval returns the newest still-open (pending or approved)
	// request for an operation fingerprint, or (nil, nil) when none is open.
	FindOpenApproval(tenantID, class, fingerprint string) (*models.PendingApproval, error)
	// ListPendingApprovals lists requests matching the (optional) tenant, status,
	// and class filters, newest first, capped at limit (0 = a sane default). It
	// takes primitives rather than the Query struct so the database layer need
	// not import this package.
	ListPendingApprovals(tenantID, status, class string, limit int) ([]models.PendingApproval, error)
	// AddApprovalDecision records one approver's decision. inserted is false when
	// the approver already decided on the request (the UNIQUE constraint),
	// enforcing distinct approvers without a race.
	AddApprovalDecision(d *models.ApprovalDecision) (inserted bool, err error)
	// CountApprovalDecisions counts distinct decisions of a kind for a request.
	CountApprovalDecisions(approvalID, decision string) (int, error)
	// SetApprovalStatus atomically transitions a request from one status to
	// another (optimistic: applies only while the row still carries `from`),
	// stamping decided_at/executed_at as appropriate. changed is false when the
	// row had already moved on, which the caller treats as losing a race.
	SetApprovalStatus(id, from, to string, at time.Time) (changed bool, err error)
	// ListExpirableApprovals returns open requests whose window has elapsed.
	ListExpirableApprovals(now time.Time) ([]models.PendingApproval, error)
}

// Query filters ListPendingApprovals. Empty fields are unconstrained.
type Query struct {
	TenantID string
	Status   string
	Class    string
	Limit    int
}

// Auditor appends events to the tamper-evident audit log. Satisfied by
// *database.DB.
type Auditor interface {
	AppendEvent(e *audit.Event) error
}

// Fingerprint derives the stable identity of a specific operation instance from
// its class, resource key, and canonical parameters. Two invocations with the
// same parameters share a fingerprint (so re-running after approval matches the
// approved request), while any parameter change yields a different fingerprint
// (so an approval granted for one operation cannot authorize a different one —
// e.g. approval to revoke serials {1,2,3} cannot execute a revoke of {4,5,6}).
func Fingerprint(class, resourceKey, params string) string {
	h := sha256.New()
	// Length-free but domain-separated with NUL, which cannot appear in the
	// short identifier strings we feed it.
	h.Write([]byte(class))
	h.Write([]byte{0})
	h.Write([]byte(resourceKey))
	h.Write([]byte{0})
	h.Write([]byte(params))
	return hex.EncodeToString(h.Sum(nil))
}
