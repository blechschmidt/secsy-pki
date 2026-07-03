// Package issueapproval is the glue between the four-eyes / maker-checker
// approval engine (internal/approval, Task 81) and end-entity certificate
// issuance (internal/ca, Task 6), implementing Task 84's per-profile manual
// issuance-approval gate.
//
// When an operator/API caller asks to issue a leaf under a profile whose
// require_approval flag is set, the request is not executed. Instead Park records
// (or reuses) a pending cert.issue approval, storing the CSR and issuance
// parameters as the request payload. The certificate is completed and delivered
// server-side by Complete only after the required number of DISTINCT approvers
// (never the requester) has signed off — reusing the engine's approver role,
// distinct-approver, and self-approval-denial rules. On rejection or expiry the
// request reaches a terminal state and no certificate is ever issued.
//
// This orchestration lives in its own package so both the REST/gRPC handlers and
// the secsy-ca CLI share exactly one implementation, and so the approval engine
// stays decoupled from certificate issuance (it never imports ca).
//
// Scope: only operator/API-driven issuance passes through here. Automated
// protocol flows (ACME, EST, SCEP, CMP) enroll machines and call ca.Manager
// directly, deliberately bypassing the manual gate.
package issueapproval

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Payload is the parked issuance request stored on a cert.issue PendingApproval.
// It carries everything Complete needs to perform the original issuance
// server-side after approval, so the requester never has to resubmit the CSR.
type Payload struct {
	CAID         string `json:"ca_id"`
	Profile      string `json:"profile"`
	CSR          string `json:"csr"` // PEM PKCS#10
	ValidityDays int    `json:"validity_days,omitempty"`
	RequestedBy  string `json:"requested_by"`
	Tenant       string `json:"tenant,omitempty"`
}

// Result is the outcome recorded on a completed cert.issue PendingApproval. The
// issued serial lets a later fetch deliver the same certificate idempotently; a
// non-empty Error records an issuance failure that occurred after approval (the
// request is terminal and will not retry).
type Result struct {
	Serial   string `json:"serial,omitempty"`
	CAID     string `json:"ca_id,omitempty"`
	Profile  string `json:"profile,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Params builds the deterministic fingerprint parameters for an issuance
// request: the profile, subject, sorted SANs, and requester (per Task 84). The
// approval engine hashes these into the request fingerprint so an approval
// cannot authorize a different issuance than the one requested, and a re-attempt
// with identical inputs reuses the same pending request rather than spawning a
// duplicate.
func Params(profile, subject string, sans []string, requester string) string {
	s := append([]string(nil), sans...)
	sort.Strings(s)
	return strings.Join([]string{
		"profile=" + profile,
		"subject=" + subject,
		"sans=" + strings.Join(s, ","),
		"requester=" + requester,
	}, "\n")
}

// ParkRequest describes an operator/API issuance to hold for approval.
type ParkRequest struct {
	Engine       *approval.Engine
	CAID         string
	CALabel      string
	Profile      ca.Profile
	CSRPEM       []byte
	ValidityDays int
	Actor        string
	ActorName    string
	Tenant       string
	IP           string
}

// Park validates the CSR and records (or reuses) a pending cert.issue approval
// request WITHOUT issuing anything. It returns the parked request and whether it
// was freshly created (so the caller emits the cert.issue.pending audit event
// and metric exactly once, not on every re-attempt). A returned request whose
// status is already "approved" means the threshold is met and the certificate is
// ready to be completed via Complete.
func Park(ctx context.Context, req ParkRequest) (*models.PendingApproval, bool, error) {
	ident, err := ca.InspectCSRForIssue(req.CSRPEM)
	if err != nil {
		return nil, false, err
	}
	payload, err := json.Marshal(Payload{
		CAID:         req.CAID,
		Profile:      req.Profile.Name,
		CSR:          string(req.CSRPEM),
		ValidityDays: req.ValidityDays,
		RequestedBy:  req.Actor,
		Tenant:       req.Tenant,
	})
	if err != nil {
		return nil, false, fmt.Errorf("issueapproval: encoding payload: %w", err)
	}

	res, err := req.Engine.Guard(ctx, approval.GuardRequest{
		Class:        approval.ClassCertIssue,
		ResourceKey:  "ca:" + req.CAID,
		ResourceName: req.CALabel,
		Summary:      summarize(ident, req.Profile.Name),
		Details:      details(ident, req.Actor),
		Params:       Params(req.Profile.Name, ident.Subject, ident.SANs, req.Actor),
		Payload:      string(payload),
		Actor:        req.Actor,
		ActorName:    req.ActorName,
		Tenant:       req.Tenant,
		IP:           req.IP,
		ParkOnly:     true, // cert.issue completes via Complete, never inline
	})
	if err != nil {
		return nil, false, err
	}
	return res.Approval, res.Created, nil
}

// State classifies the result of attempting to complete/deliver a request.
type State string

const (
	// StateDelivered: the certificate is issued and available in Outcome.
	StateDelivered State = "delivered"
	// StatePending: the request still awaits the approver threshold.
	StatePending State = "pending"
	// StateDenied: the request was rejected or expired; it will never issue.
	StateDenied State = "denied"
	// StateFailed: issuance failed after approval (Outcome.Err explains).
	StateFailed State = "failed"
	// StateNotIssue: the request is not a cert.issue approval.
	StateNotIssue State = "not_issue"
)

// Outcome reports the result of Complete. When State is StateDelivered, Issued
// and ChainPEM carry the certificate; otherwise they are nil/empty and Reason or
// Err explains why.
type Outcome struct {
	Approval *models.PendingApproval
	State    State
	Reason   string
	Err      string
	Issued   *models.IssuedCertificate
	ChainPEM string
}

// Complete drives one cert.issue approval to completion by id. It is idempotent
// and concurrency-safe: exactly one caller wins the approved->executed claim and
// performs the HSM-backed issuance from the parked payload; racing or later
// callers receive the already-issued certificate. On rejection or expiry it
// reports StateDenied and never issues. A store or gate error is returned; a
// post-approval issuance failure is recorded on the request and surfaced as
// StateFailed (the request is terminal — the operator resubmits a fresh one).
func Complete(ctx context.Context, eng *approval.Engine, mgr *ca.Manager, db *database.DB, id, actor, actorName, ip string) (*Outcome, error) {
	pa, err := eng.Get(id)
	if err != nil {
		return nil, err
	}
	if pa.OperationClass != approval.ClassCertIssue {
		return &Outcome{Approval: pa, State: StateNotIssue,
			Reason: "request " + id + " is not a certificate-issuance approval"}, nil
	}

	switch pa.Status {
	case approval.StatusPending:
		return &Outcome{Approval: pa, State: StatePending,
			Reason: "awaiting approval; certificate not yet issued"}, nil
	case approval.StatusRejected:
		return &Outcome{Approval: pa, State: StateDenied, Reason: "issuance request was rejected"}, nil
	case approval.StatusExpired:
		return &Outcome{Approval: pa, State: StateDenied, Reason: "issuance request expired before approval"}, nil
	case approval.StatusExecuted:
		return deliverRecorded(db, pa), nil
	case approval.StatusApproved:
		return completeApproved(ctx, eng, mgr, db, pa, actor, actorName, ip)
	default:
		return &Outcome{Approval: pa, State: StatePending, Reason: "unexpected status " + pa.Status}, nil
	}
}

// completeApproved claims and issues an approved request. It is called only for
// status==approved; the claim serializes concurrent completers.
func completeApproved(ctx context.Context, eng *approval.Engine, mgr *ca.Manager, db *database.DB, pa *models.PendingApproval, actor, actorName, ip string) (*Outcome, error) {
	claimed, won, err := eng.Claim(ctx, pa.ID, actor, actorName, ip)
	if err != nil {
		return nil, err
	}
	if !won {
		// Another caller is completing (or already did), or the state moved on.
		if claimed != nil && claimed.Status == approval.StatusExecuted {
			return deliverRecorded(db, claimed), nil
		}
		return &Outcome{Approval: claimed, State: StatePending,
			Reason: "completion already in progress"}, nil
	}

	var payload Payload
	if err := json.Unmarshal([]byte(pa.Payload), &payload); err != nil {
		// The claim already flipped the request to executed; record the failure so
		// the terminal state is explained rather than silently empty.
		msg := "corrupt approval payload: " + err.Error()
		_ = eng.RecordResult(ctx, pa.ID, mustMarshalResult(Result{Error: msg}))
		metrics.CertIssueApprovals.Inc("error")
		return &Outcome{Approval: claimed, State: StateFailed, Err: msg}, nil //nolint:nilerr // the failure is deliberately surfaced as a terminal StateFailed Outcome, not propagated as a Go error.
	}

	result, issueErr := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:        payload.CAID,
		CSRPEM:      []byte(payload.CSR),
		Profile:     payload.Profile,
		Validity:    daysToDuration(payload.ValidityDays),
		RequestedBy: payload.RequestedBy,
	})
	if issueErr != nil {
		msg := issueErr.Error()
		_ = eng.RecordResult(ctx, pa.ID, mustMarshalResult(Result{Error: msg}))
		auditEvent(db, pa.TenantID, actor, actorName, ip, audit.ActionCertIssueApproved, payload.CAID, "",
			audit.ResultError, "approval="+pa.ID+"; issuance failed after approval: "+msg)
		metrics.CertIssueApprovals.Inc("error")
		return &Outcome{Approval: claimed, State: StateFailed, Err: msg}, nil //nolint:nilerr // the failure is deliberately surfaced as a terminal StateFailed Outcome, not propagated as a Go error.
	}

	res := Result{
		Serial:   result.Serial.String(),
		CAID:     payload.CAID,
		Profile:  result.Profile,
		IssuedAt: result.Certificate.NotBefore.UTC().Format(time.RFC3339),
	}
	if err := eng.RecordResult(ctx, pa.ID, mustMarshalResult(res)); err != nil {
		// The certificate exists and is recorded in issued_certificates; only the
		// approval->certificate link failed to persist. Surface it rather than
		// masking a partial state.
		return nil, err
	}
	auditEvent(db, pa.TenantID, actor, actorName, ip, audit.ActionCertIssueApproved, payload.CAID, res.Serial,
		audit.ResultSuccess, "approval="+pa.ID+"; profile="+res.Profile+"; requested_by="+payload.RequestedBy)
	metrics.CertIssueApprovals.Inc("approved")

	// Reload so the delivered approval reflects the executed state and the count.
	if reloaded, err := eng.Get(pa.ID); err == nil {
		claimed = reloaded
	}
	return &Outcome{
		Approval: claimed,
		State:    StateDelivered,
		Issued:   result.Record,
		ChainPEM: string(result.ChainPEM),
	}, nil
}

// deliverRecorded returns the certificate a previously-completed request issued,
// looked up by the serial recorded in its Result. It never touches the HSM.
func deliverRecorded(db *database.DB, pa *models.PendingApproval) *Outcome {
	var res Result
	if pa.Result != "" {
		_ = json.Unmarshal([]byte(pa.Result), &res)
	}
	if res.Error != "" {
		return &Outcome{Approval: pa, State: StateFailed, Err: res.Error}
	}
	if res.Serial == "" {
		return &Outcome{Approval: pa, State: StateFailed,
			Err: "the approved request was consumed without recording a certificate"}
	}
	cert, err := db.GetIssuedCertificate(res.CAID, res.Serial)
	if err != nil {
		return &Outcome{Approval: pa, State: StateFailed, Err: "loading issued certificate: " + err.Error()}
	}
	if cert == nil {
		return &Outcome{Approval: pa, State: StateFailed,
			Err: "issued certificate " + res.Serial + " not found"}
	}
	return &Outcome{Approval: pa, State: StateDelivered, Issued: cert, ChainPEM: buildChain(db, res.CAID, cert)}
}

// buildChain returns the leaf followed by its issuing CA certificate (the same
// immediate-issuer bundle the ordinary issuance response carries).
func buildChain(db *database.DB, caID string, cert *models.IssuedCertificate) string {
	leaf := strings.TrimRight(cert.Certificate, "\n")
	issuer, err := db.GetCA(caID)
	if err != nil || issuer == nil || issuer.Certificate == "" {
		return leaf + "\n"
	}
	return leaf + "\n" + issuer.Certificate
}

// NewTerminalHook returns an approval.Engine terminal-state callback that emits
// the cert.issue.denied audit event and metric when a cert.issue request is
// rejected or expires, so the negative terminal state is recorded uniformly
// regardless of the transport that triggered it (REST, CLI, or the background
// expiry sweep). Requests of other classes are ignored — their terminal states
// are covered by the engine's generic approval.reject / approval.expire events.
func NewTerminalHook(aud approval.Auditor) func(pa *models.PendingApproval, outcome string) {
	return func(pa *models.PendingApproval, outcome string) {
		if pa == nil || pa.OperationClass != approval.ClassCertIssue {
			return
		}
		caID := strings.TrimPrefix(pa.ResourceKey, "ca:")
		_ = aud.AppendEvent(&audit.Event{
			Actor:      "system",
			ActorName:  "approval-gate",
			Action:     audit.ActionCertIssueDenied,
			Tenant:     pa.TenantID,
			Target:     caID,
			TargetName: pa.ResourceName,
			Result:     audit.ResultDenied,
			Detail:     "approval=" + pa.ID + "; requested_by=" + pa.RequestedBy + "; outcome=" + outcome,
		})
		metrics.CertIssueApprovals.Inc("denied")
	}
}

// summarize renders a one-line description of a parked issuance for approvers.
func summarize(ident ca.CSRIdentity, profile string) string {
	who := ident.Subject
	if who == "" && len(ident.SANs) > 0 {
		who = ident.SANs[0]
	}
	if who == "" {
		who = "(no subject)"
	}
	return fmt.Sprintf("issue certificate for %s under profile %q", who, profile)
}

// details renders structured context stored on the request for approvers.
func details(ident ca.CSRIdentity, requester string) string {
	return fmt.Sprintf("subject=%s; sans=%s; requested_by=%s",
		ident.Subject, strings.Join(ident.SANs, ","), requester)
}

// mustMarshalResult encodes a Result; it cannot fail for these plain fields, but
// on the impossible error it falls back to an error marker so the request still
// reaches a defined terminal state.
func mustMarshalResult(r Result) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"error":"internal: failed to encode issuance result"}`
	}
	return string(b)
}

// auditEvent appends a best-effort domain audit event. A storage failure is
// swallowed: the certificate was already issued and recorded, and the engine's
// generic approval.execute event independently records the lifecycle transition.
func auditEvent(aud approval.Auditor, tenant, actor, actorName, ip, action, target, targetName, result, detail string) {
	_ = aud.AppendEvent(&audit.Event{
		Actor:      actor,
		ActorName:  actorName,
		Action:     action,
		Tenant:     tenant,
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
		IP:         ip,
	})
}

// daysToDuration converts a validity-in-days value to a Duration. Non-positive
// values yield zero, which downstream treats as "use the profile default".
func daysToDuration(days int) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}
