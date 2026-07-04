package ca

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// Batch / bulk certificate issuance (Task 101) is the mass device/service
// provisioning counterpart of the Task 70 bulk-revocation engine: it accepts an
// array of independent issue requests (CSR + profile + validity) and issues each
// under the CA's HSM-held key, returning a per-item result so a partial failure
// never discards the successes. It exists so a fleet roll-out does not have to
// fan out thousands of separate /issue calls (each re-loading the issuer,
// re-opening a signer, and interleaving the audit chain) and so an operator gets
// one confirm-count guard and one summary audit event for the whole operation.
//
// Every item passes the full per-issuance gate stack INDIVIDUALLY, because each
// item flows through the same Manager.IssueCertificate path a single /issue call
// uses: pre-issuance lint (certlint/zlint), CAA (RFC 8659/8657), name
// constraints, certificate policies, the policy-as-code (CEL) gate, CT embedding,
// and the tenant lifecycle + daily-quota reservation. Nothing about batching
// relaxes a gate — a batch is exactly N independent issuances sharing one
// confirm-count guard, one bounded worker pool, and one summary.
//
// Two properties distinguish it from a naive loop:
//
//   - Partial-success semantics: an item that trips a gate (lint failure, CAA
//     denial, tenant quota exhaustion, …) fails only itself and is reported with
//     a structured error; the rest of the batch proceeds. An item whose profile
//     requires manual four-eyes approval (Task 84) is parked and reported
//     "pending" rather than failing the batch — the certificate is fetched later
//     from the approval endpoint once approvers sign off.
//   - Bounded concurrency: items are issued through a bounded worker pool so the
//     HSM is not stampeded. The actual signatures serialize through the shared
//     PKCS#11 session pool; the worker bound caps goroutine fan-out and pool
//     contention, mirroring the "bounded HSM concurrency" the public protocol
//     endpoints get from the rate-limit guard.
//
// The manual-approval gate lives one layer up (it depends on the four-eyes
// engine, which never imports ca), so it is injected as an optional callback in
// BulkIssuerConfig. A nil gate — the CLI path and any automated caller — issues
// every item immediately, exactly as `secsy-ca issue` bypasses the manual gate.

// DefaultBulkIssueConcurrency is the number of certificates issued in parallel
// when a spec does not override it. It matches the default PKCS#11 session pool
// size so the workers keep the pool busy without oversubscribing it.
const DefaultBulkIssueConcurrency = 8

// maxBulkIssueConcurrency caps a configured concurrency so a single batch cannot
// oversubscribe the HSM session pool and starve concurrent OCSP/CRL/other
// issuance traffic.
const maxBulkIssueConcurrency = 64

// MaxBulkIssueItems bounds how many items one batch may carry, so a single
// request cannot pin unbounded memory or monopolize the issuance path. Larger
// fleets are provisioned as successive batches.
const MaxBulkIssueItems = 10000

// Structured per-item error codes, so a client can branch on the failure class
// (retryable quota vs. permanent malformed request) without string-matching.
const (
	// BulkIssueCodeInvalidRequest is a caller-side problem with the item: a
	// malformed/empty CSR or an unknown profile. Not retryable as-is.
	BulkIssueCodeInvalidRequest = "invalid_request"
	// BulkIssueCodeQuotaExceeded is a tenant daily-quota / active-cert ceiling
	// hit while issuing this item. Retryable after the quota window resets.
	BulkIssueCodeQuotaExceeded = "quota_exceeded"
	// BulkIssueCodeTenantSuspended is a suspended owning tenant. Not retryable
	// until the tenant is reactivated.
	BulkIssueCodeTenantSuspended = "tenant_suspended"
	// BulkIssueCodeGateError is a pre-issuance policy gate refusal (lint, CAA,
	// name constraints, certificate policy, CEL) or the approval-gate machinery
	// failing. The Error string carries the specific gate reason.
	BulkIssueCodeGateError = "gate_error"
	// BulkIssueCodeIssuanceError is any other issuance failure (HSM error, store
	// error, unexpected condition).
	BulkIssueCodeIssuanceError = "issuance_error"
)

// BulkIssueStatus is the terminal (or pending) disposition of one batch item.
type BulkIssueStatus string

const (
	// BulkIssueStatusIssued: the certificate was signed and recorded.
	BulkIssueStatusIssued BulkIssueStatus = "issued"
	// BulkIssueStatusPending: the item's profile requires manual approval; the
	// request was parked and no certificate was issued yet.
	BulkIssueStatusPending BulkIssueStatus = "pending"
	// BulkIssueStatusFailed: the item failed a gate or issuance step. Error and
	// ErrorCode explain why; no certificate was issued.
	BulkIssueStatusFailed BulkIssueStatus = "failed"
)

// BulkIssueItem is one certificate request in a batch. The subject and SANs are
// taken from the CSR, exactly as in single issuance; the batch layer adds only a
// client-supplied Ref for correlating the result back to the request.
type BulkIssueItem struct {
	// Ref is an opaque client-supplied correlation reference echoed back in the
	// item's result so the caller can match results to requests regardless of
	// ordering. When empty the engine fills it with the item's zero-based index.
	Ref string
	// CSRPEM is a PEM-encoded PKCS#10 certificate signing request.
	CSRPEM []byte
	// Profile is the certificate profile name (empty = default profile).
	Profile string
	// ValidityDays overrides the profile default validity (0 = profile default;
	// always clamped to the profile maximum and the CA's own expiry).
	ValidityDays int
}

// BulkIssueItemResult is the per-item outcome of a batch issuance. Exactly one of
// the issued/pending/failed field groups is populated, per Status.
type BulkIssueItemResult struct {
	Ref     string          `json:"ref"`
	Index   int             `json:"index"`
	Status  BulkIssueStatus `json:"status"`
	Profile string          `json:"profile,omitempty"`

	// Issued fields (Status == issued).
	Serial      string    `json:"serial,omitempty"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	Certificate string    `json:"certificate,omitempty"` // PEM leaf
	Chain       string    `json:"chain,omitempty"`       // PEM leaf + issuer

	// Pending fields (Status == pending): the parked four-eyes approval to act on.
	ApprovalID        string `json:"approval_id,omitempty"`
	RequiredApprovals int    `json:"required_approvals,omitempty"`
	ApprovalsCount    int    `json:"approvals_count,omitempty"`

	// Failed fields (Status == failed).
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// BulkIssueSpec describes one batch-issuance operation.
type BulkIssueSpec struct {
	// CAID is the issuing CA (required). Key-rotation lineage is followed per
	// item, so issuing against a superseded id transparently uses its successor.
	CAID string
	// Items are the certificate requests. Order is preserved in the result.
	Items []BulkIssueItem
	// RequestedBy is the acting principal recorded on every per-item audit event
	// and the summary event.
	RequestedBy string
	// OperationID correlates the per-item audit events with the summary event.
	// Empty generates a fresh id.
	OperationID string
	// ConfirmCount, when >= 0, must equal len(Items); a mismatch aborts the whole
	// operation with *BulkIssueCountMismatchError before anything is issued. This
	// is the guard against accidental mass issuance (a script that doubled its
	// input, say). Pass a negative value to skip the check (scripted/forced use).
	ConfirmCount int
	// Concurrency bounds how many items are issued in parallel (0 =
	// DefaultBulkIssueConcurrency, capped at maxBulkIssueConcurrency).
	Concurrency int
	// Progress, when non-nil, is called after each item reaches a terminal or
	// pending state, with the running resolved count and the total.
	Progress func(done, total int)
}

// BulkIssueResult summarizes an executed batch issuance.
type BulkIssueResult struct {
	OperationID string `json:"operation_id"`
	CAID        string `json:"ca_id"`
	// Requested is the number of items submitted; Issued/Pending/Failed partition
	// it by disposition (Issued + Pending + Failed == Requested).
	Requested int `json:"requested"`
	Issued    int `json:"issued"`
	Pending   int `json:"pending"`
	Failed    int `json:"failed"`
	// Items carries the per-item results in request order.
	Items        []BulkIssueItemResult `json:"items"`
	Duration     time.Duration         `json:"-"`
	DurationSecs float64               `json:"duration_seconds"`
}

// BulkIssueCountMismatchError reports that the operator-confirmed item count does
// not match the batch actually submitted. Nothing was issued; the caller should
// re-confirm the correct count.
type BulkIssueCountMismatchError struct {
	Confirmed int
	Actual    int
}

func (e *BulkIssueCountMismatchError) Error() string {
	return fmt.Sprintf("confirmation count %d does not match the %d item(s) submitted; confirm the correct count", e.Confirmed, e.Actual)
}

// BulkIssueGateResult reports the outcome of consulting the per-profile manual
// issuance-approval gate for one item.
type BulkIssueGateResult struct {
	// Gated is true when issuance under the item's profile must be held for
	// manual four-eyes approval; the engine records the item pending (with the
	// parked approval id below) and does NOT issue it.
	Gated             bool
	ApprovalID        string
	RequiredApprovals int
	ApprovalsCount    int
}

// BulkIssueApprovalGate consults Task 84's per-profile manual issuance-approval
// gate for one item before it is issued. When the item's profile requires
// approval it PARKS the request (recording a pending cert.issue approval) and
// returns Gated=true with the approval id; it never issues, and parking has no
// HSM side effects. The two error returns mirror the handler-level gate:
// clientErr signals a caller-side problem (malformed CSR / unknown profile) that
// fails just this item as invalid_request; err signals a gate/store failure that
// fails just this item as gate_error. A nil gate (the CLI and other automated
// callers) issues every item immediately, mirroring how `secsy-ca issue`
// bypasses the manual gate by construction.
type BulkIssueApprovalGate func(ctx context.Context, item BulkIssueItem) (result BulkIssueGateResult, clientErr, err error)

// BulkIssuerConfig wires optional serving-layer behavior into the engine.
type BulkIssuerConfig struct {
	// ApprovalGate, when set, routes each item through the per-profile manual
	// issuance-approval gate before issuing. Nil issues every item immediately.
	ApprovalGate BulkIssueApprovalGate
}

// BulkIssuer executes batch issuances over a manager's store and provider.
type BulkIssuer struct {
	mgr *Manager
	cfg BulkIssuerConfig
}

// NewBulkIssuer builds a batch-issuance engine over the manager.
func NewBulkIssuer(mgr *Manager, cfg BulkIssuerConfig) *BulkIssuer {
	return &BulkIssuer{mgr: mgr, cfg: cfg}
}

// validateSpec checks the batch shape and that the CA exists before any work.
func (b *BulkIssuer) validateSpec(spec BulkIssueSpec) error {
	if spec.CAID == "" {
		return fmt.Errorf("CA id is required")
	}
	if len(spec.Items) == 0 {
		return fmt.Errorf("batch contains no items")
	}
	if len(spec.Items) > MaxBulkIssueItems {
		return fmt.Errorf("batch of %d items exceeds the maximum of %d; split it into smaller batches", len(spec.Items), MaxBulkIssueItems)
	}
	// Fail fast on a non-existent/non-X.509 CA rather than per item.
	if _, _, err := b.mgr.loadIssuer(spec.CAID); err != nil {
		return err
	}
	return nil
}

// BulkIssuePreviewItem is one entry of a dry-run plan: the validated identity a
// well-formed item would carry, or the reason it is malformed.
type BulkIssuePreviewItem struct {
	Ref     string `json:"ref"`
	Index   int    `json:"index"`
	Valid   bool   `json:"valid"`
	Subject string `json:"subject,omitempty"`
	// SANs is the item CSR's subject alternative names (DNS/IP/email/URI).
	SANs    []string `json:"sans,omitempty"`
	Profile string   `json:"profile,omitempty"`
	// RequiresApproval reports that the item's profile is configured to route
	// issuance through the manual four-eyes approval gate (Task 84). Actual
	// gating additionally requires the approvals engine to be enabled — Preview
	// reports the profile's intent so an operator can foresee parked items.
	RequiresApproval bool   `json:"requires_approval"`
	Error            string `json:"error,omitempty"`
}

// BulkIssuePlan is the dry-run preview of a batch issuance: each item validated
// (CSR parsed, profile resolved) with nothing issued or parked, plus the count
// to confirm.
type BulkIssuePlan struct {
	OperationID string `json:"operation_id"`
	CAID        string `json:"ca_id"`
	CALabel     string `json:"ca_label"`
	// Requested is the item count (the number to confirm); Valid/Invalid split it
	// by well-formedness, and NeedApproval counts valid items whose profile
	// requires manual approval.
	Requested    int                    `json:"requested"`
	Valid        int                    `json:"valid"`
	Invalid      int                    `json:"invalid"`
	NeedApproval int                    `json:"need_approval"`
	Items        []BulkIssuePreviewItem `json:"items"`
}

// Preview validates a batch without issuing or parking anything: each item's CSR
// is parsed and its profile resolved, so an operator can catch a malformed batch
// (and see which items would be held for approval) before confirming the count.
func (b *BulkIssuer) Preview(ctx context.Context, spec BulkIssueSpec) (*BulkIssuePlan, error) {
	_, span := tracing.Start(ctx, "ca.bulk_issue_preview", attribute.String("ca.id", spec.CAID))
	defer span.End()

	if err := b.validateSpec(spec); err != nil {
		return nil, err
	}
	issuerCA, _, err := b.mgr.loadIssuer(spec.CAID)
	if err != nil {
		return nil, err
	}
	opID := spec.OperationID
	if opID == "" {
		opID = uuid.New().String()
	}
	plan := &BulkIssuePlan{
		OperationID: opID,
		CAID:        issuerCA.ID,
		CALabel:     issuerCA.Label,
		Requested:   len(spec.Items),
		Items:       make([]BulkIssuePreviewItem, len(spec.Items)),
	}
	for i := range spec.Items {
		item := normalizeBulkItem(spec.Items[i], i)
		entry := BulkIssuePreviewItem{Ref: item.Ref, Index: i, Profile: item.Profile}
		ident, cerr := InspectCSRForIssue(item.CSRPEM)
		if cerr != nil {
			entry.Error = cerr.Error()
			plan.Invalid++
			plan.Items[i] = entry
			continue
		}
		profile, perr := LookupProfile(item.Profile)
		if perr != nil {
			entry.Error = perr.Error()
			plan.Invalid++
			plan.Items[i] = entry
			continue
		}
		entry.Valid = true
		entry.Subject = ident.Subject
		entry.SANs = ident.SANs
		entry.Profile = profile.Name
		entry.RequiresApproval = profile.RequireApproval
		if profile.RequireApproval {
			plan.NeedApproval++
		}
		plan.Valid++
		plan.Items[i] = entry
	}
	return plan, nil
}

// Execute runs the batch. When spec.ConfirmCount >= 0 it is checked against the
// submitted item count before anything is issued. Items are first routed through
// the optional approval gate (parked items become "pending"), then the remaining
// items are issued with bounded concurrency. Each item is independent: its
// failure is reported in its result and never aborts the batch. The returned
// error is non-nil only for a whole-operation failure (bad spec or count
// mismatch); per-item failures live in the result.
func (b *BulkIssuer) Execute(ctx context.Context, spec BulkIssueSpec) (_ *BulkIssueResult, err error) {
	ctx, span := tracing.Start(ctx, "ca.bulk_issue", attribute.String("ca.id", spec.CAID))
	defer func() { tracing.End(span, err) }()
	start := time.Now()

	if verr := b.validateSpec(spec); verr != nil {
		metrics.IssuanceBulk.Inc(metrics.ResultError)
		return nil, verr
	}
	if spec.ConfirmCount >= 0 && spec.ConfirmCount != len(spec.Items) {
		// Deliberately not counted as an operation error: nothing was attempted.
		return nil, &BulkIssueCountMismatchError{Confirmed: spec.ConfirmCount, Actual: len(spec.Items)}
	}

	opID := spec.OperationID
	if opID == "" {
		opID = uuid.New().String()
	}
	tenantID, terr := b.mgr.db.GetCATenant(spec.CAID)
	if terr != nil {
		log.Printf("WARNING: bulk issue: could not resolve tenant of CA %q for audit/usage accounting: %v", spec.CAID, terr)
	}

	concurrency := spec.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultBulkIssueConcurrency
	}
	if concurrency > maxBulkIssueConcurrency {
		concurrency = maxBulkIssueConcurrency
	}

	span.SetAttributes(
		attribute.Int("bulk.requested", len(spec.Items)),
		attribute.String("bulk.operation_id", opID),
		attribute.Int("bulk.concurrency", concurrency),
	)

	results := make([]BulkIssueItemResult, len(spec.Items))
	var done int64
	markDone := func() {
		if spec.Progress != nil {
			spec.Progress(int(atomic.AddInt64(&done, 1)), len(spec.Items))
		}
	}

	// Phase 1 (sequential): consult the manual-approval gate. Parking is cheap
	// (no HSM) and running it sequentially avoids racing the approval engine on
	// two items that fingerprint identically within one batch. Gated items become
	// "pending"; client/gate errors become "failed"; the rest queue for issuance.
	toIssue := make([]int, 0, len(spec.Items))
	for i := range spec.Items {
		item := normalizeBulkItem(spec.Items[i], i)
		if b.cfg.ApprovalGate == nil {
			toIssue = append(toIssue, i)
			continue
		}
		gate, clientErr, gerr := b.cfg.ApprovalGate(ctx, item)
		switch {
		case clientErr != nil:
			results[i] = failedItem(item, i, clientErr.Error(), BulkIssueCodeInvalidRequest)
			b.recordItemEvent(spec, opID, tenantID, results[i], audit.ResultError)
			markDone()
		case gerr != nil:
			results[i] = failedItem(item, i, gerr.Error(), BulkIssueCodeGateError)
			b.recordItemEvent(spec, opID, tenantID, results[i], audit.ResultError)
			markDone()
		case gate.Gated:
			// The gate's Park already emitted the cert.issue.pending audit event
			// and metric, so the engine does not double-record it here.
			results[i] = BulkIssueItemResult{
				Ref: item.Ref, Index: i, Status: BulkIssueStatusPending, Profile: item.Profile,
				ApprovalID: gate.ApprovalID, RequiredApprovals: gate.RequiredApprovals,
				ApprovalsCount: gate.ApprovalsCount,
			}
			markDone()
		default:
			toIssue = append(toIssue, i)
		}
	}

	// Phase 2 (bounded concurrency): issue the non-gated items. The HSM
	// signatures serialize through the shared session pool; the semaphore caps
	// goroutine fan-out and pool contention. A canceled context stops dispatch;
	// items already in flight finish and record their own outcome.
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, idx := range toIssue {
		if ctx.Err() != nil {
			results[idx] = failedItem(normalizeBulkItem(spec.Items[idx], idx), idx,
				"batch canceled before issuance: "+ctx.Err().Error(), BulkIssueCodeIssuanceError)
			markDone()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = b.issueOne(ctx, spec, opID, tenantID, normalizeBulkItem(spec.Items[i], i), i)
			markDone()
		}(idx)
	}
	wg.Wait()

	result := &BulkIssueResult{
		OperationID: opID,
		CAID:        spec.CAID,
		Requested:   len(spec.Items),
		Items:       results,
	}
	for i := range results {
		switch results[i].Status {
		case BulkIssueStatusIssued:
			result.Issued++
		case BulkIssueStatusPending:
			result.Pending++
		default:
			result.Failed++
		}
	}
	result.Duration = time.Since(start)
	result.DurationSecs = result.Duration.Seconds()

	metrics.IssuanceBulk.Inc(metrics.ResultSuccess)
	metrics.IssuanceBulkDuration.Observe(result.DurationSecs)
	if result.Issued > 0 {
		metrics.IssuanceBulkCertificates.Add(uint64(result.Issued))
	}
	span.SetAttributes(
		attribute.Int("bulk.issued", result.Issued),
		attribute.Int("bulk.pending", result.Pending),
		attribute.Int("bulk.failed", result.Failed),
	)
	b.recordSummaryEvent(spec, opID, tenantID, result)
	return result, nil
}

// issueOne issues a single non-gated item through the full Manager.IssueCertificate
// gate stack and records a per-item cert.issue audit event.
func (b *BulkIssuer) issueOne(ctx context.Context, spec BulkIssueSpec, opID, tenantID string, item BulkIssueItem, idx int) BulkIssueItemResult {
	res, err := b.mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        spec.CAID,
		CSRPEM:      item.CSRPEM,
		Profile:     item.Profile,
		Validity:    bulkValidity(item.ValidityDays),
		RequestedBy: spec.RequestedBy,
	})
	if err != nil {
		out := failedItem(item, idx, err.Error(), classifyBulkIssueError(err))
		b.recordItemEvent(spec, opID, tenantID, out, audit.ResultError)
		return out
	}
	out := BulkIssueItemResult{
		Ref:         item.Ref,
		Index:       idx,
		Status:      BulkIssueStatusIssued,
		Profile:     res.Profile,
		Serial:      res.Serial.String(),
		NotBefore:   res.Certificate.NotBefore,
		NotAfter:    res.Certificate.NotAfter,
		Certificate: string(res.PEM),
		Chain:       string(res.ChainPEM),
	}
	b.recordItemEvent(spec, opID, tenantID, out, audit.ResultSuccess)
	return out
}

// recordItemEvent appends the per-item cert.issue audit event, tying it to the
// batch via bulk_op. It mirrors the single-issue handler's cert.issue event so
// the batch's issuances are indistinguishable in the audit trail from ordinary
// ones, save for the bulk_op correlation tag.
func (b *BulkIssuer) recordItemEvent(spec BulkIssueSpec, opID, tenantID string, item BulkIssueItemResult, outcome string) {
	detail := fmt.Sprintf("profile=%s bulk_op=%s ref=%s", item.Profile, opID, item.Ref)
	if outcome == audit.ResultError {
		detail += " error=" + item.Error
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actorOrSystem(spec.RequestedBy),
		Action:     audit.ActionCertIssue,
		Tenant:     tenantID,
		Target:     spec.CAID,
		TargetName: item.Serial,
		Result:     outcome,
		Detail:     detail,
	}
	if err := b.mgr.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.issue audit event for bulk item ref %s: %v", item.Ref, err)
	}
}

// recordSummaryEvent appends the operation-level cert.issue_bulk summary event.
func (b *BulkIssuer) recordSummaryEvent(spec BulkIssueSpec, opID, tenantID string, result *BulkIssueResult) {
	detail := fmt.Sprintf("op=%s requested=%d issued=%d pending=%d failed=%d concurrency=%d duration=%s",
		opID, result.Requested, result.Issued, result.Pending, result.Failed,
		effectiveConcurrency(spec.Concurrency), result.Duration.Round(time.Millisecond))
	outcome := audit.ResultSuccess
	if result.Failed > 0 && result.Issued == 0 && result.Pending == 0 {
		// Every item failed: record the summary itself as an error for alerting.
		outcome = audit.ResultError
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actorOrSystem(spec.RequestedBy),
		Action:     audit.ActionCertIssueBulk,
		Tenant:     tenantID,
		Target:     spec.CAID,
		TargetName: opID,
		Result:     outcome,
		Detail:     detail,
	}
	if err := b.mgr.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.issue_bulk summary audit event: %v", err)
	}
}

// normalizeBulkItem fills an empty Ref with the item's index so every result is
// addressable, and trims the profile.
func normalizeBulkItem(item BulkIssueItem, idx int) BulkIssueItem {
	item.Profile = strings.TrimSpace(item.Profile)
	if strings.TrimSpace(item.Ref) == "" {
		item.Ref = fmt.Sprintf("#%d", idx)
	}
	return item
}

// failedItem builds a failed per-item result.
func failedItem(item BulkIssueItem, idx int, msg, code string) BulkIssueItemResult {
	return BulkIssueItemResult{
		Ref: item.Ref, Index: idx, Status: BulkIssueStatusFailed,
		Profile: item.Profile, Error: msg, ErrorCode: code,
	}
}

// classifyBulkIssueError maps an issuance error to a structured per-item code so
// clients can distinguish retryable (quota) from permanent failures without
// parsing the message. Only the typed tenant errors are classified precisely;
// pre-issuance policy-gate refusals (lint, CAA, name constraints, certificate
// policy, CEL) and everything else are reported as issuance_error, with the
// specific reason preserved verbatim in the item's Error string.
func classifyBulkIssueError(err error) string {
	var quota *models.QuotaExceededError
	if errors.As(err, &quota) {
		return BulkIssueCodeQuotaExceeded
	}
	var susp *models.TenantSuspendedError
	if errors.As(err, &susp) {
		return BulkIssueCodeTenantSuspended
	}
	return BulkIssueCodeIssuanceError
}

// bulkValidity converts an item's validity-in-days to a Duration (0 = profile
// default; downstream clamps to the profile maximum and the CA expiry).
func bulkValidity(days int) time.Duration {
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// effectiveConcurrency reports the concurrency the engine would use for a spec
// value, for the summary detail line.
func effectiveConcurrency(requested int) int {
	if requested <= 0 {
		return DefaultBulkIssueConcurrency
	}
	if requested > maxBulkIssueConcurrency {
		return maxBulkIssueConcurrency
	}
	return requested
}
