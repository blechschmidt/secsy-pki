package ca

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// Bulk revocation (Task 70) is the incident-response path for compromise
// scenarios: a CA key leaks, a vulnerable device fleet must be cut off, or a
// registration bug mis-issued a batch — and the CA/Browser Forum Baseline
// Requirements give the operator 24 hours (key compromise) to revoke every
// affected certificate. Revoking tens of thousands of serials one API call at
// a time regenerates CRLs per certificate and floods the audit chain with
// interleaved noise; this engine instead:
//
//   - selects candidates once (tenant/CA come from the manager + spec; profile,
//     CN/SAN pattern, issuance window, and an explicit serial list narrow it),
//   - previews the selection as a dry run (mandatory confirmation counts),
//   - applies revocations in bounded transactional batches with progress
//     reporting,
//   - regenerates the base and delta CRLs exactly once at the end (per affected
//     scope when CRL partitioning is enabled),
//   - invalidates cached OCSP responses for the revoked serials and refreshes
//     the pre-signed OCSP set so relying parties see "revoked" immediately, and
//   - appends one audit event per revoked certificate plus a summary event tied
//     together by an operation id.
//
// Resumability is by construction rather than by checkpoint state: the
// selection only ever returns not-yet-revoked certificates and the batch write
// skips serials that are already revoked, so re-running an interrupted
// operation (same filters, any operation id) continues exactly where it
// stopped and never double-counts, double-audits, or churns revocation
// timestamps. Revocation is deliberately never gated by tenant quotas or
// suspension — a suspended tenant's certificates must always be revocable.

// bulkSampleSize bounds the preview sample included in a plan.
const bulkSampleSize = 20

// DefaultBulkRevokeBatchSize is the number of certificates revoked per store
// transaction when the spec does not override it.
const DefaultBulkRevokeBatchSize = 500

// maxBulkRevokeBatchSize caps a configured batch size so a single transaction
// stays bounded.
const maxBulkRevokeBatchSize = 5000

// BulkRevokeFilter narrows the certificates a bulk revocation covers. All set
// fields must match (they AND together). A zero filter selects every
// not-yet-revoked, unexpired certificate of the CA — the CA-key-compromise
// case.
type BulkRevokeFilter struct {
	// Profile restricts to certificates issued under this profile.
	Profile string
	// Pattern is a case-insensitive glob (path.Match syntax: * ? [...]) tested
	// against the common name and every SAN; a certificate matches when any
	// name matches.
	Pattern string
	// IssuedAfter / IssuedBefore bound the certificate's NotBefore (inclusive).
	IssuedAfter  *time.Time
	IssuedBefore *time.Time
	// Serials restricts the operation to these serials (decimal strings).
	// Serials unknown to the issued-certificate inventory are still revoked —
	// in a CA-key compromise the attacker's certificates are precisely the
	// ones the inventory never saw — but they bypass the other filters (which
	// need inventory rows to evaluate) and are reported separately in the plan.
	Serials []string
	// IncludeExpired also revokes certificates past their NotAfter. Off by
	// default: an RFC 5280 CRL need not list expired serials, so revoking them
	// only bloats the CRL.
	IncludeExpired bool
}

// Describe renders the filter for audit trails and operator display.
func (f BulkRevokeFilter) Describe() string {
	var parts []string
	if f.Profile != "" {
		parts = append(parts, "profile="+f.Profile)
	}
	if f.Pattern != "" {
		parts = append(parts, "pattern="+f.Pattern)
	}
	if f.IssuedAfter != nil {
		parts = append(parts, "issued_after="+f.IssuedAfter.UTC().Format(time.RFC3339))
	}
	if f.IssuedBefore != nil {
		parts = append(parts, "issued_before="+f.IssuedBefore.UTC().Format(time.RFC3339))
	}
	if len(f.Serials) > 0 {
		parts = append(parts, fmt.Sprintf("serials=%d", len(f.Serials)))
	}
	if f.IncludeExpired {
		parts = append(parts, "include_expired=true")
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

// BulkRevokeSpec describes one bulk-revocation operation.
type BulkRevokeSpec struct {
	// CAID is the issuing CA whose certificates are revoked (required).
	CAID string
	// Filter selects the certificates. A zero filter selects the whole CA.
	Filter BulkRevokeFilter
	// Reason is the RFC 5280 revocation reason name applied to every
	// certificate ("" = unspecified; key-compromise response should pass
	// "keyCompromise").
	Reason string
	// RequestedBy is the acting principal recorded on every audit event.
	RequestedBy string
	// OperationID correlates the per-certificate audit events with the summary
	// event and, on a resumed run, with the interrupted operation's events.
	// Empty generates a fresh id.
	OperationID string
	// BatchSize is the number of certificates revoked per store transaction
	// (0 = DefaultBulkRevokeBatchSize).
	BatchSize int
	// ConfirmCount, when >= 0, must equal the freshly computed candidate total
	// at execution time; a mismatch aborts with *BulkCountMismatchError before
	// anything is revoked. This is the dry-run count the operator confirmed.
	// Pass a negative value to skip the check (emergency/scripted use).
	ConfirmCount int
	// Progress, when non-nil, is called after every applied batch with the
	// running revoked count and the planned total.
	Progress func(revoked, total int)
}

// BulkRevokeItem is one entry of a plan's preview sample.
type BulkRevokeItem struct {
	Serial     string    `json:"serial"`
	CommonName string    `json:"common_name,omitempty"`
	Profile    string    `json:"profile,omitempty"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	// Known reports whether the serial is backed by an inventory row (false =
	// a serial-list entry the inventory never saw).
	Known bool `json:"known"`
}

// BulkRevokePlan is the dry-run preview of a bulk revocation: exactly what the
// execution pass would revoke, with the counts the operator must confirm.
type BulkRevokePlan struct {
	OperationID string `json:"operation_id"`
	CAID        string `json:"ca_id"`
	CALabel     string `json:"ca_label"`
	Reason      string `json:"reason"`
	Filter      string `json:"filter"`
	// Total is the number of certificates the operation will revoke. This is
	// the count a confirmed execution must echo back.
	Total int `json:"total"`
	// Known / Unknown split Total into inventory-backed certificates and
	// serial-list entries with no inventory row (revoked as bare CRL entries).
	Known   int `json:"known"`
	Unknown int `json:"unknown"`
	// AlreadyRevoked counts requested serial-list entries skipped because they
	// are already revoked (an interrupted run being resumed, typically).
	AlreadyRevoked int `json:"already_revoked"`
	// FilteredOut counts serial-list entries present in the inventory but
	// excluded by the other filters.
	FilteredOut int `json:"filtered_out"`
	// ExpiredExcluded counts certificates matching every filter but skipped
	// because they are expired (and IncludeExpired is off).
	ExpiredExcluded int `json:"expired_excluded"`
	// Sample holds up to 20 of the certificates that will be revoked.
	Sample []BulkRevokeItem `json:"sample,omitempty"`

	// serials is the full ordered candidate list, reused by Execute so the
	// plan it confirmed is the plan it applies.
	serials []string
}

// BulkRevokeResult summarizes an executed bulk revocation.
type BulkRevokeResult struct {
	OperationID string `json:"operation_id"`
	CAID        string `json:"ca_id"`
	Reason      string `json:"reason"`
	// Planned is the candidate total the run started from; Revoked is how many
	// certificates this run newly revoked. AlreadySkipped counts planned
	// serials that turned out to be revoked by the time their batch was
	// written (a concurrent revocation racing this operation).
	Planned        int `json:"planned"`
	Revoked        int `json:"revoked"`
	AlreadySkipped int `json:"already_skipped"`
	Batches        int `json:"batches"`
	// CRLScopes lists the CRL scopes ("full", "partition:N") whose base and
	// delta CRLs were regenerated after the batches completed.
	CRLScopes []string `json:"crl_scopes,omitempty"`
	// OCSPInvalidated is the number of cached OCSP responses dropped.
	OCSPInvalidated int `json:"ocsp_invalidated"`
	// PresignRefreshed is the number of OCSP responses re-signed by the
	// post-revocation presign refresh (0 when no presigner is wired).
	PresignRefreshed int `json:"presign_refreshed"`
	// PresignError carries a non-fatal presign-refresh failure. The
	// revocations and CRLs stand; the online responder signs fresh (correct)
	// responses on demand until the next scheduled presign batch succeeds.
	PresignError string        `json:"presign_error,omitempty"`
	Duration     time.Duration `json:"-"`
	DurationSecs float64       `json:"duration_seconds"`
}

// BulkCountMismatchError reports that the operator-confirmed certificate count
// no longer matches the live selection — certificates were issued, revoked, or
// expired between the dry run and the execution. Nothing has been revoked; the
// caller should re-preview and confirm the fresh count.
type BulkCountMismatchError struct {
	Confirmed int
	Actual    int
}

func (e *BulkCountMismatchError) Error() string {
	return fmt.Sprintf("confirmation count %d does not match the current selection of %d certificates; re-run the dry run and confirm the fresh count", e.Confirmed, e.Actual)
}

// BulkRevokerConfig wires the serving-layer caches into the engine. Both
// fields are optional: the CLI runs without either (the server's caches are
// process-local and its presigner refreshes on schedule), while the API path
// passes the live instances so relying parties see the revocations
// immediately.
type BulkRevokerConfig struct {
	// Cache, when non-nil, has the revoked serials' cached OCSP responses
	// invalidated as each batch lands.
	Cache *OCSPCache
	// Presigner, when non-nil, re-signs the CA's pre-signed OCSP response set
	// once after the operation so the cache serves "revoked" without waiting
	// for the next scheduled batch.
	Presigner *OCSPPresigner
}

// BulkRevoker executes mass revocations over a manager's store and provider.
type BulkRevoker struct {
	mgr *Manager
	cfg BulkRevokerConfig
}

// NewBulkRevoker builds a bulk-revocation engine over the manager.
func NewBulkRevoker(mgr *Manager, cfg BulkRevokerConfig) *BulkRevoker {
	return &BulkRevoker{mgr: mgr, cfg: cfg}
}

// Preview computes the dry-run plan for a spec without changing anything.
func (b *BulkRevoker) Preview(ctx context.Context, spec BulkRevokeSpec) (*BulkRevokePlan, error) {
	_, span := tracing.Start(ctx, "ca.bulk_revoke_preview", attribute.String("ca.id", spec.CAID))
	defer span.End()
	return b.buildPlan(spec)
}

// buildPlan validates the spec and computes the exact candidate set.
func (b *BulkRevoker) buildPlan(spec BulkRevokeSpec) (*BulkRevokePlan, error) {
	issuerCA, _, err := b.mgr.loadIssuer(spec.CAID)
	if err != nil {
		return nil, err
	}
	if _, err := pki.ParseRevocationReason(spec.Reason); err != nil {
		return nil, err
	}
	matchPattern, err := compileNamePattern(spec.Filter.Pattern)
	if err != nil {
		return nil, err
	}
	wanted, err := normalizeSerialSet(spec.Filter.Serials)
	if err != nil {
		return nil, err
	}

	// One query returns expired rows too; the expired split happens here so the
	// plan can report how many matching certificates were excluded by expiry.
	now := time.Now()
	candidates, err := b.mgr.db.ListRevocationCandidates(database.RevocationSelector{
		CAID:           spec.CAID,
		Profile:        spec.Filter.Profile,
		IssuedAfter:    spec.Filter.IssuedAfter,
		IssuedBefore:   spec.Filter.IssuedBefore,
		IncludeExpired: true,
		Now:            now,
	})
	if err != nil {
		return nil, fmt.Errorf("listing revocation candidates: %w", err)
	}

	plan := &BulkRevokePlan{
		OperationID: spec.OperationID,
		CAID:        issuerCA.ID,
		CALabel:     issuerCA.Label,
		Reason:      reasonOrUnspecified(spec.Reason),
		Filter:      spec.Filter.Describe(),
	}
	if plan.OperationID == "" {
		plan.OperationID = uuid.New().String()
	}

	addSample := func(item BulkRevokeItem) {
		if len(plan.Sample) < bulkSampleSize {
			plan.Sample = append(plan.Sample, item)
		}
	}

	matchedSerials := make(map[string]bool, len(candidates))
	for i := range candidates {
		c := &candidates[i]
		if matchPattern != nil && !matchPattern(c.CommonName, c.SANs) {
			continue
		}
		if wanted != nil && !wanted[c.Serial] {
			continue
		}
		if !spec.Filter.IncludeExpired && !c.NotAfter.After(now) {
			plan.ExpiredExcluded++
			continue
		}
		matchedSerials[c.Serial] = true
		plan.Known++
		plan.serials = append(plan.serials, c.Serial)
		addSample(BulkRevokeItem{
			Serial: c.Serial, CommonName: c.CommonName, Profile: c.Profile,
			NotAfter: c.NotAfter, Known: true,
		})
	}

	// Serial-list entries the inventory pass did not cover: already revoked,
	// present-but-filtered-out, or entirely unknown. Unknown serials are still
	// revoked (attacker-issued certificates are never in the inventory).
	if wanted != nil {
		missing := make([]string, 0)
		for s := range wanted {
			if !matchedSerials[s] {
				missing = append(missing, s)
			}
		}
		sort.Strings(missing)
		for _, s := range missing {
			rc, err := b.mgr.db.GetRevokedCertificate(spec.CAID, s)
			if err != nil {
				return nil, fmt.Errorf("checking revocation state of serial %s: %w", s, err)
			}
			if rc != nil {
				plan.AlreadyRevoked++
				continue
			}
			ic, err := b.mgr.db.GetIssuedCertificate(spec.CAID, s)
			if err != nil {
				return nil, fmt.Errorf("looking up serial %s: %w", s, err)
			}
			if ic != nil {
				plan.FilteredOut++
				continue
			}
			plan.Unknown++
			plan.serials = append(plan.serials, s)
			addSample(BulkRevokeItem{Serial: s, Known: false})
		}
	}

	sort.Strings(plan.serials)
	plan.Total = len(plan.serials)
	return plan, nil
}

// Execute runs the bulk revocation. The plan is recomputed from the live store
// and, when spec.ConfirmCount >= 0, checked against the confirmed count before
// anything is written. On mid-run failure the returned result (non-nil
// alongside the error) reports what was applied; re-running the same spec
// resumes with the remaining certificates.
func (b *BulkRevoker) Execute(ctx context.Context, spec BulkRevokeSpec) (_ *BulkRevokeResult, err error) {
	ctx, span := tracing.Start(ctx, "ca.bulk_revoke", attribute.String("ca.id", spec.CAID))
	defer func() { tracing.End(span, err) }()
	start := time.Now()

	plan, err := b.buildPlan(spec)
	if err != nil {
		metrics.RevocationsBulk.Inc(metrics.ResultError)
		return nil, err
	}
	if spec.ConfirmCount >= 0 && spec.ConfirmCount != plan.Total {
		// Deliberately not counted as an operation error: nothing was attempted.
		return nil, &BulkCountMismatchError{Confirmed: spec.ConfirmCount, Actual: plan.Total}
	}

	reason, err := pki.ParseRevocationReason(spec.Reason)
	if err != nil {
		metrics.RevocationsBulk.Inc(metrics.ResultError)
		return nil, err
	}
	batchSize := spec.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBulkRevokeBatchSize
	}
	if batchSize > maxBulkRevokeBatchSize {
		batchSize = maxBulkRevokeBatchSize
	}

	tenantID, terr := b.mgr.db.GetCATenant(spec.CAID)
	if terr != nil {
		log.Printf("WARNING: bulk revoke: could not resolve tenant of CA %q for audit/usage accounting: %v", spec.CAID, terr)
	}

	result := &BulkRevokeResult{
		OperationID: plan.OperationID,
		CAID:        plan.CAID,
		Reason:      plan.Reason,
		Planned:     plan.Total,
	}
	span.SetAttributes(attribute.Int("bulk.planned", plan.Total), attribute.String("bulk.operation_id", plan.OperationID))

	// One revocation timestamp for the whole operation keeps the CRL entries of
	// one incident consistent and unambiguous in the delta window.
	when := time.Now()

	finish := func(runErr error) (*BulkRevokeResult, error) {
		result.Duration = time.Since(start)
		result.DurationSecs = result.Duration.Seconds()
		metrics.RevocationsBulkDuration.Observe(result.DurationSecs)
		if result.Revoked > 0 {
			metrics.RevocationsBulkCertificates.Add(uint64(result.Revoked))
		}
		outcome := audit.ResultSuccess
		if runErr != nil {
			outcome = audit.ResultError
			metrics.RevocationsBulk.Inc(metrics.ResultError)
		} else {
			metrics.RevocationsBulk.Inc(metrics.ResultSuccess)
		}
		b.recordSummaryEvent(plan, spec, tenantID, result, outcome, runErr)
		return result, runErr
	}

	remaining := plan.serials
	for len(remaining) > 0 {
		if ctx.Err() != nil {
			return finish(fmt.Errorf("bulk revocation interrupted after %d of %d certificates (re-run to resume): %w",
				result.Revoked, plan.Total, ctx.Err()))
		}
		n := batchSize
		if n > len(remaining) {
			n = len(remaining)
		}
		batch := remaining[:n]
		remaining = remaining[n:]

		applied, err := b.mgr.db.BulkRevokeCertificates(spec.CAID, batch, reason, when)
		if err != nil {
			return finish(fmt.Errorf("bulk revocation failed after %d of %d certificates (re-run to resume): %w",
				result.Revoked, plan.Total, err))
		}
		result.Batches++
		result.Revoked += len(applied)
		result.AlreadySkipped += len(batch) - len(applied)

		for _, serial := range applied {
			b.recordCertEvent(plan, spec, tenantID, serial)
			if b.cfg.Cache != nil {
				b.cfg.Cache.Invalidate(spec.CAID, serial)
				result.OCSPInvalidated++
			}
		}
		if spec.Progress != nil {
			spec.Progress(result.Revoked, plan.Total)
		}
	}

	if result.Revoked > 0 && tenantID != "" {
		// Usage accounting only — revocation is never quota-gated, and a
		// suspended tenant's certificates must remain revocable.
		if err := b.mgr.db.AddTenantUsage(tenantID, database.UsageDay(when), database.UsageCertsRevoked, int64(result.Revoked)); err != nil {
			log.Printf("WARNING: bulk revoke: failed to account %d revocations for tenant %q: %v", result.Revoked, tenantID, err)
		}
	}

	// One CRL regeneration for the whole operation instead of one per
	// certificate: the full-scope base+delta pair always, plus the base+delta
	// pair of every partition an affected serial hashes into.
	if result.Revoked > 0 {
		scopes, err := b.regenerateCRLs(ctx, spec.CAID, plan)
		result.CRLScopes = scopes
		if err != nil {
			return finish(fmt.Errorf("revocations recorded, but CRL regeneration failed (regenerate with `secsy-ca gen-crl` or re-run): %w", err))
		}
	}

	// Refresh the pre-signed OCSP set so the response cache attests "revoked"
	// without waiting for the next scheduled presign batch. Non-fatal: the
	// per-serial invalidation above already forces fresh (correct) on-demand
	// signatures for the revoked serials.
	if b.cfg.Presigner != nil && result.Revoked > 0 {
		responses, perr := b.cfg.Presigner.PresignCA(ctx, spec.CAID)
		if perr != nil {
			result.PresignError = perr.Error()
			log.Printf("WARNING: bulk revoke: OCSP presign refresh for CA %s failed (on-demand responses remain correct): %v", spec.CAID, perr)
		} else {
			result.PresignRefreshed = len(responses)
		}
	}

	span.SetAttributes(attribute.Int("bulk.revoked", result.Revoked))
	return finish(nil)
}

// regenerateCRLs force-regenerates the base and delta CRL of every scope the
// operation touched, returning the regenerated scope keys.
func (b *BulkRevoker) regenerateCRLs(ctx context.Context, caID string, plan *BulkRevokePlan) ([]string, error) {
	shards := []int{FullScope}
	if crlSharded() {
		affected := make(map[int]bool)
		for _, s := range plan.serials {
			serial, ok := new(big.Int).SetString(s, 10)
			if !ok {
				continue
			}
			affected[ShardForSerial(serial)] = true
		}
		for shard := range affected {
			shards = append(shards, shard)
		}
		sort.Ints(shards[1:])
	}

	scopes := make([]string, 0, len(shards))
	for _, shard := range shards {
		base, err := b.mgr.regenerateBaseCRL(ctx, caID, shard)
		if err != nil {
			return scopes, fmt.Errorf("regenerating base CRL (%s): %w", scopeKey(shard), err)
		}
		if _, err := b.mgr.regenerateDeltaCRL(ctx, caID, shard, base); err != nil {
			return scopes, fmt.Errorf("regenerating delta CRL (%s): %w", scopeKey(shard), err)
		}
		scopes = append(scopes, scopeKey(shard))
	}
	return scopes, nil
}

// recordCertEvent appends the per-certificate audit event for one revocation.
func (b *BulkRevoker) recordCertEvent(plan *BulkRevokePlan, spec BulkRevokeSpec, tenantID, serial string) {
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actorOrSystem(spec.RequestedBy),
		Action:     audit.ActionCertRevoke,
		Tenant:     tenantID,
		Target:     plan.CAID,
		TargetName: serial,
		Result:     audit.ResultSuccess,
		Detail:     fmt.Sprintf("reason=%s bulk_op=%s", plan.Reason, plan.OperationID),
	}
	if err := b.mgr.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.revoke audit event for serial %s: %v", serial, err)
	}
}

// recordSummaryEvent appends the operation-level summary audit event.
func (b *BulkRevoker) recordSummaryEvent(plan *BulkRevokePlan, spec BulkRevokeSpec, tenantID string, result *BulkRevokeResult, outcome string, runErr error) {
	detail := fmt.Sprintf("op=%s reason=%s filter=[%s] planned=%d revoked=%d already_skipped=%d batches=%d crl_scopes=%s duration=%s",
		plan.OperationID, plan.Reason, plan.Filter, result.Planned, result.Revoked,
		result.AlreadySkipped, result.Batches, strings.Join(result.CRLScopes, ","), result.Duration.Round(time.Millisecond))
	if runErr != nil {
		detail += " error=" + runErr.Error()
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actorOrSystem(spec.RequestedBy),
		Action:     audit.ActionCertRevokeBulk,
		Tenant:     tenantID,
		Target:     plan.CAID,
		TargetName: plan.CALabel,
		Result:     outcome,
		Detail:     detail,
	}
	if err := b.mgr.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.revoke_bulk summary audit event: %v", err)
	}
}

// compileNamePattern validates a glob and returns a matcher over a
// certificate's common name and SANs (nil matcher = no pattern filter).
func compileNamePattern(pattern string) (func(cn string, sans []string) bool, error) {
	if pattern == "" {
		return nil, nil
	}
	p := strings.ToLower(pattern)
	if _, err := path.Match(p, "probe"); err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return func(cn string, sans []string) bool {
		if cn != "" {
			if ok, _ := path.Match(p, strings.ToLower(cn)); ok {
				return true
			}
		}
		for _, san := range sans {
			if ok, _ := path.Match(p, strings.ToLower(san)); ok {
				return true
			}
		}
		return false
	}, nil
}

// normalizeSerialSet validates a serial list and returns the canonical decimal
// set (nil when the list is empty).
func normalizeSerialSet(serials []string) (map[string]bool, error) {
	if len(serials) == 0 {
		return nil, nil
	}
	set := make(map[string]bool, len(serials))
	for _, s := range serials {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Sign() < 0 {
			return nil, fmt.Errorf("serial %q is not a valid decimal integer", s)
		}
		set[n.String()] = true
	}
	if len(set) == 0 {
		return nil, nil
	}
	return set, nil
}

// reasonOrUnspecified canonicalizes an empty reason name for display/audit.
func reasonOrUnspecified(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "unspecified"
	}
	return strings.TrimSpace(reason)
}

// actorOrSystem substitutes the system principal for an empty actor.
func actorOrSystem(actor string) string {
	if actor == "" {
		return "system"
	}
	return actor
}
