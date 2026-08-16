package ers

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Store is the slice of the persistence layer the preservation service needs;
// *database.DB satisfies it. Keeping it an interface avoids an import cycle
// (database is imported transitively through tsa) and keeps the service testable
// with an in-memory fake.
type Store interface {
	MaxEventSeq() (int64, error)
	GetErsCursor() (int64, error)
	ErsCursorInitialized() (bool, error)
	SetErsCursor(seq int64) error
	ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error)

	InsertEvidenceRecord(*models.EvidenceRecord) error
	UpdateEvidenceRecord(*models.EvidenceRecord) error
	ListAllEvidenceRecords() ([]models.EvidenceRecord, error)
	ListEvidenceRecords(limit, offset int) ([]models.EvidenceRecord, int, error)

	AppendEvent(*audit.Event) error
}

// Scope values for a persisted Evidence Record.
const (
	ScopeAudit    = "audit"
	ScopeArtifact = "artifact"
)

// Service generates and renews Evidence Records. It is safe for the naturally
// serial background loop; concurrent callers are not expected.
type Service struct {
	store      Store
	ts         Timestamper
	hash       crypto.Hash            // hash for new records and the hash-tree-renewal target
	deprecated func(crypto.Hash) bool // reports whether a chain algorithm must be migrated
	lookahead  time.Duration          // time-stamp renewal fires this long before TSA cert expiry
	batch      int
	now        func() time.Time
	actor      string
	logf       func(string, ...any)
}

// Options parameterizes NewService.
type Options struct {
	// Hash is the algorithm for new records and the target of hash-tree renewal.
	// Zero defaults to SHA-256.
	Hash crypto.Hash
	// Deprecated reports whether an existing record's current chain algorithm must
	// be migrated by hash-tree renewal. Nil defaults to the FIPS policy (a
	// non-approved algorithm is deprecated). A record whose algorithm is weaker
	// than Hash is always migrated, regardless of this predicate.
	Deprecated func(crypto.Hash) bool
	// RenewalLookahead is how long before a record's newest TSA certificate
	// expires a time-stamp renewal fires. Zero defaults to 30 days.
	RenewalLookahead time.Duration
	// Batch bounds how many audit events one generation cycle folds into a single
	// record. Zero defaults to 256.
	Batch int
	// Logf, when non-nil, receives progress lines.
	Logf func(string, ...any)
}

// NewService assembles a preservation service.
func NewService(store Store, ts Timestamper, opts Options) *Service {
	hash := opts.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}
	deprecated := opts.Deprecated
	if deprecated == nil {
		deprecated = defaultDeprecated
	}
	lookahead := opts.RenewalLookahead
	if lookahead <= 0 {
		lookahead = 30 * 24 * time.Hour
	}
	batch := opts.Batch
	if batch <= 0 {
		batch = 256
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Service{
		store: store, ts: ts, hash: hash, deprecated: deprecated,
		lookahead: lookahead, batch: batch, now: time.Now, actor: "ers", logf: logf,
	}
}

// SetClock overrides the time source (tests only).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// WithActor overrides the audit-event actor (e.g. "secsy-ca-cli").
func (s *Service) WithActor(a string) *Service { s.actor = a; return s }

// GenerateAudit folds every audit event newer than the cursor into Evidence
// Records, batchSize events per record, advancing the durable cursor only after
// each record is persisted (so a crash re-preserves the last batch rather than
// losing it). It returns the number of records created.
func (s *Service) GenerateAudit(ctx context.Context) (int, error) {
	initialized, err := s.store.ErsCursorInitialized()
	if err != nil {
		return 0, fmt.Errorf("ers: reading cursor state: %w", err)
	}
	// Snapshot the head once, up front, and never preserve past it in this cycle.
	// preserveEvents appends an ers.generate audit event, which is itself a new
	// log entry; without this bound the loop would chase its own tail forever.
	// Events appended during the cycle (our ers.generate/ers.renew records) are
	// simply preserved by the next cycle — bounded, and still exactly once.
	head, err := s.store.MaxEventSeq()
	if err != nil {
		return 0, fmt.Errorf("ers: reading event-log head: %w", err)
	}
	if !initialized {
		// First enablement: seed the cursor at the current head so preservation
		// starts from "now" rather than replaying the entire back-history in one
		// giant record. Operators wanting historical coverage use `ers generate`.
		if err := s.store.SetErsCursor(head); err != nil {
			return 0, fmt.Errorf("ers: seeding cursor: %w", err)
		}
		return 0, nil
	}

	created := 0
	for {
		cursor, err := s.store.GetErsCursor()
		if err != nil {
			return created, fmt.Errorf("ers: reading cursor: %w", err)
		}
		if cursor >= head {
			return created, nil
		}
		events, err := s.store.ListEventsSince(cursor, s.batch)
		if err != nil {
			return created, fmt.Errorf("ers: listing events since %d: %w", cursor, err)
		}
		// Never preserve past the snapshot head.
		for len(events) > 0 && events[len(events)-1].Seq > head {
			events = events[:len(events)-1]
		}
		if len(events) == 0 {
			return created, nil
		}
		if _, err := s.preserveEvents(ctx, events); err != nil {
			return created, err
		}
		created++
		if err := s.store.SetErsCursor(events[len(events)-1].Seq); err != nil {
			return created, fmt.Errorf("ers: advancing cursor: %w", err)
		}
	}
}

// preserveEvents mints and persists one Evidence Record over a batch of events.
func (s *Service) preserveEvents(ctx context.Context, events []audit.Event) (*models.EvidenceRecord, error) {
	objs := make([]DataObject, len(events))
	for i, e := range events {
		objs[i] = DataObject{ID: eventObjectID(e.Seq), Bytes: auditObjectBytes(e)}
	}
	er, err := Generate(ctx, s.ts, GenerateOptions{Objects: objs, Hash: s.hash})
	if err != nil {
		return nil, fmt.Errorf("ers: generating evidence record: %w", err)
	}
	first, last := events[0].Seq, events[len(events)-1].Seq
	rec, err := s.newRow(er, ScopeAudit, fmt.Sprintf("audit events %d-%d", first, last), first, last, objectIDs(objs))
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertEvidenceRecord(rec); err != nil {
		return nil, fmt.Errorf("ers: persisting evidence record: %w", err)
	}
	metrics.RecordErsGenerated()
	s.record(audit.ActionERSGenerate, rec.ID, audit.ResultSuccess,
		fmt.Sprintf("scope=audit objects=%d seq=%d-%d hash=%s", len(objs), first, last, rec.DigestAlg))
	return rec, nil
}

// GenerateArtifact mints and persists an Evidence Record over caller-supplied
// data objects (the CLI `ers generate -file` path). description labels the
// record; the objects are NOT stored, so renewal/verification of an artifact
// record requires the caller to re-supply them.
func (s *Service) GenerateArtifact(ctx context.Context, description string, objs []DataObject) (*models.EvidenceRecord, error) {
	if len(objs) == 0 {
		return nil, ErrEmpty
	}
	er, err := Generate(ctx, s.ts, GenerateOptions{Objects: objs, Hash: s.hash})
	if err != nil {
		return nil, err
	}
	rec, err := s.newRow(er, ScopeArtifact, description, 0, 0, objectIDs(objs))
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertEvidenceRecord(rec); err != nil {
		return nil, fmt.Errorf("ers: persisting evidence record: %w", err)
	}
	metrics.RecordErsGenerated()
	s.record(audit.ActionERSGenerate, rec.ID, audit.ResultSuccess,
		fmt.Sprintf("scope=artifact objects=%d hash=%s", len(objs), rec.DigestAlg))
	return rec, nil
}

// RenewAll scans every persisted record and renews those that are due: a
// hash-tree renewal when the current algorithm is deprecated or weaker than the
// service hash, otherwise a time-stamp renewal when the newest TSA certificate
// is within the lookahead of expiry. It returns the number renewed and the
// number still pending afterward (records that need a hash-tree renewal but
// whose objects are not re-derivable here — artifact records, which the CLI
// renews). Errors on individual records are logged and counted, not fatal.
func (s *Service) RenewAll(ctx context.Context) (renewed, pending int, err error) {
	records, err := s.store.ListAllEvidenceRecords()
	if err != nil {
		return 0, 0, fmt.Errorf("ers: listing evidence records: %w", err)
	}
	for i := range records {
		rec := records[i]
		did, stillPending, rerr := s.renewOne(ctx, &rec)
		if rerr != nil {
			s.logf("ers: renewing record %s: %v", rec.ID, rerr)
			s.record(audit.ActionERSRenew, rec.ID, audit.ResultError, rerr.Error())
			pending++
			continue
		}
		if did != "" {
			renewed++
			metrics.RecordErsRenewed(did)
			s.record(audit.ActionERSRenew, rec.ID, audit.ResultSuccess,
				fmt.Sprintf("kind=%s chains=%d hash=%s", did, rec.Chains, rec.DigestAlg))
		}
		if stillPending {
			pending++
		}
	}
	return renewed, pending, nil
}

// renewOne renews one record if due, updating it in place and returning the
// renewal kind performed ("timestamp"|"hashtree"|"") and whether it is still
// pending a renewal it could not perform here.
func (s *Service) renewOne(ctx context.Context, rec *models.EvidenceRecord) (kind string, pending bool, err error) {
	er, err := Parse(rec.Record)
	if err != nil {
		return "", false, fmt.Errorf("parsing stored record: %w", err)
	}
	curHash, err := er.CurrentHash()
	if err != nil {
		return "", false, err
	}
	now := s.now()

	// Hash-tree renewal takes priority: a deprecated or weaker algorithm must be
	// migrated before the underlying hashes lose their strength.
	if s.needsHashTreeRenewal(curHash) {
		objs, derr := s.resolveObjects(*rec)
		if derr != nil {
			// Cannot re-derive the objects here (an artifact record). Leave it for
			// the CLI, which supplies the bytes.
			return "", true, nil //nolint:nilerr // derr surfaces as pending=true, not as a failure: the record is renewable, just not from here.
		}
		renewed, rerr := er.RenewHashTree(ctx, s.ts, objs, s.hash)
		if rerr != nil {
			return "", false, fmt.Errorf("hash-tree renewal: %w", rerr)
		}
		if err := s.applyRenewal(rec, renewed, now); err != nil {
			return "", false, err
		}
		return "hashtree", false, nil
	}

	// Time-stamp renewal: fire when the newest TSA certificate is near expiry.
	if s.needsTimestampRenewal(er, now) {
		renewed, rerr := er.RenewTimestamp(ctx, s.ts)
		if rerr != nil {
			return "", false, fmt.Errorf("time-stamp renewal: %w", rerr)
		}
		if err := s.applyRenewal(rec, renewed, now); err != nil {
			return "", false, err
		}
		return "timestamp", false, nil
	}
	return "", false, nil
}

// needsHashTreeRenewal reports whether a record on curHash must be migrated to
// the service hash: either the algorithm is deprecated, or it is strictly weaker
// than the target.
func (s *Service) needsHashTreeRenewal(curHash crypto.Hash) bool {
	if s.deprecated(curHash) {
		return true
	}
	return hashRank(curHash) < hashRank(s.hash)
}

// needsTimestampRenewal reports whether the newest TSA certificate is within the
// lookahead of expiry (or already expired).
func (s *Service) needsTimestampRenewal(er *EvidenceRecord, now time.Time) bool {
	notAfter, ok := er.LatestSignerNotAfter()
	if !ok {
		return false
	}
	return now.Add(s.lookahead).After(notAfter)
}

// applyRenewal writes the renewed record back to the store, refreshing the
// derived metadata columns.
func (s *Service) applyRenewal(rec *models.EvidenceRecord, renewed *EvidenceRecord, now time.Time) error {
	if err := RefreshRow(rec, renewed, now); err != nil {
		return err
	}
	return s.store.UpdateEvidenceRecord(rec)
}

// RefreshRow updates a persisted record's mutable metadata columns from a freshly
// renewed EvidenceRecord: the DER, chain count, current hash algorithm, newest
// genTime, TSA-certificate expiry, and the renewal timestamp. The covered-object
// range is never touched. Both the background renewal path and the CLI use it, so
// a record renewed either way carries identical metadata.
func RefreshRow(rec *models.EvidenceRecord, renewed *EvidenceRecord, renewedAt time.Time) error {
	der, err := renewed.Marshal()
	if err != nil {
		return fmt.Errorf("ers: encoding renewed record: %w", err)
	}
	rec.Record = der
	rec.Chains = renewed.ChainCount()
	if h, herr := renewed.CurrentHash(); herr == nil {
		rec.DigestAlg = HashName(h)
	}
	if gt, ok := renewed.LatestGenTime(); ok {
		rec.LastGenTime = gt
	}
	if na, ok := renewed.LatestSignerNotAfter(); ok {
		rec.TSANotAfter = &na
	} else {
		rec.TSANotAfter = nil
	}
	at := renewedAt.UTC()
	rec.RenewedAt = &at
	return nil
}

// GenerateAuditRange preserves an explicit inclusive range of audit events as a
// single audit-scope Evidence Record, independent of the cursor. It backs the
// `secsy-ca ers generate -audit-from -audit-to` path for preserving historical
// events. from must be >= 1 and <= to.
func (s *Service) GenerateAuditRange(ctx context.Context, from, to int64) (*models.EvidenceRecord, error) {
	if from < 1 || to < from {
		return nil, fmt.Errorf("ers: invalid audit range %d-%d", from, to)
	}
	events, err := s.store.ListEventsSince(from-1, int(to-from+1))
	if err != nil {
		return nil, fmt.Errorf("ers: listing audit events %d-%d: %w", from, to, err)
	}
	var batch []audit.Event
	for _, e := range events {
		if e.Seq >= from && e.Seq <= to {
			batch = append(batch, e)
		}
	}
	if len(batch) == 0 {
		return nil, fmt.Errorf("ers: no audit events in range %d-%d", from, to)
	}
	return s.preserveEvents(ctx, batch)
}

// resolveObjects reconstructs the protected data objects of a record so it can
// be re-hashed (hash-tree renewal, verification). Audit records re-fetch their
// events from the event log; artifact records cannot be reconstructed here and
// return an error.
func (s *Service) resolveObjects(rec models.EvidenceRecord) ([]DataObject, error) {
	if rec.Scope != ScopeAudit {
		return nil, fmt.Errorf("ers: cannot reconstruct objects for a %q-scope record without the original data", rec.Scope)
	}
	if rec.LastSeq < rec.FirstSeq {
		return nil, fmt.Errorf("ers: record %s has an invalid seq range", rec.ID)
	}
	count := int(rec.LastSeq - rec.FirstSeq + 1)
	events, err := s.store.ListEventsSince(rec.FirstSeq-1, count)
	if err != nil {
		return nil, fmt.Errorf("ers: re-fetching audit events %d-%d: %w", rec.FirstSeq, rec.LastSeq, err)
	}
	objs := make([]DataObject, 0, count)
	for _, e := range events {
		if e.Seq < rec.FirstSeq || e.Seq > rec.LastSeq {
			continue
		}
		objs = append(objs, DataObject{ID: eventObjectID(e.Seq), Bytes: auditObjectBytes(e)})
	}
	if len(objs) != count {
		return nil, fmt.Errorf("ers: expected %d audit events for record %s, found %d (log truncated?)", count, rec.ID, len(objs))
	}
	return objs, nil
}

// ResolveObjects is the exported wrapper used by the CLI/verify endpoint to
// reconstruct an audit-scope record's protected objects for verification.
func (s *Service) ResolveObjects(rec models.EvidenceRecord) ([]DataObject, error) {
	return s.resolveObjects(rec)
}

// RunOnce performs one full preservation cycle: generate over new audit events
// (when preserveAudit) then renew due records, recording the cycle metric and a
// freshness timestamp. It never returns an error — a failure is logged, counted,
// and retried next tick — so a transient TSA outage never tears down the loop.
func (s *Service) RunOnce(ctx context.Context, preserveAudit bool) {
	start := s.now()
	var generated, renewed, pending int
	var cycleErr error

	if preserveAudit {
		g, err := s.GenerateAudit(ctx)
		generated = g
		if err != nil {
			cycleErr = err
		}
	}
	if cycleErr == nil {
		r, p, err := s.RenewAll(ctx)
		renewed, pending = r, p
		if err != nil {
			cycleErr = err
		}
	}

	total := 0
	if _, t, err := s.store.ListEvidenceRecords(1, 0); err == nil {
		total = t
	}
	metrics.RecordErsCycle(start, total, pending, cycleErr)
	if cycleErr != nil {
		s.logf("ers: preservation cycle FAILED: %v", cycleErr)
		return
	}
	if generated > 0 || renewed > 0 {
		s.logf("ers: preservation cycle ok — %d generated, %d renewed, %d records, %d pending renewal",
			generated, renewed, total, pending)
	}
}

// SeedMetrics initializes the record-count and freshness gauges from the store
// at startup. Best-effort.
func (s *Service) SeedMetrics() error {
	records, _, err := s.store.ListEvidenceRecords(1, 0)
	if err != nil {
		return err
	}
	total := 0
	var newest time.Time
	if all, aerr := s.store.ListAllEvidenceRecords(); aerr == nil {
		total = len(all)
		for _, r := range all {
			t := r.CreatedAt
			if r.RenewedAt != nil && r.RenewedAt.After(t) {
				t = *r.RenewedAt
			}
			if t.After(newest) {
				newest = t
			}
		}
	} else {
		total = len(records)
	}
	metrics.SeedErs(total, newest)
	return nil
}

// newRow assembles a persisted-record row from a freshly built/renewed
// EvidenceRecord and its metadata.
func (s *Service) newRow(er *EvidenceRecord, scope, description string, first, last int64, ids []string) (*models.EvidenceRecord, error) {
	rec := &models.EvidenceRecord{
		ID:          uuid.New().String(),
		Scope:       scope,
		Description: description,
		FirstSeq:    first,
		LastSeq:     last,
		ObjectIDs:   ids,
		Chains:      er.ChainCount(),
		CreatedAt:   s.now().UTC(),
	}
	der, err := er.Marshal()
	if err != nil {
		return nil, fmt.Errorf("ers: encoding record: %w", err)
	}
	rec.Record = der
	if h, err := er.CurrentHash(); err == nil {
		rec.DigestAlg = HashName(h)
	}
	if gt, ok := er.LatestGenTime(); ok {
		rec.LastGenTime = gt
	} else {
		rec.LastGenTime = rec.CreatedAt
	}
	if na, ok := er.LatestSignerNotAfter(); ok {
		rec.TSANotAfter = &na
	}
	return rec, nil
}

// record appends an ers.* audit event, best-effort.
func (s *Service) record(action, target, result, detail string) {
	if err := s.store.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      s.actor,
		ActorRoles: "system",
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		s.logf("ers: appending %s audit event: %v", action, err)
	}
}

// defaultDeprecated marks an algorithm deprecated when the FIPS crypto policy is
// enforced and does not approve it. Without the policy nothing is deprecated by
// default; hash-tree renewal then only happens when an operator raises ers.hash.
func defaultDeprecated(h crypto.Hash) bool {
	return fipsDeprecated(h)
}

// hashRank orders the SHA-2 family so "weaker than the target" is well defined.
func hashRank(h crypto.Hash) int {
	switch h {
	case crypto.SHA256:
		return 1
	case crypto.SHA384:
		return 2
	case crypto.SHA512:
		return 3
	default:
		return 0
	}
}

// eventObjectID is the stable data-object identifier for an audit event.
func eventObjectID(seq int64) string { return fmt.Sprintf("event:%d", seq) }

// objectIDs extracts the identifiers of a set of data objects.
func objectIDs(objs []DataObject) []string {
	ids := make([]string, len(objs))
	for i, o := range objs {
		ids[i] = o.ID
	}
	return ids
}

// auditObjectBytes is the canonical, stable serialization of an audit event's
// immutable content — the bytes an Evidence Record protects. Every field is
// length-prefixed so no rearrangement of field values can collide, and the
// serialization is fully reproducible from the append-only event_log row, so a
// record's objects can be re-derived for verification and hash-tree renewal.
func auditObjectBytes(e audit.Event) []byte {
	var b bytes.Buffer
	writeStr := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b.Write(l[:])
		b.WriteString(s)
	}
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], uint64(e.Seq))
	b.Write(seqb[:])
	writeStr(e.ID)
	writeStr(e.Timestamp.UTC().Format(time.RFC3339Nano))
	writeStr(e.Actor)
	writeStr(e.ActorName)
	writeStr(e.ActorRoles)
	writeStr(e.Action)
	writeStr(e.Tenant)
	writeStr(e.Target)
	writeStr(e.TargetName)
	writeStr(e.Result)
	writeStr(e.Detail)
	writeStr(e.PrevHash)
	writeStr(e.Hash)
	return b.Bytes()
}
