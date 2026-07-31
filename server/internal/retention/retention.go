// Package retention implements the certificate-inventory retention/archival job
// (Task 157): a leader-elected background loop that safely ages out long-expired,
// terminal issued-certificate rows so a high-volume CA (short-lived STAR/ACME
// issuance) does not grow issued_certificates unbounded.
//
// The policy is fail-safe by construction. Eligibility is driven entirely by
// not_after: a row is eligible only once its validity ended more than the
// configured grace window (retention.min_age_days) ago. A still-valid or
// revoked-but-not-yet-expired certificate has a not_after in the future, so it is
// never selected — this is what guarantees the CRL/OCSP-load-bearing set is
// retained. Held (suspended) certificates and certificates pinned by an open
// approval are additionally excluded. The job never touches the authoritative
// revoked_certificates table, so OCSP/CRL for every retained serial is unaffected.
//
// Two modes:
//   - archive: MOVE eligible rows into issued_certificates_archive (nothing is
//     lost; the hot table shrinks). The archive INSERT and source DELETE share one
//     transaction with the DELETE last, so a row never leaves the hot table
//     without its archive copy committed.
//   - prune: archive, then hard-delete archive rows older than prune_after_days —
//     "delete after successful archive".
//
// Every run appends one tamper-evident inventory.retention audit event carrying a
// manifest digest over the archived/pruned set, so the hash-chained audit log is
// a durable record of exactly which certificates left the hot inventory even
// after a prune removes the rows — preserving audit-chain continuity.
package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/google/uuid"
)

// Store is the narrow view of the persistence layer the retention job needs.
// *database.DB satisfies it; a test may substitute a fake.
type Store interface {
	Driver() string
	CountRetentionEligible(cutoff time.Time) (int, error)
	CountArchiveEligible(cutoff time.Time) (int, error)
	CountArchivedCertificates() (int, error)
	ListRetentionEligible(cutoff time.Time, afterCA, afterSerial string, limit int) ([]database.RetentionCandidate, error)
	ArchiveRetentionBatch(cutoff time.Time, runID, reason string, now time.Time, excludeSerials []string, limit int) ([]database.RetentionCandidate, error)
	PruneArchiveBatch(cutoff time.Time, limit int) ([]database.RetentionCandidate, error)
	OpenApprovalSerials() (map[string]struct{}, error)
	AppendEvent(*audit.Event) error
}

// Runner is the retention job. It is a singleton background job: register its Run
// on the leader elector so exactly one replica ages out inventory at a time. It
// is a no-op on non-leaders (they never call Run) and never blocks issuance
// (bounded, batched transactions over already-terminal rows).
type Runner struct {
	db     Store
	cfg    config.RetentionConfig
	logger *log.Logger
	// now is the clock; overridable in tests.
	now func() time.Time
}

// New builds a Runner from the resolved retention configuration.
func New(db Store, cfg config.RetentionConfig, logger *log.Logger) (*Runner, error) {
	if db == nil {
		return nil, fmt.Errorf("retention: nil store")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{db: db, cfg: cfg, logger: logger, now: time.Now}, nil
}

// SetClock overrides the clock (tests).
func (r *Runner) SetClock(now func() time.Time) { r.now = now }

// Result is the outcome of one retention pass (real or dry-run).
type Result struct {
	Mode        string    `json:"mode"`
	DryRun      bool      `json:"dry_run"`
	Window      string    `json:"window"`                 // resolved min_age
	Cutoff      time.Time `json:"cutoff"`                 // not_after < cutoff is eligible
	PruneCutoff time.Time `json:"prune_cutoff,omitempty"` // prune mode only
	// Eligible is the count of retention-eligible rows in the hot table at run
	// start (an upper bound: it does not subtract approval-pinned serials).
	Eligible int `json:"eligible"`
	// Archived is the number of rows moved to the archive (dry-run: would move).
	Archived int `json:"archived"`
	// Pruned is the number of archive rows hard-deleted (dry-run: would delete).
	Pruned int `json:"pruned"`
	// Backlog is the eligible count remaining after the run (trends to the
	// approval-pinned residue, normally zero).
	Backlog int `json:"backlog"`
	// ArchiveSize is the archive table row count after the run.
	ArchiveSize int `json:"archive_size"`
	// ProtectedByApprovals is how many serials were skipped because an open
	// approval pins them.
	ProtectedByApprovals int `json:"protected_by_approvals"`
	// Digest is "sha256:<hex>" over the archived (and pruned) manifest — a
	// tamper-evident fingerprint recorded in the audit log.
	Digest     string    `json:"digest"`
	Started    time.Time `json:"started"`
	DurationMS int64     `json:"duration_ms"`
}

// Run executes one pass immediately, then on every interval tick until ctx is
// cancelled. It blocks; callers register it as a leader-elected background job.
func (r *Runner) Run(ctx context.Context) {
	r.logger.Printf("certificate inventory retention started (mode=%s, interval=%s, min_age=%s, prune_after=%s, batch=%d, driver=%s)",
		r.cfg.ResolvedMode(), r.cfg.Interval(), humanDays(r.cfg.MinAge()), humanDays(r.cfg.PruneAfter()), r.cfg.Batch(), r.db.Driver())
	r.RunOnce(ctx)

	ticker := time.NewTicker(r.cfg.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Printf("certificate inventory retention stopped")
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}

// RunOnce performs exactly one retention pass, recording metrics and the
// inventory.retention audit event. It never returns an error: a failed pass is
// logged, counted, and audited so the next tick simply retries. It is what the
// leader-elected loop calls each tick.
func (r *Runner) RunOnce(ctx context.Context) Result {
	res, _ := r.RunNow(ctx)
	return res
}

// RunNow performs one real retention pass, records metrics and the
// inventory.retention audit event, logs the outcome, and returns the result plus
// any error — so the `inventory retention run` CLI can exit non-zero on failure
// while the background loop (via RunOnce) simply ignores it and retries next tick.
func (r *Runner) RunNow(ctx context.Context) (Result, error) {
	res, err := r.pass(ctx, false)
	metrics.RecordInventoryRetention(res.Started, res.Archived, res.Pruned, res.Backlog, res.ArchiveSize, err)
	r.recordAudit(res, err)
	if err != nil {
		r.logger.Printf("inventory retention: FAILED after %s: %v",
			time.Since(res.Started).Round(time.Millisecond), err)
	} else {
		r.logger.Printf("inventory retention: ok — mode=%s archived=%d pruned=%d backlog=%d archive_size=%d (%s)",
			res.Mode, res.Archived, res.Pruned, res.Backlog, res.ArchiveSize, time.Since(res.Started).Round(time.Millisecond))
	}
	return res, err
}

// Plan performs a non-mutating dry-run: it reports the counts and the manifest
// digest a real run would produce, touching no rows. It backs
// `inventory retention dry-run`.
func (r *Runner) Plan(ctx context.Context) (Result, error) {
	return r.pass(ctx, true)
}

// Snapshot returns the current retention state (cheap counts, no scan) for the
// `inventory retention status` command.
type Snapshot struct {
	Mode        string    `json:"mode"`
	Window      string    `json:"window"`
	Cutoff      time.Time `json:"cutoff"`
	PruneCutoff time.Time `json:"prune_cutoff,omitempty"`
	Eligible    int       `json:"eligible"`
	Prunable    int       `json:"prunable"`
	ArchiveSize int       `json:"archive_size"`
}

// Snapshot reads the current eligibility/archive counts without mutating.
func (r *Runner) Snapshot(ctx context.Context) (Snapshot, error) {
	start := r.now().UTC()
	minAge := r.cfg.MinAge()
	cutoff := start.Add(-minAge)
	pruneCutoff := start.Add(-r.cfg.PruneAfter())
	s := Snapshot{Mode: r.cfg.ResolvedMode(), Window: humanDays(minAge), Cutoff: cutoff}
	var err error
	if s.Eligible, err = r.db.CountRetentionEligible(cutoff); err != nil {
		return s, fmt.Errorf("counting eligible: %w", err)
	}
	if s.ArchiveSize, err = r.db.CountArchivedCertificates(); err != nil {
		return s, fmt.Errorf("counting archive: %w", err)
	}
	if s.Mode == config.RetentionModePrune {
		s.PruneCutoff = pruneCutoff
		archPrune, aerr := r.db.CountArchiveEligible(pruneCutoff)
		if aerr != nil {
			return s, fmt.Errorf("counting prunable archive: %w", aerr)
		}
		issuedPrune, ierr := r.db.CountRetentionEligible(pruneCutoff)
		if ierr != nil {
			return s, fmt.Errorf("counting prunable issued: %w", ierr)
		}
		s.Prunable = archPrune + issuedPrune
	}
	return s, nil
}

// pass computes cutoffs, resolves the approval-pinned exclusion set, and either
// reports (dryRun) or performs the archive and prune passes.
func (r *Runner) pass(ctx context.Context, dryRun bool) (Result, error) {
	start := r.now().UTC()
	minAge := r.cfg.MinAge()
	cutoff := start.Add(-minAge)
	mode := r.cfg.ResolvedMode()
	pruneCutoff := start.Add(-r.cfg.PruneAfter())
	batch := r.cfg.Batch()

	res := Result{Mode: mode, DryRun: dryRun, Window: humanDays(minAge), Cutoff: cutoff, Started: start}
	if mode == config.RetentionModePrune {
		res.PruneCutoff = pruneCutoff
	}

	excl, err := r.db.OpenApprovalSerials()
	if err != nil {
		return res, fmt.Errorf("resolving open-approval serials: %w", err)
	}
	res.ProtectedByApprovals = len(excl)
	exclList := sortedKeys(excl)

	if res.Eligible, err = r.db.CountRetentionEligible(cutoff); err != nil {
		return res, fmt.Errorf("counting eligible: %w", err)
	}

	h := sha256.New()

	if dryRun {
		wouldArchive := 0
		afterCA, afterSerial := "", ""
		for {
			page, lerr := r.db.ListRetentionEligible(cutoff, afterCA, afterSerial, batch)
			if lerr != nil {
				return res, fmt.Errorf("listing eligible: %w", lerr)
			}
			if len(page) == 0 {
				break
			}
			for _, c := range page {
				if _, pinned := excl[c.Serial]; pinned {
					continue
				}
				wouldArchive++
				foldDigest(h, c)
			}
			last := page[len(page)-1]
			afterCA, afterSerial = last.CAID, last.Serial
			if len(page) < batch {
				break
			}
		}
		res.Archived = wouldArchive
		if mode == config.RetentionModePrune {
			// A prune run archives everything eligible then hard-deletes archive
			// rows older than pruneCutoff, so the rows that end up deleted are the
			// existing archive rows past pruneCutoff plus the freshly-archived rows
			// that are themselves past pruneCutoff.
			archPrune, aerr := r.db.CountArchiveEligible(pruneCutoff)
			if aerr != nil {
				return res, fmt.Errorf("counting prunable archive: %w", aerr)
			}
			issuedPrune, ierr := r.db.CountRetentionEligible(pruneCutoff)
			if ierr != nil {
				return res, fmt.Errorf("counting prunable issued: %w", ierr)
			}
			res.Pruned = archPrune + issuedPrune
		}
		res.Backlog = res.Eligible
		if n, cerr := r.db.CountArchivedCertificates(); cerr == nil {
			res.ArchiveSize = n
		}
		res.Digest = digestString(h)
		res.DurationMS = r.now().Sub(start).Milliseconds()
		return res, nil
	}

	// Real run: archive-move, then (prune mode) hard-delete.
	runID := uuid.NewString()
	reason := fmt.Sprintf("%s min_age=%s", mode, humanDays(minAge))
	for {
		moved, aerr := r.db.ArchiveRetentionBatch(cutoff, runID, reason, start, exclList, batch)
		if aerr != nil {
			return res, fmt.Errorf("archiving batch: %w", aerr)
		}
		if len(moved) == 0 {
			break
		}
		for _, c := range moved {
			foldDigest(h, c)
		}
		res.Archived += len(moved)
	}

	if mode == config.RetentionModePrune {
		for {
			deleted, perr := r.db.PruneArchiveBatch(pruneCutoff, batch)
			if perr != nil {
				return res, fmt.Errorf("pruning batch: %w", perr)
			}
			if len(deleted) == 0 {
				break
			}
			for _, c := range deleted {
				foldDigest(h, c)
			}
			res.Pruned += len(deleted)
		}
	}

	if res.Backlog, err = r.db.CountRetentionEligible(cutoff); err != nil {
		return res, fmt.Errorf("counting backlog: %w", err)
	}
	if res.ArchiveSize, err = r.db.CountArchivedCertificates(); err != nil {
		return res, fmt.Errorf("counting archive: %w", err)
	}
	res.Digest = digestString(h)
	res.DurationMS = r.now().Sub(start).Milliseconds()
	return res, nil
}

// recordAudit appends the inventory.retention event for one pass, best-effort.
func (r *Runner) recordAudit(res Result, runErr error) {
	result := audit.ResultSuccess
	detail := fmt.Sprintf("mode=%s archived=%d pruned=%d eligible=%d backlog=%d archive_size=%d protected_by_approvals=%d window=%s digest=%s driver=%s",
		res.Mode, res.Archived, res.Pruned, res.Eligible, res.Backlog, res.ArchiveSize,
		res.ProtectedByApprovals, humanDays(r.cfg.MinAge()), res.Digest, r.db.Driver())
	if runErr != nil {
		result = audit.ResultError
		detail = fmt.Sprintf("mode=%s error=%s driver=%s", res.Mode, runErr.Error(), r.db.Driver())
	}
	if err := r.db.AppendEvent(&audit.Event{
		ID:         uuid.NewString(),
		Actor:      "retention",
		ActorRoles: "system",
		Action:     audit.ActionInventoryRetention,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		r.logger.Printf("inventory retention: WARNING: failed to append audit event: %v", err)
	}
}

// foldDigest folds one candidate into the running manifest hash. Fields are
// unit-separated and the record newline-terminated so no two distinct records
// can collide.
func foldDigest(h hash.Hash, c database.RetentionCandidate) {
	_, _ = h.Write([]byte(c.CAID + "\x1f" + c.Serial + "\x1f" +
		strconv.FormatInt(c.NotAfter.UTC().Unix(), 10) + "\x1f" + c.Status + "\n"))
}

func digestString(h hash.Hash) string {
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// sortedKeys returns the map keys sorted, so the exclusion list is deterministic.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// humanDays renders a day-multiple duration as "Nd", falling back to the
// Duration string for sub-day values.
func humanDays(d time.Duration) string {
	if d <= 0 {
		return "0d"
	}
	if d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return d.String()
}
