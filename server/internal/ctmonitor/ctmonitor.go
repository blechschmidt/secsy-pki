// Package ctmonitor implements the post-issuance half of Certificate
// Transparency (Task 93): it verifies that the CT logs actually keep the promise
// their Signed Certificate Timestamps make.
//
// Task 26 submits precertificates to CT logs at issuance and embeds the returned
// SCTs into the final certificate. An SCT is a log's signed promise to
// incorporate the certificate into its append-only Merkle tree within its
// Maximum Merge Delay (MMD). Nothing, until now, checked that the log honored
// that promise. This package closes the loop:
//
//   - It scans issued certificates that carry embedded SCTs.
//   - For each embedded SCT whose log MMD has elapsed, it fetches the log's
//     Signed Tree Head (get-sth, signature-verified) and the inclusion proof for
//     the precertificate entry (get-proof-by-hash), then verifies the Merkle
//     audit path against the SCT's log id and timestamp.
//   - It records the per-SCT inclusion state in the sct_inclusion store table.
//   - Any SCT a log fails to honor after its MMD — no proof, or a proof that does
//     not chain to the log's signed root — is a genuine mis-issuance /
//     log-misbehavior signal: it is alerted through the expiry monitor's
//     notification sinks and counted in a dedicated metric.
//
// The monitor is a singleton background job: register its Run on the leader
// elector so exactly one replica verifies at a time. It never touches the HSM
// (it reads certificates from the store, fetches over HTTP, and verifies with
// the logs' public keys), and never blocks issuance.
package ctmonitor

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// actor is the identity the monitor runs and audits as.
const actor = "ct-monitor"

// Store is the read/write persistence surface the monitor needs. *database.DB
// satisfies it.
type Store interface {
	ListCertificatesPendingInclusion(limit int) ([]models.IssuedCertificate, error)
	GetCA(id string) (*models.CA, error)
	GetSCTInclusion(caID, serial, logID string) (*models.SCTInclusion, error)
	UpsertSCTInclusion(r *models.SCTInclusion) error
	CountSCTInclusionByStatus() (map[string]int, error)
	AppendEvent(e *audit.Event) error
}

// LogRegistry resolves a configured CT log by the log id an SCT carries.
// *ct.Submitter satisfies it.
type LogRegistry interface {
	LogByID(id [32]byte) (*ct.Log, bool)
}

// Notifier dispatches log-misbehavior alerts. *monitor.Notifier satisfies it;
// it may be nil (failures are then only logged, audited, and counted).
type Notifier interface {
	NotifyCTMisbehavior(ctx context.Context, events []monitor.CTMisbehavior)
}

// Monitor verifies SCT inclusion for issued certificates against their CT logs.
type Monitor struct {
	store    Store
	logs     LogRegistry
	cfg      config.CTInclusionMonitorConfig
	notifier Notifier
	logger   *log.Logger
	// now and httpTimeout are overridable in tests.
	now         func() time.Time
	httpTimeout time.Duration
}

// New builds a Monitor. store and logs are required; notifier may be nil.
func New(store Store, logs LogRegistry, cfg config.CTInclusionMonitorConfig, notifier Notifier, logger *log.Logger) (*Monitor, error) {
	if store == nil {
		return nil, fmt.Errorf("ctmonitor: a store is required")
	}
	if logs == nil {
		return nil, fmt.Errorf("ctmonitor: a CT log registry is required")
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Monitor{
		store:       store,
		logs:        logs,
		cfg:         cfg,
		notifier:    notifier,
		logger:      logger,
		now:         time.Now,
		httpTimeout: cfg.Timeout(),
	}, nil
}

// Run scans immediately, then on every interval tick, until ctx is cancelled. It
// blocks; callers register it as a leader-elected background job.
func (m *Monitor) Run(ctx context.Context) {
	m.logger.Printf("CT inclusion monitor started (interval=%s, timeout=%s, max_certs_per_run=%d)",
		m.cfg.Interval(), m.httpTimeout, m.cfg.MaxCerts())
	m.RunOnce(ctx)

	ticker := time.NewTicker(m.cfg.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.logger.Printf("CT inclusion monitor stopped")
			return
		case <-ticker.C:
			m.RunOnce(ctx)
		}
	}
}

// ScanResult summarizes one inclusion-verification scan.
type ScanResult struct {
	StartedAt time.Time `json:"started_at"`
	// Certs is the number of certificates examined.
	Certs int `json:"certs"`
	// Per-SCT outcome tallies for this scan.
	Checked    int `json:"checked"`
	Included   int `json:"included"`
	Pending    int `json:"pending"`
	Failed     int `json:"failed"`
	UnknownLog int `json:"unknown_log"`
	Errors     int `json:"errors"`
	// NewMisbehavior counts SCTs that transitioned into the failed state this
	// scan (the events that were alerted).
	NewMisbehavior int `json:"new_misbehavior"`
	// Err is a scan-level error (e.g. enumerating the store failed); per-SCT
	// verification failures are tallied above, not here.
	Err error `json:"-"`
	// misbehavior accumulates the alertable events discovered this scan.
	misbehavior []monitor.CTMisbehavior
	// sths caches each log's signed tree head for the scan so a run makes one
	// get-sth call per log rather than one per SCT.
	sths map[string]*sthResult
	// issuers caches parsed issuer certificates per CA id.
	issuers map[string]*x509.Certificate
}

// sthResult memoizes a per-scan get-sth outcome (success or error) per log.
type sthResult struct {
	sth *ct.SignedTreeHead
	err error
}

// RunOnce performs one full inclusion-verification scan, records metrics and a
// ct.inclusion audit event, and dispatches any newly discovered log misbehavior.
// It never returns an error — a failure is logged, counted, and audited so the
// next tick retries and a transient failure never tears down the loop. It
// returns the scan result (also used by the CLI and tests).
func (m *Monitor) RunOnce(ctx context.Context) *ScanResult {
	res := &ScanResult{
		StartedAt: m.now(),
		sths:      map[string]*sthResult{},
		issuers:   map[string]*x509.Certificate{},
	}

	certs, err := m.store.ListCertificatesPendingInclusion(m.cfg.MaxCerts())
	if err != nil {
		res.Err = fmt.Errorf("listing certificates with unresolved SCTs: %w", err)
		m.logger.Printf("CT inclusion monitor: FAILED: %v", res.Err)
		m.finish(res)
		return res
	}
	res.Certs = len(certs)

	for i := range certs {
		if ctx.Err() != nil {
			break
		}
		m.checkCert(ctx, &certs[i], res)
	}

	m.finish(res)

	if len(res.misbehavior) > 0 {
		m.logger.Printf("CT inclusion monitor: %d NEW log-misbehavior event(s) detected", len(res.misbehavior))
		if m.notifier != nil {
			m.notifier.NotifyCTMisbehavior(ctx, res.misbehavior)
		}
	}
	m.logger.Printf("CT inclusion monitor: scanned %d cert(s), %d SCT check(s) (included=%d pending=%d failed=%d unknown_log=%d error=%d)",
		res.Certs, res.Checked, res.Included, res.Pending, res.Failed, res.UnknownLog, res.Errors)
	return res
}

// finish refreshes the backlog gauges from the store, stamps the run metrics,
// and records the audit event.
func (m *Monitor) finish(res *ScanResult) {
	res.NewMisbehavior = len(res.misbehavior)
	pending, failed := m.backlog()
	metrics.RecordCTMonitorRun(res.StartedAt, pending, failed, res.Err)
	m.recordAudit(res, pending, failed)
}

// backlog reads the standing pending/failed SCT counts from the store for the
// gauges and the audit detail. Errors leave the counts at zero (best-effort).
func (m *Monitor) backlog() (pending, failed int) {
	counts, err := m.store.CountSCTInclusionByStatus()
	if err != nil {
		return 0, 0
	}
	return counts[models.SCTInclusionPending], counts[models.SCTInclusionFailed]
}

// checkCert verifies every embedded SCT of one certificate.
func (m *Monitor) checkCert(ctx context.Context, cert *models.IssuedCertificate, res *ScanResult) {
	leaf, err := pki.ParseCertificatePEM([]byte(cert.Certificate))
	if err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: parsing certificate %s/%s: %v", cert.CAID, cert.Serial, err)
		return
	}
	var sctExtValue []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(ct.OIDSCTList) {
			sctExtValue = e.Value
			break
		}
	}
	if sctExtValue == nil {
		return // recorded sct_count>0 but no SCT list extension; nothing to verify
	}
	scts, err := ct.ParseSCTListExtension(sctExtValue)
	if err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: parsing SCT list of %s/%s: %v", cert.CAID, cert.Serial, err)
		return
	}
	// The bytes the log signed / built its Merkle leaf from: the final
	// certificate's TBS with the SCT list extension removed (equivalently the
	// precertificate's TBS with the poison removed).
	tbs, err := ct.TBSWithoutExtension(leaf.Raw, ct.OIDSCTList)
	if err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: reconstructing precert TBS of %s/%s: %v", cert.CAID, cert.Serial, err)
		return
	}
	issuer, err := m.issuerCert(cert.CAID, res)
	if err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: loading issuer of %s/%s: %v", cert.CAID, cert.Serial, err)
		return
	}

	for _, sct := range scts {
		if ctx.Err() != nil {
			return
		}
		m.checkSCT(ctx, cert, issuer, tbs, sct, res)
	}
}

// checkSCT verifies one embedded SCT's inclusion and upserts its state.
func (m *Monitor) checkSCT(ctx context.Context, cert *models.IssuedCertificate, issuer *x509.Certificate, tbs []byte, sct *ct.SCT, res *ScanResult) {
	res.Checked++
	logIDHex := hex.EncodeToString(sct.LogID[:])
	prior, _ := m.store.GetSCTInclusion(cert.CAID, cert.Serial, logIDHex)

	now := m.now()
	rec := &models.SCTInclusion{
		CAID:          cert.CAID,
		Serial:        cert.Serial,
		LogID:         logIDHex,
		SCTTimestamp:  time.UnixMilli(int64(sct.Timestamp)).UTC(),
		LastCheckedAt: func() *time.Time { t := now; return &t }(),
		Checks:        1,
	}
	if prior != nil {
		rec.Checks = prior.Checks + 1
		rec.FirstCheckedAt = prior.FirstCheckedAt
		rec.LogName = prior.LogName
		rec.Alerted = prior.Alerted
		rec.TreeSize = prior.TreeSize
		rec.LeafIndex = prior.LeafIndex
		rec.IncludedAt = prior.IncludedAt
	}
	if rec.FirstCheckedAt == nil {
		t := now
		rec.FirstCheckedAt = &t
	}

	// Resolve the log. An SCT from a log not in the registry (or without a public
	// key, so its STH cannot be verified) cannot be checked — a configuration
	// gap, not misbehavior.
	lg, ok := m.logs.LogByID(sct.LogID)
	if !ok || !lg.HasKey() {
		if lg != nil {
			rec.LogName = lg.Name
		}
		rec.Status = models.SCTInclusionUnknownLog
		rec.LastError = "SCT log id is not in the configured registry (or the log has no public key); inclusion cannot be verified"
		metrics.CTInclusionChecks.Inc(logLabel(lg), models.SCTInclusionUnknownLog)
		res.UnknownLog++
		m.save(rec)
		return
	}
	rec.LogName = lg.Name

	// Only expect inclusion once the log's Maximum Merge Delay has elapsed; until
	// then a missing entry is a pending merge, not misbehavior.
	if !lg.MMDElapsed(sct.Timestamp, now) {
		rec.Status = models.SCTInclusionPending
		rec.LastError = ""
		metrics.CTInclusionChecks.Inc(lg.Name, models.SCTInclusionPending)
		res.Pending++
		m.save(rec)
		return
	}

	// Signed Tree Head (cached per log, signature-verified inside GetSTH).
	sth, err := m.sthFor(ctx, res, lg)
	if err != nil {
		m.transientPending(rec, prior, fmt.Sprintf("get-sth: %v", err))
		metrics.CTInclusionChecks.Inc(lg.Name, metrics.ResultError)
		res.Errors++
		m.save(rec)
		return
	}

	leafHash, err := ct.PrecertLeafHash(sct, issuer, tbs)
	if err != nil {
		m.transientPending(rec, prior, fmt.Sprintf("computing Merkle leaf hash: %v", err))
		metrics.CTInclusionChecks.Inc(lg.Name, metrics.ResultError)
		res.Errors++
		m.save(rec)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, m.httpTimeout)
	proof, err := lg.GetProofByHash(reqCtx, leafHash[:], sth.TreeSize)
	cancel()
	switch {
	case errors.Is(err, ct.ErrProofNotFound):
		// The MMD has elapsed and the log has no proof for the entry: a genuine
		// failure to honor the SCT.
		m.recordFailure(rec, prior, res,
			fmt.Sprintf("log did not include the certificate by its Maximum Merge Delay: no inclusion proof at tree size %d", sth.TreeSize))
		return
	case err != nil:
		m.transientPending(rec, prior, fmt.Sprintf("get-proof-by-hash: %v", err))
		metrics.CTInclusionChecks.Inc(lg.Name, metrics.ResultError)
		res.Errors++
		m.save(rec)
		return
	}

	if err := ct.VerifyInclusionProof(proof.LeafIndex, sth.TreeSize, proof.AuditPath, sth.SHA256RootHash[:], leafHash[:]); err != nil {
		// A proof that does not chain to the log's signed root is also misbehavior.
		m.recordFailure(rec, prior, res, fmt.Sprintf("invalid inclusion proof: %v", err))
		return
	}

	// Included and proven.
	rec.Status = models.SCTInclusionIncluded
	rec.TreeSize = int64(sth.TreeSize)
	rec.LeafIndex = int64(proof.LeafIndex)
	rec.LastError = ""
	rec.Alerted = false
	if rec.IncludedAt == nil {
		t := now
		rec.IncludedAt = &t
	}
	metrics.CTInclusionChecks.Inc(lg.Name, models.SCTInclusionIncluded)
	res.Included++
	m.save(rec)
}

// transientPending marks a record pending after a recoverable failure (a fetch
// error), preserving a prior terminal 'included' state so a temporary log
// outage never regresses a proven certificate.
func (m *Monitor) transientPending(rec *models.SCTInclusion, prior *models.SCTInclusion, detail string) {
	rec.LastError = detail
	if prior != nil && prior.Status == models.SCTInclusionIncluded {
		rec.Status = models.SCTInclusionIncluded // keep the proven state; just note the error
		return
	}
	rec.Status = models.SCTInclusionPending
}

// recordFailure marks an SCT failed and, on the transition into failure, counts
// the misbehavior metric and queues an alert (once per failure, not every scan).
func (m *Monitor) recordFailure(rec *models.SCTInclusion, prior *models.SCTInclusion, res *ScanResult, reason string) {
	rec.Status = models.SCTInclusionFailed
	rec.LastError = reason
	metrics.CTInclusionChecks.Inc(rec.LogName, models.SCTInclusionFailed)
	res.Failed++

	alreadyAlerted := prior != nil && prior.Status == models.SCTInclusionFailed && prior.Alerted
	if !alreadyAlerted {
		metrics.RecordCTLogMisbehavior(rec.LogName)
		res.misbehavior = append(res.misbehavior, monitor.CTMisbehavior{
			CAID:    rec.CAID,
			Serial:  rec.Serial,
			LogName: rec.LogName,
			LogID:   rec.LogID,
			Reason:  reason,
			At:      m.now(),
		})
		m.logger.Printf("CT inclusion monitor: LOG MISBEHAVIOR log=%s ca=%s serial=%s: %s",
			rec.LogName, rec.CAID, rec.Serial, reason)
	}
	rec.Alerted = true
	m.save(rec)
}

// sthFor returns the log's Signed Tree Head for this scan, fetching (and
// signature-verifying) it once per log and caching the outcome.
func (m *Monitor) sthFor(ctx context.Context, res *ScanResult, lg *ct.Log) (*ct.SignedTreeHead, error) {
	if cached, ok := res.sths[lg.Name]; ok {
		return cached.sth, cached.err
	}
	reqCtx, cancel := context.WithTimeout(ctx, m.httpTimeout)
	defer cancel()
	sth, err := lg.GetSTH(reqCtx)
	res.sths[lg.Name] = &sthResult{sth: sth, err: err}
	return sth, err
}

// issuerCert parses (and caches per scan) the issuing CA's certificate, whose
// public key hash binds the SCT and the Merkle leaf.
func (m *Monitor) issuerCert(caID string, res *ScanResult) (*x509.Certificate, error) {
	if c, ok := res.issuers[caID]; ok {
		if c == nil {
			return nil, fmt.Errorf("issuer CA %q has no usable certificate", caID)
		}
		return c, nil
	}
	caRec, err := m.store.GetCA(caID)
	if err != nil {
		return nil, err
	}
	if caRec == nil || caRec.Certificate == "" {
		res.issuers[caID] = nil
		return nil, fmt.Errorf("issuer CA %q has no certificate on record", caID)
	}
	cert, err := pki.ParseCertificatePEM([]byte(caRec.Certificate))
	if err != nil {
		res.issuers[caID] = nil
		return nil, err
	}
	res.issuers[caID] = cert
	return cert, nil
}

// save persists the record, logging (but not failing the scan) on error.
func (m *Monitor) save(rec *models.SCTInclusion) {
	if err := m.store.UpsertSCTInclusion(rec); err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: persisting inclusion state for %s/%s log=%s: %v",
			rec.CAID, rec.Serial, rec.LogName, err)
	}
}

// recordAudit appends the ct.inclusion event for one scan, best-effort.
func (m *Monitor) recordAudit(res *ScanResult, pending, failed int) {
	result := audit.ResultSuccess
	detail := fmt.Sprintf("certs=%d checked=%d included=%d pending=%d failed=%d unknown_log=%d errors=%d new_misbehavior=%d standing_pending=%d standing_failed=%d",
		res.Certs, res.Checked, res.Included, res.Pending, res.Failed, res.UnknownLog, res.Errors,
		len(res.misbehavior), pending, failed)
	if res.Err != nil {
		result = audit.ResultError
		detail = fmt.Sprintf("error=%s", res.Err.Error())
	} else if len(res.misbehavior) > 0 {
		result = audit.ResultError
	}
	if err := m.store.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "system",
		Action:     audit.ActionCTInclusion,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		m.logger.Printf("CT inclusion monitor: WARNING: failed to append ct.inclusion audit event: %v", err)
	}
}

// logLabel returns a metric-safe log label, "unknown" when the log is not in
// the registry.
func logLabel(lg *ct.Log) string {
	if lg == nil {
		return "unknown"
	}
	return lg.Name
}
