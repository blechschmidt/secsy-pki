// Package canary implements the synthetic issuance canary (Task 71): an
// opt-in, end-to-end self-test loop that continuously proves the certificate
// issuance and revocation path works.
//
// Each interval, for every configured CA, a probe walks the full lifecycle of
// a real — but synthetic — certificate:
//
//	issue        HSM-signed issuance from the dedicated canary profile
//	             (short-lived, non-public, lint gate enforced)
//	chain        full-chain verification of the fresh leaf up to the root
//	ocsp_good    the OCSP responder attests "good" for the new serial with a
//	             fresh, correctly signed response
//	crl          the serial's CRL scope is signed, fresh (thisUpdate/nextUpdate
//	             bracket now), and does not yet list the serial
//	revoke       revocation of the probe certificate
//	ocsp_revoked "revoked" has propagated: the revocation store has the entry
//	             and the OCSP responder now attests "revoked"
//
// Every stage is timed into secsy_canary_stage_duration_seconds; a fully
// successful probe advances secsy_canary_last_success_timestamp_seconds for
// the CA, and any failure increments secsy_canary_failures_total{ca,stage}
// and is dispatched through the expiry monitor's notification sinks
// (log/webhook). Each probe is recorded as a canary.probe audit event, which
// `secsy-ca doctor` reads to surface the last canary outcome offline.
//
// Probe certificates are stamped with models.CertMarkerCanary so the expiry
// monitor's warning/auto-renew storm logic and the inventory/compliance
// reports exclude them. Issuance deliberately goes through the ordinary path
// — including the tenant lifecycle/quota gate and the fail-closed lint gate —
// because the canary's job is to prove exactly what a real caller would
// experience.
//
// The prober is a singleton background job: register it on the leader elector
// so one replica probes at a time.
package canary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// Probe stages, in execution order. StageResolve covers configuration errors
// (a listed CA that cannot be found) so they surface on the same alert path as
// runtime failures.
const (
	StageResolve     = "resolve"
	StageIssue       = "issue"
	StageChain       = "chain"
	StageOCSPGood    = "ocsp_good"
	StageCRL         = "crl"
	StageRevoke      = "revoke"
	StageOCSPRevoked = "ocsp_revoked"
)

// actor is the identity probes run and audit as.
const actor = "canary"

// probeCN / probeDNSName identify probe certificates. The .invalid TLD is
// reserved (RFC 2606) and can never resolve, so a leaked canary certificate is
// useless for impersonating a real host.
const (
	probeCN      = "secsy-canary"
	probeDNSName = "secsy-canary.invalid"
)

// revocationReason is stamped on probe revocations: the certificate's job is
// simply over.
const revocationReason = "cessationOfOperation"

// PKI is the slice of *ca.Manager the prober drives. Every method runs the
// same code paths the API/CLI use, HSM signing included.
type PKI interface {
	IssueCertificate(ctx context.Context, spec ca.IssueSpec) (*ca.IssueResult, error)
	RevokeCertificate(ctx context.Context, caID, serial, reasonName string) (bool, error)
	OCSPRespond(ctx context.Context, caID string, reqDER []byte) ([]byte, error)
	GetBaseCRL(ctx context.Context, caID string, shard int) ([]byte, error)
	CombinedChainPEM(caID string) ([]byte, error)
}

// Store is the read/audit side of the persistence store the prober needs.
// *database.DB satisfies it.
type Store interface {
	GetCA(id string) (*models.CA, error)
	GetCAByLabel(label string) (*models.CA, error)
	GetRevokedCertificate(caID, serial string) (*models.RevokedCertificate, error)
	AppendEvent(e *audit.Event) error
}

// FailureNotifier receives the failed probes of one canary cycle.
// *monitor.Notifier satisfies it.
type FailureNotifier interface {
	NotifyCanaryFailures(ctx context.Context, failures []monitor.CanaryFailure)
}

// StageTiming is one timed probe stage.
type StageTiming struct {
	Stage    string        `json:"stage"`
	Duration time.Duration `json:"duration"`
}

// Result is the outcome of probing one CA.
type Result struct {
	CAID    string `json:"ca_id"`
	CALabel string `json:"ca_label"`
	// Serial is the probe certificate's serial (empty when issuance failed).
	Serial    string        `json:"serial,omitempty"`
	Stages    []StageTiming `json:"stages"`
	StartedAt time.Time     `json:"started_at"`
	Elapsed   time.Duration `json:"elapsed"`
	// FailedStage / Err describe the first failing stage; both are zero on a
	// fully successful probe.
	FailedStage string `json:"failed_stage,omitempty"`
	Err         error  `json:"-"`
}

// OK reports whether every stage of the probe succeeded.
func (r *Result) OK() bool { return r.Err == nil }

// Prober runs synthetic issuance probes against the configured CAs.
type Prober struct {
	pki      PKI
	store    Store
	cfg      config.CanaryConfig
	notifier FailureNotifier
	logger   *log.Logger
}

// New builds a Prober from the application canary config. notifier may be nil
// (failures are then only logged, audited, and counted in metrics).
func New(pki PKI, store Store, cfg config.CanaryConfig, notifier FailureNotifier, logger *log.Logger) (*Prober, error) {
	if pki == nil || store == nil {
		return nil, fmt.Errorf("canary: pki and store are required")
	}
	if len(cfg.CAs) == 0 {
		return nil, fmt.Errorf("canary: at least one CA to probe is required")
	}
	if cfg.Profile == "" {
		cfg.Profile = "canary"
	}
	if _, err := ca.LookupProfile(cfg.Profile); err != nil {
		return nil, fmt.Errorf("canary: profile: %w", err)
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Prober{pki: pki, store: store, cfg: cfg, notifier: notifier, logger: logger}, nil
}

// Run probes immediately, then on every interval tick, until ctx is cancelled.
// It blocks; callers register it as a leader-elected background job.
func (p *Prober) Run(ctx context.Context) {
	p.logger.Printf("issuance canary started (interval=%s, timeout=%s, profile=%s, cas=%s)",
		p.cfg.Interval(), p.cfg.Timeout(), p.cfg.Profile, strings.Join(p.cfg.CAs, ", "))
	p.RunOnce(ctx)

	ticker := time.NewTicker(p.cfg.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.logger.Printf("issuance canary stopped")
			return
		case <-ticker.C:
			p.RunOnce(ctx)
		}
	}
}

// RunOnce probes every configured CA once, records metrics and audit events,
// and dispatches any failures to the notifier. It returns the per-CA results
// (also used by tests).
func (p *Prober) RunOnce(ctx context.Context) []*Result {
	results := make([]*Result, 0, len(p.cfg.CAs))
	var failures []monitor.CanaryFailure

	for _, ref := range p.cfg.CAs {
		if ctx.Err() != nil {
			return results
		}
		res := p.ProbeRef(ctx, ref)
		results = append(results, res)

		if res.OK() {
			metrics.CanaryProbes.Inc(res.CALabel, "success")
			metrics.CanaryLastSuccess.Set(float64(time.Now().Unix()), res.CALabel)
			p.logger.Printf("issuance canary: ca=%s serial=%s ok (%s)", res.CALabel, res.Serial, stageSummary(res.Stages))
		} else {
			metrics.CanaryProbes.Inc(res.CALabel, "error")
			metrics.CanaryFailures.Inc(res.CALabel, res.FailedStage)
			p.logger.Printf("issuance canary: ca=%s FAILED at %s: %v", res.CALabel, res.FailedStage, res.Err)
			failures = append(failures, monitor.CanaryFailure{
				CAID:    res.CAID,
				CALabel: res.CALabel,
				Stage:   res.FailedStage,
				Serial:  res.Serial,
				Error:   res.Err.Error(),
				At:      res.StartedAt,
			})
		}
		p.recordAudit(res)
	}

	if len(failures) > 0 && p.notifier != nil {
		p.notifier.NotifyCanaryFailures(ctx, failures)
	}
	return results
}

// ProbeRef resolves one configured CA reference (id or label) and probes it
// under the configured per-probe timeout.
func (p *Prober) ProbeRef(ctx context.Context, ref string) *Result {
	res := &Result{CALabel: ref, StartedAt: time.Now()}
	var target *models.CA
	if !p.stage(res, StageResolve, func() error {
		t, err := p.resolveCA(ref)
		if err != nil {
			return err
		}
		target = t
		res.CAID, res.CALabel = t.ID, t.Label
		return nil
	}) {
		res.Elapsed = time.Since(res.StartedAt)
		return res
	}

	probeCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout())
	defer cancel()
	p.probe(probeCtx, target, res)
	res.Elapsed = time.Since(res.StartedAt)
	return res
}

// resolveCA looks a configured CA reference up by id first, then by label.
func (p *Prober) resolveCA(ref string) (*models.CA, error) {
	byID, err := p.store.GetCA(ref)
	if err != nil {
		return nil, fmt.Errorf("looking up CA %q: %w", ref, err)
	}
	if byID != nil {
		return byID, nil
	}
	byLabel, err := p.store.GetCAByLabel(ref)
	if err != nil {
		return nil, fmt.Errorf("looking up CA %q by label: %w", ref, err)
	}
	if byLabel == nil {
		return nil, fmt.Errorf("CA %q not found (by id or label)", ref)
	}
	return byLabel, nil
}

// probe walks the full lifecycle stages against one resolved CA, recording
// stage timings and the first failure on res.
func (p *Prober) probe(ctx context.Context, target *models.CA, res *Result) {
	var (
		issued     *ca.IssueResult
		leaf       *x509.Certificate
		issuerID   string // actual issuer after rotation-lineage resolution
		issuerCert *x509.Certificate
		revoked    bool
	)

	// Never leave a valid canary certificate behind: if any stage after
	// issuance fails before the revoke stage ran, revoke it best-effort on a
	// fresh context (the probe context may be the reason the stage failed).
	defer func() {
		if issued == nil || revoked {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := p.pki.RevokeCertificate(cleanupCtx, issuerID, res.Serial, revocationReason); err != nil {
			p.logger.Printf("issuance canary: WARNING: cleanup revocation of serial %s (ca=%s) failed: %v; "+
				"the probe certificate expires on its own within the profile validity", res.Serial, res.CALabel, err)
		}
	}()

	// Stage 1: HSM-backed issuance from the canary profile, through the full
	// ordinary path (tenant gate, lint gate, serial allocation, store record).
	if !p.stage(res, StageIssue, func() error {
		csrPEM, err := newProbeCSR()
		if err != nil {
			return fmt.Errorf("building probe CSR: %w", err)
		}
		r, err := p.pki.IssueCertificate(ctx, ca.IssueSpec{
			CAID:        target.ID,
			CSRPEM:      csrPEM,
			Profile:     p.cfg.Profile,
			RequestedBy: actor,
			Marker:      models.CertMarkerCanary,
		})
		if err != nil {
			return err
		}
		issued = r
		leaf = r.Certificate
		issuerID = r.Record.CAID
		res.Serial = r.Serial.String()
		return nil
	}) {
		return
	}

	// Stage 2: full-chain verification. The combined chain bundle carries the
	// issuing CA, any rotation-overlap siblings, and the ancestors up to (and
	// including) the root — externally signed parents included.
	if !p.stage(res, StageChain, func() error {
		issuerRec, err := p.store.GetCA(issuerID)
		if err != nil {
			return fmt.Errorf("loading issuer CA: %w", err)
		}
		if issuerRec == nil || issuerRec.Certificate == "" {
			return fmt.Errorf("issuer CA %q has no certificate on record", issuerID)
		}
		issuerCert, err = firstCertificate([]byte(issuerRec.Certificate))
		if err != nil {
			return fmt.Errorf("parsing issuer certificate: %w", err)
		}
		bundle, err := p.pki.CombinedChainPEM(issuerID)
		if err != nil {
			return fmt.Errorf("building chain bundle: %w", err)
		}
		return verifyChain(leaf, bundle)
	}) {
		return
	}

	// Stage 3: the OCSP responder must attest "good" for the fresh serial with
	// a correctly signed, fresh response.
	if !p.stage(res, StageOCSPGood, func() error {
		resp, err := p.ocspStatus(ctx, issuerID, leaf, issuerCert)
		if err != nil {
			return err
		}
		if resp.Status != ocsp.Good {
			return fmt.Errorf("OCSP status = %s, want good", ocspStatusName(resp.Status))
		}
		return nil
	}) {
		return
	}

	// Stage 4: the CRL scope covering this serial must be signed by the
	// issuer, fresh, and must not (yet) list the serial.
	if !p.stage(res, StageCRL, func() error {
		return p.checkCRL(ctx, issuerID, issuerCert, issued)
	}) {
		return
	}

	// Stage 5: revoke the probe certificate.
	if !p.stage(res, StageRevoke, func() error {
		applied, err := p.pki.RevokeCertificate(ctx, issuerID, res.Serial, revocationReason)
		if err != nil {
			return err
		}
		if !applied {
			return errors.New("revocation of a fresh serial reported as already applied")
		}
		revoked = true
		return nil
	}) {
		return
	}

	// Stage 6: "revoked" must propagate — authoritative revocation store first,
	// then the OCSP responder's answer.
	p.stage(res, StageOCSPRevoked, func() error {
		rec, err := p.store.GetRevokedCertificate(issuerID, res.Serial)
		if err != nil {
			return fmt.Errorf("reading revocation store: %w", err)
		}
		if rec == nil {
			return errors.New("revocation store has no entry for the revoked serial")
		}
		resp, err := p.ocspStatus(ctx, issuerID, leaf, issuerCert)
		if err != nil {
			return err
		}
		if resp.Status != ocsp.Revoked {
			return fmt.Errorf("OCSP status = %s after revocation, want revoked", ocspStatusName(resp.Status))
		}
		return nil
	})
}

// stage runs fn as the named probe stage, timing it into the stage-duration
// histogram and recording the first failure on res. It returns whether the
// probe should continue.
func (p *Prober) stage(res *Result, name string, fn func() error) bool {
	start := time.Now()
	err := fn()
	d := time.Since(start)
	metrics.CanaryStageDuration.Observe(d.Seconds(), name)
	res.Stages = append(res.Stages, StageTiming{Stage: name, Duration: d})
	if err != nil {
		res.FailedStage = name
		res.Err = fmt.Errorf("%s: %w", name, err)
		return false
	}
	return true
}

// ocspStatus builds a real OCSP request for the leaf, has the responder answer
// it through the same entry point the HTTP handler uses, and parses/verifies
// the signed response.
func (p *Prober) ocspStatus(ctx context.Context, issuerID string, leaf, issuerCert *x509.Certificate) (*ocsp.Response, error) {
	reqDER, err := ocsp.CreateRequest(leaf, issuerCert, nil)
	if err != nil {
		return nil, fmt.Errorf("building OCSP request: %w", err)
	}
	respDER, err := p.pki.OCSPRespond(ctx, issuerID, reqDER)
	if err != nil {
		return nil, fmt.Errorf("OCSP responder: %w", err)
	}
	resp, err := ocsp.ParseResponseForCert(respDER, leaf, issuerCert)
	if err != nil {
		return nil, fmt.Errorf("parsing/verifying OCSP response: %w", err)
	}
	now := time.Now()
	if !resp.NextUpdate.IsZero() && !resp.NextUpdate.After(now) {
		return nil, fmt.Errorf("OCSP response is stale: nextUpdate %s is not in the future", resp.NextUpdate.Format(time.RFC3339))
	}
	if resp.ThisUpdate.After(now.Add(5 * time.Minute)) {
		return nil, fmt.Errorf("OCSP response thisUpdate %s is in the future", resp.ThisUpdate.Format(time.RFC3339))
	}
	return resp, nil
}

// checkCRL fetches the base CRL for the scope the probe serial maps to and
// verifies signature, freshness, and that the fresh serial is not listed.
func (p *Prober) checkCRL(ctx context.Context, issuerID string, issuerCert *x509.Certificate, issued *ca.IssueResult) error {
	shard := ca.ShardForSerial(issued.Serial)
	der, err := p.pki.GetBaseCRL(ctx, issuerID, shard)
	if err != nil {
		return fmt.Errorf("fetching base CRL (shard %d): %w", shard, err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("parsing CRL: %w", err)
	}
	if err := rl.CheckSignatureFrom(issuerCert); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}
	now := time.Now()
	if rl.ThisUpdate.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("CRL thisUpdate %s is in the future", rl.ThisUpdate.Format(time.RFC3339))
	}
	if !rl.NextUpdate.After(now) {
		return fmt.Errorf("CRL is stale: nextUpdate %s is not in the future", rl.NextUpdate.Format(time.RFC3339))
	}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber != nil && e.SerialNumber.Cmp(issued.Serial) == 0 {
			return errors.New("freshly issued probe serial already appears on the CRL")
		}
	}
	return nil
}

// recordAudit appends the canary.probe event for one probe, best-effort.
func (p *Prober) recordAudit(res *Result) {
	result := audit.ResultSuccess
	detail := fmt.Sprintf("profile=%s serial=%s stages=%s", p.cfg.Profile, res.Serial, stageSummary(res.Stages))
	if !res.OK() {
		result = audit.ResultError
		detail += fmt.Sprintf(" failed_stage=%s error=%s", res.FailedStage, res.Err.Error())
	}
	target, targetName := res.CAID, res.CALabel
	if target == "" {
		target = res.CALabel // unresolved reference
	}
	if err := p.store.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "system",
		Action:     audit.ActionCanaryProbe,
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
	}); err != nil {
		p.logger.Printf("issuance canary: WARNING: failed to append canary.probe audit event: %v", err)
	}
}

// stageSummary renders stage timings compactly, e.g.
// "issue:41ms,chain:1ms,ocsp_good:12ms".
func stageSummary(stages []StageTiming) string {
	parts := make([]string, len(stages))
	for i, s := range stages {
		parts[i] = fmt.Sprintf("%s:%s", s.Stage, s.Duration.Round(time.Millisecond))
	}
	return strings.Join(parts, ",")
}

// newProbeCSR generates a fresh ephemeral ECDSA P-256 key and a self-signed
// PKCS#10 CSR for the probe identity. The private key never leaves this
// function: probe certificates are one-shot artifacts, so the key is simply
// discarded.
func newProbeCSR() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating probe key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: probeCN},
		DNSNames: []string{probeDNSName},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("creating probe CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// firstCertificate parses the first CERTIFICATE block in a PEM bundle.
func firstCertificate(pemBytes []byte) (*x509.Certificate, error) {
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// verifyChain verifies the leaf against the CA chain bundle: self-signed
// bundle certificates anchor the roots pool (falling back to the bundle's last
// certificate for externally rooted chains whose root is not distributed), and
// everything else is available as an intermediate.
func verifyChain(leaf *x509.Certificate, bundlePEM []byte) error {
	var certs []*x509.Certificate
	for rest := bundlePEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing chain certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return errors.New("chain bundle contains no certificates")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	haveRoot := false
	for _, c := range certs {
		if isSelfSigned(c) {
			roots.AddCert(c)
			haveRoot = true
		} else {
			intermediates.AddCert(c)
		}
	}
	if !haveRoot {
		// Externally signed deployments may not distribute the third-party
		// root; trust the topmost provided certificate as the anchor.
		roots.AddCert(certs[len(certs)-1])
	}

	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}
	if len(chains) == 0 || len(chains[0]) < 2 {
		return errors.New("chain verification produced no leaf-to-root chain")
	}
	return nil
}

// isSelfSigned reports whether a certificate is its own issuer (a root).
func isSelfSigned(c *x509.Certificate) bool {
	if !c.IsCA || c.CheckSignatureFrom(c) != nil {
		return false
	}
	return true
}

// ocspStatusName renders an OCSP status code for error messages.
func ocspStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return fmt.Sprintf("status(%d)", status)
	}
}
