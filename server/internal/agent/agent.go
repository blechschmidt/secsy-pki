package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Agent evaluates and renews the configured certificates. It is safe to drive
// from a single goroutine (the CLI's run/once/status commands).
type Agent struct {
	cfg        *Config
	httpClient *http.Client
	acme       *acmeClient
	est        *estClient
	state      *agentState
	metrics    *agentMetrics

	trust *trustBundle // cached URL bundle

	// now is the agent's clock; tests inject a fake one to force renewals.
	now func() time.Time
}

// New builds an Agent from a validated configuration, creating the state
// directory on first use.
func New(cfg *Config) (*Agent, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state_dir: %w", err)
	}
	state, err := loadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(cfg.Server)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg:        cfg,
		httpClient: httpClient,
		state:      state,
		metrics:    newAgentMetrics(),
		now:        time.Now,
	}
	if cfg.ACME.Directory != "" {
		a.acme = newACMEClient(cfg.ACME, cfg.StateDir, httpClient)
	}
	if cfg.EST.URL != "" {
		a.est, err = newESTClient(cfg.EST, httpClient)
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

// SetClock overrides the agent's time source (used by tests to force
// renewals without waiting out certificate lifetimes).
func (a *Agent) SetClock(now func() time.Time) { a.now = now }

// Close releases pass-scoped resources (the http-01 listener) and persists
// state.
func (a *Agent) Close() error {
	if a.acme != nil {
		a.acme.closeSolver()
	}
	return a.state.save()
}

// CertOutcome describes what one pass did for one certificate.
type CertOutcome struct {
	Name string `json:"name"`
	// Action is "renewed", "fresh" (nothing to do), "failed", or "backoff"
	// (due, but suppressed by failure backoff in daemon mode).
	Action string `json:"action"`
	// Reason explains a renewal or failure.
	Reason string `json:"reason,omitempty"`
	// RenewAt is the planned renewal moment for fresh certificates.
	RenewAt *time.Time `json:"renew_at,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// Report summarizes one agent pass.
type Report struct {
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Outcomes   []CertOutcome `json:"certificates"`
}

// Renewed lists the certificates installed during the pass.
func (r *Report) Renewed() []string { return r.byAction("renewed") }

// Failed lists the certificates whose renewal failed.
func (r *Report) Failed() []string { return r.byAction("failed") }

func (r *Report) byAction(action string) []string {
	var out []string
	for _, o := range r.Outcomes {
		if o.Action == action {
			out = append(out, o.Name)
		}
	}
	return out
}

// RunOnce performs a single evaluation/renewal pass over every configured
// certificate (the `secsy-agent once` command). Renewals due are always
// attempted, ignoring daemon backoff.
func (a *Agent) RunOnce(ctx context.Context) (*Report, error) {
	defer a.acmeSolverClose()
	report := a.pass(ctx, true)
	if err := a.state.save(); err != nil {
		return report, err
	}
	return report, nil
}

// Run is the daemon loop: an immediate pass, then one every check_interval
// until ctx is cancelled. The optional metrics listener runs for the daemon's
// lifetime.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.Metrics.Listen != "" {
		if err := a.metrics.serve(ctx, a.cfg.Metrics.Listen); err != nil {
			return err
		}
	}
	log.Printf("agent: starting; %d certificate(s), check interval %s", len(a.cfg.Certificates), a.cfg.Renewal.CheckInterval.Std())
	ticker := time.NewTicker(a.cfg.Renewal.CheckInterval.Std())
	defer ticker.Stop()
	for {
		a.pass(ctx, false)
		a.acmeSolverClose()
		if err := a.state.save(); err != nil {
			log.Printf("agent: saving state: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (a *Agent) acmeSolverClose() {
	if a.acme != nil {
		a.acme.closeSolver()
	}
}

// pass evaluates every spec and renews what is due. force bypasses failure
// backoff (used by `once`).
func (a *Agent) pass(ctx context.Context, force bool) *Report {
	report := &Report{StartedAt: a.now()}
	for _, spec := range a.cfg.Certificates {
		outcome := a.processSpec(ctx, spec, force)
		report.Outcomes = append(report.Outcomes, outcome)
	}
	report.FinishedAt = a.now()
	if err := a.metrics.finishPass(a.cfg.Metrics.Textfile, report.FinishedAt); err != nil {
		log.Printf("agent: %v", err)
	}
	return report
}

// processSpec evaluates one spec and, when due, renews it.
func (a *Agent) processSpec(ctx context.Context, spec *CertSpec, force bool) CertOutcome {
	now := a.now()
	st := a.state.cert(spec.Name)
	dec := a.evaluate(ctx, spec, now, false)

	if !dec.due {
		inst, _ := a.loadInstalled(spec)
		a.metrics.observe(spec.Name, inst, dec.renewAt, st, true)
		renewAt := dec.renewAt
		return CertOutcome{Name: spec.Name, Action: "fresh", RenewAt: &renewAt}
	}

	if !force && !st.NextAttempt.IsZero() && now.Before(st.NextAttempt) {
		inst, _ := a.loadInstalled(spec)
		a.metrics.observe(spec.Name, inst, time.Time{}, st, false)
		return CertOutcome{
			Name:   spec.Name,
			Action: "backoff",
			Reason: fmt.Sprintf("%s; retrying after %s (%d consecutive failures)", dec.reason, st.NextAttempt.Format(time.RFC3339), st.ConsecutiveFailures),
		}
	}

	log.Printf("agent: %s: renewing (%s)", spec.Name, dec.reason)
	st.LastAttempt = now
	a.state.dirty = true
	leafSerial, err := a.renew(ctx, spec, st, now)
	if err != nil {
		st.ConsecutiveFailures++
		st.LastOutcome = "failed"
		st.LastError = err.Error()
		st.NextAttempt = now.Add(backoffDelay(a.cfg.Renewal.CheckInterval.Std(), st.ConsecutiveFailures))
		a.state.dirty = true
		inst, _ := a.loadInstalled(spec)
		a.metrics.observe(spec.Name, inst, time.Time{}, st, false)
		log.Printf("agent: %s: renewal failed: %v", spec.Name, err)
		return CertOutcome{Name: spec.Name, Action: "failed", Reason: dec.reason, Error: err.Error()}
	}

	st.Serial = leafSerial
	st.EnrolledVia = spec.Enroll
	st.ARI = nil // the cached window belonged to the replaced certificate
	st.LastRenewal = now
	st.LastOutcome = "renewed"
	st.LastError = ""
	st.ConsecutiveFailures = 0
	st.NextAttempt = time.Time{}
	a.state.dirty = true

	inst, _ := a.loadInstalled(spec)
	next := a.evaluate(ctx, spec, a.now(), true)
	a.metrics.observe(spec.Name, inst, next.renewAt, st, true)
	log.Printf("agent: %s: renewed (serial %s)", spec.Name, leafSerial)
	return CertOutcome{Name: spec.Name, Action: "renewed", Reason: dec.reason}
}

// backoffDelay grows exponentially from the check interval, capped at an
// hour, so a persistently failing enrollment cannot hammer the server.
func backoffDelay(base time.Duration, failures int) time.Duration {
	if base <= 0 {
		base = time.Minute
	}
	delay := base
	for i := 1; i < failures && delay < time.Hour; i++ {
		delay *= 2
	}
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay
}

// renew generates a fresh local key, enrolls it over the spec's protocol,
// verifies the returned chain against the trust bundle, and installs it
// atomically. It returns the new leaf's serial.
func (a *Agent) renew(ctx context.Context, spec *CertSpec, st *certState, now time.Time) (string, error) {
	bundle, err := a.trustBundle(ctx)
	if err != nil {
		return "", err
	}
	key, err := generateKey(spec)
	if err != nil {
		return "", err
	}
	csrDER, err := buildCSR(spec, key)
	if err != nil {
		return "", err
	}
	certs, err := a.enroll(ctx, spec, csrDER, now)
	if err != nil {
		return "", err
	}
	res, err := a.install(spec, key, certs, bundle, now)
	if err != nil {
		return "", err
	}
	return res.leaf.SerialNumber.String(), nil
}

// enroll dispatches to the spec's enrollment protocol.
func (a *Agent) enroll(ctx context.Context, spec *CertSpec, csrDER []byte, now time.Time) ([]*x509.Certificate, error) {
	switch spec.Enroll {
	case EnrollACME:
		if a.acme == nil {
			return nil, fmt.Errorf("acme is not configured")
		}
		return a.acme.Enroll(ctx, spec, csrDER, now)
	case EnrollEST:
		if a.est == nil {
			return nil, fmt.Errorf("est is not configured")
		}
		var clientCert *tls.Certificate
		reenroll := false
		if inst, _ := a.loadInstalled(spec); inst != nil && now.Before(inst.leaf.NotAfter) {
			reenroll = true
			clientCert = &tls.Certificate{Certificate: [][]byte{inst.leaf.Raw}, PrivateKey: inst.key}
		}
		return a.est.Enroll(ctx, csrDER, reenroll, clientCert)
	default:
		return nil, fmt.Errorf("unknown enrollment protocol %q", spec.Enroll)
	}
}

// trustBundle returns the verification anchors, re-fetching URL bundles when
// stale and falling back to the cached copy on transient fetch errors.
func (a *Agent) trustBundle(ctx context.Context) (*trustBundle, error) {
	if a.cfg.Trust.BundleFile != "" {
		return a.loadTrustBundle(ctx)
	}
	now := a.now()
	if a.trust != nil && now.Before(a.trust.fetchedAt.Add(a.cfg.Trust.RefreshInterval.Std())) {
		return a.trust, nil
	}
	bundle, err := a.loadTrustBundle(ctx)
	if err != nil {
		if a.trust != nil {
			log.Printf("agent: trust bundle refresh failed, using cached copy: %v", err)
			return a.trust, nil
		}
		return nil, err
	}
	a.trust = bundle
	return bundle, nil
}

// ---- status ----

// CertStatus is one certificate's entry in the status report.
type CertStatus struct {
	Name        string     `json:"name"`
	Enroll      string     `json:"enroll"`
	Present     bool       `json:"present"`
	Serial      string     `json:"serial,omitempty"`
	Subject     string     `json:"subject,omitempty"`
	SANs        []string   `json:"sans,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Due         bool       `json:"due"`
	Reason      string     `json:"reason,omitempty"`
	RenewAt     *time.Time `json:"renew_at,omitempty"`
	RenewSource string     `json:"renew_source,omitempty"`
	LastRenewal *time.Time `json:"last_renewal,omitempty"`
	LastOutcome string     `json:"last_outcome,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	KeyFile     string     `json:"key_file"`
	CertFile    string     `json:"cert_file"`
}

// StatusReport is the `secsy-agent status` JSON document.
type StatusReport struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	StateDir     string       `json:"state_dir"`
	Certificates []CertStatus `json:"certificates"`
}

// Status inspects tracked certificates without touching the network (cached
// ARI windows are used when fresh; otherwise the lifetime fraction is shown).
func (a *Agent) Status() *StatusReport {
	now := a.now()
	report := &StatusReport{GeneratedAt: now, StateDir: a.cfg.StateDir}
	for _, spec := range a.cfg.Certificates {
		st := a.state.cert(spec.Name)
		cs := CertStatus{
			Name:     spec.Name,
			Enroll:   spec.Enroll,
			KeyFile:  spec.KeyFile,
			CertFile: spec.CertFile,
		}
		if inst, _ := a.loadInstalled(spec); inst != nil {
			cs.Present = true
			cs.Serial = inst.leaf.SerialNumber.String()
			cs.Subject = inst.leaf.Subject.String()
			cs.SANs = certSANs(inst.leaf)
			nb, na := inst.leaf.NotBefore, inst.leaf.NotAfter
			cs.NotBefore, cs.NotAfter = &nb, &na
		}
		dec := a.evaluate(context.Background(), spec, now, true)
		cs.Due = dec.due
		cs.Reason = dec.reason
		cs.RenewSource = dec.source
		if !dec.renewAt.IsZero() {
			t := dec.renewAt
			cs.RenewAt = &t
		}
		if !st.LastRenewal.IsZero() {
			t := st.LastRenewal
			cs.LastRenewal = &t
		}
		cs.LastOutcome = st.LastOutcome
		cs.LastError = st.LastError
		report.Certificates = append(report.Certificates, cs)
	}
	return report
}

// certSANs renders a certificate's SANs in canonical order.
func certSANs(leaf *x509.Certificate) []string {
	var out []string
	for _, d := range leaf.DNSNames {
		out = append(out, "dns:"+strings.ToLower(d))
	}
	for _, ip := range leaf.IPAddresses {
		out = append(out, "ip:"+ip.String())
	}
	sort.Strings(out)
	return out
}
