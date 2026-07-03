package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// agentMetrics exposes the agent's certificate posture for Prometheus, both as
// a node_exporter textfile and over an optional /metrics listener. All series
// are gauges (textfiles are re-written wholesale, and counters would reset on
// every agent restart anyway).
type agentMetrics struct {
	registry *metrics.Registry

	notAfter    *metrics.Gauge
	notBefore   *metrics.Gauge
	renewAt     *metrics.Gauge
	present     *metrics.Gauge
	lastSuccess *metrics.Gauge
	lastRenewal *metrics.Gauge
	lastRun     *metrics.Gauge
}

func newAgentMetrics() *agentMetrics {
	r := metrics.NewRegistry()
	return &agentMetrics{
		registry: r,
		notAfter: metrics.NewGauge(r, "secsy_agent_certificate_not_after_seconds",
			"Expiry (Unix seconds) of the installed certificate.", "certificate"),
		notBefore: metrics.NewGauge(r, "secsy_agent_certificate_not_before_seconds",
			"Start of validity (Unix seconds) of the installed certificate.", "certificate"),
		renewAt: metrics.NewGauge(r, "secsy_agent_certificate_renewal_time_seconds",
			"Planned renewal moment (Unix seconds); 0 while renewal is due or pending.", "certificate"),
		present: metrics.NewGauge(r, "secsy_agent_certificate_present",
			"1 when key and certificate are installed and consistent.", "certificate"),
		lastSuccess: metrics.NewGauge(r, "secsy_agent_certificate_last_success",
			"1 when the certificate's most recent evaluation succeeded, 0 after an error.", "certificate"),
		lastRenewal: metrics.NewGauge(r, "secsy_agent_certificate_last_renewal_seconds",
			"When the certificate was last renewed/installed (Unix seconds); 0 if never in this state file.", "certificate"),
		lastRun: metrics.NewGauge(r, "secsy_agent_last_run_seconds",
			"When the agent last completed a pass (Unix seconds)."),
	}
}

// observe records one spec's posture after an evaluation or renewal.
func (m *agentMetrics) observe(name string, inst *installedCert, renewAt time.Time, st *certState, ok bool) {
	if inst != nil {
		m.present.Set(1, name)
		m.notAfter.Set(float64(inst.leaf.NotAfter.Unix()), name)
		m.notBefore.Set(float64(inst.leaf.NotBefore.Unix()), name)
	} else {
		m.present.Set(0, name)
		m.notAfter.Set(0, name)
		m.notBefore.Set(0, name)
	}
	if renewAt.IsZero() {
		m.renewAt.Set(0, name)
	} else {
		m.renewAt.Set(float64(renewAt.Unix()), name)
	}
	if ok {
		m.lastSuccess.Set(1, name)
	} else {
		m.lastSuccess.Set(0, name)
	}
	if st != nil && !st.LastRenewal.IsZero() {
		m.lastRenewal.Set(float64(st.LastRenewal.Unix()), name)
	} else {
		m.lastRenewal.Set(0, name)
	}
}

// finishPass stamps the pass completion time and rewrites the textfile.
func (m *agentMetrics) finishPass(textfile string, now time.Time) error {
	m.lastRun.Set(float64(now.Unix()))
	if textfile == "" {
		return nil
	}
	var b strings.Builder
	if _, err := m.registry.WriteTo(&b); err != nil {
		return fmt.Errorf("rendering metrics: %w", err)
	}
	// Atomic rename so the node_exporter textfile collector never reads a
	// half-written file.
	if err := writeFileAtomic(textfile, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing metrics textfile: %w", err)
	}
	return nil
}

// serve exposes /metrics on addr until ctx is done. Errors after a successful
// bind are logged, not fatal: metrics must never take down renewals.
func (m *agentMetrics) serve(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("binding metrics listener on %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", metrics.ContentType)
		m.registry.WriteTo(w) //nolint:errcheck
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx) //nolint:errcheck
	}()
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("agent: metrics listener: %v", err)
		}
	}()
	return nil
}
