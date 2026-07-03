package handlers

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// readinessTimeout bounds how long the readiness probe waits on its
// dependencies (database, HSM) before declaring them unready. It must be short
// enough that a load balancer's probe does not hang.
const readinessTimeout = 3 * time.Second

// RegisterObservability mounts the operational endpoints — Prometheus metrics,
// liveness, and readiness — directly on the mux. They are intentionally
// unauthenticated: they expose no secrets or key material, and monitoring
// systems (Prometheus, Kubernetes kubelet, load balancers) scrape them before
// any user context exists. Restrict access at the network layer if desired.
func (a *API) RegisterObservability(mux *http.ServeMux) {
	mux.HandleFunc("GET /metrics", a.Metrics)
	mux.HandleFunc("GET /healthz", a.Healthz)
	mux.HandleFunc("GET /readyz", a.Readyz)
}

// Metrics serves the process's metrics in the Prometheus text exposition
// format.
func (a *API) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", metrics.ContentType)
	metrics.Default.WriteTo(w)
}

// buildVersion is the release version stamped by the linker (-X main.version)
// and installed via SetBuildVersion at startup; "dev" when unstamped.
var buildVersion = "dev"

// SetBuildVersion installs the binary's release version for the /healthz build
// block. Called once from main before serving; an empty value keeps "dev".
func SetBuildVersion(v string) {
	if v != "" {
		buildVersion = v
	}
}

// buildInfo assembles the /healthz "build" block: release version, Go runtime,
// and the FIPS 140-3 posture — whether the Go Cryptographic Module is active
// (fips140), which frozen module snapshot the binary was built against
// (fips140_module, empty for non-FIPS builds), and whether the fail-closed
// security.fips algorithm policy is enforced (fips140_policy).
func buildInfo() map[string]string {
	module := "off"
	if fips.ModuleEnabled() {
		module = "on"
	}
	policy := "off"
	if fips.PolicyEnforced() {
		policy = "enforced"
	}
	return map[string]string{
		"version":        buildVersion,
		"go":             runtime.Version(),
		"fips140":        module,
		"fips140_module": fips.ModuleVersion(),
		"fips140_policy": policy,
	}
}

// Healthz is the liveness probe. It reports that the process is running and able
// to serve HTTP; it deliberately does NOT check external dependencies, so a
// transient database or HSM outage does not cause an orchestrator to kill and
// restart an otherwise-healthy process (that is the readiness probe's job).
// The build block identifies the running binary (version, Go, FIPS mode) so
// operators can verify a FIPS deployment from the endpoint alone.
func (a *API) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"build":  buildInfo(),
	})
}

// componentStatus is the per-dependency result reported by the readiness probe.
type componentStatus struct {
	Status string `json:"status"`           // "up" | "down" | "skipped" | "leader" | "follower"
	Error  string `json:"error,omitempty"`  // present when Status == "down"
	Detail string `json:"detail,omitempty"` // extra context, e.g. the election mode
}

// Readyz is the readiness probe. It verifies the process can actually serve
// requests by checking its critical dependencies: the database and — via the
// key-provider's connectivity probe — the HSM. It returns 200 only when every
// checked dependency is healthy, otherwise 503, so a load balancer stops
// sending traffic to an instance that cannot issue certificates.
func (a *API) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	components := make(map[string]componentStatus, 2)
	ready := true

	// Database connectivity.
	if err := a.db.Ping(ctx); err != nil {
		components["database"] = componentStatus{Status: "down", Error: err.Error()}
		metrics.Up.Set(0, "database")
		ready = false
	} else {
		components["database"] = componentStatus{Status: "up"}
		metrics.Up.Set(1, "database")
	}

	// HSM / key-provider connectivity. Not every provider supports probing; a
	// provider that does not is reported as "skipped" and does not fail
	// readiness (there is nothing we can assert about it).
	components["hsm"] = a.probeKeyProvider(ctx, &ready)

	// Background-job leadership (Task 68). Informational only: a follower is
	// fully ready to serve traffic (the singleton jobs run on the leader), so
	// leadership never fails readiness — it is surfaced here so operators can
	// identify the job-running replica from the probe they already watch.
	if a.leaderInfo != nil {
		st := "follower"
		if a.leaderInfo.IsLeader() {
			st = "leader"
		}
		components["leadership"] = componentStatus{Status: st, Detail: "mode=" + a.leaderInfo.Mode()}
	}

	status := http.StatusOK
	overall := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		overall = "not_ready"
	}
	writeJSON(w, status, map[string]any{
		"status":     overall,
		"components": components,
	})
}

// probeKeyProvider runs the key-provider connectivity probe, updates the
// component "up" gauge, and clears the ready flag on failure. A provider that
// does not implement Prober is reported as skipped without affecting readiness.
func (a *API) probeKeyProvider(ctx context.Context, ready *bool) componentStatus {
	prober, ok := a.keyProvider.(keyprovider.Prober)
	if !ok {
		return componentStatus{Status: "skipped"}
	}
	err := prober.Ping(ctx)
	if err == nil {
		metrics.Up.Set(1, "hsm")
		return componentStatus{Status: "up"}
	}
	if errors.Is(err, keyprovider.ErrProbeUnsupported) {
		return componentStatus{Status: "skipped"}
	}
	metrics.Up.Set(0, "hsm")
	*ready = false
	return componentStatus{Status: "down", Error: err.Error()}
}
