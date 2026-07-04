package main

import (
	"log"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/profiling"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// setupPProf wires the opt-in net/http/pprof runtime-profiling endpoints
// (Task 115). It is a no-op unless server.pprof.enabled is set, and it never
// exposes profiling unauthenticated:
//
//   - mode "loopback" (default): a dedicated HTTP listener bound to a loopback
//     address (server.pprof.address, default 127.0.0.1:6060), reachable only from
//     the host itself (SSH tunnel / kubectl port-forward). The address is
//     validated as loopback at config load, so this listener can never bind a
//     routable interface. Access control is the loopback bind.
//   - mode "authenticated": /debug/pprof/ is mounted on the main API listener,
//     behind operator authentication (authMw.Authenticate) AND the admin-only
//     server:profile capability. A profile is a raw dump of process memory and
//     goroutine stacks — it can contain in-flight secrets — so the capability
//     gate is deliberately as strict as HSM administration.
//
// The mutex and block profilers are enabled here when configured (they are off in
// the runtime by default because they add overhead); they are the levers for
// diagnosing PKCS#11 session-pool contention and goroutines blocked waiting on an
// HSM session.
func setupPProf(cfg *config.Config, authMw *middleware.AuthMiddleware, api *handlers.API, mux *http.ServeMux) {
	pc := cfg.Server.PProf
	if !pc.Enabled {
		return
	}

	// Enable the mutex/block profilers if requested (no-op for non-positive
	// values). CPU/heap/goroutine/allocs need no such enabling.
	profiling.EnableRuntimeProfilers(pc.MutexProfileFraction, pc.BlockProfileRate)

	handler := profiling.Handler()

	switch pc.ResolvedMode() {
	case config.PProfModeAuthenticated:
		// Mount on the main mux behind auth + the server:profile capability.
		// Authenticate runs first (resolving the principal into the request
		// context); AccessControlled then enforces the capability and never falls
		// through on denial.
		//
		// The routes are registered per-method (GET for every profile, POST for
		// `go tool pprof`'s symbol calls) rather than as a single method-agnostic
		// "/debug/pprof/". A method-agnostic pattern conflicts with the app's
		// "GET /" static catch-all under Go 1.22+ ServeMux precedence (neither is
		// more specific), which panics at startup; "GET /debug/pprof/" is a strict
		// subset of "GET /", so it composes cleanly, and no "POST /" catch-all
		// exists for "POST /debug/pprof/" to collide with.
		gated := authMw.Authenticate(profiling.AccessControlled(handler, func(r *http.Request) bool {
			return api.Can(middleware.GetUserInfo(r.Context()), rbac.ActionProfile)
		}))
		mux.Handle("GET /debug/pprof/", gated)
		mux.Handle("POST /debug/pprof/", gated)
		log.Printf("pprof profiling enabled on the API listener at /debug/pprof/ "+
			"(operator auth + %q capability required)", rbac.ActionProfile)

	default: // config.PProfModeLoopback (validated at config load)
		addr := pc.ResolvedAddress()
		srv := &http.Server{
			Addr:    addr,
			Handler: handler,
			// Bound the header read (slowloris) but leave read/write unbounded so a
			// long CPU profile or execution trace (?seconds=N) is not cut off.
			ReadHeaderTimeout: 10 * time.Second,
		}
		// Auxiliary listener: a bind failure must not take down the PKI, so log it
		// rather than crash. The core server keeps serving without profiling.
		go func() {
			log.Printf("pprof profiling enabled on dedicated loopback listener http://%s/debug/pprof/ "+
				"(loopback-only; reach it via an SSH tunnel or `kubectl port-forward`)", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("WARNING: pprof loopback listener on %s stopped: %v", addr, err)
			}
		}()
	}

	if pc.MutexProfileFraction > 0 || pc.BlockProfileRate > 0 {
		log.Printf("pprof runtime profilers: mutex_fraction=%d block_rate=%d",
			pc.MutexProfileFraction, pc.BlockProfileRate)
	}
}
