// Package profiling provides opt-in, access-controlled net/http/pprof runtime
// profiling for the server (Task 115).
//
// The endpoints are OFF by default. When enabled they are never exposed
// unauthenticated: the caller (cmd/server) either binds Handler() to a dedicated
// loopback-only listener, or mounts AccessControlled(Handler(), …) on the main
// API listener behind operator authentication plus the admin-only server:profile
// capability. Either way a profile — which is a raw dump of process memory and
// goroutine stacks and can contain in-flight secrets, CSRs, and session material
// — never leaves the process to an anonymous caller on a routable interface.
//
// This package holds the reusable, dependency-light pieces so the gating is unit
// testable in isolation: the pprof handler set, the access-control wrapper, and
// the runtime mutex/block profiler toggles. The wiring (config → listener/mount)
// lives in cmd/server.
package profiling

import (
	"net/http"
	"net/http/pprof"
	"runtime"
)

// Handler returns an http.Handler exposing the standard net/http/pprof endpoints
// under /debug/pprof/. It builds a DEDICATED mux and mounts it only where the
// caller asks (a loopback listener or, gated, the API mux).
//
// Note: importing net/http/pprof also registers these routes on
// http.DefaultServeMux via that package's init — this is unavoidable when using
// the stdlib pprof handlers. It is harmless here because the server never serves
// http.DefaultServeMux (it serves its own middleware-wrapped mux), so profiling
// is reachable ONLY through the access-controlled paths this package sets up.
//
// The registered set covers every profile an operator needs for HSM-latency and
// session-pool debugging:
//
//	/debug/pprof/            index; also serves the named profiles below
//	/debug/pprof/heap        heap allocations (in-use / allocated)
//	/debug/pprof/goroutine   all current goroutine stacks
//	/debug/pprof/allocs      past memory allocations
//	/debug/pprof/mutex       lock contention (needs SetMutexProfileFraction > 0)
//	/debug/pprof/block       blocking events (needs SetBlockProfileRate > 0)
//	/debug/pprof/threadcreate OS-thread creation
//	/debug/pprof/profile     CPU profile (?seconds=N)
//	/debug/pprof/trace       execution trace (?seconds=N)
//	/debug/pprof/cmdline     the process command line
//	/debug/pprof/symbol      symbol lookup
//
// pprof.Index serves both the index page and the named profiles under
// /debug/pprof/<name>, so heap/goroutine/allocs/mutex/block/threadcreate need no
// explicit route.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// AccessControlled wraps h so a request is served only when authorized reports
// true; otherwise it responds 403 Forbidden and h is never reached. It assumes an
// authentication layer has already run ahead of it and populated whatever
// authorized inspects (typically the resolved principal in the request context),
// so this package stays free of the auth/rbac packages and remains unit testable.
//
// Fail closed: a nil authorizer denies everything (the safe default if the caller
// forgot to wire the capability check), and any false/denied result is a hard
// 403 with no fall-through — a profiler must never be reachable by an
// unauthorized caller.
func AccessControlled(h http.Handler, authorized func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authorized == nil || !authorized(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: profiling requires the server:profile capability"}`))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// EnableRuntimeProfilers turns on the mutex and block profilers, which the Go
// runtime keeps off by default because they add per-event overhead. A
// non-positive value leaves the corresponding profiler disabled. It is safe to
// call once at startup; the CPU, heap, goroutine, and allocs profiles need no
// such enabling.
//
//   - mutexFraction: runtime.SetMutexProfileFraction — 1 samples every mutex
//     contention event, N samples 1/N. Needed for /debug/pprof/mutex to have data.
//   - blockRateNanos: runtime.SetBlockProfileRate — a blocking event lasting at
//     least this many nanoseconds is sampled. Needed for /debug/pprof/block.
func EnableRuntimeProfilers(mutexFraction, blockRateNanos int) {
	if mutexFraction > 0 {
		runtime.SetMutexProfileFraction(mutexFraction)
	}
	if blockRateNanos > 0 {
		runtime.SetBlockProfileRate(blockRateNanos)
	}
}
