package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

// Graceful shutdown.
//
// systemd and podman stop a service with SIGTERM, which this process did not
// handle at all: the Go runtime's default disposition killed it outright. A
// `podman stop` therefore ended the server in well under a second, with no
// shutdown output, no cleanup, and in particular:
//
//   - the HSM audit collection lease left held, so the next process that has to
//     drain the device — `hsm-audit export`, `collect`, `timestamp`, `commit` —
//     waited its full 30 seconds and failed, and kept failing until the lease
//     expired a minute after the stop;
//   - the embedded YubiHSM connector's device claim dropped mid-relay, which is
//     exactly what Embedded.Close exists to avoid ("waits for in-flight relays,
//     which is what keeps a command from being cut in half between the device
//     and its client");
//   - in-flight HTTP requests — signatures, issuance — cut off rather than
//     finished;
//   - a Unix-socket deployment leaving its socket file behind.
//
// None of that is specific to containers; it is simply what a process that
// ignores SIGTERM does. The fix is the ordinary shape: one root context
// cancelled by the signal, a graceful HTTP shutdown, then waiting for the
// leader-elected jobs to stop before main returns and its deferred cleanup runs.
//
// The order matters and is the reason this is spelled out rather than left to
// defers. The listeners stop first, so nothing new arrives; the background jobs
// stop next, which is where the lease is released; the database, the key
// provider and the device claim are released last, by main's defers, once
// nothing can still be using them.

const (
	// httpShutdownGrace bounds how long in-flight requests have to finish.
	//
	// It is comfortably under the 10 seconds `docker stop` and `podman stop`
	// allow by default, because a stop that overruns is a SIGKILL — which is the
	// ungraceful exit this whole file exists to avoid. The slowest legitimate
	// request is an RSA-4096 generation on a YubiHSM, tens of seconds, and that
	// one is better cut off than the stop turned into a kill: the device log
	// entry it left is on the device, where the next drain collects it.
	httpShutdownGrace = 8 * time.Second

	// jobShutdownGrace bounds how long the leader-elected background jobs have
	// to notice cancellation and return. The collector is the one that matters:
	// its cycle is three device round trips and it releases the collection lease
	// in a defer, on a context of its own so a cancelled shutdown still frees it.
	jobShutdownGrace = 10 * time.Second
)

// rootContext returns a context cancelled by SIGINT or SIGTERM, and the
// function that releases the signal handlers.
//
// Those two and no others. SIGINT is the foreground run; SIGTERM is every
// service manager. SIGHUP is left out on purpose — it conventionally means
// "re-read your configuration", and a process that silently treated it as a
// stop would be a trap for whoever sent it meaning the other thing.
func rootContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// serveUntilShutdown runs start — one of the blocking http.Server methods — and
// returns when either it stops on its own or ctx is cancelled, in which case the
// server is shut down gracefully first.
//
// A nil error means the listener stopped because it was asked to. Anything else
// is a listener that failed, which is fatal to the deployment and is the
// caller's to report.
func serveUntilShutdown(ctx context.Context, srv *http.Server, start func() error) error {
	errs := make(chan error, 1)
	go func() { errs <- start() }()

	select {
	case err := <-errs:
		// The listener gave up on its own: a port already bound, a certificate
		// that cannot be loaded, a socket pulled out from under it.
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	log.Printf("Shutting down: stopping the listener and finishing in-flight requests (up to %s)", httpShutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Report it and carry on with the rest of the shutdown: a request that
		// outran the grace period is worth a line, and is no reason to skip
		// releasing the collection lease and the device.
		log.Printf("WARNING: HTTP shutdown did not complete within %s: %v", httpShutdownGrace, err)
	}
	// Serve returns ErrServerClosed once Shutdown has run; draining it keeps the
	// goroutine from outliving this function with a send nobody receives.
	<-errs
	return nil
}

// waitForBackgroundJobs waits for the leader elector to stop its jobs and hand
// back its lock.
//
// This is where the HSM audit collection lease is released: the collector holds
// it for the length of a cycle and frees it in a defer, so a process that exits
// without letting that defer run leaves the lease held for its full TTL —
// which is what made an operator's `hsm-audit export` fail for a minute after
// every restart.
func waitForBackgroundJobs(done <-chan struct{}) {
	select {
	case <-done:
		log.Printf("Background jobs stopped")
	case <-time.After(jobShutdownGrace):
		log.Printf("WARNING: background jobs did not stop within %s; exiting anyway", jobShutdownGrace)
	}
}
