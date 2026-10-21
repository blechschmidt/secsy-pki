package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// The server ignored SIGTERM, which is how every service manager asks a process
// to stop. These cover the mechanism that replaced the runtime's default
// disposition: a cancelled root context stops the listener, in-flight requests
// are allowed to finish, and a listener that fails on its own is still reported
// as a failure rather than swallowed as a shutdown.

// listening returns an HTTP server on a loopback port, plus its address.
func listening(t *testing.T, h http.Handler) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(ln) }()
	return srv, ln.Addr().String()
}

// A cancelled context stops the server and reports no error: the listener
// stopped because it was asked to, which is a clean exit and must not become a
// non-zero exit status.
func TestServeUntilShutdownReturnsCleanlyOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: 5 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveUntilShutdown(ctx, srv, func() error { return srv.Serve(ln) }) }()

	// Let the listener get going, then ask it to stop.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a requested shutdown reported an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown did not return after its context was cancelled")
	}
}

// An in-flight request finishes. This is the signature that would otherwise be
// cut off at the socket — the client cannot tell a dropped connection from a
// refusal, and on the issuance path that means an issued certificate nobody
// received.
func TestServeUntilShutdownFinishesInFlightRequests(t *testing.T) {
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "finished")
	})

	srv, addr := listening(t, mux)
	// listening already serves; drive the shutdown half over the same server.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(ctx, srv, func() error { <-ctx.Done(); return http.ErrServerClosed })
	}()

	body := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			body <- "error: " + err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			body <- "read error: " + err.Error()
			return
		}
		body <- string(b)
	}()

	<-started
	cancel() // the stop arrives while the request is in the handler

	select {
	case got := <-body:
		if got != "finished" {
			t.Fatalf("the in-flight request got %q, want it to have completed", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight request never completed")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown reported: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown did not return")
	}
}

// A listener that fails on its own is a deployment failure — a bound port, an
// unreadable certificate — and must still reach the operator as one.
func TestServeUntilShutdownReportsAListenerFailure(t *testing.T) {
	srv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: 5 * time.Second}
	want := errors.New("address already in use")

	err := serveUntilShutdown(context.Background(), srv, func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("serveUntilShutdown returned %v, want the listener's own error", err)
	}
}

// Waiting for the background jobs is bounded: a job that will not stop must not
// turn a stop into a SIGKILL, because the container runtime's patience is what
// runs out next.
func TestWaitForBackgroundJobsIsBounded(t *testing.T) {
	done := make(chan struct{})
	start := time.Now()
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(done)
	}()
	waitForBackgroundJobs(done)
	if elapsed := time.Since(start); elapsed > jobShutdownGrace {
		t.Fatalf("waiting for a job that stopped took %s", elapsed)
	}
}
