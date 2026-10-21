package yubihsm

import (
	"context"
	"sync/atomic"
)

// Every command this driver sends to a force-audited YubiHSM may leave a record
// in the device's 62-entry log ring, and that ring is self-limiting: once 62
// entries accumulate unacknowledged the device stops serving auditable commands
// altogether. (The entries themselves are kept in the device's non-volatile Log
// Store and do survive a power cycle — Yubico's own description — so what a
// drain races is the ring filling, not a power cut.) Collecting them is
// therefore not housekeeping but a liveness requirement, and it has to follow
// the operations rather than a clock.
//
// The signing path already announces itself: everything the product signs with
// goes through internal/keyprovider, whose recording wrapper notifies the audit
// collector after each operation (Task 181). But the signing path is not the
// only path to the device. Key attestation, device attestation, audit-head
// commitments, option provisioning and the scratch keys those create all reach
// the hardware through *this* driver instead, and none of them passes a key
// provider. On a force-audited device each of them writes log entries that
// nothing would then drain — so a deployment that mostly ran attestations and
// rarely signed could wedge its own HSM while every provider-level operation
// looked perfectly accounted for.
//
// The observer closes that: send() is the single point every in-session command
// passes through, so a hook there covers each of those paths at once, including
// ones added later that never heard of the audit subsystem.

// commandObserver is the process-wide hook, nil unless a collector installed
// one. It is package-level rather than per-client because the callers that need
// covering — hsmattest, hsmaudit, hsm — each open their own short-lived client
// for one operation, so a per-client setter would have to be threaded through
// every one of those call sites and would be silently forgotten by the next.
var commandObserver atomic.Pointer[func(cmd byte)]

// SetCommandObserver installs fn, called after every command sent inside a
// secure channel, with that command's code. Passing nil removes the hook.
//
// fn must not block, must not fail, and must not itself issue device commands:
// it runs inline on the command path, holding the client's lock, so anything
// slower than a channel send stalls the operation that triggered it. The
// intended implementation is Collector.Notify, which drops a token into a
// buffered channel and returns.
//
// The hook does not fire for the three commands the collector's own drain
// issues — GET DEVICE INFO, GET LOG ENTRIES, SET LOG INDEX. None of them is
// audited, so excluding them loses nothing, and including them would have each
// drain cycle signal the need for another drain cycle. Everything else fires,
// audited or not: a spurious signal costs one coalesced drain that finds
// nothing, while a missing one costs a ring slot that is never freed.
func SetCommandObserver(fn func(cmd byte)) {
	if fn == nil {
		commandObserver.Store(nil)
		return
	}
	commandObserver.Store(&fn)
}

// suppressObserverKey marks a context whose device commands belong to the drain
// itself, and so must not be announced back to it.
type suppressObserverKey struct{}

// WithoutCommandObserver returns a context on which no command fires the
// observer. The drain cycle runs under one.
//
// It exists because the exclusion list below cannot be the whole answer, and
// quietly was not: the cycle reads device info, and reading device info on this
// codebase means GET DEVICE INFO *plus* two GET OPTION calls, because what the
// collector needs from it includes the force-audit setting. GET OPTION is a
// perfectly ordinary command that anything else may issue, so it cannot be
// excluded by code — and with it announced, every cycle signalled the need for
// another one. An idle server then drained about eleven times a second, held
// the cross-process collection lease almost continuously, and starved every
// operator command that has to drain before it can proceed.
//
// Scoping the silence to the cycle's context rather than to a set of command
// codes is what keeps that from coming back. The invariant is "a drain's own
// traffic does not request another drain", which is a property of who is
// talking to the device, not of what they say — so a cycle that later reads one
// more thing from the device inherits the silence instead of reintroducing the
// loop. Nothing is lost: the commands a cycle issues are unaudited (verified on
// hardware: an idle deployment's ring stays empty across thousands of drains),
// and anything they did record would be collected by that same cycle's fetch or
// the next one.
func WithoutCommandObserver(ctx context.Context) context.Context {
	if ctx == nil {
		return context.WithValue(context.Background(), suppressObserverKey{}, true)
	}
	return context.WithValue(ctx, suppressObserverKey{}, true)
}

// CommandObserverSuppressed reports whether ctx silences the command observer.
//
// It is exported so the audit subsystem can assert the invariant from its own
// tests — "every device call a drain cycle makes carries a silenced context" is
// checkable there, where the Device interface lives, without a YubiHSM.
func CommandObserverSuppressed(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	suppressed, _ := ctx.Value(suppressObserverKey{}).(bool)
	return suppressed
}

// notifyCommand fires the observer for cmd, unless the context silences it or
// cmd is one of the drain's own.
//
// The command exclusions remain for the paths that have no drain context to
// carry: Client.Close sends CLOSE SESSION on a context of its own, and the
// legacy per-request drain in internal/handlers reads the log without one.
func notifyCommand(ctx context.Context, cmd byte) {
	switch cmd {
	case cmdGetDeviceInfo, cmdGetLogEntries, cmdSetLogIndex, cmdCloseSession:
		return
	}
	if CommandObserverSuppressed(ctx) {
		return
	}
	if fn := commandObserver.Load(); fn != nil {
		(*fn)(cmd)
	}
}
