package yubihsm

import "sync/atomic"

// Every command this driver sends to a force-audited YubiHSM may leave a record
// in the device's 62-entry log ring, and that ring is both volatile and
// self-limiting: entries survive only until a power cut, and once 62 of them
// accumulate unacknowledged the device stops serving auditable commands
// altogether. Collecting them is therefore not housekeeping but a liveness
// requirement, and it has to follow the operations rather than a clock.
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
// nothing, while a missing one costs an entry that sits in a volatile ring.
func SetCommandObserver(fn func(cmd byte)) {
	if fn == nil {
		commandObserver.Store(nil)
		return
	}
	commandObserver.Store(&fn)
}

// notifyCommand fires the observer for cmd, unless cmd is one of the drain's own.
func notifyCommand(cmd byte) {
	switch cmd {
	case cmdGetDeviceInfo, cmdGetLogEntries, cmdSetLogIndex, cmdCloseSession:
		return
	}
	if fn := commandObserver.Load(); fn != nil {
		(*fn)(cmd)
	}
}
