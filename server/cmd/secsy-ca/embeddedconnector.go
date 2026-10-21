package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// The in-process YubiHSM connector, for the CLI (Task 204).
//
// The server's copy of this (cmd/server/embeddedconnector.go) explains what the
// relay is and why a deployment needs one. The CLI's needs differ in three
// ways, and they are what this file is about.
//
// It starts lazily. A `secsy-ca` invocation does not know whether it will touch
// the HSM — `list` and `validate-cert` never do — so claiming the device at
// startup would make an unrelated command fail on a host where the device is
// busy. The relay therefore comes up at the first key provider and not before.
//
// It is not fatal. The server refuses to run without the relay its
// configuration calls for, because it is about to sign continuously against a
// device whose log nothing else would drain. A CLI command is one operation,
// its signatures are in the ledger before the drain runs, and the entries stay
// on the device for the next drain either way — so a relay that cannot start is
// a warning followed by the key provider's own, much more specific, error.
//
// It expects to find one already running. In a single-container deployment the
// server holds the device and serves the relay; an operator's `secsy-ca` in
// that container must use it rather than compete for a USB claim it cannot
// have. hsm.StartEmbeddedConnector reports that case by returning no relay and
// no error, having pointed the PKCS#11 module at the endpoint that does exist.

var (
	cliConnector     *yubihsm.Embedded
	cliConnectorOnce sync.Once
)

// ensureEmbeddedConnector brings up the relay before the first key provider.
//
// Called from buildProvider, which every dispatch arm that needs a key reaches,
// so no command can open the module without the device having first been
// multiplexed — and no command that needs no key pays for it.
func ensureEmbeddedConnector(cfg *config.Config) {
	cliConnectorOnce.Do(func() {
		plan := hsm.PlanEmbeddedConnector(hsm.EmbeddedConnectorOptions{
			Enabled:      cfg.YubiHSM.EmbeddedConnector.Enabled,
			Listen:       cfg.YubiHSM.EmbeddedConnector.Listen,
			Device:       cfg.YubiHSM.EmbeddedConnector.Device,
			ConnectorURL: cfg.YubiHSM.ConnectorURL,
			PKCS11Module: cfg.SigningPKCS11Module(),
		})
		if plan.Err != nil {
			log.Printf("WARNING: %v", plan.Err)
			return
		}
		if !plan.Start {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		e, err := hsm.StartEmbeddedConnector(ctx, plan, log.Default())
		if err != nil {
			log.Printf("WARNING: the embedded YubiHSM connector could not start (%v); this command will "+
				"reach the device directly, which works only if nothing else holds it", err)
			return
		}
		cliConnector = e
	})
}

// stopEmbeddedConnector releases the device on the way out.
//
// It is deferred ahead of collectAfterHSMUse so it unwinds *after* it: the
// drain needs the relay's claim, since by then the key provider has closed but
// the device is still held by this process.
func stopEmbeddedConnector() {
	if cliConnector == nil {
		return
	}
	if err := cliConnector.Close(); err != nil {
		log.Printf("WARNING: closing the embedded YubiHSM connector: %v", err)
	}
}

// releaseEmbeddedConnector closes this process's relay and forgets it, so a
// later OpenTransport claims the device itself rather than routing to a handle
// that is no longer good.
//
// One command needs that mid-run: a factory reset reboots the device, which
// drops off the USB bus and comes back on a new node, leaving the relay holding
// a stale file descriptor. Everything after the reset — the wait for the device
// to return, and the operator's next command — has to reach the re-enumerated
// device, and nothing in the process may still be holding the old claim.
//
// It reports whether this process was the relay's owner. A deployment that
// joined somebody else's relay (the server's, in the single-container stack) has
// nothing to release here, and the re-enumeration is that owner's to notice.
func releaseEmbeddedConnector() bool {
	e := cliConnector
	if e == nil {
		return false
	}
	// Forgotten before it is closed, not after: closing a USB handle on a device
	// that has just rebooted can block in the kernel, and the caller is prepared
	// to abandon this call. Clearing the global first means main's own deferred
	// close cannot then inherit that block on the way out.
	cliConnector = nil
	if err := e.Close(); err != nil {
		log.Printf("WARNING: closing the embedded YubiHSM connector: %v", err)
	}
	return true
}

// embeddedConnectorIsOurs reports whether this process is the one holding the
// device's USB claim, as opposed to having joined a relay somebody else serves.
//
// Asked before a reset rather than inferred from releaseEmbeddedConnector's
// return, because that call closes a USB handle and may not come back promptly
// on a device that has just rebooted — and the answer decides where to look for
// the device afterwards.
func embeddedConnectorIsOurs() bool { return cliConnector != nil }
