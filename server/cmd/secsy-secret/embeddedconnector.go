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

// The in-process YubiHSM connector, for secsy-secret (Task 204).
//
// The same lazy, non-fatal, join-what-is-there policy secsy-ca uses, and for
// the same reasons — see cmd/secsy-ca/embeddedconnector.go, which documents
// them, and cmd/server/embeddedconnector.go for what the relay is. It is
// duplicated rather than shared because these are two separate main packages
// and the whole of it is twenty lines of policy over hsm.PlanEmbeddedConnector,
// which is where the decision actually lives.
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
// Called from buildProvider, so no command can open the module without the
// device having first been multiplexed — and a command that needs no key, like
// `secsy-secret lifecycle list`, does not pay for it.
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
// It runs after collectAfterHSMUse, not before: the drain reaches the device
// through the relay's claim, since by then the key provider has closed but the
// device is still held by this process.
func stopEmbeddedConnector() {
	if cliConnector == nil {
		return
	}
	if err := cliConnector.Close(); err != nil {
		log.Printf("WARNING: closing the embedded YubiHSM connector: %v", err)
	}
}
