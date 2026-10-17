package main

import (
	"context"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// The in-process YubiHSM connector (Task 204).
//
// A YubiHSM 2 speaks over one USB interface and the kernel grants that
// interface to one claim. Yubico's PKCS#11 module holds it for the life of its
// session pool — the life of this process — so the audit driver, which must
// read the device log because PKCS#11 cannot express GET LOG ENTRIES, never
// gets it. That deployment cannot collect its device log at all, and
// hsmaudit.DrainContention refuses to start it rather than deliver a CA whose
// force-audited HSM will stop signing once 62 uncollected entries accumulate.
//
// Until now the only answer was Yubico's yubihsm-connector: a second process,
// and in a container deployment a second container, with the device node passed
// to it and a health check in front of it. That put the sole copy of a volatile
// audit log behind a sidecar's lifecycle, for a relay.
//
// So this process runs the relay. It claims the device before anything else
// touches it, serves Yubico's connector protocol on loopback, and points the
// module's own configuration at that endpoint. Everything in-process that needs
// the native driver is routed to the same claim by internal/yubihsm, and every
// command the module sends arrives here as an HTTP request — which is what lets
// collection follow the module's operations, not merely this program's own.
//
// Ordering is the one subtle part. The relay must be up before any key provider
// is built (the module reads its connector once, at C_Initialize) and before
// the audit subsystem probes the device, so it is the first thing in main that
// touches hardware.

// embeddedConnector is the running relay, or nil when this deployment does not
// multiplex the device in-process.
//
// Package-level for the same reason hsmAuditCollector is: it has to exist
// before the first key provider and before the audit wiring, both of which are
// far from each other in startup, and nothing between them should have to carry
// it.
var embeddedConnector *yubihsm.Embedded

// startEmbeddedConnector brings up the relay this configuration calls for.
//
// A configuration that asks for a relay it cannot have is fatal, by the same
// reasoning as the audit log file's unwritable path: the operator stated how
// this deployment reaches its HSM, and starting up having silently done
// something else is worse than not starting. A relay that is simply not needed
// is not an error and says why at debug level — "no PKCS#11 signing path
// competes for the device" is a perfectly good deployment.
func startEmbeddedConnector(cfg *config.Config) {
	plan := hsm.PlanEmbeddedConnector(embeddedConnectorOptions(cfg))
	if plan.Err != nil {
		log.Fatalf("FATAL: %v", plan.Err)
	}
	if !plan.Start {
		if cfg.YubiHSM.ConnectorURL != "" || cfg.YubiHSM.AuthKeyID != 0 {
			log.Printf("Embedded YubiHSM connector off: %s", plan.Reason)
		}
		return
	}
	log.Printf("Embedded YubiHSM connector: %s", plan.Reason)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e, err := hsm.StartEmbeddedConnector(ctx, plan, log.Default())
	if err != nil {
		// Fatal, and not a warning that lets the server come up signing: the
		// deployment that needs a relay is exactly the one whose device log
		// nothing else will drain, and a CA that signs without collecting on a
		// force-audited device is on a countdown to refusing to sign at all.
		log.Fatalf("FATAL: the embedded YubiHSM connector could not start: %v\n"+
			"  Set yubihsm.embedded_connector.enabled to false and run Yubico's yubihsm-connector "+
			"if this host shares the device with another process.", err)
	}
	// nil with no error means something else already serves the address — this
	// program's own server process in a second container, or a yubihsm-connector
	// daemon. The device is multiplexed either way, which is all that was needed.
	embeddedConnector = e
}

// stopEmbeddedConnector releases the device on the way out.
func stopEmbeddedConnector() {
	if embeddedConnector == nil {
		return
	}
	if err := embeddedConnector.Close(); err != nil {
		log.Printf("WARNING: closing the embedded YubiHSM connector: %v", err)
	}
}

// embeddedConnectorOptions reads the relay decision's inputs out of the config.
//
// The verdict comes from hsm.PlanEmbeddedConnector, not from here, and that is
// the point: `secsy-ca doctor` reaches it from the same four values in a
// process where no relay is running, so a preflight check cannot disagree with
// the server it is checking.
func embeddedConnectorOptions(cfg *config.Config) hsm.EmbeddedConnectorOptions {
	return hsm.EmbeddedConnectorOptions{
		Enabled:      cfg.YubiHSM.EmbeddedConnector.Enabled,
		Listen:       cfg.YubiHSM.EmbeddedConnector.Listen,
		Device:       cfg.YubiHSM.EmbeddedConnector.Device,
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		PKCS11Module: cfg.SigningPKCS11Module(),
	}
}
