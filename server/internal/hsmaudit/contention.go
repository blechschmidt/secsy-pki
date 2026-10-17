package hsmaudit

// Who holds the device.
//
// A YubiHSM 2 speaks one protocol over one USB interface, and exactly one
// process may claim that interface. Everything else about the audit subsystem
// assumes the device-log drain can reach the device whenever it needs to, and
// on the direct-USB transport that assumption is false for the shape a YubiHSM
// deployment actually takes: a server that signs through Yubico's PKCS#11 module
// keeps a session pool open for its whole life, the module holds the interface
// for as long as it has a session, and so the collector — which goes through
// the native driver, because PKCS#11 cannot express GET LOG ENTRIES — is
// locked out permanently.
//
// The failure is total and silent in the wrong direction. Collection fails every
// cycle with EBUSY while signing continues, so the deployment looks healthy and
// produces signatures whose device log entries nothing is collecting. On a
// commissioned device that ends in an outage five dozen operations later; on a
// device that merely has per-command auditing on it ends in a device log that
// overwrote itself and a verifier that rejects the result. There is no audit
// configuration under which it works.
//
// The fix is a connector: something whose entire purpose is to multiplex the
// device, so the module and the driver both reach it over HTTP. secsy-pki ships
// one inside the process that needs it (internal/yubihsm.StartEmbedded), which
// is why the default answer to this condition is no longer "run a daemon" but
// "the relay is already there". Yubico's yubihsm-connector remains the right
// answer when the device must be shared with something outside this process, or
// reached from another host.
//
// This file exists so that the one thing standing between an operator and
// either fix — the knowledge that one is required — is detected from
// configuration alone, at startup and in `secsy-ca doctor`, rather than
// inferred from a repeating EBUSY in the log.

import (
	"errors"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// ErrDrainContention marks a deployment whose device-log drain can never run
// because the signing path holds the device. Callers test for it with errors.Is
// so they can distinguish "misconfigured" from "device unreachable".
var ErrDrainContention = errors.New("the YubiHSM audit log cannot be drained while the signing path holds the device")

// DrainContention reports whether a deployment can drain its device audit log
// while its signing path is live.
//
// auditConnectorURL is the connector URL the native driver resolves to — not
// the raw configuration value, since an empty one means direct USB (see
// hsm.EffectiveConnectorURL). pkcs11Module is the PKCS#11 module a signing role
// drives the same device through, or "" when none does. embeddedConnector says
// whether this deployment multiplexes the device in-process
// (hsm.PlanEmbeddedConnector decides, from the same configuration).
//
// It returns nil for every deployment that can share the device: anything on an
// http:// or https:// connector, anything running the embedded connector, and
// anything whose signing path does not go through a module competing for the
// same USB interface — a cloud KMS, a software keystore, or a different token
// entirely.
func DrainContention(auditConnectorURL, pkcs11Module string, embeddedConnector bool) error {
	if pkcs11Module == "" || embeddedConnector || !yubihsm.IsDirectUSB(auditConnectorURL) {
		return nil
	}
	url := auditConnectorURL
	if url == "" {
		url = "yhusb:// (the default for an unset connector URL)"
	}
	return fmt.Errorf("%w\n"+
		"  The audit driver addresses the device over %s, and only one process may claim that USB\n"+
		"  interface. It is held for the whole life of a signing process by the PKCS#11 module\n"+
		"      %s\n"+
		"  which the key provider keeps a session on, so every collection cycle fails with\n"+
		"  \"device or resource busy\". A commissioned device then fills its 62-entry log and stops\n"+
		"  serving signatures altogether.\n"+
		"  Fix: let this process multiplex the device itself — one container, no daemon:\n"+
		"      yubihsm:\n"+
		"        embedded_connector:\n"+
		"          enabled: true     (secsy-pki config; or SECSY_YUBIHSM_EMBEDDED_CONNECTOR=1)\n"+
		"  Or run Yubico's yubihsm-connector, which is the right answer when something outside\n"+
		"  this process needs the device too:\n"+
		"      yubihsm-connector -l 127.0.0.1:12345\n"+
		"      yubihsm.connector_url: http://127.0.0.1:12345   (secsy-pki config)\n"+
		"      connector = http://127.0.0.1:12345              (yubihsm_pkcs11.conf)\n"+
		"  See docs/hsm/audit-log.md", ErrDrainContention, url, pkcs11Module)
}
