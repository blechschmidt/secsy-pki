package main

import (
	"context"
	"log"
	"sync/atomic"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Signature-ledger recording and device-log collection for the CLI (Task 167,
// Task 181).
//
// secsy-ca signs from the same HSM the server does — init-root, issue, gen-crl,
// rotate, ssh, sign and the rest all reach a key provider. Every one of those
// signatures appears in the device audit log, so every one of them needs a
// ledger row too; a CLI-issued certificate that the ledger does not know about
// is indistinguishable, on the device log, from an abused key.
//
// It also needs collecting. The device log is a volatile 62-entry ring, and a
// CLI-only deployment (no server running, or a server that cannot reach this
// device) has nothing else that would ever drain it: entries would sit there
// until a power cut lost them or the ring filled and the device stopped
// accepting auditable commands. So the CLI drains too, once, after the command
// has finished with the HSM — the same "collect after the operations" rule the
// server follows, at the granularity a one-shot process has.
//
// The recorder is a package-level hook rather than a parameter threaded through
// buildProvider because buildProvider is called from three dozen dispatch arms
// and has no access to the store. Installing it once, immediately after the
// database is opened, covers all of them.

var signatureRecorder keyprovider.SignatureRecorder

// hsmUsed records whether any HSM operation actually happened, so a command
// that never reached the device does not pay for a drain — and, more to the
// point, so `secsy-ca list` on a machine where the YubiHSM is not plugged in
// does not start reporting device errors.
var hsmUsed atomic.Bool

// installSignatureRecorder turns on ledger recording when the attached device
// has been provisioned for audited operation.
//
// A failure to determine that is reported and treated as "off". The alternative
// — refusing to run any CLI command because the audit state could not be read —
// would make a database hiccup lock an operator out of the CA, and the device
// log still bounds what the HSM did regardless.
func installSignatureRecorder(db *database.DB) {
	rec, err := hsmaudit.EnableRecording(context.Background(), db)
	if err != nil {
		log.Printf("WARNING: could not determine HSM audit state, signature ledger recording is off: %v", err)
		return
	}
	signatureRecorder = rec
}

// recordSignatures wraps p so its signatures reach the ledger and its device
// log entries get collected, when recording is enabled. It is a no-op
// otherwise, so an unprovisioned deployment behaves exactly as before.
func recordSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	return keyprovider.Record(p, signatureRecorder, keyprovider.OnOperation(func() { hsmUsed.Store(true) }))
}

// collectAfterHSMUse drains the device log if this process used the HSM.
//
// It is deferred immediately after the recorder is installed, which puts it
// *after* the key provider's own deferred Close in unwind order — deliberately,
// so the PKCS#11 session is gone before the native driver opens its own. The
// two reach the same USB device by different routes and need not be polite to
// each other.
//
// A failure here is a warning, never an error: the command's work is done and
// its signatures are already in the ledger, so failing the invocation would
// misreport a completed issuance as a failed one. The entries stay on the
// device, where the next drain — this CLI's or the server's — picks them up.
func collectAfterHSMUse(cfg *config.Config, db *database.DB) {
	if !hsmUsed.Load() || signatureRecorder == nil {
		return
	}
	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	res, err := hsmaudit.NewCollector(dev, db, 0, log.Default()).Collect(context.Background())
	if err != nil {
		log.Printf("WARNING: HSM device log not collected after this command: %v. "+
			"The entries remain on the device; run `secsy-ca hsm-audit collect` once it is reachable.", err)
		return
	}
	if res.Collected > 0 {
		log.Printf("HSM audit: collected %d device log entr(ies) (%d signature(s)); device log %s used.",
			res.Collected, res.Signatures, res.LogUsed)
	}
}
