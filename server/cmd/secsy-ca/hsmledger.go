package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
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
	if rec != nil {
		yubihsm.SetCommandObserver(func(byte) { markHSMUsed() })
	}
}

// recordSignatures wraps p so its signatures reach the ledger and its device
// log entries get collected, when recording is enabled. It is a no-op
// otherwise, so an unprovisioned deployment behaves exactly as before.
func recordSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	return keyprovider.Record(p, signatureRecorder, keyprovider.OnOperation(markHSMUsed))
}

// markHSMUsed records that this process reached the device.
//
// It is also installed as the native driver's command observer, so the commands
// that do not pass a key provider — key and device attestation, audit-head
// commitments, provisioning — count as HSM use too. `secsy-ca hsm-attest key`
// on a force-audited device writes three log entries and never touches a key
// provider; before the driver hook, none of them was drained by the process
// that produced them.
func markHSMUsed() { hsmUsed.Store(true) }

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
	c := hsmaudit.NewCollector(dev, db, 0, log.Default())
	// The CLI writes the same append-only file the server does. Both processes
	// append to it under the collection lease, and O_APPEND keeps a batch from
	// interleaving with the other writer's — so an operator's `secsy-ca issue`
	// leaves its device entries in the file exactly as the server's issuance
	// would, rather than only in the database.
	f, err := openConfiguredAuditLogFile(cfg)
	if err != nil {
		log.Printf("WARNING: HSM device log not collected after this command: %v", err)
		return
	}
	if f != nil {
		defer func() { _ = f.Close() }()
		c.AddSink(f)
	}
	res, err := c.Collect(context.Background())
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

// openConfiguredAuditLogFile opens the append-only device-log file, or returns
// (nil, nil) when none is configured.
//
// Unlike the server, which refuses to start without a file it was told to
// write, the CLI reports the failure to its caller: a `secsy-ca` invocation has
// already done its work by the time the drain runs, and an unwritable evidence
// file must not turn a completed issuance into a failed command. The entries
// stay on the device either way, so the next drain — this file having been
// fixed — still collects them.
func openConfiguredAuditLogFile(cfg *config.Config) (*hsmaudit.LogFile, error) {
	path := strings.TrimSpace(cfg.YubiHSM.AuditLogFile)
	if path == "" {
		return nil, nil
	}
	f, err := hsmaudit.OpenLogFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening the append-only HSM audit log file: %w", err)
	}
	return f, nil
}
