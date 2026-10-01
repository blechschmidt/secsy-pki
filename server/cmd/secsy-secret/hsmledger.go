package main

// Signature-ledger recording and device-log collection for secsy-secret.
//
// The secret layer is a signing path like any other, and for a long time it was
// the only one that said nothing about itself. `secsy-secret sign` asks the
// YubiHSM for an ECDSA or RSA signature; `signing-key` and `init-kek` generate
// keys on it; `decrypt`, `get`, `exec` and `rewrap` unwrap data keys with an
// on-device RSA-OAEP decryption; `random` and `datakey` draw from its RNG.
// Every one of those is an audited command on a commissioned device, and none
// of them reached either half of the audit subsystem.
//
// Both halves matter, and for different reasons.
//
// Without a ledger row, a signature the secret layer requested is a device log
// entry the CA cannot account for — and Reconcile calls an unaccounted-for
// device signature key abuse, correctly, because that is exactly what it looks
// like. So the missing rows did not merely leave a gap in the evidence: they
// manufactured a false accusation against the deployment's own HSM, in the one
// subsystem whose alarms have to be believed.
//
// Without a drain, the entries stay in a volatile 62-entry ring that a power
// cut loses and a full log turns into an outage. A deployment whose operators
// use `secsy-secret` — the normal case; it is the tool the secret layer ships
// with — would fill that ring from a process that never collected it, and the
// device would stop serving the CA.
//
// The wiring mirrors cmd/secsy-ca/hsmledger.go, including the ordering trick in
// setupHSMLedger: the drain has to run after the key provider's Close, because
// the two reach the same USB device by different routes and only one of them
// may hold it.

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

// signatureRecorder is the process-wide ledger hook, installed once before the
// key provider is built. It is a package-level variable rather than a parameter
// because buildProvider is called from one place but the provider is handed to
// two dozen dispatch arms, none of which should have to know this exists.
var signatureRecorder keyprovider.SignatureRecorder

// hsmUsed records whether this process actually reached the device, so a
// command that never did does not pay for a drain — and, more to the point, so
// `secsy-secret kek-info` on a machine where the YubiHSM is not plugged in does
// not start reporting device errors.
var hsmUsed atomic.Bool

// markHSMUsed records that this process reached the device. It is also
// installed as the native driver's command observer, so the device commands
// that never pass a key provider count as HSM use too.
func markHSMUsed() { hsmUsed.Store(true) }

// setupHSMLedger turns on ledger recording for this invocation and returns the
// teardown that drains the device log and releases the database.
//
// The caller must defer the returned function *before* building the key
// provider. Deferred in that order it unwinds after the provider's own Close,
// which is what the drain needs: Yubico's PKCS#11 module holds the device's USB
// interface for as long as it has a session, and the collector reaches the same
// device through the native driver. Draining while the module still holds it
// fails with "device or resource busy" — see yubihsm.ErrDeviceBusy.
//
// A deployment with no database configured gets no recording. That is not a
// silent downgrade: the ledger, the collected device log and the pinned audit
// state all live in that database, so there is nowhere for any of it to go, and
// `secsy-secret` has always been usable with a bare KEK and no store.
//
// A database that is configured but unreadable is reported and treated as
// "off", mirroring secsy-ca: refusing to decrypt a secret because an audit
// lookup failed would make a database hiccup lock an operator out of their own
// data, and the device log still bounds what the HSM did regardless.
func setupHSMLedger(cfg *config.Config) func() {
	if cfg.Database.Driver == "" || cfg.Database.DSN == "" {
		return func() {}
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		log.Printf("WARNING: could not open the database, HSM signature-ledger recording is off: %v", err)
		return func() {}
	}
	rec, err := hsmaudit.EnableRecording(context.Background(), db)
	if err != nil {
		log.Printf("WARNING: could not determine HSM audit state, signature-ledger recording is off: %v", err)
		_ = db.Close()
		return func() {}
	}
	if rec == nil {
		// The device was never commissioned for audited operation, so there is
		// no pinned anchor a ledger could be reconciled against. Nothing to do,
		// and nothing to warn about: that is the ordinary software-backed case.
		_ = db.Close()
		return func() {}
	}
	signatureRecorder = rec
	yubihsm.SetCommandObserver(func(byte) { markHSMUsed() })
	return func() {
		collectAfterHSMUse(cfg, db)
		_ = db.Close()
	}
}

// recordSignatures wraps p so its signatures reach the ledger and its device
// log entries get collected. It is a no-op when recording is off, so an
// unprovisioned deployment behaves exactly as before.
func recordSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	return keyprovider.Record(p, signatureRecorder, keyprovider.OnOperation(markHSMUsed))
}

// collectAfterHSMUse drains the device log if this process used the HSM.
//
// A failure here is a warning, never an error: the command's work is done and
// its signatures are already in the ledger, so failing the invocation would
// misreport a completed decryption as a failed one. The entries stay on the
// device, where the next drain — this CLI's, secsy-ca's, or the server's —
// picks them up.
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
	// The same append-only file the server and secsy-ca write. Both processes
	// append under the collection lease, and O_APPEND keeps a batch from
	// interleaving with another writer's — so an operator's `secsy-secret sign`
	// leaves its device entries in the file exactly as the server's would,
	// rather than only in the database.
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
// (nil, nil) when none is configured. The failure is reported to the caller
// rather than being fatal: a `secsy-secret` invocation has already done its
// work by the time the drain runs, and an unwritable evidence file must not
// turn a completed operation into a failed command.
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
