package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// HSM audit-log collection and signature-ledger recording (Task 167, Task 181).
//
// The device log is a 62-entry ring. On a force-audited device the HSM refuses
// every auditable command once it fills — which is what makes the log complete
// rather than merely informative, and also means draining it is not optional
// housekeeping but a liveness requirement.
//
// Collection is driven by the operations themselves: the key-provider wrapper
// every signature, decryption and key wrap passes through signals the collector
// when it is done, so the durable copy trails the device's own by one drain
// cycle regardless of how busy the CA is. A backstop timer covers what this
// process's own operations cannot announce (another process's commands, a
// signal lost to a crash) and keeps an idle deployment probing a device that
// may have wedged.
//
// The loop is leader-elected so idle replicas do not generate device traffic
// they have no operations to justify. That gate is not what makes concurrent
// drains safe — provisioning, export, freshness attestation, device commitment
// and the CLI all drain outside it — the collector's process mutex and the
// store's collection lease are (see internal/hsmaudit/lease.go).

// hsmAuditCollector is the process-wide device-log drain, or nil when the
// attached device has not been commissioned for audited operation.
//
// It is a package-level variable for the same reason signatureRecorder below is:
// it has to be built before the first key provider, so that no signature can be
// produced before the thing that collects its device log entry exists, and the
// leader registration happens much later in startup.
var hsmAuditCollector *hsmaudit.Collector

// setupHSMAudit builds the device-log collector and the signature-ledger
// recorder, and wires the first to the second.
//
// A deployment that has never run `secsy-ca hsm-audit provision` gets neither —
// there is no pinned anchor to verify against, so collecting would produce a
// chain that cannot be attributed to a known device history, and a ledger with
// no device log to reconcile against proves nothing on its own.
func setupHSMAudit(cfg *config.Config, db *database.DB) {
	st, err := db.LoadAuditState(context.Background())
	if err != nil {
		log.Printf("WARNING: could not read HSM audit state, device-log collection "+
			"and signature-ledger recording are off: %v", err)
		return
	}
	if st == nil {
		warnUncollectedForcedAudit(cfg)
		return
	}

	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	backstop := hsmAuditBackstop(cfg)
	c := hsmaudit.NewCollector(dev, db, backstop, log.Default())
	c.OnFailure(func(error) { metrics.HSMAuditCollectionFailures.Inc() })
	if f := openAuditLogFile(cfg); f != nil {
		c.AddSink(f)
	}
	hsmAuditCollector = c

	rec, err := hsmaudit.EnableRecording(context.Background(), db)
	if err != nil {
		log.Printf("WARNING: could not read HSM audit state, signature-ledger recording is off: %v", err)
	} else if rec != nil {
		signatureRecorder = rec
		log.Printf("HSM signature-ledger recording enabled: every signature is recorded for audit reconciliation")
	}

	if perOperationCollection(cfg, dev) {
		// Two chokepoints, because there are two routes to the device. The key
		// provider carries everything the product signs with; the native driver
		// carries key and device attestation, audit-head commitments and option
		// changes, none of which pass a key provider and all of which leave log
		// entries on a force-audited device.
		yubihsm.SetCommandObserver(func(byte) { c.Notify() })
		log.Printf("HSM audit collection enabled (device %s, anchor %s, after every HSM operation, backstop %s)",
			st.DeviceSerial, st.Anchor, backstop)
	} else {
		hsmAuditNotify = nil
		log.Printf("HSM audit collection enabled (device %s, anchor %s, every %s — per-operation collection "+
			"is disabled, so entries stay in the device's volatile 62-entry ring until the next sweep)",
			st.DeviceSerial, st.Anchor, backstop)
	}
	//nolint:staticcheck // SA1019: honouring the deprecated key is the whole point of reading it here.
	if cfg.YubiHSM.AuditCollectIntervalSeconds > 0 && cfg.YubiHSM.AuditCollectBackstopSeconds == 0 {
		log.Printf("WARNING: yubihsm.audit_collect_interval_seconds is deprecated: collection now runs after " +
			"every HSM operation. The configured value is being used as the backstop sweep interval; " +
			"rename it to audit_collect_backstop_seconds.")
	}
}

// setupHSMAuditCollector registers the drain loop with the leader elector.
func setupHSMAuditCollector(elector *leader.Elector) {
	c := hsmAuditCollector
	if c == nil {
		return
	}
	elector.Register("hsm-audit-collector", func(ctx context.Context) {
		c.Run(ctx)
	})
}

// hsmAuditNotify signals the collector that an operation reached the HSM. It is
// a function value so the wiring can disable it wholesale when per-operation
// collection is turned off, without every call site testing a flag.
var hsmAuditNotify = func() { hsmAuditCollector.Notify() }

// openAuditLogFile opens the configured append-only device-log file.
//
// The sink is deliberately not retained for a shutdown close. Every record is
// written with a direct write plus an fsync before the collector acknowledges
// anything on the device, so there is nothing buffered for a Close to flush,
// and the file descriptor is released by process exit either way. Holding a
// package-level handle in order to close it would suggest a durability step
// that does not exist.
//
// A file that cannot be opened is fatal, not a warning. The point of the file is
// to be a copy the operator of this host cannot quietly remove, so starting
// without it — after somebody configured it — would silently deliver the
// opposite of what was asked for. Failing here is loud, happens at startup
// rather than at the first drain, and names the path.
func openAuditLogFile(cfg *config.Config) *hsmaudit.LogFile {
	path := strings.TrimSpace(cfg.YubiHSM.AuditLogFile)
	if path == "" {
		return nil
	}
	f, err := hsmaudit.OpenLogFile(path)
	if err != nil {
		log.Fatalf("FATAL: yubihsm.audit_log_file is set to %s but it cannot be opened for append: %v", path, err)
	}
	if n, _, ok := f.Last(); ok {
		log.Printf("HSM audit log file %s open for append (continues from entry %d)", path, n)
	} else {
		log.Printf("HSM audit log file %s open for append (new file)", path)
	}
	return f
}

// perOperationCollection reports whether the drain follows every HSM operation.
//
// Unset means on: an operator who has gone to the trouble of commissioning a
// force-audited device wants its log collected promptly, not eventually.
//
// An explicit `false` is honoured only on a device that is not force-audited.
// With force-audit on, the 62-entry ring is not a buffer that overflows into
// older entries — it is a hard stop, after which the HSM refuses every audited
// command and the CA stops issuing. Letting configuration disable the drain
// there would let a deployment turn a tuning knob and get an outage, so the
// device's setting wins and says so.
func perOperationCollection(cfg *config.Config, dev hsmaudit.Device) bool {
	v := cfg.YubiHSM.AuditCollectPerOperation
	if v == nil || *v {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	forced, err := hsmaudit.ForceAuditEnabled(ctx, dev)
	if err != nil {
		log.Printf("WARNING: could not read the device audit options to check force-audit (%v); "+
			"keeping per-operation collection on, because a force-audited device wedges without it", err)
		return true
	}
	if forced {
		log.Printf("WARNING: yubihsm.audit_collect_per_operation is false, but the attached device has " +
			"force-audit enabled: it stops accepting audited commands once 62 entries accumulate. " +
			"Per-operation collection stays on.")
		return true
	}
	return false
}

// warnUncollectedForcedAudit reports a device that force-audits but has no
// pinned audit state, so nothing in this process will drain its log.
//
// This is the one configuration that fails silently and then stops the CA: the
// collector is gated on provisioning, because without a pinned anchor a
// collected chain cannot be attributed to a known device history — but the
// device does not care why nobody is draining it, and refuses every audited
// command as soon as its 62 slots fill. An operator who force-audited a device
// by hand (yubihsm-shell, an inherited HSM) and never ran `hsm-audit provision`
// gets no other indication until issuance stops.
//
// The probe is skipped entirely when no YubiHSM is configured. An unset
// hsm.Config carries an empty connector URL, which the driver resolves to the
// default direct-USB one — so probing unconditionally would have every
// SoftHSM or software-backed deployment reach for whichever device happens to
// be plugged into the machine.
func warnUncollectedForcedAudit(cfg *config.Config) {
	if cfg.YubiHSM.ConnectorURL == "" && cfg.YubiHSM.AuthKeyID == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	forced, err := hsmaudit.ForceAuditEnabled(ctx, dev)
	if err != nil || !forced {
		return
	}
	log.Printf("WARNING: the attached YubiHSM has force-audit enabled but this deployment has no pinned " +
		"audit state, so nothing here drains its log. The device holds 62 log entries and then refuses " +
		"every audited command — including signing. Run `secsy-ca hsm-audit provision` to commission it, " +
		"or `secsy-ca hsm-audit collect` to drain it by hand.")
}

// hsmAuditBackstop resolves the sweep cadence used when no operation prompts a
// drain, honouring the deprecated audit_collect_interval_seconds so an existing
// deployment's tuning is not silently discarded.
func hsmAuditBackstop(cfg *config.Config) time.Duration {
	if s := cfg.YubiHSM.AuditCollectBackstopSeconds; s > 0 {
		return time.Duration(s) * time.Second
	}
	//nolint:staticcheck // SA1019: the deprecated key is read precisely so an existing deployment's tuning survives.
	if s := cfg.YubiHSM.AuditCollectIntervalSeconds; s > 0 {
		return time.Duration(s) * time.Second
	}
	return hsmaudit.BackstopInterval
}

// setupHSMAuditFreshness registers the RFC 3161 attestation job that keeps
// exported audit bundles provably current.
//
// Without it every other check still passes on a bundle exported months ago, so
// an operator could answer an audit with a snapshot taken before the abuse and
// nothing in the verification would object. Running it continuously — rather
// than stamping at export time — is what divides the timeline into attested
// intervals a later signature cannot be backdated into.
//
// It shares the collector's provisioning gate: with no pinned anchor there is
// no head worth attesting to. When no timestamp authority can be resolved the
// job is skipped with a warning rather than failing startup, because a missing
// TSA must not take a CA offline — and the verifier fails closed on the
// resulting gap regardless, which is the safe direction.
func setupHSMAuditFreshness(cfg *config.Config, db *database.DB, authority *tsa.Authority, elector *leader.Elector) {
	st, err := db.LoadAuditState(context.Background())
	if err != nil || st == nil {
		return // already reported by setupHSMAudit
	}

	ts, err := buildFreshnessTimestamper(cfg, authority)
	if err != nil {
		log.Printf("WARNING: HSM audit freshness attestation is off: %v. "+
			"Exported audit bundles will not be able to prove they are current.", err)
		return
	}

	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	interval := hsmAuditFreshnessInterval(cfg)
	runner := hsmaudit.NewFreshnessRunner(hsmaudit.NewService(dev, db), ts, interval, log.Default())

	log.Printf("HSM audit freshness attestation enabled (interval %s)", interval)
	elector.Register("hsm-audit-freshness", func(ctx context.Context) {
		runner.Run(ctx)
	})
}

// hsmAuditFreshnessInterval resolves the attestation cadence.
func hsmAuditFreshnessInterval(cfg *config.Config) time.Duration {
	if s := cfg.YubiHSM.AuditFreshnessIntervalSeconds; s > 0 {
		return time.Duration(s) * time.Second
	}
	return hsmaudit.FreshnessInterval
}

// setupHSMAuditCommitment registers the job that has the device sign a binding
// of the audit head to its own serial number.
//
// The freshness attestation above dates the audit head. This says which device
// asserted it — and nothing else in the subsystem can, because a YubiHSM audit
// entry carries no serial number and no signature, so every other check holds
// equally well over a log fabricated offline. Together the two produce the
// statement an auditor actually needs: *this device* asserted *this state* at
// *this time*.
//
// It shares the collector's provisioning gate and the freshness job's TSA
// fallback chain, and is skipped with a warning rather than failing startup for
// the same reason: a device or TSA problem must not take a CA offline, and the
// verifier fails closed on the resulting gap regardless.
func setupHSMAuditCommitment(cfg *config.Config, db *database.DB, authority *tsa.Authority, elector *leader.Elector) {
	st, err := db.LoadAuditState(context.Background())
	if err != nil || st == nil {
		return // already reported by setupHSMAudit
	}

	ts, err := buildFreshnessTimestamper(cfg, authority)
	if err != nil {
		log.Printf("WARNING: HSM audit device commitment is off: %v. "+
			"Exported audit bundles will not be able to show which device produced the log.", err)
		return
	}

	dev := hsmaudit.NewHardwareDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	svc := hsmaudit.NewService(dev, db)
	if id := cfg.YubiHSM.AuditCommitmentKeyID; id != 0 {
		svc.SetCommitmentKeyID(uint16(id))
	}
	interval := hsmAuditCommitmentInterval(cfg)
	runner := hsmaudit.NewCommitmentRunner(svc, ts, interval, log.Default())

	log.Printf("HSM audit device commitment enabled (interval %s)", interval)
	elector.Register("hsm-audit-commitment", func(ctx context.Context) {
		runner.Run(ctx)
	})
}

// hsmAuditCommitmentInterval resolves the commitment cadence.
func hsmAuditCommitmentInterval(cfg *config.Config) time.Duration {
	if s := cfg.YubiHSM.AuditCommitmentIntervalSeconds; s > 0 {
		return time.Duration(s) * time.Second
	}
	return hsmaudit.CommitmentInterval
}

// buildFreshnessTimestamper selects where attestation tokens come from: the
// dedicated external TSA, else the one already configured for audit-chain
// anchoring, else this PKI's own in-process authority.
//
// The middle step matters: a deployment that configured an independent TSA for
// Task 64 anchoring wants the same independence here, and making it configure
// the same URL twice invites the two drifting apart. The last step is a real
// fallback but a weak one — the internal TSA signs with the HSM under audit, so
// it proves freshness against an outsider and not against an operator holding
// that HSM. The verifier says so, and -require-external-tsa rejects it outright.
func buildFreshnessTimestamper(cfg *config.Config, authority *tsa.Authority) (hsmaudit.Timestamper, error) {
	if url := cfg.YubiHSM.AuditFreshnessTSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, time.Duration(cfg.YubiHSM.AuditFreshnessTimeoutSeconds)*time.Second), nil
	}
	if url := cfg.Audit.Anchor.TSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, time.Duration(cfg.Audit.Anchor.TimeoutSeconds)*time.Second), nil
	}
	if authority == nil {
		return nil, fmt.Errorf("no timestamp authority available: set yubihsm.audit_freshness_tsa_url to an " +
			"external RFC 3161 TSA (recommended), or enable the internal tsa: block")
	}
	return anchor.NewAuthorityTimestamper(authority), nil
}

// signatureRecorder is the process-wide ledger hook. It is a package-level
// variable rather than a parameter because buildRoleProvider is called for five
// separate key roles from several places and has no access to the store;
// installing the hook once, right after the database is opened, covers them all
// and guarantees no role is quietly left unrecorded.
var signatureRecorder keyprovider.SignatureRecorder

// recordHSMSignatures wraps p so every signature it produces is written to the
// tamper-evident signature ledger, and every operation it performs prompts a
// device-log drain.
//
// This is the chokepoint that gives the device log something to be reconciled
// against: the log says how many signatures a key made, the ledger says which
// ones they were. Wrapping at the provider means CA issuance, CRL and OCSP
// signing, the TSA, the SSH CA, SVIDs, artifact signing and every background
// job are covered without each having to know the audit subsystem exists — and
// so is code added later.
//
// The same wrapper carries the collection signal, deliberately: the set of
// operations that need a ledger row and the set whose device log entries need
// collecting are the same set, so binding them to one chokepoint means neither
// can be extended without the other.
func recordHSMSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	if hsmAuditCollector == nil || hsmAuditNotify == nil {
		return keyprovider.Record(p, signatureRecorder)
	}
	return keyprovider.Record(p, signatureRecorder, keyprovider.OnOperation(hsmAuditNotify))
}
