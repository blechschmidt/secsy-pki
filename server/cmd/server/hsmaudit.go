package main

import (
	"context"
	"fmt"
	"log"
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
)

// HSM audit-log collection and signature-ledger recording (Task 167).
//
// The device log is a 62-entry ring. On a force-audited device the HSM refuses
// every auditable command once it fills — which is what makes the log complete
// rather than merely informative, and also means draining it is not optional
// housekeeping but a liveness requirement. The collector runs continuously and
// well ahead of the fill rate.
//
// It is leader-elected because acknowledging entries is destructive and must
// have exactly one owner: two replicas draining the same device would each see
// half the entries and each report the other half as an uncollected gap.

// setupHSMAuditCollector registers the device-log drain when the attached
// YubiHSM has been commissioned for audited operation.
//
// A deployment that has never run `secsy-ca hsm-audit provision` gets nothing —
// there is no pinned anchor to verify against, so collecting would produce a
// chain that cannot be attributed to a known device history.
func setupHSMAuditCollector(cfg *config.Config, db *database.DB, elector *leader.Elector) {
	st, err := db.LoadAuditState(context.Background())
	if err != nil {
		log.Printf("WARNING: could not read HSM audit state, device-log collection is off: %v", err)
		return
	}
	if st == nil {
		return
	}

	dev := hsmaudit.NewShellDevice(hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	})
	c := hsmaudit.NewCollector(dev, db, hsmAuditInterval(cfg), log.Default())
	c.OnFailure(func(error) { metrics.HSMAuditCollectionFailures.Inc() })

	log.Printf("HSM audit collection enabled (device %s, anchor %s, interval %s)",
		st.DeviceSerial, st.Anchor, hsmAuditInterval(cfg))
	elector.Register("hsm-audit-collector", func(ctx context.Context) {
		c.Run(ctx)
	})
}

// hsmAuditInterval resolves the drain cadence. The default is deliberately
// brisk relative to the 62-entry ring: at one entry per signature plus session
// overhead, a busy CA can fill it in well under a minute, and a full ring stops
// issuance outright.
func hsmAuditInterval(cfg *config.Config) time.Duration {
	if s := cfg.YubiHSM.AuditCollectIntervalSeconds; s > 0 {
		return time.Duration(s) * time.Second
	}
	return 15 * time.Second
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
		return // already reported by setupHSMAuditCollector
	}

	ts, err := buildFreshnessTimestamper(cfg, authority)
	if err != nil {
		log.Printf("WARNING: HSM audit freshness attestation is off: %v. "+
			"Exported audit bundles will not be able to prove they are current.", err)
		return
	}

	dev := hsmaudit.NewShellDevice(hsm.Config{
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

// installSignatureRecorder enables ledger recording when the attached device has
// been commissioned for audited operation.
func installSignatureRecorder(db *database.DB) {
	rec, err := hsmaudit.EnableRecording(context.Background(), db)
	if err != nil {
		log.Printf("WARNING: could not read HSM audit state, signature-ledger recording is off: %v", err)
		return
	}
	if rec != nil {
		log.Printf("HSM signature-ledger recording enabled: every signature is recorded for audit reconciliation")
	}
	signatureRecorder = rec
}

// recordHSMSignatures wraps p so every signature it produces is written to the
// tamper-evident signature ledger.
//
// This is the chokepoint that gives the device log something to be reconciled
// against: the log says how many signatures a key made, the ledger says which
// ones they were. Wrapping at the provider means CA issuance, CRL and OCSP
// signing, the TSA, the SSH CA, SVIDs, artifact signing and every background
// job are covered without each having to know the audit subsystem exists — and
// so is code added later.
func recordHSMSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	return keyprovider.Record(p, signatureRecorder)
}
