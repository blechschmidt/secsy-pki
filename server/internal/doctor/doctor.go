// Package doctor implements the read-only preflight diagnostic suite behind
// `secsy-ca doctor`. It inspects a node's effective configuration and its
// dependencies — key providers (PKCS#11 HSM / HA token sets / cloud KMS /
// software keystore), the persistence backend, the tamper-evident audit chain,
// certificate expiry headroom, CRL freshness, clock sanity, and the listener
// TLS material — and reports one pass/warn/fail/skip Result per check.
//
// Invariants:
//
//   - Read-only. The suite never generates keys, issues certificates, writes
//     rows, or applies schema migrations (the store is opened via
//     database.OpenExisting). The only crypto performed is sign/verify
//     self-tests against existing keys, which prove the key is usable without
//     any private material leaving the provider — respecting the
//     non-extractability invariant from the security review.
//   - Reuse over re-implementation. Connectivity probes go through
//     keyprovider.Prober, HA token health through the PKCS11HAProvider's own
//     probing Ping, chain verification through audit.VerifyChain, and the
//     deep store check through database.VerifyStoreIntegrity — the same code
//     paths the server and `secsy-ca db verify` trust.
//   - A broken dependency degrades to skips, not a crash: checks that need
//     the config or the database report skip with the reason when their
//     prerequisite failed, so the report always covers the full check list.
package doctor

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// LDAPProber is the narrow view of the directory authenticator the auth.ldap
// check uses: a log-safe description and a read-only connectivity/bind probe.
// *authn.LDAPAuthenticator satisfies it; keeping it an interface avoids a doctor
// dependency on the authn package.
type LDAPProber interface {
	// Describe returns a short, credential-free description of the directory target.
	Describe() string
	// Probe verifies reachability, TLS negotiation, and (for search-then-bind) the
	// service-account bind. It performs no end-user authentication.
	Probe(ctx context.Context) error
}

// Status classifies the outcome of one diagnostic check.
type Status string

const (
	// StatusPass means the check completed and the invariant holds.
	StatusPass Status = "pass"
	// StatusWarn means the node is operational but needs attention soon
	// (expiring certificate, unknown config key, degraded HA set, …).
	StatusWarn Status = "warn"
	// StatusFail means the node is broken or will refuse to start/serve.
	StatusFail Status = "fail"
	// StatusSkip means the check did not apply (feature disabled) or could not
	// run because a prerequisite check failed; the detail says which.
	StatusSkip Status = "skip"
)

// Result is the outcome of a single named check.
type Result struct {
	// Name identifies the check, dotted by area (e.g. "keyprovider.ca").
	Name string `json:"name"`
	// Status is the pass/warn/fail/skip classification.
	Status Status `json:"status"`
	// Detail is a one-line human explanation of the outcome.
	Detail string `json:"detail"`
	// ElapsedMS is how long the check took, for spotting slow dependencies.
	ElapsedMS int64 `json:"elapsed_ms"`
}

// Summary counts results by status.
type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Report is the full outcome of a doctor run.
type Report struct {
	// CheckedAt is when the run started (UTC).
	CheckedAt time.Time `json:"checked_at"`
	// ConfigPath is the config file the run diagnosed.
	ConfigPath string `json:"config_path"`
	// Checks are the individual results in execution order.
	Checks []Result `json:"checks"`
	// Summary counts the results by status.
	Summary Summary `json:"summary"`
	// OK is true when no check failed (warnings do not clear it to false).
	OK bool `json:"ok"`
}

// Exit codes for CI consumption: distinct, stable, and documented in the
// runbook. A warning exits non-zero-but-distinct so a pipeline can choose to
// tolerate warnings (`secsy-ca doctor || [ $? -eq 2 ]`) or not.
const (
	ExitOK   = 0 // every check passed or was skipped
	ExitFail = 1 // at least one check failed
	ExitWarn = 2 // no failures, but at least one warning
)

// ExitCode maps the report onto the CI-friendly exit codes above.
func (r *Report) ExitCode() int {
	if r.Summary.Fail > 0 {
		return ExitFail
	}
	if r.Summary.Warn > 0 {
		return ExitWarn
	}
	return ExitOK
}

// add records a result and updates the summary.
func (r *Report) add(res Result) {
	r.Checks = append(r.Checks, res)
	switch res.Status {
	case StatusPass:
		r.Summary.Pass++
	case StatusWarn:
		r.Summary.Warn++
	case StatusFail:
		r.Summary.Fail++
		r.OK = false
	case StatusSkip:
		r.Summary.Skip++
	}
}

// Options configures a doctor run. The zero value is not usable: ConfigPath
// and BuildProvider are required; every threshold has a sensible default
// applied by Run.
type Options struct {
	// ConfigPath is the config file to diagnose (the same file the server and
	// secsy-ca run from).
	ConfigPath string

	// BuildProvider constructs the key-provider backend for a signing role
	// ("ca", "tsa", "signing"), exactly as the caller's server/CLI would.
	// Injecting it keeps provider-construction glue (YubiHSM connector files,
	// settings mapping) in one place — the caller — rather than duplicated
	// here. Required.
	BuildProvider func(cfg *config.Config, role string) (keyprovider.Provider, error)

	// BuildPinSources constructs the PKCS#11 PIN source(s) from config (the shared
	// pkcs11.pin_source plus any per-token overrides), so the "pin.source" check
	// can probe each external source for reachability. Injected by the caller,
	// which owns the config→keyprovider settings mapping. Optional: when nil the
	// pin.source check is skipped.
	BuildPinSources func(cfg *config.Config) ([]keyprovider.NamedPinSource, error)

	// BuildLDAP constructs a directory prober from config, so the "auth.ldap" check
	// can verify the LDAP/AD server is reachable, TLS is negotiated, and the
	// service-account bind succeeds. Injected by the caller, which owns the
	// config→authn mapping (including the bind-password credential source and TLS
	// trust material). Optional: when nil the auth.ldap check is skipped.
	BuildLDAP func(cfg *config.Config) (LDAPProber, error)

	// ExpiryWarn / ExpiryFail are the certificate-expiry headroom thresholds:
	// a certificate expiring within ExpiryFail fails, within ExpiryWarn warns.
	// Defaults: 7 and 30 days.
	ExpiryWarn time.Duration
	ExpiryFail time.Duration

	// AuditSample is the maximum number of newest audit events whose chain is
	// re-verified by the sampled head check. Default 1000. The -deep mode
	// additionally verifies the whole chain from the genesis entry.
	AuditSample int

	// SkewWarn / SkewFail are the acceptable clock offsets between this host
	// and the database server before the clock check warns/fails. Defaults:
	// 10s and 60s.
	SkewWarn time.Duration
	SkewFail time.Duration

	// DialTimeout bounds the live listener probe. Default 3s.
	DialTimeout time.Duration

	// SkipListener disables the live TLS handshake against the configured
	// listener address (the static certificate/key checks still run).
	SkipListener bool

	// Deep additionally runs the full store-integrity verification
	// (database.VerifyStoreIntegrity — the `secsy-ca db verify` gate) and the
	// full audit-chain walk. Reads the entire event log; may be slow on very
	// large stores.
	Deep bool
}

func (o *Options) applyDefaults() {
	if o.ExpiryWarn <= 0 {
		o.ExpiryWarn = 30 * 24 * time.Hour
	}
	if o.ExpiryFail <= 0 {
		o.ExpiryFail = 7 * 24 * time.Hour
	}
	if o.AuditSample <= 0 {
		o.AuditSample = 1000
	}
	if o.SkewWarn <= 0 {
		o.SkewWarn = 10 * time.Second
	}
	if o.SkewFail <= 0 {
		o.SkewFail = 60 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 3 * time.Second
	}
}

// run executes one named check, timing it and recording its result.
func (r *Report) run(name string, fn func() (Status, string)) {
	start := time.Now()
	status, detail := fn()
	res := Result{Name: name, Status: status, Detail: detail, ElapsedMS: time.Since(start).Milliseconds()}
	r.add(res)
}

// skip records a skipped check with a reason.
func (r *Report) skip(name, reason string) {
	r.add(Result{Name: name, Status: StatusSkip, Detail: reason})
}

// Run executes the full diagnostic suite and returns the report. It never
// returns an error: every failure mode is expressed as a check result so the
// caller always gets the complete table. All resources (providers, database
// handles) are closed before it returns.
func Run(ctx context.Context, opts Options) *Report {
	opts.applyDefaults()
	r := &Report{CheckedAt: time.Now().UTC(), ConfigPath: opts.ConfigPath, OK: true}

	// 1. Configuration: parse + validation, then strict unknown-key lint.
	cfg := checkConfig(r, opts.ConfigPath)
	if cfg == nil {
		// Without a loadable config nothing else can be diagnosed; emit the
		// remaining checks as skips so the report shape is stable for CI.
		for _, name := range []string{
			"db.connectivity", "db.schema", "keyprovider.ca", "pin.source", "auth.ldap", "pkcs11.uris", "keys.ca",
			"audit.chain_head", "certs.ca_expiry", "crl.freshness",
			"canary.last_probe", "ct.inclusion", "webhook.dead_letters",
			"keychecks.blocklist", "keychecks.profiles", "clock.skew",
			"serving.self_issued", "listener.tls",
			"fips.mode", "fips.store_keys", "fips.secret_oaep",
		} {
			r.skip(name, "config did not load")
		}
		return r
	}

	// 2. Key providers per signing role: reachability (module/slot/PIN for
	// PKCS#11, credentials for cloud KMS), plus per-token HA health.
	providers := checkProviders(ctx, r, cfg, opts)
	defer providers.closeAll()

	// 2b. External PIN source: prove the credential store backing the PKCS#11 user
	// PIN is reachable and yields a PIN, so a plaintext-free PIN configuration is
	// verified before the HSM actually needs it.
	checkPinSources(ctx, r, cfg, opts)

	// 2d. LDAP / Active Directory operator authentication: prove the directory is
	// reachable, TLS is negotiated (fail-closed), and the service-account bind
	// succeeds, so a misconfigured directory is caught before an operator is locked
	// out at login.
	checkLDAP(ctx, r, cfg, opts)

	// 3. Database: connectivity without migrating, then pending-migration
	// (missing table) detection.
	db, schemaOK := checkDatabase(r, cfg)
	if db != nil {
		defer func() { _ = db.Close() }()
	}

	// 3b. PKCS#11 URI addressing: parse every configured RFC 7512 pkcs11: URI (the
	// config module/token URIs and each CA's stored key URI) and resolve each CA
	// key on the token, validating full object/id/token addressing.
	checkPKCS11URIs(ctx, r, cfg, db, schemaOK, providers)

	// 4. Role keys: a sign/verify self-test per configured key, against the
	// exact provider and label the runtime would use.
	checkRoleKeys(ctx, r, cfg, db, schemaOK, providers)

	// 5. Audit chain: sampled head verification (and the full walk with -deep).
	checkAuditChain(r, db, schemaOK, opts)

	// 6. Certificate expiry headroom: CA certificates from the store, TSA and
	// code-signing certificates from their configured PEM files.
	checkCertExpiry(r, cfg, db, schemaOK, opts)

	// 7. CRL freshness against nextUpdate.
	checkCRLFreshness(r, cfg, db, schemaOK)

	// 7b. Issuance canary: the newest canary.probe outcome per probed CA.
	checkCanary(r, cfg, db, schemaOK)

	// 7c. Scheduled encrypted backup: freshness of the newest backup.run.
	checkBackup(r, cfg, db, schemaOK)

	// 7c′. Automated restore-verification: freshness of the newest backup.verify —
	// proof the newest backup can actually be restored (an untested backup is not
	// a backup).
	checkBackupRestoreVerified(r, cfg, db, schemaOK)

	// 7c″. Certificate-inventory retention: freshness of the newest
	// inventory.retention run (Task 157) — a stalled retention job means a
	// high-volume CA's issued_certificates table grows unbounded.
	checkRetention(r, cfg, db, schemaOK)

	// 7d. CT SCT inclusion monitor: standing inclusion state and scan freshness.
	checkCTInclusion(r, cfg, db, schemaOK)

	// 7e. Outbound webhook dead-letters: deliveries that exhausted their retry
	// budget and need operator triage (a paused endpoint, a wrong URL/secret).
	checkWebhookDeadLetters(r, cfg, db, schemaOK)

	// 7f. Pre-issuance key-quality gate (Task 120): the Debian weak-key blocklist
	// loads, the operator compromised-key blocklist size, and any profile that has
	// weakened the fail-closed gate.
	checkKeyChecks(r, cfg, db, schemaOK)

	// 7g. Post-quantum hybrid KEK wrapping (Task 137): when secret.pqc_hybrid is
	// enabled every KEK family has ML-KEM material, and any provisioned material
	// unseals and round-trips.
	checkPQCHybrid(ctx, r, cfg, db, schemaOK, providers)

	// 8. Clock-skew sanity against the database host and the audit head.
	checkClockSkew(ctx, r, db, schemaOK, opts)

	// 8f. Self-managed serving-TLS certificate freshness (Task 118): the newest
	// serving-tls-marked record, flagged when inside its renew_before window.
	checkServingCert(r, cfg, db, schemaOK, opts)

	// 9. Listener TLS: static certificate/key material plus, when reachable, a
	// live handshake against the configured address.
	checkListenerTLS(r, cfg, opts)

	// 10. FIPS 140-3 posture (only meaningful with security.fips): module state,
	// store key-material policy conformance, and the secret-layer SHA-256 OAEP
	// negotiation the policy requires.
	checkFIPS(ctx, r, cfg, db, schemaOK, providers)

	return r
}

// roleProviders tracks one constructed provider per distinct backend type, so
// roles sharing a backend share the instance (and its session pool).
type roleProviders struct {
	byRole map[string]keyprovider.Provider // role -> provider (may alias)
	owned  []keyprovider.Provider          // distinct instances to close
}

func (p *roleProviders) get(role string) keyprovider.Provider {
	if p == nil {
		return nil
	}
	return p.byRole[role]
}

func (p *roleProviders) closeAll() {
	if p == nil {
		return
	}
	for _, prov := range p.owned {
		_ = prov.Close()
	}
}

// rolesInUse returns the signing roles the configuration actually exercises,
// always including "ca" (the CA key provider also backs OCSP responder keys
// and the secret-envelope KEK).
func rolesInUse(cfg *config.Config) []string {
	roles := []string{"ca"}
	if cfg.TSA.Enabled || cfg.TSA.KeyLabel != "" {
		roles = append(roles, "tsa")
	}
	if cfg.Signing.Enabled || len(cfg.Signing.Signers) > 0 {
		roles = append(roles, "signing")
	}
	return roles
}

// sortedKeys returns map keys in stable order for deterministic details.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// plural returns "s" for counts other than one, for terse detail strings.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// humanDuration renders a duration in the largest useful unit for details.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0fh", d.Hours())
	case d >= 2*time.Minute:
		return fmt.Sprintf("%.0fm", d.Minutes())
	default:
		return d.Round(time.Millisecond).String()
	}
}

// dbHandle is the narrow view of the store the checks use; *database.DB
// satisfies it. Narrowing it keeps each check's dependency explicit and lets
// unit tests stub the store where useful.
type dbHandle = *database.DB
