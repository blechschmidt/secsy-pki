package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/brski"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/canary"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/cmp"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/ctmonitor"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/discovery"
	"github.com/blechschmidt/secsy-pki/server/internal/est"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/issueapproval"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/mailtransport"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/mswstep"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/ratelimit"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/scep"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
	"github.com/blechschmidt/secsy-pki/server/internal/servingcert"
	"github.com/blechschmidt/secsy-pki/server/internal/siem"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
	"github.com/blechschmidt/secsy-pki/server/internal/timesource"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"

	"github.com/google/uuid"
)

// version is the release version, stamped by the linker (-X main.version) in
// release/container builds; "dev" otherwise. Reported by -version, the startup
// log, and the /healthz build block.
var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and FIPS 140-3 mode, then exit")
	flag.Parse()

	if *showVersion {
		// Machine-checkable one-liner: `make build-fips` and the FIPS container
		// build grep it for "fips140=on" to verify the binary really runs on the
		// Go Cryptographic Module.
		fmt.Printf("secsy-pki-server %s %s %s\n", version, runtime.Version(), fips.Summary())
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Report the FIPS 140-3 posture up front: whether the Go Cryptographic
	// Module is active (build/GODEBUG) and whether the fail-closed security.fips
	// algorithm policy is enforced (config, mirrored by config.Load). A policy
	// without the module is a legitimate rehearsal configuration but not a FIPS
	// deployment, so it warns loudly.
	handlers.SetBuildVersion(version)
	log.Printf("FIPS 140-3: %s", fips.Summary())
	if cfg.Security.FIPS && !fips.ModuleEnabled() {
		log.Printf("WARNING: security.fips is enforced but this binary is not running on the Go FIPS 140-3 module; build with `make build-fips` (GOFIPS140) or set GODEBUG=fips140=on")
	}

	// OpenTelemetry distributed tracing. Installs the global TracerProvider and
	// W3C propagator so the request middleware and the CA/HSM/store hot paths emit
	// spans. Disabled by default: with tracing.enabled=false this installs a no-op
	// tracer and starts no exporter. The Shutdown flushes buffered spans on a
	// graceful exit.
	traceProvider, err := tracing.Init(context.Background(), tracingConfig(cfg))
	if err != nil {
		log.Fatalf("Failed to initialize tracing: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := traceProvider.Shutdown(shutdownCtx); err != nil {
			log.Printf("WARNING: tracing shutdown: %v", err)
		}
	}()
	if cfg.Tracing.Enabled {
		log.Printf("OpenTelemetry tracing enabled (endpoint=%s protocol=%s sample_ratio=%v)",
			cfg.Tracing.Endpoint, cfg.Tracing.Protocol, cfg.Tracing.SampleRatio)
	}

	db, err := database.NewWithOptions(cfg.Database.Driver, cfg.Database.DSN, database.PoolOptions{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.Database.ConnMaxLifetimeSecs) * time.Second,
		ConnMaxIdleTime: time.Duration(cfg.Database.ConnMaxIdleTimeSecs) * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Enable HSM signature-ledger recording before any key provider is built
	// (Task 167), so no role's provider is constructed without the hook and every
	// signature the process produces is accounted for.
	installSignatureRecorder(db)

	// Multi-replica coordination (Task 68): the singleton background jobs
	// registered below (expiry monitor/auto-renewal + CA rotation, discovery
	// scans, OCSP pre-signing, CRL regeneration/publishing, SIEM export, audit
	// anchoring) run only on the elected leader, so the server is safe to run
	// with replicas > 1 against a shared PostgreSQL. On SQLite the elector
	// resolves to static single-node leadership and the jobs start at boot
	// exactly as before. The elector holds a session-level advisory lock on its
	// own dedicated connection; jobs start when it is acquired and stop when it
	// is lost.
	elector, err := leader.New(leader.Config{
		Mode:          cfg.Coordination.Mode,
		Driver:        cfg.Database.Driver,
		DSN:           cfg.Database.DSN,
		LockName:      cfg.Coordination.LockName,
		RenewInterval: time.Duration(cfg.Coordination.RenewIntervalSeconds) * time.Second,
		RetryInterval: time.Duration(cfg.Coordination.RetryIntervalSeconds) * time.Second,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("Coordination configuration error: %v", err)
	}

	// Initialize OIDC provider (optional - may fail if no OIDC configured)
	var oidcProvider *auth.OIDCProvider
	if cfg.OIDC.IssuerURL != "" {
		oidcProvider, err = auth.NewOIDCProvider(
			cfg.OIDC.IssuerURL,
			cfg.OIDC.ClientID,
		)
		if err != nil {
			log.Printf("WARNING: OIDC provider initialization failed: %v", err)
			log.Printf("Only root user (basic auth) will be available")
		}
	} else {
		log.Printf("OIDC not configured - only root user (basic auth) will be available")
	}

	authMw := middleware.NewAuthMiddleware(oidcProvider, cfg.RootUser.Username, cfg.RootUser.Password)

	// RBAC: build the central role assignments and install a resolver so every
	// authenticated OIDC subject carries its organization-wide roles. Assignments
	// may be keyed by OIDC subject or by email; group-derived roles are unioned in.
	rbacAssignments := rbac.NewAssignments(toRoleMap(cfg.RBAC.Subjects), toRoleMap(cfg.RBAC.Groups))

	// Multi-tenant isolation (Task 43): provision the tenants declared in config
	// (idempotent), and build the per-tenant RBAC assignments layered over the
	// platform-wide ones above. The top-level rbac block grants PLATFORM roles
	// (spanning all tenants); each tenant's rbac block grants roles ONLY within
	// that tenant.
	if err := provisionTenants(db, cfg.Tenants); err != nil {
		log.Fatalf("Provisioning tenants: %v", err)
	}
	byTenant := make(map[string]*rbac.Assignments, len(cfg.Tenants))
	for _, tc := range cfg.Tenants {
		byTenant[tc.ID] = rbac.NewAssignments(toRoleMap(tc.RBAC.Subjects), toRoleMap(tc.RBAC.Groups))
	}
	tenantAssignments := rbac.NewTenantAssignments(rbacAssignments, byTenant)

	// Per-tenant S/MIME e-mail domain scoping (Task 66): certificates minted by
	// a tenant's CAs under an S/MIME profile may only certify these domains.
	tenantEmailDomains := make(map[string][]string)
	for _, tc := range cfg.Tenants {
		if len(tc.AllowedEmailDomains) > 0 {
			tenantEmailDomains[tc.ID] = tc.AllowedEmailDomains
		}
	}
	if err := ca.SetTenantEmailDomains(tenantEmailDomains); err != nil {
		log.Fatalf("Invalid tenant allowed_email_domains: %v", err)
	}

	// Per-tenant UPN realm scoping (Task 122): certificates minted by a tenant's
	// CAs under a smartcard-logon / PKINIT profile may only certify these realms.
	tenantUPNRealms := make(map[string][]string)
	for _, tc := range cfg.Tenants {
		if len(tc.AllowedUPNRealms) > 0 {
			tenantUPNRealms[tc.ID] = tc.AllowedUPNRealms
		}
	}
	if err := ca.SetTenantUPNRealms(tenantUPNRealms); err != nil {
		log.Fatalf("Invalid tenant allowed_upn_realms: %v", err)
	}

	authMw.SetRoleResolver(func(u *models.UserInfo) []string {
		groupIDs, _ := db.GetUserGroups(u.Subject)
		return dedupRoles(tenantAssignments.PlatformRolesFor(u.Subject, u.Email, u.EmailVerified, groupIDs))
	})
	authMw.SetTenantRoleResolver(func(u *models.UserInfo) map[string][]string {
		groupIDs, _ := db.GetUserGroups(u.Subject)
		out := make(map[string][]string)
		for _, tid := range tenantAssignments.Tenants() {
			roles := tenantAssignments.TenantRolesFor(tid, u.Subject, u.Email, u.EmailVerified, groupIDs)
			if len(roles) > 0 {
				out[tid] = dedupRoles(roles)
			}
		}
		return out
	})
	authMw.SetRootEnabled(cfg.Policy.RootBasicAuthEnabled())
	if !cfg.Policy.RootBasicAuthEnabled() {
		log.Printf("Built-in root basic-auth login is DISABLED (policy.allow_root_basic_auth=false)")
	}

	// Native scoped API tokens / service accounts (Task 86): install the token
	// authenticator so machine callers can authenticate with a revocable,
	// role/tenant-scoped credential under a distinct Authorization scheme.
	authMw.SetTokenAuthenticator(authn.NewTokenAuthenticator(db))
	if !rbacAssignments.Empty() {
		log.Printf("RBAC role assignments loaded (subjects=%d, groups=%d)", len(cfg.RBAC.Subjects), len(cfg.RBAC.Groups))
	}
	if len(cfg.Tenants) > 0 {
		log.Printf("Multi-tenant mode: %d tenant(s) provisioned from config", len(cfg.Tenants))
	}

	// Install the Certificate Transparency log registry (RFC 6962). Profiles opt
	// in to CT per-profile and reference these logs by name.
	ctSubmitter, err := buildCTSubmitter(cfg.CertificateTransparency)
	if err != nil {
		log.Fatalf("Invalid certificate_transparency config: %v", err)
	}
	if ctSubmitter != nil {
		ca.SetCTSubmitter(ctSubmitter)
		log.Printf("Certificate Transparency enabled with %d log(s): %v",
			len(ctSubmitter.LogNames()), ctSubmitter.LogNames())
	}

	// Install the optional Debian OpenSSL / operator weak-key blocklist consulted
	// by the fail-closed pre-issuance key-quality gate (Task 120). A configured
	// path that cannot be loaded is fatal, so a typo fails closed at startup rather
	// than silently disabling the check.
	if paths := cfg.KeyChecks.WeakKeyBlocklistPaths; len(paths) > 0 {
		bl, err := keycheck.LoadBlocklist(paths...)
		if err != nil {
			log.Fatalf("Invalid keychecks.weak_key_blocklist_paths: %v", err)
		}
		ca.SetWeakKeyBlocklist(bl)
		log.Printf("Weak-key blocklist loaded: %d fingerprint(s) from %d source(s)", bl.Len(), len(bl.Sources()))
	}

	// Install any operator-defined certificate profiles, layered over built-ins.
	if len(cfg.Profiles) > 0 {
		profiles := make([]ca.Profile, 0, len(cfg.Profiles))
		for _, p := range cfg.Profiles {
			prof := ca.Profile{
				Name:                    p.Name,
				Description:             p.Description,
				KeyUsages:               p.KeyUsages,
				ExtKeyUsages:            p.ExtKeyUsages,
				DefaultValidityDays:     p.DefaultValidityDays,
				MaxValidityDays:         p.MaxValidityDays,
				RequireApproval:         p.RequireApproval,
				MustStaple:              p.MustStaple,
				AllowMustStapleOverride: p.AllowMustStapleOverride,
			}
			if p.CT.Enabled {
				if ctSubmitter == nil {
					log.Fatalf("Profile %q enables certificate transparency but no CT logs are configured", p.Name)
				}
				for _, name := range p.CT.Logs {
					if !ctSubmitter.Has(name) {
						log.Fatalf("Profile %q references unknown CT log %q", p.Name, name)
					}
				}
				prof.CT = &ca.CTConfig{
					Enabled:              true,
					Logs:                 p.CT.Logs,
					MinSCTs:              p.CT.MinSCTs,
					MinDistinctOperators: p.CT.MinDistinctOperators,
					RequireOperators:     p.CT.RequireOperators,
					FailOpen:             p.CT.FailOpen,
					TimeoutSeconds:       p.CT.TimeoutSeconds,
					Retries:              p.CT.Retries,
				}
				// An operator-diversity policy can only be enforced when every log
				// it might submit to has a resolved operator. Validate at startup so
				// a policy that could never be satisfied (or would silently
				// under-count) fails loudly here rather than at issuance time.
				if p.CT.MinDistinctOperators > 0 || len(p.CT.RequireOperators) > 0 {
					if err := validateCTOperatorPolicy(p.Name, p.CT, ctSubmitter); err != nil {
						log.Fatalf("%v", err)
					}
				}
			}
			prof.Lint = &ca.LintConfig{
				Disabled:          p.Lint.Disabled,
				Mode:              p.Lint.Mode,
				Public:            p.Lint.Public,
				RequireMustStaple: p.Lint.RequireMustStaple,
				Overrides:         p.Lint.Overrides,
				ZLint:             zlintConfig(p.Lint.ZLint),
			}
			if p.Lint.ZLint.Enabled && !certlint.ZLintAvailable() {
				log.Printf("WARNING: profile %q enables the zlint backend, but this binary was not built with -tags zlint; "+
					"only the hand-rolled Baseline Requirements checks will run", p.Name)
			}
			if mode := strings.ToLower(strings.TrimSpace(p.CAA.Mode)); mode != "" && mode != "off" {
				identifier := p.CAA.Identifier
				if identifier == "" {
					identifier = cfg.CAA.Identifier
				}
				if mode == "enforce" && identifier == "" {
					log.Fatalf("Profile %q enables CAA enforcement but no CA identifier is configured (set caa.identifier)", p.Name)
				}
				prof.CAA = &ca.CAAConfig{
					Mode:           mode,
					Identifier:     identifier,
					TimeoutSeconds: p.CAA.TimeoutSeconds,
				}
			}
			if len(p.Policies.OIDs) > 0 || len(p.Policies.Mappings) > 0 {
				prof.Policies = &certpolicy.PolicyConfig{
					OIDs:     p.Policies.OIDs,
					CPS:      p.Policies.CPS,
					Critical: p.Policies.Critical,
					Mappings: p.Policies.Mappings,
				}
			}
			if p.SMIME.Enabled {
				prof.SMIME = &ca.SMIMEConfig{
					Variant:        p.SMIME.Variant,
					BRProfile:      p.SMIME.BRProfile,
					AllowedDomains: p.SMIME.AllowedDomains,
					SubjectEmail:   p.SMIME.SubjectEmail,
				}
			}
			if p.UPN.Enabled {
				prof.UPN = &ca.UPNConfig{
					AllowedRealms: p.UPN.AllowedRealms,
					RequireUPN:    p.UPN.RequireUPN,
				}
			}
			prof.KeyChecks = keyChecksConfig(p.KeyChecks)
			profiles = append(profiles, prof)
		}
		if err := ca.SetCustomProfiles(profiles); err != nil {
			log.Fatalf("Invalid custom certificate profile: %v", err)
		}
		log.Printf("Loaded %d custom certificate profile(s)", len(profiles))
	}

	// Install any operator-defined SSH signing profiles (Task 57), layered over
	// the built-in user-default/host-default profiles.
	if len(cfg.SSH.Profiles) > 0 {
		sshProfiles, err := sshProfilesFromConfig(cfg.SSH.Profiles)
		if err != nil {
			log.Fatalf("Invalid ssh profile: %v", err)
		}
		if err := sshca.SetCustomProfiles(sshProfiles); err != nil {
			log.Fatalf("Invalid ssh profile: %v", err)
		}
		log.Printf("Loaded %d custom SSH signing profile(s)", len(sshProfiles))
	}

	// Install the DNS resolver backing the CAA pre-issuance gate when any profile
	// enables it. The resolver is wrapped in a TTL cache shared across requests. A
	// profile enforcing CAA cannot run without a resolver, so a resolver-build
	// failure is fatal only then; otherwise it is a warning.
	caaUsed, caaEnforced := false, false
	for _, p := range cfg.Profiles {
		if mode := strings.ToLower(strings.TrimSpace(p.CAA.Mode)); mode != "" && mode != "off" {
			caaUsed = true
			if mode == "enforce" {
				caaEnforced = true
			}
		}
	}
	if caaUsed {
		sysResolver, err := caa.NewSystemResolver()
		if err != nil {
			if caaEnforced {
				log.Fatalf("CAA enforcement is enabled but no DNS resolver is available: %v", err)
			}
			log.Printf("WARNING: CAA is configured (permissive) but no DNS resolver is available: %v", err)
		} else {
			ttl := time.Duration(cfg.CAA.CacheTTLSeconds) * time.Second
			ca.SetCAAResolver(caa.NewCachingResolver(sysResolver, ttl))
			log.Printf("CAA pre-issuance gate enabled (enforce=%v)", caaEnforced)
		}
	}

	// Install the CRL distribution policy (delta CRLs + partitioning, RFC 5280).
	// The base URL for CDP/IDP/Freshest-CRL links falls back to the ACME base URL
	// when unset, since both name the same externally reachable origin.
	crlBaseURL := cfg.CRL.BaseURL
	if crlBaseURL == "" {
		crlBaseURL = cfg.ACME.BaseURL
	}
	ca.SetCRLConfig(ca.CRLDistConfig{
		Shards:        cfg.CRL.Shards,
		BaseURL:       crlBaseURL,
		BaseValidity:  time.Duration(cfg.CRL.BaseValidityHours) * time.Hour,
		DeltaValidity: time.Duration(cfg.CRL.DeltaIntervalMinutes) * time.Minute,
	})
	if cfg.CRL.Shards >= 2 {
		log.Printf("CRL partitioning enabled: %d shards (base URL %q)", cfg.CRL.Shards, crlBaseURL)
	}

	// Ensure YUBIHSM_PKCS11_CONF is set so the YubiHSM PKCS#11 module knows the connector URL
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err != nil {
			log.Printf("WARNING: failed to write %s: %v", confPath, err)
		} else {
			_ = os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}

	// The primary provider serves the CA role: CA-key signing, OCSP responder
	// keys, ACME/SCEP/EST/CMP issuance, and the secret KEK. Its backend is the
	// CA-role type (key_provider.roles.ca), falling back to the global type.
	provider, err := buildRoleProvider(cfg, "ca")
	if err != nil {
		log.Fatalf("Failed to initialize key provider: %v", err)
	}
	defer provider.Close()
	log.Printf("Key provider (ca role): %s", provider.Name())

	// The TSA may sign with a different backend than the CA (e.g. CA on a PKCS#11
	// HSM, TSA in AWS KMS). When the resolved backend matches the CA role, reuse
	// the primary provider so a single HSM session pool / KMS client is shared.
	tsaProvider := provider
	if cfg.KeyProviderTypeForRole("tsa") != cfg.KeyProviderTypeForRole("ca") {
		tp, terr := buildRoleProvider(cfg, "tsa")
		if terr != nil {
			log.Fatalf("Failed to initialize TSA key provider: %v", terr)
		}
		defer tp.Close()
		tsaProvider = tp
		log.Printf("Key provider (tsa role): %s", tsaProvider.Name())
	}

	// Artifact code-signing keys (Task 60) may likewise live on a dedicated
	// backend (key_provider.roles.signing).
	signingProvider := provider
	if cfg.Signing.Enabled && cfg.KeyProviderTypeForRole("signing") != cfg.KeyProviderTypeForRole("ca") {
		sp, serr := buildRoleProvider(cfg, "signing")
		if serr != nil {
			log.Fatalf("Failed to initialize signing key provider: %v", serr)
		}
		defer sp.Close()
		signingProvider = sp
		log.Printf("Key provider (signing role): %s", signingProvider.Name())
	}

	hsmCfg := hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	}

	api := handlers.NewAPI(db, provider, oidcProvider, hsmCfg, cfg.YubiHSM.SuppressAuditWarning, cfg.Secret.KEKLabel)
	// Wire the operator live audit-event feed (Task 90/104): the audit-append
	// chokepoint fans every hash-chained event out to the SSE subscribers so the
	// console live-tail sees events from HTTP handlers, background jobs, and
	// protocol servers alike. The Publisher is non-blocking (drop-oldest on a slow
	// reader), so this cannot stall the append hot path.
	db.SetEventHook(api.EventPublisher().Publish)
	api.SetPolicy(handlers.Policy{
		RequireReason:       cfg.Policy.RequireReason,
		MaxCertValidityDays: cfg.Policy.MaxCertValidityDays,
	})
	// Post-quantum hybrid KEK wrapping for the secret layer (Task 137): seal new
	// envelopes with an additional ML-KEM-1024 encapsulation for KEK families
	// that have ML-KEM material provisioned.
	api.SetPQCHybrid(cfg.Secret.PQCHybrid)
	// Format-preserving encryption / tokenization templates (Task 144): resolve the
	// configured FF1 transforms once at startup (config validation already proved
	// they resolve) and install them so the transform endpoints can serve them.
	transforms, terr := cfg.Secret.ResolveTransforms()
	if terr != nil {
		log.Fatalf("Failed to resolve secret.transforms: %v", terr)
	}
	api.SetTransformTemplates(transforms)
	// Four-eyes / maker-checker approval gate (Task 81): construct the engine over
	// the shared store (which is both the Store and the audit Auditor) and install
	// it so the guarded operations (CA creation/rotation/retirement, bulk
	// revocation) become fail-closed chokepoints. The policy governs enforcement,
	// so installing unconditionally is safe — a disabled policy is a no-op gate.
	approvalEngine := approval.NewEngine(db, db, approval.Policy{
		Enabled:          cfg.Approvals.Enabled,
		DefaultThreshold: cfg.Approvals.ApprovalDefaultThreshold(),
		Thresholds:       cfg.Approvals.Thresholds,
		TTL:              cfg.Approvals.ApprovalTTL(),
	})
	// Emit the cert.issue.denied domain event + metric whenever a per-profile
	// issuance approval (Task 84) is rejected or expires, regardless of the
	// transport that triggered it (including the background expiry sweep below).
	approvalEngine.SetTerminalHook(issueapproval.NewTerminalHook(db))
	api.SetApprovals(approvalEngine)
	// Native scoped API tokens (Task 86): apply the lifetime policy and seed the
	// active-token gauge from the store so the metric is correct from startup.
	api.SetAPITokenMaxLifetime(cfg.Auth.APITokenMaxLifetime())
	if n, err := db.CountActiveAPITokens(); err == nil {
		metrics.SetAuthTokensActive(n)
	}
	// Expire stale approval requests on a leader-elected background loop (a
	// singleton job, like the other periodic sweeps). Expiry is also enforced
	// fail-closed at read time in the engine, so this is hygiene, not correctness.
	if cfg.Approvals.Enabled {
		elector.Register("approval-expiry", func(ctx context.Context) {
			approvalExpiryLoop(ctx, approvalEngine, log.Default())
		})
	}
	monitorOpts := monitor.OptionsFromDays(
		cfg.Monitor.WarningDays, cfg.Monitor.CriticalDays,
		cfg.Monitor.RenewBeforeDays, cfg.Monitor.RenewProfiles)
	// When SPIFFE is enabled, teach the monitor which profile mints SVIDs so it
	// renews them aggressively on a fraction of their (short) lifetime rather than
	// the absolute, day-scale renew-before window.
	if cfg.SPIFFE.Enabled {
		monitorOpts.SVIDProfiles = []string{cfg.SPIFFE.SVIDProfileName()}
		monitorOpts.SVIDRenewFraction = cfg.SPIFFE.RenewFraction
	}
	api.SetMonitorOptions(monitorOpts)
	// Discovery API endpoints (/api/discovery, /api/discovery/scan) use the
	// configured targets/expiry window and share the monitor's notification sinks.
	api.SetDiscoveryConfig(cfg.Discovery, cfg.Monitor)
	api.SetSSHConfig(cfg.SSH.KRLComment)
	// OCSP response cache TTL: 0 keeps the server default, a negative value
	// disables caching, and a positive value sets an explicit TTL.
	if cfg.Server.OCSPCacheTTLSeconds != 0 {
		api.SetOCSPCacheTTL(time.Duration(cfg.Server.OCSPCacheTTLSeconds) * time.Second)
	}
	// OCSP responder hardening: nonce echoing (RFC 8954), delegated responder
	// certificate, and validity bounds.
	{
		oc := cfg.Server.OCSP
		nonceEnabled := true // default on
		if oc.NonceEnabled != nil {
			nonceEnabled = *oc.NonceEnabled
		}
		nonceMaxAge := 60 * time.Second
		if oc.NonceMaxAgeSeconds > 0 {
			nonceMaxAge = time.Duration(oc.NonceMaxAgeSeconds) * time.Second
		}
		delegatedValidity := time.Duration(oc.DelegatedValidityHours) * time.Hour
		api.SetOCSPPolicy(handlers.OCSPPolicy{
			NonceEnabled: nonceEnabled,
			NonceMaxAge:  nonceMaxAge,
			Delegated:    oc.Delegated,
		}, delegatedValidity, oc.DelegatedKeyType)
		if oc.Delegated {
			log.Printf("OCSP delegated responder enabled (short-lived id-kp-OCSPSigning certificate)")
		}
		if nonceEnabled {
			log.Printf("OCSP nonce echoing enabled (RFC 8954, max-age %s)", nonceMaxAge)
		}
	}
	if cfg.Secret.KEKLabel != "" {
		log.Printf("Secret encryption enabled (KEK label: %s)", cfg.Secret.KEKLabel)
	}
	if cfg.Secret.Escrow.Enabled {
		specs := make([]secret.AgentSpec, 0, len(cfg.Secret.Escrow.Agents))
		for _, ag := range cfg.Secret.Escrow.Agents {
			pemVal := ag.PublicKey
			if pemVal == "" && ag.PublicKeyFile != "" {
				b, err := os.ReadFile(ag.PublicKeyFile)
				if err != nil {
					log.Fatalf("reading escrow agent %q public_key_file: %v", ag.ID, err)
				}
				pemVal = string(b)
			}
			specs = append(specs, secret.AgentSpec{ID: ag.ID, KeyLabel: ag.KeyLabel, PublicKeyPEM: pemVal})
		}
		api.SetEscrow(cfg.Secret.Escrow.Threshold, specs)
		log.Printf("Key escrow enabled (%d-of-%d recovery agents)", cfg.Secret.Escrow.Threshold, len(specs))
	}

	// SPIFFE X.509-SVID issuance: install the trust-domain allowlist and enable
	// the /api/ca/{id}/svid + /svid/bundle endpoints. The allowlist is the RBAC
	// layer specific to SVIDs — only permitted (subject, trust-domain) pairs may
	// mint an SVID, on top of the CA's ordinary issue capability.
	if cfg.SPIFFE.Enabled {
		policy := spiffe.NewPolicy(spiffe.PolicyConfig{
			TrustDomains:        cfg.SPIFFE.TrustDomains,
			SubjectTrustDomains: cfg.SPIFFE.SubjectTrustDomains,
			RefreshHint:         cfg.SPIFFE.RefreshHint(),
			DefaultCAID:         cfg.SPIFFE.DefaultCAID,
		})
		api.SetSPIFFE(policy, cfg.SPIFFE.SVIDProfileName())
		api.SetSPIFFEJWT(cfg.SPIFFE.JWTDefaultAudience, cfg.SPIFFE.JWTDefaultTTL(), cfg.SPIFFE.JWTMaxTTL())
		log.Printf("SPIFFE X.509-SVID + JWT-SVID issuance enabled (profile %q, trust domains %v)",
			cfg.SPIFFE.SVIDProfileName(), policy.AllowedTrustDomains())
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	// Strong operator authentication (Task 50): interactive OIDC/password login
	// with claim/group -> RBAC role mapping, mutual-TLS client-certificate
	// binding, WebAuthn step-up, and the session/CSRF plumbing. Returns the client
	// CA pool to install on the TLS listener when mTLS is enabled.
	mtlsClientCAs, err := setupOperatorAuth(cfg, db, oidcProvider, tenantAssignments, authMw, api, mux)
	if err != nil {
		log.Fatalf("Operator authentication setup failed: %v", err)
	}

	// Operational endpoints: Prometheus /metrics, /healthz (liveness), /readyz
	// (readiness incl. HSM/DB probes). Unauthenticated by design — restrict at
	// the network layer if needed.
	api.RegisterObservability(mux)

	// Opt-in, access-controlled net/http/pprof profiling (Task 115). Off by
	// default; when enabled it is bound to a loopback-only listener, or mounted on
	// the API listener behind operator auth + the admin-only server:profile
	// capability — never exposed unauthenticated. It is the lever for capturing
	// CPU/heap/goroutine/mutex/block profiles in production to debug HSM latency
	// and PKCS#11 session-pool contention.
	setupPProf(cfg, authMw, api, mux)

	// gRPC API surface (Task 56): expose the core issuance/revocation/status
	// operations over gRPC alongside REST, reusing the same handlers.API and auth
	// middleware so authorization, tenant scoping, and audit behave identically.
	// It listens on its own port with the same TLS certificate (and, when mTLS is
	// enabled, the same operator client-CA pool) as the REST listener.
	if cfg.GRPC.Enabled {
		grpcTLSCert, grpcTLSKey := cfg.GRPC.TLSCert, cfg.GRPC.TLSKey
		if grpcTLSCert == "" && grpcTLSKey == "" {
			grpcTLSCert, grpcTLSKey = cfg.Server.TLSCert, cfg.Server.TLSKey
		}
		var grpcClientCAs *x509.CertPool
		if cfg.GRPC.MTLS {
			if mtlsClientCAs == nil {
				log.Fatalf("grpc.mtls is enabled but no mutual-TLS client CA is configured (set auth.mtls)")
			}
			grpcClientCAs = mtlsClientCAs
		}
		grpcInsecure := grpcTLSCert == "" && grpcTLSKey == "" && insecureHTTPAllowed()
		grpcSrv, err := grpcapi.New(grpcapi.Config{
			Address:   cfg.GRPC.GRPCAddress(),
			TLSCert:   grpcTLSCert,
			TLSKey:    grpcTLSKey,
			ClientCAs: grpcClientCAs,
			Insecure:  grpcInsecure,
		}, api, authMw)
		if err != nil {
			log.Fatalf("gRPC server setup failed: %v", err)
		}
		log.Printf("Starting gRPC server on %s (reflection + health enabled, mTLS=%v)", grpcSrv.Addr(), cfg.GRPC.MTLS)
		go func() {
			if err := grpcSrv.Serve(); err != nil {
				log.Fatalf("gRPC server failed: %v", err)
			}
		}()
	}

	// Certificate-expiry monitor: a background goroutine that periodically scans
	// issued certificates, reports upcoming expirations through the configured
	// notification sinks, and (when enabled) auto-renews eligible leaves via the
	// same HSM-backed issuance path. Leader-gated: with replicas > 1, a single
	// replica scanning prevents duplicate expiry alerts and racing auto-renewals
	// (and re-scanning after a handover is idempotent — a renewed certificate is
	// superseded and never renewed twice).
	if cfg.Monitor.Enabled {
		caMgr := ca.NewManager(db, provider)
		mon := monitor.New(db, caMgr, db, monitorOpts)
		runner, err := monitor.NewRunner(mon, cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("Certificate-expiry monitor configuration error: %v", err)
		}
		// Enable HSM-backed intermediate-CA key rotation when configured: the same
		// manager cross-signs a fresh key under the parent and opens a dual-chain
		// overlap window as intermediates near expiry.
		runner.WithRotation(caMgr, db)
		// Secret-layer KEK rotation posture (Task 63): each tick refreshes the
		// secrets-on-old-KEK / active-version gauges and logs families whose
		// stored secrets still need a re-wrap.
		runner.WithSecretKEKCheck(func(context.Context) ([]string, error) {
			return secret.RefreshKEKMetrics(db, cfg.Secret.KEKLabel)
		})
		// Stored-secret TTL / rotation reminders (Task 73), delivered through
		// the same notification sinks with storm prevention.
		runner.WithSecretLifecycle(monitor.NewSecretLifecycleScanner(db, cfg.Monitor))
		elector.Register("expiry-monitor", runner.Run)
	}

	// Synthetic issuance canary (Task 71): an end-to-end self-test loop that
	// per configured CA periodically issues a short-lived certificate from the
	// dedicated canary profile, verifies the full chain, checks OCSP answers
	// "good" and the CRL is fresh, revokes it, and confirms "revoked"
	// propagates — timing every stage and alerting through the monitor's
	// notification sinks on failure. Leader-gated: probes cost real HSM signing
	// operations and consume tenant quota, so exactly one replica probes.
	if cfg.Canary.Enabled {
		notifier, err := monitor.NewNotifier(cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("Issuance canary notification configuration error: %v", err)
		}
		prober, err := canary.New(ca.NewManager(db, provider), db, cfg.Canary, notifier, log.Default())
		if err != nil {
			log.Fatalf("Issuance canary configuration error: %v", err)
		}
		elector.Register("issuance-canary", prober.Run)
	}

	// CT SCT inclusion monitor (Task 93): the post-issuance half of Certificate
	// Transparency. Once a log's Maximum Merge Delay has elapsed for a certificate's
	// embedded SCTs it fetches the log's signed tree head and the get-proof-by-hash
	// Merkle audit path, verifies inclusion, and records per-SCT state; any SCT a
	// log fails to honor (never included after MMD, or an invalid proof) is a
	// mis-issuance / log-misbehavior signal, alerted through the monitor sinks and
	// counted in a dedicated metric. Leader-gated: one replica verifies at a time
	// (the per-SCT state is shared) and a handover is idempotent (the next scan
	// simply re-verifies). No HSM: reads certificates, fetches over HTTP, verifies
	// with the logs' public keys.
	if cfg.CertificateTransparency.InclusionMonitor.Enabled {
		if ctSubmitter == nil {
			log.Fatalf("certificate_transparency.inclusion_monitor.enabled is set but no certificate_transparency.logs are configured")
		}
		notifier, err := monitor.NewNotifier(cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("CT inclusion monitor notification configuration error: %v", err)
		}
		ctMon, err := ctmonitor.New(db, ctSubmitter, cfg.CertificateTransparency.InclusionMonitor, notifier, log.Default())
		if err != nil {
			log.Fatalf("CT inclusion monitor configuration error: %v", err)
		}
		elector.Register("ct-inclusion-monitor", ctMon.Run)
	}

	// External certificate discovery scanner (Task 54): periodically probes the
	// configured TLS endpoints, records the served leaf certificates (with their
	// security flags) into the inventory, and dispatches expiring/weak/rogue
	// findings through the same notification sinks as the expiry monitor.
	// Leader-gated: one replica scanning avoids probing every external endpoint
	// once per replica and duplicating findings/alerts. No HSM operations — a
	// TLS client plus X.509 analysis.
	if cfg.Discovery.Enabled {
		discoRunner, err := discovery.NewBackgroundRunner(db, cfg.Discovery, cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("Certificate discovery configuration error: %v", err)
		}
		if discoRunner != nil {
			elector.Register("discovery-scan", discoRunner.Run)
		} else {
			log.Printf("Certificate discovery enabled but no targets configured; scanner not started")
		}
	}

	// OCSP pre-signing and static artifact publishing (Task 58): batch-sign OCSP
	// responses for all known serials into the response cache so the public
	// responder stays off the HSM, and publish CRLs/chains/pre-signed responses
	// as static artifacts (directory or S3) for CDN fronting. Both are
	// leader-gated: presigning on one replica keeps the batch HSM load constant
	// as replicas scale (followers fall back to the on-demand signing path with
	// its TTL cache), and the publish loop — which regenerates CRLs, delta
	// CRLs, and partition shards on its schedule — must not have replicas
	// racing snapshot swaps against the same store.
	presigner := setupOCSPPresign(cfg, db, provider, api, elector)
	setupPublish(cfg, db, provider, presigner, elector)
	if presigner != nil {
		// Bulk revocation (Task 70) refreshes the pre-signed OCSP set right
		// after a mass revocation so cached responses say "revoked" without
		// waiting for the next scheduled batch.
		api.SetOCSPPresigner(presigner)
	}

	// Scheduled encrypted backups (Task 89): a leader-elected loop that
	// periodically produces the DR backup artifact (logical DB dump + config +
	// public CA material + audit-chain head fingerprint), envelope-encrypts it
	// under the HSM-backed KEK, and writes it to a directory or S3 store with
	// atomic swap, manifest, and keep-N/max-age retention. Never blocks issuance.
	setupBackup(cfg, db, provider, *cfgPath, elector)

	// Certificate-inventory retention/archival (Task 157): a leader-elected loop
	// that safely ages out long-expired, terminal issued-certificate rows so a
	// high-volume (short-lived STAR/ACME) CA does not grow issued_certificates
	// unbounded. Fail-safe (never removes a valid, revoked-but-unexpired, held, or
	// approval-pinned cert) and never touches revoked_certificates, so OCSP/CRL for
	// retained serials is unaffected. HSM-independent.
	setupRetention(cfg, db, elector)

	// HSM device audit-log collection (Task 167): a leader-elected loop that
	// drains the YubiHSM's 62-entry log ring into durable storage, verifying that
	// each segment continues the previous one before acknowledging anything.
	// Registered only on a device commissioned via `secsy-ca hsm-audit provision`.
	// Leader-gated because acknowledging entries is destructive and must have
	// exactly one owner.
	setupHSMAuditCollector(cfg, db, elector)

	// Durable outbound webhooks (Task 116): a leader-elected worker that POSTs
	// certificate lifecycle events to operator-registered endpoints with
	// at-least-once delivery, exponential-backoff retries, dead-lettering, and
	// HMAC-signed bodies. Composes the audit-append hook to wake promptly on new
	// events. The subscription-management API/CLI work regardless of webhook.enabled.
	setupWebhook(cfg, db, api, elector)

	// Audit-log SIEM export: a background worker per sink streams the
	// tamper-evident event log to external syslog/CEF/webhook collectors from a
	// durable per-sink cursor. At-least-once, backpressured, and lossless across
	// restarts. Leader-gated: the per-sink cursor is shared state, and a single
	// exporter advancing it avoids replicas delivering interleaved duplicates;
	// a handover at worst redelivers the last unacknowledged batch, which the
	// at-least-once contract already requires downstreams to tolerate.
	if cfg.Audit.Export.Enabled {
		exporter, err := buildAuditExporter(db, cfg)
		if err != nil {
			log.Fatalf("Audit SIEM export configuration error: %v", err)
		}
		log.Printf("Audit SIEM export enabled (%d sink(s))", len(cfg.Audit.Export.Sinks))
		elector.Register("siem-export", exporter.Run)
	}

	// Shared hardware key-attestation verifier (Task 49). Built once from the
	// attestation config plus per-profile modes and handed to every enrollment
	// server so their per-profile "require"/"permissive" policies enforce
	// consistently. Nil when attestation is disabled everywhere (gate inert).
	attestVerifier, err := buildAttestationVerifier(cfg)
	if err != nil {
		log.Fatalf("Attestation configuration error: %v", err)
	}
	// Share it with the issuance-preview endpoint (Task 113) so a dry-run reports a
	// profile's attestation posture. Nil (attestation disabled) leaves the preview's
	// attestation gate inert.
	api.SetAttestationVerifier(attestVerifier)

	// ACME (RFC 8555) automated-issuance server. Its endpoints authenticate
	// clients via JWS account keys (not OIDC/basic auth) and are therefore
	// registered directly on the mux, outside the OIDC auth middleware.
	if cfg.ACME.Enabled {
		acmeCfg, err := buildACMEConfig(db, cfg)
		if err != nil {
			log.Fatalf("ACME configuration error: %v", err)
		}
		acmeCfg.Attestation = attestVerifier
		acmeSrv := acme.New(db, provider, acmeCfg)
		acmeSrv.Register(mux)
		// Prune expired consumed-nonce records on a leader-elected background loop
		// (Task 97), like the other periodic sweeps. Correctness does not depend on
		// it — an expired nonce is rejected by its embedded timestamp before the
		// shared consumed-set is consulted — so this is hygiene that bounds the
		// set's growth.
		elector.Register("acme-nonce-gc", acmeSrv.RunNonceGC)
		// RFC 8823 email-reply-00 inbound-mail poller (Task 108): when the email
		// challenge is configured, one replica reads the shared IMAP mailbox and
		// validates challenge replies.
		if acmeCfg.Email != nil {
			elector.Register("acme-email-poller", acmeSrv.RunEmailChallengePoller)
			log.Printf("ACME email-reply-00 (RFC 8823) challenge enabled (from=%s)", cfg.ACME.Email.From)
		}
		// RFC 8739 STAR renewer (Task 136): when short-term auto-renewed certificates
		// are enabled, one replica re-issues each STAR certificate ahead of expiry
		// until its end-date. Leader-elected so a single replica drives the recurrence.
		if acmeCfg.Star != nil {
			elector.Register("acme-star-renewer", acmeSrv.RunStarRenewer)
			log.Printf("ACME STAR (RFC 8739) short-term auto-renewed certificates enabled")
		}
	}

	// SCEP (RFC 8894) device-enrollment server. Like ACME it authenticates
	// clients with its own scheme (challenge password), so it mounts outside the
	// OIDC auth middleware. The issuing CA must be RSA (enveloped-data key
	// transport).
	if cfg.SCEP.Enabled {
		scepCfg, err := buildSCEPConfig(db, cfg)
		if err != nil {
			log.Fatalf("SCEP configuration error: %v", err)
		}
		scepCfg.Attestation = attestVerifier
		scep.New(db, provider, scepCfg).Register(mux)
	}

	// BRSKI (RFC 8995) zero-touch onboarding registrar (Task 87). Built before EST
	// so the EST server can adopt it as the pledge authorizer for the post-voucher
	// enrollment handoff. It validates the pledge's IDevID against the trusted
	// manufacturer roots (reused from the attestation config), relays the voucher
	// request to the MASA, returns the signed voucher, and authorizes the pledge to
	// EST-enroll its operational LDevID.
	var brskiRegistrar *brski.Registrar
	if cfg.BRSKI.Enabled {
		reg, err := buildBRSKIRegistrar(db, provider, cfg)
		if err != nil {
			log.Fatalf("BRSKI configuration error: %v", err)
		}
		reg.Register(mux)
		brskiRegistrar = reg
	}

	// EST (RFC 7030) device-enrollment server. Authenticates via HTTP Basic or a
	// TLS client certificate; mounted outside the OIDC middleware.
	if cfg.EST.Enabled {
		estCfg, err := buildESTConfig(db, cfg)
		if err != nil {
			log.Fatalf("EST configuration error: %v", err)
		}
		estCfg.Attestation = attestVerifier
		if brskiRegistrar != nil {
			estCfg.PledgeAuthorizer = brskiRegistrar
		}
		est.New(db, provider, estCfg).Register(mux)
	}

	// Trusted external time source (Task 163): when a time.source (NTS/Roughtime)
	// is configured, this fail-closed Clock cross-checks the host wall clock
	// before the TSA signs a token or an audit anchor is created, refusing to sign
	// when the drift exceeds the threshold. Nil (the zero-config default) leaves
	// the host clock as the sole reference, so existing deployments are unaffected.
	timeClock, err := buildTimeClock(db, cfg)
	if err != nil {
		log.Fatalf("Trusted time-source configuration error: %v", err)
	}
	if timeClock != nil {
		log.Printf("Trusted time source enabled: %s (fail-closed drift check on TSA + audit anchoring)", timeClock.Describe())
	}

	// RFC 3161 Time-Stamp Authority. The /tsa endpoint is anonymous and public
	// (like OCSP/CRL), so it mounts outside the OIDC middleware and is metered by
	// the rate-limit + HSM-concurrency guard below. The authority is kept for the
	// artifact-signing service, which countersigns with it in-process.
	var tsaAuthority *tsa.Authority
	if cfg.TSA.Enabled {
		tsaCfg, err := buildTSAConfig(db, cfg)
		if err != nil {
			log.Fatalf("TSA configuration error: %v", err)
		}
		authority, err := tsa.New(db, tsaProvider, tsaCfg)
		if err != nil {
			log.Fatalf("TSA configuration error: %v", err)
		}
		if timeClock != nil {
			authority.SetTrustedClock(timeClock)
		}
		authority.Register(mux)
		tsaAuthority = authority
	}

	// Audit-chain anchoring (Task 64): a background job that periodically binds
	// the tamper-evident event log's head hash into an RFC 3161 timestamp token
	// — from the in-process TSA above, or an external TSA URL for independence —
	// and persists it, so `secsy-ca audit verify` detects whole-chain truncation
	// or rewrite behind any anchor point. Leader-gated: one anchor per head is
	// the point of the exercise, and the idle-skip rule (an unchanged head is
	// not re-anchored) makes the post-handover first run a no-op.
	if cfg.Audit.Anchor.Enabled {
		ts, err := buildAnchorTimestamper(cfg, tsaAuthority)
		if err != nil {
			log.Fatalf("Audit anchor configuration error: %v", err)
		}
		anchorSvc := anchor.NewService(db, ts)
		if timeClock != nil {
			anchorSvc.SetTrustedClock(timeClock)
		}
		anchorRunner := anchor.NewRunner(anchorSvc,
			time.Duration(cfg.Audit.Anchor.IntervalHours)*time.Hour, log.Default())
		elector.Register("audit-anchor", anchorRunner.Run)
	}

	// RFC 4998 Evidence-Record preservation (Task 161): a leader-elected job that
	// folds recent audit events into Evidence Records over the internal TSA and
	// renews existing records — time-stamp renewal before the TSA certificate
	// expires and hash-tree renewal on algorithm deprecation — so the audit chain
	// and signed artifacts survive hash/signature-algorithm obsolescence. It sits
	// after the TSA block so it can reuse the in-process authority.
	setupErs(cfg, db, tsaAuthority, elector)

	// HSM audit freshness attestation (Task 167): a leader-elected job that has a
	// timestamp authority attest, on a fixed cadence, that the current HSM audit
	// head existed at that moment. Without it every other check in an exported
	// bundle still passes on a months-old snapshot, so an operator could answer
	// an audit with state captured before the abuse. Like setupErs it sits after
	// the TSA block so it can fall back to the in-process authority.
	setupHSMAuditFreshness(cfg, db, tsaAuthority, elector)

	// Artifact code-signing service (Task 60): CMS detached signatures over
	// release artifacts at /api/sign (RBAC role "signer"), with optional RFC 3161
	// countersignatures from the in-process TSA. Signer keys/certificates are
	// provisioned offline with `secsy-ca signing-key`.
	if cfg.Signing.Enabled {
		svc, err := buildSigningService(db, cfg, signingProvider, provider, tsaAuthority)
		if err != nil {
			log.Fatalf("Signing configuration error: %v", err)
		}
		api.SetSigningService(svc)
		log.Printf("Artifact signing enabled (%d signer(s), CAdES timestamping: %t, long-term-validation: %t)",
			len(cfg.Signing.Signers), svc.TimestampingAvailable(), svc.LTVAvailable())
	}

	// Lightweight CMP (RFC 9483) certificate-management server. Like the other
	// enrollment protocols it authenticates with its own message protection
	// (shared-secret PBM or a signature from a certificate this CA issued), so it
	// mounts outside the OIDC middleware and is metered by the rate-limit guard.
	if cfg.CMP.Enabled {
		cmpCfg, err := buildCMPConfig(db, cfg)
		if err != nil {
			log.Fatalf("CMP configuration error: %v", err)
		}
		cmp.New(db, provider, cmpCfg).Register(mux)
	}

	// Microsoft Windows autoenrollment web services (Task 162): the MS-XCEP policy
	// (CEP) and MS-WSTEP enrollment (CES) SOAP endpoints for GPO-driven Windows
	// autoenrollment. Like the other enrollment protocols they authenticate with
	// their own mechanism (a native API token or a mutual-TLS client certificate),
	// so they mount outside the OIDC middleware and are metered by the rate-limit +
	// HSM-concurrency guard below.
	if cfg.MSWSTEP.Enabled {
		msCfg, err := buildMSWSTEPConfig(db, cfg)
		if err != nil {
			log.Fatalf("MS-WSTEP configuration error: %v", err)
		}
		mswstep.New(db, provider, msCfg).Register(mux)
	}

	// Serve the legacy disk-based SPA from web/static when present. The Task 21
	// operator console is served separately from an embedded (go:embed) bundle
	// under /console/ by RegisterRoutes, so it ships in the binary regardless.
	// When the legacy SPA is absent (e.g. the container image), send the site
	// root straight to the embedded console.
	webDir := "web/static"
	if _, err := os.Stat(webDir); err == nil {
		mux.Handle("GET /", http.FileServer(http.Dir(webDir)))
	} else {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/console/", http.StatusFound)
		})
	}

	// Job registration is complete — start the election. On SQLite (static
	// mode) leadership and every registered job start immediately, preserving
	// single-node behavior; on PostgreSQL the jobs start once the advisory lock
	// is acquired, which for a lone replica is the first attempt. The readiness
	// probe reports this replica's role under the "leadership" component.
	api.SetLeaderInfo(elector)
	go elector.Run(context.Background())

	// Cap every request body to guard against memory-exhaustion DoS from an
	// (authenticated) client. Individual handlers may impose tighter limits.
	handler := limitRequestBody(mux, maxRequestBodyBytes)

	// Rate limiting, per-account/IP/global/per-tenant quotas, and a bounded
	// in-flight concurrency guard protecting the HSM on the public endpoints
	// (ACME, OCSP, CRL, SCEP/EST/CMP). Sits inside the observability layer so
	// shed requests are still logged and metered, and outside the body cap so it
	// runs before any per-handler work. Even with rate_limit.enabled false the
	// middleware is installed for its tenant enrollment gate (Task 61): a
	// suspended tenant's enrollment protocol surfaces answer 403 outright, while
	// OCSP/CRL for its already-issued certificates keep flowing.
	if rlmw := buildRateLimit(cfg, db); rlmw != nil && rlmw.Active() {
		handler = rlmw.Handler(handler)
		log.Printf("Public-endpoint protection enabled (rate limiting: %v; tenant enrollment gate: on)", cfg.RateLimit.Enabled)
	}

	// Outermost middleware: assign a correlation ID to every request, record HTTP
	// metrics, and emit one structured (JSON) log line per request. Wrapping the
	// whole tree means it also covers ACME, static assets, and the health/metrics
	// endpoints, and makes the request ID visible to the access and audit logs.
	obs := middleware.NewObservability(os.Stdout)
	handler = obs.Handler(handler)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	selfIssue := cfg.Server.TLS.SelfIssue.Enabled
	haveDiskCert := cfg.Server.TLSCert != "" && cfg.Server.TLSKey != ""
	if selfIssue || haveDiskCert {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		// Mutual-TLS client-certificate authentication (Task 50). Request a client
		// certificate and verify it against the configured client CA(s) when one is
		// presented — VerifyClientCertIfGiven keeps the console and public endpoints
		// reachable without a client cert, while a presented cert is chain-verified
		// by the TLS stack before the auth middleware binds it to a principal.
		if mtlsClientCAs != nil {
			// Request (but do not require or handshake-verify) a client certificate:
			// the operator-auth binder verifies presented certs against this pool,
			// while other consumers (EST TLS reenrollment) validate their own device
			// certs against the PKI CA. RequestClientCert therefore keeps both paths
			// working without one CA pool having to trust the other.
			tlsCfg.ClientCAs = mtlsClientCAs
			tlsCfg.ClientAuth = tls.RequestClientCert
			log.Printf("Mutual-TLS client-certificate authentication enabled")
		}

		// certFile/keyFile stay empty in self-issue mode: the certificate is served
		// entirely through tls.Config.GetCertificate, so ListenAndServeTLS needs no
		// disk key pair.
		var certFile, keyFile string
		switch {
		case selfIssue:
			// Self-managed serving certificate (Task 118): the server issues its own
			// HTTPS listener certificate from an internal CA via ca.Manager, keeps the
			// private key in the configured key provider, and auto-rotates it before
			// expiry — swapping it hitlessly through the same GetCertificate hook the
			// OCSP-stapling path uses. It supersedes any static tls_cert/tls_key.
			si, err := buildSelfIssuedServingCert(context.Background(), cfg, db, provider)
			if err != nil {
				log.Fatalf("configuring self-issued serving certificate: %v", err)
			}
			tlsCfg.GetCertificate = si.Holder().GetCertificate
			go si.Run(context.Background())
			sc := cfg.Server.TLS.SelfIssue
			log.Printf("Self-issued serving certificate enabled (CA %s, profile %q); key kept in the %s provider, auto-rotating",
				sc.CAID, sc.ResolvedProfile(), provider.Name())
		case haveDiskCert:
			certFile, keyFile = cfg.Server.TLSCert, cfg.Server.TLSKey
			// TLS OCSP stapling: when the operator names the CA that issued the
			// server's own certificate, produce and periodically refresh an
			// HSM-signed OCSP staple and serve it in the handshake so clients get
			// revocation status without a separate responder round-trip.
			if caID := cfg.Server.OCSP.StapleCAID; caID != "" {
				holder, err := newStapledCertificate(certFile, keyFile, caID, db, provider)
				if err != nil {
					log.Fatalf("configuring OCSP stapling: %v", err)
				}
				tlsCfg.GetCertificate = holder.GetCertificate
				log.Printf("TLS OCSP stapling enabled for the server certificate (CA %s)", caID)
			}
		}

		server := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsCfg,
		}
		log.Printf("Starting HTTPS server on %s", addr)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		// Fail closed: an enterprise PKI serving bearer tokens, basic-auth root
		// credentials, secret encrypt/decrypt, and CA operations must not run in
		// cleartext by accident. Refuse to start without TLS unless the operator
		// explicitly opts in (e.g. when TLS is terminated at a trusted proxy).
		if !insecureHTTPAllowed() {
			log.Fatalf("Refusing to start: no TLS configured (set server.tls_cert/tls_key). " +
				"To run plain HTTP behind a trusted TLS-terminating proxy, set SECSY_ALLOW_INSECURE_HTTP=1.")
		}
		log.Printf("WARNING: SECSY_ALLOW_INSECURE_HTTP is set — starting cleartext HTTP server on %s. "+
			"Only do this behind a trusted TLS-terminating proxy.", addr)
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// tracingConfig maps the server's tracing config block onto the internal
// tracing package's Config, translating the seconds-based timeout knob.
func tracingConfig(cfg *config.Config) tracing.Config {
	t := cfg.Tracing
	return tracing.Config{
		Enabled:        t.Enabled,
		Endpoint:       t.Endpoint,
		Protocol:       t.Protocol,
		Insecure:       t.Insecure,
		SampleRatio:    t.SampleRatio,
		ServiceName:    t.ServiceName,
		ServiceVersion: t.ServiceVersion,
		Headers:        t.Headers,
		Timeout:        time.Duration(t.TimeoutSeconds) * time.Second,
	}
}

// maxRequestBodyBytes bounds any single request body (8 MiB) — comfortably
// larger than any legitimate CSR/JSON payload while preventing unbounded
// allocation.
const maxRequestBodyBytes = 8 << 20

// limitRequestBody wraps h so every request body is capped at n bytes.
func limitRequestBody(h http.Handler, n int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		h.ServeHTTP(w, r)
	})
}

// insecureHTTPAllowed reports whether the operator explicitly opted in to
// serving plain HTTP via the SECSY_ALLOW_INSECURE_HTTP environment variable.
func insecureHTTPAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECSY_ALLOW_INSECURE_HTTP"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// buildAttestationVerifier assembles the shared hardware key-attestation
// verifier (Task 49) from the top-level attestation config plus the per-profile
// attestation modes. It returns (nil, nil) when attestation is disabled
// everywhere (default mode off and no profile enforcing), so the enrollment
// servers run with the gate inert. It fails at startup when a profile requires
// attestation but no trusted manufacturer roots are configured — a policy that
// could otherwise silently reject every enrollment.
func buildAttestationVerifier(cfg *config.Config) (*attestation.Verifier, error) {
	profileModes := make(map[string]attestation.Mode)
	anyEnforcing := false
	for _, p := range cfg.Profiles {
		if strings.TrimSpace(p.Attestation.Mode) == "" {
			continue
		}
		m, err := attestation.ParseMode(p.Attestation.Mode)
		if err != nil {
			return nil, fmt.Errorf("profile %q attestation: %w", p.Name, err)
		}
		profileModes[p.Name] = m
		if m != attestation.ModeOff {
			anyEnforcing = true
		}
	}
	defMode, err := attestation.ParseMode(cfg.Attestation.DefaultMode)
	if err != nil {
		return nil, fmt.Errorf("attestation.default_mode: %w", err)
	}
	if defMode != attestation.ModeOff {
		anyEnforcing = true
	}
	if !anyEnforcing {
		return nil, nil
	}

	// Load trusted manufacturer certificates. Self-signed certificates become
	// roots; the rest are made available as intermediates for chain building.
	var allCerts []*x509.Certificate
	for _, path := range cfg.Attestation.TrustedRootFiles {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading attestation.trusted_root_files %q: %w", path, err)
		}
		certs, err := parseCertChainPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation trusted roots %q: %w", path, err)
		}
		allCerts = append(allCerts, certs...)
	}
	if strings.TrimSpace(cfg.Attestation.TrustedRootsPEM) != "" {
		certs, err := parseCertChainPEM([]byte(cfg.Attestation.TrustedRootsPEM))
		if err != nil {
			return nil, fmt.Errorf("parsing attestation.trusted_roots_pem: %w", err)
		}
		allCerts = append(allCerts, certs...)
	}

	roots := x509.NewCertPool()
	var intermediates []*x509.Certificate
	for _, c := range allCerts {
		if isSelfSigned(c) {
			roots.AddCert(c)
		} else {
			intermediates = append(intermediates, c)
		}
	}

	v, err := attestation.NewVerifier(attestation.Options{
		Roots:         roots,
		Intermediates: intermediates,
		DefaultMode:   defMode,
		ProfileModes:  profileModes,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Enrollment key attestation enabled (default_mode=%s, %d profile override(s), %d trusted cert(s))",
		defMode, len(profileModes), len(allCerts))
	return v, nil
}

// isSelfSigned reports whether a certificate is self-signed (its own issuer and
// a valid self-signature), used to classify loaded attestation certificates into
// trust anchors (roots) versus chain-building intermediates.
func isSelfSigned(c *x509.Certificate) bool {
	if !bytesEqualName(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

func bytesEqualName(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildACMEConfig resolves the ACME issuing CA and assembles the acme.Config
// from the application config. It fails if the configured CA does not exist or
// is not an X.509 issuer, so misconfiguration surfaces at startup.
func buildACMEConfig(db *database.DB, cfg *config.Config) (acme.Config, error) {
	caID := cfg.ACME.CAID
	if caID == "" && cfg.ACME.CALabel != "" {
		found, err := db.GetCAByLabel(cfg.ACME.CALabel)
		if err != nil {
			return acme.Config{}, fmt.Errorf("looking up ACME CA by label %q: %w", cfg.ACME.CALabel, err)
		}
		if found == nil {
			return acme.Config{}, fmt.Errorf("ACME CA with label %q not found", cfg.ACME.CALabel)
		}
		caID = found.ID
	}
	if caID == "" {
		return acme.Config{}, fmt.Errorf("no ACME issuing CA configured (set acme.ca_id or acme.ca_label)")
	}
	issuer, err := db.GetCA(caID)
	if err != nil {
		return acme.Config{}, fmt.Errorf("looking up ACME CA %q: %w", caID, err)
	}
	if issuer == nil {
		return acme.Config{}, fmt.Errorf("ACME CA %q not found", caID)
	}
	if issuer.Certificate == "" {
		return acme.Config{}, fmt.Errorf("ACME CA %q is not an X.509 issuer (no certificate)", issuer.Label)
	}

	ac := acme.Config{
		BaseURL:            cfg.ACME.BaseURL,
		DirectoryPath:      cfg.ACME.DirectoryPath,
		CAID:               caID,
		Profile:            cfg.ACME.Profile,
		TermsOfService:     cfg.ACME.TermsOfService,
		HTTP01Port:         cfg.ACME.HTTP01Port,
		TLSALPN01Port:      cfg.ACME.TLSALPN01Port,
		DNSResolver:        cfg.ACME.DNSResolver,
		ChallengeTypes:     cfg.ACME.ChallengeTypes,
		RequireEAB:         cfg.ACME.RequireEAB,
		EABHMACKeys:        cfg.ACME.EABHMACKeys,
		AllowIPIdentifiers: cfg.ACME.AllowIPIdentifiers,
		PreAuthorization:   cfg.ACME.PreAuthorization,
	}
	if cfg.ACME.OrderValidityHours > 0 {
		ac.OrderValidity = time.Duration(cfg.ACME.OrderValidityHours) * time.Hour
	}
	if cfg.ACME.AuthzValidityHours > 0 {
		ac.AuthzValidity = time.Duration(cfg.ACME.AuthzValidityHours) * time.Hour
	}

	// ACME Renewal Information (ARI). The suggested-renewal window mirrors the
	// expiry monitor's renew-before threshold so ARI hints and the server's own
	// auto-renewal agree on when a certificate should be replaced.
	day := 24 * time.Hour
	ac.RenewBefore = time.Duration(cfg.ACME.RenewalWindowDays) * day
	if ac.RenewBefore == 0 && cfg.Monitor.RenewBeforeDays > 0 {
		ac.RenewBefore = time.Duration(cfg.Monitor.RenewBeforeDays) * day
	}
	ac.RenewalWindowWidth = time.Duration(cfg.ACME.RenewalWindowWidthHours) * time.Hour
	if cfg.ACME.RenewalPollHours > 0 {
		ac.RenewalPollInterval = time.Duration(cfg.ACME.RenewalPollHours) * time.Hour
	}
	ac.ExplanationURL = cfg.ACME.RenewalExplanationURL

	// Optional operator-pinned shared secret for signing anti-replay nonces
	// (Task 97). Validated in config.validateACME; decode it here into the raw key
	// the server uses. When unset, the server derives a durable shared secret from
	// the store instead, so multi-replica correctness needs no configuration.
	if cfg.ACME.NonceHMACKey != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.ACME.NonceHMACKey)
		if err != nil {
			return acme.Config{}, fmt.Errorf("acme.nonce_hmac_key: %w", err)
		}
		ac.NonceSecret = key
	}

	// ACME Profiles extension (RFC 9773): translate the configured
	// client-selectable profiles into the acme.Config, resolving each to a
	// concrete internal issuance profile id and verifying it exists now that the
	// custom profiles have been loaded (ca.SetCustomProfiles runs earlier in
	// startup). A typo therefore fails at startup rather than at the first order
	// that selects the profile.
	if len(cfg.ACME.Profiles) > 0 {
		defaultProfile := cfg.ACME.Profile
		if defaultProfile == "" {
			defaultProfile = "server"
		}
		profiles := make(map[string]acme.ACMEProfile, len(cfg.ACME.Profiles))
		for name, p := range cfg.ACME.Profiles {
			internalID := p.Profile
			if internalID == "" {
				internalID = defaultProfile
			}
			if _, err := ca.LookupProfile(internalID); err != nil {
				return acme.Config{}, fmt.Errorf("acme.profiles[%q]: %w", name, err)
			}
			profiles[name] = acme.ACMEProfile{Description: p.Description, Profile: internalID}
		}
		ac.Profiles = profiles
	}

	// RFC 8823 email-reply-00 challenge (Task 108): wire the SMTP sink, the IMAP
	// poller, and the optional DKIM signer for S/MIME issuance via ACME.
	email, err := buildACMEEmailConfig(cfg)
	if err != nil {
		return acme.Config{}, err
	}
	ac.Email = email

	// RFC 8739 STAR short-term auto-renewed certificates (Task 136): translate the
	// operator-friendly hour/day bounds into the durations the server validates
	// against. Zero fields fall back to the server's defaults (1h / 7d / 365d).
	if cfg.ACME.Star.Enabled {
		ac.Star = &acme.StarConfig{
			MinLifetime: time.Duration(cfg.ACME.Star.MinLifetimeHours) * time.Hour,
			MaxLifetime: time.Duration(cfg.ACME.Star.MaxLifetimeHours) * time.Hour,
			MaxDuration: time.Duration(cfg.ACME.Star.MaxDurationDays) * 24 * time.Hour,
		}
	}

	// Multi-Perspective Issuance Corroboration (Task 142, SC-067): translate the
	// operator-friendly seconds/perspective config into the acme.MPICConfig the
	// coordinator consumes. Structurally validated in config.validateACMEMPIC; the
	// dialer/proxy wiring is built and further validated in acme.New (newCoordinator).
	ac.MPIC = buildACMEMPICConfig(cfg)

	return ac, nil
}

// buildACMEMPICConfig assembles the MPIC coordinator configuration (Task 142)
// from the acme.mpic config block, converting the seconds-based operator inputs
// into the durations the coordinator uses. When disabled it still copies the
// perspective list through harmlessly; acme.New treats a disabled coordinator as
// single-perspective.
func buildACMEMPICConfig(cfg *config.Config) acme.MPICConfig {
	m := cfg.ACME.MPIC
	out := acme.MPICConfig{
		Enabled: m.Enabled,
		Timeout: time.Duration(m.PerspectiveTimeoutSeconds) * time.Second,
		Policy: acme.QuorumPolicy{
			MinPerspectives: m.Quorum.MinPerspectives,
			MaxFailures:     m.Quorum.MaxFailures,
			RequireAll:      m.Quorum.RequireAll,
		},
	}
	for _, p := range m.Perspectives {
		out.Perspectives = append(out.Perspectives, acme.PerspectiveConfig{
			Name:        p.Name,
			DNSResolver: p.DNSResolver,
			ProxyURL:    p.ProxyURL,
			Timeout:     time.Duration(p.TimeoutSeconds) * time.Second,
		})
	}
	return out
}

// buildACMEEmailConfig assembles the RFC 8823 email-reply-00 challenge transport
// (Task 108) from the acme.email config block. It returns nil (the challenge
// off) when the block is not fully configured; otherwise it constructs the SMTP
// sender, the IMAP inbox, and (when present) the DKIM signer, and verifies the
// email issuance profile is an S/MIME profile so applySMIMEPolicy gates finalize.
func buildACMEEmailConfig(cfg *config.Config) (*acme.EmailChallengeConfig, error) {
	ec := cfg.ACME.Email
	if !ec.Configured() {
		return nil, nil
	}

	profile := ec.Profile
	if profile == "" {
		profile = "smime"
	}
	if p, err := ca.LookupProfile(profile); err != nil {
		return nil, fmt.Errorf("acme.email.profile: %w", err)
	} else if p.SMIME == nil {
		return nil, fmt.Errorf("acme.email.profile %q is not an S/MIME profile", profile)
	}

	sender, err := mailtransport.NewSMTPSender(mailtransport.SMTPConfig{
		Host:               ec.SMTP.Host,
		Port:               ec.SMTP.Port,
		Username:           ec.SMTP.Username,
		Password:           ec.SMTP.Password,
		TLSMode:            ec.SMTP.TLSMode,
		InsecureSkipVerify: ec.SMTP.InsecureSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("acme.email.smtp: %w", err)
	}
	inbox, err := mailtransport.NewIMAPInbox(mailtransport.IMAPConfig{
		Host:               ec.IMAP.Host,
		Port:               ec.IMAP.Port,
		Username:           ec.IMAP.Username,
		Password:           ec.IMAP.Password,
		Mailbox:            ec.IMAP.Mailbox,
		TLSMode:            ec.IMAP.TLSMode,
		InsecureSkipVerify: ec.IMAP.InsecureSkipVerify,
		MaxMessages:        ec.IMAP.MaxMessages,
	})
	if err != nil {
		return nil, fmt.Errorf("acme.email.imap: %w", err)
	}

	out := &acme.EmailChallengeConfig{
		From:          ec.From,
		Sender:        sender,
		Inbox:         inbox,
		Profile:       profile,
		SubjectPrefix: ec.SubjectPrefix,
	}
	if ec.PollIntervalSeconds > 0 {
		out.PollInterval = time.Duration(ec.PollIntervalSeconds) * time.Second
	}
	dkim, err := buildDKIMSigner(ec.DKIM)
	if err != nil {
		return nil, fmt.Errorf("acme.email.dkim: %w", err)
	}
	out.DKIM = dkim
	return out, nil
}

// buildDKIMSigner loads the RSA DKIM key (from file or inline PEM) and returns a
// signer, or nil when no key is configured (challenge emails are then unsigned).
func buildDKIMSigner(c config.ACMEEmailDKIM) (*acme.DKIMSigner, error) {
	pemData := strings.TrimSpace(c.PrivateKeyPEM)
	if pemData == "" && c.PrivateKeyFile == "" {
		return nil, nil
	}
	if pemData == "" {
		b, err := os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading private key %q: %w", c.PrivateKeyFile, err)
		}
		pemData = string(b)
	}
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in DKIM private key")
	}
	key, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer := &acme.DKIMSigner{Domain: c.Domain, Selector: c.Selector, Signer: key}
	if err := signer.Validate(); err != nil {
		return nil, err
	}
	return signer, nil
}

// parseRSAPrivateKey decodes a PKCS#1 or PKCS#8 RSA private key.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing DKIM private key: %w", err)
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("DKIM private key is not an RSA key")
	}
	return rsaKey, nil
}

// resolveCAID resolves a configured (caID, caLabel) pair to a concrete CA id,
// verifying the CA exists and is an X.509 issuer. It centralizes the lookup
// shared by the ACME/SCEP/EST config builders.
func resolveCAID(db *database.DB, caID, caLabel, proto string) (string, error) {
	if caID == "" && caLabel != "" {
		found, err := db.GetCAByLabel(caLabel)
		if err != nil {
			return "", fmt.Errorf("looking up %s CA by label %q: %w", proto, caLabel, err)
		}
		if found == nil {
			return "", fmt.Errorf("%s CA with label %q not found", proto, caLabel)
		}
		caID = found.ID
	}
	if caID == "" {
		return "", fmt.Errorf("no %s issuing CA configured (set ca_id or ca_label)", proto)
	}
	issuer, err := db.GetCA(caID)
	if err != nil {
		return "", fmt.Errorf("looking up %s CA %q: %w", proto, caID, err)
	}
	if issuer == nil {
		return "", fmt.Errorf("%s CA %q not found", proto, caID)
	}
	if issuer.Certificate == "" {
		return "", fmt.Errorf("%s CA %q is not an X.509 issuer (no certificate)", proto, issuer.Label)
	}
	return caID, nil
}

// buildSCEPConfig assembles the scep.Config from the application config. It
// additionally requires the issuing CA to be RSA, since SCEP's enveloped-data
// key transport cannot address an ECDSA/Ed25519 CA certificate.
func buildSCEPConfig(db *database.DB, cfg *config.Config) (scep.Config, error) {
	caID, err := resolveCAID(db, cfg.SCEP.CAID, cfg.SCEP.CALabel, "scep")
	if err != nil {
		return scep.Config{}, err
	}
	issuer, _ := db.GetCA(caID)
	if !strings.HasPrefix(strings.ToLower(issuer.KeyType), "rsa") {
		return scep.Config{}, fmt.Errorf("SCEP CA %q has key type %q; SCEP requires an RSA CA", issuer.Label, issuer.KeyType)
	}
	grants := make([]scep.Grant, 0, len(cfg.SCEP.Grants))
	for _, g := range cfg.SCEP.Grants {
		grants = append(grants, scep.Grant{Name: g.Name, Challenge: g.Challenge, Profile: g.Profile})
	}
	return scep.Config{
		DirectoryPath:    cfg.SCEP.DirectoryPath,
		CAID:             caID,
		Profile:          cfg.SCEP.Profile,
		Grants:           grants,
		RequireChallenge: cfg.SCEP.RequireChallengeEnabled(),
		AllowRenewal:     cfg.SCEP.AllowRenewal,
	}, nil
}

// buildESTConfig assembles the est.Config from the application config.
func buildESTConfig(db *database.DB, cfg *config.Config) (est.Config, error) {
	caID, err := resolveCAID(db, cfg.EST.CAID, cfg.EST.CALabel, "est")
	if err != nil {
		return est.Config{}, err
	}
	users := make(map[string]est.User, len(cfg.EST.Users))
	for name, u := range cfg.EST.Users {
		users[name] = est.User{Password: u.Password, Profile: u.Profile}
	}
	var csrAttrs map[string][]est.CSRAttr
	if len(cfg.EST.CSRAttrs) > 0 {
		csrAttrs = make(map[string][]est.CSRAttr, len(cfg.EST.CSRAttrs))
		for profile, specs := range cfg.EST.CSRAttrs {
			attrs := make([]est.CSRAttr, len(specs))
			for i, s := range specs {
				attrs[i] = est.CSRAttr{OID: s.OID, Values: s.Values}
			}
			csrAttrs[profile] = attrs
		}
	}
	if err := est.ValidateCSRAttrConfig(cfg.EST.CSRAttrECCurve, csrAttrs); err != nil {
		return est.Config{}, err
	}
	return est.Config{
		BasePath:               cfg.EST.BasePath,
		CAID:                   caID,
		Profile:                cfg.EST.Profile,
		Users:                  users,
		AllowTLSClientReenroll: cfg.EST.AllowTLSClientReenroll,
		EnableServerKeygen:     cfg.EST.EnableServerKeygen,
		ServerKeygenKeyType:    cfg.EST.ServerKeygenKeyType,
		CSRAttrECCurve:         cfg.EST.CSRAttrECCurve,
		CSRAttrs:               csrAttrs,
	}, nil
}

// buildBRSKIRegistrar assembles the RFC 8995 BRSKI registrar (Task 87): its
// domain CA (for the LDevID handoff), the HSM-backed registrar signing identity,
// the domain/provisioning certificate the pledge pins, the trusted manufacturer
// roots the pledge IDevID must chain to (reused from the attestation config plus
// any brski-specific anchors), and the MASA client (external HTTPS or the minimal
// built-in in-process MASA).
func buildBRSKIRegistrar(db *database.DB, provider keyprovider.Provider, cfg *config.Config) (*brski.Registrar, error) {
	// Domain issuing CA for the LDevID handoff (defaults to the EST CA).
	caID, caLabel := cfg.BRSKI.CAID, cfg.BRSKI.CALabel
	if caID == "" && caLabel == "" {
		caID, caLabel = cfg.EST.CAID, cfg.EST.CALabel
	}
	resolvedCA, err := resolveCAID(db, caID, caLabel, "brski")
	if err != nil {
		return nil, err
	}

	// Registrar voucher-request signing identity (typically HSM-backed).
	regSigner, err := newProviderBackedSigner(provider, cfg.BRSKI.RegistrarKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("brski.registrar_key_label: %w", err)
	}
	regChain, err := loadCertChainFile(cfg.BRSKI.RegistrarCertFile)
	if err != nil {
		return nil, fmt.Errorf("brski.registrar_cert_file: %w", err)
	}

	// Domain (provisioning/TLS) certificate the pledge pins; defaults to the
	// registrar signing certificate (a single registrar identity).
	domainCert := regChain[0]
	if cfg.BRSKI.DomainCertFile != "" {
		domainChain, err := loadCertChainFile(cfg.BRSKI.DomainCertFile)
		if err != nil {
			return nil, fmt.Errorf("brski.domain_cert_file: %w", err)
		}
		domainCert = domainChain[0]
	}

	// IDevID manufacturer trust: reuse the attestation trusted roots plus any
	// brski-specific trust anchors.
	roots, intermediates, err := buildBRSKIIDevIDTrust(cfg)
	if err != nil {
		return nil, err
	}
	if len(roots.Subjects()) == 0 { //nolint:staticcheck // emptiness check
		return nil, fmt.Errorf("brski.enabled requires trusted IDevID manufacturer roots (set attestation.trusted_root_files or brski.trust_anchor_files)")
	}

	profile := cfg.BRSKI.Profile
	if profile == "" {
		profile = orDefaultPath(cfg.EST.Profile, "client")
	}

	masaClient, err := buildBRSKIMASA(provider, cfg, roots, intermediates)
	if err != nil {
		return nil, err
	}

	proximity := cfg.BRSKI.RequireProximityEnabled()
	return brski.New(db, brski.Config{
		BasePath:            cfg.BRSKI.BasePath,
		CAID:                resolvedCA,
		Profile:             profile,
		EnabledProfiles:     brskiEnabledProfiles(cfg),
		DomainCert:          domainCert,
		RegistrarKey:        regSigner,
		RegistrarCert:       regChain[0],
		RegistrarChain:      regChain[1:],
		IDevIDRoots:         roots,
		IDevIDIntermediates: intermediates,
		MASA:                masaClient,
		RequireProximity:    &proximity,
		PledgeTTL:           time.Duration(cfg.BRSKI.PledgeTTLMinutes) * time.Minute,
	})
}

// buildBRSKIMASA selects the MASA client: an external HTTPS MASA when brski.masa.url
// is set, otherwise the minimal built-in in-process MASA signing with an
// HSM-backed key.
func buildBRSKIMASA(provider keyprovider.Provider, cfg *config.Config, roots *x509.CertPool, intermediates []*x509.Certificate) (brski.MASAClient, error) {
	if cfg.BRSKI.MASA.URL != "" {
		return brski.HTTPMASA{BaseURL: cfg.BRSKI.MASA.URL}, nil
	}
	masaSigner, err := newProviderBackedSigner(provider, cfg.BRSKI.MASA.KeyLabel)
	if err != nil {
		return nil, fmt.Errorf("brski.masa.key_label: %w", err)
	}
	masaChain, err := loadCertChainFile(cfg.BRSKI.MASA.CertFile)
	if err != nil {
		return nil, fmt.Errorf("brski.masa.cert_file: %w", err)
	}
	svc, err := brski.NewService(brski.ServiceConfig{
		Signer:              masaSigner,
		Cert:                masaChain[0],
		Chain:               masaChain[1:],
		IDevIDRoots:         roots,
		IDevIDIntermediates: intermediates,
		VoucherValidity:     time.Duration(cfg.BRSKI.MASA.VoucherValidityHours) * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	return brski.InProcessMASA{Service: svc}, nil
}

// buildBRSKIIDevIDTrust loads the manufacturer trust anchors the pledge IDevID is
// validated against: the attestation trusted roots (reused) plus any BRSKI-
// specific trust anchors. Self-signed certificates become roots; the rest are
// path-building intermediates — the same classification the attestation gate uses.
func buildBRSKIIDevIDTrust(cfg *config.Config) (*x509.CertPool, []*x509.Certificate, error) {
	roots := x509.NewCertPool()
	var intermediates []*x509.Certificate
	add := func(certs []*x509.Certificate) {
		for _, c := range certs {
			if isSelfSigned(c) {
				roots.AddCert(c)
			} else {
				intermediates = append(intermediates, c)
			}
		}
	}
	files := append([]string{}, cfg.Attestation.TrustedRootFiles...)
	files = append(files, cfg.BRSKI.TrustAnchorFiles...)
	for _, path := range files {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading BRSKI IDevID trust anchor %q: %w", path, err)
		}
		certs, err := parseCertChainPEM(pemBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing BRSKI IDevID trust anchor %q: %w", path, err)
		}
		add(certs)
	}
	for _, inline := range []string{cfg.Attestation.TrustedRootsPEM, cfg.BRSKI.TrustAnchorsPEM} {
		if strings.TrimSpace(inline) == "" {
			continue
		}
		certs, err := parseCertChainPEM([]byte(inline))
		if err != nil {
			return nil, nil, fmt.Errorf("parsing inline BRSKI IDevID trust anchors: %w", err)
		}
		add(certs)
	}
	return roots, intermediates, nil
}

// zlintConfig converts a profile's zlint configuration into the ca.ZLintConfig
// consumed by the pre-issuance lint gate. It returns nil when zlint is not
// enabled for the profile so the gate skips the backend entirely.
func zlintConfig(c config.ProfileZLintConfig) *ca.ZLintConfig {
	if !c.Enabled {
		return nil
	}
	return &ca.ZLintConfig{
		Enabled:        true,
		ErrorMode:      c.ErrorMode,
		WarnMode:       c.WarnMode,
		NoticeMode:     c.NoticeMode,
		IncludeSources: c.IncludeSources,
		ExcludeSources: c.ExcludeSources,
		IncludeNames:   c.IncludeNames,
		ExcludeNames:   c.ExcludeNames,
		Overrides:      c.Overrides,
	}
}

// keyChecksConfig converts a profile's key-quality configuration into the
// ca.KeyCheckConfig consumed by the pre-issuance gate (Task 120). The zero value
// maps to nil — the default (enforce mode, standard structural checks + operator
// blocklist) — so a profile that omits the block gets the safe default rather
// than an inert one.
func keyChecksConfig(c config.ProfileKeyChecksConfig) *ca.KeyCheckConfig {
	if c == (config.ProfileKeyChecksConfig{}) {
		return nil
	}
	return &ca.KeyCheckConfig{
		Disabled:         c.Disabled,
		Mode:             c.Mode,
		DetectDuplicates: c.DetectDuplicates,
		MinRSABits:       c.MinRSABits,
	}
}

// brskiEnabledProfiles returns the set of issuance profiles marked BRSKI-enabled
// (profiles[].brski.enabled). When no profile sets the flag it returns nil, which
// the registrar treats as "the configured profile is implicitly allowed".
func brskiEnabledProfiles(cfg *config.Config) map[string]bool {
	var enabled map[string]bool
	for _, p := range cfg.Profiles {
		if p.BRSKI.Enabled {
			if enabled == nil {
				enabled = make(map[string]bool)
			}
			enabled[p.Name] = true
		}
	}
	return enabled
}

// loadCertChainFile reads a PEM file and returns its certificates (leaf first),
// erroring when the file holds none.
func loadCertChainFile(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	chain, err := parseCertChainPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%q contains no certificates", path)
	}
	return chain, nil
}

// providerBackedSigner adapts a keyprovider key to a long-lived crypto.Signer
// that acquires a fresh provider signer (and its HSM session) per Sign call and
// releases it immediately. A long-lived component (the BRSKI registrar/MASA) can
// hold one of these for the server's lifetime while still signing through the
// bounded session pool, since the infrequent onboarding signatures never pin a
// session between operations.
type providerBackedSigner struct {
	provider keyprovider.Provider
	ref      keyprovider.KeyRef
	pub      crypto.PublicKey
}

func newProviderBackedSigner(provider keyprovider.Provider, label string) (*providerBackedSigner, error) {
	if label == "" {
		return nil, fmt.Errorf("key label is empty")
	}
	pub, err := provider.PublicKey(context.Background(), keyprovider.KeyRef{Label: label})
	if err != nil {
		return nil, fmt.Errorf("loading public key for %q: %w", label, err)
	}
	return &providerBackedSigner{provider: provider, ref: keyprovider.KeyRef{Label: label}, pub: pub}, nil
}

func (s *providerBackedSigner) Public() crypto.PublicKey { return s.pub }

func (s *providerBackedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := s.provider.Signer(context.Background(), s.ref)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	return signer.Sign(rand, digest, opts)
}

// buildCMPConfig assembles the cmp.Config from the application config.
func buildCMPConfig(db *database.DB, cfg *config.Config) (cmp.Config, error) {
	caID, err := resolveCAID(db, cfg.CMP.CAID, cfg.CMP.CALabel, "cmp")
	if err != nil {
		return cmp.Config{}, err
	}
	secrets := make([]cmp.Secret, 0, len(cfg.CMP.Secrets))
	for _, s := range cfg.CMP.Secrets {
		secrets = append(secrets, cmp.Secret{Reference: s.Reference, Secret: s.Secret, Profile: s.Profile})
	}
	return cmp.Config{
		Path:                     cfg.CMP.Path,
		CAID:                     caID,
		Profile:                  cfg.CMP.Profile,
		Secrets:                  secrets,
		AllowSignatureProtection: cfg.CMP.AllowSignatureProtection,
	}, nil
}

// buildMSWSTEPConfig assembles the mswstep.Config for the Microsoft Windows
// autoenrollment web services (Task 162). Client authentication is Kerberos-free:
// a native scoped API token (always available) and, when operator mTLS is
// configured, the same client-CA pool and bindings the operator-auth binder uses.
func buildMSWSTEPConfig(db *database.DB, cfg *config.Config) (mswstep.Config, error) {
	caID, err := resolveCAID(db, cfg.MSWSTEP.CAID, cfg.MSWSTEP.CALabel, "mswstep")
	if err != nil {
		return mswstep.Config{}, err
	}
	templates := make([]mswstep.Template, 0, len(cfg.MSWSTEP.Templates))
	for _, t := range cfg.MSWSTEP.Templates {
		templates = append(templates, mswstep.Template{
			Profile:          t.Profile,
			Name:             t.Name,
			OID:              t.OID,
			Enroll:           t.Enroll,
			AutoEnroll:       t.AutoEnroll,
			MinimalKeyLength: t.MinimalKeyLength,
			SchemaVersion:    t.SchemaVersion,
			MajorRevision:    t.MajorRevision,
		})
	}
	msCfg := mswstep.Config{
		PolicyPath:                cfg.MSWSTEP.PolicyPath,
		EnrollPath:                cfg.MSWSTEP.EnrollPath,
		CAID:                      caID,
		DefaultProfile:            cfg.MSWSTEP.DefaultProfile,
		PolicyID:                  cfg.MSWSTEP.PolicyID,
		PolicyFriendlyName:        cfg.MSWSTEP.PolicyFriendlyName,
		NextUpdateHours:           cfg.MSWSTEP.NextUpdateHours,
		TemplateOIDArc:            cfg.MSWSTEP.TemplateOIDArc,
		CESEndpoint:               cfg.MSWSTEP.CESEndpoint,
		Templates:                 templates,
		AllowClientCertIssuedByCA: cfg.MSWSTEP.AllowClientCertIssuedByCA,
		// Native scoped API tokens are the primary Kerberos-free machine-auth
		// mechanism; a token is verified against the same store as the REST/gRPC paths.
		Tokens: authn.NewTokenAuthenticator(db),
	}
	// Reuse the operator mutual-TLS client-CA pool and bindings so an operator
	// certificate authenticates identically to the REST/gRPC surfaces.
	if cfg.Auth.MTLS.Enabled {
		pool, err := loadClientCAs(cfg.Auth.MTLS.CAFile)
		if err != nil {
			return mswstep.Config{}, fmt.Errorf("mswstep mtls: %w", err)
		}
		msCfg.CertBinder = authn.NewCertBinder(buildCertBindings(cfg.Auth.MTLS.Bindings), pool)
	}
	return msCfg, nil
}

// buildTSAConfig assembles the tsa.Config from the application config. The
// assembly (certificate/chain loading, policy OID and digest parsing) lives in
// tsa.LoadAuthorityConfig so the secsy-ca CLI (audit-chain anchoring) builds an
// identical authority from the same config block.
func buildTSAConfig(db *database.DB, cfg *config.Config) (tsa.Config, error) {
	return tsa.LoadAuthorityConfig(db, cfg.TSA)
}

// buildTimeClock assembles the trusted-time Clock (Task 163) from the
// time.source config block. When no external source is configured it returns
// nil, so callers keep their default host-clock behavior untouched. Otherwise it
// returns a fail-closed Checker whose failures are recorded to the tamper-
// evident audit log via the auditor. It mirrors buildAnchorTimestamper: a single
// assembly point shared conceptually with the CLI (both go through
// timesource.FromConfig).
func buildTimeClock(db *database.DB, cfg *config.Config) (timesource.Clock, error) {
	if !cfg.Time.Source.Enabled() {
		return nil, nil
	}
	auditor := func(res timesource.CheckResult) {
		if db == nil {
			return
		}
		if err := db.AppendEvent(&audit.Event{
			ID:         uuid.New().String(),
			Actor:      "system",
			ActorRoles: "system",
			Action:     audit.ActionTimeCheck,
			Result:     audit.ResultDenied,
			Detail:     res.Detail(),
		}); err != nil {
			log.Printf("timesource: appending time.check audit event: %v", err)
		}
	}
	return timesource.FromConfig(cfg.Time.Source, auditor)
}

// buildAnchorTimestamper selects the audit-anchor token source: the external
// TSA URL when configured, else the in-process authority. Config validation
// already requires one of the two, but the authority can still be nil here if
// its own construction was skipped, so this re-checks fail-fast.
func buildAnchorTimestamper(cfg *config.Config, authority *tsa.Authority) (anchor.Timestamper, error) {
	if url := cfg.Audit.Anchor.TSAURL; url != "" {
		return anchor.NewHTTPTimestamper(url, time.Duration(cfg.Audit.Anchor.TimeoutSeconds)*time.Second), nil
	}
	if authority == nil {
		return nil, fmt.Errorf("audit.anchor.enabled requires the internal TSA (tsa.enabled: true) or audit.anchor.tsa_url")
	}
	return anchor.NewAuthorityTimestamper(authority), nil
}

// buildSigningService assembles the artifact-signing service from the signing:
// config block: each signer's certificate (and any inline chain) is loaded from
// its PEM file, the issuing CA's chain is appended from the database when the
// file holds only the leaf, and the tenant defaults to the built-in one. The
// TSA authority may be nil; NewService then rejects signers that default to
// timestamping.
func buildSigningService(db *database.DB, cfg *config.Config, provider, caProvider keyprovider.Provider, authority *tsa.Authority) (*signing.Service, error) {
	signers := make([]signing.SignerConfig, 0, len(cfg.Signing.Signers))
	for _, sc := range cfg.Signing.Signers {
		certPEM, err := os.ReadFile(sc.CertificateFile)
		if err != nil {
			return nil, fmt.Errorf("signer %q: reading certificate_file %q: %w", sc.Name, sc.CertificateFile, err)
		}
		chain, err := parseCertChainPEM(certPEM)
		if err != nil {
			return nil, fmt.Errorf("signer %q: parsing certificate_file: %w", sc.Name, err)
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("signer %q: certificate_file %q contains no certificates", sc.Name, sc.CertificateFile)
		}
		if len(chain) == 1 && (sc.CAID != "" || sc.CALabel != "") {
			caID, err := resolveCAID(db, sc.CAID, sc.CALabel, "signing")
			if err != nil {
				return nil, fmt.Errorf("signer %q: %w", sc.Name, err)
			}
			issuers, err := loadCAChain(db, caID)
			if err != nil {
				return nil, fmt.Errorf("signer %q: %w", sc.Name, err)
			}
			chain = append(chain, issuers...)
		}
		tenant := sc.Tenant
		if tenant == "" {
			tenant = models.DefaultTenantID
		}
		level, err := signing.ParseLevel(sc.Level)
		if err != nil {
			return nil, fmt.Errorf("signer %q: %w", sc.Name, err)
		}
		signers = append(signers, signing.SignerConfig{
			Name:               sc.Name,
			KeyLabel:           sc.KeyLabel,
			Certificate:        chain[0],
			Chain:              chain,
			Digest:             hashFromName(sc.Digest),
			TimestampByDefault: sc.Timestamp,
			DefaultLevel:       level,
			TenantID:           tenant,
		})
	}
	svc, err := signing.NewService(provider, authority, signers)
	if err != nil {
		return nil, err
	}
	// Wire the long-term-validation revocation source (CAdES-LT): the CA manager
	// produces the OCSP responses / CRLs embedded in an LT signature. Built on the
	// CA-role provider — revocation material is signed by the CA key, not the
	// signing key.
	svc.SetRevocationSource(ca.NewManager(db, caProvider))
	return svc, nil
}

// loadCAChain returns the certificate chain for caID: the CA certificate
// followed by its parents up to the root.
func loadCAChain(db *database.DB, caID string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	id := caID
	for id != "" {
		m, err := db.GetCA(id)
		if err != nil {
			return nil, fmt.Errorf("loading CA %q: %w", id, err)
		}
		if m == nil || m.Certificate == "" {
			break
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			return nil, fmt.Errorf("parsing CA %q certificate: %w", id, err)
		}
		chain = append(chain, cert)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	return chain, nil
}

// parseCertChainPEM parses one or more concatenated PEM CERTIFICATE blocks.
func parseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// hashFromName maps a config hash name to a crypto.Hash (0 when empty/unknown).
func hashFromName(name string) crypto.Hash {
	switch name {
	case "sha1":
		return crypto.SHA1
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

// buildAuditExporter translates the audit-export config into a siem.Exporter
// bound to the database (as both the event source and the durable cursor store).
func buildAuditExporter(db *database.DB, cfg *config.Config) (*siem.Exporter, error) {
	ec := cfg.Audit.Export
	specs := make([]siem.SinkSpec, 0, len(ec.Sinks))
	for _, s := range ec.Sinks {
		format := siem.Format(s.Format)
		if format == "" {
			// A syslog collector expects syslog; a webhook expects NDJSON.
			if s.Type == "webhook" {
				format = siem.FormatJSON
			} else {
				format = siem.FormatRFC5424
			}
		}
		spec := siem.SinkSpec{
			Name:    s.Name,
			Type:    s.Type,
			Format:  format,
			Network: s.Network,
			Address: s.Address,
			Framing: siem.SyslogFraming(s.Framing),
			TLS: siem.SyslogTLSConfig{
				CAFile:             s.TLS.CAFile,
				ServerName:         s.TLS.ServerName,
				ClientCertFile:     s.TLS.ClientCertFile,
				ClientKeyFile:      s.TLS.ClientKeyFile,
				InsecureSkipVerify: s.TLS.InsecureSkipVerify,
			},
			URL:     s.URL,
			Headers: s.Headers,
			Formatter: siem.FormatterOptions{
				Hostname:     s.Hostname,
				AppName:      s.AppName,
				EnterpriseID: s.EnterpriseID,
				Facility:     s.Facility,
				CEFVendor:    s.CEFVendor,
				CEFProduct:   s.CEFProduct,
				CEFVersion:   s.CEFVersion,
			},
		}
		if s.TimeoutSeconds > 0 {
			spec.Timeout = time.Duration(s.TimeoutSeconds) * time.Second
		}
		if s.Network == "tls" && s.TLS.InsecureSkipVerify {
			log.Printf("WARNING: audit export sink %q has TLS verification disabled (insecure_skip_verify)", s.Name)
		}
		specs = append(specs, spec)
	}

	sinks, err := siem.BuildSinks(specs)
	if err != nil {
		return nil, err
	}
	opts := siem.Options{
		PollInterval: time.Duration(ec.PollIntervalSeconds) * time.Second,
		BatchSize:    ec.BatchSize,
		RetryBackoff: time.Duration(ec.RetryBackoffSeconds) * time.Second,
		MaxBackoff:   time.Duration(ec.MaxBackoffSeconds) * time.Second,
		Logger:       log.Default(),
	}
	return siem.NewExporter(db, db, sinks, opts), nil
}

// provisionTenants creates any config-declared tenants that do not yet exist and
// keeps their name/slug/KEK in sync on restart. It is idempotent: an existing
// tenant is updated in place rather than duplicated. The built-in default tenant
// is seeded by the schema migration and never needs declaring.
func provisionTenants(db *database.DB, tenants []config.TenantConfig) error {
	for _, tc := range tenants {
		slug := tc.Slug
		if slug == "" {
			slug = tc.ID
		}
		name := tc.Name
		if name == "" {
			name = tc.ID
		}
		existing, err := db.GetTenant(tc.ID)
		if err != nil {
			return fmt.Errorf("tenant %q: %w", tc.ID, err)
		}
		if existing == nil {
			if err := db.CreateTenant(&models.Tenant{
				ID:       tc.ID,
				Slug:     slug,
				Name:     name,
				Status:   models.TenantStatusActive,
				KEKLabel: tc.KEKLabel,
			}); err != nil {
				return fmt.Errorf("creating tenant %q: %w", tc.ID, err)
			}
			log.Printf("Provisioned tenant %q (slug=%s)", tc.ID, slug)
		}
	}
	return nil
}

// approvalExpiryLoop periodically retires stale four-eyes approval requests
// (Task 81). It runs only on the elected leader; an initial sweep runs
// immediately so a restart does not leave already-expired requests lingering
// until the first tick.
func approvalExpiryLoop(ctx context.Context, eng *approval.Engine, logger *log.Logger) {
	const interval = time.Hour
	sweep := func() {
		if n, err := eng.SweepExpired(ctx); err != nil {
			logger.Printf("approval-expiry: sweep failed: %v", err)
		} else if n > 0 {
			logger.Printf("approval-expiry: expired %d stale approval request(s)", n)
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// toRoleMap converts a config string->[]string role map into the typed form the
// rbac package expects. Unknown role names are dropped by rbac.NewAssignments.
func toRoleMap(in map[string][]string) map[string][]rbac.Role {
	if in == nil {
		return nil
	}
	out := make(map[string][]rbac.Role, len(in))
	for k, roles := range in {
		typed := make([]rbac.Role, 0, len(roles))
		for _, r := range roles {
			typed = append(typed, rbac.Role(r))
		}
		out[k] = typed
	}
	return out
}

// dedupRoles collapses a role slice to unique string values, preserving order.
func dedupRoles(roles []rbac.Role) []string {
	seen := make(map[rbac.Role]bool, len(roles))
	var out []string
	for _, r := range roles {
		if !seen[r] {
			seen[r] = true
			out = append(out, string(r))
		}
	}
	return out
}

// buildRateLimit constructs the public-endpoint rate-limit middleware from the
// configuration, or returns nil when nothing would be enforced. Unset knobs
// fall back to safe defaults, and the concurrency guard's ceiling defaults to
// the PKCS#11 session pool size so it tracks the backend it protects. The
// limiter and guard obey rate_limit.enabled; the tenant enrollment gate
// (suspension blocking + per-tenant overrides, Task 61) is always wired when a
// store is available, since tenant lifecycle enforcement must not depend on
// rate limiting being turned on.
func buildRateLimit(cfg *config.Config, db *database.DB) *ratelimit.Middleware {
	rl := cfg.RateLimit

	var limiter *ratelimit.TieredLimiter
	var guard *ratelimit.Guard
	if rl.Enabled {
		limiter = ratelimit.NewTieredLimiter(ratelimit.LimiterConfig{
			Global:     ratelimit.Rate{Rate: rl.Global.Rate, Burst: rl.Global.Burst},
			PerIP:      ratelimit.Rate{Rate: rl.PerIP.Rate, Burst: rl.PerIP.Burst},
			PerAccount: ratelimit.Rate{Rate: rl.PerAccount.Rate, Burst: rl.PerAccount.Burst},
			PerTenant:  ratelimit.Rate{Rate: rl.PerTenant.Rate, Burst: rl.PerTenant.Burst},
			MaxKeys:    rl.MaxKeys,
			IdleTTL:    time.Duration(rl.IdleTTLSeconds) * time.Second,
		})
	}

	if rl.Enabled && rl.Concurrency.GuardEnabled(true) {
		maxInFlight := rl.Concurrency.MaxInFlight
		if maxInFlight <= 0 {
			// Track the session pool: bounding in-flight requests to the number of
			// concurrent HSM sessions keeps the pool busy without letting excess
			// requests pile up behind its borrow() backpressure.
			maxInFlight = cfg.PKCS11.SessionPoolSize
			if maxInFlight <= 0 {
				maxInFlight = keyprovider.DefaultSessionPoolSize
			}
		}
		maxQueue := rl.Concurrency.MaxQueue
		if maxQueue == 0 {
			maxQueue = 64
		}
		timeout := time.Duration(rl.Concurrency.AcquireTimeoutMs) * time.Millisecond
		if rl.Concurrency.AcquireTimeoutMs == 0 {
			timeout = 5 * time.Second
		}
		guard = ratelimit.NewGuard(ratelimit.GuardConfig{
			MaxInFlight:    maxInFlight,
			MaxQueue:       maxQueue,
			AcquireTimeout: timeout,
		})
	}

	// Only meter a protocol's paths when its server is actually mounted; OCSP and
	// CRL live under the always-present CA API and are matched unconditionally.
	pref := ratelimit.Prefixes{}
	if cfg.ACME.Enabled {
		pref.ACME = orDefaultPath(cfg.ACME.DirectoryPath, "/acme")
	}
	if cfg.EST.Enabled {
		pref.EST = orDefaultPath(cfg.EST.BasePath, "/.well-known/est")
	}
	if cfg.BRSKI.Enabled {
		pref.BRSKI = orDefaultPath(cfg.BRSKI.BasePath, "/.well-known/brski")
	}
	if cfg.SCEP.Enabled {
		pref.SCEP = orDefaultPath(cfg.SCEP.DirectoryPath, "/scep")
	}
	if cfg.TSA.Enabled {
		pref.TSA = orDefaultPath(cfg.TSA.Path, "/tsa")
	}
	if cfg.CMP.Enabled {
		pref.CMP = orDefaultPath(cfg.CMP.Path, "/cmp")
	}
	if cfg.MSWSTEP.Enabled {
		pref.MSXCEP = orDefaultPath(cfg.MSWSTEP.PolicyPath, "/mswstep/policy")
		pref.MSWSTEP = orDefaultPath(cfg.MSWSTEP.EnrollPath, "/mswstep/enroll")
	}
	if cfg.Signing.Enabled {
		pref.Sign = "/api/sign"
	}

	var tenantState func(*http.Request, string) *ratelimit.TenantState
	if db != nil {
		tenantState = newTenantStateSource(db, cfg).Resolve
	}
	if limiter == nil && guard == nil && tenantState == nil {
		return nil
	}
	return ratelimit.New(ratelimit.Options{Limiter: limiter, Guard: guard, Prefixes: pref, TenantState: tenantState})
}

// tenantStateTTL bounds how stale the middleware's view of a tenant's
// lifecycle/rate override may be. Suspension therefore reaches the public
// enrollment surfaces within a few seconds without a per-request DB hit; the
// authoritative fail-closed gate inside the CA manager always reads fresh
// state.
const tenantStateTTL = 3 * time.Second

// tenantStateSource resolves, for the rate-limit middleware, which tenant owns
// each public enrollment protocol (via the protocol instance's bound CA) and
// that tenant's current lifecycle/rate-override state. A protocol's CA→tenant
// binding is immutable, so it is resolved lazily once; the tenant state itself
// is cached for tenantStateTTL.
type tenantStateSource struct {
	db  *database.DB
	cfg *config.Config

	mu            sync.Mutex
	tenantByProto map[string]string
	stateByTenant map[string]cachedTenantState
}

type cachedTenantState struct {
	state   ratelimit.TenantState
	expires time.Time
}

func newTenantStateSource(db *database.DB, cfg *config.Config) *tenantStateSource {
	return &tenantStateSource{
		db:            db,
		cfg:           cfg,
		tenantByProto: make(map[string]string),
		stateByTenant: make(map[string]cachedTenantState),
	}
}

// Resolve maps a classified endpoint (e.g. "acme_finalize", "est_enroll") to
// its protocol's tenant state. Endpoints that are not tenant-scoped, and
// protocols whose CA cannot (yet) be resolved, return nil — the middleware then
// applies no tenant handling and the CA-manager gate remains the enforcement
// point.
func (s *tenantStateSource) Resolve(_ *http.Request, endpoint string) *ratelimit.TenantState {
	var proto string
	switch {
	case strings.HasPrefix(endpoint, "acme"):
		proto = "acme"
	case strings.HasPrefix(endpoint, "est"):
		proto = "est"
	case strings.HasPrefix(endpoint, "scep"):
		proto = "scep"
	case endpoint == "cmp":
		proto = "cmp"
	case strings.HasPrefix(endpoint, "mswstep"):
		proto = "mswstep"
	default:
		return nil
	}
	tenantID := s.tenantForProtocol(proto)
	if tenantID == "" {
		return nil
	}
	return s.stateFor(tenantID)
}

// tenantForProtocol resolves (once) the tenant that owns the protocol's bound
// CA. An unresolvable CA (e.g. not created yet) is retried on the next request
// rather than cached.
func (s *tenantStateSource) tenantForProtocol(proto string) string {
	s.mu.Lock()
	if id, ok := s.tenantByProto[proto]; ok {
		s.mu.Unlock()
		return id
	}
	s.mu.Unlock()

	var caID, caLabel string
	switch proto {
	case "acme":
		caID, caLabel = s.cfg.ACME.CAID, s.cfg.ACME.CALabel
	case "est":
		caID, caLabel = s.cfg.EST.CAID, s.cfg.EST.CALabel
	case "scep":
		caID, caLabel = s.cfg.SCEP.CAID, s.cfg.SCEP.CALabel
	case "cmp":
		caID, caLabel = s.cfg.CMP.CAID, s.cfg.CMP.CALabel
	case "mswstep":
		caID, caLabel = s.cfg.MSWSTEP.CAID, s.cfg.MSWSTEP.CALabel
	}
	var caRec *models.CA
	var err error
	switch {
	case caID != "":
		caRec, err = s.db.GetCA(caID)
	case caLabel != "":
		caRec, err = s.db.GetCAByLabel(caLabel)
	}
	if err != nil || caRec == nil {
		return ""
	}
	tenantID := caRec.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	s.mu.Lock()
	s.tenantByProto[proto] = tenantID
	s.mu.Unlock()
	return tenantID
}

// stateFor returns the tenant's current middleware-relevant state, cached for
// tenantStateTTL. A read failure yields nil (no middleware-level handling)
// rather than blocking traffic: the CA manager's gate is the fail-closed
// authority, while this front gate is best-effort protocol-surface hygiene.
func (s *tenantStateSource) stateFor(tenantID string) *ratelimit.TenantState {
	now := time.Now()
	s.mu.Lock()
	if e, ok := s.stateByTenant[tenantID]; ok && now.Before(e.expires) {
		s.mu.Unlock()
		st := e.state
		return &st
	}
	s.mu.Unlock()

	t, err := s.db.GetTenant(tenantID)
	if err != nil || t == nil {
		return nil
	}
	st := ratelimit.TenantState{ID: t.ID, Suspended: t.Status != models.TenantStatusActive}
	if t.Quotas.RateLimitPerSecond > 0 && t.Quotas.RateLimitBurst > 0 {
		st.Limit = &ratelimit.Rate{Rate: t.Quotas.RateLimitPerSecond, Burst: t.Quotas.RateLimitBurst}
	}
	s.mu.Lock()
	s.stateByTenant[tenantID] = cachedTenantState{state: st, expires: now.Add(tenantStateTTL)}
	s.mu.Unlock()
	return &st
}

// orDefaultPath returns p when non-empty (after trimming), else the default.
func orDefaultPath(p, def string) string {
	if strings.TrimSpace(p) == "" {
		return def
	}
	return p
}

// buildCTSubmitter constructs the Certificate Transparency submitter from the
// configured logs. It returns (nil, nil) when no logs are configured, which
// leaves CT disabled regardless of per-profile settings. Log public keys may be
// supplied inline (public_key) or from a file (public_key_file).
func buildCTSubmitter(cfg config.CTConfig) (*ct.Submitter, error) {
	if len(cfg.Logs) == 0 {
		return nil, nil
	}
	logs := make([]ct.LogConfig, 0, len(cfg.Logs))
	for _, l := range cfg.Logs {
		pubPEM := l.PublicKey
		if pubPEM == "" && l.PublicKeyFile != "" {
			data, err := os.ReadFile(l.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("reading public_key_file for CT log %q: %w", l.Name, err)
			}
			pubPEM = string(data)
		}
		logs = append(logs, ct.LogConfig{Name: l.Name, URL: l.URL, PublicKeyPEM: pubPEM, MMD: l.MMD(), Operator: l.Operator})
	}
	// Optionally attribute logs to their operators from a Google-style CT log
	// list, filling only logs without an explicit operator (operator config
	// always wins). This lets an operator-diversity policy work without
	// hand-copying every operator name.
	if f := strings.TrimSpace(cfg.KnownLogsFile); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading certificate_transparency.known_logs_file %q: %w", f, err)
		}
		ops, err := ct.LoadOperatorMap(data)
		if err != nil {
			return nil, fmt.Errorf("certificate_transparency.known_logs_file %q: %w", f, err)
		}
		ct.ApplyOperators(logs, ops)
	}
	// A dedicated HTTP client with a conservative overall timeout; per-attempt
	// timeouts are applied by the submitter from each profile's policy.
	client := &http.Client{Timeout: 30 * time.Second}
	return ct.NewSubmitter(logs, client)
}

// validateCTOperatorPolicy fails startup when a profile enables a CT
// operator-diversity policy (min_distinct_operators / require_operators) that the
// configured logs cannot possibly satisfy: a candidate log missing an operator
// (diversity over an unknown operator is meaningless), fewer distinct operators
// available than required, or a required operator that runs none of the
// candidate logs. Operators are read from the (already operator-resolved)
// submitter, so any known_logs_file attribution is reflected. The candidate set
// is the profile's named logs, or every registered log when none are named.
func validateCTOperatorPolicy(profile string, pc config.ProfileCTConfig, sub *ct.Submitter) error {
	opByName := make(map[string]string)
	for _, l := range sub.Logs() {
		opByName[l.Name] = strings.TrimSpace(l.Operator)
	}
	names := pc.Logs
	if len(names) == 0 {
		names = sub.LogNames()
	}
	operators := make(map[string]bool)
	var missing []string
	for _, n := range names {
		if op := opByName[n]; op != "" {
			operators[op] = true
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("profile %q enables a CT operator-diversity policy (min_distinct_operators/require_operators) but these candidate logs have no operator configured: %v — set each log's `operator` or a certificate_transparency.known_logs_file", profile, missing)
	}
	if n := pc.MinDistinctOperators; n > len(operators) {
		return fmt.Errorf("profile %q requires %d distinct CT log operators but its candidate logs cover only %d", profile, n, len(operators))
	}
	for _, req := range pc.RequireOperators {
		if req = strings.TrimSpace(req); req != "" && !operators[req] {
			return fmt.Errorf("profile %q requires an SCT from CT operator %q but none of its candidate logs is run by that operator", profile, req)
		}
	}
	return nil
}

// buildRoleProvider constructs the instrumented key provider for a signing role
// ("ca" or "tsa"), selecting the backend from the per-role override or the global
// key_provider.type. All backend sub-settings (PKCS#11 token, software keystore,
// cloud KMS) are shared; only the selected type differs per role.
func buildRoleProvider(cfg *config.Config, role string) (keyprovider.Provider, error) {
	p, err := keyprovider.New(keyProviderConfigForRole(cfg, role))
	if err != nil {
		return nil, err
	}
	// Wrap so every key operation (sign, decrypt, generate, find, public-key
	// export, connectivity probe) records latency and error metrics. The wrapper
	// is transparent and preserves the Decrypter/Prober/KeyLister capabilities.
	// The ledger wrapper goes outside it so a signature is recorded only once it
	// has actually been produced (Task 167).
	return recordHSMSignatures(keyprovider.Instrument(p)), nil
}

// pkcs11TokenSettings maps the config's optional multi-token HA list onto the
// keyprovider token-settings type. It returns nil for the single-token case so
// keyprovider.New selects the direct pooled provider.
func pkcs11TokenSettings(tokens []config.PKCS11TokenConfig) []keyprovider.TokenSettings {
	if len(tokens) == 0 {
		return nil
	}
	out := make([]keyprovider.TokenSettings, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, keyprovider.TokenSettings{
			Name:              t.Name,
			URI:               t.URI,
			TokenLabel:        t.TokenLabel,
			TokenSerial:       t.TokenSerial,
			TokenManufacturer: t.TokenManufacturer,
			Pin:               t.Pin,
			PinSource:         pinSourceSettings(t.PinSource),
		})
	}
	return out
}

// pinSourceSettings maps the config pin_source block onto the keyprovider settings
// type (mirrors the helper in cmd/secsy-ca and cmd/secsy-secret). It reuses
// vaultSettings for the embedded Vault connection parameters.
func pinSourceSettings(p config.PinSourceConfig) keyprovider.PinSourceSettings {
	return keyprovider.PinSourceSettings{
		Type: p.Type,
		Env:  keyprovider.EnvPinSourceSettings{Var: p.Env.Var},
		File: keyprovider.FilePinSourceSettings{Path: p.File.Path, AllowInsecurePerms: p.File.AllowInsecurePerms},
		Vault: keyprovider.VaultPinSourceSettings{
			VaultSettings: vaultSettings(p.Vault.VaultProviderConfig),
			Path:          p.Vault.Path,
			Field:         p.Vault.Field,
			KVVersion:     p.Vault.KVVersion,
		},
		AWS:   keyprovider.AWSPinSourceSettings{Region: p.AWS.Region, SecretID: p.AWS.SecretID, Field: p.AWS.Field},
		Azure: keyprovider.AzurePinSourceSettings{VaultURL: p.Azure.VaultURL, Name: p.Azure.Name, Version: p.Azure.Version, Field: p.Azure.Field},
		GCP:   gcpPinSourceSettings(p.GCP),
	}
}

// keyProviderConfigForRole assembles the keyprovider.Config for a role, resolving
// the backend type via the config's per-role override. It is shared by the server
// and (in cmd/secsy-ca) the CLI so both wire identical settings.
func keyProviderConfigForRole(cfg *config.Config, role string) keyprovider.Config {
	return keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProviderTypeForRole(role)),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			URI:               cfg.PKCS11.URI,
			Pin:               cfg.PKCS11.Pin,
			PinSource:         pinSourceSettings(cfg.PKCS11.PinSource),
			TokenLabel:        cfg.PKCS11.TokenLabel,
			TokenSerial:       cfg.PKCS11.TokenSerial,
			TokenManufacturer: cfg.PKCS11.TokenManufacturer,
			SessionPoolSize:   cfg.PKCS11.SessionPoolSize,
			Tokens:            pkcs11TokenSettings(cfg.PKCS11.Tokens),
			SelectionPolicy:   cfg.PKCS11.SelectionPolicy,
			FailureThreshold:  cfg.PKCS11.FailureThreshold,
			ProbeInterval:     time.Duration(cfg.PKCS11.ProbeIntervalSeconds) * time.Second,
		},
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: cfg.KeyProvider.Software.KeystoreDir,
		},
		KMS: keyprovider.KMSSettings{
			Backend:   cfg.KeyProvider.KMS.Backend,
			Region:    cfg.KeyProvider.KMS.Region,
			KeyPrefix: cfg.KeyProvider.KMS.KeyPrefix,
			VaultURL:  cfg.KeyProvider.KMS.VaultURL,
			Vault:     vaultSettings(cfg.KeyProvider.KMS.Vault),
			GCP:       gcpKMSSettings(cfg.KeyProvider.KMS.GCP),
		},
	}
}

// gcpKMSSettings maps the config's Google Cloud KMS block onto the keyprovider
// settings type. It is shared by the server and (in cmd/secsy-ca) the CLI so
// both wire identical Cloud KMS parameters.
func gcpKMSSettings(g config.GCPProviderConfig) keyprovider.GCPKMSSettings {
	return keyprovider.GCPKMSSettings{
		Project:         g.Project,
		Location:        g.Location,
		KeyRing:         g.KeyRing,
		CredentialsFile: g.CredentialsFile,
		CredentialsJSON: g.CredentialsJSON,
		ProtectionLevel: g.ProtectionLevel,
		RSAPSS:          g.RSAPSS,
		Endpoint:        g.Endpoint,
	}
}

// gcpPinSourceSettings maps the config's Google Cloud Secret Manager pin_source
// block onto the keyprovider settings type. Shared across the three commands.
func gcpPinSourceSettings(g config.GCPPinSourceConfig) keyprovider.GCPPinSourceSettings {
	return keyprovider.GCPPinSourceSettings{
		Project:         g.Project,
		Secret:          g.Secret,
		Version:         g.Version,
		CredentialsFile: g.CredentialsFile,
		CredentialsJSON: g.CredentialsJSON,
		Field:           g.Field,
		Endpoint:        g.Endpoint,
	}
}

// vaultSettings maps the config's HashiCorp Vault block onto the keyprovider
// settings type. It is shared by the server and (in cmd/secsy-ca) the CLI so both
// wire identical Vault Transit parameters.
func vaultSettings(v config.VaultProviderConfig) keyprovider.VaultSettings {
	return keyprovider.VaultSettings{
		Address:     v.Address,
		Mount:       v.Mount,
		Namespace:   v.Namespace,
		AuthMethod:  v.AuthMethod,
		Token:       v.Token,
		RoleID:      v.RoleID,
		SecretID:    v.SecretID,
		AppRolePath: v.AppRolePath,
		CACertFile:  v.CACertFile,
		Insecure:    v.Insecure,
		Timeout:     time.Duration(v.TimeoutSeconds) * time.Second,
	}
}

// newStapledCertificate loads the server's TLS key pair, produces an initial
// OCSP staple signed under caID, and launches a background refresher. Stapling
// is best-effort: a failure to obtain a staple is logged but does not prevent
// the server from serving (the certificate is served without a staple). It
// returns the shared servingcert.Holder whose GetCertificate hook feeds the TLS
// listener — the same hook the self-issued serving certificate rotates through.
func newStapledCertificate(certFile, keyFile, caID string, db *database.DB, provider keyprovider.Provider) (*servingcert.Holder, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing TLS certificate: %w", err)
	}
	pair.Leaf = leaf
	holder := servingcert.NewHolder(&pair)

	refresh := func() time.Time {
		mgr := ca.NewManager(db, provider)
		// Bound each attempt so a hung HSM call cannot wedge the refresher.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		staple, err := mgr.OCSPStapleForCertificate(ctx, caID, leaf, ca.OCSPRespondOptions{})
		if err != nil {
			metrics.OCSPStaples.Inc(metrics.ResultError)
			log.Printf("OCSP stapling: failed to refresh staple: %v", err)
			return time.Now().Add(5 * time.Minute) // retry soon
		}
		holder.SetStaple(staple)
		metrics.OCSPStaples.Inc(metrics.ResultSuccess)
		// Re-staple at half the response validity to always serve a fresh staple.
		if nextUpdate, ok := pki.OCSPResponseNextUpdate(staple); ok {
			half := time.Until(nextUpdate) / 2
			if half < time.Minute {
				half = time.Minute
			}
			return time.Now().Add(half)
		}
		return time.Now().Add(time.Hour)
	}

	next := refresh() // initial staple, best-effort
	go func() {
		for {
			time.Sleep(time.Until(next))
			next = refresh()
		}
	}()
	return holder, nil
}

// buildSelfIssuedServingCert wires the self-managed serving certificate (Task
// 118) from config: it resolves the renew-before/IP/validity fields, constructs a
// ca.Manager over the same key provider, and issues the initial certificate. It
// returns (nil, nil) when self-issue is disabled so the caller falls back cleanly
// to the static tls_cert/tls_key path.
func buildSelfIssuedServingCert(ctx context.Context, cfg *config.Config, db *database.DB, provider keyprovider.Provider) (*servingcert.SelfIssuer, error) {
	sc := cfg.Server.TLS.SelfIssue
	if !sc.Enabled {
		return nil, nil
	}
	renewBefore, err := sc.RenewBeforeDuration()
	if err != nil {
		return nil, err
	}
	ips, err := sc.ParsedIPs()
	if err != nil {
		return nil, err
	}
	return servingcert.New(ctx, ca.NewManager(db, provider), provider, servingcert.Config{
		CAID:        sc.CAID,
		Profile:     sc.ResolvedProfile(),
		CommonName:  sc.ResolvedCommonName(),
		DNSNames:    sc.DNSNames,
		IPs:         ips,
		KeyLabel:    sc.ResolvedKeyLabel(),
		KeyType:     sc.KeyType,
		RenewBefore: renewBefore,
		Validity:    sc.Validity(),
	}, log.Default())
}
