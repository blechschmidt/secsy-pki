package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/est"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/ratelimit"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/scep"
	"github.com/blechschmidt/secsy-pki/server/internal/siem"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.New(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

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
	authMw.SetRoleResolver(func(u *models.UserInfo) []string {
		groupIDs, _ := db.GetUserGroups(u.Subject)
		roles := rbacAssignments.RolesFor(u.Subject, groupIDs)
		// Email-keyed assignments are only honored for a verified email. An
		// unverified or user-settable email must not let a subject claim roles
		// assigned to someone else's address. The immutable subject and group
		// memberships are always trusted.
		if u.Email != "" && u.EmailVerified {
			roles = append(roles, rbacAssignments.RolesFor(u.Email, nil)...)
		}
		return dedupRoles(roles)
	})
	authMw.SetRootEnabled(cfg.Policy.RootBasicAuthEnabled())
	if !cfg.Policy.RootBasicAuthEnabled() {
		log.Printf("Built-in root basic-auth login is DISABLED (policy.allow_root_basic_auth=false)")
	}
	if !rbacAssignments.Empty() {
		log.Printf("RBAC role assignments loaded (subjects=%d, groups=%d)", len(cfg.RBAC.Subjects), len(cfg.RBAC.Groups))
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

	// Install any operator-defined certificate profiles, layered over built-ins.
	if len(cfg.Profiles) > 0 {
		profiles := make([]ca.Profile, 0, len(cfg.Profiles))
		for _, p := range cfg.Profiles {
			prof := ca.Profile{
				Name:                p.Name,
				Description:         p.Description,
				KeyUsages:           p.KeyUsages,
				ExtKeyUsages:        p.ExtKeyUsages,
				DefaultValidityDays: p.DefaultValidityDays,
				MaxValidityDays:     p.MaxValidityDays,
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
					Enabled:        true,
					Logs:           p.CT.Logs,
					MinSCTs:        p.CT.MinSCTs,
					FailOpen:       p.CT.FailOpen,
					TimeoutSeconds: p.CT.TimeoutSeconds,
					Retries:        p.CT.Retries,
				}
			}
			prof.Lint = &ca.LintConfig{
				Disabled:  p.Lint.Disabled,
				Mode:      p.Lint.Mode,
				Public:    p.Lint.Public,
				Overrides: p.Lint.Overrides,
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
			profiles = append(profiles, prof)
		}
		if err := ca.SetCustomProfiles(profiles); err != nil {
			log.Fatalf("Invalid custom certificate profile: %v", err)
		}
		log.Printf("Loaded %d custom certificate profile(s)", len(profiles))
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

	// Ensure YUBIHSM_PKCS11_CONF is set so the YubiHSM PKCS#11 module knows the connector URL
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err != nil {
			log.Printf("WARNING: failed to write %s: %v", confPath, err)
		} else {
			os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}

	provider, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProvider.Type),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			Pin:               cfg.PKCS11.Pin,
			TokenLabel:        cfg.PKCS11.TokenLabel,
			TokenSerial:       cfg.PKCS11.TokenSerial,
			TokenManufacturer: cfg.PKCS11.TokenManufacturer,
			SessionPoolSize:   cfg.PKCS11.SessionPoolSize,
		},
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: cfg.KeyProvider.Software.KeystoreDir,
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize key provider: %v", err)
	}
	defer provider.Close()
	log.Printf("Key provider: %s", provider.Name())

	// Wrap the provider so every key operation (sign, decrypt, generate, find,
	// public-key export, connectivity probe) records latency and error metrics.
	// The wrapper is transparent and preserves the Decrypter/Prober capabilities.
	provider = keyprovider.Instrument(provider)

	hsmCfg := hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	}

	api := handlers.NewAPI(db, provider, oidcProvider, hsmCfg, cfg.YubiHSM.SuppressAuditWarning, cfg.Secret.KEKLabel)
	api.SetPolicy(handlers.Policy{
		RequireReason:       cfg.Policy.RequireReason,
		MaxCertValidityDays: cfg.Policy.MaxCertValidityDays,
	})
	monitorOpts := monitor.OptionsFromDays(
		cfg.Monitor.WarningDays, cfg.Monitor.CriticalDays,
		cfg.Monitor.RenewBeforeDays, cfg.Monitor.RenewProfiles)
	api.SetMonitorOptions(monitorOpts)
	// OCSP response cache TTL: 0 keeps the server default, a negative value
	// disables caching, and a positive value sets an explicit TTL.
	if cfg.Server.OCSPCacheTTLSeconds != 0 {
		api.SetOCSPCacheTTL(time.Duration(cfg.Server.OCSPCacheTTLSeconds) * time.Second)
	}
	if cfg.Secret.KEKLabel != "" {
		log.Printf("Secret encryption enabled (KEK label: %s)", cfg.Secret.KEKLabel)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	// Operational endpoints: Prometheus /metrics, /healthz (liveness), /readyz
	// (readiness incl. HSM/DB probes). Unauthenticated by design — restrict at
	// the network layer if needed.
	api.RegisterObservability(mux)

	// Certificate-expiry monitor: a background goroutine that periodically scans
	// issued certificates, reports upcoming expirations through the configured
	// notification sinks, and (when enabled) auto-renews eligible leaves via the
	// same HSM-backed issuance path. Runs for the process lifetime.
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
		go runner.Run(context.Background())
	}

	// Audit-log SIEM export: a background worker per sink streams the
	// tamper-evident event log to external syslog/CEF/webhook collectors from a
	// durable per-sink cursor. At-least-once, backpressured, and lossless across
	// restarts. Runs for the process lifetime.
	if cfg.Audit.Export.Enabled {
		exporter, err := buildAuditExporter(db, cfg)
		if err != nil {
			log.Fatalf("Audit SIEM export configuration error: %v", err)
		}
		log.Printf("Audit SIEM export enabled (%d sink(s))", len(cfg.Audit.Export.Sinks))
		go exporter.Run(context.Background())
	}

	// ACME (RFC 8555) automated-issuance server. Its endpoints authenticate
	// clients via JWS account keys (not OIDC/basic auth) and are therefore
	// registered directly on the mux, outside the OIDC auth middleware.
	if cfg.ACME.Enabled {
		acmeCfg, err := buildACMEConfig(db, cfg)
		if err != nil {
			log.Fatalf("ACME configuration error: %v", err)
		}
		acmeSrv := acme.New(db, provider, acmeCfg)
		acmeSrv.Register(mux)
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
		scep.New(db, provider, scepCfg).Register(mux)
	}

	// EST (RFC 7030) device-enrollment server. Authenticates via HTTP Basic or a
	// TLS client certificate; mounted outside the OIDC middleware.
	if cfg.EST.Enabled {
		estCfg, err := buildESTConfig(db, cfg)
		if err != nil {
			log.Fatalf("EST configuration error: %v", err)
		}
		est.New(db, provider, estCfg).Register(mux)
	}

	// RFC 3161 Time-Stamp Authority. The /tsa endpoint is anonymous and public
	// (like OCSP/CRL), so it mounts outside the OIDC middleware and is metered by
	// the rate-limit + HSM-concurrency guard below.
	if cfg.TSA.Enabled {
		tsaCfg, err := buildTSAConfig(db, cfg)
		if err != nil {
			log.Fatalf("TSA configuration error: %v", err)
		}
		authority, err := tsa.New(db, provider, tsaCfg)
		if err != nil {
			log.Fatalf("TSA configuration error: %v", err)
		}
		authority.Register(mux)
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

	// Cap every request body to guard against memory-exhaustion DoS from an
	// (authenticated) client. Individual handlers may impose tighter limits.
	handler := limitRequestBody(mux, maxRequestBodyBytes)

	// Rate limiting, per-account/IP/global quotas, and a bounded in-flight
	// concurrency guard protecting the HSM on the public endpoints (ACME, OCSP,
	// CRL, SCEP/EST). Sits inside the observability layer so shed requests are
	// still logged and metered, and outside the body cap so it runs before any
	// per-handler work. No-op when rate_limit.enabled is false.
	if rlmw := buildRateLimit(cfg); rlmw != nil && rlmw.Active() {
		handler = rlmw.Handler(handler)
		log.Printf("Rate limiting enabled for public endpoints (ACME/OCSP/CRL/SCEP/EST)")
	}

	// Outermost middleware: assign a correlation ID to every request, record HTTP
	// metrics, and emit one structured (JSON) log line per request. Wrapping the
	// whole tree means it also covers ACME, static assets, and the health/metrics
	// endpoints, and makes the request ID visible to the access and audit logs.
	obs := middleware.NewObservability(os.Stdout)
	handler = obs.Handler(handler)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		server := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsCfg,
		}
		log.Printf("Starting HTTPS server on %s", addr)
		if err := server.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil {
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
		ChallengeTypes:     cfg.ACME.ChallengeTypes,
		RequireEAB:         cfg.ACME.RequireEAB,
		EABHMACKeys:        cfg.ACME.EABHMACKeys,
		AllowIPIdentifiers: cfg.ACME.AllowIPIdentifiers,
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
	return ac, nil
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
	return est.Config{
		BasePath:               cfg.EST.BasePath,
		CAID:                   caID,
		Profile:                cfg.EST.Profile,
		Users:                  users,
		AllowTLSClientReenroll: cfg.EST.AllowTLSClientReenroll,
		EnableServerKeygen:     cfg.EST.EnableServerKeygen,
		ServerKeygenKeyType:    cfg.EST.ServerKeygenKeyType,
	}, nil
}

// buildTSAConfig assembles the tsa.Config from the application config. It loads
// the TSA signing certificate (and any inline chain) from the configured PEM
// file, appending the issuing CA's chain from the database when a CA is named
// and the file carries only the leaf. It parses the policy OID, signature
// digest, and accepted message-imprint hashes.
func buildTSAConfig(db *database.DB, cfg *config.Config) (tsa.Config, error) {
	certPEM, err := os.ReadFile(cfg.TSA.CertificateFile)
	if err != nil {
		return tsa.Config{}, fmt.Errorf("reading tsa.certificate_file %q: %w", cfg.TSA.CertificateFile, err)
	}
	chain, err := parseCertChainPEM(certPEM)
	if err != nil {
		return tsa.Config{}, fmt.Errorf("parsing tsa.certificate_file: %w", err)
	}
	if len(chain) == 0 {
		return tsa.Config{}, fmt.Errorf("tsa.certificate_file %q contains no certificates", cfg.TSA.CertificateFile)
	}

	// If the file holds only the TSA leaf, append the issuing CA's chain from the
	// database so certReq responses carry a verifiable path.
	if len(chain) == 1 && (cfg.TSA.CAID != "" || cfg.TSA.CALabel != "") {
		caID, err := resolveCAID(db, cfg.TSA.CAID, cfg.TSA.CALabel, "tsa")
		if err != nil {
			return tsa.Config{}, err
		}
		issuers, err := loadCAChain(db, caID)
		if err != nil {
			return tsa.Config{}, err
		}
		chain = append(chain, issuers...)
	}

	tc := tsa.Config{
		Path:            cfg.TSA.Path,
		KeyLabel:        cfg.TSA.KeyLabel,
		Certificate:     chain[0],
		Chain:           chain,
		Accuracy:        tsa.Accuracy{Seconds: cfg.TSA.AccuracySeconds, Millis: cfg.TSA.AccuracyMillis, Micros: cfg.TSA.AccuracyMicros},
		Ordering:        cfg.TSA.Ordering,
		SignatureDigest: hashFromName(cfg.TSA.SignatureDigest),
		IncludeTSAName:  cfg.TSA.IncludeTSAName,
	}
	if cfg.TSA.PolicyOID != "" {
		oid, err := parseDottedOID(cfg.TSA.PolicyOID)
		if err != nil {
			return tsa.Config{}, fmt.Errorf("tsa.policy_oid: %w", err)
		}
		tc.PolicyOID = oid
	}
	for _, name := range cfg.TSA.AcceptedHashes {
		if h := hashFromName(name); h != 0 {
			tc.AcceptedHashes = append(tc.AcceptedHashes, h)
		}
	}
	return tc, nil
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

// parseDottedOID parses a dotted-decimal OID into an asn1.ObjectIdentifier.
func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid arc %q", p)
		}
		oid = append(oid, n)
	}
	return oid, nil
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
// configuration, or returns nil when rate limiting is disabled. Unset knobs
// fall back to safe defaults, and the concurrency guard's ceiling defaults to
// the PKCS#11 session pool size so it tracks the backend it protects.
func buildRateLimit(cfg *config.Config) *ratelimit.Middleware {
	rl := cfg.RateLimit
	if !rl.Enabled {
		return nil
	}

	limiter := ratelimit.NewTieredLimiter(ratelimit.LimiterConfig{
		Global:     ratelimit.Rate{Rate: rl.Global.Rate, Burst: rl.Global.Burst},
		PerIP:      ratelimit.Rate{Rate: rl.PerIP.Rate, Burst: rl.PerIP.Burst},
		PerAccount: ratelimit.Rate{Rate: rl.PerAccount.Rate, Burst: rl.PerAccount.Burst},
		MaxKeys:    rl.MaxKeys,
		IdleTTL:    time.Duration(rl.IdleTTLSeconds) * time.Second,
	})

	var guard *ratelimit.Guard
	if rl.Concurrency.GuardEnabled(true) {
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
	if cfg.SCEP.Enabled {
		pref.SCEP = orDefaultPath(cfg.SCEP.DirectoryPath, "/scep")
	}
	if cfg.TSA.Enabled {
		pref.TSA = orDefaultPath(cfg.TSA.Path, "/tsa")
	}

	return ratelimit.New(ratelimit.Options{Limiter: limiter, Guard: guard, Prefixes: pref})
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
		logs = append(logs, ct.LogConfig{Name: l.Name, URL: l.URL, PublicKeyPEM: pubPEM})
	}
	// A dedicated HTTP client with a conservative overall timeout; per-attempt
	// timeouts are applied by the submitter from each profile's policy.
	client := &http.Client{Timeout: 30 * time.Second}
	return ct.NewSubmitter(logs, client)
}
