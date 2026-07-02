package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
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

	// Install any operator-defined certificate profiles, layered over built-ins.
	if len(cfg.Profiles) > 0 {
		profiles := make([]ca.Profile, 0, len(cfg.Profiles))
		for _, p := range cfg.Profiles {
			profiles = append(profiles, ca.Profile{
				Name:                p.Name,
				Description:         p.Description,
				KeyUsages:           p.KeyUsages,
				ExtKeyUsages:        p.ExtKeyUsages,
				DefaultValidityDays: p.DefaultValidityDays,
				MaxValidityDays:     p.MaxValidityDays,
			})
		}
		if err := ca.SetCustomProfiles(profiles); err != nil {
			log.Fatalf("Invalid custom certificate profile: %v", err)
		}
		log.Printf("Loaded %d custom certificate profile(s)", len(profiles))
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
		mon := monitor.New(db, ca.NewManager(db, provider), db, monitorOpts)
		runner, err := monitor.NewRunner(mon, cfg.Monitor, log.Default())
		if err != nil {
			log.Fatalf("Certificate-expiry monitor configuration error: %v", err)
		}
		go runner.Run(context.Background())
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

	// Serve the SPA
	webDir := "web/static"
	if _, err := os.Stat(webDir); err == nil {
		mux.Handle("GET /", http.FileServer(http.Dir(webDir)))
	}

	// Cap every request body to guard against memory-exhaustion DoS from an
	// (authenticated) client. Individual handlers may impose tighter limits.
	handler := limitRequestBody(mux, maxRequestBodyBytes)

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
	return ac, nil
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
