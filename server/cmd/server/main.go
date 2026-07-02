package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
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
		if u.Email != "" {
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
	if cfg.Secret.KEKLabel != "" {
		log.Printf("Secret encryption enabled (KEK label: %s)", cfg.Secret.KEKLabel)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	// Serve the SPA
	webDir := "web/static"
	if _, err := os.Stat(webDir); err == nil {
		mux.Handle("GET /", http.FileServer(http.Dir(webDir)))
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		server := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsCfg,
		}
		log.Printf("Starting HTTPS server on %s", addr)
		if err := server.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		log.Printf("WARNING: No TLS configured, starting HTTP server on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Server failed: %v", err)
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
