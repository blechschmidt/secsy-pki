package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ssh-pki/server/internal/auth"
	"github.com/ssh-pki/server/internal/config"
	"github.com/ssh-pki/server/internal/database"
	"github.com/ssh-pki/server/internal/handlers"
	"github.com/ssh-pki/server/internal/middleware"
	"github.com/ssh-pki/server/internal/pki"
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

	p11cfg := pki.PKCS11Config{
		ModulePath: cfg.PKCS11.ModulePath,
		Pin:        cfg.PKCS11.Pin,
		TokenLabel: cfg.PKCS11.TokenLabel,
	}

	api := handlers.NewAPI(db, p11cfg, oidcProvider)

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
