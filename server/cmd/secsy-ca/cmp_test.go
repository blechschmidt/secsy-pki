//go:build sqlite

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cmp"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestCMPClientEndToEnd drives the `secsy-ca cmp` subcommand against a real
// (httptest) CMP server backed by a software-provider CA, exercising the full
// HTTP client path and response handling.
func TestCMPClientEndToEnd(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "cmp-cli.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "cmp-cli-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "CMP CLI Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}

	mux := http.NewServeMux()
	cmp.New(db, provider, cmp.Config{
		CAID:    root.ID,
		Profile: "client",
		Secrets: []cmp.Secret{{Reference: "cli-ref", Secret: "cli-secret", Profile: "client"}},
	}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	certOut := filepath.Join(t.TempDir(), "cert.pem")
	err = cmdCMP([]string{
		"-url", srv.URL + "/cmp",
		"-reference", "cli-ref",
		"-secret", "cli-secret",
		"-cn", "cli-device.example.com",
		"-dns", "cli-device.example.com",
		"-cert-out", certOut,
	})
	if err != nil {
		t.Fatalf("cmdCMP: %v", err)
	}
	if info, err := os.Stat(certOut); err != nil || info.Size() == 0 {
		t.Fatalf("certificate not written: err=%v", err)
	}

	// A wrong secret must produce a rejection error, not a certificate.
	err = cmdCMP([]string{
		"-url", srv.URL + "/cmp",
		"-reference", "cli-ref",
		"-secret", "wrong-secret",
		"-cn", "cli-device.example.com",
	})
	if err == nil {
		t.Fatal("cmdCMP accepted a wrong secret")
	}
}
