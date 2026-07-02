//go:build sqlite

package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestIntegrationDiscoverOwnIssuedCert is the end-to-end acceptance test: a CA is
// recorded in the real (SQLite) store, a leaf it issued is served over TLS, and
// the discovery Runner — building its trust pool from the store's CA
// certificates — scans the endpoint, recognizes the leaf as issued by this PKI
// (not rogue), and persists the finding into the discovered-certificate
// inventory. It exercises the full Runner path (store → known roots → scanner →
// inventory) without any HSM.
//
// It is tagged `sqlite` so it compiles only when the embedded SQLite driver is
// available (matching the rest of the store-backed tests); plain `go test ./...`
// skips it.
func TestIntegrationDiscoverOwnIssuedCert(t *testing.T) {
	db, err := database.New("sqlite", t.TempDir()+"/discovery-integration.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Build this PKI's CA and a leaf it issued, plus an unrelated (foreign) CA and
	// leaf to prove the rogue path is exercised in the same scan.
	caCert, caKey := makeCert(t, certOpts{cn: "Secsy Integration CA", isCA: true})
	ourLeaf, ourKey := makeCert(t, certOpts{
		cn:        "svc.internal.example",
		dnsNames:  []string{"svc.internal.example"},
		parent:    caCert,
		parentKey: caKey,
	})
	foreignCA, foreignKey := makeCert(t, certOpts{cn: "Foreign CA", isCA: true})
	foreignLeaf, foreignLeafKey := makeCert(t, certOpts{
		cn:        "shadow.internal.example",
		dnsNames:  []string{"shadow.internal.example"},
		parent:    foreignCA,
		parentKey: foreignKey,
	})

	// Record our CA in the store so KnownRootsFromStore recognizes leaves it signed.
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	notBefore, notAfter := caCert.NotBefore, caCert.NotAfter
	if err := db.CreateCA(&models.CA{
		ID:          "integration-ca",
		Label:       "Integration CA",
		PKCS11URI:   "pkcs11:object=integration",
		KeyType:     "ecdsa",
		PublicKey:   "unused-for-discovery",
		Certificate: caPEM,
		Subject:     caCert.Subject.String(),
		NotBefore:   &notBefore,
		NotAfter:    &notAfter,
	}); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	ourAddr := startTLSServer(t, []*x509.Certificate{ourLeaf, caCert}, ourKey)
	rogueAddr := startTLSServer(t, []*x509.Certificate{foreignLeaf, foreignCA}, foreignLeafKey)

	targets, err := ParseTargets(TargetSpec{Endpoints: []string{
		ourAddr + "#svc.internal.example",
		rogueAddr + "#shadow.internal.example",
	}})
	if err != nil {
		t.Fatalf("parse targets: %v", err)
	}

	runner := NewRunner(db, config.MonitorConfig{}, 30, nil)
	res, err := runner.Scan(context.Background(), targets, true /*store*/, false /*notify*/)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if res.Stored != 2 {
		t.Errorf("expected 2 stored findings, got %d", res.Stored)
	}
	if res.Report.Counts.IssuedByPKI != 1 {
		t.Errorf("expected exactly 1 issued-by-this-PKI finding, got %d", res.Report.Counts.IssuedByPKI)
	}
	if res.Report.Counts.Rogue != 1 {
		t.Errorf("expected exactly 1 rogue finding, got %d", res.Report.Counts.Rogue)
	}

	// Verify the finding for our own endpoint.
	var ours *Finding
	for i := range res.Report.Findings {
		if res.Report.Findings[i].CommonName == "svc.internal.example" {
			ours = &res.Report.Findings[i]
		}
	}
	if ours == nil {
		t.Fatal("no finding for our own endpoint")
	}
	if !ours.IssuedByPKI || ours.Rogue {
		t.Errorf("our leaf: issued_by_pki=%v rogue=%v, want true/false", ours.IssuedByPKI, ours.Rogue)
	}

	// Confirm persistence: the discovered-certificate inventory now holds both.
	stored, err := db.ListDiscoveredCertificates("")
	if err != nil {
		t.Fatalf("list discovered: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected 2 discovered records, got %d", len(stored))
	}
	var foundOurs bool
	for _, d := range stored {
		if d.CommonName == "svc.internal.example" {
			foundOurs = true
			if !d.IssuedByPKI || d.Rogue {
				t.Errorf("persisted record flags wrong: issued_by_pki=%v rogue=%v", d.IssuedByPKI, d.Rogue)
			}
			if d.Fingerprint == "" || d.Certificate == "" {
				t.Errorf("persisted record missing fingerprint/PEM")
			}
		}
	}
	if !foundOurs {
		t.Error("our issued certificate was not persisted to the inventory")
	}

	// Re-scanning must upsert (not duplicate) on (endpoint, fingerprint).
	if _, err := runner.Scan(context.Background(), targets, true, false); err != nil {
		t.Fatalf("re-scan: %v", err)
	}
	stored2, err := db.ListDiscoveredCertificates("")
	if err != nil {
		t.Fatalf("list discovered after re-scan: %v", err)
	}
	if len(stored2) != 2 {
		t.Errorf("re-scan should upsert in place; expected 2 records, got %d", len(stored2))
	}
}
