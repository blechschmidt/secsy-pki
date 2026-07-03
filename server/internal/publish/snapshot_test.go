//go:build sqlite

package publish

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func csrPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestBuildSnapshotFullLayout builds a snapshot from a real (software-provider)
// CA with partitioned CRLs, a revocation, and pre-signed OCSP responses, then
// publishes it to a directory store and verifies:
//   - the complete artifact layout (base/delta CRLs, per-shard CRLs, chain, CA
//     cert, OCSP by-serial and by-request keys),
//   - every CRL parses, is CA-signed, and covers the revoked serial in the
//     right shard,
//   - the pre-signed responses parse and attest the right statuses,
//   - the by-request key equals the base64url canonical GET request, so a CDN
//     mapping RFC 6960 GET URLs onto static objects finds the right response,
//   - the manifest verifies end to end (publish.Verify).
func TestBuildSnapshotFullLayout(t *testing.T) {
	// Partitioned CRL distribution for the duration of this test.
	ca.SetCRLConfig(ca.CRLDistConfig{Shards: 2, BaseURL: "https://pki.test"})
	defer ca.SetCRLConfig(ca.CRLDistConfig{})

	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { prov.Close() })

	ctx := context.Background()
	mgr := ca.NewManager(db, prov)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    "publish-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Publish Test Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert, err := pki.ParseCertificatePEM([]byte(root.Certificate))
	if err != nil {
		t.Fatalf("parsing root cert: %v", err)
	}

	var revokedSerial string
	for i := 0; i < 3; i++ {
		leaf, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
			CAID:    root.ID,
			CSRPEM:  csrPEM(t, fmt.Sprintf("leaf-%d.example.com", i)),
			Profile: "server",
		})
		if err != nil {
			t.Fatalf("IssueCertificate %d: %v", i, err)
		}
		if i == 0 {
			revokedSerial = leaf.Serial.String()
		}
	}
	if _, err := mgr.RevokeCertificate(ctx, root.ID, revokedSerial, "superseded"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	presigner := ca.NewOCSPPresigner(mgr, ca.OCSPPresignerConfig{Validity: 2 * time.Hour})
	artifacts, cas, err := BuildSnapshot(ctx, SnapshotSource{Mgr: mgr, DB: db, Presigner: presigner},
		SnapshotOptions{IncludeOCSP: true, FreshOCSP: true})
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	if len(cas) != 1 || cas[0].ID != root.ID {
		t.Fatalf("cas = %+v, want just the root", cas)
	}
	if cas[0].OCSPResponses != 3 {
		t.Errorf("OCSPResponses = %d, want 3", cas[0].OCSPResponses)
	}
	if cas[0].CRLShards != 2 {
		t.Errorf("CRLShards = %d, want 2", cas[0].CRLShards)
	}

	byPath := map[string]*Artifact{}
	for i := range artifacts {
		byPath[artifacts[i].Path] = &artifacts[i]
	}
	base := root.ID
	for _, want := range []string{
		base + "/ca.der", base + "/ca.pem", base + "/chain.pem",
		base + "/crl.der", base + "/crl-delta.der",
		base + "/crl-partition-0.der", base + "/crl-partition-0-delta.der",
		base + "/crl-partition-1.der", base + "/crl-partition-1-delta.der",
	} {
		if byPath[want] == nil {
			t.Errorf("missing artifact %s", want)
		}
	}

	// The complete CRL lists the revocation; exactly one shard does.
	fullCRL := parseCRL(t, byPath[base+"/crl.der"], rootCert)
	if !crlLists(fullCRL, revokedSerial) {
		t.Error("complete CRL does not list the revoked serial")
	}
	inShards := 0
	for s := 0; s < 2; s++ {
		shard := parseCRL(t, byPath[fmt.Sprintf("%s/crl-partition-%d.der", base, s)], rootCert)
		if crlLists(shard, revokedSerial) {
			inShards++
		}
	}
	if inShards != 1 {
		t.Errorf("revoked serial appears in %d shards, want exactly 1", inShards)
	}

	// Every pre-signed response is present under both keys and attests the
	// right status; the by-request key is the canonical GET encoding.
	statuses := map[string]int{}
	for _, r := range presigner.Latest(root.ID) {
		statuses[r.Serial] = r.Status

		art := byPath[base+"/ocsp/by-serial/"+r.Serial+".der"]
		if art == nil {
			t.Fatalf("missing by-serial response for %s", r.Serial)
		}
		parsed, err := ocsp.ParseResponse(art.Data, rootCert)
		if err != nil {
			t.Fatalf("serial %s: %v", r.Serial, err)
		}
		if parsed.Status != r.Status {
			t.Errorf("serial %s: published status %d, want %d", r.Serial, parsed.Status, r.Status)
		}

		serialInt, ok := new(big.Int).SetString(r.Serial, 10)
		if !ok {
			t.Fatalf("bad serial %q", r.Serial)
		}
		reqDER, err := pki.BuildOCSPRequestForSerial(rootCert, serialInt)
		if err != nil {
			t.Fatalf("canonical request: %v", err)
		}
		reqKey := base + "/ocsp/by-request/" + base64.RawURLEncoding.EncodeToString(reqDER) + ".der"
		reqArt := byPath[reqKey]
		if reqArt == nil {
			t.Fatalf("missing by-request response for %s", r.Serial)
		}
		if string(reqArt.Data) != string(art.Data) {
			t.Errorf("serial %s: by-request bytes differ from by-serial", r.Serial)
		}
	}
	if statuses[revokedSerial] != pki.OCSPRevoked {
		t.Errorf("revoked serial pre-signed as %d, want revoked", statuses[revokedSerial])
	}

	// Publish to a directory store and verify the whole snapshot.
	store, err := NewDirStore(t.TempDir(), 2)
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	manifest, err := NewPublisher(store).Publish(ctx, cas, artifacts)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := Verify(ctx, store); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if manifest.EarliestExpiry == nil {
		t.Fatal("manifest carries no EarliestExpiry")
	}
	// The chain bundle on disk parses as certificates.
	chain, err := os.ReadFile(filepath.Join(store.Root(), "current", filepath.FromSlash(base+"/chain.pem")))
	if err != nil {
		t.Fatalf("reading published chain: %v", err)
	}
	if err := validatePEMCertificates(chain); err != nil {
		t.Fatalf("published chain invalid: %v", err)
	}
}

func parseCRL(t *testing.T, a *Artifact, issuer *x509.Certificate) *x509.RevocationList {
	t.Helper()
	if a == nil {
		t.Fatal("nil CRL artifact")
	}
	rl, err := x509.ParseRevocationList(a.Data)
	if err != nil {
		t.Fatalf("parsing CRL %s: %v", a.Path, err)
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CRL %s not signed by CA: %v", a.Path, err)
	}
	return rl
}

func crlLists(rl *x509.RevocationList, serial string) bool {
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber.String() == serial {
			return true
		}
	}
	return false
}
