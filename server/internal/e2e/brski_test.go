//go:build sqlite

// This file drives BRSKI (RFC 8995) zero-touch onboarding end-to-end against a
// real, HSM-backed domain CA (SoftHSM in CI). A synthetic pledge — with a
// manufacturer-issued IDevID — runs the complete flow: provisional TLS to the
// registrar, a signed pledge voucher-request, voucher issuance by the built-in
// MASA, voucher validation and domain pinning, voucher-status telemetry, then the
// EST simpleenroll handoff over the same mutually-authenticated connection that
// yields an operational LDevID signed on the HSM, and finally enroll-status
// telemetry. It proves the BRSKI → EST → HSM issuance path works with a key that
// never leaves the token.
//
// It shares the SECSY_* gating and HSM helpers (hsmProvider, uniqueLabel,
// mustParse) with fullflow_test.go, so a plain `go test ./...` with no HSM stays
// green.
package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/brski"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	estsrv "github.com/blechschmidt/secsy-pki/server/internal/est"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestBRSKIOnboardingHSM runs the full BRSKI voucher→enroll flow against an
// HSM-resident domain CA, with a synthetic pledge and the built-in MASA.
func TestBRSKIOnboardingHSM(t *testing.T) {
	provider := hsmProvider(t)
	ctx := context.Background()

	// --- Domain side: an HSM-backed issuing CA and a shared database. ---
	dsn := t.TempDir() + "/brski.db"
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mgr := ca.NewManager(db, provider)
	domainRoot, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "brski-domain-ca"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "BRSKI Domain CA"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	domainCA := mustParse(t, domainRoot.Certificate)

	// --- Manufacturer side: the IDevID trust anchor, the MASA identity, and a
	// pledge IDevID issued under it. These are software keys (a manufacturer's PKI
	// is separate from the domain HSM). ---
	mfrKey, mfrCert := brskiCA(t, "BRSKI Test Manufacturer")
	mfrPool := x509.NewCertPool()
	mfrPool.AddCert(mfrCert)
	masaKey, masaCert := brskiLeaf(t, "BRSKI Test MASA", "", mfrKey, mfrCert)

	const pledgeSerial = "BRSKI-DEV-HSM-0001"
	idevidKey, idevidCert := brskiLeaf(t, "pledge-hsm.example", pledgeSerial, mfrKey, mfrCert)

	// --- Registrar identity: the domain/provisioning certificate the pledge pins.
	// Software key (it terminates the provisional TLS and signs voucher-requests). ---
	regKey, regCert := brskiSelfSigned(t, "brski-registrar-hsm.example")

	// --- Built-in MASA and BRSKI registrar. ---
	masa, err := brski.NewService(brski.ServiceConfig{
		Signer:      masaKey,
		Cert:        masaCert,
		Chain:       []*x509.Certificate{mfrCert},
		IDevIDRoots: mfrPool,
		Log:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("brski.NewService: %v", err)
	}
	proximity := true
	registrar, err := brski.New(db, brski.Config{
		CAID:             domainRoot.ID,
		Profile:          "client",
		DomainCert:       regCert,
		RegistrarKey:     regKey,
		RegistrarCert:    regCert,
		IDevIDRoots:      mfrPool,
		MASA:             brski.InProcessMASA{Service: masa},
		RequireProximity: &proximity,
		PledgeTTL:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("brski.New: %v", err)
	}

	// --- EST server, with the registrar as the post-BRSKI pledge authorizer. The
	// LDevID is signed on the HSM domain CA. ---
	estSrv := estsrv.New(db, provider, estsrv.Config{
		CAID:             domainRoot.ID,
		Profile:          "client",
		PledgeAuthorizer: registrar,
	})

	mux := http.NewServeMux()
	registrar.Register(mux)
	estSrv.Register(mux)

	// mTLS test server: the registrar identity is the TLS server certificate; the
	// pledge presents its IDevID as an (unverified-at-TLS) client certificate, so
	// the EST handoff can authorize it by that identity.
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{regCert.Raw}, PrivateKey: regKey}},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	// The pledge's HTTP client: it trusts the registrar provisionally (BRSKI
	// pins the domain certificate from the voucher rather than via a PKI path) and
	// presents its IDevID as the client certificate.
	pledge := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // BRSKI provisional TLS: the pledge pins the domain cert from the voucher.
			Certificates:       []tls.Certificate{{Certificate: [][]byte{idevidCert.Raw}, PrivateKey: idevidKey}},
		},
	}}

	// (1) Provisional TLS: capture the registrar's server certificate the pledge
	// will pin as proximity-registrar-cert.
	probe, err := pledge.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("provisional TLS probe: %v", err)
	}
	if probe.TLS == nil || len(probe.TLS.PeerCertificates) == 0 {
		t.Fatal("no server certificate on the provisional connection")
	}
	serverCert := probe.TLS.PeerCertificates[0]
	probe.Body.Close()
	if !bytes.Equal(serverCert.Raw, regCert.Raw) {
		t.Fatal("provisional server certificate is not the registrar identity")
	}

	// (2) Build and sign the pledge voucher-request (CMS, IDevID key), pinning the
	// server certificate, and POST it to the registrar.
	nonce := brskiRandom(t, 16)
	pvrContent, err := brski.MarshalVoucherRequest(&brski.Voucher{
		CreatedOn:              time.Now(),
		Nonce:                  nonce,
		SerialNumber:           pledgeSerial,
		Assertion:              brski.AssertionProximity,
		ProximityRegistrarCert: serverCert.Raw,
	})
	if err != nil {
		t.Fatalf("MarshalVoucherRequest: %v", err)
	}
	pvrCMS, err := cms.BuildSignedData(cms.SignedDataOpts{
		Content:    pvrContent,
		SignerCert: idevidCert,
		Signer:     idevidKey,
	})
	if err != nil {
		t.Fatalf("signing pledge voucher-request: %v", err)
	}
	voucherCMS := brskiPost(t, pledge, ts.URL+"/.well-known/brski/requestvoucher", brski.MediaTypeVoucherCMS, pvrCMS)

	// (3) Pledge-side voucher validation: the voucher must be signed by a
	// certificate chaining to the pre-installed MASA anchor, echo the nonce, and
	// pin exactly the domain certificate the pledge connected to.
	vSD, err := cms.ParseSignedData(voucherCMS)
	if err != nil {
		t.Fatalf("parse voucher CMS: %v", err)
	}
	if err := vSD.Verify(); err != nil {
		t.Fatalf("voucher CMS signature: %v", err)
	}
	if _, err := vSD.SignerCertificate().Verify(x509.VerifyOptions{Roots: mfrPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("voucher signer does not chain to the MASA anchor: %v", err)
	}
	voucher, err := brski.ParseVoucher(vSD.Content)
	if err != nil {
		t.Fatalf("parse voucher: %v", err)
	}
	if !bytes.Equal(voucher.Nonce, nonce) {
		t.Fatal("voucher nonce does not echo the request")
	}
	if !bytes.Equal(voucher.PinnedDomainCert, serverCert.Raw) {
		t.Fatal("pinned-domain-cert does not match the provisional registrar certificate")
	}
	if voucher.SerialNumber != pledgeSerial {
		t.Fatalf("voucher serial = %q, want %q", voucher.SerialNumber, pledgeSerial)
	}

	// (4) Voucher-status telemetry (success).
	brskiPostStatus(t, pledge, ts.URL+"/.well-known/brski/voucher_status", true)

	// (5) EST simpleenroll over the now-trusted mTLS connection. The registrar
	// authorizes the pledge by its IDevID; the LDevID is signed on the HSM.
	ldevidKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pledge-hsm-ldevid", SerialNumber: pledgeSerial},
	}, ldevidKey)
	if err != nil {
		t.Fatal(err)
	}
	enrollResp := brskiPost(t, pledge, ts.URL+"/.well-known/est/simpleenroll", "application/pkcs10",
		[]byte(base64.StdEncoding.EncodeToString(csrDER)))
	ldevid := brskiParseEST(t, enrollResp)
	if err := ldevid.CheckSignatureFrom(domainCA); err != nil {
		t.Fatalf("HSM-issued LDevID does not chain to the domain CA: %v", err)
	}
	if !brskiPublicKeyEqual(t, ldevid.PublicKey, &ldevidKey.PublicKey) {
		t.Fatal("issued LDevID does not certify the pledge's LDevID key")
	}

	// (6) Enroll-status telemetry (success).
	brskiPostStatus(t, pledge, ts.URL+"/.well-known/brski/enrollstatus", true)

	// After the flow the pledge grant is still valid; a device that never
	// bootstrapped must not be authorized to enroll.
	if _, _, ok := registrar.AuthorizePledge(mfrCert); ok {
		t.Fatal("a non-bootstrapped certificate must not be authorized to enroll")
	}
}

// ---- pledge HTTP helpers --------------------------------------------------

func brskiPost(t *testing.T, client *http.Client, url, contentType string, body []byte) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d: %s", url, resp.StatusCode, out)
	}
	return out
}

func brskiPostStatus(t *testing.T, client *http.Client, url string, ok bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"version": "1", "status": ok, "reason": ""})
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: status %d: %s", url, resp.StatusCode, out)
	}
}

func brskiParseEST(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("base64 EST body: %v", err)
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatalf("parse EST PKCS7: %v", err)
	}
	if len(sd.Certificates) == 0 {
		t.Fatal("no certificates in EST response")
	}
	return sd.Certificates[0]
}

// ---- certificate helpers (software manufacturer/registrar PKI) ------------

func brskiCA(t *testing.T, cn string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func brskiLeaf(t *testing.T, cn, serialAttr string, caKey crypto.Signer, caCert *x509.Certificate) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: brskiSerial(t),
		Subject:      pkix.Name{CommonName: cn, SerialNumber: serialAttr},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func brskiSelfSigned(t *testing.T, cn string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: brskiSerial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func brskiSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func brskiRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func brskiPublicKeyEqual(t *testing.T, a, b crypto.PublicKey) bool {
	t.Helper()
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
