//go:build sqlite

// These tests exercise the EST server end-to-end against the software key
// provider. They cover cacerts, Basic-auth simpleenroll, auth rejection,
// TLS-client-certificate reenrollment, and server-side key generation. A
// SoftHSM-backed variant lives in internal/e2e.
package est

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newTestEST(t *testing.T, cfg Config, tlsClientAuth bool) (*Server, *httptest.Server, *x509.Certificate) {
	t.Helper()
	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	db, err := database.New("sqlite", t.TempDir()+"/est.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	// EST places no RSA requirement on the CA; use an ECDSA CA to prove it.
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "est-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "EST Test Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	cfg.CAID = root.ID
	srv := New(db, provider, cfg)
	mux := http.NewServeMux()
	srv.Register(mux)

	var ts *httptest.Server
	if tlsClientAuth {
		ts = httptest.NewUnstartedServer(mux)
		ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		ts.StartTLS()
	} else {
		ts = httptest.NewServer(mux)
	}
	t.Cleanup(ts.Close)

	block, _ := pem.Decode([]byte(root.Certificate))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return srv, ts, caCert
}

func makeCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// parseEnrollResponse decodes a base64 certs-only PKCS#7 EST response.
func parseEnrollResponse(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatalf("parse PKCS7: %v", err)
	}
	if len(sd.Certificates) == 0 {
		t.Fatal("no certificates in EST response")
	}
	return sd.Certificates[0]
}

func TestEST_CACerts(t *testing.T) {
	_, ts, caCert := newTestEST(t, Config{}, false)
	resp, err := http.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "pkcs7-mime") {
		t.Fatalf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	got := parseEnrollResponse(t, body)
	if !bytes.Equal(got.Raw, caCert.Raw) {
		t.Fatal("cacerts did not return the CA certificate")
	}
}

func TestEST_SimpleEnroll(t *testing.T) {
	_, ts, caCert := newTestEST(t, Config{
		Users: map[string]User{"device": {Password: "pw", Profile: "client"}},
	}, false)

	_, csrDER := makeCSR(t, "est-device-1")
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.SetBasicAuth("device", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	leaf := parseEnrollResponse(t, body)
	if leaf.Subject.CommonName != "est-device-1" {
		t.Fatalf("issued CN = %q", leaf.Subject.CommonName)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
}

func TestEST_SimpleEnrollBadCredentials(t *testing.T) {
	_, ts, _ := newTestEST(t, Config{
		Users: map[string]User{"device": {Password: "pw"}},
	}, false)
	_, csrDER := makeCSR(t, "rogue")
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.SetBasicAuth("device", "wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEST_ReenrollWithClientCert(t *testing.T) {
	_, ts, caCert := newTestEST(t, Config{
		Users:                  map[string]User{"device": {Password: "pw"}},
		AllowTLSClientReenroll: true,
	}, true)

	// First enroll over Basic auth to obtain a client certificate + key.
	clientKey, csrDER := makeCSR(t, "reenroll-device")
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.SetBasicAuth("device", "pw")
	// ts is a TLS server; use a client that trusts its cert.
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	leaf := parseEnrollResponse(t, body)

	// Now reenroll authenticated ONLY by the TLS client certificate.
	clientTLSCert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: clientKey}
	mtls := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{clientTLSCert},
	}}}
	_, reCSRDER := makeCSR(t, "reenroll-device")
	rreq, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simplereenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(reCSRDER)))
	rresp, err := mtls.Do(rreq)
	if err != nil {
		t.Fatal(err)
	}
	defer rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rresp.Body)
		t.Fatalf("reenroll status %d: %s", rresp.StatusCode, b)
	}
	rbody, _ := io.ReadAll(rresp.Body)
	renewed := parseEnrollResponse(t, rbody)
	if renewed.Subject.CommonName != "reenroll-device" {
		t.Fatalf("renewed CN = %q", renewed.Subject.CommonName)
	}
	if err := renewed.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("renewed cert does not chain to CA: %v", err)
	}
}

func TestEST_ServerKeygen(t *testing.T) {
	_, ts, caCert := newTestEST(t, Config{
		Users:               map[string]User{"device": {Password: "pw"}},
		EnableServerKeygen:  true,
		ServerKeygenKeyType: keyprovider.KeyTypeECDSAP256,
	}, false)

	_, csrDER := makeCSR(t, "keygen-device")
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/serverkeygen",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.SetBasicAuth("device", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "multipart/mixed") {
		t.Fatalf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	// The response must carry both a PKCS#8 private key and a certificate.
	if !strings.Contains(string(body), "application/pkcs8") || !strings.Contains(string(body), "certs-only") {
		t.Fatalf("serverkeygen response missing parts:\n%s", body)
	}
	_ = caCert
}
