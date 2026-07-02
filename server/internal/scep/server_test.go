//go:build sqlite

// These tests exercise the SCEP server end-to-end against the software key
// provider (no HSM), driving it with a SCEP client assembled from the cms
// package. They cover GetCACaps, GetCACert, a challenge-authorized enrollment,
// challenge rejection, and challenge-free renewal. A SoftHSM-backed variant
// lives in internal/e2e.
package scep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
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

func newTestServer(t *testing.T, cfg Config) (*Server, *httptest.Server, *x509.Certificate) {
	t.Helper()
	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	db, err := database.New("sqlite", t.TempDir()+"/scep.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	// SCEP requires an RSA CA (the pkiMessage EnvelopedData uses RSA key
	// transport to the CA certificate).
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "scep-root",
		KeyType:  keyprovider.KeyTypeRSA2048,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "SCEP Test Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}

	cfg.CAID = root.ID
	srv := New(db, provider, cfg)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	block, _ := pem.Decode([]byte(root.Certificate))
	if block == nil {
		t.Fatal("CA certificate is not PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return srv, ts, caCert
}

// scepClient is a minimal SCEP client used to drive the server under test.
type scepClient struct {
	t       *testing.T
	baseURL string
	caCert  *x509.Certificate

	key  *rsa.PrivateKey
	cert *x509.Certificate // signer cert (self-signed initially, issued after enroll)
}

func newSCEPClient(t *testing.T, ts *httptest.Server, caCert *x509.Certificate, cn string) *scepClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	// Temporary self-signed certificate the initial request is signed with.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &scepClient{t: t, baseURL: ts.URL, caCert: caCert, key: key, cert: cert}
}

// recipient fetches the SCEP RA encryption certificate via GetCACert. Requests
// are enveloped to it (not to the CA certificate).
func (c *scepClient) recipient() *x509.Certificate {
	c.t.Helper()
	resp, err := http.Get(c.baseURL + "/scep?operation=GetCACert")
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	sd, err := cms.ParseSignedData(body)
	if err != nil {
		c.t.Fatalf("parsing GetCACert PKCS7: %v", err)
	}
	for _, cert := range sd.Certificates {
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 && !cert.IsCA {
			return cert
		}
	}
	c.t.Fatal("GetCACert did not include an RA encryption certificate")
	return nil
}

// enroll runs a PKCSReq and returns the issued certificate.
func (c *scepClient) enroll(cn, challenge string) (*x509.Certificate, string, error) {
	c.t.Helper()
	csrDER := buildCSR(c.t, c.key, cn, challenge)

	enveloped, err := cms.BuildEnvelopedData(csrDER, c.recipient())
	if err != nil {
		return nil, "", err
	}

	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)
	pkiMsg, err := cms.BuildSignedData(cms.SignedDataOpts{
		Content:    enveloped,
		SignerCert: c.cert,
		Signer:     c.key,
		Digest:     crypto.SHA256,
		ExtraAttrs: []cms.Attribute{
			{Type: oidSCEPTransactionID, Value: "txn-" + cn},
			{Type: oidSCEPMessageType, Value: msgTypePKCSReq},
			{Type: oidSCEPSenderNonce, Value: senderNonce},
		},
	})
	if err != nil {
		return nil, "", err
	}

	resp, err := http.Post(c.baseURL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(pkiMsg))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	sd, err := cms.ParseSignedData(body)
	if err != nil {
		return nil, "", err
	}
	if err := sd.Verify(); err != nil {
		return nil, "", err
	}
	// The response must be signed by the CA.
	if sd.SignerCertificate() == nil || !bytes.Equal(sd.SignerCertificate().Raw, c.caCert.Raw) {
		c.t.Fatal("CertRep not signed by the CA")
	}

	status := attrString(c.t, sd, oidSCEPPKIStatus)
	if status != pkiStatusSuccess {
		return nil, status, nil
	}

	// The recipient nonce must echo our sender nonce.
	if rn := attrOctet(c.t, sd, oidSCEPRecipientNonce); !bytes.Equal(rn, senderNonce) {
		c.t.Fatalf("recipient nonce mismatch")
	}

	env, err := cms.ParseEnvelopedData(sd.Content)
	if err != nil {
		return nil, "", err
	}
	degenerate, err := env.Decrypt(c.cert, c.key)
	if err != nil {
		return nil, "", err
	}
	certsOnly, err := cms.ParseSignedData(degenerate)
	if err != nil {
		return nil, "", err
	}
	if len(certsOnly.Certificates) == 0 {
		c.t.Fatal("no certificates in CertRep")
	}
	issued := certsOnly.Certificates[0]
	// Adopt the issued cert as our signer identity for subsequent renewals.
	c.cert = issued
	return issued, status, nil
}

func TestSCEP_GetCACaps(t *testing.T) {
	_, ts, _ := newTestServer(t, Config{})
	resp, err := http.Get(ts.URL + "/scep?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "POSTPKIOperation") || !strings.Contains(string(body), "SHA-256") {
		t.Fatalf("unexpected caps: %q", body)
	}
}

func TestSCEP_GetCACert(t *testing.T) {
	_, ts, caCert := newTestServer(t, Config{})
	resp, err := http.Get(ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-x509-ca-ra-cert" {
		t.Fatalf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	sd, err := cms.ParseSignedData(body)
	if err != nil {
		t.Fatalf("parsing GetCACert PKCS7: %v", err)
	}
	var haveCA, haveRA bool
	for _, cert := range sd.Certificates {
		if bytes.Equal(cert.Raw, caCert.Raw) {
			haveCA = true
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 && !cert.IsCA {
			haveRA = true
		}
	}
	if !haveCA || !haveRA {
		t.Fatalf("GetCACert must return both CA and RA certs (haveCA=%v haveRA=%v)", haveCA, haveRA)
	}
}

func TestSCEP_EnrollWithChallenge(t *testing.T) {
	_, ts, caCert := newTestServer(t, Config{
		Profile:          "client",
		RequireChallenge: true,
		Grants:           []Grant{{Name: "fleet-a", Challenge: "s3cr3t", Profile: "client"}},
	})
	c := newSCEPClient(t, ts, caCert, "device01")
	issued, status, err := c.enroll("device01", "s3cr3t")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if status != pkiStatusSuccess {
		t.Fatalf("pkiStatus = %q, want success", status)
	}
	if issued.Subject.CommonName != "device01" {
		t.Fatalf("issued CN = %q", issued.Subject.CommonName)
	}
	// The issued certificate must chain to the CA.
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
}

func TestSCEP_EnrollWrongChallengeRejected(t *testing.T) {
	_, ts, caCert := newTestServer(t, Config{
		RequireChallenge: true,
		Grants:           []Grant{{Name: "fleet-a", Challenge: "s3cr3t"}},
	})
	c := newSCEPClient(t, ts, caCert, "rogue")
	_, status, err := c.enroll("rogue", "wrong-password")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if status != pkiStatusFailure {
		t.Fatalf("pkiStatus = %q, want failure for a bad challenge", status)
	}
}

func TestSCEP_Renewal(t *testing.T) {
	_, ts, caCert := newTestServer(t, Config{
		RequireChallenge: true,
		AllowRenewal:     true,
		Grants:           []Grant{{Name: "fleet-a", Challenge: "s3cr3t"}},
	})
	c := newSCEPClient(t, ts, caCert, "device02")
	if _, status, err := c.enroll("device02", "s3cr3t"); err != nil || status != pkiStatusSuccess {
		t.Fatalf("initial enroll: status=%q err=%v", status, err)
	}
	// Renew with NO challenge: the request is now signed by the issued cert.
	renewed, status, err := c.enroll("device02", "")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if status != pkiStatusSuccess {
		t.Fatalf("renewal pkiStatus = %q, want success", status)
	}
	if renewed.Subject.CommonName != "device02" {
		t.Fatalf("renewed CN = %q", renewed.Subject.CommonName)
	}
}

// ---- test helpers ---------------------------------------------------------

func attrString(t *testing.T, sd *cms.ParsedSignedData, oid asn1.ObjectIdentifier) string {
	t.Helper()
	raw, ok := sd.AuthenticatedAttribute(oid)
	if !ok {
		t.Fatalf("attribute %v missing", oid)
	}
	var s string
	if _, err := asn1.Unmarshal(raw.FullBytes, &s); err != nil {
		t.Fatalf("decoding %v: %v", oid, err)
	}
	return s
}

func attrOctet(t *testing.T, sd *cms.ParsedSignedData, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	raw, ok := sd.AuthenticatedAttribute(oid)
	if !ok {
		t.Fatalf("attribute %v missing", oid)
	}
	var b []byte
	if _, err := asn1.Unmarshal(raw.FullBytes, &b); err != nil {
		t.Fatalf("decoding %v: %v", oid, err)
	}
	return b
}

// buildCSR builds a PKCS#10 CSR carrying an optional challengePassword attribute.
func buildCSR(t *testing.T, key *rsa.PrivateKey, cn, challenge string) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}

	type criAttr struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	var attrs []criAttr
	if challenge != "" {
		cpVal, err := asn1.Marshal(challenge) // PrintableString
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs, criAttr{
			Type:   oidChallengePassword,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: cpVal},
		})
	}

	type cri struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []criAttr `asn1:"tag:0"`
	}
	criStruct := cri{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: subject},
		PublicKey:  asn1.RawValue{FullBytes: spki},
		Attributes: attrs,
	}
	criDER, err := asn1.Marshal(criStruct)
	if err != nil {
		t.Fatal(err)
	}

	h := crypto.SHA256.New()
	h.Write(criDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}

	type certReq struct {
		Info      asn1.RawValue
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	sha256WithRSA := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		Parameters: asn1.NullRawValue,
	}
	reqDER, err := asn1.Marshal(certReq{
		Info:      asn1.RawValue{FullBytes: criDER},
		SigAlg:    sha256WithRSA,
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reqDER
}
