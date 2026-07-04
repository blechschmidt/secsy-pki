//go:build sqlite

// This file drives the SCEP (RFC 8894) and EST (RFC 7030) enrollment servers
// end-to-end against a real, HSM-backed CA (SoftHSM in CI). It proves both
// device-enrollment protocols work with certificates signed on the token — and,
// for SCEP, that the pkiMessage's enveloped payload is unwrapped with the CA's
// RSA key inside the HSM (the PKCS#1 v1.5 C_Decrypt path), never exporting the
// private key.
//
// It shares the SECSY_* gating and helpers (hsmProvider, uniqueLabel) with
// fullflow_test.go, so a plain `go test ./...` with no HSM stays green.
package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
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
	estsrv "github.com/blechschmidt/secsy-pki/server/internal/est"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	scepsrv "github.com/blechschmidt/secsy-pki/server/internal/scep"
)

// SCEP attribute OIDs and message-type / status constants (mirrored from the
// scep package, which keeps them unexported).
var (
	e2eOIDMessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	e2eOIDPKIStatus     = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	e2eOIDSenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	e2eOIDTransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	e2eOIDChallengePass = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// e2eEnrollEnv wires a database + HSM provider and an issuing CA of a chosen key
// type, returning the manager, CA id and parsed CA certificate.
func e2eEnrollEnv(t *testing.T, provider keyprovider.Provider, keyType string) (*database.DB, string, *x509.Certificate) {
	t.Helper()
	dsn := t.TempDir() + "/enroll.db"
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    uniqueLabel(t, "enroll-ca"),
		KeyType:  keyType,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Enroll HSM CA"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	caCert := mustParse(t, root.Certificate)
	return db, root.ID, caCert
}

// TestSCEPEnrollHSM enrolls and renews a device certificate over SCEP against an
// HSM-resident RSA CA.
func TestSCEPEnrollHSM(t *testing.T) {
	provider := hsmProvider(t)
	db, caID, caCert := e2eEnrollEnv(t, provider, keyprovider.KeyTypeRSA2048)

	srv := scepsrv.New(db, provider, scepsrv.Config{
		CAID:             caID,
		Profile:          "client",
		RequireChallenge: true,
		AllowRenewal:     true,
		Grants:           []scepsrv.Grant{{Name: "fleet", Challenge: "hsm-secret", Profile: "client"}},
	})
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// GetCACert must return the HSM CA certificate plus the RA encryption cert.
	resp, err := http.Get(ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	caBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	getCA, err := cms.ParseSignedData(caBody)
	if err != nil {
		t.Fatalf("parsing GetCACert: %v", err)
	}
	var raCert *x509.Certificate
	var haveCA bool
	for _, c := range getCA.Certificates {
		if bytes.Equal(c.Raw, caCert.Raw) {
			haveCA = true
		}
		if c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 && !c.IsCA {
			raCert = c
		}
	}
	if !haveCA || raCert == nil {
		t.Fatalf("GetCACert must return CA and RA certs (haveCA=%v ra=%v)", haveCA, raCert != nil)
	}

	// Initial enrollment with the challenge password.
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	deviceCert := selfSigned(t, deviceKey, "hsm-device")

	issued := scepRoundTrip(t, ts.URL, raCert, deviceKey, deviceCert, "hsm-device", "hsm-secret")
	if issued.Subject.CommonName != "hsm-device" {
		t.Fatalf("issued CN = %q", issued.Subject.CommonName)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("HSM-issued SCEP cert does not chain to CA: %v", err)
	}

	// Renewal: sign the next PKCSReq with the issued cert, no challenge.
	renewed := scepRoundTrip(t, ts.URL, raCert, deviceKey, issued, "hsm-device", "")
	if err := renewed.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("renewed SCEP cert does not chain to CA: %v", err)
	}
}

// TestESTEnrollHSM enrolls a device certificate over EST against an HSM-resident
// ECDSA CA (EST places no RSA requirement on the CA).
func TestESTEnrollHSM(t *testing.T) {
	provider := hsmProvider(t)
	db, caID, caCert := e2eEnrollEnv(t, provider, keyprovider.KeyTypeECDSAP256)

	srv := estsrv.New(db, provider, estsrv.Config{
		CAID:    caID,
		Profile: "client",
		Users:   map[string]estsrv.User{"device": {Password: "hsm-pw", Profile: "client"}},
	})
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// cacerts.
	resp, err := http.Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := estParse(t, body); !bytes.Equal(got.Raw, caCert.Raw) {
		t.Fatal("EST cacerts did not return the HSM CA certificate")
	}

	// csrattrs advertises the client profile's derived attributes (RFC 7030
	// §4.5): an id-ecPublicKey key-type hint (OID 1.2.840.10045.2.1) and a
	// clientAuth extended key usage (OID 1.3.6.1.5.5.7.3.2).
	caResp, err := http.Get(ts.URL + "/.well-known/est/csrattrs")
	if err != nil {
		t.Fatal(err)
	}
	if ct := caResp.Header.Get("Content-Type"); !strings.Contains(ct, "application/csrattrs") {
		t.Fatalf("csrattrs content-type = %q", ct)
	}
	caBody, _ := io.ReadAll(caResp.Body)
	caResp.Body.Close()
	caDER, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(caBody)), ""))
	if err != nil {
		t.Fatalf("decode csrattrs: %v", err)
	}
	caStr := string(caDER)
	if !strings.Contains(caStr, string([]byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01})) {
		t.Error("csrattrs did not advertise id-ecPublicKey for the client profile")
	}
	if !strings.Contains(caStr, string([]byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02})) {
		t.Error("csrattrs did not advertise the clientAuth extended key usage")
	}

	// simpleenroll over Basic auth; the leaf is signed on the token.
	csrDER := makeCSRDER(t, "est-hsm-device")
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.SetBasicAuth("device", "hsm-pw")
	eresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ebody, _ := io.ReadAll(eresp.Body)
	eresp.Body.Close()
	if eresp.StatusCode != http.StatusOK {
		t.Fatalf("simpleenroll status %d: %s", eresp.StatusCode, ebody)
	}
	leaf := estParse(t, ebody)
	if leaf.Subject.CommonName != "est-hsm-device" {
		t.Fatalf("issued CN = %q", leaf.Subject.CommonName)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("HSM-issued EST cert does not chain to CA: %v", err)
	}
}

// ---- SCEP client helpers --------------------------------------------------

func scepRoundTrip(t *testing.T, baseURL string, recipient *x509.Certificate, key *rsa.PrivateKey, signerCert *x509.Certificate, cn, challenge string) *x509.Certificate {
	t.Helper()
	csrDER := csrWithChallenge(t, key, cn, challenge)
	enveloped, err := cms.BuildEnvelopedData(csrDER, recipient)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	pkiMsg, err := cms.BuildSignedData(cms.SignedDataOpts{
		Content:    enveloped,
		SignerCert: signerCert,
		Signer:     key,
		Digest:     crypto.SHA256,
		ExtraAttrs: []cms.Attribute{
			{Type: e2eOIDTransactionID, Value: "txn-" + cn},
			{Type: e2eOIDMessageType, Value: "19"},
			{Type: e2eOIDSenderNonce, Value: nonce},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(baseURL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(pkiMsg))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	sd, err := cms.ParseSignedData(body)
	if err != nil {
		t.Fatalf("parse CertRep: %v", err)
	}
	if err := sd.Verify(); err != nil {
		t.Fatalf("CertRep signature (HSM-signed) failed to verify: %v", err)
	}
	if status := scepAttrString(t, sd, e2eOIDPKIStatus); status != "0" {
		t.Fatalf("SCEP pkiStatus = %q, want success", status)
	}
	env, err := cms.ParseEnvelopedData(sd.Content)
	if err != nil {
		t.Fatalf("parse enveloped CertRep: %v", err)
	}
	degenerate, err := env.Decrypt(signerCert, key)
	if err != nil {
		t.Fatalf("decrypt CertRep: %v", err)
	}
	certsOnly, err := cms.ParseSignedData(degenerate)
	if err != nil {
		t.Fatalf("parse degenerate certs: %v", err)
	}
	if len(certsOnly.Certificates) == 0 {
		t.Fatal("no certificate in CertRep")
	}
	return certsOnly.Certificates[0]
}

func scepAttrString(t *testing.T, sd *cms.ParsedSignedData, oid asn1.ObjectIdentifier) string {
	t.Helper()
	raw, ok := sd.AuthenticatedAttribute(oid)
	if !ok {
		t.Fatalf("attribute %v missing", oid)
	}
	var s string
	if _, err := asn1.Unmarshal(raw.FullBytes, &s); err != nil {
		t.Fatalf("decode %v: %v", oid, err)
	}
	return s
}

func selfSigned(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// csrWithChallenge builds a PKCS#10 with an optional challengePassword attribute.
func csrWithChallenge(t *testing.T, key *rsa.PrivateKey, cn, challenge string) []byte {
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
		cp, _ := asn1.Marshal(challenge)
		attrs = append(attrs, criAttr{Type: e2eOIDChallengePass,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: cp}})
	}
	type cri struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []criAttr `asn1:"tag:0"`
	}
	criDER, err := asn1.Marshal(cri{Version: 0,
		Subject:   asn1.RawValue{FullBytes: subject},
		PublicKey: asn1.RawValue{FullBytes: spki}, Attributes: attrs})
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
	reqDER, err := asn1.Marshal(certReq{
		Info:      asn1.RawValue{FullBytes: criDER},
		SigAlg:    pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reqDER
}

// ---- EST client helpers ---------------------------------------------------

func makeCSRDER(t *testing.T, cn string) []byte {
	t.Helper()
	// Reuse makeCSR (PEM) from fullflow_test and strip to DER.
	block, _ := pem.Decode(makeCSR(t, cn, nil))
	return block.Bytes
}

func estParse(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatalf("parse EST p7: %v", err)
	}
	if len(sd.Certificates) == 0 {
		t.Fatal("no certs in EST response")
	}
	return sd.Certificates[0]
}
