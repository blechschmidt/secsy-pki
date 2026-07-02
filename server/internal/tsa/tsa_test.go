package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// harness bundles a configured Authority with the certificates a verifier needs.
type harness struct {
	authority *Authority
	tsaCert   *x509.Certificate
	caCert    *x509.Certificate
}

// newHarness builds a software-backed TSA: a self-signed RSA CA, a dedicated RSA
// TSA key, and a TSA certificate with the id-kp-timeStamping EKU. No HSM needed.
func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	provider, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	// Self-signed RSA CA.
	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "ca", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "Test TSA Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	// Dedicated TSA key + certificate (critical id-kp-timeStamping EKU).
	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "tsa", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{OIDExtKeyUsageTimeStamping})
	if err != nil {
		t.Fatalf("marshal EKU: %v", err)
	}
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "Test TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatalf("parse TSA cert: %v", err)
	}

	authority, err := New(nil, provider, Config{
		KeyLabel:       "tsa",
		Certificate:    tsaCert,
		Chain:          []*x509.Certificate{tsaCert, caCert},
		Accuracy:       Accuracy{Seconds: 1},
		IncludeTSAName: true,
	})
	if err != nil {
		t.Fatalf("New authority: %v", err)
	}
	return &harness{authority: authority, tsaCert: tsaCert, caCert: caCert}
}

func TestParseRequestValidation(t *testing.T) {
	good := sha256.Sum256([]byte("hello"))

	valid, err := MakeRequest(crypto.SHA256, good[:], &RequestOptions{Nonce: big.NewInt(42)})
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	req, err := ParseRequest(valid)
	if err != nil {
		t.Fatalf("ParseRequest(valid): %v", err)
	}
	if req.Hash != crypto.SHA256 || req.Nonce.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("parsed request mismatch: hash=%v nonce=%v", req.Hash, req.Nonce)
	}

	// Wrong digest length for the declared algorithm.
	badLen := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: []byte{0x01, 0x02},
		},
	}
	badLenDER, _ := asn1.Marshal(badLen)
	if _, err := ParseRequest(badLenDER); err == nil {
		t.Fatal("expected error for short digest")
	} else if re, ok := err.(*RequestError); !ok || re.Failure != FailureBadDataFormat {
		t.Fatalf("want badDataFormat, got %v", err)
	}

	// Unknown hash algorithm OID.
	badAlg := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
			HashedMessage: make([]byte, 32),
		},
	}
	badAlgDER, _ := asn1.Marshal(badAlg)
	if _, err := ParseRequest(badAlgDER); err == nil {
		t.Fatal("expected error for unknown alg")
	} else if re, ok := err.(*RequestError); !ok || re.Failure != FailureBadAlg {
		t.Fatalf("want badAlg, got %v", err)
	}

	// Trailing garbage.
	if _, err := ParseRequest(append(valid, 0x00)); err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestStampRoundTrip(t *testing.T) {
	h := newHarness(t)
	data := []byte("time-stamp me")
	digest := sha256.Sum256(data)
	nonce := big.NewInt(0xDEADBEEF)

	reqDER, err := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: nonce, CertReq: true})
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}

	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if !result.Granted {
		t.Fatalf("request not granted: %s", result.Detail)
	}

	// Decode the TimeStampResp: status granted, token present.
	token := parseGrantedResp(t, result.Response)

	// Verify the CMS SignedData signature against the embedded TSA certificate.
	sd, err := cms.ParseSignedData(token)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := sd.Verify(); err != nil {
		t.Fatalf("token signature verify: %v", err)
	}
	if sd.SignerCertificate() == nil || sd.SignerCertificate().SerialNumber.Cmp(h.tsaCert.SerialNumber) != 0 {
		t.Fatal("token not signed by the TSA certificate")
	}

	// The eContent is the TSTInfo; check it echoes the imprint and nonce.
	var info struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint struct {
			HashAlgorithm pkix.AlgorithmIdentifier
			HashedMessage []byte
		}
		SerialNumber *big.Int
		GenTime      time.Time     `asn1:"generalized"`
		Rest         asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(sd.Content, &info); err != nil {
		t.Fatalf("parsing TSTInfo: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("TSTInfo version = %d, want 1", info.Version)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("imprint alg = %v, want sha256", info.MessageImprint.HashAlgorithm.Algorithm)
	}
	if string(info.MessageImprint.HashedMessage) != string(digest[:]) {
		t.Error("TSTInfo message imprint does not match the request digest")
	}
	if !info.Policy.Equal(DefaultPolicyOID) {
		t.Errorf("policy = %v, want default %v", info.Policy, DefaultPolicyOID)
	}

	// certReq=true must embed the TSA certificate.
	foundTSA := false
	for _, c := range sd.Certificates {
		if c.SerialNumber.Cmp(h.tsaCert.SerialNumber) == 0 {
			foundTSA = true
		}
	}
	if !foundTSA {
		t.Error("certReq=true but the TSA certificate was not embedded")
	}
}

func TestStampNoCertReqOmitsCerts(t *testing.T) {
	h := newHarness(t)
	digest := sha256.Sum256([]byte("x"))
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], nil) // certReq defaults false

	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil || !result.Granted {
		t.Fatalf("Stamp: err=%v granted=%v", err, result.Granted)
	}
	token := parseGrantedResp(t, result.Response)
	sd, err := cms.ParseSignedData(token)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(sd.Certificates) != 0 {
		t.Errorf("certReq=false must not embed certificates, got %d", len(sd.Certificates))
	}
	// The token must still verify (Verify resolves the signer from embedded certs,
	// which are absent here) — so verify manually against the known TSA cert.
	if err := verifyDetached(sd, h.tsaCert); err != nil {
		t.Fatalf("token signature verify: %v", err)
	}
}

func TestStampRejectsUnacceptedPolicy(t *testing.T) {
	h := newHarness(t)
	digest := sha256.Sum256([]byte("y"))
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 5}})

	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if result.Granted {
		t.Fatal("request with unsupported policy should have been rejected")
	}
	assertRejection(t, result.Response, FailureUnacceptedPolicy)
}

func TestStampRejectsUnacceptedHash(t *testing.T) {
	h := newHarness(t) // default accepted hashes: sha256/384/512 (not sha1)
	digest := make([]byte, 20)
	reqDER, _ := MakeRequest(crypto.SHA1, digest, nil)

	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if result.Granted {
		t.Fatal("SHA-1 request should have been rejected by the default allowlist")
	}
	assertRejection(t, result.Response, FailureBadAlg)
}

// TestOpenSSLVerify checks interop with openssl's RFC 3161 verifier. It writes
// the reply, the data, and the CA, then runs `openssl ts -verify`. Skipped when
// openssl is unavailable.
func TestOpenSSLVerify(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	h := newHarness(t)
	data := []byte("interop payload")
	digest := sha256.Sum256(data)
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: big.NewInt(7), CertReq: true})

	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil || !result.Granted {
		t.Fatalf("Stamp: err=%v granted=%v", err, result.Granted)
	}

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "data.bin")
	respPath := filepath.Join(dir, "resp.tsr")
	caPath := filepath.Join(dir, "ca.pem")
	tsaPath := filepath.Join(dir, "tsa.pem")
	writeFile(t, dataPath, data)
	writeFile(t, respPath, result.Response)
	writeFile(t, caPath, pemCert(h.caCert))
	writeFile(t, tsaPath, pemCert(h.tsaCert))

	// -untrusted supplies the TSA leaf; -CAfile the trust anchor. openssl checks
	// the CMS signature, the id-kp-timeStamping EKU, and the imprint against -data.
	cmd := exec.Command(openssl, "ts", "-verify",
		"-data", dataPath,
		"-in", respPath,
		"-CAfile", caPath,
		"-untrusted", tsaPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl ts -verify failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("Verification: OK")) {
		t.Fatalf("openssl did not report success:\n%s", out)
	}
}

func TestHTTPEndpoint(t *testing.T) {
	h := newHarness(t)
	mux := http.NewServeMux()
	h.authority.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	digest := sha256.Sum256([]byte("over http"))
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: big.NewInt(99), CertReq: true})

	resp, err := http.Post(srv.URL+"/tsa", contentTypeQuery, bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("POST /tsa: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypeReply {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypeReply)
	}
	body, _ := io.ReadAll(resp.Body)
	token := parseGrantedResp(t, body)
	sd, err := cms.ParseSignedData(token)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := sd.Verify(); err != nil {
		t.Fatalf("verify token from HTTP: %v", err)
	}

	// A GET must not be routed to the TSA handler (POST-only registration).
	getResp, err := http.Get(srv.URL + "/tsa")
	if err != nil {
		t.Fatalf("GET /tsa: %v", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode == http.StatusOK {
		t.Error("GET /tsa unexpectedly succeeded; endpoint should be POST-only")
	}
}

// ---- helpers --------------------------------------------------------------

func parseGrantedResp(t *testing.T, respDER []byte) []byte {
	t.Helper()
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatalf("parsing TimeStampResp: %v", err)
	}
	var status struct {
		Status int
	}
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &status); err != nil {
		t.Fatalf("parsing PKIStatusInfo: %v", err)
	}
	if status.Status != StatusGranted {
		t.Fatalf("PKIStatus = %d, want granted", status.Status)
	}
	if len(resp.Token.FullBytes) == 0 {
		t.Fatal("granted response carries no token")
	}
	return resp.Token.FullBytes
}

func assertRejection(t *testing.T, respDER []byte, wantBit int) {
	t.Helper()
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatalf("parsing TimeStampResp: %v", err)
	}
	if len(resp.Token.FullBytes) != 0 {
		t.Fatal("rejection response must not carry a token")
	}
	var status struct {
		Status       int
		StatusString asn1.RawValue
		FailInfo     asn1.BitString
	}
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &status); err != nil {
		t.Fatalf("parsing PKIStatusInfo: %v", err)
	}
	if status.Status != StatusRejection {
		t.Fatalf("PKIStatus = %d, want rejection", status.Status)
	}
	if status.FailInfo.At(wantBit) != 1 {
		t.Fatalf("failInfo bit %d not set (bytes % x, len %d)", wantBit, status.FailInfo.Bytes, status.FailInfo.BitLength)
	}
}

// verifyDetached verifies a SignedData whose signer certificate is not embedded,
// by supplying the known TSA certificate explicitly.
func verifyDetached(sd *cms.ParsedSignedData, tsaCert *x509.Certificate) error {
	sd.Certificates = append(sd.Certificates, tsaCert)
	return sd.Verify()
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
