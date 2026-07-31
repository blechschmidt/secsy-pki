package tsa

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/timesource"
)

// fakeTimeProvider is a trusted-time source that injects a fixed host-minus-
// source offset, so a real timesource.Checker can be driven to pass or fail
// closed without any network access.
type fakeTimeProvider struct {
	offset time.Duration
	err    error
}

func (f fakeTimeProvider) Now(context.Context) (timesource.Reading, error) {
	if f.err != nil {
		return timesource.Reading{}, f.err
	}
	return timesource.Reading{Time: time.Now().Add(-f.offset), Offset: f.offset}, nil
}

func (f fakeTimeProvider) Name() string { return "fake-trusted-time" }

// TestSoftHSMTSATrustedTimeFailClosed provisions the TSA key on SoftHSM and
// wires a real timesource.Checker in front of it (Task 163). With the host clock
// within the drift threshold the TSA signs a valid, HSM-verifiable token; with
// the injected drift beyond the threshold the TSA fails closed, returning the
// RFC 3161 timeNotAvailable rejection instead of a token — proving a compromised
// host clock cannot mint a falsely-dated timestamp. Skipped unless the SoftHSM
// environment is exported (eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMTSATrustedTimeFailClosed(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	provider, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	ctx := context.Background()
	suffix := time.Now().Format("150405") + "-" + randHex(t)
	caLabel := "test-ts-ca-" + suffix
	tsaLabel := "test-ts-key-" + suffix

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: caLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: caLabel})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM TS Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: tsaLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, _ := asn1.Marshal([]asn1.ObjectIdentifier{OIDExtKeyUsageTimeStamping})
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM TS"},
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
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	authority, err := New(nil, provider, Config{
		KeyLabel:    tsaLabel,
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
		Accuracy:    Accuracy{Seconds: 1},
	})
	if err != nil {
		t.Fatalf("New authority: %v", err)
	}

	data := []byte("trusted-time payload")
	digest := sha256.Sum256(data)
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: big.NewInt(0x99), CertReq: true})

	// 1. Host clock within the threshold: the TSA signs on the HSM and the token
	//    verifies.
	okChecker := timesource.NewChecker(
		[]timesource.Provider{fakeTimeProvider{offset: 2 * time.Second}},
		timesource.CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"},
	)
	authority.SetTrustedClock(okChecker)
	result, err := authority.Stamp(ctx, reqDER)
	if err != nil {
		t.Fatalf("Stamp within threshold: %v", err)
	}
	if !result.Granted {
		t.Fatalf("expected a granted token within the drift threshold, got rejection: %s", result.Detail)
	}
	tokenDER := parseGrantedResp(t, result.Response)
	sd, err := cms.ParseSignedData(tokenDER)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := sd.Verify(); err != nil {
		t.Fatalf("HSM-signed token failed verification: %v", err)
	}

	// 2. Host clock drifted beyond the threshold: the TSA refuses to sign and
	//    returns a timeNotAvailable rejection.
	driftChecker := timesource.NewChecker(
		[]timesource.Provider{fakeTimeProvider{offset: 90 * time.Second}},
		timesource.CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"},
	)
	authority.SetTrustedClock(driftChecker)
	rejected, err := authority.Stamp(ctx, reqDER)
	if err != nil {
		t.Fatalf("Stamp under drift should be a protocol rejection, not an error: %v", err)
	}
	if rejected.Granted {
		t.Fatal("TSA must NOT grant a token when the host clock drift exceeds the threshold")
	}
	if !strings.Contains(rejected.Detail, "time source") {
		t.Fatalf("rejection detail = %q, want a time-source reason", rejected.Detail)
	}
	assertTimeNotAvailable(t, rejected.Response)

	// 3. A recovered clock signs again (the failure is not sticky beyond the
	//    checker's short failure-cache window; a fresh checker proves recovery).
	authority.SetTrustedClock(okChecker2())
	recovered, err := authority.Stamp(ctx, reqDER)
	if err != nil || !recovered.Granted {
		t.Fatalf("TSA should sign again once the clock is trusted: err=%v granted=%v", err, recovered.Granted)
	}
}

func okChecker2() *timesource.Checker {
	return timesource.NewChecker(
		[]timesource.Provider{fakeTimeProvider{offset: 1 * time.Second}},
		timesource.CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"},
	)
}

// assertTimeNotAvailable decodes a rejection TimeStampResp and asserts the
// PKIFailureInfo carries the timeNotAvailable bit (RFC 3161 §2.4.2, bit 14).
func assertTimeNotAvailable(t *testing.T, respDER []byte) {
	t.Helper()
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatalf("parsing rejection response: %v", err)
	}
	var status struct {
		Status       int
		StatusString asn1.RawValue  `asn1:"optional"`
		FailInfo     asn1.BitString `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &status); err != nil {
		t.Fatalf("parsing PKIStatusInfo: %v", err)
	}
	if status.Status != StatusRejection {
		t.Fatalf("status = %d, want rejection (%d)", status.Status, StatusRejection)
	}
	if status.FailInfo.At(FailureTimeNotAvailable) != 1 {
		t.Fatalf("failInfo does not carry the timeNotAvailable bit (%d): %+v", FailureTimeNotAvailable, status.FailInfo)
	}
}
